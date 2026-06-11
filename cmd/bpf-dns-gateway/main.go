// Command bpf-dns-gateway is the controller entrypoint. It loads the
// eBPF programs, populates the config + suffix-rule maps, attaches to
// pod veths as they appear, health-checks the VPC DNS resolver, and
// exports Prometheus metrics. Runs as a systemd Type=notify service.
//
// Startup / shutdown ordering follows design.md §7.2 / §7.3.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/viveksb007/bpf-dns-gateway/internal/config"
	"github.com/viveksb007/bpf-dns-gateway/internal/controller"
	bpf "github.com/viveksb007/bpf-dns-gateway/internal/ebpf"
	"github.com/viveksb007/bpf-dns-gateway/internal/health"
	"github.com/viveksb007/bpf-dns-gateway/internal/metrics"
	"github.com/viveksb007/bpf-dns-gateway/internal/netlinkmon"
)

func main() {
	configPath := flag.String("config", "/etc/bpf-dns-gateway/config.yaml", "path to config YAML")
	pinDir := flag.String("pin-dir", bpf.DefaultPinDir, "bpffs directory for pinned maps")
	flag.Parse()

	if err := run(*configPath, *pinDir); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath, pinDir string) error {
	// 1. Load + validate config.
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting bpf-dns-gateway",
		"config", configPath,
		"corednsServiceIP", cfg.CorednsServiceIP,
		"hostResolverIP", cfg.HostResolverIP,
		"rules", len(cfg.Rules),
	)

	// 2. Load eBPF programs + pin maps.
	loader, err := bpf.New(pinDir)
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}
	// In the normal path loader.Close + Unpin run in the ordered
	// shutdown below (after detach), NOT via defer. cleanupLoader is
	// only for the early-return failures during startup, before any
	// programs are attached.
	cleanupLoader := func() {
		_ = loader.Close()
		_ = loader.Unpin()
	}

	// 3. Populate config_map + suffix_rules.
	if err := loader.PopulateConfig(bpf.Config{
		CorednsIP:      net.ParseIP(cfg.CorednsServiceIP),
		HostResolverIP: net.ParseIP(cfg.HostResolverIP),
	}); err != nil {
		cleanupLoader()
		return fmt.Errorf("populate config: %w", err)
	}
	if err := loader.PopulateSuffixRules(cfg.Patterns()); err != nil {
		cleanupLoader()
		return fmt.Errorf("populate suffix rules: %w", err)
	}

	// 4. Build subsystems.
	mgr := bpf.NewAttachManager(loader)
	monitor := netlinkmon.New(logger)
	ctrl, err := controller.New(controller.Options{
		Loader:  loader,
		Manager: mgr,
		Monitor: monitor,
		Logger:  logger,
	})
	if err != nil {
		cleanupLoader()
		return fmt.Errorf("new controller: %w", err)
	}

	checker, err := health.New(health.Config{
		ResolverIP:       net.ParseIP(cfg.HostResolverIP),
		Interval:         cfg.HealthCheckInterval(),
		Timeout:          cfg.HealthCheckTimeout(),
		FailureThreshold: cfg.HealthCheckThreshold(),
	}, loader, logger)
	if err != nil {
		cleanupLoader()
		return fmt.Errorf("new health checker: %w", err)
	}

	// 5. Metrics server.
	collector := metrics.New(loader, mgr, checker, logger)
	reg := prometheus.NewRegistry()
	if err := reg.Register(collector); err != nil {
		cleanupLoader()
		return fmt.Errorf("register collector: %w", err)
	}
	metricsSrv := startMetricsServer(cfg.MetricsAddr, reg, logger)

	// 6. Lifecycle context, canceled on SIGTERM/SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// 7. Start monitor, controller, health checker.
	// Monitor must be subscribed before the controller consumes its
	// events; ListExisting=true replays current veths so startup
	// reconciliation and live events share one path (design §7.2).
	go func() {
		if err := monitor.Start(ctx); err != nil {
			logger.Error("netlink monitor stopped with error", "err", err)
			stop() // tear the whole process down; controller will detach
		}
	}()
	go func() {
		if err := ctrl.Run(ctx); err != nil {
			logger.Error("controller stopped with error", "err", err)
			stop()
		}
	}()
	go func() {
		if err := checker.Run(ctx); err != nil {
			logger.Error("health checker stopped with error", "err", err)
		}
	}()

	// 8. Signal readiness to systemd.
	if err := sdNotifyReady(); err != nil {
		logger.Warn("sd_notify(READY) failed", "err", err)
	}
	logger.Info("ready")

	// 9. Block until shutdown signal.
	<-ctx.Done()
	logger.Info("shutdown signal received; beginning ordered shutdown")
	_ = sdNotifyStopping()

	// 9a. Set bypass=1 immediately so ingress stops DNAT'ing new queries
	// while we tear down (egress keeps draining in-flight responses).
	if err := loader.SetBypass(true); err != nil {
		logger.Error("failed to set bypass during shutdown", "err", err)
	}

	// 9b. Wait for the controller to finish detaching from all veths.
	select {
	case <-ctrl.Done():
	case <-time.After(10 * time.Second):
		logger.Warn("controller did not finish detaching within 10s")
	}

	// 9c. Stop the metrics server.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("metrics server shutdown error", "err", err)
	}

	// 9d. Unpin maps + close program fds (TCX already detached above).
	if err := loader.Close(); err != nil {
		logger.Warn("loader close error", "err", err)
	}
	if err := loader.Unpin(); err != nil {
		logger.Warn("loader unpin error", "err", err)
	}

	logger.Info("shutdown complete")
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func startMetricsServer(addr string, reg *prometheus.Registry, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "addr", addr, "err", err)
		}
	}()
	logger.Info("metrics server listening", "addr", addr)
	return srv
}

// --- sd_notify (systemd Type=notify) ---

// sdNotify sends a datagram to the systemd notify socket. No-op when
// NOTIFY_SOCKET is unset (i.e. not run under systemd Type=notify).
func sdNotify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	addr := &net.UnixAddr{Name: sock, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return err
	}
	return nil
}

func sdNotifyReady() error    { return sdNotify("READY=1") }
func sdNotifyStopping() error { return sdNotify("STOPPING=1") }
