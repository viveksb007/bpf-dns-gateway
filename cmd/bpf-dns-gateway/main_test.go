package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Regression test for the silent-bind-failure bug: startMetricsServer
// used ListenAndServe in a goroutine, so a busy/bad metricsAddr was only
// logged and the process ran on without metrics or /healthz. The bind
// must fail synchronously so run() can abort startup.
func TestStartMetricsServer_BusyPortReturnsError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv, err := startMetricsServer(ln.Addr().String(), prometheus.NewRegistry(), slog.Default())
	if err == nil {
		srv.Close()
		t.Fatal("startMetricsServer on a busy port: expected bind error, got nil")
	}
	if !strings.Contains(err.Error(), "bind metrics listener") {
		t.Errorf("error %q does not mention the bind failure", err)
	}
}

func TestStartMetricsServer_ServesHealthzAndMetrics(t *testing.T) {
	srv, err := startMetricsServer("127.0.0.1:0", prometheus.NewRegistry(), slog.Default())
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	defer srv.Close()

	for _, path := range []string{"/healthz", "/metrics"} {
		resp, err := http.Get(fmt.Sprintf("http://%s%s", srv.Addr, path))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, body %q", path, resp.StatusCode, body)
		}
	}
}
