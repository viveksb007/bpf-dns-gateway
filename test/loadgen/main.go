// Command loadgen is a throwaway benchmark tool for the S3 DNS diversity +
// latency test (docs/benchmark-diversity.md). Two modes:
//
//   - aggregator: HTTP service collecting per-arm unique resolved IPs and
//     per-query latencies; reports counts + p50/p95/p99.
//   - querier:    resolves an S3 name (via the Go resolver -> /etc/resolv.conf
//     -> CoreDNS ClusterIP -> gateway) and streams each IP + latency to the
//     aggregator. Steady (loop for DURATION) or coordinated (one shot at
//     START_EPOCH).
//
// Stdlib only (CGO_ENABLED=0) so it builds without a module proxy and runs
// in a distroless/static image.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

func main() {
	switch os.Getenv("MODE") {
	case "aggregator":
		runAggregator()
	case "querier":
		runQuerier()
	default:
		fmt.Fprintln(os.Stderr, "set MODE=aggregator|querier")
		os.Exit(2)
	}
}

// ---- shared wire types ----

type sample struct {
	Arm       string  `json:"arm"`
	IPs       []string `json:"ips"`
	LatencyMs float64 `json:"latencyMs"`
	Err       bool    `json:"err"`
}

type report struct {
	Arm       string  `json:"arm"`
	UniqueIPs int     `json:"uniqueIPs"`
	Samples   int     `json:"samples"`
	Errors    int     `json:"errors"`
	P50       float64 `json:"p50"`
	P95       float64 `json:"p95"`
	P99       float64 `json:"p99"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
}

// ---- aggregator ----

type armState struct {
	ips       map[string]struct{}
	latencies []float64
	errors    int
}

func runAggregator() {
	var mu sync.Mutex
	arms := map[string]*armState{}

	getArm := func(name string) *armState {
		a := arms[name]
		if a == nil {
			a = &armState{ips: map[string]struct{}{}}
			arms[name] = a
		}
		return a
	}

	http.HandleFunc("/sample", func(w http.ResponseWriter, r *http.Request) {
		var s sample
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		a := getArm(s.Arm)
		if s.Err {
			a.errors++
		} else {
			for _, ip := range s.IPs {
				a.ips[ip] = struct{}{}
			}
			a.latencies = append(a.latencies, s.LatencyMs)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		arm := r.URL.Query().Get("arm")
		mu.Lock()
		a := getArm(arm)
		lat := append([]float64(nil), a.latencies...)
		rep := report{Arm: arm, UniqueIPs: len(a.ips), Samples: len(a.latencies), Errors: a.errors}
		mu.Unlock()
		sort.Float64s(lat)
		rep.P50 = pctile(lat, 50)
		rep.P95 = pctile(lat, 95)
		rep.P99 = pctile(lat, 99)
		if len(lat) > 0 {
			rep.Min = lat[0]
			rep.Max = lat[len(lat)-1]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
	})

	// /reset?arm= clears one arm so a re-run starts clean.
	http.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		arm := r.URL.Query().Get("arm")
		mu.Lock()
		delete(arms, arm)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":8080"
	fmt.Fprintln(os.Stderr, "aggregator listening", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "aggregator:", err)
		os.Exit(1)
	}
}

func pctile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int((p / 100) * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---- querier ----

func runQuerier() {
	arm := getenv("ARM", "unknown")
	qname := getenv("QNAME", "test-bucket.s3.us-west-2.amazonaws.com.")
	aggURL := getenv("AGG_URL", "http://loadgen-agg:8080")
	qmode := getenv("QMODE", "steady") // steady | coordinated

	// Use the Go resolver but force it to go through /etc/resolv.conf
	// (PreferGo=false uses cgo/getent semantics; PreferGo=true uses the
	// pure-Go resolver which also reads resolv.conf). Either way the
	// query lands at the CoreDNS ClusterIP. Use PreferGo for determinism
	// in a static binary.
	res := &net.Resolver{PreferGo: true}

	client := &http.Client{Timeout: 5 * time.Second}
	send := func(s sample) {
		s.Arm = arm
		b, _ := json.Marshal(s)
		req, _ := http.NewRequest(http.MethodPost, aggURL+"/sample", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}

	lookup := func() sample {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		t0 := time.Now()
		addrs, err := res.LookupHost(ctx, qname)
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			return sample{Err: true, LatencyMs: ms}
		}
		return sample{IPs: addrs, LatencyMs: ms}
	}

	if qmode == "coordinated" {
		startEpoch, _ := strconv.ParseInt(getenv("START_EPOCH", "0"), 10, 64)
		target := time.Unix(startEpoch, 0)
		// Sleep until ~50ms before, then busy-wait to fire tightly together.
		if d := time.Until(target) - 50*time.Millisecond; d > 0 {
			time.Sleep(d)
		}
		for time.Now().Before(target) {
		}
		send(lookup())
		// Stay alive briefly so the pod isn't restarted as CrashLoop.
		time.Sleep(30 * time.Second)
		return
	}

	// steady
	durSec, _ := strconv.Atoi(getenv("DURATION", "60"))
	deadline := time.Now().Add(time.Duration(durSec) * time.Second)
	tick := time.NewTicker(500 * time.Millisecond) // ~2 q/s
	defer tick.Stop()
	for time.Now().Before(deadline) {
		<-tick.C
		send(lookup())
	}
	// idle so the Deployment pod stays Running between arms (we scale to 0
	// to stop, rather than relying on completion).
	for {
		time.Sleep(60 * time.Second)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
