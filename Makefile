BINARY := bpf-dns-gateway
GO := go
CLANG := clang

.PHONY: generate build test clean vet vmlinux

generate:
	$(GO) generate ./internal/ebpf/...

build: generate
	$(GO) build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

clean:
	rm -rf bin/
	rm -f internal/ebpf/dnsgateway_x86_bpfel.go internal/ebpf/dnsgateway_x86_bpfel.o
