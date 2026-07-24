BINARY := bpf-dns-gateway
GO := go
CLANG := clang

.PHONY: generate build test clean vet fmt fmt-check vmlinux

generate:
	$(GO) generate ./internal/ebpf/...

build: fmt-check generate
	$(GO) build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# gofmt always exits 0, so fail explicitly when it lists any files.
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt check failed; run 'make fmt' to fix:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

fmt:
	gofmt -w .

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

clean:
	rm -rf bin/
	rm -f internal/ebpf/dnsgateway_x86_bpfel.go internal/ebpf/dnsgateway_x86_bpfel.o
