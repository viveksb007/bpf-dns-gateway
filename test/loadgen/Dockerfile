# Image for the loadgen benchmark tool (querier + aggregator), a throwaway
# test artifact (docs/benchmark-diversity.md) — not part of the product.
#
# loadgen is stdlib-only. Build the static binary first, then wrap it:
#   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o loadgen ./test/loadgen
#   docker build -f test/loadgen/Dockerfile -t <registry>/loadgen:tag \
#                --build-context bin=. test/loadgen   # (or copy the binary in)
#
# A from-source multi-stage build also works where a Go module proxy is
# reachable; on hosts where it is not, prefer the prebuilt-binary path above.
FROM gcr.io/distroless/static-debian12:nonroot
COPY loadgen /usr/local/bin/loadgen
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/loadgen"]
