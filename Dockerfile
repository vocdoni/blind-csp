FROM golang:1.20 AS builder

WORKDIR /src
RUN --mount=type=cache,sharing=locked,id=gomod,target=/go/pkg/mod/cache \
	--mount=type=bind,source=go.sum,target=go.sum \
	--mount=type=bind,source=go.mod,target=go.mod \
	go mod download -x
RUN --mount=type=cache,sharing=locked,id=gomod,target=/go/pkg/mod/cache \
	--mount=type=cache,sharing=locked,id=goroot,target=/root/.cache/go-build \
	--mount=type=bind,target=. \
    go build -o=blind-csp -ldflags="-s -w" -trimpath

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /src/blind-csp /app
ENTRYPOINT ["/app/blind-csp"]
