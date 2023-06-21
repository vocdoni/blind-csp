FROM golang:1.20 AS builder

WORKDIR /src
COPY . .
RUN go build -o=. -ldflags="-s -w"

FROM debian:bookworm-slim as base

WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app
COPY --from=builder /src/blind-csp ./
ENTRYPOINT ["/app/blind-csp"]
