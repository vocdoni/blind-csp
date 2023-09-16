FROM golang:1.20 AS builder

WORKDIR /src
COPY . .
RUN go build -o=. -ldflags="-s -w"

FROM debian:bookworm-slim as base

WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app
COPY --from=builder /src/blind-csp ./
COPY --from=builder /src/handlers/oauthhandler/config.yml ./handlers/oauthhandler/config.yml

ENTRYPOINT ["/app/blind-csp"]
