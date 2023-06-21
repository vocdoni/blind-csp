FROM golang:1.20 AS builder

WORKDIR /src
COPY . .
RUN go build -o=blind-csp -ldflags="-s -w"

FROM alpine:latest

WORKDIR /app
COPY --from=builder /src/blind-csp ./
ENTRYPOINT ["/app/blind-csp"]
