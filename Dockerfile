FROM golang:1.15.8-alpine3.13 AS builder

WORKDIR /src
COPY . .
RUN apk update && apk add build-base
RUN go build -o=. -ldflags="-s -w"

FROM alpine:3.13

WORKDIR /app
COPY --from=builder /src/blind-ca ./
ENTRYPOINT ["/app/blind-ca"]
