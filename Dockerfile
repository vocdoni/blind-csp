FROM golang:1.17-alpine3.13 AS builder

WORKDIR /src
COPY . .
RUN apk update && apk add build-base
RUN go build -o=. -ldflags="-s -w"
RUN go build -o=smsApiAdmin -ldflags="-s -w" ./handlers/smshandler/adminapi

FROM alpine:3.13

WORKDIR /app
COPY --from=builder /src/blind-csp ./
COPY --from=builder /src/smsApiAdmin ./
ENTRYPOINT ["/app/blind-csp"]
