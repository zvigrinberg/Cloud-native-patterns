FROM golang:latest as builder

ARG BUILD_VERSION=1
WORKDIR /app

COPY *.go ./

RUN  CGO_ENABLED=0 GOOS=linux go build -o /tmp/manifests.secrets-store manifests.secrets-store-app.go

FROM alpine:3 as runner
RUN apk add --no-cache ca-certificates
COPY --from=builder /tmp/secrets-store /go/bin/manifests.secrets-store

ENV SERVER_PORT=8080
EXPOSE ${SERVER_PORT}
ENTRYPOINT ["/go/bin/manifests.secrets-store"]