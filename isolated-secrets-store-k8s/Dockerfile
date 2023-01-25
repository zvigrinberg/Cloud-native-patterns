FROM golang:latest as builder

ARG BUILD_VERSION=1
WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY pkg/ ./pkg/

RUN ls -lh /tmp/
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly  -v -o /tmp/secrets-store -ldflags "-X main.BuildVersion=$BUILD_VERSION"

FROM alpine:3 as runner
RUN apk add --no-cache ca-certificates
COPY --from=builder /tmp/secrets-store /go/bin/secrets-store

ENV LOG_LEVEL='info'
ENV SERVER_PORT=8080
EXPOSE ${SERVER_PORT}
ENTRYPOINT ["/go/bin/secrets-store"]