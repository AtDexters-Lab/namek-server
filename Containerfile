FROM golang:1.24-alpine AS builder

ARG VERSION=dev

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /namek ./cmd/namek/

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    mkdir -p /etc/namek/tpm-ca/hardware

COPY --from=builder /namek /namek

EXPOSE 53 443 8056
ENTRYPOINT ["/namek", "-config", "/piccolo/config/app.yaml"]
