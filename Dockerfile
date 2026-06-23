# syntax=docker/dockerfile:1

FROM node:20-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM golang:1.25-alpine AS go-builder
WORKDIR /app
# Copy go.sum alongside go.mod so module downloads are integrity-verified and the
# layer caches deterministically.
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=dashboard-builder /app/dashboard/dist ./dashboard/dist
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/relay ./cmd/relay

FROM alpine:3.19
RUN apk add --no-cache wget && adduser -D -u 10001 relay
WORKDIR /app
COPY --from=go-builder /out/relay /usr/local/bin/relay
COPY config/example.yaml /etc/relay/relay.yaml

# Point the binary at the baked-in config and run as a non-root user.
ENV RELAY_CONFIG=/etc/relay/relay.yaml
USER 10001

# 8088: HTTP listener (matches config/example.yaml and docker-compose). 8443 is
# reserved for the HTTPS listener when TLS is configured.
EXPOSE 8088 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8088/_relay/health || exit 1

ENTRYPOINT ["/usr/local/bin/relay"]
