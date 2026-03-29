# syntax=docker/dockerfile:1

FROM node:20-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY dashboard/package.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

FROM golang:1.25-alpine AS go-builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . ./
COPY --from=dashboard-builder /app/dashboard/dist ./dashboard/dist
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/relay ./cmd/relay

FROM alpine:3.19
WORKDIR /app
COPY --from=go-builder /out/relay /usr/local/bin/relay
COPY config/example.yaml /etc/relay/relay.yaml
EXPOSE 8088 8443
ENTRYPOINT ["/usr/local/bin/relay"]
