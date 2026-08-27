FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/mcp-oauth-proxy main.go

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata bash

WORKDIR /app
COPY --from=builder /app/mcp-oauth-proxy /app/mcp-oauth-proxy

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/app/mcp-oauth-proxy"]
