FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mcpshark ./cmd/mcpshark

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /mcpshark /usr/local/bin/mcpshark
ENTRYPOINT ["mcpshark"]
