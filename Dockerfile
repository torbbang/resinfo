# Build stage
FROM docker.io/library/golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build the custom CoreDNS binary
RUN CGO_ENABLED=0 GOOS=linux go build -o coredns_custom ./cmd/coredns/main.go

# Final stage
FROM docker.io/library/alpine:latest

# Install ca-certificates and curl for downloading databases and TLS support
RUN apk add --no-cache ca-certificates curl

WORKDIR /app

# Download the latest GeoIP and ASN databases from O-X-L
RUN curl -L https://geoip.oxl.app/file/asn_ipv4_small.mmdb.zip -o /app/asn_v4.zip \
    && curl -L https://geoip.oxl.app/file/asn_ipv6_small.mmdb.zip -o /app/asn_v6.zip \
    && unzip -o /app/asn_v4.zip -d /app && mv /app/asn_ipv4_small.mmdb /app/asn_v4.mmdb \
    && unzip -o /app/asn_v6.zip -d /app && mv /app/asn_ipv6_small.mmdb /app/asn_v6.mmdb

COPY --from=builder /src/coredns_custom /usr/local/bin/coredns
COPY Corefile /app/Corefile
COPY zone.db.template /app/zone.db.template
COPY entrypoint.sh /app/entrypoint.sh

# Create persistent directories
RUN mkdir -p /app/certs
RUN chmod +x /app/entrypoint.sh

# Expose standard DNS ports
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 853/tcp

# Run CoreDNS as an unprivileged user for security
RUN adduser -D -u 1000 coredns
RUN chown -R coredns:coredns /app
USER coredns

ENTRYPOINT ["/app/entrypoint.sh"]
