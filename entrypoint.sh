#!/bin/sh

DOMAIN=${DOMAIN:-resinfo.net}
IP=${IP:-127.0.0.1}
ACME_EMAIL=${ACME_EMAIL:-admin@${DOMAIN}}
SERIAL=$(date +%Y%m%d%H)
export DOMAIN ACME_EMAIL

echo "[entrypoint] Configuring for Domain: $DOMAIN, IP: $IP${IPV6:+, IPv6: $IPV6}"

sed "s/{{DOMAIN}}/$DOMAIN/g; s/{{IP}}/$IP/g; s/{{SERIAL}}/$SERIAL/g" /app/zone.db.template > /app/zone.db

if [ -n "$IPV6" ]; then
    printf "ns1\t3600 IN AAAA\t%s\n@\t3600 IN AAAA\t%s\n" \
        "$IPV6" "$IPV6" >> /app/zone.db
fi

# Generate Corefile
cat > /app/Corefile <<EOF
${DOMAIN} {
    file /app/zone.db
    resinfo {
        asn_v4 /app/asn_v4.mmdb
        asn_v6 /app/asn_v6.mmdb
    }
    log
    errors
}
EOF

exec /usr/local/bin/coredns -conf /app/Corefile
