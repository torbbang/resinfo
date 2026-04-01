> [!IMPORTANT]
> ## 🚚 This project has moved to [git.torbjorn.dev](https://git.torbjorn.dev/torbbang/resinfo)
> This GitHub repository is archived and no longer maintained.

---

# ResInfo

ResInfo is a custom [CoreDNS](https://coredns.io/) plugin that acts as a passive diagnostic tool for DNS resolvers. By querying it, you receive a real-time capability report of your last-hop resolver, detailing its privacy bounds (ECS, QNAME minimization) and security posture (DNSSEC flags).

### Try it
```bash
dig TXT test.resinfo.net +short
```
*Note: To accurately test QNAME minimization, query a deep subdomain: `dig TXT check.my.dns.resinfo.net +short`*

### Example Output
```text
"Resolver: 1.1.1.1 [AS13335 Cloudflare, Inc., United States]"
"Transport: udp"
"DNSSEC: DO=YES AD=YES CD=NO"
"EDNS0-Cookie: YES"
"EDNS0-Padding: NO"
"EDNS0-Client-Subnet: NO"
"QNAME-Minimization: YES"
"0x20-Case-Randomization: YES"
"UDP-Buffer-Size: 1232"
"Learn more: https://resinfo.net"
```

## Configuration
The `resinfo` plugin can be configured with a custom "Learn more" link and optional ASN databases.

```corefile
resinfo [LINK] {
    db     PATH
    asn_v4 PATH
    asn_v6 PATH
}
```
* `LINK`: The URL to display at the end of the response. Defaults to `https://resinfo.net`.
* `asn_v4` / `asn_v6`: Path to an [O-X-L geoip-asn](https://github.com/O-X-L/geoip-asn) MMDB file for IPv4/IPv6. Used for ASN name and country lookups.

## Security Design
* **Authoritative-Only:** Recursion is strictly disabled to prevent amplification.
* **Strict Rate Limiting:** Enforces 1 query/second per IP using a background-swept mutex map.

---

## Self-Hosting Deployment

Requires a Linux host with Docker, port 53 available, and a delegated domain.

### 1. Free Port 53 (Ubuntu/Debian)
Disable `systemd-resolved` to allow Docker to bind to port 53.
```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

### 2. Build & Run

```bash
git clone https://github.com/torbbang/resinfo.git
cd resinfo

docker build -t resinfo-dns .
docker run -d \
  --name resinfo-dns \
  --restart unless-stopped \
  -e DOMAIN=example.com \
  -e IP=203.0.113.5 \
  -e ACME_EMAIL=admin@example.com \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 853:853/tcp \
  resinfo-dns
```

| Variable | Description | Default |
|---|---|---|
| `DOMAIN` | The domain to serve | `resinfo.net` |
| `IP` | Public IPv4 address of this host | `127.0.0.1` |
| `IPV6` | Public IPv6 address of this host (optional) | *(unset)* |
| `ACME_EMAIL` | Email for Let's Encrypt registration | `admin@$DOMAIN` |
*(Note: You can easily use Podman as a drop-in replacement by changing `docker` to `sudo podman`).*

### 3. DNS Delegation
Create glue records at your registrar pointing to your host's IP (e.g., `203.0.113.5`):
1.  **A Record:** `ns1.test` -> `203.0.113.5`
2.  **NS Record:** `test` -> `ns1.test.resinfo.net.`

## License
MIT