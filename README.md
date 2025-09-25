# WordPress on GCP — Security Audit (v2)

A read‑only Bash script that audits a WordPress deployment behind **Google Cloud HTTP(S) Load Balancing**.  
It checks DNS, LB wiring, SSL/TLS (incl. expiry), redirects, security headers, `xmlrpc.php`, CDN/cache, backend health,
firewall hygiene, optional remote `wp-config.php` hardening, Cloud Armor, HTTP/3, compression, canonical host, and more.

> **Safety**: The script does **not** change any configuration. It reads and reports only.

## Features
- PASS/WARN/FAIL output with a clean **Summary** (ordered list of what to fix first).
- Strong HSTS validation (preload + includeSubDomains + max-age≥31536000).
- TLS certificate **expiry** warning.
- HTTP→HTTPS redirect test; canonical `www`→apex redirect test.
- Security headers (XFO, XCTO, Referrer-Policy, CSP, Permissions-Policy, COEP, COOP).
- `xmlrpc.php` blocking check.
- CDN cacheability for static assets (incl. `Age` growth) and non-cacheable HTML.
- HTTP/3 (QUIC) detection; Brotli/Gzip compression for assets.
- Firewall sanity (no open SSH to the world), external IPs on instances.
- Optional remote `wp-config.php` checks via IAP SSH.
- `--fast` flag to skip slow checks. `--no-color` for CI logs.

## Prerequisites
- Linux/macOS with: `gcloud`, `curl`, `dig`, `awk`, `sed` available in `PATH`.
- Google Cloud access to the target project; IAP SSH permission if using `INSTANCE`.

## Quick start
```bash
chmod +x wp_sec_audit_v2.sh
PROJECT_ID=my-project DOMAIN=example.com ./wp_sec_audit_v2.sh
```

Optional flags:
```bash
PROJECT_ID=my-project DOMAIN=example.com ./wp_sec_audit_v2.sh --fast --no-color
```

Remote `wp-config.php` checks (via IAP):
```bash
PROJECT_ID=my-project DOMAIN=example.com INSTANCE=wp-1 ZONE=me-west1-b ./wp_sec_audit_v2.sh
```

## Environment variables
- `PROJECT_ID` (required) — GCP project id
- `DOMAIN` (required) — apex domain (e.g., `example.com`)
- `REGION` default `me-west1`
- `ZONE` default `me-west1-b`
- `LB_IP_NAME` default `wp-lb-ip`
- `BACKEND` default `wp-backend`
- `HTTP_PROXY` default `wp-http-proxy`
- `HTTPS_PROXY` default `wp-https-proxy`
- `HTTP_FR` default `wp-http-fr`
- `HTTPS_FR` default `wp-https-fr`
- `IGM` default `wp-igm`
- `INSTANCE` optional — VM name for IAP SSH
- `ASSET_PATH` default `/wp-includes/css/dist/block-library/style.css`

## Output
At the end you’ll see:
```
PASS=12  WARN=3  FAIL=1

=== FAIL (fix first) ===
 1) Security Headers | HSTS missing
 ...

=== WARN (improve next) ===
 1) CDN / Cache-Control (static asset) | Suboptimal Cache-Control ...
 ...
```

## Notes
- The script is tailored for **GCP HTTP(S) LB** + WordPress, but many checks are generic.
- Some checks (e.g., CDN `Age`) may vary if a CDN layer is disabled/cold.
- Use only on domains you control and with proper authorization.

