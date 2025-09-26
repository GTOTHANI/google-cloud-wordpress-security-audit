# 🔒 WordPress GCP Security Audit Tool

A read‑only Bash script that audits a WordPress deployment behind **Google Cloud HTTP(S) Load Balancing**.  
It checks DNS, LB wiring, SSL/TLS (incl. expiry), redirects, security headers, `xmlrpc.php`, CDN/cache, backend health,
firewall hygiene, optional remote `wp-config.php` hardening, Cloud Armor, HTTP/3, compression, canonical host, and more.

> **Safety**: The script does **not** change any configuration. It reads and reports only.

> A comprehensive security audit tool for WordPress deployments on Google Cloud Platform Load Balancer infrastructure.

## 🌟 Features

- **🌐 DNS Configuration** - Validates A records, CNAME, IPv6, and CAA policies
- **🔐 SSL/TLS Analysis** - Managed certificates, expiration dates, and domain validation
- **⚡ Load Balancer Health** - Backend services, forwarding rules, and health checks  
- **🛡️ Security Headers** - HSTS, CSP, X-Frame-Options, and modern security policies
- **🚫 WordPress Hardening** - xmlrpc.php protection and wp-config.php validation
- **📡 CDN & Caching** - Cache-Control headers and static asset optimization
- **🛡️ Cloud Armor** - WAF policies and security rule analysis
- **🔄 HTTP/3 & QUIC** - Modern protocol support verification
- **🔧 Infrastructure** - Firewall rules and instance security analysis

## 📋 Prerequisites

### Required Tools
- `gcloud` CLI (authenticated and configured)
- `dig` (DNS lookup utility)
- `curl` (HTTP client)
- `awk` and `sed` (text processing)

### GCP Permissions
Your account needs the following IAM roles:
- `Compute Network Viewer` (minimum)
- `DNS Reader` (if using Cloud DNS)
- `Compute Security Admin` (for Cloud Armor policies)

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y google-cloud-sdk dnsutils curl gawk
```

**macOS:**
```bash
brew install google-cloud-sdk bind curl gawk gnu-sed
```

**RHEL/CentOS:**
```bash
sudo yum install -y google-cloud-sdk bind-utils curl gawk
```

## 🚀 Quick Start

### 1. Download and Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/wp-gcp-security-audit.git
cd wp-gcp-security-audit

# Make executable
chmod +x wp_sec_audit_v2.sh
```

### 2. Basic Usage
```bash
# Interactive mode (will prompt for missing values)
./wp_sec_audit_v2.sh

# Direct execution with parameters
./wp_sec_audit_v2.sh --project my-gcp-project --domain example.com

# Fast mode (skip slower SSH checks)
./wp_sec_audit_v2.sh --fast --project my-project --domain mysite.com
```

### 3. Environment Configuration
```bash
# Create configuration template
./wp_sec_audit_v2.sh --make-env

# Edit the generated .env file
nano .env

# Run with .env configuration
./wp_sec_audit_v2.sh
```

## ⚙️ Configuration Options

### Command Line Flags
| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--project` | GCP Project ID | `gcloud config` | `--project my-wp-project` |
| `--domain` | Apex domain name | *required* | `--domain example.com` |
| `--region` | GCP region | `me-west1` | `--region us-central1` |
| `--zone` | GCP zone | `me-west1-b` | `--zone us-central1-a` |
| `--lb-ip-name` | Load balancer IP name | `wp-lb-ip` | `--lb-ip-name prod-ip` |
| `--backend` | Backend service name | `wp-backend` | `--backend wp-prod-backend` |
| `--instance` | VM for wp-config checks | *none* | `--instance wp-vm-1` |
| `--fast` | Skip slower checks | `false` | `--fast` |
| `--no-color` | Disable colored output | `false` | `--no-color` |

### Environment Variables
```bash
export PROJECT_ID="my-gcp-project"
export DOMAIN="example.com"
export REGION="us-central1"
export ZONE="us-central1-a"
export INSTANCE="wp-instance-1"
```

### Configuration File (.env)
```env
PROJECT_ID=my-gcp-project
DOMAIN=example.com
REGION=us-central1
ZONE=us-central1-a
INSTANCE=wp-prod-vm
BACKEND=wp-backend-service
LB_IP_NAME=wp-load-balancer-ip
```

## 📊 Understanding the Output

### Security Check Categories

**🟢 PASS** - Configuration meets security best practices  
**🟡 WARN** - Improvement recommended but not critical  
**🔴 FAIL** - Security issue requiring immediate attention  

### Sample Output
```
=== WordPress GCP Security Audit (v2) ===
Project: my-project | Domain: example.com

== DNS ==
[PASS] A @example.com → 34.102.136.180 (LB=34.102.136.180)
[PASS] CNAME www → example.com
[PASS] No AAAA (IPv6) — fine for current LB

== SSL ==
[PASS] Managed certificate 'wp-ssl-cert' ACTIVE
[PASS] Certificate valid for ~87 more days

== Security Headers ==
[PASS] HSTS strong (preload, includeSubDomains)
[WARN] CSP not set (optional, but recommended)

== Summary ==
PASS=12  WARN=3  FAIL=1

=== FAIL (fix first) ===
1) Backend Health | Backend health state: UNHEALTHY

=== WARN (improve next) ===
1) Security Headers | CSP not set (optional, but recommended)
2) xmlrpc.php | xmlrpc.php is not fully blocked
```

## 🎯 Use Cases

### CI/CD Integration
```bash
# In your deployment pipeline
./wp_sec_audit_v2.sh --fast --no-color --project $GCP_PROJECT --domain $PROD_DOMAIN
if [ $? -ne 0 ]; then echo "Security audit failed"; exit 1; fi
```

### Monitoring & Alerting
```bash
# Run periodic security checks
./wp_sec_audit_v2.sh --fast > security_report.log 2>&1
grep -c "FAIL" security_report.log && send_alert
```

### Multi-Environment Testing
```bash
# Development
./wp_sec_audit_v2.sh --project dev-wp --domain dev.example.com

# Staging  
./wp_sec_audit_v2.sh --project staging-wp --domain staging.example.com

# Production
./wp_sec_audit_v2.sh --project prod-wp --domain example.com
```

## 🔧 Advanced Configuration

### Custom Resource Names
If your GCP resources use different naming conventions:
```bash
./wp_sec_audit_v2.sh \
  --project prod-wordpress \
  --domain mysite.com \
  --backend custom-wp-backend \
  --lb-ip-name prod-external-ip \
  --http-proxy wp-http-target-proxy \
  --https-proxy wp-https-target-proxy
```

### WordPress Configuration Checks
For remote wp-config.php validation via SSH:
```bash
./wp_sec_audit_v2.sh \
  --project my-project \
  --domain example.com \
  --instance wp-server-1 \
  --zone us-central1-a
```

## 🐛 Troubleshooting

### Common Issues

**Authentication Error:**
```bash
# Re-authenticate gcloud
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

**Permission Denied:**
```bash
# Check IAM permissions
gcloud projects get-iam-policy YOUR_PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role)" --filter="bindings.members:YOUR_EMAIL"
```

**DNS Resolution Issues:**
```bash
# Test DNS manually
dig +short @8.8.8.8 example.com A
dig +short @8.8.8.8 www.example.com CNAME
```

**SSL Certificate Problems:**
```bash
# Check certificate status manually
gcloud compute ssl-certificates list --project=YOUR_PROJECT
```

### Debug Mode
```bash
# Enable verbose output
bash -x ./wp_sec_audit_v2.sh --project test --domain example.com
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
```bash
git clone https://github.com/yourusername/wp-gcp-security-audit.git
cd wp-gcp-security-audit

# Install shellcheck for linting
sudo apt install shellcheck  # Ubuntu/Debian
brew install shellcheck      # macOS

# Run tests
shellcheck wp_sec_audit_v2.sh
```


## 🙏 Acknowledgments

- Built for WordPress deployments on Google Cloud Platform
- Inspired by web security best practices and OWASP guidelines
- Designed for DevOps teams managing WordPress at scale

---

**⭐ If this tool helped secure your WordPress deployment, please consider giving it a star!**

## Notes
- The script is tailored for **GCP HTTP(S) LB** + WordPress, but many checks are generic.
- Some checks (e.g., CDN `Age`) may vary if a CDN layer is disabled/cold.
- Use only on domains you control and with proper authorization.

