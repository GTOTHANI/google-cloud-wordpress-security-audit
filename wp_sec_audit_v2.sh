#!/usr/bin/env bash
# WordPress on GCP — Security Audit (v2)
# Generic-friendly input layer:
# - Reads flags (CLI), then .env, then environment variables.
# - Falls back to gcloud default project / interactive prompts (if TTY).
# - Provides `--make-env` to scaffold a .env template quickly.

set -u

#########################################
# Nice exit on Ctrl-C
#########################################
trap 'echo; echo "Aborted."; exit 130' INT

#########################################
# Defaults (can be overridden by .env / CLI / ENV)
#########################################
PROJECT_ID="${PROJECT_ID:-}"
DOMAIN="${DOMAIN:-}"                # example.com (apex)
REGION="${REGION:-me-west1}"
ZONE="${ZONE:-me-west1-b}"
LB_IP_NAME="${LB_IP_NAME:-wp-lb-ip}"
BACKEND="${BACKEND:-wp-backend}"
HTTP_PROXY="${HTTP_PROXY:-wp-http-proxy}"
HTTPS_PROXY="${HTTPS_PROXY:-wp-https-proxy}"
HTTP_FR="${HTTP_FR:-wp-http-fr}"
HTTPS_FR="${HTTPS_FR:-wp-https-fr}"
IGM="${IGM:-wp-igm}"
INSTANCE="${INSTANCE:-}"            # optional; if set, will SSH via IAP
ASSET_PATH="${ASSET_PATH:-/wp-includes/css/dist/block-library/style.css}"

FAST=0          # --fast
NO_COLOR=0     # --no-color

#########################################
# Helpers
#########################################
is_tty() { [[ -t 0 && -t 1 ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
die() { echo "Error: $*" >&2; exit 64; }

banner() {
  echo "=============================================="
  echo "  WordPress on GCP — Security Audit (v2)"
  echo "=============================================="
}

usage() {
  cat <<'USAGE'
Usage:
  ./wp_sec_audit_v2.sh [FLAGS] [--]                # will prompt if needed (interactive)
  PROJECT_ID=... DOMAIN=example.com ./wp_sec_audit_v2.sh [FLAGS]

Flags / Options:
  --project ID                GCP project id
  --domain DOMAIN             Apex domain (e.g., example.com)
  --region REGION             Default: me-west1
  --zone ZONE                 Default: me-west1-b
  --lb-ip-name NAME           Default: wp-lb-ip
  --backend NAME              Default: wp-backend
  --http-proxy NAME           Default: wp-http-proxy
  --https-proxy NAME          Default: wp-https-proxy
  --http-fr NAME              Default: wp-http-fr
  --https-fr NAME             Default: wp-https-fr
  --igm NAME                  Default: wp-igm
  --instance NAME             Optional VM for IAP SSH (wp-config checks)
  --asset-path PATH           Asset path for cache tests (default WP CSS)
  --fast                      Skip slower checks (SSH, policy listings)
  --no-color                  Disable ANSI colors (CI-friendly)
  --make-env                  Create a .env template and exit
  --help, -h                  Show this help and exit

Precedence of config (highest first):
  1) CLI flags
  2) ./.env (if exists)
  3) Environment variables
  4) gcloud default project (for PROJECT_ID)
  5) Interactive prompts (when running in a TTY)

Examples:
  ./wp_sec_audit_v2.sh --project my-proj --domain example.com
  ./wp_sec_audit_v2.sh --fast --no-color
  PROJECT_ID=my-proj DOMAIN=example.com ./wp_sec_audit_v2.sh
USAGE
}

write_env_template() {
  cat > .env <<EOF
# Copy this file to .env and adjust values.
PROJECT_ID=${PROJECT_ID}
DOMAIN=${DOMAIN}
REGION=${REGION}
ZONE=${ZONE}
LB_IP_NAME=${LB_IP_NAME}
BACKEND=${BACKEND}
HTTP_PROXY=${HTTP_PROXY}
HTTPS_PROXY=${HTTPS_PROXY}
HTTP_FR=${HTTP_FR}
HTTPS_FR=${HTTPS_FR}
IGM=${IGM}
INSTANCE=${INSTANCE}
ASSET_PATH=${ASSET_PATH}
# Flags are passed via CLI: --fast / --no-color
EOF
  echo "Created .env template in $(pwd)/.env"
}

#########################################
# Parse CLI flags (supports --key=value and --key value)
#########################################
# First, if .env exists, source it (weak precedence; will be overridden by explicit CLI)
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  source ./.env
fi

parse_arg() { # parse_arg KEY VALUE
  local k="$1" v="$2"
  case "$k" in
    project) PROJECT_ID="$v" ;;
    domain) DOMAIN="$v" ;;
    region) REGION="$v" ;;
    zone) ZONE="$v" ;;
    lb-ip-name) LB_IP_NAME="$v" ;;
    backend) BACKEND="$v" ;;
    http-proxy) HTTP_PROXY="$v" ;;
    https-proxy) HTTPS_PROXY="$v" ;;
    http-fr) HTTP_FR="$v" ;;
    https-fr) HTTPS_FR="$v" ;;
    igm) IGM="$v" ;;
    instance) INSTANCE="$v" ;;
    asset-path) ASSET_PATH="$v" ;;
    *) die "Unknown option: --$k" ;;
  esac
}

argv=("$@")
i=0
while (( i < ${#argv[@]} )); do
  arg="${argv[$i]}"
  case "$arg" in
    --help|-h) usage; exit 0 ;;
    --fast) FAST=1 ;;
    --no-color) NO_COLOR=1 ;;
    --make-env) write_env_template; exit 0 ;;
    --*=*)
      key="${arg%%=*}"; key="${key#--}"
      val="${arg#*=}"
      [[ -z "$val" ]] && die "Missing value for --$key"
      parse_arg "$key" "$val"
      ;;
    --*)
      key="${arg#--}"
      (( i++ )) || true
      [[ $i -ge ${#argv[@]} ]] && die "Missing value for --$key"
      val="${argv[$i]}"
      parse_arg "$key" "$val"
      ;;
    --) shift; break ;; # stop parsing
    *) die "Unknown argument: $arg (use --help)" ;;
  esac
  (( i++ ))
done

#########################################
# Try defaults from gcloud if missing
#########################################
if [[ -z "${PROJECT_ID}" ]] && have gcloud; then
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
  PROJECT_ID="${PROJECT_ID:-}"
fi

#########################################
# Interactive prompts if still missing & TTY
#########################################
prompt_var() {
  local var="$1" msg="$2" def="${3:-}"
  local current
  # shellcheck disable=SC2015,SC2086
  current="$(eval "echo \${$var:-}")"
  if [[ -n "$current" ]]; then return 0; fi
  if is_tty; then
    if [[ -n "$def" ]]; then
      read -r -p "$msg [$def]: " ans || true
      ans="${ans:-$def}"
    else
      read -r -p "$msg: " ans || true
    fi
    # shellcheck disable=SC2140
    eval "$var=\"\$ans\""
  fi
}

prompt_var PROJECT_ID "Enter GCP PROJECT_ID"
prompt_var DOMAIN "Enter apex DOMAIN (e.g., example.com)"
prompt_var REGION "Region" "$REGION"
prompt_var ZONE "Zone" "$ZONE"

# Minimal validation
[[ -z "$PROJECT_ID" ]] && die "PROJECT_ID is required"
[[ -z "$DOMAIN" ]] && die "DOMAIN is required"
if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
  die "DOMAIN '$DOMAIN' doesn't look like a valid apex domain"
fi

#########################################
# Dependencies
#########################################
for bin in gcloud dig curl awk sed; do
  have "$bin" || die "Missing dependency: $bin"
done

#########################################
# Colors & UI
#########################################
if [[ -t 1 && $NO_COLOR -eq 0 ]]; then
  GRN="\e[32m"; RED="\e[31m"; YLW="\e[33m"; BLU="\e[36m"; RST="\e[0m"
else
  GRN=""; RED=""; YLW=""; BLU=""; RST=""
fi
ok(){   printf "%b[PASS]%b %s\n" "$GRN" "$RST" "$*"; }
bad(){  printf "%b[FAIL]%b %s\n" "$RED" "$RST" "$*"; }
wrn(){  printf "%b[WARN]%b %s\n" "$YLW" "$RST" "$*"; }
hdr(){  CURRENT_SECTION="$*"; printf "\n%b== %s ==%b\n" "$BLU" "$*" "$RST"; }

SUM_OK=0; SUM_BAD=0; SUM_WRN=0
declare -a PASS_ITEMS WARN_ITEMS FAIL_ITEMS
CURRENT_SECTION="Start"
OK(){ ok "$@"; ((SUM_OK++)); PASS_ITEMS+=("${CURRENT_SECTION} | $*"); }
BAD(){ bad "$@"; ((SUM_BAD++)); FAIL_ITEMS+=("${CURRENT_SECTION} | $*"); }
WRN(){ wrn "$@"; ((SUM_WRN++)); WARN_ITEMS+=("${CURRENT_SECTION} | $*"); }

GCLOUD=(gcloud --project="${PROJECT_ID}")
_curl(){ curl -fsS --connect-timeout 5 --max-time 15 --retry 2 --retry-all-errors "$@"; }
val_or_dash(){ local v="$1"; [[ -n "$v" ]] && printf "%s" "$v" || printf "-"; }

banner
echo "Project: ${PROJECT_ID} | Domain: ${DOMAIN}"
echo "Region: ${REGION} | Zone: ${ZONE}"
(( FAST )) && echo "(FAST mode enabled)"

#########################################
# 1) DNS
#########################################
hdr "DNS"
LB_IP="$(${GCLOUD[@]} compute addresses describe "$LB_IP_NAME" --global --format='value(address)' 2>/dev/null || true)"
A_REC="$(dig +short @8.8.8.8 "$DOMAIN" A | head -n1)"
WWW_CNAME="$(dig +short @8.8.8.8 "www.$DOMAIN" CNAME | sed 's/\.$//' || true)"
AAAA_REC="$(dig +short @8.8.8.8 "$DOMAIN" AAAA || true)"
CAA_REC="$(dig +short @8.8.8.8 "$DOMAIN" CAA || true)"

if [[ -n "$LB_IP" && "$A_REC" == "$LB_IP" ]]; then
  OK "A @${DOMAIN} → ${A_REC} (LB=${LB_IP})"
else
  BAD "A @${DOMAIN}=${A_REC} does not match LB IP (${LB_IP})"
fi

if [[ "$WWW_CNAME" == "$DOMAIN" ]]; then
  OK "CNAME www → ${DOMAIN}"
else
  BAD "CNAME of www is '${WWW_CNAME}' (expected ${DOMAIN})"
fi

if [[ -z "$AAAA_REC" ]]; then
  OK "No AAAA (IPv6) — fine for current LB"
else
  WRN "Found AAAA: ${AAAA_REC} (ensure IPv6 support if you intend to use it)"
fi

if [[ -n "$CAA_REC" ]]; then
  echo "CAA: $CAA_REC"
  if echo "$CAA_REC" | grep -Eq 'letsencrypt\.org|pki\.goog'; then
    OK "CAA allows issuance (LE/Google)"
  else
    WRN "CAA exists and may restrict CA — ensure pki.goog/letsencrypt.org as needed"
  fi
else
  OK "No CAA (open by default)"
fi

#########################################
# 2) Forwarding Rules / Proxies
#########################################
hdr "Load Balancer"
HTTP_FR_IP="$(${GCLOUD[@]} compute forwarding-rules describe "$HTTP_FR" --global --format='value(IPAddress)' 2>/dev/null || true)"
HTTPS_FR_IP="$(${GCLOUD[@]} compute forwarding-rules describe "$HTTPS_FR" --global --format='value(IPAddress)' 2>/dev/null || true)"
[[ "$HTTP_FR_IP"  == "$LB_IP" ]] && OK "FW 80 on $LB_IP"  || BAD "FW 80 IP=${HTTP_FR_IP} != ${LB_IP}"
[[ "$HTTPS_FR_IP" == "$LB_IP" ]] && OK "FW 443 on $LB_IP" || BAD "FW 443 IP=${HTTPS_FR_IP} != ${LB_IP}"

#########################################
# 3) SSL (Managed / Custom)
#########################################
hdr "SSL"
CERT_NAME="$(${GCLOUD[@]} compute target-https-proxies describe "$HTTPS_PROXY" --global --format='value(sslCertificates.basename())' 2>/dev/null || true)"
if [[ -n "$CERT_NAME" ]]; then
  CERT_TYPE="$(${GCLOUD[@]} compute ssl-certificates describe "$CERT_NAME" --global --format='value(type)' 2>/dev/null || true)"
  CERT_STATUS="$(${GCLOUD[@]} compute ssl-certificates describe "$CERT_NAME" --global --format='value(managed.status)' 2>/dev/null || true)"
  DOM_STATUS="$(${GCLOUD[@]} compute ssl-certificates describe "$CERT_NAME" --global --format='value(managed.domainStatus)' 2>/dev/null || true)"
  EXP_TIME="$(${GCLOUD[@]} compute ssl-certificates describe "$CERT_NAME" --global --format='value(expireTime)' 2>/dev/null || true)"

  if [[ "$CERT_TYPE" == "MANAGED" ]]; then
    [[ "$CERT_STATUS" == "ACTIVE" ]] && OK "Managed certificate '$CERT_NAME' ACTIVE (${DOM_STATUS})" || BAD "Managed certificate '$CERT_NAME' status: ${CERT_STATUS} (${DOM_STATUS})"
  else
    OK "Custom certificate attached: '$CERT_NAME'"
  fi

  if [[ -n "$EXP_TIME" ]]; then
    NOW_EPOCH=$(date +%s)
    EXP_EPOCH=$(date -d "$EXP_TIME" +%s 2>/dev/null || echo "")
    if [[ -n "$EXP_EPOCH" ]]; then
      DAYS=$(( (EXP_EPOCH - NOW_EPOCH) / 86400 ))
      if (( DAYS < 0 )); then BAD "Certificate expired ${DAYS#-} days ago ($EXP_TIME)"
      elif (( DAYS <= 14 )); then WRN "Certificate expires in ${DAYS} days ($EXP_TIME)"
      else OK "Certificate valid for ~${DAYS} more days ($EXP_TIME)"
      fi
    fi
  fi
else
  BAD "No SSL certificate attached to HTTPS proxy (${HTTPS_PROXY})"
fi

#########################################
# 4) HTTP → HTTPS Redirect
#########################################
hdr "HTTP→HTTPS Redirect"
R_CODE="$(_curl -I "http://${DOMAIN}" | awk 'NR==1{print $2}')"
LOC="$(_curl -I "http://${DOMAIN}" | awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2}')"
echo "HTTP code: ${R_CODE}  Location: $(val_or_dash "$LOC")"
if echo "$R_CODE" | grep -Eq '^(301|308)$' && echo "$LOC" | grep -qi "^https://${DOMAIN}"; then
  OK "LB redirects HTTP→HTTPS correctly"
else
  WRN "Missing/partial redirect at LB (might be disabled temporarily)"
fi

#########################################
# 5) Security Headers (enhanced)
#########################################
hdr "Security Headers"
H="$(_curl -I "https://${DOMAIN}" || true)"
HSTS_LINE="$(echo "$H" | awk 'BEGIN{IGNORECASE=1}/^strict-transport-security:/{print tolower($0)}')"
if [[ -n "$HSTS_LINE" ]]; then
  maxage="$(echo "$HSTS_LINE" | sed -n 's/.*max-age=\([0-9]\+\).*/\1/p')"
  incsd=$(echo "$HSTS_LINE" | grep -qi "includesubdomains" && echo 1 || echo 0)
  preld=$(echo "$HSTS_LINE" | grep -qi "preload" && echo 1 || echo 0)
  if [[ -n "$maxage" ]] && (( maxage>=31536000 )) && (( incsd==1 )) && (( preld==1 )); then
    OK "HSTS strong (preload, includeSubDomains, max-age≥31536000)"
  else
    WRN "HSTS present but weak/missing directives (recommend preload+includeSubDomains+max-age≥31536000) — line: $HSTS_LINE"
  fi
else
  BAD "HSTS missing"
fi
echo "$H" | grep -qi '^x-frame-options:'         && OK "X-Frame-Options present"        || WRN "X-Frame-Options missing"
echo "$H" | grep -qi '^x-content-type-options:'  && OK "X-Content-Type-Options present" || WRN "X-Content-Type-Options missing"
echo "$H" | grep -qi '^referrer-policy:'         && OK "Referrer-Policy present"        || WRN "Referrer-Policy missing"
if echo "$H" | grep -qi '^content-security-policy:'; then OK "CSP present (ensure it does not break WP)"; else WRN "CSP not set (optional, but recommended)"; fi
if echo "$H" | grep -qi '^permissions-policy:'; then OK "Permissions-Policy present"; else WRN "Permissions-Policy missing"; fi
if echo "$H" | grep -qi '^cross-origin-embedder-policy:'; then OK "COEP present"; else WRN "COEP missing"; fi
if echo "$H" | grep -qi '^cross-origin-opener-policy:'; then OK "COOP present"; else WRN "COOP missing"; fi

#########################################
# 6) xmlrpc.php hardening
#########################################
hdr "xmlrpc.php"
G_CODE="$(_curl -I "https://${DOMAIN}/xmlrpc.php" | awk 'NR==1{print $2}')"
P_CODE="$(_curl -X POST -d 'ping' -I "https://${DOMAIN}/xmlrpc.php" | awk 'NR==1{print $2}')"
echo "GET: ${G_CODE}  POST: ${P_CODE}"
if [[ "$G_CODE" == "403" || "$P_CODE" == "403" ]]; then
  OK "xmlrpc.php blocked"
else
  WRN "xmlrpc.php is not fully blocked (consider .htaccess or Cloud Armor)"
fi

#########################################
# 7) CDN / Cache-Control for static assets
#########################################
hdr "CDN / Cache-Control (static asset)"
H1="$(_curl -I "https://${DOMAIN}${ASSET_PATH}" || true)"
sleep 1
H2="$(_curl -I "https://${DOMAIN}${ASSET_PATH}" || true)"
CC="$(echo "$H1" | awk 'BEGIN{IGNORECASE=1}/^Cache-Control:/{print substr($0,16)}')"
AGE1="$(echo "$H1" | awk 'BEGIN{IGNORECASE=1}/^Age:/{print $2}')"
AGE2="$(echo "$H2" | awk 'BEGIN{IGNORECASE=1}/^Age:/{print $2}')"
echo "Cache-Control: $(val_or_dash "$CC")"
if echo "$CC" | grep -qi 'max-age=2592000' && echo "$CC" | grep -qi 'immutable'; then
  OK "Good Cache-Control for static assets (30d + immutable)"
else
  WRN "Suboptimal Cache-Control for static assets (recommend max-age=2592000, immutable)"
fi
if [[ -n "${AGE1}" && -n "${AGE2}" ]] && [[ "${AGE2}" =~ ^[0-9]+$ && "${AGE1}" =~ ^[0-9]+$ ]] && (( AGE2 >= AGE1 )); then
  OK "CDN appears to serve from cache (Age increasing)"
else
  WRN "CDN Age not detected/increasing (could be cold cache or CDN disabled)"
fi

#########################################
# 8) Backend Health
#########################################
hdr "Backend Health"
HEALTH="$(${GCLOUD[@]} compute backend-services get-health "$BACKEND" --global --format='get(status.healthStatus[0].healthState)' 2>/dev/null || true)"
if [[ "$HEALTH" == "HEALTHY" ]]; then
  OK "Backend HEALTHY"
else
  BAD "Backend health state: $(val_or_dash "$HEALTH")"
fi

#########################################
# 9) Firewall sanity
#########################################
hdr "Firewall"
OPEN_SSH="$(${GCLOUD[@]} compute firewall-rules list \
  --filter='direction=INGRESS AND allowed~tcp:22' \
  --format='value(name,sourceRanges,allowed)' 2>/dev/null | grep '0.0.0.0/0' || true)"
[[ -n "$OPEN_SSH" ]] && WRN "Found firewall rule allowing SSH from 0.0.0.0/0: ${OPEN_SSH} (prefer IAP only)" || OK "No wide-open SSH rules"

#########################################
# 10) WordPress wp-config.php checks (remote, optional)
#########################################
if (( FAST == 0 )) && [[ -n "${INSTANCE}" ]]; then
  hdr "WordPress wp-config.php checks (remote via IAP)"
  ${GCLOUD[@]} compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap --quiet --command '
set -u
FILE=/var/www/html/wp-config.php
if [[ ! -f "$FILE" ]]; then echo "[FAIL] wp-config.php missing"; exit 0; fi
grep -q "HTTP_X_FORWARDED_PROTO" "$FILE" && echo "[PASS] Handles HTTPS behind LB (X-Forwarded-Proto)" || echo "[FAIL] Missing handling of X-Forwarded-Proto"
grep -q "DISALLOW_FILE_EDIT" "$FILE" && echo "[PASS] DISALLOW_FILE_EDIT" || echo "[WARN] Dashboard file editor is enabled (recommend disabling)"
grep -q "FORCE_SSL_ADMIN" "$FILE" && echo "[PASS] FORCE_SSL_ADMIN" || echo "[WARN] Recommend FORCE_SSL_ADMIN"
' 2>/dev/null || true
else
  hdr "WordPress wp-config.php checks"
  WRN "Skipped remote wp-config checks (set --instance or run without --fast)"
fi

#########################################
# 11) Cloud Armor policy (if attached)
#########################################
hdr "Cloud Armor"
POLICY="$(${GCLOUD[@]} compute backend-services describe "$BACKEND" --global --format='value(securityPolicy)' 2>/dev/null || true)"
if [[ -n "$POLICY" ]]; then
  OK "Security Policy attached: $POLICY"
  if (( FAST == 0 )); then
    ${GCLOUD[@]} compute security-policies describe "$(basename "$POLICY")" \
      --format='table(name,rule[].priority,rule[].action,rule[].match.versionedExpr,rule[].match.expr.expression)' || true
  fi
else
  WRN "No Security Policy attached to backend (consider Cloud Armor WAF)"
fi

#########################################
# 12) HTTP/3 (QUIC)
#########################################
hdr "HTTP/3 (QUIC)"
if _curl --http3 -I "https://${DOMAIN}" >/dev/null 2>&1; then
  OK "HTTP/3 enabled"
else
  WRN "HTTP/3 not enabled (consider enabling QUIC on HTTPS proxy)"
fi

#########################################
# 13) Compression for static assets
#########################################
hdr "Compression (br/gzip)"
CE="$(_curl -I -H 'Accept-Encoding: br,gzip' "https://${DOMAIN}${ASSET_PATH}" | awk 'BEGIN{IGNORECASE=1}/^Content-Encoding:/{print $2}')"
if echo "$CE" | grep -qiE 'br|gzip'; then OK "Compression active (${CE})"; else WRN "No br/gzip compression detected for static assets"; fi

#########################################
# 14) Canonical host (www → apex)
#########################################
hdr "Canonical host"
R_CODE_WWW="$(_curl -I "http://www.${DOMAIN}" | awk 'NR==1{print $2}')"
LOC_WWW="$(_curl -I "http://www.${DOMAIN}" | awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2}')"
if echo "$R_CODE_WWW" | grep -Eq '^(301|308)$' && echo "$LOC_WWW" | grep -qi "^https://${DOMAIN}"; then
  OK "www redirects to canonical https://${DOMAIN}"
else
  WRN "www does not redirect to canonical (HTTP ${R_CODE_WWW} → $(val_or_dash "$LOC_WWW"))"
fi

#########################################
# 15) HTML should not be cached
#########################################
hdr "Cache-Control for HTML"
HDR_ROOT="$(_curl -I "https://${DOMAIN}/" || true)"
if echo "$HDR_ROOT" | grep -qi '^Content-Type:.*text/html'; then
  CC_ROOT="$(echo "$HDR_ROOT" | awk 'BEGIN{IGNORECASE=1}/^Cache-Control:/{print substr($0,16)}')"
  if echo "$CC_ROOT" | grep -qiE 'no-store|no-cache|private'; then
    OK "HTML response is not cached"
  else
    WRN "HTML appears cacheable: $(val_or_dash "$CC_ROOT")"
  fi
fi

#########################################
# 16) External IPs on instances (behind LB?)
#########################################
hdr "Instance External IPs"
HAS_EXT="$(${GCLOUD[@]} compute instances list --format='value(name,networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null | awk 'NF' || true)"
if [[ -n "$HAS_EXT" ]]; then
  WRN "Some instances have External IPs (prefer none behind LB/IAP)"
  echo "$HAS_EXT"
else
  OK "No instances with External IPs"
fi

#########################################
# Summary
#########################################
hdr "Summary"
printf "PASS=%d  WARN=%d  FAIL=%d\n" "$SUM_OK" "$SUM_WRN" "$SUM_BAD"
echo
printf "=== FAIL (fix first) ===\n"
if (( ${#FAIL_ITEMS[@]} == 0 )); then
  echo "None"
else
  i=1; for item in "${FAIL_ITEMS[@]}"; do printf "%2d) %s\n" "$i" "$item"; ((i++)); done
fi
echo
printf "=== WARN (improve next) ===\n"
if (( ${#WARN_ITEMS[@]} == 0 )); then
  echo "None"
else
  i=1; for item in "${WARN_ITEMS[@]}"; do printf "%2d) %s\n" "$i" "$item"; ((i++)); done
fi
echo
printf "(Script finished. Review the ordered lists above.)\n"
