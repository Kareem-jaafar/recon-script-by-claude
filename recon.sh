#!/usr/bin/env bash
# =============================================================================
# [reconBy-Ai.sh](http://reconby-ai.sh/) v5.2 — Professional Bug Bounty Recon Pipeline
# =============================================================================
# Usage:
#   ./reconBy-Ai.sh -d [example.com](http://example.com/)
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -p fast|balanced|thorough|stealth
fast اقصي سرعة واقل خفاء
balanced توازن بين السرعة و الخفاء
thorough تغطية عميقة وبطيئة
stealth  خفاء عالي جدا
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -s "subs,http,vuln"
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -w /path/to/wordlist.txt
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -x [http://127.0.0.1:8080](http://127.0.0.1:8080/)          # Burp proxy
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -P /path/to/proxies.txt           # Proxy list
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -n                                # dry-run
#   ./reconBy-Ai.sh -d [example.com](http://example.com/) -q                                # quiet
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# =============================================================================
# GLOBALS
# =============================================================================

SCRIPT_VERSION="5.2"
DOMAIN=""
OUTDIR=""
THREADS=""
RATE_LIMIT=""
PROFILE="balanced"
PROXY=""
PROXY_FILE=""
DRY_RUN=false
QUIET=false
ERRORS=0
START_TS=$(date +%s)
LOG_FILE="./recon.log"
WORDLIST="/home/kali/Downloads/SecLists/Discovery/Web-Content/raft-large-directories.txt"
CONFIG_FILE="${HOME}/.config/recon/recon.conf"
STAGES="subs,dns,http,crawl,params,fuzz,vuln,ports,files"
MAX_RETRIES=3
RETRY_DELAY=5
NUCLEI_CONC=15
HTML_REPORT=true
BLOCK_THRESHOLD=0.3        # 30% 403/429 triggers warning
RATE_ADAPTIVE=true         # Reduce rate on block detection

# =============================================================================
# COLORS
# =============================================================================

if [[ -t 1 ]]; then
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''
MAGENTA=''; BOLD=''; DIM=''; RESET=''
fi

# =============================================================================
# PROFILES  (threads / rate-limit / nuclei-concurrency / delay)
# =============================================================================

declare -A P_THREADS=( [fast]=100  [balanced]=50  [thorough]=20  [stealth]=10  )
declare -A P_RATE=(    [fast]=50   [balanced]=15  [thorough]=5   [stealth]=2   )
declare -A P_NCONC=(   [fast]=25   [balanced]=15  [thorough]=5   [stealth]=3   )
declare -A P_DELAY=(   [fast]=0    [balanced]=1   [thorough]=3   [stealth]=10  )

REQUIRED_TOOLS=(subfinder amass dnsx httpx gau katana ffuf nuclei naabu jq anew curl bc)

# =============================================================================
# LOGGING
# =============================================================================

ts()      { date '+%H:%M:%S'; }
log()      { [[ "$QUIET" == true ]] && return; printf "${BLUE}[]${RESET} ${DIM}$(_ts)${RESET} %s\n"    "$" | tee -a "$LOG_FILE"; }
info()     { [[ "$QUIET" == true ]] && return; printf "${CYAN}[+]${RESET} ${DIM}$(ts)${RESET} %s\n"    "$" | tee -a "$LOG_FILE"; }
success()  { printf "${GREEN}[✔]${RESET} ${DIM}$(_ts)${RESET} %s\n"    "$" | tee -a "$LOG_FILE"; }
warn()     { printf "${YELLOW}[!]${RESET} ${DIM}$(ts)${RESET} %s\n"   "$" | tee -a "$LOG_FILE"; }
error()    { printf "${RED}[✘]${RESET} ${DIM}$(_ts)${RESET} %s\n"      "$" | tee -a "$LOG_FILE"; ((ERRORS++)) || true; }
fatal()    { printf "${RED}[FATAL]${RESET} %s\n" "$" >&2; exit 1; }
section()  { printf "\n${BOLD}${MAGENTA}╔══ %s ══╗${RESET}\n\n" "$"; }

# =============================================================================
# HELPERS
# =============================================================================

count()   { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }
elapsed() { local s=$(( $(date +%s) - START_TS )); printf '%02dh:%02dm:%02ds' $((s/3600)) $(( (s%3600)/60 )) $((s%60)); }

stage_enabled() { [[ ",$STAGES," == ",$1," ]]; }

# Jitter sleep – base delay + random up to 5 seconds
jitter_sleep() {
local base=${1:-0}
local jitter=$(( RANDOM % 6 ))
(( base + jitter > 0 )) && sleep $(( base + jitter ))
}

pause() {
local delay="${P_DELAY[$PROFILE]:-1}"
jitter_sleep "$delay"
}

# =============================================================================
# RANDOM USER-AGENT & STEALTH HEADERS (returns raw headers, no -H)
# =============================================================================

random_ua() {
local -a agents=(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36"
)
echo "${agents[RANDOM % ${#agents[@]}]}"
}

# Outputs headers in "Key: Value" format, one per line
stealth_headers() {
local ua
ua=$(random_ua)
cat <<EOF
User-Agent: $ua
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,/;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
EOF
}

# Convert raw headers to -H "Key: Value" for tools like curl, ffuf, nuclei, httpx
build_header_args() {
local -n arr=$1
while IFS= read -r line; do
[[ -n "$line" ]] && arr+=(-H "$line")
done < <(stealth_headers)
}

# =============================================================================
# PROXY ROTATION
# =============================================================================

# Get a random proxy from file, or fallback to single proxy
get_proxy() {
if [[ -n "$PROXY_FILE" && -f "$PROXY_FILE" ]]; then
shuf -n 1 "$PROXY_FILE"
elif [[ -n "$PROXY" ]]; then
echo "$PROXY"
fi
}

# Build proxy args for tools that support it
proxy_args_curl() {
local p; p=$(get_proxy)
[[ -n "$p" ]] && echo "$p"
}
proxy_args_httpx() {
if [[ -n "$PROXY_FILE" && -f "$PROXY_FILE" ]]; then
# httpx supports -proxy-file for proxy list
echo "-proxy-file" "$PROXY_FILE"
elif [[ -n "$PROXY" ]]; then
echo "-proxy" "$PROXY"
fi
}
proxy_args_nuclei() {
if [[ -n "$PROXY_FILE" && -f "$PROXY_FILE" ]]; then
echo "-proxy-file" "$PROXY_FILE"
elif [[ -n "$PROXY" ]]; then
echo "-proxy" "$PROXY"
fi
}
proxy_args_ffuf() {
local p; p=$(get_proxy)
[[ -n "$p" ]] && echo "-x" "$p"
}

# =============================================================================
# BLOCK DETECTION & ADAPTIVE RATE
# =============================================================================

check_block() {
local httpx_json="$OUTDIR/http/httpx.json"
[[ -f "$httpx_json" ]] || return 0

local total blocked ratio
total=$(wc -l < "$httpx_json")
blocked=$(jq -r 'select(.status_code == 403 or .status_code == 429) | .status_code' "$httpx_json" | wc -l)

if (( total > 0 )); then
ratio=$(awk "BEGIN {printf \"%.2f\", $blocked/$total}")
if (( $(echo "$ratio > $BLOCK_THRESHOLD" | bc -l) )); then
warn "High block rate detected: $blocked/$total (${ratio}) — 403/429 ratio > ${BLOCK_THRESHOLD}"
if [[ "$RATE_ADAPTIVE" == true ]]; then
local old_rate=$RATE_LIMIT
RATE_LIMIT=$(( RATE_LIMIT / 2 ))
(( RATE_LIMIT < 1 )) && RATE_LIMIT=1
warn "Adaptive rate: reducing rate from $old_rate to $RATE_LIMIT"
fi
info "Pausing 60 seconds to cool down..."
sleep 60
if [[ -n "$PROXY_FILE" ]]; then
info "Rotating proxies – next requests will pick a different proxy"
else
info "Consider switching proxy or increasing stealth settings"
fi
fi
fi
}

# =============================================================================
# CLEANUP
# =============================================================================

cleanup() {
local code=$?
[[ $code -ne 0 ]] && warn "Pipeline interrupted (exit $code)"
jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT
trap 'fatal "SIGINT received"'  INT
trap 'fatal "SIGTERM received"' TERM

# =============================================================================
# RUN WRAPPER  — retries + timeout + optional delay
# =============================================================================

run() {
local label="$1"; shift
local cmd=("$@")

log "[$label] ${cmd[]}"

if [[ "$DRY_RUN" == true ]]; then
printf "${YELLOW}[dry-run]${RESET} %s\n" "${cmd[]}"
return 0
fi

local attempt=1 delay=$RETRY_DELAY

while (( attempt <= MAX_RETRIES )); do
if timeout 3600 "${cmd[@]}" >> "$LOG_FILE" 2>&1; then
success "$label completed"
pause
return 0
fi
(( attempt < MAX_RETRIES )) && {
warn "$label failed — retry ${attempt}/${MAX_RETRIES} in ${delay}s"
sleep "$delay"
delay=$((delay2))
}
((attempt++))
done

error "$label failed after $MAX_RETRIES attempts"
return 1
}

# =============================================================================
# CONFIG
# =============================================================================

load_config() {
local cfg="$1"
[[ -f "$cfg" ]] || return 0
while IFS='=' read -r key val; do
[[ "$key" =~ ^#.$ || -z "$key" ]] && continue
key="${key// /}"; val="${val// /}"
case "$key" in
DOMAIN)     [[ -z "$DOMAIN" ]]     && DOMAIN="$val" ;;
OUTDIR)     [[ -z "$OUTDIR" ]]     && OUTDIR="$val" ;;
THREADS)    [[ -z "$THREADS" ]]    && THREADS="$val" ;;
RATE_LIMIT) [[ -z "$RATE_LIMIT" ]] && RATE_LIMIT="$val" ;;
PROXY)      [[ -z "$PROXY" ]]      && PROXY="$val" ;;
PROXY_FILE) [[ -z "$PROXY_FILE" ]] && PROXY_FILE="$val" ;;
PROFILE)    PROFILE="$val" ;;
WORDLIST)   WORDLIST="$val" ;;
STAGES)     STAGES="$val" ;;
esac
done < "$cfg"
}

# =============================================================================
# ARGS
# =============================================================================

usage() {
cat <<EOF

${BOLD}[reconBy-Ai.sh](http://reconby-ai.sh/) v${SCRIPT_VERSION}${RESET} — Professional Bug Bounty Recon Pipeline

${BOLD}Usage:${RESET}
$0 -d [target.com](http://target.com/) [options]

${BOLD}Options:${RESET}
-d DOMAIN      Target domain (required)
-o OUTDIR      Output directory
-t THREADS     Thread count (overrides profile)
-r RATE        Rate limit (req/sec, overrides profile)
-p PROFILE     fast | balanced | thorough | stealth  (default: balanced)
-s STAGES      Comma-separated: subs,dns,http,crawl,params,fuzz,vuln,ports,files
-w WORDLIST    Custom wordlist path
-x PROXY       HTTP proxy (e.g. [http://127.0.0.1:8080](http://127.0.0.1:8080/))
-P PROXY_FILE  File containing proxy list (one per line) – enables rotation
-c CONFIG      Config file path
-n             Dry-run (print commands, don't execute)
-q             Quiet mode
-h             Show this help

${BOLD}Profiles:${RESET}
fast      — High speed, more resource usage
balanced  — Default, good coverage
thorough  — Slow, deep coverage
stealth   — Low & slow, minimal footprint, random UA & browser headers

${BOLD}Examples:${RESET}
$0 -d [example.com](http://example.com/)
$0 -d [example.com](http://example.com/) -p stealth
$0 -d [example.com](http://example.com/) -s "subs,http,vuln"
$0 -d [example.com](http://example.com/) -x [http://127.0.0.1:8080](http://127.0.0.1:8080/)
$0 -d [example.com](http://example.com/) -P proxies.txt

EOF
}

parse_args() {
load_config "$CONFIG_FILE"

while getopts ":d:o:t:r:w:s:p:c:x:P:nqh" opt; do
case $opt in
d) DOMAIN="$OPTARG" ;;
o) OUTDIR="$OPTARG" ;;
t) THREADS="$OPTARG" ;;
r) RATE_LIMIT="$OPTARG" ;;
w) WORDLIST="$OPTARG" ;;
s) STAGES="$OPTARG" ;;
p) PROFILE="$OPTARG" ;;
c) load_config "$OPTARG" ;;
x) PROXY="$OPTARG" ;;
P) PROXY_FILE="$OPTARG" ;;
n) DRY_RUN=true ;;
q) QUIET=true ;;
h) usage; exit 0 ;;
:) fatal "Missing argument for -$OPTARG" ;;
\?) fatal "Unknown option: -$OPTARG" ;;
esac
done

[[ -z "$DOMAIN" ]] && { usage; fatal "Target domain is required (-d)"; }

DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"

[[ -v "P_THREADS[$PROFILE]" ]] || fatal "Invalid profile: $PROFILE. Use: fast|balanced|thorough|stealth"

THREADS="${THREADS:-${P_THREADS[$PROFILE]}}"
RATE_LIMIT="${RATE_LIMIT:-${P_RATE[$PROFILE]}}"
NUCLEI_CONC="${P_NCONC[$PROFILE]}"

[[ -z "$OUTDIR" ]] && OUTDIR="$(pwd)/recon${DOMAIN//./}$(date +%Y%m%d_%H%M%S)"

if [[ ! -f "$WORDLIST" ]]; then
warn "Wordlist not found: $WORDLIST"
WORDLIST=""
fi
}

# =============================================================================
# BANNER
# =============================================================================

banner() {
printf "\n${BOLD}${CYAN}"
cat <<'EOF'
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
EOF
printf "${RESET}\n"
printf "  ${BOLD}Target:${RESET}  %s\n"   "$DOMAIN"
printf "  ${BOLD}Profile:${RESET} %s\n"   "$PROFILE"
printf "  ${BOLD}Stages:${RESET}  %s\n"   "$STAGES"
printf "  ${BOLD}Threads:${RESET} %s\n"   "$THREADS"
printf "  ${BOLD}Rate:${RESET}    %s/s\n" "$RATE_LIMIT"
[[ -n "$PROXY" ]]      && printf "  ${BOLD}Proxy:${RESET}   %s\n" "$PROXY"
[[ -n "$PROXY_FILE" ]] && printf "  ${BOLD}Proxy list:${RESET} %s\n" "$PROXY_FILE"
printf "  ${BOLD}Output:${RESET}  %s\n\n" "$OUTDIR"
}

# =============================================================================
# DEPENDENCIES
# =============================================================================

check_dependencies() {
section "Dependency Check"
local missing=()
for tool in "${REQUIRED_TOOLS[@]}"; do
if command -v "$tool" &>/dev/null; then
info "$tool ✓"
else
error "$tool ✗ (missing)"
missing+=("$tool")
fi
done
if (( ${#missing[@]} > 0 )); then
fatal "Missing tools: ${missing[]}"
fi
}

# =============================================================================
# SETUP
# =============================================================================

setup() {
mkdir -p \
"$OUTDIR/subs" "$OUTDIR/dns" "$OUTDIR/http" "$OUTDIR/crawl" \
"$OUTDIR/params" "$OUTDIR/fuzz" "$OUTDIR/vuln" "$OUTDIR/ports" \
"$OUTDIR/files" "$OUTDIR/logs" "$OUTDIR/report"

LOG_FILE="$OUTDIR/logs/recon.log"
touch "$LOG_FILE"

success "Workspace: $OUTDIR"
info "Log: $LOG_FILE"
}

# =============================================================================
# STAGE: SUBDOMAINS
# =============================================================================

stage_subs() {
stage_enabled "subs" || return 0
section "Subdomain Enumeration"

run "subfinder" \
subfinder -d "$DOMAIN" -all -recursive -silent \
-t "$THREADS" -o "$OUTDIR/subs/subfinder.txt"

run "amass" \
amass enum -passive -d "$DOMAIN" \
-o "$OUTDIR/subs/amass.txt"

if [[ "$DRY_RUN" == false ]]; then
cat "$OUTDIR/subs/subfinder.txt" "$OUTDIR/subs/amass.txt" 2>/dev/null \
| grep -v '^$' | sort -u > "$OUTDIR/subs/all_subs.txt"
success "Total subdomains: $(count "$OUTDIR/subs/all_subs.txt")"
fi
}

# =============================================================================
# STAGE: DNS RESOLUTION
# =============================================================================

stage_dns() {
stage_enabled "dns" || return 0
section "DNS Resolution"

local input="$OUTDIR/subs/all_subs.txt"
[[ -s "$input" ]] || { warn "No subdomains found — skipping DNS"; return 0; }

run "dnsx" \
dnsx -l "$input" -silent -json \
-a -aaaa -cname -mx -txt \
-o "$OUTDIR/dns/dns.json"

if [[ -f "$OUTDIR/dns/dns.json" ]]; then
jq -r '.host // empty' "$OUTDIR/dns/dns.json" 2>/dev/null \
| sort -u > "$OUTDIR/dns/resolved.txt" || true

jq -r 'select(.cname != null) | "\(.host) -> \(.cname[])"' \
"$OUTDIR/dns/dns.json" 2>/dev/null \
| sort -u > "$OUTDIR/dns/cnames.txt" || true

success "Resolved: $(count "$OUTDIR/dns/resolved.txt")"
info "CNAMEs: $(count "$OUTDIR/dns/cnames.txt")"
fi
}

# =============================================================================
# STAGE: HTTP PROBING
# =============================================================================

stage_http() {
stage_enabled "http" || return 0
section "HTTP Probe"

local input="$OUTDIR/dns/resolved.txt"
[[ -s "$input" ]] || { warn "No resolved hosts — skipping HTTP"; return 0; }

local proxy_args; proxy_args=$(proxy_args_httpx)

# Build header arguments for httpx if in stealth mode
local extra_hdrs=()
if [[ "$PROFILE" == "stealth" ]]; then
build_header_args extra_hdrs
fi

# shellcheck disable=SC2046
run "httpx" \
httpx -l "$input" \
-title -tech-detect -status-code \
-content-length -web-server -follow-redirects \
-silent -json \
$proxy_args \
"${extra_hdrs[@]}" \
-threads "$THREADS" \
-rate-limit "$RATE_LIMIT" \
-o "$OUTDIR/http/httpx.json"

if [[ -f "$OUTDIR/http/httpx.json" ]]; then
jq -r '.url // empty' "$OUTDIR/http/httpx.json" 2>/dev/null \
| sort -u > "$OUTDIR/http/live_hosts.txt" || true

for code in 200 301 302 401 403; do
jq -r "select(.status_code == $code) | .url // empty" \
"$OUTDIR/http/httpx.json" 2>/dev/null \
| sort -u > "$OUTDIR/http/status_${code}.txt" || true
done

success "Live hosts: $(count "$OUTDIR/http/live_hosts.txt")"
info "200: $(count "$OUTDIR/http/status_200.txt")  401/403: $(( $(count "$OUTDIR/http/status_401.txt") + $(count "$OUTDIR/http/status_403.txt") ))"
fi

# Block detection (may adapt rate)
check_block
}

# =============================================================================
# STAGE: CRAWLING
# =============================================================================

stage_crawl() {
stage_enabled "crawl" || return 0
section "Crawling & URL Collection"

local live="$OUTDIR/http/live_hosts.txt"
[[ -s "$live" ]] || { warn "No live hosts — skipping crawl"; return 0; }

if [[ "$DRY_RUN" == false ]]; then
gau --subs "$DOMAIN" 2>/dev/null \
| sort -u > "$OUTDIR/crawl/gau.txt" || true
info "GAU URLs: $(count "$OUTDIR/crawl/gau.txt")"
else
log "[dry-run] gau --subs $DOMAIN"
fi

run "katana" \
katana -list "$live" \
-depth 3 -silent \
-js-crawl -form-extraction \
-o "$OUTDIR/crawl/katana.txt"

if [[ "$DRY_RUN" == false ]]; then
cat "$OUTDIR/crawl/gau.txt" "$OUTDIR/crawl/katana.txt" 2>/dev/null \
| sort -u > "$OUTDIR/crawl/all_urls.txt"

grep '=' "$OUTDIR/crawl/all_urls.txt" \
> "$OUTDIR/params/urls_with_params.txt" || true

grep -iE '\.js(\?|$)' "$OUTDIR/crawl/all_urls.txt" \
> "$OUTDIR/crawl/js_files.txt" || true

success "Total URLs: $(count "$OUTDIR/crawl/all_urls.txt")"
info "JS files: $(count "$OUTDIR/crawl/js_files.txt")"
fi
}

# =============================================================================
# STAGE: PARAMS
# =============================================================================

stage_params() {
stage_enabled "params" || return 0
section "Parameter Analysis"

local pfile="$OUTDIR/params/urls_with_params.txt"
[[ -s "$pfile" ]] || { warn "No parameterized URLs found"; return 0; }

if [[ "$DRY_RUN" == false ]]; then
grep -oP '(?<=\?|&)[^=&]+(?==)' "$pfile" 2>/dev/null \
| sort | uniq -c | sort -rn \
> "$OUTDIR/params/param_names.txt" || true
fi

success "Parameterized URLs: $(count "$pfile")"
info "Unique param names: $(count "$OUTDIR/params/param_names.txt")"
}

# =============================================================================
# STAGE: FUZZING (with wordlist chunking for stealth)
# =============================================================================

stage_fuzz() {
stage_enabled "fuzz" || return 0
section "Directory Fuzzing"

[[ -n "$WORDLIST" ]] || { warn "No wordlist — skipping fuzz"; return 0; }

local live="$OUTDIR/http/live_hosts.txt"
[[ -s "$live" ]] || { warn "No live hosts — skipping fuzz"; return 0; }

local recursion_args=()
[[ "$PROFILE" == "thorough" ]] && recursion_args=(-recursion -recursion-depth 2)

# For stealth, add delay between requests
local delay_args=()
if [[ "$PROFILE" == "stealth" ]]; then
delay_args=(-delay "1-3")
fi

# Build stealth headers as ffuf arguments
local stealth_flag=()
if [[ "$PROFILE" == "stealth" ]]; then
while IFS= read -r line; do
[[ -n "$line" ]] && stealth_flag+=(-H "$line")
done < <(stealth_headers)
fi

while IFS= read -r host; do
[[ -z "$host" ]] && continue

local safe
safe=$(printf '%s' "$host" | sed 's|https\?://||g' | tr '/:.' '')

# Baseline
local baseline=0
if [[ "$DRY_RUN" == false ]]; then
baseline=$(curl -sk --connect-timeout 5 --max-time 10 \
-o /dev/null -w "%{size_download}" \
"${host}/this_path_does_not_exist_404$(date +%s)" \
2>/dev/null || echo 0)
fi

local proxy_ffuf; proxy_ffuf=$(proxy_args_ffuf)

# If wordlist is large and profile is stealth, split into chunks
local wordlist_to_use="$WORDLIST"
if [[ "$PROFILE" == "stealth" && -f "$WORDLIST" ]]; then
local chunk_dir="$OUTDIR/fuzz/chunks_${safe}"
mkdir -p "$chunk_dir"
split -l 2000 "$WORDLIST" "$chunk_dir/chunk_"
local chunks=( "$chunk_dir"/chunk_ )
info "Stealth mode: split wordlist into ${#chunks[@]} chunks of 2000 lines each"

for chunk in "${chunks[@]}"; do
run "ffuf-${safe}-$(basename "$chunk")" \
ffuf \
-u "${host}/FUZZ" \
-w "$chunk" \
-mc 200,204,301,302,307,401,403 \
-fs "$baseline" \
-t "$THREADS" \
-timeout 10 \
-rate "$RATE_LIMIT" \
"${recursion_args[@]}" \
"${delay_args[@]}" \
"${stealth_flag[@]}" \
$proxy_ffuf \
-of json \
-o "$OUTDIR/fuzz/${safe}_$(basename "$chunk").json" \
-s
jitter_sleep 10  # rest between chunks
done
else
run "ffuf-$safe" \
ffuf \
-u "${host}/FUZZ" \
-w "$wordlist_to_use" \
-mc 200,204,301,302,307,401,403 \
-fs "$baseline" \
-t "$THREADS" \
-timeout 10 \
-rate "$RATE_LIMIT" \
"${recursion_args[@]}" \
"${delay_args[@]}" \
"${stealth_flag[@]}" \
$proxy_ffuf \
-of json \
-o "$OUTDIR/fuzz/${safe}.json" \
-s
fi

done < "$live"

if [[ "$DRY_RUN" == false ]]; then
find "$OUTDIR/fuzz" -name "*.json" 2>/dev/null \
| xargs -r jq -r '.results[]? | [.status,.length,.url] | @tsv' 2>/dev/null \
| sort -u > "$OUTDIR/fuzz/all_findings.tsv" || true
fi

success "Fuzz findings: $(count "$OUTDIR/fuzz/all_findings.tsv")"
}

# =============================================================================
# STAGE: VULNERABILITY SCAN (NUCLEI)
# =============================================================================

stage_vuln() {
stage_enabled "vuln" || return 0
section "Nuclei Vulnerability Scan"

local live="$OUTDIR/http/live_hosts.txt"
[[ -s "$live" ]] || { warn "No live hosts — skipping nuclei"; return 0; }

if [[ "$DRY_RUN" == false ]]; then
timeout 300 nuclei -update-templates -silent >> "$LOG_FILE" 2>&1 \
|| warn "Template update skipped"
fi

local proxy_args; proxy_args=$(proxy_args_nuclei)

local extra_hdrs=()
if [[ "$PROFILE" == "stealth" ]]; then
build_header_args extra_hdrs
fi

# shellcheck disable=SC2046
run "nuclei" \
nuclei \
-l "$live" \
-rl "$RATE_LIMIT" \
-c "$NUCLEI_CONC" \
-timeout 15 \
-retries 2 \
-silent \
-json \
$proxy_args \
"${extra_hdrs[@]}" \
-o "$OUTDIR/vuln/nuclei.json"

if [[ -f "$OUTDIR/vuln/nuclei.json" ]]; then
jq -r '[.info.severity, .info.name, .matched_at] | @tsv' \
"$OUTDIR/vuln/nuclei.json" 2>/dev/null \
| sort -u > "$OUTDIR/vuln/all_findings.tsv" || true

for sev in critical high medium low info; do
jq -r "select(.info.severity == \"$sev\") | [.info.name, .matched_at] | @tsv" \
"$OUTDIR/vuln/nuclei.json" 2>/dev/null \
| sort -u > "$OUTDIR/vuln/${sev}.tsv" || true
done

success "Nuclei findings: $(count "$OUTDIR/vuln/all_findings.tsv")"
info "Critical: $(count "$OUTDIR/vuln/critical.tsv")  High: $(count "$OUTDIR/vuln/high.tsv")  Medium: $(count "$OUTDIR/vuln/medium.tsv")"
fi
}

# =============================================================================
# STAGE: PORT SCANNING
# =============================================================================

stage_ports() {
stage_enabled "ports" || return 0
section "Port Scanning"

local input="$OUTDIR/dns/resolved.txt"
[[ -s "$input" ]] || { warn "No resolved hosts — skipping ports"; return 0; }

run "naabu" \
naabu \
-l "$input" \
-silent \
-exclude-cdn \
-rate "$RATE_LIMIT" \
-o "$OUTDIR/ports/naabu.txt"

success "Open ports: $(count "$OUTDIR/ports/naabu.txt")"
}

# =============================================================================
# STAGE: SENSITIVE FILES (Safe curl array)
# =============================================================================

stage_files() {
stage_enabled "files" || return 0
section "Sensitive File Detection"

local live="$OUTDIR/http/live_hosts.txt"
[[ -s "$live" ]] || { warn "No live hosts — skipping files"; return 0; }

local patterns=(
".git/config" ".env" ".env.backup" ".env.local"
"config.php" "wp-config.php" "config.yml" "config.json"
"backup.zip" "backup.tar.gz" "db.sql" "database.sql"
"robots.txt" "sitemap.xml" ".htaccess"
"phpinfo.php" "info.php" "test.php"
"/.well-known/security.txt"
"/api/swagger.json" "/api/openapi.json" "/swagger.json"
"/actuator" "/actuator/env" "/actuator/mappings"
)

# Build base curl arguments (without headers/proxy, will be added per request)
local curl_base=(-sk --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}")

# Add stealth headers if applicable
if [[ "$PROFILE" == "stealth" ]]; then
while IFS= read -r header; do
[[ -n "$header" ]] && curl_base+=(-H "$header")
done < <(stealth_headers)
fi

while IFS= read -r host; do
[[ -z "$host" ]] && continue
for pattern in "${patterns[@]}"; do
local url="${host}/${pattern#/}"
if [[ "$DRY_RUN" == false ]]; then
local curl_cmd=("${curl_base[@]}")
# Add proxy (random if proxy file)
local proxy_val; proxy_val=$(get_proxy)
[[ -n "$proxy_val" ]] && curl_cmd+=(-x "$proxy_val")
curl_cmd+=("$url")

local status
status=$(curl "${curl_cmd[@]}" 2>/dev/null || echo 0)
if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]]; then
echo "${status}    ${url}" >> "$OUTDIR/files/found.txt"
fi
else
log "[dry-run] CHECK $url"
fi
done
done < "$live"

success "Sensitive files found: $(count "$OUTDIR/files/found.txt")"
}

# =============================================================================
# HTML REPORT
# =============================================================================

generate_html_report() {
[[ "$HTML_REPORT" == false || "$DRY_RUN" == true ]] && return 0

local report="$OUTDIR/report/index.html"
local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

info "Generating HTML report..."

cat > "$report" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — ${DOMAIN}</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
h1 { color: #58a6ff; margin-bottom: 10px; }
h2 { color: #79c0ff; margin: 20px 0 10px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
.meta { color: #8b949e; font-size: 0.85em; margin-bottom: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; text-align: center; }
.card .num { font-size: 2em; font-weight: bold; color: #58a6ff; }
.card .lbl { font-size: 0.8em; color: #8b949e; margin-top: 4px; }
.sev-critical { color: #f85149; } .sev-high { color: #e3b341; }
.sev-medium   { color: #d29922; } .sev-low  { color: #3fb950; }
pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 0.8em; max-height: 300px; }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85em; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #21262d; }
th { background: #161b22; color: #8b949e; }
</style>
</head>
<body>
<h1>🔍 Recon Report — ${DOMAIN}</h1>
<p class="meta">Generated: ${ts} | Profile: ${PROFILE} | Duration: $(elapsed)</p>

<h2>Summary</h2>
<div class="grid">
<div class="card"><div class="num">$(count "$OUTDIR/subs/all_subs.txt")</div><div class="lbl">Subdomains</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/dns/resolved.txt")</div><div class="lbl">Resolved</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/http/live_hosts.txt")</div><div class="lbl">Live Hosts</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/crawl/all_urls.txt")</div><div class="lbl">URLs</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/params/urls_with_params.txt")</div><div class="lbl">Parameters</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/fuzz/all_findings.tsv")</div><div class="lbl">Fuzz Findings</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/vuln/all_findings.tsv")</div><div class="lbl">Nuclei Findings</div></div>
<div class="card"><div class="num">$(count "$OUTDIR/ports/naabu.txt")</div><div class="lbl">Open Ports</div></div>
</div>

<h2>Nuclei Findings</h2>
$(if [[ -f "$OUTDIR/vuln/all_findings.tsv" && -s "$OUTDIR/vuln/all_findings.tsv" ]]; then
echo '<table><tr><th>Severity</th><th>Name</th><th>Matched At</th></tr>'
while IFS=$'\t' read -r sev name url; do
echo "<tr><td class=\"sev-${sev}\">${sev}</td><td>${name}</td><td>${url}</td></tr>"
done < "$OUTDIR/vuln/all_findings.tsv"
echo '</table>'
else
echo '<p style="color:#8b949e">No findings.</p>'
fi)

<h2>Live Hosts</h2>
<pre>$(cat "$OUTDIR/http/live_hosts.txt" 2>/dev/null | head -100 || echo "none")</pre>

<h2>Sensitive Files</h2>
<pre>$(cat "$OUTDIR/files/found.txt" 2>/dev/null || echo "none")</pre>

<h2>CNAMEs (Potential Takeover)</h2>
<pre>$(cat "$OUTDIR/dns/cnames.txt" 2>/dev/null | head -50 || echo "none")</pre>

</body>
</html>
HTML

success "HTML report: $report"
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
printf "\n${BOLD}${CYAN}╔══════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${CYAN}║           RECON SUMMARY              ║${RESET}\n"
printf "${BOLD}${CYAN}╚══════════════════════════════════════╝${RESET}\n\n"

printf "  %-22s %s\n" "Target:"        "$DOMAIN"
printf "  %-22s %s\n" "Subdomains:"    "$(count "$OUTDIR/subs/all_subs.txt")"
printf "  %-22s %s\n" "Resolved Hosts:""$(count "$OUTDIR/dns/resolved.txt")"
printf "  %-22s %s\n" "Live Hosts:"    "$(count "$OUTDIR/http/live_hosts.txt")"
printf "  %-22s %s\n" "Total URLs:"    "$(count "$OUTDIR/crawl/all_urls.txt")"
printf "  %-22s %s\n" "Parameters:"    "$(count "$OUTDIR/params/urls_with_params.txt")"
printf "  %-22s %s\n" "Fuzz Findings:" "$(count "$OUTDIR/fuzz/all_findings.tsv")"
printf "  %-22s %s\n" "Vuln Findings:" "$(count "$OUTDIR/vuln/all_findings.tsv")"

if [[ -f "$OUTDIR/vuln/all_findings.tsv" ]]; then
printf "    ${RED}Critical:${RESET} $(count "$OUTDIR/vuln/critical.tsv")  "
printf "${YELLOW}High:${RESET} $(count "$OUTDIR/vuln/high.tsv")  "
printf "${YELLOW}Medium:${RESET} $(count "$OUTDIR/vuln/medium.tsv")\n"
fi

printf "  %-22s %s\n" "Open Ports:"    "$(count "$OUTDIR/ports/naabu.txt")"
printf "  %-22s %s\n" "Sensitive Files:""$(count "$OUTDIR/files/found.txt")"
printf "  %-22s %s\n" "CNAMEs:"        "$(count "$OUTDIR/dns/cnames.txt")"
printf "  %-22s %s\n" "Duration:"      "$(elapsed)"
printf "  %-22s %s\n" "Errors:"        "$ERRORS"
printf "\n  ${BOLD}Output:${RESET}  %s\n"   "$OUTDIR"
printf "  ${BOLD}Log:${RESET}     %s\n"     "$LOG_FILE"
printf "  ${BOLD}Report:${RESET}  %s\n\n"   "$OUTDIR/report/index.html"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
parse_args "$@"
banner
check_dependencies
setup
stage_subs
stage_dns
stage_http
stage_crawl
stage_params
stage_fuzz
stage_vuln
stage_ports
stage_files
generate_html_report
print_summary
}

main "$@"
