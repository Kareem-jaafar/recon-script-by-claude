#!/usr/bin/env bash
# =============================================================================
#  [recon.sh](http://recon.sh/) — Modular Offensive Reconnaissance Pipeline
#  Author  : Senior Security Engineer
#  Version : 2.0.0
#  License : MIT
# =============================================================================
#
#  USAGE:
#    chmod +x [recon.sh](http://recon.sh/)
#    ./recon.sh -d [target.com](http://target.com/) [OPTIONS]
#
#  OPTIONS:
#    -d  DOMAIN     Target domain (required)
#    -o  OUTDIR     Output directory (default: ./recon_<domain><timestamp>)
#    -t  THREADS    Thread count for tools (default: 50)
#    -r  RATE       Nuclei rate limit – requests/sec (default: 10)
#    -w  WORDLIST   Custom wordlist path for ffuf (default: SecLists raft-large)
#    -s  STAGES     Comma-separated stages to run (default: all)
#                   Available: subs,dns,http,crawl,params,fuzz,vuln,ports,files
#    -p  PROFILE    Speed profile: fast | balanced | thorough (default: balanced)
#    -n             Dry-run mode – print commands without executing
#    -q             Quiet mode – suppress banner and progress messages
#    -h             Show this help message
#
#  DEPENDENCIES (auto-checked at startup):
#    Required : subfinder, amass, dnsx, httpx, gau, katana,
#               dalfox, ffuf, nuclei, naabu, anew
#    Optional : nmap, waybackurls, gf, unfurl, notify
#
#  EXAMPLES:
#    ./recon.sh -d [example.com](http://example.com/)
#    ./recon.sh -d [example.com](http://example.com/) -p thorough -t 100 -r 5
#    ./recon.sh -d [example.com](http://example.com/) -s subs,dns,http -n
#    ./recon.sh -d [example.com](http://example.com/) -o /tmp/bugbounty -w ~/wordlists/custom.txt
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 0 — GLOBAL CONSTANTS & COLOUR PALETTE
# ─────────────────────────────────────────────────────────────────────────────

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly START_TS=$(date +%s)
readonly START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Terminal colours (disabled automatically when not a TTY)
if [[ -t 1 ]]; then
RED='\033[0;31m';   YELLOW='\033[0;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';   BOLD='\033[1m'
DIM='\033[2m';      RESET='\033[0m'
else
RED=''; YELLOW=''; GREEN=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — DEFAULT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN=""
OUTDIR=""
THREADS=50
RATE_LIMIT=10
WORDLIST="/opt/SecLists/Discovery/Web-Content/raft-large-words.txt"
FALLBACK_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
STAGES="subs,dns,http,crawl,params,fuzz,vuln,ports,files"
PROFILE="balanced"
DRY_RUN=false
QUIET=false
LOG_FILE=""       # set after OUTDIR is determined
ERRORS=0          # incremented on non-fatal errors

# Profile-based concurrency presets (threads, nuclei_concurrency, nuclei_rate)
declare -A PROFILE_THREADS=( [fast]=100 [balanced]=50  [thorough]=20  )
declare -A PROFILE_NCONC=(   [fast]=25  [balanced]=15  [thorough]=5   )
declare -A PROFILE_NRATE=(   [fast]=30  [balanced]=10  [thorough]=3   )

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

# ── Logging ──────────────────────────────────────────────────────────────────

log()      { [[ "$QUIET" == false ]] && printf "${BOLD}[]${RESET} %s\n" "$" | tee -a "$LOG_FILE"; }
info()     { [[ "$QUIET" == false ]] && printf "${CYAN}[+]${RESET} %s\n" "$" | tee -a "$LOG_FILE"; }
success()  { printf "${GREEN}[✔]${RESET} %s\n" "$" | tee -a "$LOG_FILE"; }
warn()     { printf "${YELLOW}[!]${RESET} %s\n" "$" | tee -a "$LOG_FILE" >&2; }
error()    { printf "${RED}[✘]${RESET} %s\n" "$" | tee -a "$LOG_FILE" >&2; (( ERRORS++ )) || true; }
fatal()    { printf "${RED}${BOLD}[FATAL]${RESET} %s\n" "$" >&2; exit 1; }
section()  {
local title="$"
local line
printf -v line '%0.s─' {1..60}
[[ "$QUIET" == false ]] && printf "\n${BOLD}${BLUE}%s\n  %s\n%s${RESET}\n\n" "$line" "$title" "$line" | tee -a "$LOG_FILE"
}

# ── Command executor ──────────────────────────────────────────────────────────
# Wraps every tool call: logs the command, respects dry-run, captures errors.

run() {
local label="$1"; shift
local cmd=("$@")

log "Running: ${DIM}${cmd[]}${RESET}"

if [[ "$DRY_RUN" == true ]]; then
printf "${YELLOW}  [dry-run] Would execute:${RESET} %s\n" "${cmd[]}" | tee -a "$LOG_FILE"
return 0
fi

local start_s; start_s=$(date +%s)

if ! "${cmd[@]}" >> "$LOG_FILE" 2>&1; then
error "$label failed (exit $?). Check $LOG_FILE for details."
return 1
fi

local elapsed=$(( $(date +%s) - start_s ))
success "$label completed in ${elapsed}s"
}

# ── Stage guard ───────────────────────────────────────────────────────────────
# Returns 0 if the given stage is in the active stage list.

stage_enabled() {
local stage="$1"
[[ ",$STAGES," == ",$stage," ]]
}

# ── Count lines in a file safely ──────────────────────────────────────────────

count_lines() {
local f="$1"
[[ -f "$f" ]] && wc -l < "$f" || echo 0
}

# ── Elapsed time formatter ────────────────────────────────────────────────────

elapsed_pretty() {
local secs=$(( $(date +%s) - START_TS ))
printf '%02dh %02dm %02ds' $(( secs/3600 )) $(( (secs%3600)/60 )) $(( secs%60 ))
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — CLEANUP TRAP
# ─────────────────────────────────────────────────────────────────────────────

cleanup() {
local exit_code=$?
local elapsed; elapsed=$(elapsed_pretty)

if [[ $exit_code -ne 0 ]]; then
printf "\n${RED}${BOLD}[!] Script interrupted (exit code: %d) after %s${RESET}\n" \
"$exit_code" "$elapsed" >&2
printf "${YELLOW}    Partial output preserved in: %s${RESET}\n" "$OUTDIR" >&2
printf "${YELLOW}    Full log: %s${RESET}\n" "$LOG_FILE" >&2
fi

# Kill any background jobs spawned by this script
jobs -p | xargs -r kill 2>/dev/null || true
}

trap cleanup EXIT
trap 'fatal "Caught SIGINT — aborting."' INT
trap 'fatal "Caught SIGTERM — aborting."' TERM

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — ARGUMENT PARSING & VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

usage() {
grep '^#  ' "${BASH_SOURCE[0]}" | sed 's/^#  //'
exit 0
}

parse_args() {
[[ $# -eq 0 ]] && usage

while getopts ":d:o:t:r:w:s:p:nqh" opt; do
case $opt in
d) DOMAIN="$OPTARG"   ;;
o) OUTDIR="$OPTARG"   ;;
t) THREADS="$OPTARG"  ;;
r) RATE_LIMIT="$OPTARG" ;;
w) WORDLIST="$OPTARG" ;;
s) STAGES="$OPTARG"   ;;
p) PROFILE="$OPTARG"  ;;
n) DRY_RUN=true       ;;
q) QUIET=true         ;;
h) usage              ;;
:) fatal "Option -$OPTARG requires an argument." ;;
\?) fatal "Unknown option: -$OPTARG. Use -h for help." ;;
esac
done

# Validate required arguments
[[ -z "$DOMAIN" ]] && fatal "Target domain is required. Use -d <domain>"

# Strip protocol if user accidentally passed a URL
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

# Apply profile presets (CLI flags override profile if both given)
[[ -n "${PROFILE_THREADS[$PROFILE]+}" ]] || fatal "Invalid profile '$PROFILE'. Choose: fast | balanced | thorough"
THREADS="${PROFILE_THREADS[$PROFILE]}"
local n_conc="${PROFILE_NCONC[$PROFILE]}"
local n_rate="${PROFILE_NRATE[$PROFILE]}"
# Allow CLI -t / -r to override profile
[[ "$THREADS"    == "${PROFILE_THREADS[$PROFILE]}" ]] || true  # already set by -t
[[ "$RATE_LIMIT" == "${PROFILE_NRATE[$PROFILE]}"   ]] || n_rate="$RATE_LIMIT"
RATE_LIMIT="$n_rate"
NUCLEI_CONCURRENCY="$n_conc"

# Set output directory
if [[ -z "$OUTDIR" ]]; then
OUTDIR="$(pwd)/recon_${DOMAIN//./}$(date +%Y%m%d_%H%M%S)"
fi

# Validate stages
local valid_stages="subs dns http crawl params fuzz vuln ports files"
IFS=',' read -ra stage_list <<< "$STAGES"
for s in "${stage_list[@]}"; do
[[ " $valid_stages " == " $s " ]] || fatal "Unknown stage '$s'. Valid: $valid_stages"
done
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — TOOL DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_TOOLS=( subfinder amass dnsx httpx gau katana dalfox ffuf nuclei naabu anew )
OPTIONAL_TOOLS=( nmap waybackurls gf unfurl notify )

check_dependencies() {
section "Dependency Check"

local missing_required=()
local missing_optional=()

for tool in "${REQUIRED_TOOLS[@]}"; do
if command -v "$tool" &>/dev/null; then
info "  ✔  $tool $(${tool} --version 2>/dev/null | head -1 || true)"
else
error "  ✘  $tool — NOT FOUND (required)"
missing_required+=("$tool")
fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
if command -v "$tool" &>/dev/null; then
info "  ○  $tool $(${tool} --version 2>/dev/null | head -1 || true)"
else
warn "  ○  $tool — not found (optional, some steps will be skipped)"
missing_optional+=("$tool")
fi
done

if [[ ${#missing_required[@]} -gt 0 ]]; then
fatal "Missing required tools: ${missing_required[]}\n\
Install via:\n\
go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\](http://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest%5Cn%5C)
go install -v [github.com/projectdiscovery/dnsx/cmd/dnsx@latest\n\](http://github.com/projectdiscovery/dnsx/cmd/dnsx@latest%5Cn%5C)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest\n\](http://github.com/projectdiscovery/httpx/cmd/httpx@latest%5Cn%5C)
go install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\](http://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest%5Cn%5C)
go install -v [github.com/projectdiscovery/katana/cmd/katana@latest\n\](http://github.com/projectdiscovery/katana/cmd/katana@latest%5Cn%5C)
go install -v [github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n\](http://github.com/projectdiscovery/naabu/v2/cmd/naabu@latest%5Cn%5C)
go install -v [github.com/lc/gau/v2/cmd/gau@latest\n\](http://github.com/lc/gau/v2/cmd/gau@latest%5Cn%5C)
go install -v [github.com/hahwul/dalfox/v2@latest\n\](http://github.com/hahwul/dalfox/v2@latest%5Cn%5C)
go install -v [github.com/tomnomnom/anew@latest\n\](http://github.com/tomnomnom/anew@latest%5Cn%5C)
go install -v [github.com/owasp-amass/amass/v4/](http://github.com/owasp-amass/amass/v4/)...@master\n\
apt install ffuf"
fi

# Wordlist fallback
if [[ ! -f "$WORDLIST" ]]; then
if [[ -f "$FALLBACK_WORDLIST" ]]; then
WORDLIST="$FALLBACK_WORDLIST"
warn "Primary wordlist not found. Using fallback: $WORDLIST"
else
warn "No wordlist found at $WORDLIST — ffuf stage will be skipped."
WORDLIST=""
fi
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — DIRECTORY SCAFFOLD
# ─────────────────────────────────────────────────────────────────────────────

setup_directories() {
section "Setting Up Workspace"

local dirs=(
"$OUTDIR"
"$OUTDIR/subs"       # Subdomain enumeration results
"$OUTDIR/dns"        # DNS resolution results
"$OUTDIR/http"       # Live host detection results
"$OUTDIR/crawl"      # URL crawling (gau + katana)
"$OUTDIR/params"     # Extracted parameters
"$OUTDIR/xss"        # Dalfox XSS results
"$OUTDIR/fuzz"       # ffuf directory/file fuzzing
"$OUTDIR/vuln"       # Nuclei vulnerability results
"$OUTDIR/ports"      # Port scanning results
"$OUTDIR/files"      # Sensitive file discovery
"$OUTDIR/wordlists"  # Target-specific generated wordlists
"$OUTDIR/logs"       # Per-stage log files
)

for d in "${dirs[@]}"; do
mkdir -p "$d"
done

LOG_FILE="$OUTDIR/logs/recon_$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE"

success "Workspace created: $OUTDIR"
info    "Log file: $LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — BANNER
# ─────────────────────────────────────────────────────────────────────────────

print_banner() {
[[ "$QUIET" == true ]] && return

cat <<EOF

${BOLD}${BLUE}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
${RESET}
${BOLD}Modular Offensive Reconnaissance Pipeline${RESET} v${SCRIPT_VERSION}
${DIM}────────────────────────────────────────────${RESET}
Target   : ${BOLD}${CYAN}${DOMAIN}${RESET}
Profile  : ${BOLD}${PROFILE}${RESET}
Threads  : ${BOLD}${THREADS}${RESET}
Rate     : ${BOLD}${RATE_LIMIT} req/s${RESET}
Stages   : ${BOLD}${STAGES}${RESET}
Dry-run  : ${BOLD}${DRY_RUN}${RESET}
Started  : ${BOLD}${START_TIME}${RESET}
Output   : ${BOLD}${OUTDIR}${RESET}
${DIM}────────────────────────────────────────────${RESET}

EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — STAGE 1: SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : subfinder (passive multi-source), amass (passive + active)
# Output  : subs/subfinder.txt, subs/amass.txt, subs/all_subs.txt
# Note    : Results are deduplicated and merged into subs/all_subs.txt

stage_subs() {
stage_enabled "subs" || return 0
section "Stage 1 — Subdomain Enumeration"

# ── 1a. Subfinder ─────────────────────────────────────────────────────────
info "Running subfinder (passive, multi-source)..."
run "subfinder" \
subfinder \
-d "$DOMAIN" \
-all \
-recursive \
-t "$THREADS" \
-silent \
-o "$OUTDIR/subs/subfinder.txt"

# ── 1b. Amass passive ─────────────────────────────────────────────────────
info "Running amass (passive enumeration)..."
run "amass-passive" \
amass enum \
-passive \
-d "$DOMAIN" \
-o "$OUTDIR/subs/amass.txt" \
-timeout 30

# ── 1c. Merge and deduplicate ─────────────────────────────────────────────
info "Merging and deduplicating subdomain lists..."
if [[ "$DRY_RUN" == false ]]; then
cat \
"$OUTDIR/subs/subfinder.txt" \
"$OUTDIR/subs/amass.txt" \
| sort -u \
| anew "$OUTDIR/subs/all_subs.txt" > /dev/null

local count; count=$(count_lines "$OUTDIR/subs/all_subs.txt")
success "Total unique subdomains discovered: ${BOLD}${count}${RESET}"
fi

# ── 1d. Permutation-based expansion ──────────────────────────────────────
# Generate mutations using common prefixes to discover non-standard hosts.
if command -v alterx &>/dev/null && [[ "$DRY_RUN" == false ]]; then
info "Running alterx permutation mutations..."
cat "$OUTDIR/subs/all_subs.txt" \
| alterx -silent \
| anew "$OUTDIR/subs/permutations.txt" > /dev/null
info "Permutations generated: $(count_lines "$OUTDIR/subs/permutations.txt")"
else
warn "alterx not found — skipping permutation expansion"
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — STAGE 2: DNS RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : dnsx
# Output  : dns/resolved.txt, dns/dns_records.json
# Note    : Resolves all discovered subdomains, filters dangling CNAMEs for
#           potential subdomain takeover candidates.

stage_dns() {
stage_enabled "dns" || return 0
section "Stage 2 — DNS Resolution"

local input="$OUTDIR/subs/all_subs.txt"
[[ -f "$input" && -s "$input" ]] || { warn "No subdomains file found — skipping DNS stage."; return 0; }

# ── 2a. Resolve all subdomains ────────────────────────────────────────────
info "Resolving subdomains with dnsx..."
run "dnsx-resolve" \
dnsx \
-l "$input" \
-a -aaaa -cname -mx -ns \
-resp \
-silent \
-t "$THREADS" \
-retry 3 \
-o "$OUTDIR/dns/resolved.txt" \
-json -o "$OUTDIR/dns/dns_records.json"

# ── 2b. Extract clean resolved hostnames ─────────────────────────────────
if [[ "$DRY_RUN" == false && -f "$OUTDIR/dns/dns_records.json" ]]; then
jq -r '.host // empty' "$OUTDIR/dns/dns_records.json" 2>/dev/null \
| sort -u \
> "$OUTDIR/dns/resolved_hosts.txt" || true

local count; count=$(count_lines "$OUTDIR/dns/resolved_hosts.txt")
success "Resolved hosts: ${BOLD}${count}${RESET}"
fi

# ── 2c. Identify dangling CNAME (takeover candidates) ─────────────────────
# A dangling CNAME points to a service that no longer exists — takeover risk.
info "Identifying potential subdomain takeover candidates..."
if [[ "$DRY_RUN" == false && -f "$OUTDIR/dns/dns_records.json" ]]; then
local takeover_patterns=(
"[herokuapp.com](http://herokuapp.com/)" "[github.io](http://github.io/)" "netlify.app" "[netlify.com](http://netlify.com/)"
"[azurewebsites.net](http://azurewebsites.net/)" "[cloudapp.net](http://cloudapp.net/)" "[s3.amazonaws.com](http://s3.amazonaws.com/)"
"[ghost.io](http://ghost.io/)" "[pantheon.io](http://pantheon.io/)" "[zendesk.com](http://zendesk.com/)" "[wordpress.com](http://wordpress.com/)"
"[weebly.com](http://weebly.com/)" "[desk.com](http://desk.com/)" "[fastly.net](http://fastly.net/)" "[shopify.com](http://shopify.com/)"
)
local pattern_regex
pattern_regex=$(IFS='|'; echo "${takeover_patterns[]}")

jq -r 'select(.cname != null) | "\(.host) → \(.cname[])"' \
"$OUTDIR/dns/dns_records.json" 2>/dev/null \
| grep -iE "$pattern_regex" \
> "$OUTDIR/dns/takeover_candidates.txt" || true

local tk_count; tk_count=$(count_lines "$OUTDIR/dns/takeover_candidates.txt")
if [[ $tk_count -gt 0 ]]; then
warn "Potential subdomain takeover candidates found: ${tk_count} — check $OUTDIR/dns/takeover_candidates.txt"
fi
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — STAGE 3: LIVE HOST DETECTION
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : httpx
# Output  : http/live_hosts.txt, http/httpx_full.json
# Note    : Probes all resolved hosts on HTTP/HTTPS, captures status codes,
#           titles, technologies, server headers, and content length.
#           Filters interesting targets (admin panels, dashboards, etc.)

stage_http() {
stage_enabled "http" || return 0
section "Stage 3 — Live Host Detection"

local input="$OUTDIR/dns/resolved_hosts.txt"
[[ -f "$input" && -s "$input" ]] || {
# Fallback: use raw subdomain list if DNS stage was skipped
input="$OUTDIR/subs/all_subs.txt"
[[ -f "$input" && -s "$input" ]] || { warn "No input for HTTP probing — skipping."; return 0; }
}

# ── 3a. Full HTTP probe ───────────────────────────────────────────────────
info "Probing live HTTP(S) hosts with httpx..."
run "httpx-probe" \
httpx \
-l "$input" \
-title -tech-detect -status-code \
-content-length -location \
-follow-redirects \
-server -method GET \
-timeout 15 \
-t "$THREADS" \
-silent \
-json -o "$OUTDIR/http/httpx_full.json" \
-o "$OUTDIR/http/live_hosts.txt"

# ── 3b. Extract interesting targets ──────────────────────────────────────
# Admin panels, monitoring tools, and exposed services are high priority.
if [[ "$DRY_RUN" == false && -f "$OUTDIR/http/httpx_full.json" ]]; then
info "Extracting high-value targets from live hosts..."

# Admin / management panels
jq -r 'select(
(.title | ascii_downcase | test("admin|dashboard|management|console|panel|login|portal|jenkins|grafana|kibana|phpmyadmin|gitlab|jira"))
or
(.url | test(":8080|:8443|:9090|:9200|:3000|:5601|:6006|:4848|:2375|:15672"))
) | .url' "$OUTDIR/http/httpx_full.json" 2>/dev/null \
| sort -u > "$OUTDIR/http/interesting_targets.txt" || true

# 403 targets (potentially bypassable)
jq -r 'select(.status_code == 403) | .url' \
"$OUTDIR/http/httpx_full.json" 2>/dev/null \
| sort -u > "$OUTDIR/http/403_targets.txt" || true

# Technology fingerprints summary
jq -r '[.url, (.technologies // [] | join(","))] | @tsv' \
"$OUTDIR/http/httpx_full.json" 2>/dev/null \
| sort -u > "$OUTDIR/http/tech_fingerprints.txt" || true

local live_count; live_count=$(count_lines "$OUTDIR/http/live_hosts.txt")
local interesting; interesting=$(count_lines "$OUTDIR/http/interesting_targets.txt")
success "Live hosts: ${BOLD}${live_count}${RESET} | Interesting targets: ${BOLD}${interesting}${RESET}"
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11 — STAGE 4: URL CRAWLING & HISTORICAL COLLECTION
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : gau (historical URLs), waybackurls (Wayback Machine),
#           katana (active JS-aware crawler)
# Output  : crawl/gau_urls.txt, crawl/katana_urls.txt, crawl/all_urls.txt
# Note    : Combines passive historical data with active JS parsing to build
#           the most complete URL inventory possible.

stage_crawl() {
stage_enabled "crawl" || return 0
section "Stage 4 — URL Crawling & Historical Collection"

local live_file="$OUTDIR/http/live_hosts.txt"
[[ -f "$live_file" && -s "$live_file" ]] || { warn "No live hosts — skipping crawl stage."; return 0; }

# ── 4a. GAU — passive historical URL collection ───────────────────────────
# Queries Wayback Machine, AlienVault OTX, Common Crawl, [URLScan.io](http://urlscan.io/)
info "Collecting historical URLs with gau..."
run "gau" \
gau \
--subs \
--threads "$THREADS" \
--blacklist png,jpg,gif,jpeg,css,woff,woff2,ttf,eot,ico,svg \
--o "$OUTDIR/crawl/gau_urls.txt" \
"$DOMAIN"

# ── 4b. Waybackurls (if available) ───────────────────────────────────────
if command -v waybackurls &>/dev/null; then
info "Collecting Wayback Machine URLs with waybackurls..."
if [[ "$DRY_RUN" == false ]]; then
echo "$DOMAIN" \
| waybackurls \
| anew "$OUTDIR/crawl/gau_urls.txt" > /dev/null
fi
fi

# ── 4c. Katana — active JavaScript-aware crawler ──────────────────────────
# Parses JS bundles to extract hidden endpoints, API paths, and forms.
info "Active JS-aware crawling with katana..."
run "katana" \
katana \
-list "$live_file" \
-depth 5 \
-jc \
-kf all \
-fx \
-ef png,jpg,gif,jpeg,css,woff,woff2,ttf,eot,ico,svg,mp4,mp3 \
-c "$THREADS" \
-silent \
-o "$OUTDIR/crawl/katana_urls.txt"

# ── 4d. Merge all URLs ────────────────────────────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
cat \
"$OUTDIR/crawl/gau_urls.txt" \
"$OUTDIR/crawl/katana_urls.txt" \
| sort -u \
> "$OUTDIR/crawl/all_urls.txt"

local count; count=$(count_lines "$OUTDIR/crawl/all_urls.txt")
success "Total unique URLs collected: ${BOLD}${count}${RESET}"

# ── 4e. Filter high-interest URL patterns ─────────────────────────────
# Extract URLs matching common vulnerability patterns.
info "Filtering high-interest URL patterns..."
grep -E '\?[^=]+=|&[^=]+=' "$OUTDIR/crawl/all_urls.txt" \
| sort -u > "$OUTDIR/params/urls_with_params.txt" || true

# Extract API endpoints
grep -iE '/api/|/v[0-9]+/|/rest/|/graphql|/rpc' \
"$OUTDIR/crawl/all_urls.txt" \
| sort -u > "$OUTDIR/crawl/api_endpoints.txt" || true

# Extract JS files for manual review
grep -iE '\.js(\?|$)' "$OUTDIR/crawl/all_urls.txt" \
| sort -u > "$OUTDIR/crawl/js_files.txt" || true

info "URLs with params: $(count_lines "$OUTDIR/params/urls_with_params.txt")"
info "API endpoints: $(count_lines "$OUTDIR/crawl/api_endpoints.txt")"
info "JS files: $(count_lines "$OUTDIR/crawl/js_files.txt")"
fi

# ── 4f. Pattern-based URL filtering with gf ───────────────────────────────
if command -v gf &>/dev/null && [[ "$DRY_RUN" == false ]]; then
info "Applying gf pattern filters for vulnerability candidates..."
local gf_patterns=( sqli xss ssrf redirect rce lfi idor )
for pattern in "${gf_patterns[@]}"; do
gf "$pattern" "$OUTDIR/crawl/all_urls.txt" \
> "$OUTDIR/params/gf_${pattern}.txt" 2>/dev/null || true
local n; n=$(count_lines "$OUTDIR/params/gf_${pattern}.txt")
[[ $n -gt 0 ]] && info "  gf-$pattern: ${n} candidates"
done
else
warn "gf not found — skipping pattern filtering"
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12 — STAGE 5: PARAMETER EXTRACTION & XSS SCANNING
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : unfurl (param extraction), dalfox (XSS scanner)
# Output  : params/all_params.txt, xss/dalfox_results.txt
# Note    : Dalfox is one of the most accurate open-source XSS scanners.
#           It handles DOM XSS, blind XSS, and polyglot payload generation.

stage_params() {
stage_enabled "params" || return 0
section "Stage 5 — Parameter Extraction & XSS Detection"

local url_file="$OUTDIR/params/urls_with_params.txt"
[[ -f "$url_file" && -s "$url_file" ]] || { warn "No parameterized URLs found — skipping params stage."; return 0; }

# ── 5a. Extract unique parameter keys ─────────────────────────────────────
if command -v unfurl &>/dev/null && [[ "$DRY_RUN" == false ]]; then
info "Extracting unique parameter keys with unfurl..."
cat "$url_file" \
| unfurl --unique keys \
| sort | uniq -c | sort -rn \
> "$OUTDIR/params/all_params.txt"
info "Unique param keys discovered: $(count_lines "$OUTDIR/params/all_params.txt")"
fi

# ── 5b. Generate target-specific wordlist from parameter names ─────────────
if [[ "$DRY_RUN" == false && -f "$OUTDIR/params/all_params.txt" ]]; then
awk '{print $2}' "$OUTDIR/params/all_params.txt" \
> "$OUTDIR/wordlists/target_params.txt"
info "Target-specific param wordlist saved: $OUTDIR/wordlists/target_params.txt"
fi

# ── 5c. Dalfox XSS scan ───────────────────────────────────────────────────
# Uses pipe mode to scan each parameterized URL from the crawl output.
# --silence       : suppress progress bars (cleaner logs)
# --skip-bav      : skip basic auth verification for faster scanning
# --timeout       : per-request timeout
# --worker        : parallel workers
info "Running dalfox XSS scanner..."
run "dalfox" \
dalfox \
pipe \
--silence \
--skip-bav \
--skip-mining-all \
--timeout 15 \
--worker "$THREADS" \
--output "$OUTDIR/xss/dalfox_results.txt" \
--format json < "$url_file"

# ── 5d. Arjun — hidden parameter discovery ─────────────────────────────────
# Arjun identifies hidden HTTP parameters not visible in the URL.
if command -v arjun &>/dev/null; then
info "Running arjun for hidden parameter discovery..."
run "arjun" \
arjun \
-i "$OUTDIR/http/live_hosts.txt" \
-t "$THREADS" \
--stable \
-oJ "$OUTDIR/params/arjun_results.json"
else
warn "arjun not found — skipping hidden parameter discovery"
fi

if [[ "$DRY_RUN" == false ]]; then
local xss_count; xss_count=$(count_lines "$OUTDIR/xss/dalfox_results.txt")
[[ $xss_count -gt 0 ]] && warn "Potential XSS findings: ${xss_count} — check $OUTDIR/xss/dalfox_results.txt"
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 13 — STAGE 6: DIRECTORY & ENDPOINT FUZZING
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : ffuf
# Output  : fuzz/ffuf_<host>.json per live target
# Note    : Uses a smart filter strategy: filter by size rather than status
#           to catch soft 404s. Runs against each live host individually
#           to avoid mixing results.

stage_fuzz() {
stage_enabled "fuzz" || return 0
section "Stage 6 — Directory & Endpoint Fuzzing"

local live_file="$OUTDIR/http/live_hosts.txt"
[[ -f "$live_file" && -s "$live_file" ]] || { warn "No live hosts for fuzzing — skipping."; return 0; }
[[ -n "$WORDLIST" ]] || { warn "No wordlist available — skipping ffuf stage."; return 0; }

# ── 6a. Determine soft-404 size for each target ───────────────────────────
# Probe for a known-nonexistent path to get the baseline 404 response size.
fuzz_target() {
local url="$1"
local safe_name; safe_name=$(echo "$url" | sed 's|https\?://||;s|/||g')
local outfile="$OUTDIR/fuzz/ffuf${safe_name}.json"

# Get baseline 404 size
local baseline_size
if [[ "$DRY_RUN" == false ]]; then
baseline_size=$(curl -sk -o /dev/null -w "%{size_download}" \
"${url}/this_path_should_not_exist_xyz_abc_$(date +%s)" 2>/dev/null || echo "0")
else
baseline_size=0
fi

info "  Fuzzing: $url (baseline 404 size: ${baseline_size} bytes)"
run "ffuf-$safe_name" \
ffuf \
-u "${url}/FUZZ" \
-w "$WORDLIST" \
-mc 200,204,301,302,307,401,403,405 \
-fs "$baseline_size" \
-t "$THREADS" \
-timeout 10 \
-H "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)" \
-recursion \
-recursion-depth 2 \
-silent \
-json -o "$outfile"
}

# ── 6b. Fuzz API endpoint patterns ────────────────────────────────────────
fuzz_api() {
local url="$1"
local safe_name; safe_name=$(echo "$url" | sed 's|https\?://||;s|/||g')
local api_wordlist
api_wordlist=$(mktemp /tmp/recon_api_XXXX.txt)

# Combine API-specific paths
cat > "$api_wordlist" <<'APIPATHS'
api
api/v1
api/v2
api/v3
api/v1/admin
api/v1/users
api/v1/user
swagger.json
openapi.json
openapi.yaml
api-docs
graphql
graphiql
graphql
/api/graphql
admin
admin/login
debug
debug
health
status
metrics
internal
private
beta
APIPATHS

run "ffuf-api-$safe_name" \
ffuf \
-u "${url}/FUZZ" \
-w "$api_wordlist" \
-mc 200,204,401,403 \
-t "$THREADS" \
-timeout 10 \
-silent \
-json -o "$OUTDIR/fuzz/ffuf_api${safe_name}.json"

rm -f "$api_wordlist"
}

# ── 6c. Run fuzzing against each live host ─────────────────────────────────
local fuzz_count=0
while IFS= read -r target_url; do
[[ -z "$target_url" ]] && continue
fuzz_target "$target_url"
fuzz_api    "$target_url"
(( fuzz_count++ ))
done < "$live_file"

success "Fuzzing completed for ${fuzz_count} targets"

# ── 6d. Consolidate ffuf results ──────────────────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
find "$OUTDIR/fuzz" -name "*.json" -size +2c \
| xargs -r jq -r '.results[]? | [.status, .length, .url] | @tsv' 2>/dev/null \
| sort -u > "$OUTDIR/fuzz/all_findings.tsv" || true
info "Consolidated fuzz findings: $(count_lines "$OUTDIR/fuzz/all_findings.tsv") paths discovered"
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 14 — STAGE 7: VULNERABILITY SCANNING
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : nuclei
# Output  : vuln/nuclei<severity>.txt, vuln/nuclei_all.json
# Note    : Runs in severity-separated passes for better triage. Rate-limiting
#           is critical here to avoid being blocked and to reduce false positives.
#           Template order: exposures → technologies → misconfigs → CVEs → vulns

stage_vuln() {
stage_enabled "vuln" || return 0
section "Stage 7 — Vulnerability Scanning (Nuclei)"

local live_file="$OUTDIR/http/live_hosts.txt"
[[ -f "$live_file" && -s "$live_file" ]] || { warn "No live hosts for vulnerability scanning — skipping."; return 0; }

# Update nuclei templates before scanning
info "Updating nuclei templates..."
if [[ "$DRY_RUN" == false ]]; then
nuclei -update-templates -silent >> "$LOG_FILE" 2>&1 || warn "Template update failed — using existing templates"
fi

# ── 7a. Pass 1: Technology detection & exposure scan ─────────────────────
# Lightweight first pass — identifies tech stack and obvious exposures.
info "Pass 1: Technology fingerprinting and exposures..."
run "nuclei-tech" \
nuclei \
-l "$live_file" \
-tags tech,exposure,panel \
-severity info,low \
-rl "$RATE_LIMIT" \
-c "${NUCLEI_CONCURRENCY:-15}" \
-timeout 10 \
-retries 2 \
-silent \
-json -o "$OUTDIR/vuln/nuclei_tech.json" \
-o "$OUTDIR/vuln/nuclei_tech.txt"

# ── 7b. Pass 2: Misconfiguration scan ────────────────────────────────────
# Finds misconfigured services, headers, and default credentials.
info "Pass 2: Misconfiguration detection..."
run "nuclei-misconfig" \
nuclei \
-l "$live_file" \
-tags misconfig,default-login,auth-bypass \
-severity low,medium,high \
-rl "$RATE_LIMIT" \
-c "${NUCLEI_CONCURRENCY:-15}" \
-timeout 10 \
-retries 2 \
-silent \
-json -o "$OUTDIR/vuln/nuclei_misconfig.json" \
-o "$OUTDIR/vuln/nuclei_misconfig.txt"

# ── 7c. Pass 3: CVE and known vulnerability scan ──────────────────────────
# Matches discovered technology versions against known CVEs.
info "Pass 3: CVE and known vulnerability detection..."
run "nuclei-cve" \
nuclei \
-l "$live_file" \
-tags cve \
-severity medium,high,critical \
-rl "$RATE_LIMIT" \
-c "${NUCLEI_CONCURRENCY:-15}" \
-timeout 15 \
-retries 2 \
-silent \
-json -o "$OUTDIR/vuln/nuclei_cve.json" \
-o "$OUTDIR/vuln/nuclei_cve.txt"

# ── 7d. Pass 4: High-severity injection and auth checks ───────────────────
# Targets: SQLi, SSRF, SSTI, open redirects, auth bypasses.
info "Pass 4: Injection and authentication vulnerability checks..."
run "nuclei-vulns" \
nuclei \
-l "$live_file" \
-tags sqli,ssrf,ssti,redirect,xss,lfi,rce \
-severity high,critical \
-rl "$(( RATE_LIMIT / 2 ))" \
-c "$(( NUCLEI_CONCURRENCY / 2 ))" \
-timeout 20 \
-retries 3 \
-silent \
-json -o "$OUTDIR/vuln/nuclei_injections.json" \
-o "$OUTDIR/vuln/nuclei_injections.txt"

# ── 7e. Pass 5: Takeover checks ───────────────────────────────────────────
info "Pass 5: Subdomain takeover checks..."
run "nuclei-takeover" \
nuclei \
-l "$OUTDIR/subs/all_subs.txt" \
-tags takeover \
-rl "$RATE_LIMIT" \
-c "${NUCLEI_CONCURRENCY:-15}" \
-timeout 15 \
-silent \
-json -o "$OUTDIR/vuln/nuclei_takeovers.json" \
-o "$OUTDIR/vuln/nuclei_takeovers.txt"

# ── 7f. Consolidate and triage nuclei results ─────────────────────────────
if [[ "$DRY_RUN" == false ]]; then
find "$OUTDIR/vuln" -name "*.json" -size +2c \
| xargs -r cat 2>/dev/null \
| jq -r '[.info.severity // "info", .info.name // "unknown", .host // "unknown", .matched-at // ""] | @tsv' 2>/dev/null \
| sort -t$'\t' -k1,1 \
> "$OUTDIR/vuln/all_findings.tsv" || true

# Count by severity
for sev in critical high medium low info; do
local n; n=$(grep -c "^$sev" "$OUTDIR/vuln/all_findings.tsv" 2>/dev/null || echo 0)
[[ $n -gt 0 ]] && info "  Severity ${sev}: ${BOLD}${n}${RESET} findings"
done
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15 — STAGE 8: PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : naabu (fast discovery), nmap (detailed service fingerprint)
# Output  : ports/naabu_open.txt, ports/nmap_services.txt
# Note    : naabu does fast SYN-based port discovery, then nmap does deep
#           service and version detection only on discovered open ports.

stage_ports() {
stage_enabled "ports" || return 0
section "Stage 8 — Port Scanning"

local input="$OUTDIR/dns/resolved_hosts.txt"
[[ -f "$input" && -s "$input" ]] || {
input="$OUTDIR/subs/all_subs.txt"
[[ -f "$input" && -s "$input" ]] || { warn "No resolved hosts for port scanning — skipping."; return 0; }
}

# Common web and management ports
local web_ports="80,443,8080,8443,8000,8008,8888,3000,4000,4443,5000,7000,9000,9090,9200,9300,5601,3306,5432,6379,27017,2375,2376,6443,10250,15672"

# ── 8a. Naabu fast port discovery ─────────────────────────────────────────
info "Running naabu for fast port discovery..."
run "naabu" \
naabu \
-l "$input" \
-p "$web_ports" \
-rate 1000 \
-silent \
-exclude-cdn \
-o "$OUTDIR/ports/naabu_open.txt"

# ── 8b. Nmap deep service fingerprint on discovered open ports ─────────────
if command -v nmap &>/dev/null && [[ "$DRY_RUN" == false && -f "$OUTDIR/ports/naabu_open.txt" && -s "$OUTDIR/ports/naabu_open.txt" ]]; then
info "Running nmap service detection on discovered open ports..."

# Parse naabu output (format: host:port) for nmap input
awk -F: '{print $1}' "$OUTDIR/ports/naabu_open.txt" \
| sort -u > "$OUTDIR/ports/nmap_targets.txt"

local open_port_list
open_port_list=$(awk -F: '{print $2}' "$OUTDIR/ports/naabu_open.txt" \
| sort -un | tr '\n' ',' | sed 's/,$//')

if [[ -n "$open_port_list" ]]; then
run "nmap" \
nmap \
-sV -sC \
-p "$open_port_list" \
-iL "$OUTDIR/ports/nmap_targets.txt" \
--open \
--script "http-title,http-headers,http-methods,banner,ssl-cert,vulners" \
-T3 \
-oN "$OUTDIR/ports/nmap_services.txt" \
-oX "$OUTDIR/ports/nmap_services.xml"
fi
elif ! command -v nmap &>/dev/null; then
warn "nmap not found — skipping deep service fingerprinting"
fi

if [[ "$DRY_RUN" == false ]]; then
local port_count; port_count=$(count_lines "$OUTDIR/ports/naabu_open.txt")
success "Open ports discovered: ${BOLD}${port_count}${RESET}"

# Highlight dangerous services
if [[ -f "$OUTDIR/ports/naabu_open.txt" ]]; then
grep -E ':2375$|:9200$|:27017$|:6379$|:5432$|:3306$' \
"$OUTDIR/ports/naabu_open.txt" \
> "$OUTDIR/ports/dangerous_services.txt" || true
local danger; danger=$(count_lines "$OUTDIR/ports/dangerous_services.txt")
[[ $danger -gt 0 ]] && warn "Potentially unauthenticated services found: ${danger} — check $OUTDIR/ports/dangerous_services.txt"
fi
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 16 — STAGE 9: SENSITIVE FILE DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
# Tools   : ffuf (targeted sensitive path fuzzing), curl
# Output  : files/sensitive_files.txt, files/secrets_in_js.txt
# Note    : Targets backup files, config files, exposed git repos, env files,
#           API keys in JS, and cloud metadata endpoints.

stage_files() {
stage_enabled "files" || return 0
section "Stage 9 — Sensitive File Discovery"

local live_file="$OUTDIR/http/live_hosts.txt"
[[ -f "$live_file" && -s "$live_file" ]] || { warn "No live hosts — skipping sensitive file discovery."; return 0; }

# ── 9a. Build sensitive file wordlist ─────────────────────────────────────
local sens_wordlist="$OUTDIR/wordlists/sensitive_files.txt"
cat > "$sens_wordlist" <<'SENSITIVE_PATHS'
.git/HEAD
.git/config
.git/COMMIT_EDITMSG
.gitignore
.env
.env.local
.env.production
.env.staging
.env.backup
.env.old
.DS_Store
config.php
config.yml
config.yaml
config.json
database.yml
database.php
[settings.py](http://settings.py/)
settings.php
wp-config.php
wp-config.php.bak
configuration.php
LocalSettings.php
.htaccess
.htpasswd
web.config
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
phpinfo.php
info.php
test.php
server-status
server-info
profiler
debug
debug/default/view
phpMyAdmin/index.php
phpmyadmin/index.php
PMA/index.php
adminer.php
admin.php
administrator/index.php
backup.zip
backup.tar.gz
backup.sql
db_backup.sql
dump.sql
data.sql
www.zip
site.zip
htdocs.zip
public_html.zip
api-docs
api/docs
swagger/index.html
swagger.json
swagger.yaml
openapi.json
openapi.yaml
v1/api-docs
v2/api-docs
actuator
actuator/env
actuator/mappings
actuator/health
actuator/info
actuator/dump
actuator/trace
.aws/credentials
.ssh/id_rsa
.ssh/authorized_keys
id_rsa
private.key
server.key
certificate.pem
packages.json
package.json
composer.json
composer.lock
Gemfile
Gemfile.lock
requirements.txt
Dockerfile
docker-compose.yml
.travis.yml
.circleci/config.yml
jenkins/build
jenkins.xml
SENSITIVE_PATHS

# ── 9b. Fuzzing for sensitive files ───────────────────────────────────────
info "Fuzzing for sensitive files and configurations..."
run "ffuf-sensitive" \
ffuf \
-l "$live_file" \
-w "$sens_wordlist" \
-u "HFUZZ/WFUZZ" \
-mc 200,204,301,302,403 \
-t "$THREADS" \
-timeout 10 \
-silent \
-json -o "$OUTDIR/files/sensitive_ffuf.json"

# ── 9c. Extract secrets from JS files ─────────────────────────────────────
# Scan crawled JS files for API keys, tokens, and sensitive patterns.
if [[ "$DRY_RUN" == false && -f "$OUTDIR/crawl/js_files.txt" && -s "$OUTDIR/crawl/js_files.txt" ]]; then
info "Scanning JS files for hardcoded secrets..."

# Secret patterns: API keys, tokens, private keys, passwords
local secret_pattern='(api[-]?key|apikey|api[-]?secret|secret[-]?key|access[-]?token|bearer|authorization|password|passwd|private[-]?key|client[-]?secret|oauth[-]?token|stripe[-]?key|aws[-]?access|aws[-]?secret|sendgrid|twilio|slack[-]?token|firebase)["\s:=]+["\x27][A-Za-z0-9_\/\+\-\.]{8,}'

while IFS= read -r js_url; do
[[ -z "$js_url" ]] && continue
curl -sk --max-time 10 "$js_url" 2>/dev/null \
| grep -iEo "$secret_pattern" \
| sed "s|^|[$js_url] |" \
>> "$OUTDIR/files/secrets_in_js.txt" || true
done < "$OUTDIR/crawl/js_files.txt"

local secret_count; secret_count=$(count_lines "$OUTDIR/files/secrets_in_js.txt")
[[ $secret_count -gt 0 ]] && warn "Potential secrets in JS files: ${secret_count} — check $OUTDIR/files/secrets_in_js.txt"
fi

# ── 9d. Check for exposed .git repositories ───────────────────────────────
info "Checking for exposed .git repositories..."
if [[ "$DRY_RUN" == false ]]; then
while IFS= read -r host; do
[[ -z "$host" ]] && continue
local status
status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "${host}/.git/HEAD" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
warn "Exposed .git repository: ${host}/.git/HEAD"
echo "${host}/.git/HEAD" >> "$OUTDIR/files/exposed_git.txt"
fi
done < "$live_file"
fi

# ── 9e. Cloud metadata endpoint checks ───────────────────────────────────
# Relevant if SSRF is found — these are the internal targets.
cat > "$OUTDIR/files/cloud_metadata_targets.txt" <<'CLOUD_META'
# AWS Instance Metadata Service (IMDSv1 — no auth required)
http://169.254.169.254/latest/meta-data/http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud Metadata
http://metadata.google.internal/computeMetadata/v1/http://169.254.169.254/computeMetadata/v1/

# Azure Instance Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Digital Ocean Metadata
http://169.254.169.254/metadata/v1/

# Alternative bypass encodings (use when direct access is filtered)
http://[::ffff:169.254.169.254]/latest/meta-data/
[http://0xA9FEA9FE/latest/meta-data/](http://169.254.169.254/latest/meta-data/)http://169.254.169.254.nip.io/latest/meta-data/
CLOUD_META

success "Sensitive file discovery completed"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17 — FINAL SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────────────────

print_summary() {
local elapsed; elapsed=$(elapsed_pretty)
local end_time; end_time=$(date '+%Y-%m-%d %H:%M:%S')

# Build counts safely (handle missing files gracefully)
local c_subs;    c_subs=$(count_lines    "$OUTDIR/subs/all_subs.txt"                 2>/dev/null || echo 0)
local c_dns;     c_dns=$(count_lines     "$OUTDIR/dns/resolved_hosts.txt"            2>/dev/null || echo 0)
local c_live;    c_live=$(count_lines    "$OUTDIR/http/live_hosts.txt"               2>/dev/null || echo 0)
local c_urls;    c_urls=$(count_lines    "$OUTDIR/crawl/all_urls.txt"                2>/dev/null || echo 0)
local c_params;  c_params=$(count_lines  "$OUTDIR/params/urls_with_params.txt"       2>/dev/null || echo 0)
local c_xss;     c_xss=$(count_lines     "$OUTDIR/xss/dalfox_results.txt"           2>/dev/null || echo 0)
local c_fuzz;    c_fuzz=$(count_lines    "$OUTDIR/fuzz/all_findings.tsv"             2>/dev/null || echo 0)
local c_vuln;    c_vuln=$(count_lines    "$OUTDIR/vuln/all_findings.tsv"             2>/dev/null || echo 0)
local c_ports;   c_ports=$(count_lines   "$OUTDIR/ports/naabu_open.txt"              2>/dev/null || echo 0)
local c_secrets; c_secrets=$(count_lines "$OUTDIR/files/secrets_in_js.txt"          2>/dev/null || echo 0)
local c_take;    c_take=$(count_lines    "$OUTDIR/dns/takeover_candidates.txt"       2>/dev/null || echo 0)
local c_danger;  c_danger=$(count_lines  "$OUTDIR/ports/dangerous_services.txt"     2>/dev/null || echo 0)

printf "\n${BOLD}${BLUE}"
printf '═%.0s' {1..70}
printf "\n"
printf "  RECON COMPLETE — %s\n" "$DOMAIN"
printf '═%.0s' {1..70}
printf "\n${RESET}"

printf "${BOLD}%-35s %s${RESET}\n" "  Started:"  "$START_TIME"
printf "${BOLD}%-35s %s${RESET}\n" "  Finished:" "$end_time"
printf "${BOLD}%-35s %s${RESET}\n" "  Duration:" "$elapsed"
printf "${BOLD}%-35s %s${RESET}\n" "  Errors:"   "$ERRORS"
printf "\n"

printf "${BOLD}  DISCOVERY SUMMARY${RESET}\n"
printf "${DIM}  %-33s %s${RESET}\n" "Metric" "Count"
printf "${DIM}  %-33s %s${RESET}\n" "─────────────────────────────────" "─────"
printf "  %-33s ${BOLD}%s${RESET}\n"     "Subdomains discovered:"         "$c_subs"
printf "  %-33s ${BOLD}%s${RESET}\n"     "DNS-resolved hosts:"            "$c_dns"
printf "  %-33s ${BOLD}%s${RESET}\n"     "Live HTTP(S) hosts:"            "$c_live"
printf "  %-33s ${BOLD}%s${RESET}\n"     "Total URLs collected:"          "$c_urls"
printf "  %-33s ${BOLD}%s${RESET}\n"     "URLs with parameters:"          "$c_params"
printf "  %-33s ${BOLD}%s${RESET}\n"     "Open ports discovered:"         "$c_ports"
printf "  %-33s ${BOLD}%s${RESET}\n"     "Fuzz discoveries:"              "$c_fuzz"

printf "\n"
printf "${BOLD}  VULNERABILITY FINDINGS${RESET}\n"
printf "${DIM}  %-33s %s${RESET}\n" "─────────────────────────────────" "─────"

if [[ -f "$OUTDIR/vuln/all_findings.tsv" ]]; then
for sev in critical high medium low info; do
local n; n=$(grep -c "^$sev" "$OUTDIR/vuln/all_findings.tsv" 2>/dev/null || echo 0)
local color=""
case $sev in
critical) color="$RED"    ;;
high)     color="$YELLOW" ;;
medium)   color="$CYAN"   ;;
*)        color=""        ;;
esac
[[ $n -gt 0 ]] && printf "  %-33s ${color}${BOLD}%s${RESET}\n" "  Nuclei [$sev]:" "$n"
done
fi

printf "  %-33s ${BOLD}%s${RESET}\n" "XSS (dalfox):"                  "$c_xss"
printf "  %-33s ${BOLD}%s${RESET}\n" "JS secrets found:"              "$c_secrets"

printf "\n"
printf "${BOLD}  CRITICAL HIGHLIGHTS${RESET}\n"
printf "${DIM}  %-33s %s${RESET}\n" "─────────────────────────────────" "─────"
printf "  %-33s ${BOLD}%s${RESET}\n" "Takeover candidates:"           "$c_take"
printf "  %-33s ${BOLD}%s${RESET}\n" "Dangerous open services:"       "$c_danger"

printf "\n"
printf "${BOLD}  OUTPUT FILES${RESET}\n"
printf "${DIM}  %-50s %s${RESET}\n" "─────────────────────────────────────────────────" "Lines"

local key_files=(
"$OUTDIR/subs/all_subs.txt"
"$OUTDIR/dns/resolved_hosts.txt"
"$OUTDIR/dns/takeover_candidates.txt"
"$OUTDIR/http/live_hosts.txt"
"$OUTDIR/http/interesting_targets.txt"
"$OUTDIR/http/tech_fingerprints.txt"
"$OUTDIR/crawl/all_urls.txt"
"$OUTDIR/crawl/api_endpoints.txt"
"$OUTDIR/params/urls_with_params.txt"
"$OUTDIR/xss/dalfox_results.txt"
"$OUTDIR/fuzz/all_findings.tsv"
"$OUTDIR/vuln/nuclei_cve.txt"
"$OUTDIR/vuln/all_findings.tsv"
"$OUTDIR/ports/naabu_open.txt"
"$OUTDIR/ports/dangerous_services.txt"
"$OUTDIR/files/secrets_in_js.txt"
"$OUTDIR/files/exposed_git.txt"
)

for f in "${key_files[@]}"; do
if [[ -f "$f" && -s "$f" ]]; then
local n; n=$(count_lines "$f")
printf "  %-50s ${BOLD}%s${RESET}\n" "${f/$OUTDIR\//}" "$n"
fi
done

printf "\n  ${BOLD}Full output: ${CYAN}%s${RESET}\n"   "$OUTDIR"
printf "  ${BOLD}Full log:    ${CYAN}%s${RESET}\n\n"   "$LOG_FILE"

printf "${BOLD}${BLUE}"
printf '═%.0s' {1..70}
printf "\n${RESET}"

# Write machine-readable summary JSON
cat > "$OUTDIR/summary.json" <<JSON
{
"target": "$DOMAIN",
"start_time": "$START_TIME",
"end_time": "$end_time",
"duration": "$elapsed",
"profile": "$PROFILE",
"errors": $ERRORS,
"counts": {
"subdomains": $c_subs,
"resolved_hosts": $c_dns,
"live_hosts": $c_live,
"total_urls": $c_urls,
"parameterized_urls": $c_params,
"open_ports": $c_ports,
"fuzz_findings": $c_fuzz,
"vuln_findings": $c_vuln,
"xss_findings": $c_xss,
"js_secrets": $c_secrets,
"takeover_candidates": $c_take,
"dangerous_services": $c_danger
},
"output_dir": "$OUTDIR"
}
JSON
info "Machine-readable summary saved: $OUTDIR/summary.json"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 18 — OPTIONAL: NOTIFY ON COMPLETION
# ─────────────────────────────────────────────────────────────────────────────

notify_completion() {
if command -v notify &>/dev/null && [[ "$DRY_RUN" == false ]]; then
local elapsed; elapsed=$(elapsed_pretty)
echo "Recon for $DOMAIN complete in $elapsed — check $OUTDIR" \
| notify -silent -bulk 2>/dev/null || true
fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 19 — MAIN ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

main() {
parse_args "$@"
setup_directories
print_banner
check_dependencies

# Run pipeline stages in order
# Each stage is independently gated by stage_enabled() —
# a failure in one stage does not abort subsequent stages.
stage_subs   || warn "Subdomain enumeration encountered errors"
stage_dns    || warn "DNS resolution encountered errors"
stage_http   || warn "HTTP probing encountered errors"
stage_crawl  || warn "URL crawling encountered errors"
stage_params || warn "Parameter extraction encountered errors"
stage_fuzz   || warn "Fuzzing encountered errors"
stage_vuln   || warn "Vulnerability scanning encountered errors"
stage_ports  || warn "Port scanning encountered errors"
stage_files  || warn "Sensitive file discovery encountered errors"

print_summary
notify_completion
}

# ── Execute ───────────────────────────────────────────────────────────────────
main "$@"
