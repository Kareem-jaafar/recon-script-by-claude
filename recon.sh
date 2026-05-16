#!/usr/bin/env bash
# =============================================================================
#  recon.sh — Production-Grade Offensive Reconnaissance Pipeline v3.0
# =============================================================================
#
#  USAGE:  ./recon.sh -d target.com [OPTIONS]
#
#  OPTIONS:
#    -d DOMAIN     Target domain (required)
#    -o OUTDIR     Output directory
#    -t THREADS    Thread count override
#    -r RATE       Nuclei rate-limit req/s override
#    -w WORDLIST   Custom ffuf wordlist
#    -s STAGES     subs,dns,http,crawl,params,fuzz,vuln,ports,files
#    -p PROFILE    fast | balanced | thorough
#    -c CONFIG     Config file
#    -n            Dry-run
#    -q            Quiet mode
#    -h            Help
#
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly START_TS=$(date +%s)
readonly START_TIME=$(date '+%Y-%m-%d %H:%M:%S')

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED=''
    YELLOW=''
    GREEN=''
    BLUE=''
    CYAN=''
    BOLD=''
    DIM=''
    RESET=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN=""
OUTDIR=""
THREADS=""
RATE_LIMIT=""
NUCLEI_CONC=15
PROFILE="balanced"
STAGES="subs,dns,http,crawl,params,fuzz,vuln,ports,files"
CONFIG_FILE="./recon.conf"

DRY_RUN=false
QUIET=false
ERRORS=0

LOG_FILE="/dev/null"

WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
WORDLIST_FALLBACK="/opt/SecLists/Discovery/Web-Content/raft-large-words.txt"

declare -A P_THREADS=(
    [fast]=100
    [balanced]=50
    [thorough]=20
)

declare -A P_RATE=(
    [fast]=30
    [balanced]=10
    [thorough]=3
)

declare -A P_NCONC=(
    [fast]=25
    [balanced]=15
    [thorough]=5
)

REQUIRED_TOOLS=(
    subfinder
    amass
    dnsx
    httpx
    gau
    katana
    ffuf
    nuclei
    naabu
    jq
    anew
)

OPTIONAL_TOOLS=(
    nmap
    dalfox
    arjun
    unfurl
    gf
    waybackurls
    alterx
    notify
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

log() {
    [[ "$QUIET" == false ]] &&
    printf "${BOLD}${BLUE}[*]${RESET} %s\n" "$*" | tee -a "$LOG_FILE"
}

info() {
    [[ "$QUIET" == false ]] &&
    printf "${CYAN}[+]${RESET} %s\n" "$*" | tee -a "$LOG_FILE"
}

success() {
    printf "${GREEN}[✔]${RESET} %s\n" "$*" | tee -a "$LOG_FILE"
}

warn() {
    printf "${YELLOW}[!]${RESET} %s\n" "$*" | tee -a "$LOG_FILE" >&2
}

error() {
    printf "${RED}[✘]${RESET} %s\n" "$*" | tee -a "$LOG_FILE" >&2
    ((ERRORS++)) || true
}

fatal() {
    printf "${RED}${BOLD}[FATAL]${RESET} %s\n" "$*" >&2
    exit 1
}

count() {
    [[ -f "$1" ]] && wc -l < "$1" 2>/dev/null || echo 0
}

elapsed() {
    local s=$(( $(date +%s) - START_TS ))
    printf '%02dh%02dm%02ds' \
        $(( s / 3600 )) \
        $(( (s % 3600) / 60 )) \
        $(( s % 60 ))
}

section() {
    [[ "$QUIET" == true ]] && return
    printf "\n${BOLD}${BLUE}── %s${RESET}\n\n" "$*"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────────────────────────────────

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
}

trap cleanup EXIT
trap 'fatal "Interrupted"' INT TERM

# ─────────────────────────────────────────────────────────────────────────────
# RUN WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

MAX_RETRIES=3
RETRY_DELAY=5

run() {

    local label="$1"
    shift

    local cmd=("$@")
    local attempt=1
    local delay=$RETRY_DELAY

    log "Running [$label]: ${cmd[*]}"

    if [[ "$DRY_RUN" == true ]]; then
        printf "${YELLOW}[dry-run]${RESET} %s\n" "${cmd[*]}"
        return 0
    fi

    while (( attempt <= MAX_RETRIES )); do

        if "${cmd[@]}" >> "$LOG_FILE" 2>&1; then
            success "$label completed"
            return 0
        fi

        if (( attempt < MAX_RETRIES )); then
            warn "$label failed — retrying in ${delay}s"
            sleep "$delay"
            delay=$(( delay * 2 ))
        fi

        ((attempt++))
    done

    error "$label failed"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# STAGES
# ─────────────────────────────────────────────────────────────────────────────

stage_enabled() {
    [[ ",$STAGES," == *",$1,"* ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

load_config() {

    local cfg="$1"

    [[ -f "$cfg" ]] || return 0

    while IFS='=' read -r key val; do

        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" || -z "$val" ]] && continue

        key="${key// /}"
        val="${val// /}"

        case "$key" in
            DOMAIN) DOMAIN="$val" ;;
            THREADS) THREADS="$val" ;;
            RATE_LIMIT) RATE_LIMIT="$val" ;;
            PROFILE) PROFILE="$val" ;;
            WORDLIST) WORDLIST="$val" ;;
            STAGES) STAGES="$val" ;;
            OUTDIR) OUTDIR="$val" ;;
        esac

    done < "$cfg"
}

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENTS
# ─────────────────────────────────────────────────────────────────────────────

usage() {
    grep '^#' "${BASH_SOURCE[0]}" | sed 's/^#//'
    exit 0
}

parse_args() {

    load_config "$CONFIG_FILE"

    while getopts ":d:o:t:r:w:s:p:c:nqh" opt; do
        case $opt in
            d) DOMAIN="$OPTARG" ;;
            o) OUTDIR="$OPTARG" ;;
            t) THREADS="$OPTARG" ;;
            r) RATE_LIMIT="$OPTARG" ;;
            w) WORDLIST="$OPTARG" ;;
            s) STAGES="$OPTARG" ;;
            p) PROFILE="$OPTARG" ;;
            c) load_config "$OPTARG" ;;
            n) DRY_RUN=true ;;
            q) QUIET=true ;;
            h) usage ;;
            :) fatal "Missing argument for -$OPTARG" ;;
            \?) fatal "Unknown option -$OPTARG" ;;
        esac
    done

    [[ -z "$DOMAIN" ]] && fatal "Target domain required"

    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN%%/*}"

    [[ -v "P_THREADS[$PROFILE]" ]] ||
        fatal "Invalid profile: $PROFILE"

    THREADS="${THREADS:-${P_THREADS[$PROFILE]}}"
    RATE_LIMIT="${RATE_LIMIT:-${P_RATE[$PROFILE]}}"
    NUCLEI_CONC="${P_NCONC[$PROFILE]}"

    [[ -z "$OUTDIR" ]] &&
        OUTDIR="$(pwd)/recon_${DOMAIN//./_}_$(date +%Y%m%d_%H%M%S)"

    if [[ ! -f "$WORDLIST" ]]; then
        if [[ -f "$WORDLIST_FALLBACK" ]]; then
            WORDLIST="$WORDLIST_FALLBACK"
        else
            WORDLIST=""
            warn "Wordlist not found"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCIES
# ─────────────────────────────────────────────────────────────────────────────

check_dependencies() {

    section "Dependency Check"

    local missing=()

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            info "$tool"
        else
            error "$tool missing"
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        fatal "Missing tools: ${missing[*]}"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────

setup() {

    mkdir -p "$OUTDIR"/{
        subs,
        dns,
        http,
        crawl,
        params,
        xss,
        fuzz,
        vuln,
        ports,
        files,
        wordlists,
        logs
    }

    LOG_FILE="$OUTDIR/logs/recon.log"

    touch "$LOG_FILE"

    success "Workspace: $OUTDIR"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────

stage_subs() {

    stage_enabled "subs" || return 0

    section "Subdomain Enumeration"

    run "subfinder" \
        subfinder \
        -d "$DOMAIN" \
        -all \
        -recursive \
        -silent \
        -t "$THREADS" \
        -o "$OUTDIR/subs/subfinder.txt"

    run "amass" \
        amass enum \
        -passive \
        -d "$DOMAIN" \
        -o "$OUTDIR/subs/amass.txt"

    if [[ "$DRY_RUN" == false ]]; then

        cat \
            "$OUTDIR/subs/subfinder.txt" \
            "$OUTDIR/subs/amass.txt" \
            2>/dev/null |
        sort -u \
        > "$OUTDIR/subs/all_subs.txt"

        success "Subdomains: $(count "$OUTDIR/subs/all_subs.txt")"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────────────────────────────────────

stage_dns() {

    stage_enabled "dns" || return 0

    section "DNS Resolution"

    local input="$OUTDIR/subs/all_subs.txt"

    [[ -s "$input" ]] || return 0

    run "dnsx" \
        dnsx \
        -l "$input" \
        -a \
        -resp \
        -silent \
        -json \
        -retry 3 \
        -t "$THREADS" \
        -o "$OUTDIR/dns/dns.json"

    if [[ -s "$OUTDIR/dns/dns.json" ]]; then

        jq -r '.host // empty' \
            "$OUTDIR/dns/dns.json" |
        sort -u \
        > "$OUTDIR/dns/resolved.txt"

        success "Resolved: $(count "$OUTDIR/dns/resolved.txt")"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────

stage_http() {

    stage_enabled "http" || return 0

    section "HTTP Probing"

    local input="$OUTDIR/dns/resolved.txt"

    [[ -s "$input" ]] || return 0

    run "httpx" \
        httpx \
        -l "$input" \
        -title \
        -tech-detect \
        -status-code \
        -follow-redirects \
        -timeout 15 \
        -json \
        -silent \
        -t "$THREADS" \
        -o "$OUTDIR/http/httpx.json"

    if [[ -s "$OUTDIR/http/httpx.json" ]]; then

        jq -r '.url // empty' \
            "$OUTDIR/http/httpx.json" |
        sort -u \
        > "$OUTDIR/http/live_hosts.txt"

        success "Live hosts: $(count "$OUTDIR/http/live_hosts.txt")"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CRAWLING
# ─────────────────────────────────────────────────────────────────────────────

stage_crawl() {

    stage_enabled "crawl" || return 0

    section "Crawling"

    local live="$OUTDIR/http/live_hosts.txt"

    [[ -s "$live" ]] || return 0

    if [[ "$DRY_RUN" == false ]]; then

        gau --subs "$DOMAIN" \
            2>>"$LOG_FILE" |
        sort -u \
        > "$OUTDIR/crawl/gau.txt"
    fi

    run "katana" \
        katana \
        -list "$live" \
        -depth 5 \
        -jc \
        -silent \
        -o "$OUTDIR/crawl/katana.txt"

    if [[ "$DRY_RUN" == false ]]; then

        cat \
            "$OUTDIR/crawl/gau.txt" \
            "$OUTDIR/crawl/katana.txt" \
            2>/dev/null |
        sort -u \
        > "$OUTDIR/crawl/all_urls.txt"

        grep -E '\?.+=' \
            "$OUTDIR/crawl/all_urls.txt" \
        > "$OUTDIR/params/urls_with_params.txt" || true

        success "URLs: $(count "$OUTDIR/crawl/all_urls.txt")"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PARAMS + XSS
# ─────────────────────────────────────────────────────────────────────────────

stage_params() {

    stage_enabled "params" || return 0

    section "Parameters & XSS"

    local url_file="$OUTDIR/params/urls_with_params.txt"

    [[ -s "$url_file" ]] || return 0

    if command -v dalfox &>/dev/null; then

        run "dalfox" \
            dalfox pipe \
            --silence \
            --worker "$THREADS" \
            --output "$OUTDIR/xss/dalfox.txt" \
            < "$url_file"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# FUZZING
# ─────────────────────────────────────────────────────────────────────────────

stage_fuzz() {

    stage_enabled "fuzz" || return 0

    section "Fuzzing"

    local live="$OUTDIR/http/live_hosts.txt"

    [[ -s "$live" ]] || return 0
    [[ -n "$WORDLIST" ]] || return 0

    while IFS= read -r host; do

        [[ -z "$host" ]] && continue

        local safe

        safe=$(printf '%s' "$host" |
            sed 's|https\?://||;s|[/:.@?=&]|_|g')

        run "ffuf-$safe" \
            ffuf \
            -u "${host}/FUZZ" \
            -w "$WORDLIST" \
            -mc 200,204,301,302,401,403 \
            -t "$THREADS" \
            -timeout 10 \
            -of json \
            -o "$OUTDIR/fuzz/${safe}.json" \
            -s

    done < "$live"
}

# ─────────────────────────────────────────────────────────────────────────────
# NUCLEI
# ─────────────────────────────────────────────────────────────────────────────

stage_vuln() {

    stage_enabled "vuln" || return 0

    section "Nuclei"

    local live="$OUTDIR/http/live_hosts.txt"

    [[ -s "$live" ]] || return 0

    if [[ "$DRY_RUN" == false ]]; then
        nuclei -update-templates -silent \
            >> "$LOG_FILE" 2>&1 || true
    fi

    run "nuclei" \
        nuclei \
        -l "$live" \
        -rl "$RATE_LIMIT" \
        -c "$NUCLEI_CONC" \
        -timeout 15 \
        -retries 2 \
        -silent \
        -severity low,medium,high,critical \
        -json \
        -o "$OUTDIR/vuln/nuclei.json"
}

# ─────────────────────────────────────────────────────────────────────────────
# PORTS
# ─────────────────────────────────────────────────────────────────────────────

stage_ports() {

    stage_enabled "ports" || return 0

    section "Port Scan"

    local input="$OUTDIR/dns/resolved.txt"

    [[ -s "$input" ]] || return 0

    run "naabu" \
        naabu \
        -l "$input" \
        -rate 1000 \
        -silent \
        -o "$OUTDIR/ports/naabu.txt"

    if command -v nmap &>/dev/null &&
       [[ -s "$OUTDIR/ports/naabu.txt" ]]; then

        awk -F: '{print $1}' \
            "$OUTDIR/ports/naabu.txt" |
        sort -u \
        > "$OUTDIR/ports/targets.txt"

        local ports

        ports=$(awk -F: '{print $2}' \
            "$OUTDIR/ports/naabu.txt" |
            sort -un |
            tr '\n' ',' |
            sed 's/,$//')

        if [[ -n "$ports" ]]; then

            run "nmap" \
                nmap \
                -sV \
                -sC \
                -p "$ports" \
                -iL "$OUTDIR/ports/targets.txt" \
                -oN "$OUTDIR/ports/nmap.txt"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# FILES
# ─────────────────────────────────────────────────────────────────────────────

stage_files() {

    stage_enabled "files" || return 0

    section "Sensitive Files"

    local live="$OUTDIR/http/live_hosts.txt"

    [[ -s "$live" ]] || return 0

    local sw="$OUTDIR/wordlists/sensitive.txt"

    cat > "$sw" <<EOF
.git/HEAD
.git/config
.env
.env.local
config.php
wp-config.php
backup.zip
backup.sql
swagger.json
graphql
actuator
Dockerfile
docker-compose.yml
EOF

    while IFS= read -r host; do

        [[ -z "$host" ]] && continue

        local safe

        safe=$(printf '%s' "$host" |
            sed 's|https\?://||;s|[/:.@?=&]|_|g')

        run "files-$safe" \
            ffuf \
            -u "${host}/FUZZ" \
            -w "$sw" \
            -mc 200,204,301,302,403 \
            -t 20 \
            -timeout 10 \
            -of json \
            -o "$OUTDIR/files/${safe}.json" \
            -s

    done < "$live"
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print_summary() {

    printf "\n${BOLD}${BLUE}"
    printf '═%.0s' {1..60}
    printf "\nRECON COMPLETE — %s\n" "$DOMAIN"
    printf '═%.0s' {1..60}
    printf "\n${RESET}"

    printf "Subdomains:        %s\n" \
        "$(count "$OUTDIR/subs/all_subs.txt")"

    printf "Resolved Hosts:    %s\n" \
        "$(count "$OUTDIR/dns/resolved.txt")"

    printf "Live Hosts:        %s\n" \
        "$(count "$OUTDIR/http/live_hosts.txt")"

    printf "URLs:              %s\n" \
        "$(count "$OUTDIR/crawl/all_urls.txt")"

    printf "Parameters:        %s\n" \
        "$(count "$OUTDIR/params/urls_with_params.txt")"

    printf "Nuclei Findings:   %s\n" \
        "$(count "$OUTDIR/vuln/nuclei.json")"

    printf "Duration:          %s\n" "$(elapsed)"

    printf "\nOutput: %s\n" "$OUTDIR"
    printf "Log:    %s\n\n" "$LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

main() {

    parse_args "$@"

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

    print_summary
}

main "$@"
