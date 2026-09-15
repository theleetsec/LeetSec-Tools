#!/usr/bin/env bash
# tests/fixtures/fake-tool.sh — deterministic stand-ins for the recon toolchain.
#
# Symlinked as subfinder, puredns, httpx and so on. Dispatches on the name it
# was invoked under, parses the same flags the pipeline passes, and writes
# plausible output. Every fixture deliberately includes at least one
# out-of-scope name so scope filtering is actually exercised rather than
# assumed.
#
# No network access, no timing dependency, so the end-to-end test is fast and
# repeatable in CI.
set -u

name=$(basename "$0")
if [ -n "${FAKE_TOOL_TRACE:-}" ]; then printf '%s' "$name" >> "$FAKE_TOOL_TRACE"; printf ' %s' "$@" >> "$FAKE_TOOL_TRACE"; printf '\n' >> "$FAKE_TOOL_TRACE"; fi

# Pull a flag's value out of the argument list without caring about order.
flagval() {
    local want="$1"; shift
    while [ "$#" -gt 0 ]; do
        [ "$1" = "$want" ] && { printf '%s' "${2:-}"; return 0; }
        shift
    done
    return 1
}

# First argument that is not a flag and not a flag's value.
firstpos() {
    local skip_next=false a
    for a in "$@"; do
        if [ "$skip_next" = true ]; then skip_next=false; continue; fi
        case "$a" in
            -*) case "$a" in
                    -r|-w|-o|-l|-f|-sub|-perm|-list|--rate-limit|-rate|-c|-threads|\
                    -timeout|-retries|-depth|-numbers|-concurrency|-severity|-tags|\
                    -top-ports|-scan-type|-stats-interval|-jsonl-export|--timeout|\
                    --chrome-path|--screenshot-path) skip_next=true ;;
                esac
                ;;
            *)  printf '%s' "$a"; return 0 ;;
        esac
    done
    return 1
}

case "$name" in
    subfinder)
        [ "${FAKE_SUBFINDER_FAIL:-0}" = 1 ] && { printf 'source unavailable\n' >&2; exit 42; }
        d=$(flagval -d "$@") || exit 1
        out=$(flagval -o "$@") || out="/dev/stdout"
        printf 'www.%s\napi.%s\ndev.%s\nstaging.%s\nnot%s.attacker.net\n' \
            "$d" "$d" "$d" "$d" "$d" > "$out"
        if [ "${FAKE_EXTRA_NAMES:-0}" = 1 ]; then
            printf 'bulk-miss.%s\naaaa-only.%s\n_service.%s\nnx.%s\ncustomer.mx.saas.%s\nmx.saas.%s\nmail.other.%s\n' "$d" "$d" "$d" "$d" "$d" "$d" "$d" >> "$out"
        fi
        ;;
    assetfinder)
        d="${!#}"
        printf 'mail.%s\napi.%s\nblog.%s\n%s.evil.example\n' "$d" "$d" "$d" "$d"
        ;;
    amass)
        d=$(flagval -d "$@") || exit 1
        case "${1:-}" in
            enum)
                if flagval -o "$@" >/dev/null; then printf 'flag provided but not defined: -o\n' >&2; exit 1; fi
                [ "${FAKE_AMASS_FAIL:-0}" = 1 ] && { printf 'engine unavailable\n' >&2; exit 42; }
                printf 'Session Scope\nFQDN:\n%s\n' "$d"
                ;;
            subs)
                [ "${FAKE_AMASS_EXPORT_FAIL:-0}" = 1 ] && { printf 'database unavailable\n' >&2; exit 42; }
                printf 'vpn.%s\nlegacy.%s\n' "$d" "$d"
                ;;
            *) exit 1 ;;
        esac
        ;;
    findomain)
        d=$(flagval -t "$@") || exit 1
        printf 'api.%s\n' "$d"
        ;;
    curl)
        [ "${FAKE_CURL_FAIL:-0}" = 1 ] && { printf 'synthetic upstream failure\n' >&2; exit 56; }
        out=$(flagval -o "$@") || out=/dev/stdout
        case "${!#}" in
            *crt.sh*) printf '[{"name_value":"api.example.com"}]\n' > "$out" ;;
            *web.archive.org*) printf 'https://www.example.com/index.html\n' > "$out" ;;
            *) printf 'www\napi\n' > "$out" ;;
        esac
        ;;
    gau)
        while IFS= read -r d; do printf 'https://archive.%s/item\n' "$d"; done
        ;;
    tlsx|dig) exit 0 ;;
    waybackurls)
        while IFS= read -r d; do
            [ -n "$d" ] || continue
            printf 'https://www.%s/index.html\nhttps://cdn.%s/app.js\nhttp://user@old.%s:8080/x?y=1\n' \
                "$d" "$d" "$d"
            [ "${FAKE_EXTRA_NAMES:-0}" = 1 ] && printf 'https://customer.mx.saas.%s/reintroduced\n' "$d"
        done
        [ "${FAKE_WAYBACK_TIMEOUT:-0}" = 1 ] && exit 124
        ;;
    puredns)
        sub="${1:-}"; shift || true
        w=$(flagval -w "$@") || w="/dev/stdout"
        case "$sub" in
            resolve)
                inp=$(firstpos "$@") || inp=""
                # Resolve everything except names containing "nx".
                if [ -n "$inp" ] && [ -f "$inp" ]; then
                    if [ "${FAKE_DNS_DROP:-0}" = 1 ]; then grep -vE 'nx|bulk-miss|aaaa-only|_' "$inp" | sort -u > "$w"
                    else grep -v 'nx' "$inp" | sort -u > "$w"; fi
                else
                    : > "$w"
                fi
                ;;
            bruteforce)
                # args: <wordlist> <domain> ...
                wl=$(firstpos "$@") || wl=""
                dom=""
                seen=false
                for a in "$@"; do
                    case "$a" in -*) continue ;; esac
                    if [ "$seen" = false ]; then seen=true; continue; fi
                    dom="$a"; break
                done
                : > "$w"
                if [ -n "$wl" ] && [ -f "$wl" ] && [ -n "$dom" ]; then
                    head -n 3 "$wl" | while IFS= read -r word; do
                        [ -n "$word" ] && printf '%s.%s\n' "$word" "$dom"
                    done > "$w"
                fi
                ;;
            *) exit 1 ;;
        esac
        ;;
    gotator)
        sub=$(flagval -sub "$@") || exit 1
        [ -f "$sub" ] || exit 0
        while IFS= read -r h; do
            [ -n "$h" ] || continue
            printf 'test-%s\nold-%s\n' "$h" "$h"
        done < "$sub"
        ;;
    httpx)
        l=$(flagval -l "$@") || exit 1
        out=$(flagval -o "$@") || out="/dev/stdout"
        json=false
        for a in "$@"; do [ "$a" = "-json" ] && json=true; done
        : > "$out"
        [ -f "$l" ] || exit 0
        n=0
        while IFS= read -r h; do
            [ -n "$h" ] || continue
            n=$(( n + 1 ))
            # Only every other host is "live", so counts differ from input.
            [ $(( n % 2 )) -eq 0 ] && continue
            case "$h" in
                *:*) url="http://${h}" ;;
                *)   url="https://${h}" ;;
            esac
            if [ "$json" = true ]; then
                printf '{"timestamp":"2026-01-01T00:00:00Z","url":"%s","status_code":200,' "$url"
                printf '"title":"Example \\"quoted\\" title","tech":["nginx"],"content_length":1234}\n'
            else
                printf '%s\n' "$url"
            fi
        done < "$l" >> "$out"
        ;;
    naabu)
        l=$(flagval -list "$@") || exit 1
        out=$(flagval -o "$@") || out="/dev/stdout"
        : > "$out"
        [ -f "$l" ] || exit 0
        head -n 3 "$l" | while IFS= read -r h; do
            [ -n "$h" ] || continue
            printf '%s:80\n%s:443\n%s:8443\n' "$h" "$h" "$h"
        done > "$out"
        ;;
    katana)
        l=$(flagval -list "$@") || exit 1
        out=$(flagval -o "$@") || out="/dev/stdout"
        : > "$out"
        [ -f "$l" ] || exit 0
        while IFS= read -r u; do
            [ -n "$u" ] || continue
            host="${u#*://}"; host="${host%%/*}"; host="${host%%:*}"
            base="${host#*.}"
            printf '%s/login\n%s/api/v1/users\nhttps://hidden.%s/secret\n' "$u" "$u" "$base"
        done < "$l" > "$out"
        if [ -n "${FAKE_KATANA_STATE_FILE:-}" ]; then
            calls=0; [ -f "$FAKE_KATANA_STATE_FILE" ] && calls=$(cat "$FAKE_KATANA_STATE_FILE")
            calls=$((calls+1)); printf '%s\n' "$calls" > "$FAKE_KATANA_STATE_FILE"
            [ "$calls" = "${FAKE_KATANA_TIMEOUT_CALL:-0}" ] && exit 124
            [ "$calls" = "${FAKE_KATANA_DELAY_CALL:-0}" ] && sleep 1
        fi
        ;;
    dnsx)
        l=$(flagval -l "$@") || exit 1
        out=$(flagval -o "$@") || out=/dev/stdout
        [ "${FAKE_DNSX_FAIL:-0}" = 1 ] && { printf 'resolver unavailable\n' >&2; exit 42; }
        grep -v 'nx' "$l" | sort -u > "$out"
        ;;
    nuclei)
        # -update-templates is a no-op here.
        for a in "$@"; do [ "$a" = "-update-templates" ] && exit 0; done
        l=$(flagval -l "$@") || exit 1
        out=$(flagval -o "$@") || out="/dev/stdout"
        jsonl=$(flagval -jsonl-export "$@") || jsonl=""
        : > "$out"
        [ -f "$l" ] || exit 0
        first=$(head -n 1 "$l")
        [ -n "$first" ] || exit 0
        {
            printf '[tech-detect:nginx] [http] [info] %s\n' "$first"
            printf '[CVE-2026-0001] [http] [critical] %s\n' "$first"
            printf '[missing-csp] [http] [medium] %s\n' "$first"
        } > "$out"
        [ -n "$jsonl" ] && printf '{"template-id":"CVE-2026-0001","info":{"severity":"critical"},"matched-at":"%s"}\n' \
            "$first" > "$jsonl"
        ;;
    gowitness)
        f=$(flagval -f "$@") || exit 1
        dir=$(flagval --screenshot-path "$@") || dir="."
        mkdir -p "$dir"
        [ -f "$f" ] || exit 0
        i=0
        while IFS= read -r u; do
            [ -n "$u" ] || continue
            i=$(( i + 1 ))
            printf 'fake png\n' > "${dir}/shot_${i}.png"
        done < "$f"
        ;;
    massdns) exit 0 ;;
    *) printf 'fake-tool: unhandled name %s\n' "$name" >&2; exit 127 ;;
esac
exit 0
