#!/usr/bin/env bash
# Regression tests use synthetic names and the strict local fixture toolchain.

test_hardening_units() {
    printf '\n== Collection filters and crawl budgets\n'
    local saved_out="${OUT_DIR:-}" path="${TMP}/exclusion-unit"
    mkdir -p "$path"; OUT_DIR="$path"
    printf '*.mx.saas.example.com\nexact.example.com\n' > "$path/collection-exclusions.txt"
    printf 'customer.mx.saas.example.com\ndeep.customer.mx.saas.example.com\nmx.saas.example.com\nmail.other.example.com\nexact.example.com\nnotmx.saas.example.com\n' \
        | pipe_apply_exclusions > "$path/filtered"
    is "wildcard excludes descendants and preserves suffix apex" "$(compat_count "$path/filtered")" 3
    yes_ "other mail namespace retained" "$(grep -qx 'mail.other.example.com' "$path/filtered"; echo $?)"
    printf 'https://user@CUSTOMER.mx.saas.example.com:443/reintroduced\nhttps://mx.saas.example.com/path\n' \
        | pipe_apply_exclusions urls > "$path/urls"
    is "URL ingress applies the same filter" "$(compat_count "$path/urls")" 1
    printf '_service.example.com\nmalformed;example.com\nmalformed..example.com\n192.0.2.1\n' | pipe_collection_names example.com > "$path/valid-names"
    is "validates names before disabling bulk sanitization" "$(compat_count "$path/valid-names")" 1
    is "small crawl budget" "$(pipe_crawl_budget 1)" 2700
    is "budget scales with seed count" "$(pipe_crawl_budget 1001)" 5400
    is "automatic budget is capped" "$(pipe_crawl_budget 50000)" 21600
    is "explicit whole-hour budget" "$(pipe_parse_crawl_budget 2h)" 7200
    local bad
    for bad in 0 -1 1.5h 1h30m 169h 999999999999999999999h; do
        if pipe_parse_crawl_budget "$bad" >/dev/null; then bad "rejects budget $bad" "accepted"; else ok "rejects budget $bad"; fi
    done
    printf '*.bad..example.com\n' > "$path/invalid"
    if pipe_read_exclusions "$path/invalid" >/dev/null; then bad "reject invalid exclusion syntax" "accepted"; else ok "reject invalid exclusion syntax"; fi
    OUT_DIR="$saved_out"
}

test_hardening_e2e() {
    printf '\n== Hardening regressions\n'
    local out="${TMP}/hardening-e2e" run trace="${TMP}/hardening.trace" exclusions="${TMP}/hardening-exclusions.txt"
    printf '*.mx.saas.example.com\n' > "$exclusions"
    local status_out="${TMP}/selected-status" status_run
    if FAKE_CURL_FAIL=1 run_scan "$status_out" --only p1,p5,p7; then
        ok "selected phases succeed despite HTTP source failures"
    else bad "selected phases succeed despite HTTP source failures" "scan failed"; fi
    status_run=$(find "$status_out/recon_example.com" -maxdepth 1 -mindepth 1 -type d -name '20*' | sort -r | head -n 1)
    yes_ "selected run reports completion" "$(grep -q 'Scan complete: example.com' "$status_run/logs/leetenum.log"; echo $?)"
    yes_ "selected run remains resumable without baseline marker" "$([ ! -f "$status_run/.state/complete" ]; echo $?)"
    yes_ "crt.sh failure recorded durably" "$(grep -q 'crt.sh failed' "$status_run/optional-warnings.log"; echo $?)"
    yes_ "Wayback failure is not swallowed by pipeline" "$(grep -q 'Wayback index failed' "$status_run/optional-warnings.log"; echo $?)"
    yes_ "report warning count reflects failures" "$(grep -q 'Optional source warnings | 2 ' "$status_run/reports/summary.md"; echo $?)"
    if FAKE_TOOL_TRACE="$trace" FAKE_EXTRA_NAMES=1 FAKE_DNS_DROP=1 FAKE_AMASS_FAIL=1 FAKE_SUBFINDER_FAIL=1 \
        run_scan "$out" --only p1 --exclude-file "$exclusions"; then ok "optional source failures do not fail passive phase"
    else bad "optional source failures do not fail passive phase" "scan failed"; fi
    run=$(find "$out/recon_example.com" -maxdepth 1 -mindepth 1 -type d -name '20*' | sort -r | head -n 1)
    yes_ "optional failure still checkpoints p1" "$([ -f "$run/.state/p1.done" ]; echo $?)"
    yes_ "optional failure is recorded" "$([ -s "$run/optional-warnings.log" ]; echo $?)"
    if grep -q 'amass enum .* -o ' "$trace"; then bad "Amass enum never uses unsupported -o" "found"; else ok "Amass enum never uses unsupported -o"; fi
    # Rerun with the strict v5 fixture successful and test first-pass misses.
    if FAKE_TOOL_TRACE="$trace" FAKE_EXTRA_NAMES=1 FAKE_DNS_DROP=1 \
        run_scan "$out" --only p1 --exclude-file "$exclusions"; then ok "successful Amass export and DNS recovery"
    else bad "successful Amass export and DNS recovery" "scan failed"; fi
    yes_ "reads Amass subs names" "$(grep -qx 'vpn.example.com' "$run/01_passive.txt"; echo $?)"
    local h
    for h in bulk-miss.example.com aaaa-only.example.com _service.example.com; do
        yes_ "recovers $h omitted by bulk pass" "$(grep -qx "$h" "$run/01_passive.txt"; echo $?)"
    done
    yes_ "NX name retained separately" "$(grep -qx 'nx.example.com' "$run/01_unresolved.txt"; echo $?)"
    if grep -qx 'nx.example.com' "$run/01_passive.txt"; then bad "does not promote unresolved name" "found"; else ok "does not promote unresolved name"; fi
    yes_ "recovery queries A and AAAA" "$(grep -q 'dnsx .* -a -aaaa ' "$trace"; echo $?)"
    yes_ "recovery rate capped at 500" "$(grep -q 'dnsx .* -rate-limit 500 ' "$trace"; echo $?)"
    yes_ "disables bulk sanitization for validated candidates" "$(grep -q -- '--skip-sanitize' "$trace"; echo $?)"
    yes_ "exclusion apex retained" "$(grep -qx 'mx.saas.example.com' "$run/01_candidates.txt"; echo $?)"
    yes_ "other mail namespace retained in input" "$(grep -qx 'mail.other.example.com' "$run/01_candidates.txt"; echo $?)"

    local i=0 calls="${TMP}/katana-calls"
    : > "$run/05_live_urls.txt"
    while [ "$i" -lt 201 ]; do printf 'https://seed%s.example.com\n' "$i" >> "$run/05_live_urls.txt"; i=$((i+1)); done
    local crawl_trace="${TMP}/crawl.trace"
    if FAKE_TOOL_TRACE="$crawl_trace" FAKE_EXTRA_NAMES=1 FAKE_KATANA_STATE_FILE="$calls" FAKE_KATANA_TIMEOUT_CALL=2 \
        run_scan "$out" --only p7 --crawl-budget 2h --exclude-file "$exclusions"; then bad "truncated crawl remains pending" "reported success"
    else ok "truncated crawl remains pending"; fi
    is "only completed seed batch checkpointed" "$(compat_count "$run/07_katana_done_urls.txt")" 100
    local before; before=$(compat_count "$run/07_urls.txt")
    yes_ "partial URL output retained" "$([ "$before" -gt 0 ]; echo $?)"
    yes_ "truncated p7 has no done marker" "$([ ! -f "$run/.state/p7.done" ]; echo $?)"
    if FAKE_TOOL_TRACE="$crawl_trace" FAKE_EXTRA_NAMES=1 FAKE_KATANA_STATE_FILE="$calls" \
        run_scan "$out" --resume-crawl --crawl-budget 2h --exclude-file "$exclusions"; then ok "continues unfinished crawl"
    else bad "continues unfinished crawl" "scan failed"; fi
    is "all seeds checkpointed after continuation" "$(compat_count "$run/07_katana_done_urls.txt")" 201
    is "completed batches are not replayed" "$(cat "$calls")" 4
    is "completed archive source is not replayed" "$(grep -c '^waybackurls' "$crawl_trace")" 1
    yes_ "URL output survives continuation" "$([ "$(compat_count "$run/07_urls.txt")" -ge "$before" ]; echo $?)"
    yes_ "continuation completes p7" "$([ -f "$run/.state/p7.done" ]; echo $?)"
    if grep -q 'customer.mx.saas.example.com' "$run/01_candidates.txt" "$run/07_candidates.txt" "$run/07_urls.txt" "$run/master_dns.txt"; then
        bad "exclusion survives archive reintroduction and master rebuild" "excluded name found"
    else ok "exclusion survives archive reintroduction and master rebuild"; fi
    if run_scan "$out" --resume-crawl >/dev/null 2>&1; then bad "resume refuses changed filters" "accepted"
    else ok "resume refuses changed filters"; fi

    if FAKE_EXTRA_NAMES=1 FAKE_DNS_DROP=1 FAKE_DNSX_FAIL=1 run_scan "${TMP}/hardening-dns-failure" --only p1; then
        bad "required DNS recovery failure remains pending" "reported success"
    else ok "required DNS recovery failure remains pending"; fi
}
