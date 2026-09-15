#!/usr/bin/env bash
# Collection reliability helpers shared by passive discovery and crawling.

pipe_optional_warning() {
    printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "${OUT_DIR}/optional-warnings.log" \
        || { PIPE_PHASE_FAILED=true; return 1; }
    ui_warn "$1"
}

pipe_read_exclusions() {
    local path="$1"
    [ -r "$path" ] || return 1
    compat_bytes awk '
        { sub(/#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); p=tolower($0); if (p=="") next
          n=p; sub(/^\*\./, "", n)
          if (length(n)>253 || n !~ /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/) { exit 1 }
          count=split(n, labels, "."); for (i=1;i<=count;i++) if (length(labels[i])>63) exit 1
          print p }
    ' "$path" | compat_sort -u
}

pipe_bind_exclusions() {
    local tmp="${WORK_DIR}/exclusions.txt" dest="${OUT_DIR}/collection-exclusions.txt"
    : > "$tmp"
    if [ -n "${PIPE_ARG_EXCLUDE_FILE:-}" ]; then pipe_read_exclusions "$PIPE_ARG_EXCLUDE_FILE" > "$tmp" || return 1; fi
    if [ "$RESUMED" = "true" ]; then
        if [ -e "$dest" ]; then
            cmp -s "$tmp" "$dest" || { ui_warn "Collection exclusions differ; use the same file or --fresh"; return 1; }
        elif [ -s "$tmp" ]; then ui_warn "Collection exclusions differ; use --fresh"; return 1
        fi
    fi
    cp "$tmp" "$dest"
}

# Load patterns once and match label boundaries. This stays fast for million-line
# inputs and never interprets a hostname or pattern as shell syntax.
pipe_apply_exclusions() {
    local mode="${1:-names}" patterns="${OUT_DIR:-}/collection-exclusions.txt"
    compat_bytes awk -v patterns="$patterns" -v mode="$mode" '
        BEGIN { while ((getline p < patterns)>0) { if (substr(p,1,2)=="*.") suffix[substr(p,3)]=1; else exact[p]=1 }; close(patterns) }
        { h=tolower($0); gsub(/\r/, "", h); sub(/^[[:space:]]+/, "", h); sub(/[[:space:]]+$/, "", h)
          if (mode=="urls") { sub(/^https?:\/\//,"",h); sub(/[\/?#].*$/, "",h); sub(/^.*@/, "",h); sub(/:[0-9]+$/, "",h) }
          sub(/^\*\./, "",h); sub(/\.$/, "",h)
          if (h in exact) next
          excluded=0; while (index(h,".")>0) { sub(/^[^.]+\./,"",h); if (h in suffix) { excluded=1; break } }
          if (!excluded) print $0 }
    '
}

pipe_collection_names() {
    # Validate before --skip-sanitize: allow legitimate underscore service labels,
    # reject malformed names and addresses, and preserve the existing scope gate.
    compat_bytes awk '
        { n=tolower($0); gsub(/\r/, "", n); gsub(/^[[:space:]]+|[[:space:]]+$/, "", n)
          sub(/^\*\./, "", n); sub(/^\./, "", n); sub(/\.$/, "", n)
          if (length(n)>253 || n !~ /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/) next
          count=split(n, labels, "."); valid=1; ipv4=(count==4)
          for (i=1;i<=count;i++) { if (length(labels[i])>63) valid=0; if (labels[i] !~ /^[0-9]+$/ || labels[i]+0>255 || (length(labels[i])>1 && substr(labels[i],1,1)=="0")) ipv4=0 }
          if (valid && !ipv4) print n }
    ' | pipe_filter_scope "$1" | pipe_apply_exclusions
}

pipe_resolve_candidates() {
    local target="$1" in="$2" art="$3" prefix="$4" what="$5"
    local bulk="${WORK_DIR}/${what}_bulk.txt" recovered="${WORK_DIR}/${what}_recovered.txt"
    local misses="${OUT_DIR}/${prefix}_unresolved.txt" combined="${WORK_DIR}/${what}_combined.txt" rc=0 rate
    local bulk_input="${WORK_DIR}/${what}_bulk_candidates.txt" known="${WORK_DIR}/${what}_previously_verified.txt"
    : > "$bulk"; : > "$recovered"
    : > "$known"
    if [ "$what" = crawled ] && [ -s "${OUT_DIR}/master_dns.txt" ]; then
        compat_bytes comm -12 "$in" "${OUT_DIR}/master_dns.txt" > "$known" || return 1
    fi
    compat_bytes comm -23 "$in" "$known" > "$bulk_input" || return 1
    if [ -s "$bulk_input" ] && pipe_need puredns "${what} bulk resolution"; then
        ui_step_cfg "${LOG_DIR}/resolve_${what}.log" "$bulk" "" true
        ui_run "Bulk resolving ${what} candidates" -- puredns resolve "$bulk_input" -r "$WL_RESOLVERS" -w "$bulk" \
            --rate-limit "$DNS_RATE" --skip-wildcard-filter --skip-validation --skip-sanitize \
            || pipe_optional_warning "puredns ${what} bulk pass failed; independent recovery remains enabled"
    fi
    cat "$bulk" "$known" | compat_bytes tr '[:upper:]' '[:lower:]' | pipe_collection_names "$target" | compat_sort -u > "$combined" || return 1
    compat_bytes comm -12 "$in" "$combined" > "${bulk}.accepted" || return 1
    mv "${bulk}.accepted" "$bulk" || return 1
    compat_bytes comm -23 "$in" "$bulk" > "${misses}.part" || return 1
    mv "${misses}.part" "$misses" || return 1
    if [ -s "$misses" ]; then
        if pipe_need dnsx "${what} A/AAAA recovery"; then
            rate="$DNS_RATE"; [ "$rate" -gt 500 ] && rate=500
            ui_step_cfg "${LOG_DIR}/recover_${what}.log" "$recovered" "" false
            ui_run "Retrying missed ${what} names (A/AAAA)" -- dnsx -l "$misses" -a -aaaa \
                -silent -no-color -disable-update-check -threads 100 -rate-limit "$rate" -retry 3 -o "$recovered" || rc=$?
        else rc=1; ui_warn "dnsx is required to verify missed candidates"; fi
    fi
    cat "$bulk" "$recovered" | compat_bytes tr '[:upper:]' '[:lower:]' | pipe_collection_names "$target" | compat_sort -u > "$combined" || return 1
    compat_bytes comm -12 "$in" "$combined" > "${art}.part" || return 1
    mv "${art}.part" "$art" || return 1
    compat_bytes comm -23 "$in" "$art" > "${misses}.part" || return 1
    mv "${misses}.part" "$misses" || return 1
    ui_detail "unresolved candidates retained" "$(compat_count "$misses")"
    return "$rc"
}

pipe_parse_crawl_budget() {
    local value="$1" unit=1 n
    printf '%s' "$value" | compat_bytes grep -Eq '^[1-9][0-9]*[smh]?$' || return 1
    case "$value" in *s) value="${value%s}" ;; *m) value="${value%m}"; unit=60 ;; *h) value="${value%h}"; unit=3600 ;; esac
    [ "${#value}" -le 6 ] || return 1
    n=$(( value * unit )); [ "$n" -le 604800 ] || return 1
    printf '%s\n' "$n"
}

pipe_crawl_budget() {
    local blocks=$(( ($1 + 999) / 1000 ))
    [ "$blocks" -lt 1 ] && blocks=1; [ "$blocks" -gt 8 ] && blocks=8
    printf '%s\n' "$((blocks * 2700))"
}

pipe_clear_crawl_progress() {
    rm -f "${OUT_DIR}/07_katana_done_urls.txt" "${OUT_DIR}/07_katana_urls.txt" \
        "${OUT_DIR}/07_wayback_urls.txt" "${OUT_DIR}/07_gau_urls.txt" \
        "${OUT_DIR}/07_wayback_complete" "${OUT_DIR}/07_gau_complete" "${OUT_DIR}/07_crawl_pending.txt" \
        "${OUT_DIR}/07_katana_attempt.txt" "${OUT_DIR}/07_wayback_attempt.txt" "${OUT_DIR}/07_gau_attempt.txt"
}

pipe_merge_crawl_output() {
    local dest="$1" source="$2"
    { if [ -f "$dest" ]; then cat "$dest" || return 1; fi
      if [ -f "$source" ]; then cat "$source" || return 1; fi; } \
        | compat_bytes awk '/^https?:\/\//' | pipe_apply_exclusions urls | compat_sort -u > "${dest}.part" || return 1
    mv "${dest}.part" "$dest"
}

pipe_crawl_urls() {
    local live="$1" total completed remaining limit deadline left start end batch out rc result=0 source bin marker archive_limit=600
    total=$(compat_count "$live")
    # Recover output even if Ctrl-C interrupted the UI before its merge step.
    for source in katana wayback gau; do
        pipe_merge_crawl_output "${OUT_DIR}/07_${source}_urls.txt" "${OUT_DIR}/07_${source}_attempt.txt" || return 1
    done
    : > "${OUT_DIR}/07_crawl_pending.txt"
    [ "$total" -gt 0 ] || return 0
    if [ -n "${PIPE_ARG_CRAWL_BUDGET:-}" ]; then limit=$(pipe_parse_crawl_budget "$PIPE_ARG_CRAWL_BUDGET") || return 1
        archive_limit="$limit"
    else limit=$(pipe_crawl_budget "$total"); fi
    completed="${OUT_DIR}/07_katana_done_urls.txt"
    [ -e "$completed" ] || : > "$completed"
    remaining="${WORK_DIR}/katana_remaining.txt"
    compat_bytes comm -23 "$live" "$completed" > "$remaining" || return 1
    deadline=$(( $(date +%s) + limit ))
    if pipe_need katana "crawling"; then
        start=1; total=$(compat_count "$remaining")
        while [ "$start" -le "$total" ]; do
            left=$(( deadline - $(date +%s) ))
            if [ "$left" -le 0 ]; then printf 'katana\n' >> "${OUT_DIR}/07_crawl_pending.txt"; result=124; break; fi
            end=$(( start + 99 )); batch="${WORK_DIR}/katana_input.txt"; out="${OUT_DIR}/07_katana_attempt.txt"
            compat_bytes sed -n "${start},${end}p" "$remaining" > "$batch" || return 1
            : > "$out"
            ui_step_cfg "${LOG_DIR}/katana.log" "$out" "" true
            rc=0
            COMPAT_TIMEOUT_SIGNAL=INT ui_run "Crawling seed batch (${limit}s total budget)" -- compat_timeout "$left" \
                katana -list "$batch" -depth 2 -js-crawl -concurrency "$KATANA_CONC" \
                -rate-limit 100 -timeout 10 -silent -no-color -o "$out" || rc=$?
            pipe_merge_crawl_output "${OUT_DIR}/07_katana_urls.txt" "$out" || return 1
            if [ "$rc" -ne 0 ]; then
                printf 'katana\n' >> "${OUT_DIR}/07_crawl_pending.txt"
                pipe_optional_warning "katana stopped; saved output and unfinished seed batch retained"
                [ "$rc" -eq 124 ] && result=124
                break
            fi
            cat "$completed" "$batch" | compat_sort -u > "${completed}.part" || return 1
            mv "${completed}.part" "$completed" || return 1
            start=$(( end + 1 ))
        done
    else pipe_optional_warning "katana not installed; other crawl sources remain enabled"
    fi
    for source in wayback gau; do
        marker="${OUT_DIR}/07_${source}_complete"
        [ -f "$marker" ] && continue
        bin="$source"; [ "$source" = wayback ] && bin=waybackurls
        if ! pipe_need "$bin" "archive mining"; then pipe_optional_warning "${bin} not installed"; continue; fi
        out="${OUT_DIR}/07_${source}_attempt.txt"
        : > "$out"; rc=0
        ui_step_cfg "${LOG_DIR}/${bin}.log" "$out" "" true
        if [ "$source" = wayback ]; then
            ARCHIVE_OUT="$out" ARCHIVE_LIMIT="$archive_limit" ui_run_sh "waybackurls archive mining (${archive_limit}s budget)" \
                'printf "%s\n" "$PIPE_TARGET" | compat_timeout "$ARCHIVE_LIMIT" waybackurls > "$ARCHIVE_OUT"' || rc=$?
        else
            ARCHIVE_OUT="$out" ARCHIVE_LIMIT="$archive_limit" ui_run_sh "gau archive mining (${archive_limit}s budget)" \
                'printf "%s\n" "$PIPE_TARGET" | compat_timeout "$ARCHIVE_LIMIT" gau --subs --threads 5 > "$ARCHIVE_OUT"' || rc=$?
        fi
        pipe_merge_crawl_output "${OUT_DIR}/07_${source}_urls.txt" "$out" || return 1
        if [ "$rc" -eq 0 ]; then printf 'complete\n' > "$marker" || return 1
        else
            printf '%s\n' "$bin" >> "${OUT_DIR}/07_crawl_pending.txt"
            pipe_optional_warning "${bin} stopped; partial archive output retained"
            [ "$rc" -eq 124 ] && result=124
        fi
    done
    [ "$result" -eq 0 ] || ui_warn "Crawl budget exhausted; use --resume-crawl --crawl-budget 2h to continue"
    return "$result"
}
