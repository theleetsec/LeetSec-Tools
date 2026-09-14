#!/usr/bin/env bash
# lib/ui.sh — terminal presentation layer.
#
# Design rules:
#   1. Capabilities are probed, never assumed. Colour, Unicode and cursor
#      control each degrade independently, so the same code path produces a
#      live animated view on a terminal and clean greppable lines in a cron
#      log or `tee` pipeline.
#   2. Every long-running step reports elapsed time and, where a result file
#      exists, a live row count. The user should never wonder if it is stuck.
#   3. Widths come from the real terminal, not a hardcoded 78 columns.
#
# Sourced, never executed.

# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------
ui_init() {
    UI_STDOUT_TTY="false"; [ -t 1 ] && UI_STDOUT_TTY="true"
    UI_COLS=80
    UI_ANIMATE="false"
    UI_START_TS=$(date +%s)

    if [ "$UI_STDOUT_TTY" = "true" ]; then
        UI_COLS=$( { tput cols 2>/dev/null || echo 80; } )
        [[ "$UI_COLS" =~ ^[0-9]+$ ]] || UI_COLS=80
        [ "$UI_COLS" -lt 60 ] && UI_COLS=60
        [ "$UI_COLS" -gt 120 ] && UI_COLS=120
        UI_ANIMATE="true"
    fi

    # Colour: honour NO_COLOR (informal standard), FORCE_COLOR, dumb terminals.
    local depth=0
    if [ "$UI_STDOUT_TTY" = "true" ] && [ "${TERM:-dumb}" != "dumb" ]; then
        depth=$( { tput colors 2>/dev/null || echo 0; } )
        [[ "$depth" =~ ^[0-9]+$ ]] || depth=0
    fi
    [ -n "${NO_COLOR:-}" ] && depth=0
    [ -n "${FORCE_COLOR:-}" ] && depth=256
    UI_COLOR_DEPTH="$depth"

    # Bounded widths so a redrawn line can never wrap. Computing them once
    # means the animation loop does no measurement work per frame.
    UI_BAR_W=24; [ "$UI_COLS" -lt 80 ] && UI_BAR_W=12
    UI_LABEL_MAX=$(( UI_COLS - UI_BAR_W - 24 ))
    [ "$UI_LABEL_MAX" -lt 16 ] && UI_LABEL_MAX=16

    ui_load_palette
    ui_load_glyphs
}

# Muted, professional palette. One accent colour, semantic states, and dim
# structural text — readable on both light and dark backgrounds, and safe to
# paste into a client-facing report.
ui_load_palette() {
    if [ "${UI_COLOR_DEPTH:-0}" -ge 8 ]; then
        C_RESET=$'\033[0m';  C_BOLD=$'\033[1m';   C_DIM=$'\033[2m'
        C_ACCENT=$'\033[36m'                       # cyan — headings, labels
        C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
        C_TEXT=$'\033[39m'
        if [ "${UI_COLOR_DEPTH:-0}" -ge 256 ]; then
            C_ACCENT=$'\033[38;5;38m'              # steel blue
            C_DIM=$'\033[38;5;244m'                # mid grey, not near-black
            C_OK=$'\033[38;5;71m'
            C_WARN=$'\033[38;5;179m'
            C_ERR=$'\033[38;5;167m'
        fi
    else
        C_RESET=''; C_BOLD=''; C_DIM=''; C_ACCENT=''
        C_OK=''; C_WARN=''; C_ERR=''; C_TEXT=''
    fi
}

# Unicode is not universal: minimal containers run with LC_ALL=C, and Windows
# consoles under Git Bash mangle box drawing. Probe the charset instead.
ui_load_glyphs() {
    local charset=""
    charset=$(locale charmap 2>/dev/null || true)
    if [ -z "$charset" ]; then
        charset="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
    fi

    if printf '%s' "$charset" | grep -qi "utf-\?8" && [ "$LS_OS" != "windows" ]; then
        UI_UNICODE="true"
        G_OK="✓"; G_ERR="✗"; G_WARN="!"; G_INFO="·"; G_ARROW="→"
        G_HR="─"; G_BAR_FULL="█"; G_BAR_EMPTY="░"
        UI_SPIN=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    else
        UI_UNICODE="false"
        G_OK="+"; G_ERR="x"; G_WARN="!"; G_INFO="-"; G_ARROW=">"
        G_HR="-"; G_BAR_FULL="#"; G_BAR_EMPTY="."
        UI_SPIN=("|" "/" "-" "\\")
    fi
}

# ---------------------------------------------------------------------------
# Output primitives
#
# Everything funnels through ui_emit so that the plain-text mirror in the log
# file stays free of escape codes. Timestamps are added only in the file, to
# keep the interactive view uncluttered.
# ---------------------------------------------------------------------------
ui_set_logfile() { UI_LOG_FILE="$1"; : > "$UI_LOG_FILE" 2>/dev/null || UI_LOG_FILE=""; }

ui_emit() {
    local styled="$1" plain="$2"
    printf '%b\n' "$styled"
    if [ -n "${UI_LOG_FILE:-}" ]; then
        printf '%s %s\n' "$(date '+%H:%M:%S')" "$plain" >> "$UI_LOG_FILE" 2>/dev/null || true
    fi
}

ui_info()  { ui_emit "${C_DIM}${G_INFO}${C_RESET} $1" "[info] $1"; }
ui_ok()    { ui_emit "${C_OK}${G_OK}${C_RESET} $1"    "[ ok ] $1"; }
ui_warn()  { ui_emit "${C_WARN}${G_WARN}${C_RESET} $1" "[warn] $1"; }
ui_err()   { ui_emit "${C_ERR}${G_ERR}${C_RESET} $1"  "[fail] $1"; }
ui_blank() { printf '\n'; [ -n "${UI_LOG_FILE:-}" ] && printf '\n' >> "$UI_LOG_FILE"; }

ui_die() { ui_err "$1"; ui_cursor_show; exit "${2:-1}"; }

ui_hr() {
    local line
    line=$(ui_repeat "$G_HR" "$UI_COLS")
    ui_emit "${C_DIM}${line}${C_RESET}" "$(ui_repeat '-' "$UI_COLS")"
}

# Indented detail line under a step, e.g. "  → resolved: 1204".
ui_detail() {
    local label="$1" value="$2"
    ui_emit "  ${C_DIM}${G_ARROW}${C_RESET} ${C_DIM}${label}:${C_RESET} ${C_BOLD}${value}${C_RESET}" \
            "    ${label}: ${value}"
}

ui_cursor_hide() { [ "$UI_ANIMATE" = "true" ] && printf '\033[?25l'; return 0; }
ui_cursor_show() { [ "$UI_ANIMATE" = "true" ] && printf '\033[?25h'; return 0; }

# Repeat a string N times.
#
# `tr ' ' '─'` cannot do this: tr works on bytes, so repeating any multi-byte
# glyph produced mojibake in the rules and progress bars. Bash pattern
# substitution is character-aware, so pad with spaces and swap them out.
ui_repeat() {
    local unit="$1" n="$2" pad
    [ "$n" -le 0 ] && return 0
    printf -v pad '%*s' "$n" ''
    printf '%s' "${pad// /$unit}"
}

# ---------------------------------------------------------------------------
# Time formatting
# ---------------------------------------------------------------------------
ui_fmt_duration() {
    local s="${1:-0}"
    [[ "$s" =~ ^[0-9]+$ ]] || s=0
    if [ "$s" -lt 60 ]; then
        printf '%ds\n' "$s"
    elif [ "$s" -lt 3600 ]; then
        printf '%dm%02ds\n' $(( s / 60 )) $(( s % 60 ))
    else
        printf '%dh%02dm%02ds\n' $(( s / 3600 )) $(( (s % 3600) / 60 )) $(( s % 60 ))
    fi
}

ui_elapsed() { ui_fmt_duration $(( $(date +%s) - UI_START_TS )); }

# ---------------------------------------------------------------------------
# Banner
#
# No clear(): wiping the user's scrollback destroys the context they need when
# a scan fails or when they scroll back to read an earlier phase.
# ---------------------------------------------------------------------------
ui_banner() {
    local version="$1" subtitle="$2"
    ui_blank
    ui_emit "${C_ACCENT}${C_BOLD}  LeetEnum${C_RESET}${C_DIM} v${version}${C_RESET}" \
            "LeetEnum v${version}"
    ui_emit "${C_DIM}  Reconnaissance pipeline${C_RESET}${C_DIM} ${G_INFO} LeetSecurity LLC${C_RESET}" \
            "Reconnaissance pipeline - LeetSecurity LLC"
    [ -n "$subtitle" ] && ui_emit "${C_DIM}  ${subtitle}${C_RESET}" "$subtitle"
    ui_hr
}

# ---------------------------------------------------------------------------
# Phase header
#
# The original built a box with `printf '%*s' $((65-${#title}))`, which emits a
# negative-width error and a mangled border as soon as a title exceeds 65
# characters. This computes padding from the real width and clamps at zero.
# ---------------------------------------------------------------------------
ui_phase() {
    local index="$1" total="$2" title="$3" note="$4"
    local tag="[${index}/${total}]"
    local head="${tag} ${title}"
    local pad=$(( UI_COLS - ${#head} - 12 ))
    [ "$pad" -lt 1 ] && pad=1
    local fill
    fill=$(ui_repeat "$G_HR" "$pad")

    ui_blank
    ui_emit "${C_ACCENT}${C_BOLD}${tag}${C_RESET} ${C_BOLD}${title}${C_RESET} ${C_DIM}${fill}${C_RESET} ${C_DIM}$(ui_elapsed)${C_RESET}" \
            "=== ${head} (elapsed $(ui_elapsed))"
    [ -n "$note" ] && ui_emit "${C_DIM}      ${note}${C_RESET}" "    ${note}"
}

# Phase that is being skipped because its checkpoint already exists.
ui_phase_cached() {
    local index="$1" total="$2" title="$3"
    ui_emit "${C_DIM}[${index}/${total}] ${title} ${G_INFO} already complete, reusing results${C_RESET}" \
            "=== [${index}/${total}] ${title} (cached)"
}

# ---------------------------------------------------------------------------
# Determinate progress bar. Used where a total is genuinely known.
# ---------------------------------------------------------------------------
ui_bar() {
    local current="$1" total="$2" width="${3:-${UI_BAR_W:-24}}"
    [[ "$current" =~ ^[0-9]+$ ]] || current=0
    [ "$total" -le 0 ] && total=1
    [ "$current" -gt "$total" ] && current="$total"
    local filled=$(( current * width / total ))
    local pct=$(( current * 100 / total ))
    printf '%s%s %3d%%' \
        "$(ui_repeat "$G_BAR_FULL" "$filled")" \
        "$(ui_repeat "$G_BAR_EMPTY" $(( width - filled )))" \
        "$pct"
}

# Truncate a label to the precomputed budget so a \r redraw never wraps onto a
# second line, which would leave torn output behind.
ui_fit() {
    local s="$1" max="${2:-${UI_LABEL_MAX:-40}}"
    if [ "${#s}" -gt "$max" ]; then
        printf '%s...' "${s:0:$(( max - 3 ))}"
    else
        printf '%s' "$s"
    fi
}

# ---------------------------------------------------------------------------
# Step supervisor
#
# Watches a background child and reports three things continuously: that it is
# alive, how long it has been alive, and how many results it has produced so
# far. The result count is what actually answers "is this working or hanging?"
# for a long DNS brute force.
#
# On a non-TTY (cron, tee, tmux pipe-pane, CI) it prints one start line and one
# finish line instead of animating, so logs stay greppable.
#
# Globals in:  UI_STEP_LOG   file for the child's stdout+stderr
#              UI_STEP_WATCH file whose line count is displayed live
#              UI_STEP_TOTAL when set, draws a bar instead of a spinner
# ---------------------------------------------------------------------------
_ui_supervise() {
    local label="$1" pid="$2"
    local start rc=0 i=0 count="" frame body short
    start=$(date +%s)
    short=$(ui_fit "$label")

    if [ "$UI_ANIMATE" != "true" ]; then
        ui_emit "${C_DIM}${G_ARROW}${C_RESET} ${label} ${C_DIM}started${C_RESET}" "[ .. ] ${label} started"
        wait "$pid"; rc=$?
    else
        ui_cursor_hide
        while kill -0 "$pid" 2>/dev/null; do
            frame="${UI_SPIN[$i]}"
            i=$(( (i + 1) % ${#UI_SPIN[@]} ))

            if [ -n "${UI_STEP_TOTAL:-}" ] && [ "${UI_STEP_TOTAL}" -gt 0 ]; then
                body="${short} $(ui_bar "$(compat_count "${UI_STEP_WATCH:-}")" "$UI_STEP_TOTAL")"
            else
                count=""
                if [ -n "${UI_STEP_WATCH:-}" ] && [ -s "${UI_STEP_WATCH}" ]; then
                    count=" ${C_DIM}${G_INFO}${C_RESET} $(compat_count "$UI_STEP_WATCH") found"
                fi
                body="${short}${count}"
            fi

            printf '\r\033[2K%b' \
                "${C_ACCENT}${frame}${C_RESET} ${body} ${C_DIM}[$(ui_fmt_duration $(( $(date +%s) - start )))]${C_RESET}"
            sleep 0.12
        done
        wait "$pid"; rc=$?
        ui_cursor_show
        printf '\r\033[2K'
    fi
    _UI_STEP_SECS=$(( $(date +%s) - start ))
    return "$rc"
}

_ui_finish() {
    local label="$1" rc="$2"
    local dur count="" suffix=""
    dur=$(ui_fmt_duration "${_UI_STEP_SECS:-0}")

    if [ -n "${UI_STEP_WATCH:-}" ]; then
        count=$(compat_count "$UI_STEP_WATCH")
        suffix=" ${C_DIM}${G_INFO}${C_RESET} ${C_BOLD}${count}${C_RESET}${C_DIM} results${C_RESET}"
    fi

    if [ "$rc" -eq 0 ]; then
        ui_emit "${C_OK}${G_OK}${C_RESET} ${label} ${C_DIM}(${dur})${C_RESET}${suffix}" \
                "[ ok ] ${label} (${dur})${count:+ - ${count} results}"
    elif [ "${UI_STEP_SOFT:-false}" = "true" ]; then
        ui_emit "${C_WARN}${G_WARN}${C_RESET} ${label} ${C_DIM}(${dur}, exit ${rc}, continuing)${C_RESET}${suffix}" \
                "[warn] ${label} (${dur}, exit ${rc}, continuing)"
    else
        ui_emit "${C_ERR}${G_ERR}${C_RESET} ${label} ${C_DIM}(${dur}, exit ${rc})${C_RESET}" \
                "[fail] ${label} (${dur}, exit ${rc})"
        [ -s "${UI_STEP_LOG:-}" ] && ui_emit \
            "  ${C_DIM}last log line: $(tail -n 1 "$UI_STEP_LOG" | cut -c1-$(( UI_COLS - 20 )))${C_RESET}" \
            "    last log line: $(tail -n 1 "$UI_STEP_LOG")"
    fi
    return "$rc"
}

# Run a command as argv. Nothing is re-parsed by a shell, so a hostile target
# string cannot become code — this replaces the original `eval "$@"` path.
#
#   ui_run "Probing HTTP" -- httpx -l "$list" -threads 50
ui_run() {
    local label="$1"; shift
    [ "${1:-}" = "--" ] && shift

    local log="${UI_STEP_LOG:-/dev/null}"
    "$@" >"$log" 2>&1 &
    local pid=$!
    _UI_CHILD_PID=$pid
    local rc=0
    _ui_supervise "$label" "$pid" || rc=$?
    _UI_CHILD_PID=""
    local frc=0
    _ui_finish "$label" "$rc" || frc=$?
    ui_step_reset
    return "$frc"
}

# Run a fixed shell snippet for genuine pipelines (curl | jq | sort). The
# snippet must be a literal in this repo; pass all variable data through the
# environment so it is never parsed as syntax.
#
#   TARGET="$t" ui_run_sh "Mining crt.sh" 'curl -s ".../$TARGET" | jq -r ...'
ui_run_sh() {
    local label="$1" script="$2"
    local log="${UI_STEP_LOG:-/dev/null}"
    bash -o pipefail -c "$script" >"$log" 2>&1 &
    local pid=$!
    _UI_CHILD_PID=$pid
    local rc=0
    _ui_supervise "$label" "$pid" || rc=$?
    _UI_CHILD_PID=""
    local frc=0
    _ui_finish "$label" "$rc" || frc=$?
    ui_step_reset
    return "$frc"
}

# Configure the next step: where its output log goes, which file to watch for a
# live result count, an optional total for a determinate bar, and whether a
# non-zero exit is fatal or merely noted.
#   ui_step_cfg <logfile> [watchfile] [total] [soft]
ui_step_cfg() {
    UI_STEP_LOG="${1:-/dev/null}"
    UI_STEP_WATCH="${2:-}"
    UI_STEP_TOTAL="${3:-}"
    UI_STEP_SOFT="${4:-true}"
}

ui_step_reset() {
    UI_STEP_LOG=""; UI_STEP_WATCH=""; UI_STEP_TOTAL=""; UI_STEP_SOFT="true"
}

# ---------------------------------------------------------------------------
# Interactive prompts
#
# The original delegated to `gum` and silently skipped configuration whenever
# gum was missing, which is how users ended up with notifications that never
# fired. These are pure bash, so they always work, and they fall back to
# defaults on a non-TTY instead of blocking a cron run forever.
# ---------------------------------------------------------------------------
ui_confirm() {
    local prompt="$1" default="${2:-n}" reply
    if [ "$UI_STDOUT_TTY" != "true" ]; then
        [ "$default" = "y" ]; return $?
    fi
    local hint="[y/N]"; [ "$default" = "y" ] && hint="[Y/n]"
    printf '%b %b ' "${C_ACCENT}?${C_RESET} ${prompt}" "${C_DIM}${hint}${C_RESET}"
    read -r reply || reply=""
    reply="${reply:-$default}"
    case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
}

ui_ask() {
    local prompt="$1" default="${2:-}" secret="${3:-false}" reply
    if [ "$UI_STDOUT_TTY" != "true" ]; then printf '%s\n' "$default"; return 0; fi
    printf '%b ' "${C_ACCENT}?${C_RESET} ${prompt}${default:+ ${C_DIM}(${default})${C_RESET}}:" >&2
    if [ "$secret" = "true" ]; then
        read -rs reply || reply=""; printf '\n' >&2
    else
        read -r reply || reply=""
    fi
    printf '%s\n' "${reply:-$default}"
}

ui_choose() {
    local prompt="$1"; shift
    local options=("$@") i reply
    if [ "$UI_STDOUT_TTY" != "true" ]; then printf '%s\n' "${options[0]}"; return 0; fi
    printf '%b\n' "${C_ACCENT}?${C_RESET} ${prompt}" >&2
    for i in "${!options[@]}"; do
        printf '    %b\n' "${C_BOLD}$(( i + 1 ))${C_RESET}) ${options[$i]}" >&2
    done
    printf '  %b ' "${C_DIM}choice [1-${#options[@]}]:${C_RESET}" >&2
    read -r reply || reply="1"
    [[ "$reply" =~ ^[0-9]+$ ]] && [ "$reply" -ge 1 ] && [ "$reply" -le "${#options[@]}" ] \
        || reply=1
    printf '%s\n' "${options[$(( reply - 1 ))]}"
}

# ---------------------------------------------------------------------------
# Summary block
# ---------------------------------------------------------------------------
ui_summary_open() {
    ui_blank
    ui_hr
    ui_emit "${C_BOLD}  ${1}${C_RESET}" "== ${1}"
    ui_blank
}

ui_summary_row() {
    local label="$1" value="$2" tone="${3:-}"
    local colour="$C_BOLD"
    case "$tone" in
        ok)   colour="$C_OK" ;;
        warn) colour="$C_WARN" ;;
        err)  colour="$C_ERR" ;;
    esac
    ui_emit "$(printf '  %b%-22s%b %b%s%b' \
        "$C_DIM" "$label" "$C_RESET" "$colour" "$value" "$C_RESET")" \
        "$(printf '  %-22s %s' "$label" "$value")"
}

ui_summary_close() {
    ui_blank
    ui_hr
}

# ---------------------------------------------------------------------------
# Shutdown
#
# The original trap called `exit 0` and left the child recon tools running, so
# Ctrl+C returned the prompt while nuclei kept hammering the target in the
# background. Signal the whole process group, then give it a moment to drain.
# ---------------------------------------------------------------------------
ui_shutdown() {
    local signal="${1:-TERM}"
    ui_cursor_show
    if [ -n "${_UI_CHILD_PID:-}" ] && kill -0 "$_UI_CHILD_PID" 2>/dev/null; then
        kill -"$signal" "-$_UI_CHILD_PID" 2>/dev/null || kill -"$signal" "$_UI_CHILD_PID" 2>/dev/null
    fi
    # Reap anything else this shell started.
    jobs -p 2>/dev/null | while read -r p; do kill -"$signal" "$p" 2>/dev/null || true; done
}

ui_install_traps() {
    trap 'printf "\n"; ui_warn "Interrupted, stopping child scanners"; ui_shutdown TERM; exit 130' INT
    trap 'ui_shutdown TERM; exit 143' TERM
    trap 'ui_cursor_show' EXIT
}

