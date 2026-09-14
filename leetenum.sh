#!/usr/bin/env bash
# leetenum.sh — LeetEnum entrypoint.
#
# Reconnaissance pipeline. Property of LeetSecurity LLC.
#
# This file does three things and nothing else: locate lib/, parse the command
# line, and dispatch. All behaviour lives in lib/. The previous single-file
# version mixed argument parsing, tool installation, UI drawing and the scan
# itself across 567 lines with shared mutable globals, which is why a change to
# one phase could silently break another.
#
# Deliberately NOT using `set -e`. A recon pipeline runs a dozen third-party
# binaries that legitimately exit non-zero (no results found, rate limited,
# template parse warning). Under `set -e` the original aborted mid-scan and
# discarded work already done. Failures are handled per step instead, and
# `set -u` still catches genuine typos.
set -uo pipefail

LEETENUM_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Self-location.
#
# Must survive being invoked through a symlink, because that is exactly how
# install.sh and the Homebrew formula expose it. `dirname "$0"` alone resolves
# to /usr/local/bin and lib/ is not there.
# ---------------------------------------------------------------------------
_ls_self() {
    local src="${BASH_SOURCE[0]}" dir
    while [ -L "$src" ]; do
        dir=$(cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd)
        src=$(readlink "$src")
        case "$src" in /*) ;; *) src="${dir}/${src}" ;; esac
    done
    cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd
}

LS_ROOT=$(_ls_self)
LS_LIB="${LEETENUM_LIB_DIR:-${LS_ROOT}/lib}"

for _m in compat ui config deps pipeline; do
    if [ ! -r "${LS_LIB}/${_m}.sh" ]; then
        printf 'leetenum: cannot find %s/%s.sh\n' "$LS_LIB" "$_m" >&2
        printf 'Set LEETENUM_LIB_DIR or reinstall.\n' >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    . "${LS_LIB}/${_m}.sh"
done
unset _m

# ---------------------------------------------------------------------------
# Bash version gate.
#
# macOS ships bash 3.2 from 2007 and that is a supported target, so the code
# avoids associative arrays and `${var^^}` throughout. 3.2 is the real floor;
# anything older lacks `printf -v` and cannot run the UI layer at all.
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSINFO[0]:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
    printf 'leetenum: bash 3.2 or newer required (found %s).\n' "${BASH_VERSION:-unknown}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PIPE_ARG_TARGET=""
PIPE_ARG_OUTROOT="${LEETENUM_OUTPUT_DIR:-$PWD}"
PIPE_ARG_PROFILE="auto"
PIPE_ARG_MONITOR="false"
PIPE_ARG_DEEP="false"
PIPE_ARG_FRESH="false"
PIPE_ARG_ONLY=""
PIPE_ARG_SKIP=""
ARG_INTERVAL=21600          # 6h, used only in monitor mode
ARG_TARGET_FILE=""
ARG_YES="false"

usage() {
    cat <<'HELPTEXT_HEAD'
LeetEnum - reconnaissance pipeline (LeetSecurity LLC)
HELPTEXT_HEAD
    printf 'Version %s\n' "$LEETENUM_VERSION"
    cat <<'HELPTEXT'

USAGE
  leetenum <domain>                     scan a single target
  leetenum scan -d <domain> [options]   same, explicit form
  leetenum install                      install every dependency
  leetenum doctor                       report environment and tool status
  leetenum config                       reconfigure notifications
  leetenum update                       update tools and templates
  leetenum version

SCAN OPTIONS
  -d, --domain <domain>     target apex domain
  -f, --file <path>         file of domains, one per line
  -o, --output <dir>        output root (default: current directory)
  -p, --profile <name>      lite | balanced | beast | auto   (default: auto)
      --deep                include low and info severity findings
      --fresh               ignore checkpoints and start over
      --only <p1,p5>        run only these phases
      --skip <p6,p9>       run everything except these phases
  -m, --monitor             loop continuously, reporting only what is new
      --interval <seconds>  monitor sleep between runs (default: 21600)
  -y, --yes                 never prompt; assume defaults
      --no-color            disable colour (NO_COLOR is also honoured)
  -h, --help

PHASES
  p1 passive   p2 brute     p3 recursive   p4 permutations  p5 http
  p6 ports     p7 crawl     p8 vulns       p9 screenshots

EXAMPLES
  leetenum example.com
  leetenum scan -d example.com --profile beast --deep
  leetenum scan -d example.com --only p5,p8      # re-probe and re-scan only
  leetenum scan -f targets.txt -o ~/engagements
  leetenum scan -d example.com --monitor --interval 3600

ENVIRONMENT
  LEETENUM_WORDLIST     override the DNS brute-force wordlist
  LEETENUM_OUTPUT_DIR   default output root
  LEETENUM_CONFIG_DIR   config location (default $XDG_CONFIG_HOME/leetsec)
  LEETENUM_CACHE_DIR    cache location (default $XDG_CACHE_HOME/leetsec)
  LEETENUM_UNPINNED=1   install tools at @latest instead of pinned versions
  LEETENUM_FORCE=1      reinstall tools that are already present
HELPTEXT
}

# ---------------------------------------------------------------------------
# Argument parsing
#
# The original used a `while [[ $# -gt 0 ]]` loop that fell through unknown
# flags silently, so `--profle beast` ran with the default profile and no
# warning. Unknown options are now an error, and every option that takes a
# value checks that the value exists rather than consuming the next flag.
# ---------------------------------------------------------------------------
arg_die() {
    printf 'leetenum: %s\n' "$1" >&2
    printf "Run 'leetenum --help'.\n" >&2
    exit 2
}

# Validate in the current shell and assign separately. Doing this as
# `VAR=$(need_value ...)` looks tidier but is broken: `exit` inside a command
# substitution terminates only the subshell, so a trailing `-d` with no value
# printed the error and then looped forever without ever consuming an argument.
need_value() {
    case "${2:-}" in
        ''|-*) arg_die "$1 requires a value" ;;
    esac
    return 0
}

CMD=""
parse_args() {
    # A bare domain as the first argument is the common case and should just work.
    case "${1:-}" in
        scan|install|doctor|config|update|version|help) CMD="$1"; shift ;;
        -h|--help)     CMD="help"; shift ;;
        --version)     CMD="version"; shift ;;
        -update)       CMD="update"; shift ;;      # v1 compatibility
        --reset)       CMD="config"; shift ;;      # v1 compatibility
        ''|-*)         CMD="scan" ;;
        *)             CMD="scan"; PIPE_ARG_TARGET="$1"; shift ;;
    esac

    while [ "$#" -gt 0 ]; do
        case "$1" in
            -d|--domain)   need_value "$1" "${2:-}"; PIPE_ARG_TARGET="$2";  shift 2 ;;
            -f|--file)     need_value "$1" "${2:-}"; ARG_TARGET_FILE="$2";  shift 2 ;;
            -o|--output)   need_value "$1" "${2:-}"; PIPE_ARG_OUTROOT="$2"; shift 2 ;;
            -p|--profile)  need_value "$1" "${2:-}"; PIPE_ARG_PROFILE="$2"; shift 2 ;;
            --only)        need_value "$1" "${2:-}"; PIPE_ARG_ONLY="$2";    shift 2 ;;
            --skip)        need_value "$1" "${2:-}"; PIPE_ARG_SKIP="$2";    shift 2 ;;
            --interval)    need_value "$1" "${2:-}"; ARG_INTERVAL="$2";     shift 2 ;;
            -m|--monitor)  PIPE_ARG_MONITOR="true"; shift ;;
            --deep)        PIPE_ARG_DEEP="true"; shift ;;
            --fresh)       PIPE_ARG_FRESH="true"; shift ;;
            -y|--yes)      ARG_YES="true"; shift ;;
            --no-color)    NO_COLOR=1; export NO_COLOR; shift ;;
            -h|--help)     CMD="help"; shift ;;
            --)            shift; break ;;
            -*)            arg_die "unknown option $1" ;;
            *)             [ -z "$PIPE_ARG_TARGET" ] && PIPE_ARG_TARGET="$1"; shift ;;
        esac
    done

    case "$PIPE_ARG_PROFILE" in
        lite|balanced|beast|auto) ;;
        *) arg_die "profile must be lite, balanced, beast or auto" ;;
    esac
    printf '%s' "$ARG_INTERVAL" | grep -Eq '^[0-9]+$' \
        || arg_die "--interval must be a whole number of seconds"
    validate_phase_list --only "$PIPE_ARG_ONLY"
    validate_phase_list --skip "$PIPE_ARG_SKIP"
}

# Catching `--only 6` or `--only phase6` here saves a user from a scan that
# silently does nothing at all.
validate_phase_list() {
    local flag="$1" list="$2" item
    [ -n "$list" ] || return 0
    local IFS=','
    for item in $list; do
        case "$item" in
            p1|p2|p3|p4|p5|p6|p7|p8|p9) ;;
            *) arg_die "${flag}: ${item} is not a phase id (use p1..p9)" ;;
        esac
    done
    return 0
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_scan() {
    local targets=() t normalised rc=0

    if [ -n "$ARG_TARGET_FILE" ]; then
        [ -r "$ARG_TARGET_FILE" ] || ui_die "Cannot read ${ARG_TARGET_FILE}"
        while IFS= read -r t || [ -n "$t" ]; do
            t="${t%%#*}"                          # strip comments
            t=$(printf '%s' "$t" | tr -d '[:space:]')
            [ -n "$t" ] || continue
            targets+=("$t")
        done < "$ARG_TARGET_FILE"
    elif [ -n "$PIPE_ARG_TARGET" ]; then
        targets+=("$PIPE_ARG_TARGET")
    fi

    if [ "${#targets[@]}" -eq 0 ]; then
        # Prompting beats exiting with a usage error when someone just typed the
        # command name to see what it does.
        if [ "$UI_STDOUT_TTY" = "true" ] && [ "$ARG_YES" != "true" ]; then
            t=$(ui_ask "Target domain")
            [ -n "$t" ] && targets+=("$t")
        fi
        [ "${#targets[@]}" -eq 0 ] && { usage; exit 2; }
    fi

    # Validate every target before starting, so a typo in entry 40 of a target
    # file surfaces now instead of six hours in.
    local valid=()
    for t in "${targets[@]}"; do
        if normalised=$(pipe_normalise_target "$t"); then
            valid+=("$normalised")
        else
            ui_warn "Skipping invalid target: ${t}"
        fi
    done
    [ "${#valid[@]}" -eq 0 ] && ui_die "No valid targets."

    mkdir -p "$PIPE_ARG_OUTROOT" 2>/dev/null \
        || ui_die "Cannot create output directory ${PIPE_ARG_OUTROOT}"
    PIPE_ARG_OUTROOT=$(compat_realpath "$PIPE_ARG_OUTROOT")

    deps_ensure_path
    preflight || return 1
    config_wizard

    if [ "$PIPE_ARG_MONITOR" = "true" ]; then
        monitor_loop "${valid[@]}"
    else
        for t in "${valid[@]}"; do
            PIPE_ARG_TARGET="$t"
            UI_START_TS=$(date +%s)
            pipe_run || rc=1
            pipe_cleanup_workdir
        done
    fi
    return "$rc"
}

# ---------------------------------------------------------------------------
# Preflight
#
# Required tools are checked once, up front. The original checked inside each
# phase and continued regardless, so a missing puredns produced a scan that ran
# for twenty minutes and wrote nothing.
# ---------------------------------------------------------------------------
preflight() {
    local missing=() b
    for b in "${DEPS_REQUIRED[@]}"; do
        command -v "$b" >/dev/null 2>&1 || missing+=("$b")
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        ui_err "Required tool(s) missing: ${missing[*]}"
        if [ "$ARG_YES" = "true" ] || ui_confirm "Install dependencies now?" y; then
            deps_install_all || return 1
            for b in "${DEPS_REQUIRED[@]}"; do
                command -v "$b" >/dev/null 2>&1 || ui_die "Still missing ${b}. See 'leetenum doctor'."
            done
        else
            ui_info "Run 'leetenum install' when ready."
            return 1
        fi
    fi

    compat_online || ui_warn "No outbound connectivity detected; passive sources will fail."
    return 0
}

# ---------------------------------------------------------------------------
# Monitor mode
#
# Each iteration is a fresh run directory so the differential is meaningful.
# Sleep is interruptible: the original slept in one long `sleep $INTERVAL`, and
# Ctrl+C during it left the trap unable to reap children.
# ---------------------------------------------------------------------------
monitor_loop() {
    local targets=("$@") t round=0
    ui_info "Monitor mode: $(( ARG_INTERVAL / 60 )) minute interval. Ctrl+C to stop."

    while true; do
        round=$(( round + 1 ))
        ui_hr
        ui_emit "${C_ACCENT}${C_BOLD}Round ${round}${C_RESET} ${C_DIM}$(date '+%Y-%m-%d %H:%M:%S')${C_RESET}" \
                "=== Round ${round} $(date '+%Y-%m-%d %H:%M:%S')"

        for t in "${targets[@]}"; do
            PIPE_ARG_TARGET="$t"
            UI_START_TS=$(date +%s)
            pipe_run
            pipe_cleanup_workdir
        done

        ui_info "Sleeping until $(monitor_next_time)"
        local slept=0
        while [ "$slept" -lt "$ARG_INTERVAL" ]; do
            sleep 5
            slept=$(( slept + 5 ))
        done
    done
}

# date arithmetic differs between GNU (`-d @epoch`) and BSD (`-r epoch`), so
# probe rather than assume; falls back to a plain duration.
monitor_next_time() {
    local when=$(( $(date +%s) + ARG_INTERVAL ))
    date -d "@${when}" '+%H:%M:%S' 2>/dev/null \
        || date -r "$when" '+%H:%M:%S' 2>/dev/null \
        || printf 'in %s' "$(ui_fmt_duration "$ARG_INTERVAL")"
}

cmd_install() {
    ui_banner "$LEETENUM_VERSION" "Installing dependencies"
    deps_install_all
}

cmd_doctor() {
    ui_banner "$LEETENUM_VERSION" "Environment report"
    deps_report
}

cmd_config() {
    config_init_dirs
    # Clearing the stored choice is what makes the wizard run again; the v1
    # `--reset` deleted the whole config file including working webhooks.
    config_wizard reset
    ui_ok "Configuration saved to ${LS_CONF_FILE}"
}

cmd_update() {
    ui_banner "$LEETENUM_VERSION" "Updating toolchain"
    config_init_dirs
    LEETENUM_FORCE=1 deps_install_go_tools
    deps_sync_templates
    # Force a wordlist refresh by clearing the cache stamps.
    rm -f "${LS_CACHE_DIR}/wordlists/resolvers.txt" 2>/dev/null || true
    LOG_DIR="${LS_CACHE_DIR}" pipe_prepare_wordlists
    ui_ok "Toolchain, templates and wordlists updated"
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
main() {
    compat_init
    ui_init
    ui_install_traps
    config_init_dirs

    parse_args "$@"

    case "$CMD" in
        help)    usage; return 0 ;;
        version) printf 'leetenum %s (%s/%s)\n' "$LEETENUM_VERSION" "$LS_OS" "$LS_ARCH"; return 0 ;;
    esac

    case "$CMD" in
        install) cmd_install ;;
        doctor)  cmd_doctor ;;
        config)  cmd_config ;;
        update)  cmd_update ;;
        scan)
            ui_banner "$LEETENUM_VERSION" \
                "$([ "$PIPE_ARG_MONITOR" = true ] && printf 'continuous monitoring' \
                                                  || printf 'single-pass scan')"
            cmd_scan
            ;;
        *)       usage; return 2 ;;
    esac
}

main "$@"
