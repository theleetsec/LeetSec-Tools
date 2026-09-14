#!/usr/bin/env bash
# lib/deps.sh — dependency inventory, verification and installation.
#
# Corrections over the original tool table:
#   * gotator was pointed at github.com/josderstad/gotator, which does not
#     exist. The real module is github.com/Josue87/gotator. That is why all
#     three of the original "failsafe" install paths failed in sequence.
#   * nuclei v2 and amass v3 are both retired. Their v2/v3 module paths still
#     resolve but install years-old binaries with stale template schemas.
#   * Versions are pinned. `@latest` for a security toolchain means an upstream
#     push can change your results overnight and is not reproducible across a
#     team; LEETENUM_UNPINNED=1 opts back into latest.
#
# Splitting the inventory from the install logic also lets `leetenum doctor`
# report status without touching the system.

DEPS_GO_MIN="1.23"

# name|module|pinned version|role
DEPS_GO_TOOLS=(
    "massdns||system|DNS resolver backend"
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder|v2.6.6|passive enumeration"
    "assetfinder|github.com/tomnomnom/assetfinder|v0.1.1|passive enumeration"
    "amass|github.com/owasp-amass/amass/v4/...|v4.2.0|passive enumeration"
    "puredns|github.com/d3mondev/puredns/v2|v2.1.1|DNS resolution and brute force"
    "gotator|github.com/Josue87/gotator|v1.0.1|permutation generation"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx|v1.6.9|HTTP probing"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu|v2.3.1|port scanning"
    "katana|github.com/projectdiscovery/katana/cmd/katana|v1.1.0|crawling"
    "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei|v3.3.5|vulnerability scanning"
    "gowitness|github.com/sensepost/gowitness|3.0.5|screenshots"
    "anew|github.com/tomnomnom/anew|v0.0.4|deduplication"
    "waybackurls|github.com/tomnomnom/waybackurls|v0.1.0|archive mining"
    "gau|github.com/lc/gau/v2/cmd/gau|v2.2.4|URL archive mining"
    "tlsx|github.com/projectdiscovery/tlsx/cmd/tlsx|v1.1.9|TLS SAN/CN names"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx|v1.2.1|DNS record probing"
)

# Tools that must exist for a scan to produce anything at all.
DEPS_REQUIRED=(subfinder puredns httpx massdns)

# System packages, keyed by package manager where names differ.
deps_sys_pkg() {
    local bin="$1"
    case "${LS_PKG_MGR}:${bin}" in
        brew:massdns)    printf 'massdns\n' ;;
        apt:massdns)     printf 'massdns\n' ;;
        *:massdns)       printf 'massdns\n' ;;
        brew:chromium)   printf 'chromium\n' ;;
        apt:chromium)    printf 'chromium\n' ;;
        dnf:chromium)    printf 'chromium\n' ;;
        pacman:chromium) printf 'chromium\n' ;;
        apk:chromium)    printf 'chromium\n' ;;
        brew:go)         printf 'go\n' ;;
        apt:go)          printf 'golang-go\n' ;;
        dnf:go)          printf 'golang\n' ;;
        pacman:go)       printf 'go\n' ;;
        apk:go)          printf 'go\n' ;;
        *)               printf '%s\n' "$bin" ;;
    esac
}

deps_go_bin_dir() {
    local d
    d=$(go env GOBIN 2>/dev/null)
    [ -z "$d" ] && d="$(go env GOPATH 2>/dev/null)/bin"
    [ "$d" = "/bin" ] && d="$HOME/go/bin"
    printf '%s\n' "$d"
}

# Make sure the Go bin directory is on PATH for this process, and tell the user
# how to make it permanent. Silently exporting PATH was why "installed" tools
# appeared missing on the next login.
deps_ensure_path() {
    local gobin
    gobin=$(deps_go_bin_dir 2>/dev/null || printf '%s/go/bin' "$HOME")
    case ":$PATH:" in
        *":$gobin:"*) ;;
        *) export PATH="$PATH:$gobin" ;;
    esac
    LS_GO_BIN="$gobin"
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

# Print a status table. Read-only: safe to run anywhere, including CI.
deps_report() {
    local missing_required=0 missing_optional=0
    deps_ensure_path

    ui_summary_open "Environment"
    ui_summary_row "Platform" "${LS_OS}/${LS_ARCH}$([ "$LS_IS_WSL" = true ] && printf ' (WSL)')"
    ui_summary_row "CPU cores" "$LS_CORES"
    ui_summary_row "Memory" "$(( LS_RAM_MB / 1024 )) GB (${LS_RAM_MB} MB)"
    ui_summary_row "Package manager" "${LS_PKG_MGR}"
    ui_summary_row "GNU sort" "$([ "$LS_SORT_IS_GNU" = true ] && printf yes || printf 'no (BSD mode)')"
    # Which mechanism enforces the per-tool wall-clock budgets. Worth reporting
    # because macOS has no `timeout` at all, and a run there is bounded by the
    # shell watchdog in compat.sh rather than by coreutils.
    if [ -n "${LS_TIMEOUT_BIN:-}" ]; then
        ui_summary_row "Phase budgets" "${LS_TIMEOUT_BIN}"
    else
        ui_summary_row "Phase budgets" "shell watchdog (no timeout binary)"
    fi
    ui_summary_row "Scratch space" "$(compat_scratch_dir probe)"
    if command -v go >/dev/null 2>&1; then
        ui_summary_row "Go toolchain" "$(go version 2>/dev/null | awk '{print $3}')" ok
    else
        ui_summary_row "Go toolchain" "not installed" err
    fi
    ui_summary_close

    ui_summary_open "Tools"
    local entry name ver path required
    for entry in "${DEPS_GO_TOOLS[@]}"; do
        IFS='|' read -r name _ ver _ <<< "$entry"
        required="no"
        case " ${DEPS_REQUIRED[*]} " in *" $name "*) required="yes" ;; esac
        if path=$(command -v "$name" 2>/dev/null); then
            ui_summary_row "$name" "installed (pinned ${ver})" ok
        elif [ "$required" = "yes" ]; then
            ui_summary_row "$name" "MISSING - required" err
            missing_required=$(( missing_required + 1 ))
        else
            ui_summary_row "$name" "missing - optional" warn
            missing_optional=$(( missing_optional + 1 ))
        fi
    done

    local b
    for b in massdns jq tmux git; do
        if command -v "$b" >/dev/null 2>&1; then
            ui_summary_row "$b" "installed" ok
        else
            ui_summary_row "$b" "missing" warn
        fi
    done
    if compat_find_chrome >/dev/null; then
        ui_summary_row "chromium" "$(compat_find_chrome)" ok
    else
        ui_summary_row "chromium" "missing - screenshots disabled" warn
    fi
    ui_summary_close

    if [ "$missing_required" -gt 0 ]; then
        ui_err "${missing_required} required tool(s) missing. Run: leetenum install"
        return 1
    fi
    [ "$missing_optional" -gt 0 ] && ui_info "Optional tools missing; those phases will be skipped."
    return 0
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

deps_install_go() {
    command -v go >/dev/null 2>&1 && return 0
    if [ "$LS_PKG_MGR" = "none" ]; then
        ui_err "No package manager found and Go is missing."
        ui_info "Install Go from https://go.dev/dl/ then re-run 'leetenum install'."
        return 1
    fi
    ui_step_cfg "${LS_CACHE_DIR}/install.log" "" "" false
    ui_run_sh "Installing Go toolchain" \
        "${LS_PKG_REFRESH} >/dev/null 2>&1 || true; ${LS_PKG_INSTALL} $(deps_sys_pkg go)" || return 1
    command -v go >/dev/null 2>&1
}

deps_install_system() {
    [ "$LS_PKG_MGR" = "none" ] && { ui_warn "No package manager; skipping system packages."; return 0; }

    local wanted=() b
    for b in massdns jq git tmux; do
        command -v "$b" >/dev/null 2>&1 || wanted+=("$(deps_sys_pkg "$b")")
    done
    compat_find_chrome >/dev/null || wanted+=("$(deps_sys_pkg chromium)")

    # Header/build packages massdns needs when it has to be compiled.
    if [ "$LS_PKG_MGR" = "apt" ]; then
        wanted+=(build-essential libpcap-dev)
    elif [ "$LS_PKG_MGR" = "dnf" ]; then
        wanted+=(gcc make libpcap-devel)
    fi

    [ "${#wanted[@]}" -eq 0 ] && { ui_ok "System packages already present"; return 0; }

    ui_step_cfg "${LS_CACHE_DIR}/install.log" "" "" true
    ui_run_sh "Refreshing package index" "${LS_PKG_REFRESH} >/dev/null 2>&1" || true

    # One package per invocation. Batching them meant a single name the local
    # package manager does not carry — massdns is one, on more than one platform
    # — failed the whole command and took every other package with it, so a Mac
    # could end up with no chromium for a reason that had nothing to do with
    # chromium. None of these is fatal: massdns falls through to the source build
    # below and the rest only affect optional phases.
    local pkg failed=()
    for pkg in "${wanted[@]}"; do
        ui_step_cfg "${LS_CACHE_DIR}/install.log" "" "" true
        ui_run_sh "Installing ${pkg}" "${LS_PKG_INSTALL} ${pkg}" || failed+=("$pkg")
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        ui_warn "Unavailable from ${LS_PKG_MGR}: ${failed[*]}"
        ui_info "Log: ${LS_CACHE_DIR}/install.log"
    fi
    return 0
}

# Build massdns from source when no package exists (common on macOS/arm64 and
# on RHEL derivatives). Kept out of the happy path because it needs a compiler.
deps_build_massdns() {
    command -v massdns >/dev/null 2>&1 && return 0
    command -v git >/dev/null 2>&1 || { ui_warn "git missing; cannot build massdns"; return 1; }

    local src="${LS_CACHE_DIR}/src/massdns"
    rm -rf "$src"; mkdir -p "$(dirname "$src")"

    # massdns's default target compiles against <sys/epoll.h>, which is Linux
    # only. Upstream ships a `nolinux` target that uses select() instead, and
    # without it the build dies on macOS and BSD — which then takes phases 2, 3
    # and 4 with it, because puredns is only a wrapper around this binary and
    # fails at runtime rather than at install time. `all` is named explicitly on
    # Linux instead of relying on the default target.
    local mk_target="all"
    [ "$LS_OS" = "linux" ] || mk_target="nolinux"

    ui_step_cfg "${LS_CACHE_DIR}/install.log" "" "" false
    SRC="$src" PREFIX="${LS_GO_BIN:-$HOME/go/bin}" MK_TARGET="$mk_target" \
    ui_run_sh "Building massdns from source (${mk_target})" '
        set -e
        git clone --depth 1 -q https://github.com/blechschmidt/massdns.git "$SRC"
        cd "$SRC"
        make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" "$MK_TARGET"
        mkdir -p "$PREFIX"
        # The two targets have not always agreed on where they leave the binary.
        if [ -x bin/massdns ]; then
            install -m 0755 bin/massdns "$PREFIX/massdns"
        elif [ -x massdns ]; then
            install -m 0755 massdns "$PREFIX/massdns"
        else
            echo "build produced no massdns binary" >&2
            exit 1
        fi
    ' || return 1
    command -v massdns >/dev/null 2>&1
}

# Install the Go-based tools. Runs them sequentially with clear per-tool
# feedback: a silent 10-minute `go install` loop was the single most common
# reason users assumed the tool had hung.
deps_install_go_tools() {
    deps_install_go || return 1
    deps_ensure_path
    go env -w GO111MODULE=on 2>/dev/null || true

    local entry name module ver role spec total idx=0 failed=()
    total="${#DEPS_GO_TOOLS[@]}"

    for entry in "${DEPS_GO_TOOLS[@]}"; do
        IFS='|' read -r name module ver role <<< "$entry"
        [ "$name" = "massdns" ] && continue
        idx=$(( idx + 1 ))
        if command -v "$name" >/dev/null 2>&1 && [ "${LEETENUM_FORCE:-0}" != "1" ]; then
            ui_emit "${C_DIM}[${idx}/${total}] ${name} already present${C_RESET}" \
                    "[ ok ] ${name} already present"
            continue
        fi

        spec="${module}@${ver}"
        [ "${LEETENUM_UNPINNED:-0}" = "1" ] && spec="${module}@latest"

        ui_step_cfg "${LS_CACHE_DIR}/install-${name}.log" "" "" false
        if ! GOFLAGS=-mod=mod ui_run "[${idx}/${total}] ${name} (${role})" -- go install "$spec"; then
            # A pinned tag can be withdrawn upstream; fall back once to latest
            # rather than failing the whole install.
            ui_step_cfg "${LS_CACHE_DIR}/install-${name}.log" "" "" false
            if ! GOFLAGS=-mod=mod ui_run "[${idx}/${total}] ${name} (retry @latest)" -- \
                    go install "${module}@latest"; then
                failed+=("$name")
            fi
        fi
    done

    if [ "${#failed[@]}" -gt 0 ]; then
        ui_warn "Failed to install: ${failed[*]}"
        ui_info "Logs: ${LS_CACHE_DIR}/install-<tool>.log"
    fi
    return 0
}

# Nuclei templates, refreshed at most once a day. The original used
# `[ $(find "$f" -mtime +1) ]`, which evaluates false when the file is missing
# entirely, so a fresh install never synced templates at all.
deps_sync_templates() {
    command -v nuclei >/dev/null 2>&1 || return 0
    local stamp="${LS_CACHE_DIR}/.nuclei-sync"
    if [ -f "$stamp" ]; then
        local stale
        stale=$(find "$stamp" -mtime +1 2>/dev/null | wc -l | tr -d '[:space:]')
        [ "$stale" = "0" ] && return 0
    fi
    ui_step_cfg "${LS_CACHE_DIR}/templates.log" "" "" true
    ui_run "Syncing nuclei templates" -- nuclei -update-templates -silent || true
    touch "$stamp"
}

# Persist PATH for future shells. Appends once, and says what it changed rather
# than editing a shell rc invisibly.
deps_persist_path() {
    deps_ensure_path
    local gobin="$LS_GO_BIN" rc line
    line="export PATH=\"\$PATH:${gobin}\""

    case "${SHELL##*/}" in
        zsh)  rc="$HOME/.zshrc" ;;
        bash) rc="$HOME/.bashrc"; [ "$LS_OS" = "darwin" ] && rc="$HOME/.bash_profile" ;;
        fish) ui_info "fish detected. Add manually: fish_add_path ${gobin}"; return 0 ;;
        *)    ui_info "Add to your shell profile: ${line}"; return 0 ;;
    esac

    [ -f "$rc" ] && grep -Fq "$gobin" "$rc" && return 0
    printf '\n# Added by LeetEnum installer\n%s\n' "$line" >> "$rc"
    ui_ok "Added ${gobin} to PATH in ${rc}"
    ui_info "Run 'source ${rc}' or open a new terminal."
    return 0
}

# Full install, in dependency order.
deps_install_all() {
    config_init_dirs
    compat_online || ui_warn "Network looks unreachable; installation will probably fail."
    deps_install_system
    deps_install_go_tools
    deps_build_massdns || ui_warn "massdns unavailable, so puredns cannot resolve. Install it manually."
    deps_sync_templates
    deps_persist_path
    ui_blank
    deps_report
}
