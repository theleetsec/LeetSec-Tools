#!/usr/bin/env bash
# lib/compat.sh — portability shim for LeetEnum.
#
# Every non-POSIX assumption in the original script lives here now. Nothing
# else in the codebase should call free/nproc/md5sum/wget or touch /dev/shm
# directly. Sourced, never executed.
#
# Exports: LS_OS LS_ARCH LS_IS_WSL LS_RAM_MB LS_CORES LS_PKG_MGR LS_LOCALE
#          plus helpers: compat_hash compat_fetch compat_realpath compat_sort
#                        compat_sed_i compat_scratch_dir compat_count

# ---------------------------------------------------------------------------
# Platform identity
# ---------------------------------------------------------------------------
compat_detect_platform() {
    case "$(uname -s)" in
        Linux*)   LS_OS="linux" ;;
        Darwin*)  LS_OS="darwin" ;;
        FreeBSD*) LS_OS="freebsd" ;;
        MINGW* | MSYS* | CYGWIN*) LS_OS="windows" ;;
        *)        LS_OS="unknown" ;;
    esac

    # Normalise to the names Go and the release artifacts use, so a single
    # lookup table serves both the shell and the binary installer.
    case "$(uname -m)" in
        x86_64 | amd64)  LS_ARCH="amd64" ;;
        aarch64 | arm64) LS_ARCH="arm64" ;;
        armv7l | armv6l) LS_ARCH="arm" ;;
        i386 | i686)     LS_ARCH="386" ;;
        *)               LS_ARCH="$(uname -m)" ;;
    esac

    LS_IS_WSL="false"
    if [ "$LS_OS" = "linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
        LS_IS_WSL="true"
    fi

    export LS_OS LS_ARCH LS_IS_WSL
}

# ---------------------------------------------------------------------------
# Locale.
#
# Two separate requirements that pull in opposite directions:
#   - character handling should be UTF-8, so box-drawing glyphs, `wc -m` and
#     printf padding behave;
#   - collation must be byte-wise, so sort/comm/join agree with each other and
#     with a master list written by an earlier run on another host.
#
# LC_ALL cannot express that split: it overrides every other LC_* variable, so
# the previous `LC_ALL=C.UTF-8; LC_COLLATE=C` pair silently discarded the
# collation setting. Set the two categories individually and clear any inherited
# LC_ALL instead.
#
# The locale *name* also has to be discovered rather than guessed. glibc 2.35+
# and Debian print `C.utf8`, older systems print `C.UTF-8`, and macOS offers
# neither; matching the literal string "C.UTF-8" therefore fell through to plain
# C on modern Linux and downgraded the UI to ASCII on a terminal that handles
# UTF-8 perfectly well.
# ---------------------------------------------------------------------------
compat_set_locale() {
    unset LC_ALL
    local line norm pick=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # The set is written '_-' rather than '-_': tr parses a leading dash as
        # an option, so `tr -d '-_'` fails with "invalid option" on GNU tr and
        # every locale name silently normalises to the empty string.
        norm=$(printf '%s' "$line" | tr -d '_-' | tr '[:upper:]' '[:lower:]')
        case "$norm" in
            c.utf8)    pick="$line"; break ;;
            enus.utf8) [ -z "$pick" ] && pick="$line" ;;
        esac
    done <<EOF
$(locale -a 2>/dev/null)
EOF

    if [ -n "$pick" ]; then
        export LC_CTYPE="$pick"
    else
        # No UTF-8 locale on the box. ui_load_glyphs sees this via `locale
        # charmap` and switches to the ASCII glyph set on its own.
        export LC_CTYPE="C"
    fi
    export LC_COLLATE="C"
    export LS_LOCALE="$LC_CTYPE"
}

# ---------------------------------------------------------------------------
# Hardware probing
#
# `free -g` was the single worst portability offender: absent on macOS, and on
# any host under 1 GiB it reports 0, which then fed `[ "$RAM" -ge 60 ]` and
# produced an integer-expression error. Report MB and never trust it blindly.
# ---------------------------------------------------------------------------
compat_detect_hardware() {
    LS_RAM_MB=0
    LS_CORES=1

    case "$LS_OS" in
        linux)
            if [ -r /proc/meminfo ]; then
                LS_RAM_MB=$(awk '/^MemTotal:/ {printf "%d", $2/1024; exit}' /proc/meminfo)
            fi
            ;;
        darwin)
            local bytes
            bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
            LS_RAM_MB=$(( bytes / 1024 / 1024 ))
            ;;
        freebsd)
            local bytes
            bytes=$(sysctl -n hw.physmem 2>/dev/null || echo 0)
            LS_RAM_MB=$(( bytes / 1024 / 1024 ))
            ;;
        windows)
            # Git Bash: no /proc/meminfo, so borrow from PowerShell.
            local kb
            kb=$(powershell.exe -NoProfile -Command \
                "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize" 2>/dev/null | tr -d '\r')
            [ -n "$kb" ] && LS_RAM_MB=$(( kb / 1024 ))
            ;;
    esac

    # getconf is POSIX and present on Linux, macOS and BSD; nproc is GNU-only.
    if command -v getconf >/dev/null 2>&1; then
        LS_CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    elif command -v nproc >/dev/null 2>&1; then
        LS_CORES=$(nproc)
    elif command -v sysctl >/dev/null 2>&1; then
        LS_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    fi

    # Guarantee integers so downstream arithmetic can never explode.
    [[ "$LS_RAM_MB" =~ ^[0-9]+$ ]] || LS_RAM_MB=0
    [[ "$LS_CORES"  =~ ^[0-9]+$ ]] || LS_CORES=1
    [ "$LS_CORES" -lt 1 ] && LS_CORES=1

    export LS_RAM_MB LS_CORES
}

# ---------------------------------------------------------------------------
# Scratch space
#
# The original unconditionally used /dev/shm. That directory does not exist on
# macOS at all, and on Linux it is RAM-backed: a large target can write several
# GB of candidate hostnames into it and OOM-kill a 2 GB VPS mid-scan. Use it
# only when it is present, writable, and demonstrably roomy.
#
# $1 = suffix for the directory name. Echoes the chosen path.
# ---------------------------------------------------------------------------
compat_scratch_dir() {
    local suffix="$1" base="" avail_mb=0

    if [ -d /dev/shm ] && [ -w /dev/shm ]; then
        avail_mb=$(compat_avail_mb /dev/shm)
        # Need headroom for the scan *and* for everything else on the box.
        if [ "$avail_mb" -ge 2048 ] && [ "$LS_RAM_MB" -ge 8192 ]; then
            base="/dev/shm"
        fi
    fi

    if [ -z "$base" ]; then
        base="${TMPDIR:-/tmp}"
        base="${base%/}"
    fi

    local dir="${base}/leetenum_${suffix}"
    mkdir -p "$dir" 2>/dev/null || {
        dir="${HOME}/.cache/leetsec/scratch/leetenum_${suffix}"
        mkdir -p "$dir"
    }
    printf '%s\n' "$dir"
}

# Available space in MB for a path. `df -Pk` is POSIX-portable output, unlike
# `df -h` or `df --output=`, both of which differ between GNU and BSD.
compat_avail_mb() {
    local path="$1" kb
    kb=$(df -Pk "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    [[ "$kb" =~ ^[0-9]+$ ]] || kb=0
    printf '%s\n' "$(( kb / 1024 ))"
}

# ---------------------------------------------------------------------------
# Byte transparency on the data path
#
# compat_set_locale deliberately exports a UTF-8 LC_CTYPE so box glyphs, `wc -m`
# and printf padding behave. That is right for the UI and wrong for the data,
# because the BSD userland aborts on the first byte that is not valid UTF-8 while
# GNU coreutils passes it through. Measured on macOS 15 against a five-line list
# with one bad byte in line 2:
#
#     LC_CTYPE=C.UTF-8            LC_ALL=C
#     tr  -d '\r'      1 line     5 lines   tr: Illegal byte sequence
#     tr  upper→lower  1 line     5 lines   tr: Illegal byte sequence
#     sed 's|^..://||' 1 line     5 lines   sed: RE error: illegal byte sequence
#     sort -u          0 lines    5 lines   sort: Illegal byte sequence
#
# Every hostname after the bad byte is dropped. The input is crt.sh, the Wayback
# CDX index and katana output, so the bytes are third-party controlled and this is
# reachable in any engagement — and because GNU is unaffected, the same scan
# produced a different host set on Linux than on macOS with nothing to show why.
#
# Wrap the stage, not the whole program: LC_ALL here is scoped to the one command.
compat_bytes() { LC_ALL=C "$@"; }
export -f compat_bytes

# ---------------------------------------------------------------------------
# Small portable utilities
# ---------------------------------------------------------------------------

# Short stable hash of stdin. macOS has `md5`, Linux has `md5sum`, and both
# have `shasum` via Perl. Used only to name per-host work files.
compat_hash() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum | cut -d' ' -f1
    elif command -v md5 >/dev/null 2>&1; then
        md5 -q
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    else
        cksum | tr -d ' ' | cut -c1-16
    fi
}

# Download $1 to $2. macOS ships curl but not wget; minimal containers often
# ship the reverse. Returns non-zero on failure instead of leaving a truncated
# file behind, which is what silently broke resolver loading before.
compat_fetch() {
    local url="$1" dest="$2" tmp="${2}.part"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 \
             -o "$tmp" "$url" 2>/dev/null || { rm -f "$tmp"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --timeout=15 -O "$tmp" "$url" 2>/dev/null \
            || { rm -f "$tmp"; return 1; }
    else
        return 127
    fi
    [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$dest"
}

# Absolute path resolution. `realpath` is missing on macOS before 12.3 and on
# BSD; `readlink -f` is GNU-only. Fall back to a pure-shell walk.
compat_realpath() {
    local target="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath "$target" 2>/dev/null && return 0
    fi
    if readlink -f "$target" >/dev/null 2>&1; then
        readlink -f "$target" && return 0
    fi
    local dir base
    dir=$(dirname "$target"); base=$(basename "$target")
    printf '%s/%s\n' "$(cd "$dir" 2>/dev/null && pwd -P)" "$base"
}

# Bound a command in wall-clock seconds, returning 124 when the budget is hit.
#
# `timeout` is GNU coreutils and is simply absent on macOS, where the same
# invocation dies with "command not found" — so every bounded phase (amass,
# gotator, katana, waybackurls, gowitness) produced nothing at all on a Mac while
# reporting only that its tool had failed. Homebrew's coreutils installs the
# binary as `gtimeout` unless asked otherwise, which is the second name probed.
#
# With neither available the budget is enforced in shell: run the command in the
# background, poll a watchdog beside it, and escalate TERM to KILL after a five
# second grace so a tool that traps TERM still stops. `wait` reports a signalled
# child as 128+signal, and both of those are reported as 124 so the caller sees
# one "hit its budget" code regardless of which mechanism did the stopping.
#
# The `<&9` is load-bearing and its absence was a silent data-loss bug. Bash
# redirects an async command's stdin from /dev/null when job control is inactive,
# which every non-interactive script is. The one call site that pipes into a bounded
# tool — `printf '%s\n' "$PIPE_TARGET" | compat_timeout 600 waybackurls` in
# pipeline.sh — therefore handed waybackurls an empty stdin and got zero bytes back
# on every stock macOS host, where neither timeout nor gtimeout exists. Duplicating
# the caller's stdin onto fd 9 first and redirecting from it explicitly overrides
# that substitution. fd 9 rather than 3 because compat_online already uses 3.
#
# Exported because ui_run_sh evaluates its snippets in a child `bash -c`, where a
# function defined here would otherwise be invisible.
compat_timeout() {
    local secs="$1"; shift
    if [ -n "${LS_TIMEOUT_BIN:-}" ]; then
        "$LS_TIMEOUT_BIN" "$secs" "$@"
        return $?
    fi

    exec 9<&0
    "$@" <&9 &
    local cmd_pid=$!
    exec 9<&-
    (
        # Plain names, not `local`: this is a subshell, and polling `kill -0`
        # means the watchdog costs nothing and exits as soon as the tool does.
        _dog_left="$secs"
        while [ "$_dog_left" -gt 0 ]; do
            kill -0 "$cmd_pid" 2>/dev/null || exit 0
            sleep 1
            _dog_left=$(( _dog_left - 1 ))
        done
        kill -TERM "$cmd_pid" 2>/dev/null || true
        sleep 5
        kill -KILL "$cmd_pid" 2>/dev/null || true
    ) &
    local dog_pid=$!
    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?
    # Reached only once the tool is dead, so the escalation has already happened
    # if it was going to. Guarded because the watchdog usually exited on its own
    # first, and an unguarded failing kill would abort a caller running under
    # `set -e`.
    kill -KILL "$dog_pid" 2>/dev/null || true
    wait "$dog_pid" 2>/dev/null || true
    case "$rc" in 137|143) rc=124 ;; esac
    return "$rc"
}
export -f compat_timeout

# Locate a timeout binary once, rather than probing per call site.
compat_init_timeout() {
    LS_TIMEOUT_BIN=""
    if command -v timeout >/dev/null 2>&1; then
        LS_TIMEOUT_BIN="$(command -v timeout)"
    elif command -v gtimeout >/dev/null 2>&1; then
        LS_TIMEOUT_BIN="$(command -v gtimeout)"
    fi
    export LS_TIMEOUT_BIN
}

# Sort with the largest buffer the local sort actually understands. BSD sort
# (macOS default) rejects `--parallel` and treats `-S` differently, so the old
# hardcoded `sort -S 25G --parallel=N` aborted every merge step on a Mac.
# Percentages rather than absolute sizes keep this safe on a 1 GB VPS too.
compat_init_sort() {
    LS_SORT_OPTS=()
    if sort --version 2>/dev/null | grep -qi "GNU coreutils"; then
        LS_SORT_OPTS=(-S 25% "--parallel=${LS_CORES}")
        LS_SORT_IS_GNU="true"
    else
        LS_SORT_IS_GNU="false"
    fi
    export LS_SORT_IS_GNU
}

# The `${arr[@]+...}` guard is not decoration: bash 3.2, which is still the
# system bash on macOS, treats an empty array as unset under `set -u` and aborts
# the whole script on expansion. Every merge step in the pipeline goes through
# here, so this one line is the difference between working and not working on a
# stock Mac.
#
# LC_ALL=C rather than the inherited LC_COLLATE=C alone. Collation was already
# byte-wise, but BSD sort still validates *characters* against LC_CTYPE and exits
# with "sort: Illegal byte sequence" having written nothing at all — the worst of
# the four failure modes, because an empty artifact reads as "this phase found
# nothing" to every downstream consumer.
compat_sort() {
    LC_ALL=C sort ${LS_SORT_OPTS[@]+"${LS_SORT_OPTS[@]}"} "$@"
}

# In-place sed. GNU wants `-i`, BSD wants `-i ''`.
compat_sed_i() {
    local expr="$1"; shift
    if sed --version >/dev/null 2>&1; then
        sed -i "$expr" "$@"
    else
        sed -i '' "$expr" "$@"
    fi
}

# Line count as a bare integer. `wc -l < file` pads with spaces on macOS and
# BSD, which broke `[ "$CNT" -gt 0 ]` comparisons. Missing file counts as 0
# rather than erroring.
compat_count() {
    local file="$1"
    [ -s "$file" ] || { printf '0\n'; return 0; }
    local n
    n=$(wc -l < "$file" 2>/dev/null | tr -d '[:space:]')
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    printf '%s\n' "$n"
}

# ---------------------------------------------------------------------------
# Package manager detection
#
# Adds Homebrew (macOS, both Apple Silicon and Intel prefixes) and no longer
# hard-fails when nothing is recognised — the dependency doctor can still
# install the Go-based tools, which is most of the toolchain.
# ---------------------------------------------------------------------------
compat_detect_pkg_mgr() {
    LS_PKG_MGR="none"; LS_PKG_INSTALL=""; LS_PKG_REFRESH=""; LS_PKG_SUDO=""

    # Root, or a container running as root, needs no sudo. Non-interactive
    # environments without sudo should degrade rather than hang on a prompt.
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        LS_PKG_SUDO="sudo"
    fi

    if command -v brew >/dev/null 2>&1; then
        LS_PKG_MGR="brew"
        LS_PKG_INSTALL="brew install"
        LS_PKG_REFRESH="brew update"
        LS_PKG_SUDO=""            # brew refuses to run under sudo
    elif command -v apt-get >/dev/null 2>&1; then
        LS_PKG_MGR="apt"
        LS_PKG_INSTALL="$LS_PKG_SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends"
        LS_PKG_REFRESH="$LS_PKG_SUDO env DEBIAN_FRONTEND=noninteractive apt-get update"
    elif command -v dnf >/dev/null 2>&1; then
        LS_PKG_MGR="dnf"
        LS_PKG_INSTALL="$LS_PKG_SUDO dnf install -y"
        LS_PKG_REFRESH="$LS_PKG_SUDO dnf -y makecache"
    elif command -v pacman >/dev/null 2>&1; then
        LS_PKG_MGR="pacman"
        LS_PKG_INSTALL="$LS_PKG_SUDO pacman -S --needed --noconfirm"
        LS_PKG_REFRESH="$LS_PKG_SUDO pacman -Sy"
    elif command -v apk >/dev/null 2>&1; then
        LS_PKG_MGR="apk"
        LS_PKG_INSTALL="$LS_PKG_SUDO apk add --no-cache"
        LS_PKG_REFRESH="$LS_PKG_SUDO apk update"
    elif command -v zypper >/dev/null 2>&1; then
        LS_PKG_MGR="zypper"
        LS_PKG_INSTALL="$LS_PKG_SUDO zypper --non-interactive install"
        LS_PKG_REFRESH="$LS_PKG_SUDO zypper --non-interactive refresh"
    fi

    export LS_PKG_MGR LS_PKG_INSTALL LS_PKG_REFRESH LS_PKG_SUDO
}

# ---------------------------------------------------------------------------
# Chromium discovery for the screenshot phase. gowitness needs a real browser
# path, and every platform hides it somewhere different.
# ---------------------------------------------------------------------------
compat_find_chrome() {
    local candidates=(
        "${CHROME_PATH:-}"
        "$(command -v chromium 2>/dev/null)"
        "$(command -v chromium-browser 2>/dev/null)"
        "$(command -v google-chrome 2>/dev/null)"
        "$(command -v google-chrome-stable 2>/dev/null)"
        "/Applications/Chromium.app/Contents/MacOS/Chromium"
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        "/opt/homebrew/bin/chromium"
        "/usr/lib/chromium/chromium"
        "/snap/bin/chromium"
    )
    local c
    for c in "${candidates[@]}"; do
        [ -n "$c" ] && [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

# Network reachability without relying on ICMP. Many VPS providers and most
# corporate networks drop ping, so the old `ping -c 1 8.8.8.8` gate produced
# false "no internet" failures. A TCP connect is the honest test.
compat_online() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 6 -o /dev/null "https://1.1.1.1" 2>/dev/null && return 0
        curl -fsS --max-time 6 -o /dev/null "https://8.8.8.8" 2>/dev/null && return 0
        return 1
    fi
    # Bash /dev/tcp works even in stripped containers.
    (exec 3<>/dev/tcp/1.1.1.1/443) >/dev/null 2>&1 && { exec 3>&- 2>/dev/null; return 0; }
    return 1
}

# One call to set everything up.
compat_init() {
    compat_detect_platform
    compat_set_locale
    compat_detect_hardware
    compat_init_sort
    compat_init_timeout
    compat_detect_pkg_mgr
}
