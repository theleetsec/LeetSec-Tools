#!/bin/sh
# install.sh — one-line installer for LeetEnum (LeetSecurity LLC).
#
#   curl -fsSL https://raw.githubusercontent.com/theleetsec/LeetSec-Tools/main/install.sh | sh
#
# Deliberately /bin/sh and POSIX-only. The installer has to run before we know
# anything about the host, including whether bash exists at a usable version —
# writing it in bash would mean the installer itself could fail on the machines
# that most need a working install path.
#
# What it does, in order: pick a prefix, download a pinned snapshot, verify it
# looks like LeetEnum, move it into place atomically, link one entry point onto
# PATH, then hand off to `leetenum install` for the recon toolchain.
#
# Options (also settable as environment variables):
#   --prefix DIR     install root                 (LEETENUM_PREFIX)
#   --bin DIR        directory for the symlink    (LEETENUM_BIN)
#   --ref REF        branch, tag or commit        (LEETENUM_REF, default v1.0.0)
#   --tarball FILE   install from a local .tar.gz instead of downloading,
#                    for air-gapped hosts        (LEETENUM_TARBALL)
#   --no-tools       skip the recon toolchain
#   --uninstall      remove a previous install
set -eu

REPO="theleetsec/LeetSec-Tools"
# ghcr rejects uppercase in image paths, so this cannot be derived from $REPO.
IMAGE="ghcr.io/theleetsec/leetenum"
REF="${LEETENUM_REF:-v1.0.0}"
PREFIX="${LEETENUM_PREFIX:-}"
BINDIR="${LEETENUM_BIN:-}"
LOCAL_TARBALL="${LEETENUM_TARBALL:-}"
WANT_TOOLS=1
UNINSTALL=0

# No colour when piped or when NO_COLOR is set; an installer that dumps escape
# codes into a CI log is worse than a plain one.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$(printf '\033[1m'); D=$(printf '\033[2m'); R=$(printf '\033[0m')
    OKC=$(printf '\033[32m'); ERC=$(printf '\033[31m'); WNC=$(printf '\033[33m')
else
    B=''; D=''; R=''; OKC=''; ERC=''; WNC=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s-%s %s\n' "$D" "$R" "$*"; }
ok()   { printf '%s+%s %s\n' "$OKC" "$R" "$*"; }
warn() { printf '%s!%s %s\n' "$WNC" "$R" "$*"; }
die()  { printf '%sx%s %s\n' "$ERC" "$R" "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) [ -n "${2:-}" ] || die "--prefix needs a directory"; PREFIX="$2"; shift 2 ;;
        --bin)    [ -n "${2:-}" ] || die "--bin needs a directory";    BINDIR="$2"; shift 2 ;;
        --ref)    [ -n "${2:-}" ] || die "--ref needs a value";        REF="$2";    shift 2 ;;
        --tarball) [ -n "${2:-}" ] || die "--tarball needs a file";    LOCAL_TARBALL="$2"; shift 2 ;;
        --no-tools)  WANT_TOOLS=0; shift ;;
        --uninstall) UNINSTALL=1;  shift ;;
        -h|--help)
            # Print the leading comment block, stopping at the first line of code
            # so the help text cannot drift out of sync with a line range.
            awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
            exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Where to install
#
# Default to $HOME so the common case needs no sudo at all. Root gets the
# system prefix. Nothing here ever invokes sudo on its own: an installer that
# silently escalates is an installer nobody can audit from a pipe.
# ---------------------------------------------------------------------------
if [ -z "$PREFIX" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        PREFIX="/usr/local/share/leetsec"
    else
        PREFIX="${XDG_DATA_HOME:-${HOME}/.local/share}/leetsec"
    fi
fi
APPDIR="${PREFIX}/leetenum"

# Pick the first directory that is already on PATH and writable, so the shell
# finds `leetenum` without the user editing a profile. Fall back to
# ~/.local/bin and say so.
pick_bindir() {
    [ -n "$BINDIR" ] && { printf '%s\n' "$BINDIR"; return 0; }
    if [ "$(id -u)" -eq 0 ]; then printf '/usr/local/bin\n'; return 0; fi
    for d in "${HOME}/.local/bin" "${HOME}/bin" /usr/local/bin; do
        case ":${PATH}:" in
            *":${d}:"*) [ -d "$d" ] && [ -w "$d" ] && { printf '%s\n' "$d"; return 0; } ;;
        esac
    done
    printf '%s\n' "${HOME}/.local/bin"
}
BINDIR=$(pick_bindir)

if [ "$UNINSTALL" -eq 1 ]; then
    [ -f "${APPDIR}/leetenum.sh" ] && [ -d "${APPDIR}/lib" ] \
        || die "${APPDIR} does not look like a LeetEnum installation"
    say ""
    info "Removing ${APPDIR}"
    rm -rf "$APPDIR"
    if [ -L "${BINDIR}/leetenum" ] && \
       [ "$(readlink "${BINDIR}/leetenum")" = "${APPDIR}/leetenum.sh" ]; then
        rm -f "${BINDIR}/leetenum"
    fi
    ok "LeetEnum removed."
    info "Config and cache were left alone:"
    info "  ${XDG_CONFIG_HOME:-${HOME}/.config}/leetsec"
    info "  ${XDG_CACHE_HOME:-${HOME}/.cache}/leetsec"
    exit 0
fi

# ---------------------------------------------------------------------------
# Host summary. Printed before anything is written, because the most common
# support question is "what did it think my machine was".
# ---------------------------------------------------------------------------
case "$(uname -s)" in
    Linux*)   OS="linux" ;;
    Darwin*)  OS="darwin" ;;
    FreeBSD*) OS="freebsd" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
    *) OS="unknown" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="arm" ;;
    *) ARCH="$(uname -m)" ;;
esac

say ""
say "${B}LeetEnum installer${R}"
say "${D}  LeetSecurity LLC${R}"
say ""
info "host     ${OS}/${ARCH}"
info "ref      ${REF}"
info "install  ${APPDIR}"
info "link     ${BINDIR}/leetenum"
say ""

[ "$OS" = "unknown" ] && warn "Unrecognised platform; continuing, but expect rough edges."

# Git Bash cannot run the DNS toolchain (no raw sockets, no massdns build), so
# say so plainly rather than installing something that will fail at phase 2.
if [ "$OS" = "windows" ]; then
    warn "Native Windows is not a supported runtime for the scan phases."
    warn "Use WSL2 (recommended) or the container image:"
    warn "  wsl --install -d Ubuntu   then re-run this installer inside WSL"
    warn "  docker run --rm -it -v \"\$PWD:/work\" ${IMAGE}:latest example.com"
fi

# ---------------------------------------------------------------------------
# Prerequisites
#
# Only two are non-negotiable: bash 3.2+ to run the pipeline, and one of
# curl/wget/git to fetch it. Everything else is the toolchain, which
# `leetenum install` handles with a proper package-manager abstraction.
# ---------------------------------------------------------------------------
command -v bash >/dev/null 2>&1 || die "bash is required. Install it, then re-run."

BASH_MAJOR=$(bash -c 'printf %s "${BASH_VERSINFO[0]}"' 2>/dev/null || echo 0)
if [ "${BASH_MAJOR:-0}" -lt 3 ]; then
    die "bash 3.2 or newer required (found $(bash --version 2>/dev/null | head -1))"
fi
info "bash     $(bash -c 'printf %s "$BASH_VERSION"' 2>/dev/null)"

FETCH=""
if [ -n "$LOCAL_TARBALL" ]; then
    [ -s "$LOCAL_TARBALL" ] || die "--tarball ${LOCAL_TARBALL} is missing or empty"
    FETCH="local"
else
    command -v curl >/dev/null 2>&1 && FETCH="curl"
    [ -z "$FETCH" ] && command -v wget >/dev/null 2>&1 && FETCH="wget"
    [ -z "$FETCH" ] && command -v git  >/dev/null 2>&1 && FETCH="git"
    [ -z "$FETCH" ] && die "need curl, wget or git to download LeetEnum"
fi

command -v tar >/dev/null 2>&1 || [ "$FETCH" = "git" ] \
    || die "need tar to unpack the download"

# ---------------------------------------------------------------------------
# Download into a temporary directory, then swap it in. A half-extracted tree
# left in place by an interrupted install is the one failure mode that leaves a
# user with a `leetenum` that exists but cannot work.
# ---------------------------------------------------------------------------
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/leetenum-install.XXXXXX") || die "cannot create temp dir"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT INT TERM

SRC="${TMPD}/src"
mkdir -p "$SRC"

say ""
if [ "$FETCH" = "local" ]; then
    info "Installing from ${LOCAL_TARBALL}"
else
    info "Downloading ${REPO}@${REF} via ${FETCH}"
fi

TARBALL="${TMPD}/leetenum.tar.gz"
TAR_URL="https://codeload.github.com/${REPO}/tar.gz/${REF}"

case "$FETCH" in
    local)
        cp "$LOCAL_TARBALL" "$TARBALL" || die "cannot read ${LOCAL_TARBALL}"
        ;;
    curl)
        curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 \
             -o "$TARBALL" "$TAR_URL" \
            || die "download failed: ${TAR_URL}"
        ;;
    wget)
        wget -q --tries=3 --timeout=20 -O "$TARBALL" "$TAR_URL" \
            || die "download failed: ${TAR_URL}"
        ;;
    git)
        # Fetch the requested ref exactly. Falling back to the default branch
        # would silently install a different version when a tag is misspelled.
        git init -q "${SRC}/repo" \
            && git -C "${SRC}/repo" remote add origin "https://github.com/${REPO}.git" \
            && git -C "${SRC}/repo" fetch -q --depth 1 origin "$REF" \
            && git -C "${SRC}/repo" checkout -q --detach FETCH_HEAD \
            || die "could not fetch ${REPO}@${REF}"
        ;;
esac

if [ "$FETCH" != "git" ]; then
    [ -s "$TARBALL" ] || die "download produced an empty file"
    # --strip-components drops the GitHub-generated <repo>-<ref>/ wrapper, whose
    # name depends on the ref and so cannot be predicted reliably.
    mkdir -p "${SRC}/repo"
    tar -xzf "$TARBALL" -C "${SRC}/repo" --strip-components=1 \
        || die "could not unpack the download"
fi

# Verify we got LeetEnum and not an error page rendered as HTML, which is what a
# bad ref returns and what silently installed a 9-byte "Not Found" before.
NEW="${SRC}/repo"
for f in leetenum.sh lib/compat.sh lib/ui.sh lib/config.sh lib/deps.sh lib/pipeline.sh; do
    [ -s "${NEW}/${f}" ] || die "download is incomplete: ${f} missing. Wrong --ref?"
done
head -n 1 "${NEW}/leetenum.sh" | grep -q '^#!' \
    || die "download does not look like LeetEnum"
bash -n "${NEW}/leetenum.sh" 2>/dev/null \
    || die "downloaded leetenum.sh does not parse under this bash"

VER=$(sed -n 's/^LEETENUM_VERSION="\([^"]*\)".*/\1/p' "${NEW}/leetenum.sh" | head -1)
ok "Fetched LeetEnum ${VER:-unknown}"

# ---------------------------------------------------------------------------
# Install
#
# Move the new tree in beside the old one and rename, so an upgrade is atomic
# from the point of view of anything invoking `leetenum` concurrently.
# ---------------------------------------------------------------------------
mkdir -p "$PREFIX" 2>/dev/null || die "cannot create ${PREFIX} (try --prefix, or run as root)"
[ -w "$PREFIX" ] || die "${PREFIX} is not writable (try --prefix \$HOME/.leetsec)"

STAGE="${PREFIX}/.leetenum.new.$$"
rm -rf "$STAGE"
cp -R "$NEW" "$STAGE" || die "could not stage the install"
chmod +x "${STAGE}/leetenum.sh" 2>/dev/null || true
[ -f "${STAGE}/tests/run.sh" ] && chmod +x "${STAGE}/tests/run.sh" 2>/dev/null
[ -f "${STAGE}/tests/fixtures/fake-tool.sh" ] && \
    chmod +x "${STAGE}/tests/fixtures/fake-tool.sh" 2>/dev/null

if [ -d "$APPDIR" ]; then
    OLD="${PREFIX}/.leetenum.old.$$"
    mv "$APPDIR" "$OLD" || die "could not move the previous install aside"
    mv "$STAGE" "$APPDIR" || { mv "$OLD" "$APPDIR"; die "install failed; previous version restored"; }
    rm -rf "$OLD"
    ok "Upgraded in place: ${APPDIR}"
else
    mv "$STAGE" "$APPDIR" || die "could not install to ${APPDIR}"
    ok "Installed: ${APPDIR}"
fi

# ---------------------------------------------------------------------------
# Entry point. A symlink, not a copy: `leetenum.sh` resolves symlinks to find
# lib/, so this keeps one source of truth and makes upgrades instant.
# ---------------------------------------------------------------------------
mkdir -p "$BINDIR" 2>/dev/null || true
if [ -w "$BINDIR" ]; then
    ln -sf "${APPDIR}/leetenum.sh" "${BINDIR}/leetenum"
    ok "Linked: ${BINDIR}/leetenum"
else
    warn "${BINDIR} is not writable. Link it yourself with:"
    say  "    sudo ln -sf ${APPDIR}/leetenum.sh ${BINDIR}/leetenum"
fi

# PATH advice, and only when it is actually needed. Detect the login shell's rc
# file rather than editing it: silently rewriting someone's dotfiles from a
# piped installer is not a reasonable thing to do.
case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *)
        case "${SHELL:-}" in
            */zsh)  RC="${ZDOTDIR:-$HOME}/.zshrc" ;;
            */bash) RC="${HOME}/.bashrc"; [ "$OS" = "darwin" ] && RC="${HOME}/.bash_profile" ;;
            */fish) RC="${HOME}/.config/fish/config.fish" ;;
            *)      RC="${HOME}/.profile" ;;
        esac
        say ""
        warn "${BINDIR} is not on your PATH. Add it:"
        if [ "${RC##*/}" = "config.fish" ]; then
            say  "    fish_add_path ${BINDIR}"
        else
            say  "    echo 'export PATH=\"${BINDIR}:\$PATH\"' >> ${RC} && . ${RC}"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Toolchain
#
# Separate step, and skippable. Twelve Go binaries plus a massdns build is a
# long operation, and someone installing on a machine that already has a recon
# toolchain does not need it at all.
# ---------------------------------------------------------------------------
LEETENUM="${APPDIR}/leetenum.sh"

if [ "$WANT_TOOLS" -eq 1 ] && [ "$OS" != "windows" ]; then
    say ""
    info "Installing the recon toolchain (this is the slow part)"
    say ""
    if bash "$LEETENUM" install; then
        ok "Toolchain installed"
    else
        warn "Some tools did not install. Run 'leetenum doctor' for details."
    fi
else
    say ""
    info "Skipped the toolchain. Install it with: leetenum install"
fi

say ""
say "${B}Done.${R}"
say ""
say "  leetenum doctor          check the environment"
say "  leetenum example.com     run a scan"
say ""
info "Uninstall with: ${APPDIR}/install.sh --uninstall"
say ""
exit 0
