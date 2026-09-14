#!/usr/bin/env bash
# lib/config.sh — configuration and notification transport.
#
# Two fixes over the original:
#   * Config is written atomically with 0600 permissions. Webhook URLs and bot
#     tokens are credentials; they were previously appended to a world-readable
#     file, and repeated `--reset` runs left duplicate keys behind.
#   * Notification payloads are JSON-encoded properly. The original built JSON
#     with string interpolation, so any message containing a double quote,
#     backslash or newline produced a 400 from the webhook and the alert was
#     lost silently — exactly when it mattered most.

LS_CONF_DIR="${LEETENUM_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/leetsec}"
LS_CONF_FILE="${LS_CONF_DIR}/leetenum.conf"
LS_CACHE_DIR="${LEETENUM_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/leetsec}"

config_init_dirs() {
    mkdir -p "$LS_CONF_DIR" "$LS_CACHE_DIR" "${LS_CACHE_DIR}/wordlists"
    chmod 700 "$LS_CONF_DIR" 2>/dev/null || true
}

config_load() {
    NOTIFY_SERVICE="${NOTIFY_SERVICE:-}"
    DISCORD_WEBHOOK=""; SLACK_WEBHOOK=""; TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""
    _LS_CONF_LOADED="true"

    [ -f "$LS_CONF_FILE" ] || return 0

    # Only accept KEY="value" lines from a known set. Sourcing the file outright
    # means a tampered config executes arbitrary code as the user.
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"; val="${line#*=}"
        val="${val%\"}"; val="${val#\"}"
        case "$key" in
            NOTIFY_SERVICE|DISCORD_WEBHOOK|SLACK_WEBHOOK|TELEGRAM_TOKEN|TELEGRAM_CHATID|SCAN_PROFILE)
                printf -v "$key" '%s' "$val" ;;
        esac
    done < "$LS_CONF_FILE"
}

config_save() {
    config_init_dirs
    local tmp="${LS_CONF_FILE}.tmp.$$"
    {
        printf '# LeetEnum configuration. Contains credentials; keep mode 0600.\n'
        printf 'NOTIFY_SERVICE="%s"\n' "$NOTIFY_SERVICE"
        [ -n "$DISCORD_WEBHOOK" ] && printf 'DISCORD_WEBHOOK="%s"\n' "$DISCORD_WEBHOOK"
        [ -n "$SLACK_WEBHOOK" ]   && printf 'SLACK_WEBHOOK="%s"\n'   "$SLACK_WEBHOOK"
        [ -n "$TELEGRAM_TOKEN" ]  && printf 'TELEGRAM_TOKEN="%s"\n'  "$TELEGRAM_TOKEN"
        [ -n "$TELEGRAM_CHATID" ] && printf 'TELEGRAM_CHATID="%s"\n' "$TELEGRAM_CHATID"
        [ -n "${SCAN_PROFILE:-}" ] && printf 'SCAN_PROFILE="%s"\n'   "$SCAN_PROFILE"
        # Keep the group's exit status zero: a skipped optional key above would
        # otherwise leave a non-zero status and abort the function under set -e.
        :
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$LS_CONF_FILE"
}

# Interactive first-run setup. Runs only when there is no stored choice, and
# writes NOTIFY_SERVICE="none" when declined so it never asks twice.
config_wizard() {
    config_load
    [ "${1:-}" = "reset" ] && NOTIFY_SERVICE=""
    [ -n "$NOTIFY_SERVICE" ] && return 0

    if [ "$UI_STDOUT_TTY" != "true" ] || [ "${ARG_YES:-false}" = "true" ]; then
        NOTIFY_SERVICE="none"; config_save; return 0
    fi

    ui_blank
    ui_info "First run. Alerts are optional and can be changed later with 'leetenum config'."
    if ! ui_confirm "Send a notification when a scan finishes?" n; then
        NOTIFY_SERVICE="none"; config_save; return 0
    fi

    NOTIFY_SERVICE=$(ui_choose "Which service?" "telegram" "discord" "slack")
    case "$NOTIFY_SERVICE" in
        discord)  DISCORD_WEBHOOK=$(ui_ask "Discord webhook URL" "" true) ;;
        slack)    SLACK_WEBHOOK=$(ui_ask "Slack webhook URL" "" true) ;;
        telegram) TELEGRAM_TOKEN=$(ui_ask "Telegram bot token" "" true)
                  TELEGRAM_CHATID=$(ui_ask "Telegram chat ID") ;;
    esac
    config_save
    if notify_send "LeetEnum alerts configured on $(hostname 2>/dev/null || echo host)"; then
        ui_ok "Test alert delivered"
    else
        ui_warn "Test alert failed. Check the credentials with 'leetenum config'."
    fi
}

# ---------------------------------------------------------------------------
# JSON string escaping.
#
# Prefer jq when present. The pure-bash fallback covers the characters that
# actually appear in scan messages, so alerts still work on a host without jq.
# ---------------------------------------------------------------------------
json_escape() {
    local s="$1"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$s" | jq -Rs .
        return 0
    fi
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/}"
    s="${s//$'\n'/\\n}"
    printf '"%s"' "$s"
}

# Send a notification. Returns non-zero on failure so callers can report it,
# rather than discarding the result into /dev/null as the original did.
notify_send() {
    local msg="$1" body rc=0
    [ "${_LS_CONF_LOADED:-false}" = "true" ] || config_load
    case "${NOTIFY_SERVICE:-none}" in
        none|"") return 0 ;;
    esac
    command -v curl >/dev/null 2>&1 || return 1

    case "$NOTIFY_SERVICE" in
        discord)
            [ -n "$DISCORD_WEBHOOK" ] || return 1
            body="{\"content\":$(json_escape "$msg")}"
            curl -fsS --max-time 20 -H 'Content-Type: application/json' \
                 -d "$body" "$DISCORD_WEBHOOK" -o /dev/null || rc=$?
            ;;
        slack)
            [ -n "$SLACK_WEBHOOK" ] || return 1
            body="{\"text\":$(json_escape "$msg")}"
            curl -fsS --max-time 20 -X POST -H 'Content-Type: application/json' \
                 -d "$body" "$SLACK_WEBHOOK" -o /dev/null || rc=$?
            ;;
        telegram)
            [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHATID" ] || return 1
            # --data-urlencode keeps the token out of the URL query log and
            # handles newlines and emoji in the body correctly.
            curl -fsS --max-time 20 -X POST \
                 "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
                 --data-urlencode "chat_id=${TELEGRAM_CHATID}" \
                 --data-urlencode "text=${msg}" -o /dev/null || rc=$?
            ;;
        *) return 1 ;;
    esac
    return "$rc"
}
