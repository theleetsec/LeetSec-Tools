#!/bin/bash

# ============================================================
# LeetEnum v1.0 // Property of LeetSec
# ============================================================

# --- CORE ---
export LC_ALL=C
export TERM=xterm-256color
CONF_DIR="$HOME/.config/leetsec"
CONF_FILE="$CONF_DIR/leetenum.conf"
SCRIPT_PATH=$(realpath "$0")

# Style
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; NC='\033[0m'

# --- UI ---

banner() {
    clear
    echo -e "${G}"
    cat << "EOF"
    __               __  ______                     
   / /   ___  ___  / /_/ ____/___  __  ______ ___ 
  / /   / _ \/ _ \/ __/ __/ / __ \/ / / / __ `__ \
 / /___/  __/  __/ /_/ /___/ / / / /_/ / / / / / /
/_____/\___/\___/\__/_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                  
EOF
    echo -e "${NC}"
    echo -e "${C}::: LeetSec Reconnaissance Engine v1.0 :::${NC}\n"
}

die() { echo -e "${R}[FATAL] $1${NC}"; exit 1; }
warn() { echo -e "${Y}[!] $1${NC}"; }
info() { echo -e "${B}[*] $1${NC}"; }
good() { echo -e "${G}[+] $1${NC}"; }

# Cleanup
cleanup() {
    # Don't print cleanup msg if we finished successfully
    exit 0
}
trap cleanup SIGINT SIGTERM

# Alerts (Synchronous - Guarantees Delivery)
notify() {
    msg="$1"
    # Force reload config to ensure we have keys
    [ -f "$CONF_FILE" ] && source "$CONF_FILE"
    
    if [ "$NOTIFY_SERVICE" == "Discord" ] && [ -n "$DISCORD_WEBHOOK" ]; then
        curl -s -H "Content-Type: application/json" -d "{\"content\": \"$msg\"}" "$DISCORD_WEBHOOK" > /dev/null
    elif [ "$NOTIFY_SERVICE" == "Slack" ] && [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK" > /dev/null
    elif [ "$NOTIFY_SERVICE" == "Telegram" ] && [ -n "$TELEGRAM_TOKEN" ]; then
        # Removed '&' to ensure script waits for telegram API response before exiting
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" -d chat_id="$TELEGRAM_CHATID" -d text="$msg" > /dev/null
    fi
}

# Integrity Check
check_gear() {
    mkdir -p "$CONF_DIR"
    ! ping -c 1 8.8.8.8 &>/dev/null && die "Network unreachable."

    # System Deps
    MISSING_DEPS=false
    if ! command -v massdns &>/dev/null; then
        echo -e "${R}[!] MassDNS missing.${NC}"; echo -e "${Y}    -> Run: sudo apt update && sudo apt install massdns${NC}"; MISSING_DEPS=true
    fi
    if ! command -v chromium &>/dev/null && ! command -v google-chrome &>/dev/null; then
        echo -e "${R}[!] Chromium missing.${NC}"; echo -e "${Y}    -> Run: sudo apt install chromium-browser${NC}"; MISSING_DEPS=true
    fi
    [ "$MISSING_DEPS" = true ] && die "Install dependencies manually."

    # Go Tools
    for t in tmux pv go amass subfinder puredns httpx naabu katana nuclei waybackurls anew jq gum ffuf gowitness; do
        if ! command -v $t &>/dev/null; then
            info "Installing $t..."
            if [ "$t" == "gum" ]; then go install github.com/charmbracelet/gum@latest >/dev/null 2>&1
            elif [ "$t" == "gowitness" ]; then go install github.com/sensepost/gowitness@latest >/dev/null 2>&1
            elif [[ "$t" =~ ^(tmux|pv|jq)$ ]]; then warn "Missing $t. Try 'sudo apt install $t'"; else
                go install -v "github.com/projectdiscovery/$t/v2/cmd/$t@latest" >/dev/null 2>&1 || \
                go install -v "github.com/tomnomnom/$t@latest" >/dev/null 2>&1
            fi
            export PATH=$PATH:$(go env GOPATH)/bin
        fi
    done
    
    if [ ! -f "$CONF_DIR/.nuc_chk" ] || [ $(find "$CONF_DIR/.nuc_chk" -mtime +1) ]; then
        info "Syncing Nuclei..."
        nuclei -update-templates -silent >/dev/null 2>&1
        touch "$CONF_DIR/.nuc_chk"
    fi
}

init_conf() {
    [ "$RESET" = true ] && rm -f "$CONF_FILE" && warn "Config reset."
    if [ ! -f "$CONF_FILE" ]; then touch "$CONF_FILE"; fi
    source "$CONF_FILE"
    
    # If variable is missing, force setup
    if [ -z "$NOTIFY_SERVICE" ]; then
        if gum confirm "Configure Alerts?"; then
            SVC=$(gum choose "Discord" "Slack" "Telegram")
            echo "NOTIFY_SERVICE=\"$SVC\"" >> "$CONF_FILE"
            case $SVC in
                Discord)  VAL=$(gum input --placeholder "Webhook URL" --password); echo "DISCORD_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                Slack)    VAL=$(gum input --placeholder "Webhook URL" --password); echo "SLACK_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                Telegram) 
                    TOK=$(gum input --placeholder "Bot Token" --password); echo "TELEGRAM_TOKEN=\"$TOK\"" >> "$CONF_FILE"; 
                    ID=$(gum input --placeholder "Chat ID"); echo "TELEGRAM_CHATID=\"$ID\"" >> "$CONF_FILE" ;;
            esac
            # Reload and Test immediately
            source "$CONF_FILE"
            notify "LeetEnum Configured. If you see this, it works!"
            good "Test notification sent."
        else
            echo "NOTIFY_SERVICE=\"None\"" >> "$CONF_FILE"
        fi
    fi
}

setup_cron() {
    TGT=$1
    if [ -z "$(crontab -l 2>/dev/null | grep "$SCRIPT_PATH" | grep "$TGT")" ]; then
        if gum confirm "Add to Auto-Scheduler?"; then
            D=$(gum input --placeholder "Days interval (e.g. 7)")
            if [[ "$D" =~ ^[0-9]+$ ]]; then
                (crontab -l 2>/dev/null; echo "0 0 */$D * * $SCRIPT_PATH -d $TGT -m -no-tmux >> ${HOME}/leetsec_cron.log 2>&1") | crontab -
                notify "$TGT monitored every $D days."
            fi
        fi
    fi
}

# --- CLI ARGS ---
RESET=false; TARGET=""; MONITOR=false; NO_TMUX=false; DEEP_SCAN=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) TARGET="$2"; shift ;;
        -m|--monitor) MONITOR=true ;;
        --reset) RESET=true ;;
        --deep) DEEP_SCAN=true ;;
        -no-tmux) NO_TMUX=true ;;
        *) die "Usage: $0 -d target.com [-m] [--deep]" ;;
    esac
    shift
done

check_gear
init_conf

# --- WIZARD ---
if [ -z "$TARGET" ]; then
    banner
    TARGET=$(gum input --placeholder "Target Domain")
    if gum confirm "Enable Deep Port Scan (Slow)?"; then DEEP_SCAN=true; fi
    if gum confirm "Differential Mode (Monitor)?"; then MONITOR=true; fi
fi

[ -z "$TARGET" ] && die "Target required."
TARGET=$(echo "$TARGET" | sed 's~http[s]*://~~g' | tr -d '/')

# --- SESSION GUARDIAN ---
if [ -t 0 ] && [ "$NO_TMUX" = false ]; then
    setup_cron "$TARGET"
    SESS="leet_${TARGET//./_}"
    if [ -z "$TMUX" ]; then
        if tmux has-session -t "$SESS" 2>/dev/null; then
            gum confirm "Resume active session?" && tmux attach -t "$SESS" && exit 0
        elif gum confirm "Run in background (Tmux)?"; then
            tmux new-session -d -s "$SESS" "bash $SCRIPT_PATH -d $TARGET $( [ "$MONITOR" = true ] && echo "-m" ) $( [ "$DEEP_SCAN" = true ] && echo "--deep" ) -no-tmux; bash"
            tmux attach -t "$SESS"
            exit 0
        fi
    fi
fi

# --- WORKSPACE ---
TS=$(date +%Y%m%d_%H%M)
BASE_DIR="$(pwd)/recon_${TARGET}"
LAST_MASTER=""
[ -L "${BASE_DIR}/latest" ] && LAST_MASTER=$(readlink -f "${BASE_DIR}/latest/master_dns.txt")

if [ "$MONITOR" = true ]; then
    FINAL_DIR="${BASE_DIR}/${TS}"
    info "Mode: MONITOR"
else
    LAST_SCAN=$(ls -dt "$BASE_DIR"/*/ 2>/dev/null | head -1)
    if [ -n "$LAST_SCAN" ]; then FINAL_DIR=${LAST_SCAN%/}; info "Resuming session."; else FINAL_DIR="${BASE_DIR}/${TS}"; fi
fi

WORK_DIR="/dev/shm/recon_${TARGET}_${TS}"
RPT_DIR="${FINAL_DIR}/reports"
LOCK_DIR="${FINAL_DIR}/.locks"
mkdir -p "$WORK_DIR" "$FINAL_DIR" "$RPT_DIR" "$LOCK_DIR"

# --- PROFILER ---
RAM=$(free -g | grep Mem: | awk '{print $2}')
CORES=$(nproc)

if [ "$RAM" -ge 60 ]; then 
    PROF="LEET MODE"; HTTPX=450; PUREDNS=500; NAABU=5000; LIMIT=50000; PARALLEL=50; SORT="-S 25G --parallel=${CORES}"
elif [ "$RAM" -ge 16 ]; then 
    PROF="PRO"; HTTPX=200; PUREDNS=200; NAABU=2500; LIMIT=20000; PARALLEL=15; SORT="-S 50% --parallel=${CORES}"
else 
    PROF="LITE"; HTTPX=80; PUREDNS=100; NAABU=1000; LIMIT=5000; PARALLEL=5; SORT="-S 50%"
fi
JOB_LIMIT=$((LIMIT / PARALLEL))

WL_BRUTE=~/brute_wordlist.txt
WL_PERM=~/perm_words.txt
WL_RES="${WORK_DIR}/resolvers.txt"
[ ! -s "$WL_BRUTE" ] && wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O "$WL_BRUTE"
[ ! -s "$WL_PERM" ] && wget -q https://raw.githubusercontent.com/m4ll0k/BBTz/master/perm_words.txt -O "$HOME/perm_words.txt"
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O "$WL_RES"

notify "LeetEnum Started: $TARGET [$PROF]"

# 1. PASSIVE
if [ ! -f "$LOCK_DIR/p1" ]; then
    info "Phase 1: Passive Intel"
    timeout 15m amass enum -passive -d "$TARGET" -config ~/.config/amass/config.ini -o "$WORK_DIR/amass.txt" >/dev/null 2>&1
    subfinder -d "$TARGET" -all -silent > "$WORK_DIR/subfinder.txt"
    assetfinder --subs-only "$TARGET" > "$WORK_DIR/asset.txt"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > "$WORK_DIR/crt.txt"
    cat "$WORK_DIR"/*.txt 2>/dev/null | sort $SORT -u | grep -F ".$TARGET" > "$WORK_DIR/passive_raw.txt"
    if [ -s "$WORK_DIR/passive_raw.txt" ]; then
        puredns resolve "$WORK_DIR/passive_raw.txt" -r "$WL_RES" -w "$WORK_DIR/passive_valid.txt" --rate-limit "$LIMIT" >/dev/null 2>&1
    fi
    cp "$WORK_DIR/passive_valid.txt" "$FINAL_DIR/passive.txt" 2>/dev/null
    touch "$LOCK_DIR/p1"
else
    cp "$FINAL_DIR/passive.txt" "$WORK_DIR/passive_valid.txt" 2>/dev/null
fi

# 2. BRUTE
if [ ! -f "$LOCK_DIR/p2" ]; then
    info "Phase 2: Active Brute"
    puredns bruteforce "$WL_BRUTE" "$TARGET" -r "$WL_RES" -w "$WORK_DIR/brute.txt" --rate-limit "$LIMIT" >/dev/null 2>&1
    cp "$WORK_DIR/brute.txt" "$FINAL_DIR/brute.txt" 2>/dev/null
    touch "$LOCK_DIR/p2"
else
    cp "$FINAL_DIR/brute.txt" "$WORK_DIR/brute.txt" 2>/dev/null
fi

# 3. RECURSION
if [ ! -f "$LOCK_DIR/p3" ]; then
    cat "$WORK_DIR/passive_valid.txt" "$WORK_DIR/brute.txt" 2>/dev/null | sort $SORT -u > "$WORK_DIR/known.txt"
    head -n 50000 "$WL_BRUTE" > "$WORK_DIR/rec_wl.txt"
    awk -v t="$TARGET" -F. '{if (NF <= 5) print $0}' "$WORK_DIR/known.txt" | head -n 100000 > "$WORK_DIR/rec_targets.txt"
    
    CNT=$(wc -l < "$WORK_DIR/rec_targets.txt")
    if [ "$CNT" -gt 0 ]; then
        echo -e "${C}    -> Deep Scanning $CNT targets ($PARALLEL x)...${NC}"
        do_rec() {
            s=$1; w=$2; r=$3; o=$4; l=$5
            h=$(echo "$s"|md5sum|cut -d' ' -f1)
            puredns bruteforce "$w" "$s" -r "$r" -w "$o/r_$h.txt" --rate-limit "$l" >/dev/null 2>&1
        }
        export -f do_rec
        if [ -t 0 ] && command -v pv >/dev/null; then
            cat "$WORK_DIR/rec_targets.txt" | pv -l -s "$CNT" | xargs -P "$PARALLEL" -I {} bash -c "do_rec '{}' '$WORK_DIR/rec_wl.txt' '$WL_RES' '$WORK_DIR' '$JOB_LIMIT'"
        else
            cat "$WORK_DIR/rec_targets.txt" | xargs -P "$PARALLEL" -I {} bash -c "do_rec '{}' '$WORK_DIR/rec_wl.txt' '$WL_RES' '$WORK_DIR' '$JOB_LIMIT'"
        fi
        cat "$WORK_DIR"/r_*.txt >> "$WORK_DIR/recursive.txt" 2>/dev/null
        rm "$WORK_DIR"/r_*.txt 2>/dev/null
    fi
    cp "$WORK_DIR/recursive.txt" "$FINAL_DIR/recursive.txt" 2>/dev/null
    touch "$LOCK_DIR/p3"
else
    cp "$FINAL_DIR/recursive.txt" "$WORK_DIR/recursive.txt" 2>/dev/null
fi

# 4. PERMS
if [ ! -f "$LOCK_DIR/p4" ]; then
    info "Phase 3: Permutations"
    cat "$WORK_DIR/known.txt" "$WORK_DIR/recursive.txt" 2>/dev/null | sort $SORT -u > "$WORK_DIR/seeds.txt"
    S_CNT=$(wc -l < "$WORK_DIR/seeds.txt")
    if [ "$S_CNT" -gt 0 ]; then
        [ "$S_CNT" -gt 50000 ] && head -n 50000 "$WORK_DIR/seeds.txt" > "$WORK_DIR/gotator_seeds.txt" || cp "$WORK_DIR/seeds.txt" "$WORK_DIR/gotator_seeds.txt"
        timeout 60m gotator -sub "$WORK_DIR/gotator_seeds.txt" -perm "$WL_PERM" -depth 1 -silent -md > "$WORK_DIR/perms_raw.txt"
        [ -s "$WORK_DIR/perms_raw.txt" ] && puredns resolve "$WORK_DIR/perms_raw.txt" -r "$WL_RES" -w "$WORK_DIR/perms_valid.txt" --rate-limit "$LIMIT" >/dev/null 2>&1
    fi
    cp "$WORK_DIR/perms_valid.txt" "$FINAL_DIR/perms.txt" 2>/dev/null
    touch "$LOCK_DIR/p4"
else
    cp "$FINAL_DIR/perms.txt" "$WORK_DIR/perms_valid.txt" 2>/dev/null
fi

# MERGE
cat "$WORK_DIR/seeds.txt" "$WORK_DIR/perms_valid.txt" 2>/dev/null | sort $SORT -u | grep "$TARGET" > "$WORK_DIR/master.txt"
cp "$WORK_DIR/master.txt" "$FINAL_DIR/master_dns.txt" 2>/dev/null

NEW_CNT=0
if [ "$MONITOR" = true ] && [ -f "$LAST_MASTER" ]; then
    sort $SORT -u "$LAST_MASTER" > "$WORK_DIR/old.txt"
    sort $SORT -u "$WORK_DIR/master.txt" > "$WORK_DIR/new.txt"
    comm -13 "$WORK_DIR/old.txt" "$WORK_DIR/new.txt" > "$FINAL_DIR/new_subs.txt"
    NEW_CNT=$(wc -l < "$FINAL_DIR/new_subs.txt")
    [ "$NEW_CNT" -gt 0 ] && notify "MONITOR: Found $NEW_CNT NEW subdomains!"
fi

# 5. PORTS
info "Phase 4: Omni-Port & HTTP"
if [ -s "$WORK_DIR/master.txt" ]; then
    if [ "$DEEP_SCAN" = true ]; then PORTS="-p 1-10000"; warn "DEEP SCAN enabled."; else PORTS="-top-ports 1000"; fi
    
    naabu -l "$WORK_DIR/master.txt" -rate "$NAABU" $PORTS -silent -o "$WORK_DIR/ports.txt" >/dev/null 2>&1
    [ -s "$WORK_DIR/ports.txt" ] && T_LIST="$WORK_DIR/ports.txt" || T_LIST="$WORK_DIR/master.txt"
    
    httpx -l "$T_LIST" -threads "$HTTPX" -random-agent -retries 2 -timeout 10 -sc -title -tech-detect -ip -cname -server -o "$FINAL_DIR/http_full.txt" -silent > /dev/null 2>&1
    
    # SORTING - SEPARATE FILES
    awk '{print $1}' "$FINAL_DIR/http_full.txt" | sort $SORT -u > "$WORK_DIR/live.txt"
    grep "\[200\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/200.txt"
    grep "\[301\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/301.txt"
    grep "\[302\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/302.txt"
    grep "\[401\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/401.txt"
    grep "\[403\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/403.txt"
    grep "\[404\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/404.txt"
    grep "\[500\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/500.txt"
    
    # Clean Live List for Fuzzing
    cp "$WORK_DIR/live.txt" "$FINAL_DIR/live_urls.txt"
fi

# 6. VISUALS
info "Phase 5: Visuals (Screenshots)"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v gowitness &>/dev/null; then
        echo -e "${C}    -> Taking Screenshots...${NC}"
        mkdir -p "$FINAL_DIR/screenshots"
        # FIXED: Removed --chrome-arg flags entirely to fix compatibility
        gowitness scan file -f "$WORK_DIR/live.txt" -s "$FINAL_DIR/screenshots/" --threads 10 --no-http > "$RPT_DIR/gowitness.log" 2>&1
    fi
fi

# 7. VULNS
info "Phase 6: Deep Vulnerability Scan"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v katana &>/dev/null; then
        katana -list "$WORK_DIR/live.txt" -jc -kf -c 20 -d 2 -silent 2>/dev/null | grep "$TARGET" | sort $SORT -u > "$WORK_DIR/spider.txt"
        if [ -s "$WORK_DIR/spider.txt" ]; then
            puredns resolve "$WORK_DIR/spider.txt" -r "$WL_RES" -w "$WORK_DIR/spider_val.txt" --rate-limit "$LIMIT" >/dev/null 2>&1
            cat "$WORK_DIR/spider_val.txt" >> "$FINAL_DIR/master_dns.txt"
        fi
    fi
    
    if command -v nuclei &>/dev/null; then
        nuclei -l "$WORK_DIR/live.txt" \
            -tags takeover,exposure,config,keys,cloud \
            -severity low,medium,high,critical \
            -timeout 10 -retries 2 \
            -silent | tee "$RPT_DIR/nuclei.txt" | grep --line-buffered -iE "medium|high|critical"
    fi
fi

# --- REPORT ---
rm -rf "${BASE_DIR}/latest"; ln -s "${FINAL_DIR}" "${BASE_DIR}/latest"
DNS=$(wc -l < "$FINAL_DIR/master_dns.txt")
VULN=$(wc -l < "$RPT_DIR/nuclei.txt")
LIVE=$(wc -l < "$WORK_DIR/live.txt")

cat << EOF > "$FINAL_DIR/REPORT.md"
# LeetEnum Report: $TARGET
**Date:** $(date)
**Profile:** $PROF

| Metric | Count |
|--------|-------|
| Subdomains | $DNS |
| Live Sites | $LIVE |
| Screenshots | [View Gallery](screenshots/) |
| Vulns | $VULN |

## Status Codes
- 200 OK: $(wc -l < "$FINAL_DIR/200.txt")
- 403 Forbidden: $(wc -l < "$FINAL_DIR/403.txt")
- 404 Not Found: $(wc -l < "$FINAL_DIR/404.txt")

[View Data]($FINAL_DIR)
EOF

if [ -t 0 ] && command -v gum >/dev/null; then
    gum style --border double --foreground 212 --align center --width 50 "LEETENUM COMPLETE" "Target: $TARGET" "Subs: $DNS" "Vulns: $VULN"
else
    echo "Finished. Subs: $DNS | Vulns: $VULN"
fi

notify "LeetEnum: $TARGET | Subs: $DNS | Vulns: $VULN"
