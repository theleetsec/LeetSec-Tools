#!/bin/bash

# ============================================================
# LeetEnum v1.0 // Property of LeetSec
# ============================================================

# --- CORE ---
export LC_ALL=C
export TERM=xterm-256color
# CRITICAL FIX: Add Go Bin path immediately so script can see installed tools
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin

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
    exit 0
}
trap cleanup SIGINT SIGTERM

# Alerts
notify() {
    msg="$1"
    [ -f "$CONF_FILE" ] && source "$CONF_FILE"
    
    if [ "$NOTIFY_SERVICE" == "Discord" ] && [ -n "$DISCORD_WEBHOOK" ]; then
        curl -s -H "Content-Type: application/json" -d "{\"content\": \"$msg\"}" "$DISCORD_WEBHOOK" > /dev/null
    elif [ "$NOTIFY_SERVICE" == "Slack" ] && [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK" > /dev/null
    elif [ "$NOTIFY_SERVICE" == "Telegram" ] && [ -n "$TELEGRAM_TOKEN" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" -d chat_id="$TELEGRAM_CHATID" -d text="$msg" > /dev/null
    fi
}

# --- ROBUST DEPENDENCY MANAGER ---
check_gear() {
    mkdir -p "$CONF_DIR"
    ! ping -c 1 8.8.8.8 &>/dev/null && die "Network unreachable. Check your internet."

    # 1. CORE DEPENDENCIES (Must exist first)
    # Check for Go first because we need it for everything else
    if ! command -v go &>/dev/null; then
        warn "Golang not found. Attempting to install..."
        if command -v apt &>/dev/null; then
            sudo apt update && sudo apt install -y golang-go
        elif command -v pacman &>/dev/null; then
             sudo pacman -S go
        fi
        
        # Check again
        if ! command -v go &>/dev/null; then
            die "Could not install Golang automatically. Please install Go manually: https://go.dev/doc/install"
        fi
    fi

    # 2. SYSTEM TOOLS (APT)
    MISSING_DEPS=false
    for sys_tool in massdns chromium-browser jq pv tmux git; do
        if ! command -v $sys_tool &>/dev/null; then
            # Handle aliases/alternatives
            if [ "$sys_tool" == "chromium-browser" ] && command -v google-chrome &>/dev/null; then continue; fi
            if [ "$sys_tool" == "chromium-browser" ] && command -v chromium &>/dev/null; then continue; fi
            
            warn "Missing system tool: $sys_tool. Installing..."
            sudo apt update && sudo apt install -y $sys_tool >/dev/null 2>&1
            
            # Re-check
            if ! command -v $sys_tool &>/dev/null; then
                if [ "$sys_tool" == "massdns" ]; then
                     echo -e "${R}[!] Failed to install massdns.${NC}"
                     MISSING_DEPS=true
                elif [ "$sys_tool" == "chromium-browser" ]; then
                     echo -e "${R}[!] Failed to install chromium (needed for screenshots).${NC}"
                     # Not fatal, but warned
                else
                     MISSING_DEPS=true
                fi
            fi
        fi
    done
    
    if [ "$MISSING_DEPS" = true ]; then
        die "Critical dependencies failed to install. Please install 'massdns', 'jq', 'pv', 'tmux' manually."
    fi

    # 3. GO TOOLS (AUTO-INSTALLER)
    # List of tools and their repo paths
    declare -A tools
    tools[amass]="github.com/owasp-amass/amass/v3/..."
    tools[subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    tools[assetfinder]="github.com/tomnomnom/assetfinder"
    tools[puredns]="github.com/d3mondev/puredns/v2"
    tools[httpx]="github.com/projectdiscovery/httpx/cmd/httpx"
    tools[naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu"
    tools[katana]="github.com/projectdiscovery/katana/cmd/katana"
    tools[nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    tools[waybackurls]="github.com/tomnomnom/waybackurls"
    tools[anew]="github.com/tomnomnom/anew"
    tools[gum]="github.com/charmbracelet/gum"
    tools[ffuf]="github.com/ffuf/ffuf/v2"
    tools[gotator]="github.com/josderstad/gotator"
    tools[gowitness]="github.com/sensepost/gowitness"

    for tool in "${!tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            info "Installing $tool..."
            go install -v "${tools[$tool]}@latest" >/dev/null 2>&1
            
            # Verify install
            if ! command -v $tool &>/dev/null; then
                 # Try finding it in typical go path
                 if [ -f "$HOME/go/bin/$tool" ]; then
                     # It's there but not in path. Export again to be sure.
                     export PATH=$PATH:$HOME/go/bin
                 else
                     warn "Failed to install $tool. Check your Go setup."
                 fi
            fi
        fi
    done
    
    # 4. Updates
    if [ ! -f "$CONF_DIR/.nuc_chk" ] || [ $(find "$CONF_DIR/.nuc_chk" -mtime +1) ]; then
        if command -v nuclei &>/dev/null; then
            info "Syncing Nuclei..."
            nuclei -update-templates -silent >/dev/null 2>&1
            touch "$CONF_DIR/.nuc_chk"
        fi
    fi
}

# --- CONFIG ---
init_conf() {
    [ "$RESET" = true ] && rm -f "$CONF_FILE" && warn "Config reset."
    if [ ! -f "$CONF_FILE" ]; then touch "$CONF_FILE"; fi
    source "$CONF_FILE"
    
    if [ -z "$NOTIFY_SERVICE" ]; then
        # If gum is missing, we can't show the wizard properly, fallback to text
        if command -v gum &>/dev/null; then
            if gum confirm "Configure Alerts?"; then
                SVC=$(gum choose "Discord" "Slack" "Telegram")
                echo "NOTIFY_SERVICE=\"$SVC\"" >> "$CONF_FILE"
                case $SVC in
                    Discord)  VAL=$(gum input --placeholder "Webhook URL" --password); echo "DISCORD_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                    Slack)    VAL=$(gum input --placeholder "Webhook URL" --password); echo "SLACK_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                    Telegram) TOK=$(gum input --placeholder "Bot Token" --password); ID=$(gum input --placeholder "Chat ID"); echo "TELEGRAM_TOKEN=\"$TOK\"" >> "$CONF_FILE"; echo "TELEGRAM_CHATID=\"$ID\"" >> "$CONF_FILE" ;;
                esac
                notify "LeetEnum Configured."
            else
                echo "NOTIFY_SERVICE=\"None\"" >> "$CONF_FILE"
            fi
        else
            echo "NOTIFY_SERVICE=\"None\"" >> "$CONF_FILE"
        fi
    fi
}

setup_cron() {
    TGT=$1
    if [ -z "$(crontab -l 2>/dev/null | grep "$SCRIPT_PATH" | grep "$TGT")" ]; then
        if command -v gum &>/dev/null; then
            if gum confirm "Add to Auto-Scheduler?"; then
                D=$(gum input --placeholder "Days interval (e.g. 7)")
                if [[ "$D" =~ ^[0-9]+$ ]]; then
                    (crontab -l 2>/dev/null; echo "0 0 */$D * * $SCRIPT_PATH -d $TGT -m -no-tmux >> ${HOME}/leetsec_cron.log 2>&1") | crontab -
                    notify "$TGT monitored every $D days."
                fi
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
    if command -v gum &>/dev/null; then
        TARGET=$(gum input --placeholder "Target Domain")
        if gum confirm "Enable Deep Port Scan (Slow)?"; then DEEP_SCAN=true; fi
        if gum confirm "Differential Mode (Monitor)?"; then MONITOR=true; fi
    else
        read -p "Enter Target Domain: " TARGET
    fi
fi

[ -z "$TARGET" ] && die "Target required."
TARGET=$(echo "$TARGET" | sed 's~http[s]*://~~g' | tr -d '/')

# --- SESSION GUARDIAN ---
if [ -t 0 ] && [ "$NO_TMUX" = false ]; then
    setup_cron "$TARGET"
    SESS="leet_${TARGET//./_}"
    if [ -z "$TMUX" ]; then
        if tmux has-session -t "$SESS" 2>/dev/null; then
            if command -v gum &>/dev/null; then
                 gum confirm "Resume active session?" && tmux attach -t "$SESS" && exit 0
            else
                 tmux attach -t "$SESS" && exit 0
            fi
        else
            # Only ask if gum is available, else auto-run or warn
            if command -v gum &>/dev/null; then
                if gum confirm "Run in background (Tmux)?"; then
                    tmux new-session -d -s "$SESS" "bash $SCRIPT_PATH -d $TARGET $( [ "$MONITOR" = true ] && echo "-m" ) $( [ "$DEEP_SCAN" = true ] && echo "--deep" ) -no-tmux; bash"
                    tmux attach -t "$SESS"
                    exit 0
                fi
            fi
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

notify "🚀 LeetEnum Started: $TARGET [$PROF]"

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
    
    # SORTING
    awk '{print $1}' "$FINAL_DIR/http_full.txt" | sort $SORT -u > "$WORK_DIR/live.txt"
    grep "\[200\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/200.txt"
    grep "\[403\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/403.txt"
    grep "\[404\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/404.txt"
    cp "$WORK_DIR/live.txt" "$FINAL_DIR/live_urls.txt"
fi

# 6. VISUALS
info "Phase 5: Visuals (Screenshots)"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v gowitness &>/dev/null; then
        echo -e "${C}    -> Taking Screenshots...${NC}"
        mkdir -p "$FINAL_DIR/screenshots"
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
