#!/bin/bash

# ============================================================
# LeetEnum v3.1 // Property of LeetSec
# The Recon Standard (Hyper-Velocity Edition)
# Features: Auto-Scale, Monitor, Resume, Visuals, Stability
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
    echo -e "${C}::: LeetSec Reconnaissance Engine v3.1 (Hyper-Velocity) :::${NC}\n"
}

die() { echo -e "${R}[FATAL] $1${NC}"; exit 1; }
warn() { echo -e "${Y}[!] $1${NC}"; }
info() { echo -e "${B}[*] $1${NC}"; }
good() { echo -e "${G}[+] $1${NC}"; }

# --- NOTIFICATIONS ---
notify() {
    msg="$1"
    [ -f "$CONF_FILE" ] && source "$CONF_FILE"
    
    if [ "$NOTIFY_SERVICE" == "Discord" ] && [ -n "$DISCORD_WEBHOOK" ]; then
        curl -s -H "Content-Type: application/json" -d "{\"content\": \"$msg\"}" "$DISCORD_WEBHOOK" > /dev/null &
    elif [ "$NOTIFY_SERVICE" == "Slack" ] && [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK" > /dev/null &
    elif [ "$NOTIFY_SERVICE" == "Telegram" ] && [ -n "$TELEGRAM_TOKEN" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" -d chat_id="$TELEGRAM_CHATID" -d text="$msg" > /dev/null &
    fi
}

# --- INTEGRITY CHECK ---
check_gear() {
    mkdir -p "$CONF_DIR"
    ! ping -c 1 8.8.8.8 &>/dev/null && die "Network unreachable."

    # System Deps
    MISSING=false
    if ! command -v massdns &>/dev/null; then
        echo -e "${R}[!] MassDNS missing.${NC}"; echo -e "${Y}    -> Run: sudo apt update && sudo apt install massdns${NC}"; MISSING=true
    fi
    if ! command -v chromium &>/dev/null && ! command -v google-chrome &>/dev/null; then
        echo -e "${R}[!] Chromium missing.${NC}"; echo -e "${Y}    -> Run: sudo apt install chromium-browser${NC}"; MISSING=true
    fi
    [ "$MISSING" = true ] && die "Install dependencies manually."

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
    
    if [ -z "$NOTIFY_SERVICE" ]; then
        if gum confirm "Configure Alerts?"; then
            SVC=$(gum choose "Discord" "Slack" "Telegram")
            echo "NOTIFY_SERVICE=\"$SVC\"" >> "$CONF_FILE"
            case $SVC in
                Discord)  VAL=$(gum input --placeholder "Webhook URL" --password); echo "DISCORD_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                Slack)    VAL=$(gum input --placeholder "Webhook URL" --password); echo "SLACK_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                Telegram) TOK=$(gum input --placeholder "Bot Token" --password); ID=$(gum input --placeholder "Chat ID"); echo "TELEGRAM_TOKEN=\"$TOK\"" >> "$CONF_FILE"; echo "TELEGRAM_CHATID=\"$ID\"" >> "$CONF_FILE" ;;
            esac
            notify " LeetEnum Configured."
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
                notify " $TGT monitored every $D days."
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

# --- PROFILER (SPEED UNLEASHED) ---
RAM=$(free -g | grep Mem: | awk '{print $2}')
CORES=$(nproc)

if [ "$RAM" -ge 60 ]; then 
    PROF="BEAST MODE (HYPER)"
    THREADS_HTTPX=1500
    THREADS_PUREDNS=1000
    THREADS_NAABU=30000    # 30k packets/sec
    RATE_LIMIT_TOTAL=100000 # 100k DNS queries/sec
    # Nuclei Turbo
    NUC_RL=4000; NUC_BS=150; NUC_C=100
    
    PARALLEL_RECURSION=50
    SORT_ARGS="-S 25G --parallel=${CORES}"
elif [ "$RAM" -ge 16 ]; then 
    PROF="PRO MODE"
    THREADS_HTTPX=500
    THREADS_PUREDNS=500
    THREADS_NAABU=5000
    RATE_LIMIT_TOTAL=30000
    NUC_RL=1000; NUC_BS=50; NUC_C=40
    
    PARALLEL_RECURSION=15
    SORT_ARGS="-S 50% --parallel=${CORES}"
else 
    PROF="STANDARD MODE"
    THREADS_HTTPX=100
    THREADS_PUREDNS=100
    THREADS_NAABU=1000
    RATE_LIMIT_TOTAL=5000
    NUC_RL=200; NUC_BS=20; NUC_C=20
    
    PARALLEL_RECURSION=5
    SORT_ARGS="-S 50%"
fi
RATE_LIMIT_PER_JOB=$((RATE_LIMIT_TOTAL / PARALLEL_RECURSION))

WL_BRUTE=~/brute_wordlist.txt
WL_PERM=~/perm_words.txt
WL_RES="${WORK_DIR}/resolvers.txt"
[ ! -s "$WL_BRUTE" ] && wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O "$WL_BRUTE"
[ ! -s "$WL_PERM" ] && wget -q https://raw.githubusercontent.com/m4ll0k/BBTz/master/perm_words.txt -O "$HOME/perm_words.txt"
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O "$WL_RES"

notify "LeetEnum Started: $TARGET [$PROF]"

# 1. PASSIVE
if [ ! -f "$CHECKPOINT_DIR/phase1.done" ]; then
    echo -e "${YELLOW}[*] Phase 1: Passive Collection...${NC}"
    timeout 15m amass enum -passive -d "$TARGET" -config ~/.config/amass/config.ini -o "$WORK_DIR/amass.txt" > /dev/null 2>&1
    subfinder -d "$TARGET" -all -silent 2>/dev/null > "$WORK_DIR/subfinder.txt"
    assetfinder --subs-only "$TARGET" > "$WORK_DIR/assetfinder.txt"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort $SORT_ARGS -u > "$WORK_DIR/crt.txt"
    
    cat "$WORK_DIR/amass.txt" "$WORK_DIR/subfinder.txt" "$WORK_DIR/assetfinder.txt" "$WORK_DIR/crt.txt" 2>/dev/null | sort $SORT_ARGS -u | grep -F ".$TARGET" > "$WORK_DIR/passive_raw.txt"
    
    if [ -s "$WORK_DIR/passive_raw.txt" ]; then
        puredns resolve "$WORK_DIR/passive_raw.txt" -r "$WL_RES" --write "$WORK_DIR/passive_valid.txt" --rate-limit "$RATE_LIMIT_TOTAL" 2>/dev/null > /dev/null
    fi
    cp "$WORK_DIR/passive_valid.txt" "$FINAL_DIR/passive_valid.txt" 2>/dev/null
    touch "$LOCK_DIR/p1"
else
    cp "$FINAL_DIR/passive_valid.txt" "$WORK_DIR/passive_valid.txt" 2>/dev/null
fi

# 2. BRUTE
if [ ! -f "$LOCK_DIR/p2" ]; then
    echo -e "${YELLOW}[*] Phase 2: Active Brute...${NC}"
    puredns bruteforce "$WL_BRUTE" "$TARGET" -r "$WL_RES" -w "$WORK_DIR/brute_root.txt" --rate-limit "$RATE_LIMIT_TOTAL" 2>/dev/null > /dev/null
    cp "$WORK_DIR/brute_root.txt" "$FINAL_DIR/brute_root.txt" 2>/dev/null
    touch "$LOCK_DIR/p2"
else
    cp "$FINAL_DIR/brute_root.txt" "$WORK_DIR/brute_root.txt" 2>/dev/null
fi

# 3. RECURSION
if [ ! -f "$LOCK_DIR/p3" ]; then
    cat "$WORK_DIR/passive_valid.txt" "$WORK_DIR/brute_root.txt" 2>/dev/null | sort $SORT_ARGS -u > "$WORK_DIR/current_known.txt"
    head -n 50000 "$WL_BRUTE" > "$WORK_DIR/recursion_wordlist.txt"
    awk -v target="$TARGET" -F. '{if (NF <= 5) print $0}' "$WORK_DIR/current_known.txt" | head -n 100000 > "$WORK_DIR/targets_for_recursion.txt"
    
    REC_COUNT=$(wc -l < "$WORK_DIR/targets_for_recursion.txt")
    if [ "$REC_COUNT" -gt 0 ]; then
        echo -e "${CYAN}    -> Recursing on ${REC_COUNT} targets...${NC}"
        run_recursion() {
            sub=$1; wordlist=$2; resolvers=$3; out_dir=$4; limit=$5
            safe_name=$(echo "$sub" | md5sum | cut -d' ' -f1)
            puredns bruteforce "$wordlist" "$sub" -r "$resolvers" -w "$out_dir/rec_${safe_name}.txt" --rate-limit "$limit" 2>/dev/null > /dev/null
        }
        export -f run_recursion
        if command -v pv &> /dev/null; then
            cat "$WORK_DIR/targets_for_recursion.txt" | pv -l -s "$REC_COUNT" -N "Brute Force" | xargs -P "$PARALLEL_RECURSION" -I {} bash -c "run_recursion '{}' '$WORK_DIR/recursion_wordlist.txt' '$WL_RES' '$WORK_DIR' '$RATE_LIMIT_PER_JOB'"
        else
            cat "$WORK_DIR/targets_for_recursion.txt" | xargs -P "$PARALLEL_RECURSION" -I {} bash -c "run_recursion '{}' '$WORK_DIR/recursion_wordlist.txt' '$WL_RES' '$WORK_DIR' '$RATE_LIMIT_PER_JOB'"
        fi
        cat "$WORK_DIR"/rec_*.txt >> "$WORK_DIR/brute_recursive.txt" 2>/dev/null
        rm "$WORK_DIR"/rec_*.txt 2>/dev/null
    fi
    cp "$WORK_DIR/brute_recursive.txt" "$FINAL_DIR/brute_recursive.txt" 2>/dev/null
    touch "$LOCK_DIR/p3"
else
    cp "$FINAL_DIR/brute_recursive.txt" "$WORK_DIR/brute_recursive.txt" 2>/dev/null
fi

# 4. PERMUTATIONS
if [ ! -f "$LOCK_DIR/p4" ]; then
    echo -e "${YELLOW}[*] Phase 3: Permutations...${NC}"
    cat "$WORK_DIR/current_known.txt" "$WORK_DIR/brute_recursive.txt" 2>/dev/null | sort $SORT_ARGS -u > "$WORK_DIR/all_seeds.txt"
    SEED_COUNT=$(wc -l < "$WORK_DIR/all_seeds.txt")
    if [ "$SEED_COUNT" -gt 0 ]; then
        if [ "$SEED_COUNT" -gt 50000 ]; then head -n 50000 "$WORK_DIR/all_seeds.txt" > "$WORK_DIR/gotator_seeds.txt"; else cp "$WORK_DIR/all_seeds.txt" "$WORK_DIR/gotator_seeds.txt"; fi
        timeout 60m gotator -sub "$WORK_DIR/gotator_seeds.txt" -perm "$WL_PERM" -depth 1 -silent -md > "$WORK_DIR/perms_raw.txt"
        if [ -s "$WORK_DIR/perms_raw.txt" ]; then
            puredns resolve "$WORK_DIR/perms_raw.txt" -r "$WL_RES" --write "$WORK_DIR/valid_perms.txt" --rate-limit "$RATE_LIMIT_TOTAL" 2>/dev/null > /dev/null
        fi
    fi
    cp "$WORK_DIR/valid_perms.txt" "$FINAL_DIR/valid_perms.txt" 2>/dev/null
    touch "$LOCK_DIR/p4"
else
    cp "$FINAL_DIR/valid_perms.txt" "$WORK_DIR/valid_perms.txt" 2>/dev/null
fi

# --- MERGE ---
cat "$WORK_DIR/all_seeds.txt" "$WORK_DIR/valid_perms.txt" 2>/dev/null | sort $SORT_ARGS -u | grep "$TARGET" > "$WORK_DIR/master_dns.txt"
cp "$WORK_DIR/master_dns.txt" "$FINAL_DIR/master_dns.txt" 2>/dev/null

NEW_CNT=0
if [ "$MONITOR" = true ] && [ -f "$LAST_MASTER" ]; then
    sort $SORT_ARGS -u "$LAST_MASTER" > "$WORK_DIR/old.txt"
    sort $SORT_ARGS -u "$WORK_DIR/master_dns.txt" > "$WORK_DIR/new.txt"
    comm -13 "$WORK_DIR/old.txt" "$WORK_DIR/new.txt" > "$FINAL_DIR/new_subs.txt"
    NEW_CNT=$(wc -l < "$FINAL_DIR/new_subs.txt")
    [ "$NEW_CNT" -gt 0 ] && notify "MONITOR: Found $NEW_CNT NEW subdomains!"
fi

# 5. PORTS
echo -e "${YELLOW}[*] Phase 4: Port Scanning...${NC}"
if [ -s "$WORK_DIR/master_dns.txt" ]; then
    if [ "$DEEP_SCAN" = true ]; then PORTS="-p 1-10000"; else PORTS="-top-ports 1000"; fi
    
    naabu -l "$WORK_DIR/master_dns.txt" -rate "$THREADS_NAABU" $PORTS -silent -o "$WORK_DIR/open_ports.txt" > /dev/null
    
    if [ -s "$WORK_DIR/open_ports.txt" ]; then
        httpx -l "$WORK_DIR/open_ports.txt" -threads "$THREADS_HTTPX" -random-agent -retries 2 -timeout 10 -sc -title -tech-detect -ip -cname -server -o "$FINAL_DIR/final_http_results.txt" -silent > /dev/null 2>&1
        awk '{print $1}' "$FINAL_DIR/final_http_results.txt" | sort $SORT_ARGS -u > "$WORK_DIR/live.txt"
    else
        httpx -l "$WORK_DIR/master_dns.txt" -threads "$THREADS_HTTPX" -random-agent -retries 2 -o "$FINAL_DIR/final_http_results.txt" -silent > /dev/null 2>&1
    fi
fi

# 6. VISUALS
echo -e "${YELLOW}[*] Phase 5: Visuals...${NC}"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v gowitness &>/dev/null; then
        mkdir -p "$FINAL_DIR/screenshots"
        gowitness scan file -f "$WORK_DIR/live.txt" -P "$FINAL_DIR/screenshots/" --threads 10 --no-http --chrome-arg='--no-sandbox' --chrome-arg='--disable-gpu' > "$RPT_DIR/gowitness.log" 2>&1
    fi
fi

# 7. VULNS
echo -e "${YELLOW}[*] Phase 6: Vulnerability Scanning...${NC}"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v katana &>/dev/null; then
        katana -list "$WORK_DIR/live.txt" -jc -kf -c 20 -d 2 -silent 2>/dev/null | grep "$TARGET" | sort $SORT_ARGS -u > "$WORK_DIR/spider.txt"
        if [ -s "$WORK_DIR/spider.txt" ]; then
            puredns resolve "$WORK_DIR/spider.txt" -r "$WL_RES" -w "$WORK_DIR/spider_val.txt" --rate-limit "$RATE_LIMIT_TOTAL" >/dev/null 2>&1
            cat "$WORK_DIR/spider_val.txt" >> "$FINAL_DIR/master_dns.txt"
        fi
    fi
    
    if command -v nuclei &>/dev/null; then
        # Hyper-Speed Nuclei Settings
        nuclei -l "$WORK_DIR/live.txt" -tags takeover,exposure,config,keys,cloud -severity low,medium,high,critical \
            -rl "$NUC_RL" -bs "$NUC_BS" -c "$NUC_C" -timeout 10 -retries 2 \
            -silent | tee "$RPT_DIR/nuclei.txt" | grep --line-buffered -iE "medium|high|critical"
    fi
fi

# --- REPORT ---
rm -rf "${BASE_DIR}/latest"; ln -s "${FINAL_DIR}" "${BASE_DIR}/latest"
DNS=$(wc -l < "$FINAL_DIR/master_dns.txt")
VULN=$(wc -l < "$RPT_DIR/nuclei.txt")

if [ -t 0 ] && command -v gum >/dev/null; then
    gum style --border double --foreground 212 --align center --width 50 "LEETENUM COMPLETE" "Target: $TARGET" "Subs: $DNS" "Vulns: $VULN"
else
    echo "Finished. Subs: $DNS | Vulns: $VULN"
fi

notify "LeetEnum: $TARGET | Subs: $DNS | Vulns: $VULN"
