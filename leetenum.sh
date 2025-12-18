#!/bin/bash

# ============================================================
# LeetEnum v1.0 // Property of LeetSec
# ============================================================

# --- SELF-CORRECTION ---
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
fi

# --- CORE ---
export LC_ALL=C.UTF-8
export TERM=xterm-256color
export GIT_TERMINAL_PROMPT=0
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
export GOPROXY=https://proxy.golang.org,direct

# START TIMER
START_TIME=$(date +%s)

# UPDATE CONFIGURATION
UPDATE_URL="https://raw.githubusercontent.com/theleetsec/LeetSec-Tools/main/leetenum.sh"

CONF_DIR="$HOME/.config/leetsec"
CONF_FILE="$CONF_DIR/leetenum.conf"
SCRIPT_PATH=$(realpath "$0")

# --- GEN Z PALETTE (The Aesthetic) ---
R='\033[0;31m'         # Red
G='\033[0;32m'         # Green
Y='\033[1;33m'         # Yellow
B='\033[0;34m'         # Blue
P='\033[38;5;201m'     # Neon Pink
L='\033[38;5;154m'     # Lime Green
C='\033[0;36m'         # Cyan
O='\033[38;5;208m'     # Orange
NC='\033[0m'           # No Color

# Social Flex Messages
FLEX_MESSAGES=(
    "Hunting P1s like it's a hobby. 💅"
    "Scanning the planet, one packet at a time. 🌍"
    "Cyberpunk vibes only. 👾"
    "Enumeration is an art form. 🎨"
    "No Target is Safe. 🛡️💀"
    "Turning coffee into RCEs. ☕➡️💥"
    "Your firewall is just a suggestion. 🚧"
    "Making Recon look good since 2025. ✨"
)

# Animation Elements
SPINNER=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")

# --- UI FUNCTIONS ---
get_flex() {
    echo "${FLEX_MESSAGES[$RANDOM % ${#FLEX_MESSAGES[@]}]}"
}

# The Visual Heartbeat
run_with_spinner() {
    local msg="$1"
    shift
    local cmd="$@"
    
    eval "$cmd" &
    local pid=$!
    tput civis
    
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r${P}${SPINNER[i]} ${C}%s...${NC}" "$msg"
        i=$(( (i+1) % ${#SPINNER[@]} ))
        sleep 0.1
    done
    
    wait $pid
    local exit_code=$?
    tput cnorm
    
    if [ $exit_code -eq 0 ]; then
        printf "\r${L}✔ ${C}%s ${L}Done.${NC}                        \n" "$msg"
    else
        printf "\r${R}✘ ${C}%s ${R}Failed (or empty).${NC}              \n" "$msg"
    fi
    return $exit_code
}

print_count() {
    local label="$1"
    local file="$2"
    if [ -f "$file" ]; then
        local cnt=$(wc -l < "$file")
        echo -e "   ${O}└─> ${B}$label: ${L}$cnt${NC}"
    else
        echo -e "   ${O}└─> ${B}$label: ${R}0${NC}"
    fi
}

banner() {
    clear
    echo -e "${P}"
    cat << "EOF"
██╗     ███████╗███████╗████████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██║     ██╔════╝██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║   ██║████╗ ████║
██║     █████╗  █████╗     ██║   █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║     ██╔══╝  ██╔══╝     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
███████╗███████╗███████╗   ██║   ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚══════╝╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${L}>>> ${C}LeetSec Recon Engine v1.0 ${L}<<<${NC}"
    echo -e "${O}🔥 $(get_flex) 🔥${NC}\n"
}

phase_header() {
    local title="$1"
    local desc="$2"
    echo ""
    echo -e "${P}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${NC} ${L}PHASE: $title${NC} ${P}$(printf '%*s' $((65-${#title})) | tr ' ' '║')${NC}"
    if [ -n "$desc" ]; then
        echo -e "${P}║${NC} $desc $(printf '%*s' $((67-${#desc})) | tr ' ' '║')${NC}"
    fi
    echo -e "${P}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_completion() {
    local target="$1"
    local subs="$2"
    local vulns="$3"
    local saved="$4"
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    H=$((DURATION / 3600))
    M=$(( (DURATION % 3600) / 60 ))
    S=$((DURATION % 60))
    
    echo ""
    echo -e "${P}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${NC} ${L}🎯 LEETENUM MISSION COMPLETE 🎯${NC} ${P}                                       ║${NC}"
    echo -e "${P}║${NC} ${C}Target: $target${NC} ${P}                                                      ║${NC}"
    echo -e "${P}║${NC} ${O}Time:   ${H}h ${M}m ${S}s${NC} ${P}                                                   ║${NC}"
    echo -e "${P}║${NC} ${L}Subs:   $subs | Vulns: $vulns${NC} ${P}                                           ║${NC}"
    echo -e "${P}║${NC} ${Y}📸 $(get_flex) 📸${NC} ${P}                                                  ║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${B}Output: $saved${NC}"
    echo ""
}

die() { echo -e "${R}💀 [FATAL] $1${NC}"; exit 1; }
warn() { echo -e "${Y}⚠️  [WARN] $1${NC}"; }
info() { echo -e "${C}ℹ️  [INFO] $1${NC}"; }
good() { echo -e "${L}✅ [GUCCI] $1${NC}"; }

# Cleanup
cleanup() {
    tput cnorm
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

# --- SELF UPDATER ---
update_tool() {
    info "Checking for LeetEnum updates..."
    if ! ping -c 1 8.8.8.8 &>/dev/null; then die "No internet connection."; fi
    if curl -sL "$UPDATE_URL" -o "${SCRIPT_PATH}.new"; then
        if grep -q "LeetEnum" "${SCRIPT_PATH}.new"; then
            cp "$SCRIPT_PATH" "${SCRIPT_PATH}.bak"
            mv "${SCRIPT_PATH}.new" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            good "Update successful! Restarting..."
            exit 0
        else
            rm "${SCRIPT_PATH}.new" 2>/dev/null
            die "Update failed. Invalid file received."
        fi
    else
        die "Failed to download update."
    fi
}

# --- DEPENDENCY MANAGER ---
detect_pkg_mgr() {
    if command -v apt-get &>/dev/null; then PKG_MGR="apt-get"; INSTALL_CMD="sudo apt-get install -y"; UPDATE_CMD="sudo apt-get update"
    elif command -v pacman &>/dev/null; then PKG_MGR="pacman"; INSTALL_CMD="sudo pacman -Sy --noconfirm"; UPDATE_CMD="sudo pacman -Sy"
    elif command -v dnf &>/dev/null; then PKG_MGR="dnf"; INSTALL_CMD="sudo dnf install -y"; UPDATE_CMD="sudo dnf check-update"
    elif command -v apk &>/dev/null; then PKG_MGR="apk"; INSTALL_CMD="sudo apk add --no-cache"; UPDATE_CMD="sudo apk update"
    else die "Unknown package manager."; fi
}

check_gear() {
    if [ ! -w "$(pwd)" ]; then die "Cannot write to current directory."; fi
    mkdir -p "$CONF_DIR"
    if ! ping -c 1 8.8.8.8 &>/dev/null; then warn "Network unreachable."; fi

    detect_pkg_mgr

    if ! command -v go &>/dev/null; then
        run_with_spinner "Installing Golang" "$INSTALL_CMD golang-go || $INSTALL_CMD go"
        ! command -v go &>/dev/null && die "Go install failed."
    fi
    go env -w GO111MODULE=on 2>/dev/null

    NEEDS_UPDATE=false
    for t in massdns jq pv tmux git; do
        if ! command -v $t &>/dev/null; then NEEDS_UPDATE=true; break; fi
    done
    if ! command -v chromium &>/dev/null && ! command -v chromium-browser &>/dev/null && ! command -v google-chrome &>/dev/null; then NEEDS_UPDATE=true; fi

    if [ "$NEEDS_UPDATE" = true ]; then
        run_with_spinner "Updating system packages" "$UPDATE_CMD >/dev/null 2>&1"
        [ "$PKG_MGR" == "apt-get" ] && sudo apt-get install -y libpcap-dev build-essential >/dev/null 2>&1
    fi

    install_sys() {
        bin=$1; pkg=$2
        if ! command -v $bin &>/dev/null; then run_with_spinner "Installing $bin" "$INSTALL_CMD $pkg >/dev/null 2>&1"; fi
    }
    install_sys "massdns" "massdns"; install_sys "jq" "jq"; install_sys "pv" "pv"; install_sys "tmux" "tmux"; install_sys "git" "git"

    if ! command -v massdns &>/dev/null; then
        warn "Building MassDNS from source..."
        git clone https://github.com/blechschmidt/massdns.git /tmp/massdns >/dev/null 2>&1
        cd /tmp/massdns && make >/dev/null 2>&1 && sudo make install >/dev/null 2>&1
        cd - >/dev/null
    fi
    
    if ! command -v chromium &>/dev/null && ! command -v chromium-browser &>/dev/null && ! command -v google-chrome &>/dev/null; then
        if [ "$PKG_MGR" == "pacman" ]; then $INSTALL_CMD chromium; else $INSTALL_CMD chromium-browser || $INSTALL_CMD chromium; fi
    fi
    
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
            run_with_spinner "Installing $tool" "go install -v '${tools[$tool]}@latest' >/dev/null 2>&1"
            # Gotator Failsafe
            if [ "$tool" == "gotator" ] && ! command -v gotator &>/dev/null; then
                run_with_spinner "Legacy Gotator Install" "GOSUMDB=off GO111MODULE=off go get -u github.com/josderstad/gotator >/dev/null 2>&1"
                if ! command -v gotator &>/dev/null; then
                    ( rm -rf /tmp/gotator; git clone -q https://github.com/josderstad/gotator /tmp/gotator >/dev/null 2>&1; cd /tmp/gotator && GOSUMDB=off go build -o $HOME/go/bin/gotator main.go >/dev/null 2>&1 )
                fi
            fi
        fi
    done
    
    if [ ! -f "$CONF_DIR/.nuc_chk" ] || [ $(find "$CONF_DIR/.nuc_chk" -mtime +1) ]; then
        if command -v nuclei &>/dev/null; then
            run_with_spinner "Syncing Nuclei Templates" "nuclei -update-templates -silent >/dev/null 2>&1"
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
        if command -v gum &>/dev/null; then
            if gum confirm "Configure Alerts?"; then
                SVC=$(gum choose "Discord" "Slack" "Telegram")
                echo "NOTIFY_SERVICE=\"$SVC\"" >> "$CONF_FILE"
                case $SVC in
                    Discord)  VAL=$(gum input --placeholder "Webhook" --password); echo "DISCORD_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                    Slack)    VAL=$(gum input --placeholder "Webhook" --password); echo "SLACK_WEBHOOK=\"$VAL\"" >> "$CONF_FILE" ;;
                    Telegram) TOK=$(gum input --placeholder "Token" --password); ID=$(gum input --placeholder "ChatID"); echo "TELEGRAM_TOKEN=\"$TOK\"" >> "$CONF_FILE"; echo "TELEGRAM_CHATID=\"$ID\"" >> "$CONF_FILE" ;;
                esac
                notify "🔔 LeetEnum Configured."
            else echo "NOTIFY_SERVICE=\"None\"" >> "$CONF_FILE"; fi
        else echo "NOTIFY_SERVICE=\"None\"" >> "$CONF_FILE"; fi
    fi
}

setup_cron() {
    TGT=$1
    if [ -z "$(crontab -l 2>/dev/null | grep "$SCRIPT_PATH" | grep "$TGT")" ]; then
        if command -v gum &>/dev/null; then
            if gum confirm "Add to Auto-Scheduler?"; then
                D=$(gum input --placeholder "Days (e.g. 7)")
                if [[ "$D" =~ ^[0-9]+$ ]]; then
                    (crontab -l 2>/dev/null; echo "0 0 */$D * * $SCRIPT_PATH -d $TGT -m -no-tmux >> ${HOME}/leetsec_cron.log 2>&1") | crontab -
                    notify "📅 $TGT monitored every $D days."
                fi
            fi
        fi
    fi
}

# --- CLI ---
RESET=false; TARGET=""; MONITOR=false; NO_TMUX=false; DEEP_SCAN=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) TARGET="$2"; shift ;;
        -m|--monitor) MONITOR=true ;;
        --reset) RESET=true ;;
        --deep) DEEP_SCAN=true ;;
        -no-tmux) NO_TMUX=true ;;
        -up|-update) update_tool ;;
        *) die "Usage: $0 -d target.com [-m] [--deep] [-update]" ;;
    esac
    shift
done

check_gear
init_conf

if [ -z "$TARGET" ]; then
    banner
    if command -v gum &>/dev/null; then
        TARGET=$(gum input --placeholder "Target Domain")
        if gum confirm "Enable Deep Port Scan (Slow)?"; then DEEP_SCAN=true; fi
        if gum confirm "Differential Mode (Monitor)?"; then MONITOR=true; fi
    else read -p "Target Domain: " TARGET; fi
fi

[ -z "$TARGET" ] && die "Target required."
TARGET=$(echo "$TARGET" | sed 's~http[s]*://~~g' | tr -d '/')

if [ -t 0 ] && [ "$NO_TMUX" = false ]; then
    setup_cron "$TARGET"
    SESS="leet_${TARGET//./_}"
    if [ -z "$TMUX" ]; then
        if tmux has-session -t "$SESS" 2>/dev/null; then
            if command -v gum &>/dev/null; then gum confirm "Resume active session?" && tmux attach -t "$SESS" && exit 0; else tmux attach -t "$SESS" && exit 0; fi
        else
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

TS=$(date +%Y%m%d_%H%M)
BASE_DIR="$(pwd)/recon_${TARGET}"
LAST_MASTER=""
[ -L "${BASE_DIR}/latest" ] && LAST_MASTER=$(readlink -f "${BASE_DIR}/latest/master_dns.txt")

if [ "$MONITOR" = true ]; then FINAL_DIR="${BASE_DIR}/${TS}"; info "Mode: MONITOR"; else
    LAST_SCAN=$(ls -dt "$BASE_DIR"/*/ 2>/dev/null | head -1)
    if [ -n "$LAST_SCAN" ]; then FINAL_DIR=${LAST_SCAN%/}; info "Resuming session."; else FINAL_DIR="${BASE_DIR}/${TS}"; fi
fi

WORK_DIR="/dev/shm/recon_${TARGET}_${TS}"
RPT_DIR="${FINAL_DIR}/reports"
LOCK_DIR="${FINAL_DIR}/.locks"
mkdir -p "$WORK_DIR" "$FINAL_DIR" "$RPT_DIR" "$LOCK_DIR"

RAM=$(free -g | grep Mem: | awk '{print $2}')
CORES=$(nproc)
if [ "$RAM" -ge 60 ]; then PROF="LEET"; HTTPX=450; PUREDNS=500; NAABU=5000; LIMIT=50000; PARALLEL=50; SORT="-S 25G --parallel=${CORES}"
elif [ "$RAM" -ge 16 ]; then PROF="PRO"; HTTPX=200; PUREDNS=200; NAABU=2500; LIMIT=20000; PARALLEL=15; SORT="-S 50% --parallel=${CORES}"
else PROF="LITE"; HTTPX=80; PUREDNS=100; NAABU=1000; LIMIT=5000; PARALLEL=5; SORT="-S 50%"; fi
JOB_LIMIT=$((LIMIT / PARALLEL))

WL_BRUTE=~/brute_wordlist.txt
WL_PERM=~/perm_words.txt
WL_RES="${WORK_DIR}/resolvers.txt"
[ ! -s "$WL_BRUTE" ] && wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O "$WL_BRUTE"
[ ! -s "$WL_PERM" ] && wget -q https://raw.githubusercontent.com/m4ll0k/BBTz/master/perm_words.txt -O "$HOME/perm_words.txt"
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O "$WL_RES"

notify "🚀 LeetEnum: $TARGET [$PROF]"

# 1. PASSIVE
if [ ! -f "$LOCK_DIR/p1" ]; then
    phase_header "1" "Passive Intel"
    AMASS_CMD="amass enum -passive -d '$TARGET' -o '$WORK_DIR/amass.txt'"
    [ -f "$HOME/.config/amass/config.ini" ] && AMASS_CMD="$AMASS_CMD -config $HOME/.config/amass/config.ini"
    
    run_with_spinner "Running Amass" "timeout 15m $AMASS_CMD >/dev/null 2>&1 || true"
    run_with_spinner "Running Subfinder" "subfinder -d '$TARGET' -all -silent > '$WORK_DIR/subfinder.txt'"
    run_with_spinner "Running Assetfinder" "assetfinder --subs-only '$TARGET' > '$WORK_DIR/asset.txt'"
    run_with_spinner "Mining CRT.SH" "curl -s 'https://crt.sh/?q=%25.$TARGET&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > '$WORK_DIR/crt.txt'"
    run_with_spinner "Mining Wayback" "curl -s 'http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey' | awk -F/ '{print \$3}' | sort -u > '$WORK_DIR/wayback.txt'"
    
    cat "$WORK_DIR"/*.txt 2>/dev/null | sort $SORT -u | grep -F ".$TARGET" > "$WORK_DIR/passive_raw.txt"
    if [ -s "$WORK_DIR/passive_raw.txt" ]; then
        run_with_spinner "Resolving Passive" "puredns resolve '$WORK_DIR/passive_raw.txt' -r '$WL_RES' -w '$WORK_DIR/passive_valid.txt' --rate-limit '$LIMIT' >/dev/null 2>&1"
    fi
    cp "$WORK_DIR/passive_valid.txt" "$FINAL_DIR/passive.txt" 2>/dev/null
    print_count "Passive Found" "$WORK_DIR/passive_valid.txt"
    touch "$LOCK_DIR/p1"
else
    cp "$FINAL_DIR/passive.txt" "$WORK_DIR/passive_valid.txt" 2>/dev/null
fi

# 2. BRUTE
if [ ! -f "$LOCK_DIR/p2" ]; then
    phase_header "2" "Active Brute Force"
    run_with_spinner "Brute Forcing" "puredns bruteforce '$WL_BRUTE' '$TARGET' -r '$WL_RES' -w '$WORK_DIR/brute.txt' --rate-limit '$LIMIT' >/dev/null 2>&1"
    cp "$WORK_DIR/brute.txt" "$FINAL_DIR/brute.txt" 2>/dev/null
    print_count "Brute Force Found" "$WORK_DIR/brute.txt"
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
        phase_header "3" "Deep Scanning ($CNT targets)"
        do_rec() {
            s=$1; w=$2; r=$3; o=$4; l=$5; h=$(echo "$s"|md5sum|cut -d' ' -f1)
            puredns bruteforce "$w" "$s" -r "$r" -w "$o/r_$h.txt" --rate-limit "$l" >/dev/null 2>&1
        }
        export -f do_rec
        if [ -t 0 ] && command -v pv >/dev/null; then
            cat "$WORK_DIR/rec_targets.txt" | pv -l -s "$CNT" -N "Recursion" | xargs -P "$PARALLEL" -I {} bash -c "do_rec '{}' '$WORK_DIR/rec_wl.txt' '$WL_RES' '$WORK_DIR' '$JOB_LIMIT'"
        else
            cat "$WORK_DIR/rec_targets.txt" | xargs -P "$PARALLEL" -I {} bash -c "do_rec '{}' '$WORK_DIR/rec_wl.txt' '$WL_RES' '$WORK_DIR' '$JOB_LIMIT'"
        fi
        cat "$WORK_DIR"/r_*.txt >> "$WORK_DIR/recursive.txt" 2>/dev/null
        rm "$WORK_DIR"/r_*.txt 2>/dev/null
    fi
    cp "$WORK_DIR/recursive.txt" "$FINAL_DIR/recursive.txt" 2>/dev/null
    print_count "Recursive Found" "$WORK_DIR/recursive.txt"
    touch "$LOCK_DIR/p3"
else
    cp "$FINAL_DIR/recursive.txt" "$WORK_DIR/recursive.txt" 2>/dev/null
fi

# 4. PERMS
if [ ! -f "$LOCK_DIR/p4" ]; then
    phase_header "4" "Permutations"
    cat "$WORK_DIR/known.txt" "$WORK_DIR/recursive.txt" 2>/dev/null | sort $SORT -u > "$WORK_DIR/seeds.txt"
    S_CNT=$(wc -l < "$WORK_DIR/seeds.txt")
    if [ "$S_CNT" -gt 0 ]; then
        [ "$S_CNT" -gt 50000 ] && head -n 50000 "$WORK_DIR/seeds.txt" > "$WORK_DIR/gotator_seeds.txt" || cp "$WORK_DIR/seeds.txt" "$WORK_DIR/gotator_seeds.txt"
        if command -v gotator >/dev/null; then
             run_with_spinner "Generating Perms" "timeout 60m gotator -sub '$WORK_DIR/gotator_seeds.txt' -perm '$WL_PERM' -depth 1 -silent > '$WORK_DIR/perms_raw.txt' 2>/dev/null"
             if [ -s "$WORK_DIR/perms_raw.txt" ]; then
                 run_with_spinner "Resolving Perms" "puredns resolve '$WORK_DIR/perms_raw.txt' -r '$WL_RES' -w '$WORK_DIR/perms_valid.txt' --rate-limit '$LIMIT' >/dev/null 2>&1"
             fi
        fi
    fi
    cp "$WORK_DIR/perms_valid.txt" "$FINAL_DIR/perms.txt" 2>/dev/null
    print_count "Permutations Found" "$WORK_DIR/perms_valid.txt"
    touch "$LOCK_DIR/p4"
else
    cp "$FINAL_DIR/perms.txt" "$WORK_DIR/perms_valid.txt" 2>/dev/null
fi

# MERGE
cat "$WORK_DIR/seeds.txt" "$WORK_DIR/perms_valid.txt" 2>/dev/null | sort $SORT -u | grep "$TARGET" > "$WORK_DIR/master.txt"
cp "$WORK_DIR/master.txt" "$FINAL_DIR/master_dns.txt" 2>/dev/null

# 5. TAKEOVER (DNS Level)
info "Phase 5: Subdomain Takeover Check (DNS)"
if command -v nuclei >/dev/null; then
    run_with_spinner "Checking Takeovers" "nuclei -l '$WORK_DIR/master.txt' -tags takeover -o '$RPT_DIR/dns_takeovers.txt' -silent | tee -a '$RPT_DIR/nuclei.txt'"
fi

NEW_CNT=0
if [ "$MONITOR" = true ] && [ -f "$LAST_MASTER" ]; then
    sort $SORT -u "$LAST_MASTER" > "$WORK_DIR/old.txt"
    sort $SORT -u "$WORK_DIR/master.txt" > "$WORK_DIR/new.txt"
    comm -13 "$WORK_DIR/old.txt" "$WORK_DIR/new.txt" > "$FINAL_DIR/new_subs.txt"
    NEW_CNT=$(wc -l < "$FINAL_DIR/new_subs.txt")
    [ "$NEW_CNT" -gt 0 ] && notify "🚨 MONITOR: Found $NEW_CNT NEW subdomains!"
fi

# 6. PORTS
phase_header "6" "Omni-Port & HTTP"
if [ -s "$WORK_DIR/master.txt" ]; then
    if [ "$DEEP_SCAN" = true ]; then PORTS="-p 1-10000"; warn "DEEP SCAN enabled."; else PORTS="-top-ports 1000"; fi
    
    # ADDED: -exclude-cdn logic for speed
    run_with_spinner "Port Scanning" "naabu -l '$WORK_DIR/master.txt' -rate '$NAABU' $PORTS -exclude-cdn -silent -o '$WORK_DIR/ports.txt' >/dev/null 2>&1"
    [ -s "$WORK_DIR/ports.txt" ] && T_LIST="$WORK_DIR/ports.txt" || T_LIST="$WORK_DIR/master.txt"
    
    run_with_spinner "HTTP Probing" "httpx -l '$T_LIST' -threads '$HTTPX' -random-agent -retries 2 -timeout 10 -sc -title -tech-detect -ip -cname -server -o '$FINAL_DIR/http_full.txt' -silent > /dev/null 2>&1"
    awk '{print $1}' "$FINAL_DIR/http_full.txt" | sort $SORT -u > "$WORK_DIR/live.txt"
    grep "\[200\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/200.txt"
    grep "\[403\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/403.txt"
    grep "\[404\]" "$FINAL_DIR/http_full.txt" > "$FINAL_DIR/404.txt"
    cp "$WORK_DIR/live.txt" "$FINAL_DIR/live_urls.txt"
    print_count "Live Websites" "$WORK_DIR/live.txt"
fi

# 7. VISUALS
phase_header "7" "Visuals (Screenshots)"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v gowitness &>/dev/null; then
        mkdir -p "$FINAL_DIR/screenshots"
        run_with_spinner "Taking Screenshots" "gowitness scan file -f '$WORK_DIR/live.txt' -s '$FINAL_DIR/screenshots/' --threads 10 --no-http --chrome-arg='--no-sandbox' --chrome-arg='--disable-gpu' > '$RPT_DIR/gowitness.log' 2>&1"
    fi
fi

# 8. VULNS
phase_header "8" "Deep Vulnerability Scan"
if [ -s "$WORK_DIR/live.txt" ]; then
    if command -v katana &>/dev/null; then
        run_with_spinner "Spidering JS" "katana -list '$WORK_DIR/live.txt' -jc -kf -c 20 -d 2 -silent 2>/dev/null | grep '$TARGET' | sort $SORT -u > '$WORK_DIR/spider.txt'"
        if [ -s "$WORK_DIR/spider.txt" ]; then
             puredns resolve "$WORK_DIR/spider.txt" -r "$WL_RES" -w "$WORK_DIR/spider_val.txt" --rate-limit "$LIMIT" >/dev/null 2>&1
             cat "$WORK_DIR/spider_val.txt" >> "$FINAL_DIR/master_dns.txt"
        fi
    fi
    
    if command -v nuclei &>/dev/null; then
        echo -e "${C}    -> Running Nuclei (Streaming criticals)...${NC}"
        # Added 'cve' and 'misconfig' for MSRC compliance
        nuclei -l "$WORK_DIR/live.txt" \
            -tags takeover,exposure,config,keys,cloud,cve,misconfig \
            -severity low,medium,high,critical \
            -timeout 10 -retries 2 \
            -silent | tee -a "$RPT_DIR/nuclei.txt" | grep --line-buffered -iE "medium|high|critical"
    fi
fi

# RAM CLEANUP
echo -e "${Y}[*] Cleaning RAM...${NC}"
rm -rf "$WORK_DIR/amass.txt" "$WORK_DIR/crt.txt" "$WORK_DIR/wayback.txt" "$WORK_DIR/subfinder.txt"

# --- REPORT ---
rm -rf "${BASE_DIR}/latest"; ln -s "${FINAL_DIR}" "${BASE_DIR}/latest"
DNS=$(wc -l < "$FINAL_DIR/master_dns.txt")
VULN=$(wc -l < "$RPT_DIR/nuclei.txt")
LIVE=$(wc -l < "$WORK_DIR/live.txt")

show_completion "$TARGET" "$DNS" "$VULN" "$FINAL_DIR"
notify "✅ LeetEnum: $TARGET | Subs: $DNS | Vulns: $VULN"