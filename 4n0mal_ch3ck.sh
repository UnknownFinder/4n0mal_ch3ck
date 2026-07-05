#!/bin/bash
# exec 2> /dev/null
set -euo pipefail
#==================== Initialization of variables ====================
readonly LOG_FILE="/var/log/listen_watch.log"
readonly STATE_DIR="/var/lib/listen_watch"
readonly STATE_FILE="$STATE_DIR/ports.txt"
readonly MAX_CRON_TIME=1800
readonly max_cpu=80
readonly max_ram=80
readonly ex_cpu=95
readonly ex_mem=95
RED='\033[31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
mkdir -p "$STATE_DIR"
# ==================== Requirements ====================
required_tools=("top", "ps", "grep", "lsof", "ss", "netstat", "debsecan", "ip", "route")
# ==================== Initialization of functions ====================
rtcheck() {
    if [ "$(id -u)" != "0" ]; then
        echo "NEED ROOT LOGIN! ERROR 0x28000" >&2
        exit 1
    fi
}
display() {
    clear
    if [ -f "eye.txt" ]; then
        cat eye.txt
    else
        echo "Eye file not found, skipping."
    fi
    sleep 5
    clear
}
show_instruction() {
    echo "[z] - check up for zombie processes"
    echo "[c] - check up for anomalies in cron tasks"
    echo "[p] - check up for strange/unusual processes"
    echo "[n] - check up for network anomalies"
    echo "[s] - check up for strange ssh events"
    echo "[u] - check up for critical updates"
    echo "[r] - check up for no-root commands"
    echo "[h] - help"
}
zmbkiller() {
    echo "=== Checking for zombie processes ==="
    zombies=$(ps aux | awk '$8 ~ /^[Zz]/ {print $2}')
    if [ -n "$zombies" ]; then
        echo "Zombie processes found: $zombies"
        for zombie in $zombies; do
            parent_pid=$(ps -o ppid= -p "$zombie" 2>/dev/null | tr -d ' ')
            if [ -n "$parent_pid" ] && [ "$parent_pid" -ne 1 ]; then
                echo "Killing parent process $parent_pid of zombie $zombie"
                kill -9 "$parent_pid" 2>/dev/null
            else
                echo "Cannot kill zombie $zombie (parent is init or not found)"
            fi
        done
    else
        echo "No zombie processes found."
    fi
}
chkcron() {
    echo "=== Checking up for frozen cron tasks ==="
    found=0
    while read -r pid ppid etime cmd; do
        total=0
        if [[ "$ppid" -eq 1 ]] && echo "$cmd" | grep -q cron; then
            continue
        fi
        if echo "$cmd" | grep -q '/etc/cron\|CRON'; then
            # Transform etime to readable format
            if [[ "$etime" =~ ^([0-9]+)-([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
                days="${BASH_REMATCH[1]}"
                hours="${BASH_REMATCH[2]}"
                mins="${BASH_REMATCH[3]}"
                secs="${BASH_REMATCH[4]}"
                total=$((days*86400 + hours*3600 + mins*60 + secs))
            elif [[ "$etime" =~ ^([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
                hours="${BASH_REMATCH[1]}"
                mins="${BASH_REMATCH[2]}"
                secs="${BASH_REMATCH[3]}"
                total=$((hours*3600 + mins*60 + secs))
            elif [[ "$etime" =~ ^([0-9]+):([0-9]{2})$ ]]; then
                mins="${BASH_REMATCH[1]}"
                secs="${BASH_REMATCH[2]}"
                total=$((mins*60 + secs))
            elif [[ "$etime" =~ ^([0-9]+)$ ]]; then
                total="${BASH_REMATCH[1]}"
            fi
            if (( total > MAX_CRON_TIME )); then
                echo "Зависшая задача: PID=$pid, работает уже ${total}s"
                found=1
            fi
        fi
    done < <(ps -eo pid,ppid,etime,args --no-headers 2>/dev/null)

    if [ $found -eq 0 ]; then
        echo "No frozen cron tasks found."
    fi

    echo "=== Checking up for anomalous/unusual crontasks (perhaps rootkits) ==="
    for user in $(cut -f1 -d: /etc/passwd); do
        echo "••• $user •••"
        crontab -u "$user" -l 2>/dev/null | grep -E 'bash.*curl|bash.*wget' || true
    done
}
nmpproc() {
    echo "=== Searching anomaly processes ==="
    sleep 2
    echo "Comparing /proc and ps outputs"
    ps_pids=$(ps -e -o pid= | sort -n)
    proc_pids=$(ls /proc/ | grep -E '^[0-9]+$' | sort -n)
    hidden_pids=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
    if [ -n "$hidden_pids" ]; then
        echo "Strange hidden PIDS:"
        for pid in $hidden_pids; do
            if [ -d "/proc/$pid" ]; then
                ls -l "/proc/$pid/exe" 2>/dev/null || true
                cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true
                echo
            fi
        done
    fi

    echo "Processes of temporary directories:"
    ps axeo pid,comm,args | grep -E '/(tmp|dev|run)/' | grep -v grep || true

    echo "Unnamed processes:"
    ps axeo pid,comm | awk '$2 == "[]" || $2 == ""' || true

    echo "Non-typical incoming connections:"
    if command -v lsof >/dev/null; then
        lsof -i -nP | grep LISTEN | grep -Ev ':(22|80|443)' | grep -v "COMMAND" || true
    else
        echo "lsof not installed, skipping."
    fi

    echo "=== Checking for high resource usage ==="
    high_cpu_proc=$(ps -eo pid,pcpu,comm --no-headers | awk -v tresh="$max_cpu" '$2+0 >= tresh {print $1}')
    high_ram_proc=$(ps -eo pid,pmem,comm --no-headers | awk -v tresh="$max_ram" '$2+0 >= tresh {print $1}')

    if [ -n "$high_cpu_proc" ] || [ -n "$high_ram_proc" ]; then
        echo "Warning! Overloading is detected."
        all_procs=$(echo "$high_cpu_proc $high_ram_proc" | tr ' ' '\n' | sort -u)
        for pid in $all_procs; do
            if ps -p "$pid" >/dev/null 2>&1; then
                if [ "$pid" -eq 1 ] || [ "$pid" -eq 2 ] || [ "$pid" -eq $$ ]; then
                    echo "Skipping system/self process $pid"
                    continue
                fi
                echo "Changing priority for process $pid"
                renice 15 -p "$pid" 2>/dev/null || echo "Failed to renice process $pid"
            fi
        done
    else
        echo "Overloading is not detected."
    fi

    echo "=== Checking for extreme resource usage ==="
    ex_cpu_proc=$(ps -eo pid,pcpu,comm --no-headers | awk -v tresh="$ex_cpu" '$2+0 >= tresh {print $1}')
    ex_mem_proc=$(ps -eo pid,pmem,comm --no-headers | awk -v tresh="$ex_mem" '$2+0 >= tresh {print $1}')

    if [ -n "$ex_cpu_proc" ] || [ -n "$ex_mem_proc" ]; then
        echo "Warning! Extremely high load!"
        all_ex_procs=$(echo "$ex_cpu_proc $ex_mem_proc" | tr ' ' '\n' | sort -u)
        for pid in $all_ex_procs; do
            if ps -p "$pid" >/dev/null 2>&1; then
                if [ "$pid" -eq 1 ] || [ "$pid" -eq 2 ] || [ "$pid" -eq $$ ]; then
                    echo "Skipping system/self process $pid"
                    continue
                fi
                echo "Terminating process $pid"
                kill -15 "$pid" 2>/dev/null
                sleep 2
                if ps -p "$pid" >/dev/null 2>&1; then
                    echo "Force killing process $pid"
                    kill -9 "$pid" 2>/dev/null
                fi
            fi
        done
    else
        echo "No extreme load detected."
    fi
}
ntwcheck() {
    echo "=== Checking up listening ports ===" | tee -a "$LOG_FILE"
    CURR=$(mktemp)
    ss -tulpn 2>/dev/null | awk 'NR>1 {print $1, $5}' | sort -u > "$CURR"
    if [ ! -f "$STATE_FILE" ]; then
        cp "$CURR" "$STATE_FILE"
        echo "Base of listening ports is created." | tee -a "$LOG_FILE"
        rm -f "$CURR"
        return 0
    fi

    ADDED=$(comm -13 "$STATE_FILE" "$CURR" 2>/dev/null || true)
    REMOVED=$(comm -23 "$STATE_FILE" "$CURR" 2>/dev/null || true)

    [ -n "$ADDED" ] && echo "New ports: " | tee -a "$LOG_FILE" && echo "$ADDED" | tee -a "$LOG_FILE"
    [ -n "$REMOVED" ] && echo "Closed ports:" | tee -a "$LOG_FILE" && echo "$REMOVED" | tee -a "$LOG_FILE"
    [ -z "${ADDED}${REMOVED}" ] && echo "Nothing changed." | tee -a "$LOG_FILE"

    cp "$CURR" "$STATE_FILE"
    rm -f "$CURR"
}

sshcheck() {
    echo "=== Checking up for strange things with SSH ==="
    sleep 1

    local ALARM_LOG="/var/log/alarm_$(date +%Y%m%d_%H%M%S).log"
    {
        date
        timedatectl 2>/dev/null || echo "timedatectl not available"
        echo "--- w ---"
        w
        echo "--- who ---"
        who
        echo "--- ps auxww ---"
        ps auxww
        echo "--- netstat -tulpn ---"
        if command -v netstat >/dev/null; then netstat -tulpn 2>/dev/null; else echo "netstat not installed"; fi
        echo "--- ss -tulpn ---"
        if command -v ss >/dev/null; then ss -tulpn 2>/dev/null; else echo "ss not installed"; fi
        echo "--- netstat -an | grep ESTABLISHED ---"
        if command -v netstat >/dev/null; then netstat -an 2>/dev/null | grep ESTABLISHED || true; fi
        echo "--- /etc/passwd ---"
        cat /etc/passwd
        echo "--- lastlog ---"
        lastlog
        echo "--- last -f /var/log/wtmp ---"
        last -f /var/log/wtmp 2>/dev/null || true
        echo "--- last -f /var/log/btmp ---"
        last -f /var/log/btmp 2>/dev/null || true
        echo "--- crontab -l (root) ---"
        crontab -l 2>/dev/null || true
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "--- crontab for $user ---"
            crontab -u "$user" -l 2>/dev/null || true
        done
        echo "--- find /bin /sbin -type f -mtime -1 ---"
        find /bin /sbin -type f -mtime -1 2>/dev/null || true
        echo "--- find authorized_keys ---"
        find /root /home -name "authorized_keys" 2>/dev/null || true
        echo "--- /root/.bash_history ---"
        cat /root/.bash_history 2>/dev/null || true
        echo "--- tail -100 /var/log/auth.log ---"
        tail -100 /var/log/auth.log 2>/dev/null || true
        echo "--- journalctl --lines=50 ---"
        journalctl -xe --lines=50 2>/dev/null || true
        echo "--- route -n ---"
        if command -v route >/dev/null; then route -n 2>/dev/null; else echo "route not installed"; fi
        echo "--- ip route show ---"
        if command -v ip >/dev/null; then ip route show 2>/dev/null; else echo "ip not installed"; fi
        echo "--- ip neigh ---"
        if command -v ip >/dev/null; then ip neigh 2>/dev/null; else echo "ip not installed"; fi
        echo "--- lsof -i -P -n | grep LISTEN ---"
        if command -v lsof >/dev/null; then lsof -i -P -n 2>/dev/null | grep LISTEN || true; fi
        echo "--- lsof -i -P -n | grep ESTABLISHED ---"
        if command -v lsof >/dev/null; then lsof -i -P -n 2>/dev/null | grep ESTABLISHED || true; fi
    } > "$ALARM_LOG" 2>&1

    echo "SSH check log saved to $ALARM_LOG"
}

pkgcheck() {
    echo "=== Checking up for missed security updates ==="
    local LOG="/var/log/critical-updates.log"
    local THRESHOLD=7.0
    local critical_pkgs=""

    if ! command -v debsecan >/dev/null 2>&1; then
        echo "debsecan not installed, skipping critical updates check." | tee -a "$LOG"
        return 0
    fi

    updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing" | cut -d/ -f1 || true)
    for pkg in $updates; do
        cve_count=$(debsecan --suite "$(lsb_release -sc 2>/dev/null)" --only-fixed --package "$pkg" 2>/dev/null | \
                    grep -E "\([7-9]\.[0-9]|10\.0\)" | wc -l)
        if [ $cve_count -gt 0 ]; then
            critical_pkgs="${critical_pkgs}\n- $pkg (исправляет $cve_count критических CVE)"
        fi
    done

    if [ -n "$critical_pkgs" ]; then
        echo -e "Критические уведомления безопасности:\n$critical_pkgs"
        if command -v notify-send >/dev/null 2>&1; then
            echo -e "$critical_pkgs" | notify-send -u critical -t 0 "Обновления безопасности" "$(cat)"
        fi
        echo "$(date): Найдены критические обновления: $critical_pkgs" >> "$LOG"
    else
        echo "No critical updates found."
    fi
}

npswdcheck() {
    echo "=== Checking up for NOPASSWD-commands ==="
    sudo -l 2>/dev/null | grep NOPASSWD || echo "No NOPASSWD entries found."
}

# ==================== Main code ====================

run_zmbkiller=0
run_chkcron=0
run_nmpproc=0
run_ntwcheck=0
run_sshcheck=0
run_pkgcheck=0
run_npswdcheck=0
run_show_instruction=0
run_all=1

while getopts "zcpnsurh" opt; do
    case $opt in
        z) run_all=0; run_zmbkiller=1 ;;
        c) run_all=0; run_chkcron=1 ;;
        p) run_all=0; run_nmpproc=1 ;;
        n) run_all=0; run_ntwcheck=1 ;;
        s) run_all=0; run_sshcheck=1 ;;
        u) run_all=0; run_pkgcheck=1 ;;
        r) run_all=0; run_npswdcheck=1 ;;
        h) run_all=0; run_show_instruction=1 ;;
        \?) echo "Unknown option! Check the README file, mazafaka!" >&2; exit 1 ;;
    esac
done

if [ $run_all -eq 1 ]; then
    run_zmbkiller=1
    run_chkcron=1
    run_nmpproc=1
    run_ntwcheck=1
    run_sshcheck=1
    run_pkgcheck=1
fi

rtcheck
display
echo "=== System Monitor Script started at $(date) ==="

[ $run_zmbkiller -eq 1 ] && zmbkiller
[ $run_chkcron -eq 1 ] && chkcron
[ $run_nmpproc -eq 1 ] && nmpproc
[ $run_ntwcheck -eq 1 ] && ntwcheck
[ $run_sshcheck -eq 1 ] && sshcheck
[ $run_pkgcheck -eq 1 ] && pkgcheck
[ $run_npswdcheck -eq 1 ] && npswdcheck
[ $run_show_instruction -eq 1 ] && show_instruction

echo "=== System Monitor Script finished at $(date) ==="
