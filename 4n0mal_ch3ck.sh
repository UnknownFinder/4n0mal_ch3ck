#!/bin/bash
exec 2> /dev/null
set -euo pipefail
mkdir -p "$STATE_DIR"
readonly LOG_FILE="/var/log/listen_watch.log"
readonly STATE_DIR="/var/lib/listen_watch"
readonly STATE_FILE="$STATE_DIR/ports.txt"
RED='\033[31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0,'
readonly MAX_CRON_TIME=1800
readonly max_cpu=80
readonly max_rem=80
readonly ex_cpu=95
readonly ex_mem=95
#modules
rtchk(){
if [ "$(id -u)" != "0" ]; then
   echo "NEED ROOT LOGIN! ERROR 0x28000" >&2
   exit 1
fi
}
display(){
	cat eye.txt
}
zmbkiller(){
# Поиск и обработка Zombie-процессов
echo "=== Checking for zombie processes ==="
zombies=$(ps aux | awk '$8 ~ /^[Zz]/ {print $2}')
if [ -n "$zombies" ]; then
    echo "Zombie processes found: $zombies"
    for zombie in $zombies; do
        # Получаем родительский процесс
        parent_pid=$(ps -o ppid= -p $zombie 2>/dev/null | tr -d ' ')
        if [ -n "$parent_pid" ] && [ "$parent_pid" -ne 1 ]; then
            echo "Killing parent process $parent_pid of zombie $zombie"
            kill -9 $parent_pid 2>/dev/null
        else
            echo "Cannot kill zombie $zombie (parent is init or not found)"
        fi
    done
else
    echo "No zombie processes found."
fi
}
sleep 1
slpcron(){
echo "=== Checking up for frozen cron tasks ==="
# Максимальное время выполнения задачи (в секундах)
now=$(date +%s)
# Ищем процессы, которые запустил cron
ps -eo pid,ppid,etimes,args --no-headers 2>/dev/null | while read -r pid ppid etimes cmd; do
    # ppid == 1 и команды в /etc/cron* — частый кейс
    if [[ "$ppid" -eq 1 ]] && echo "$cmd" | grep -q cron; then
        continue
    fi
    # Задачи cron обычно запускаются как sh -c "..."
    if echo "$cmd" | grep -q '/etc/cron\|CRON'; then
        if (( "$etimes" > "$MAX_CRON_TIME" )); then
            echo "Зависшая задача: PID=$pid, работает уже ${etimes}s"
        fi
    fi
done
echo "No more tasks are frozen"
}
sleep 1
nmpproc(){
# Поиск аномальных процессов
echo "=== Searching anomaly processes ==="
sleep 2
# Сравнимаем вывод ps и содержимое /proc
echo "Comparing ss output and /proc content"
ps_pid=$(ps -e -o pid= | sort -n)
proc_pids=$(ls /proc/ | grep -E '^[0-9]+$' | sort -n)
hidden_pids=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
if [ -n "$hidden_pids" ]; then
	echo "Strange hidden PIDS:"
	for pid in $hidden_pids; do
		ls -l /proc/$pid/exe 2>/dev/null
		cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '
	done
fi
# Процессы, запущенные из /tmp, /dev, /run — подозрительно
echo "Processes of temporary directories:"
ps axeo pid,comm,args | grep -E '/(tmp|dev|run)/' | grep -v grep
# Процессы без имени (заглушки или rootkit-обфускация)
echo "Unnamed processes:"
ps axeo pid,comm | awk '$2 == "[]" || $2 == ""'
# Подозрительные net-соединения (в обход ssh, http, https)
echo "Non-tipical incoming connections:"
lsof -i -nP | grep LISTEN | grep -Ev ':(22|80|443)' | grep -v "COMMAND"
sleep 1
# Поиск процессов, превышающих установленные пороги
echo "=== Checking for high resource usage ==="

# Получаем список процессов с использованием top
top_output=$(top -bn1)
high_cpu_proc=$(echo "$top_output" | tail -n +7 | awk -v tresh="$max_cpu" '{if ($9+0 >= tresh) print $1}' | sort -u)
high_ram_proc=$(echo "$top_output" | tail -n +7 | awk -v tresh="$max_ram" '{if ($10+0 >= tresh) print $1}' | sort -u)

if [ -n "$high_cpu_proc" ] || [ -n "$high_ram_proc" ]; then
    echo "Warning! Overloading is detected."
    all_procs=$(echo "$high_cpu_proc $high_ram_proc" | tr ' ' '\n' | sort -u)
    for pid in $all_procs; do
        # Проверяем, существует ли процесс и не является ли он системным
        if [ ps -p $pid > /dev/null 2>&1 ]; then
            # Пропускаем важные системные процессы
            if [ $pid -eq 1 ] || [ $pid -eq 2 ] || [ $pid -eq $$ ]; then
                echo "Skipping system/self process $pid"
                continue
            fi
            echo "Changing priority for process $pid"
            renice 15 -p $pid 2>/dev/null || echo "Failed to renice process $pid"
        fi
    done
else
    echo "Overloading is not detected."
fi
# Обработка экстремальной нагрузки
echo "=== Checking for extreme resource usage ==="

ex_cpu_proc=$(echo "$top_output" | tail -n +7 | awk -v tresh="$ex_cpu" '{if ($9+0 >= tresh) print $1}' | sort -u)
ex_mem_proc=$(echo "$top_output" | tail -n +7 | awk -v tresh="$ex_mem" '{if ($10+0 >= tresh) print $1}' | sort -u)

if [ -n "$ex_cpu_proc" ] || [ -n "$ex_mem_proc" ]; then
    echo "Warning! Extremely high load!"
    all_ex_procs=$(echo "$ex_cpu_proc $ex_mem_proc" | tr ' ' '\n' | sort -u)
    for pid in $all_ex_procs; do
        # Проверяем, существует ли процесс
        if ps -p $pid > /dev/null 2>&1; then
            # Пропускаем важные системные процессы
            if [ $pid -eq 1 ] || [ $pid -eq 2 ] || [ $pid -eq $$ ]; then
                echo "Skipping system/self process $pid"
                continue
            fi
            # Сначала пробуем SIGTERM (15), затем SIGKILL (9)
            echo "Terminating process $pid"
            kill -15 $pid 2>/dev/null
            sleep 2
            # Проверяем, жив ли еще процесс
            if ps -p $pid > /dev/null 2>&1; then
                echo "Force killing process $pid"
                kill -9 $pid 2>/dev/null
            fi
        fi
    done
else
    echo "No extreme load detected."
fi
}
LOG_FILE="/var/log/listen_watch.log"
STATE_DIR="/var/lib/listen_watch"
STATE_FILE="$STATE_DIR/ports.txt"
mkdir -p "$STATE_DIR"
ntwcheck(){
echo "=== Checking up listening ports ===" | tee -a "$LOG_FILE"
CURR=$(mktemp)
ss -tulpnH 2>/dev/null | awk '{print $1, $5}' | sort -u > "$CURR"

if [ ! -f "$STATE_FILE" ]; then
	cp "$CURR" "$STATE_FILE"
	echo "Base of listening ports is created." | tee -a "$LOG_FILE"
	rm -f "$CURR"
	exit 0
fi
ADDED=$(comm -13 "$STATE_FILE" "$CURR")
REMOVED=$(comm -23 "$STATE_FILE" "$CURR")
[ -n "$ADDED" ] && echo "New ports: " | tee -a "$LOG_FILE" && echo "$ADDED" | tee -a "$LOG_FILE"
[ -n "$REMOVED" ] && echo "Closed ports:" | tee -a "$LOG_FILE" && echo "$REMOVED" | tee -a "$LOG_FILE"
[ -z "$ADDED""$REMOVED" ] && echo "Nothing changed." | tee -a "$LOG_FILE"
cp "$CURR" "$STATE_FILE"
rm -f "$CURR"
}
sshcheck(){
echo "=== Checking up for strange things with SSH ==="
sleep 1
rm alarm.log 2>/dev/null
date && timedatectl >> alarm.log
w >> alarm.log
who >> alarm.log
ps auxww >> alarm.log
netstat -tulpn >> alarm.log
ss -tulpn >> alarm.log
netstat -an | grep ESTABLISHED >> alarm.log
cat /etc/passwd ; lastlog
last -f /var/log/wtmp >> alarm.log
last -f /var/log/btmp >> alarm.log
crontab -l >> alarm.log
for user in $(cat /etc/passwd | cut -d: -f1); do crontab -u $user -l >> alarm.log ; 2>/dev/null; done
find /bin /sbin -type f -mtime -l >> alarm.log
find /root /home -name "authorized_keys" >> alarm.log 2>/dev/null
#history
sudo cat /root/.bash_history >> alarm.log
tail -100 /var/log/auth.log >> alarm.log
journalctl -xe --lines=50 >> alarm.log
route -n >> alarm.log
ip route show >> alarm.log
arp -a >> alarm.log
lsof -i -P -n | grep LISTEN >> alarm.log
lsof -i -P -n | grep ESTABLISHED >> alarm.log
}
pkgcheck(){
echo "=== Checking up for missed security updates ==="
    LOG="/var/log/critical-updates.log"
THRESHOLD=7.0 # CVSS выше этого считаем критичным

# Получаем список обновляемых пакетов
updates=$(sudo apt list --upgradable 2>/dev/null | grep -v "Listing" | cut -d/ -f1)

for pkg in $updates; do
    # Проверяем, есть ли у пакета CVE с высоким CVSS
    cve_count=$(debsecan --suite $(lsb_release -sc) --only-fixed --package "$pkg" 2>/dev/null | \
                grep -E "\([7-9]\.[0-9]|10\.0\)" | wc -l)
    if [ $cve_count -gt 0 ]; then
        critical_pkgs="$critical_pkgs\n- $pkg (исправляет $cve_count критических CVE)"
    fi
done

if [ -n "$critical_pkgs" ]; then
    echo -e "Критические уведомления безопасности:\n$critical_pkgs" | \
        notify-send -u critical -t 0 "Обновления безопасности" "$(cat)"
    echo "$(date): Найдены критические обновления: $critical_pkgs" >> $LOG
fi
}
npswdcheck(){
echo "=== Checking up for NOPASSWD-commands ==="
sudo -l | grep NOPASSWD
}
clear
cat eye.txt
sleep 5
clear
run_zmbkiller=0
run_slpcron=0
run_nmpproc=0
run_ntwcheck=0
run_sshcheck=0
run_pkgcheck=0
run_all=1
while getopts "zcpnsu" opt; do
	case $opt in
		z)
			run_all=0
			run_zmbkiller=1
			;;
		c)
			run_all=0
			run_slpcron=1
			;;
		p)
			run_all=0
			run_nmpproc=1
			;;
		n)
			run_all=0
			run_ntwcheck=1
			;;
		s)
			run_all=0
			run_sshcheck=1
		u)
			run_all=0
			run_pkgcheck=1
		\?)
			echo "Unknown option! Check up the README file, mazafaka!"
			;;
	esac
done
if [[ $run_all -eq 1 ]]; then
	run_zmbkiller=1
	run_slpcron=1
	run_nmpproc=1
	run_ntwcheck=1
	run_sshcheck=1
	run_pkgcheck=1
fi
rtcheck
display
echo "=== System Monitor Script started at $(date) ==="
if [[ $run_zmbkiller -eq 1 ]]; then 
	zmbkiller
fi
if [[ $run_slpcrom -eq 1 ]]; then 
	slpcron
fi 
if[[ $run_nmpproc -eq 1 ]]; then
	nmpproc
fi
if [[ $run_ntwcheck -eq 1 ]]; then 
	ntwcheck
fi
if [[ $run_sshcheck -eq 1 ]]; then 
	sshcheck
fi
if [[ $run_pkgcheck -eq 1 ]]; then
	pkgcheck
fi
echo "=== System Monitor Script finished at $(date) ==="
