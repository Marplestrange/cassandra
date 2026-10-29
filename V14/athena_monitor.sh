#!/bin/bash
# ==========================================
# ATHENA MONITOR — Surveillance Athena (Synology)
# ==========================================

ATHENA_IP="100.64.0.9"
LOG_FILE="/var/log/athena_monitor.log"
ALERT_LOG="/var/log/athena_alerts.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

DISK_THRESHOLD=80
MEM_THRESHOLD=85
LOAD_THRESHOLD=4.0

alert() {
    local level="$1"
    local message="$2"
    echo "[$TIMESTAMP] [$level] $message" >> "$ALERT_LOG"
    echo "[$TIMESTAMP] [$level] $message"
}

RAW=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes root@$ATHENA_IP bash -s 2>/dev/null << 'SSHCMD'
DOCKER_BIN="/volume1/@appstore/ContainerManager/usr/bin/docker"
echo "DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')"
echo "MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')"
echo "LOAD_AVG=$(cat /proc/loadavg | awk '{print $1}')"
echo "SSHD_STATUS=$(systemctl is-active sshd 2>/dev/null || echo 'inactive')"
# Sur Synology : vérifier crond via ps
ps aux 2>/dev/null | grep -v grep | grep -q "[c]rond" && echo "CRON_STATUS=active" || echo "CRON_STATUS=inactive"
echo "DOCKER_STATUS=$(systemctl is-active pkg-ContainerManager-dockerd.service 2>/dev/null || echo 'inactive')"
DOCKER_COUNT=0
[ -x "$DOCKER_BIN" ] && DOCKER_COUNT=$($DOCKER_BIN ps -q 2>/dev/null | wc -l)
echo "DOCKER_COUNT=$DOCKER_COUNT"
SSHCMD
)

if [ $? -ne 0 ] || [ -z "$RAW" ]; then
    alert "CRITICAL" "ATHENA — Connexion SSH impossible !"
    exit 1
fi

while IFS='=' read -r key value; do
    case "$key" in
        DISK_USAGE) DISK_USAGE="$value" ;;
        MEM_USAGE) MEM_USAGE="$value" ;;
        LOAD_AVG) LOAD_AVG="$value" ;;
        SSHD_STATUS) SSHD_STATUS="$value" ;;
        CRON_STATUS) CRON_STATUS="$value" ;;
        DOCKER_STATUS) DOCKER_STATUS="$value" ;;
        DOCKER_COUNT) DOCKER_COUNT="$value" ;;
    esac
done <<< "$RAW"

echo "[$TIMESTAMP] DISK=$DISK_USAGE% MEM=$MEM_USAGE% LOAD=$LOAD_AVG DOCKERS=$DOCKER_COUNT" >> "$LOG_FILE"

[ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ] 2>/dev/null && alert "WARNING" "ATHENA — Disque à ${DISK_USAGE}%"
[ "$MEM_USAGE" -gt "$MEM_THRESHOLD" ] 2>/dev/null && alert "WARNING" "ATHENA — RAM à ${MEM_USAGE}%"
LOAD_CHECK=$(echo "$LOAD_AVG > $LOAD_THRESHOLD" | bc -l 2>/dev/null)
[ "$LOAD_CHECK" = "1" ] && alert "WARNING" "ATHENA — Load élevé: ${LOAD_AVG}"
[ "$SSHD_STATUS" != "active" ] && alert "CRITICAL" "ATHENA — SSHD: $SSHD_STATUS"
[ "$CRON_STATUS" != "active" ] && alert "CRITICAL" "ATHENA — Cron: $CRON_STATUS"
[ "$DOCKER_STATUS" != "active" ] && alert "CRITICAL" "ATHENA — Docker: $DOCKER_STATUS"

echo "[$TIMESTAMP] ✅ OK — DISK=${DISK_USAGE}% MEM=${MEM_USAGE}% LOAD=${LOAD_AVG}" >> "$LOG_FILE"
exit 0
