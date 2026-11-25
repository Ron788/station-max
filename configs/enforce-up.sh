#!/system/bin/sh
# enforce-up.sh — перевести SELinux в Permissive через Mali esc-flip.
#
# Запускается rootd как стартовая команда из /data/local/tmp/rootd/rootup.
# rootd работает в домене adbd, но запускает строки rootup через /system/bin/sh;
# sh переходит в домен shell (typetransition adbd shell_exec -> shell), и уже
# оттуда выполняется этот скрипт. Домен shell имеет доступ к /dev/mali0, поэтому
# esc-flip работает. Сначала пробуем штатный setenforce, если не выходит —
# повторяем esc-flip до ATTEMPTS раз.
#
# Почему цикл, а не один запуск: esc-flip нестабилен — «flip reader bring-up
# failed» и «FLIP ABORT before mismatch»; пока не получилось — пробуем снова.
#
# Лог: /data/local/tmp/logs/enforce.log, каждая запись с меткой времени.
# Повторный запуск безопасен: если уже Permissive — выходим сразу.

PERMISSIVE_BIN=/data/local/tmp/esc
SELINUX_ADDR=0x291352c
OLD=1
NEW=0
ATTEMPTS=10
LOG_DIR=/data/local/tmp/logs
LOG=$LOG_DIR/enforce.log
NAP=1

mkdir -p "$LOG_DIR"

log() {
    line="$(date '+%Y-%m-%d %H:%M:%S') [$$] $*"
    echo "$line" >>"$LOG"
    # stdout уходит в /data/local/tmp/rootd/rootup.out (rootd перенаправляет вывод).
    echo "$line"
}

read_enforce() {
    cat /sys/fs/selinux/enforce 2>/dev/null | tr -d ' \r\n'
}

log "start: enforce=$(read_enforce) uid=$(id -u) label=$(cat /proc/self/attr/current 2>/dev/null)"

if [ "$(read_enforce)" = "$NEW" ]; then
    log "already permissive, nothing to do"
    exit 0
fi

# Быстрый путь: штатный setenforce. В домене shell он может сработать, если
# политика разрешает запись в selinuxfs; иначе остаётся esc-flip.
if setenforce "$NEW" >/dev/null 2>&1 && [ "$(read_enforce)" = "$NEW" ]; then
    log "setenforce $NEW ok"
    exit 0
fi

if [ ! -x "$PERMISSIVE_BIN" ]; then
    log "ERROR: $PERMISSIVE_BIN missing or not executable"
    exit 1
fi

i=1
while [ "$i" -le "$ATTEMPTS" ]; do
    out="$("$PERMISSIVE_BIN" flip "$SELINUX_ADDR" "$OLD" "$NEW" 2>&1)"
    res="$(echo "$out" | grep '^RESULT:')"
    [ -n "$res" ] || res="no RESULT line"
    # RESULT-строки esc-flip уже содержат итоговый enforce= в части случаев.
    case "$res" in
        *enforce=*) ;;
        *) res="$res enforce=$(read_enforce)" ;;
    esac
    cur="$(read_enforce)"
    log "attempt $i/$ATTEMPTS: $res"
    if [ "$cur" = "$NEW" ]; then
        log "permissive ok after $i attempt(s)"
        exit 0
    fi
    i=$((i + 1))
    sleep "$NAP"
done

log "ERROR: still enforcing ($(read_enforce)) after $ATTEMPTS attempts"
exit 1
