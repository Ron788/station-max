#!/usr/bin/env bash
# Быстрая установка Этапа 4: проверки, временный root, установка набора,
# перезагрузка и проверка rootd. Вызывает get-root.py, install.sh и run-root.sh.
#
# Использование: bash scripts/quick-install.sh [IP] [--force]
#   IP      — адрес станции (по умолчанию 192.168.1.149)
#   --force — переустановить, даже если набор уже работает

set -euo pipefail

IP="192.168.1.149"
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help)
            printf 'Использование: %s [IP] [--force]\n' "${0##*/}"
            printf '  IP      адрес станции (по умолчанию 192.168.1.149)\n'
            printf '  --force переустановить, даже если набор уже работает\n'
            exit 0
            ;;
        -*)
            printf 'Неизвестный параметр: %s\n' "$arg" >&2
            exit 2
            ;;
        *) IP="$arg" ;;
    esac
done

S="$IP:5555"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_BUILD="PPR1.180610.011.5000000921"
BOOT_TIMEOUT=240

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "ОШИБКА: $*"; exit 1; }

command -v adb >/dev/null 2>&1 || die "adb не найден в PATH"
command -v python3 >/dev/null 2>&1 || die "python3 не найден в PATH"

log "проверяю станцию $S"
adb connect "$S" >/dev/null 2>&1 || true
build="$(adb -s "$S" shell getprop ro.build.display.id 2>/dev/null | tr -d '\r' || true)"
[ -n "$build" ] || die "станция не отвечает на $S"
[ "$build" = "$TARGET_BUILD" ] || die "сборка '$build' не совпадает с целевой '$TARGET_BUILD'"
log "сборка: $build"

if [ "$FORCE" -eq 0 ] \
    && [ "$(adb -s "$S" shell getenforce 2>/dev/null | tr -d '\r' || true)" = "Permissive" ] \
    && adb -s "$S" shell "test -d /data/local/tmp/rootq/pending" >/dev/null 2>&1 \
    && adb -s "$S" shell "test -f /data/local/tmp/rootd.log" >/dev/null 2>&1; then
    log "набор уже установлен и работает; повторная установка не нужна"
    log "переустановка: bash scripts/quick-install.sh $IP --force"
    exit 0
fi

log "шаг 1/4: временный root"
python3 "$REPO/scripts/get-root.py" "$IP" || die "get-root.py не смог получить root"

log "шаг 2/4: установка набора"
install_out="$(bash "$REPO/scripts/install.sh" "$IP" 2>&1)" || {
    printf '%s\n' "$install_out"
    die "install.sh завершился с ошибкой"
}
printf '%s\n' "$install_out"
if printf '%s\n' "$install_out" | grep -q 'WARN: /init'; then
    die "установщик вывел WARN про /init — перезагрузка отменена, проверьте вручную"
fi

log "шаг 3/4: перезагрузка"
adb -s "$S" reboot >/dev/null 2>&1 || true
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
booted=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    adb connect "$S" >/dev/null 2>&1 || true
    if [ "$(adb -s "$S" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)" = "1" ]; then
        booted=1
        break
    fi
    sleep 2
done
[ "$booted" -eq 1 ] || die "ADB не вернулся за ${BOOT_TIMEOUT} с после перезагрузки — станция могла загрузиться без ADB; проверьте watchdog и /data/local/tmp/logs/adbd.log"

log "шаг 4/4: проверка"
enforce=""
i=0
while [ "$i" -lt 30 ]; do
    enforce="$(adb -s "$S" shell getenforce 2>/dev/null | tr -d '\r' || true)"
    [ "$enforce" = "Permissive" ] && break
    i=$((i + 1))
    sleep 2
done
[ "$enforce" = "Permissive" ] || die "SELinux: '$enforce', ожидался Permissive — смотрите /data/local/tmp/logs/enforce.log"

adb -s "$S" shell "test -f /data/local/tmp/rootd.log" >/dev/null 2>&1 \
    || die "нет /data/local/tmp/rootd.log — rootd не запустился"
adb -s "$S" shell "test -d /data/local/tmp/rootq/pending" >/dev/null 2>&1 \
    || die "нет очереди /data/local/tmp/rootq"

if command -v timeout >/dev/null 2>&1; then
    id_out="$(ANDROID_SERIAL="$S" timeout 120 bash "$REPO/scripts/run-root.sh" "id" 2>/dev/null)" \
        || die "run-root.sh не выполнил задание"
else
    id_out="$(ANDROID_SERIAL="$S" bash "$REPO/scripts/run-root.sh" "id" 2>/dev/null)" \
        || die "run-root.sh не выполнил задание"
fi
printf '%s\n' "$id_out"
case "$id_out" in
    *"uid=0"*) ;;
    *) die "rootd выполнил команду не от root" ;;
esac

log "готово: rootd работает, станция в Permissive"
log "дальше — 4.6: выключить lite-kit и проверить watchdog перезагрузкой"
