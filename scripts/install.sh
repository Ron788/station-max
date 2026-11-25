#!/usr/bin/env bash
# Устанавливает kit на станцию: /odm/bin/rootd, /odm/etc/init/rootd.rc,
# /data/local/tmp/rootd/*, очередь /data/local/tmp/rootq.
# esc на станции уже есть: его загружает get-root.py, иначе root-сессии не было бы.
#
# Требует: станция в Permissive (scripts/get-root.py) и триггер ядра
# ещё активен — installer запускается в root-сессии через read-триггер.
#
# Использование: bash scripts/install.sh [IP]

set -euo pipefail

IP="${1:-192.168.1.149}"
S="$IP:5555"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
STAGE=/data/local/tmp/stage

verify_binary() {
    local file="$1" name expected actual
    name="$(basename "$file")"
    expected="$(awk -v n="$name" '$2 == n { print $1; exit }' "$REPO/binaries/SHA256SUMS")"
    [ -n "$expected" ] || {
        printf 'Ошибка: в binaries/SHA256SUMS нет записи для %s\n' "$name" >&2
        exit 1
    }
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        printf 'Ошибка: нет sha256sum или shasum для проверки %s\n' "$name" >&2
        exit 1
    fi
    [ "$actual" = "$expected" ] || {
        printf 'Ошибка: контрольная сумма %s не совпадает с binaries/SHA256SUMS\n' "$name" >&2
        exit 1
    }
}

adb -s "$S" shell id >/dev/null 2>&1 || {
    echo "adb не отвечает на $S" >&2
    exit 1
}

verify_binary "$REPO/binaries/rootd"

adb -s "$S" shell "rm -rf $STAGE; mkdir -p $STAGE"
adb -s "$S" push "$REPO/binaries/rootd" "$STAGE/rootd"
adb -s "$S" push "$REPO/configs/rootd.rc" "$STAGE/rootd.rc"
adb -s "$S" push "$REPO/configs/rootup" "$STAGE/rootup"
adb -s "$S" push "$REPO/configs/enforce-up.sh" "$STAGE/enforce-up.sh"
adb -s "$S" push "$REPO/configs/adbd-watchdog.sh" "$STAGE/adbd-watchdog.sh"
adb -s "$S" push "$REPO/configs/install_device.sh" "$STAGE/install_device.sh"
adb -s "$S" shell "chmod 755 $STAGE/install_device.sh"

# Убедиться, что rootd в staging полностью совпадает с проверенным локальным файлом.
# Это отделяет ошибку передачи/записи от ошибки установки в /odm.
local_sum="$(sha256sum "$REPO/binaries/rootd" | awk '{print $1}')"
stage_sum="$(adb -s "$S" shell "sha256sum $STAGE/rootd" | awk '{print $1}')"
if [ -z "$stage_sum" ]; then
    echo "Ошибка: не удалось прочитать sha256 $STAGE/rootd после загрузки" >&2
    exit 1
fi
if [ "$stage_sum" != "$local_sum" ]; then
    echo "Ошибка: rootd в staging не совпадает с binaries/rootd после загрузки" >&2
    echo "  staging:  $stage_sum" >&2
    echo "  локально: $local_sum" >&2
    exit 1
fi
echo "OK: staging rootd совпадает с binaries/rootd ($local_sum)"

# Триггер root и установщик в одной сессии: read переключает creds, sh-потомок
# наследует uid 0. Это второй триггер после get-root.py.
#
# adb shell не возвращает код удалённой команды, поэтому успех определяется по
# маркеру из установщика, а не по коду adb. Вывод дублируется в файл на
# станции: /system/bin/sh здесь — mksh, PIPESTATUS у него есть.
remote_log=/data/local/tmp/logs/install.log
adb -s "$S" shell "mkdir -p /data/local/tmp/logs"
out="$(adb -s "$S" shell "read _x < /sys/fs/selinux/reject_unknown 2>/dev/null; sh $STAGE/install_device.sh 2>&1 | tee $remote_log")"
echo "$out"

case "$out" in
    *"=== done rc=0 ==="*) ;;
    *)
        echo "Ошибка: установщик не дошёл до конца. Полный вывод: $remote_log" >&2
        exit 1
        ;;
esac

