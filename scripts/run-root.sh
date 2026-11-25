#!/usr/bin/env bash
# Отправить shell-команду в очередь rootd, вывести результат и удалить его с устройства.
set -euo pipefail

usage() {
    printf 'Использование: %s "команда"\n' "${0##*/}" >&2
}

if [[ $# -ne 1 || -z $1 ]]; then
    usage
    exit 2
fi

if ! command -v adb >/dev/null 2>&1; then
    printf 'Ошибка: adb не найден в PATH.\n' >&2
    exit 127
fi

# Идентификатор только из безопасных для shell/пути символов.
id="$(date +%s)-$$-${RANDOM}"
remote="/data/local/tmp/rootq"
local_tmp="$(mktemp)"

cleanup_local() {
    rm -f -- "$local_tmp"
}
trap cleanup_local EXIT

# ADB shell принимает одну удалённую shell-строку: экранируем все динамические
# значения как POSIX shell-аргументы, чтобы команда не интерпретировалась локально.
quote_remote() {
    printf "'%s'" "${1//\'/\'\\\'\'}"
}

q_id="$(quote_remote "$id")"
q_remote="$(quote_remote "$remote")"

printf '%s' "$1" >"$local_tmp"

# Сначала передаём содержимое во временный файл без расширения .job, затем
# атомарно переименовываем его в pending/<id>.job на стороне устройства.
if ! adb push "$local_tmp" "/data/local/tmp/rootq/pending/.${id}.tmp" >/dev/null; then
    printf 'Ошибка: не удалось передать задание на устройство.\n' >&2
    exit 1
fi
if ! adb shell "mv $q_remote/pending/.$id.tmp $q_remote/pending/$id.job"; then
    printf 'Ошибка: не удалось опубликовать задание в очереди.\n' >&2
    exit 1
fi

printf 'Задание %s отправлено; ожидание результата...\n' "$id" >&2

while :; do
    # status появляется после завершения команды. Отдельно проверяем и interrupted.
    if adb shell "test -f $q_remote/results/$q_id.status" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Читаем вывод и статус до очистки. Не прерываемся на ненулевом коде команды.
set +e
adb exec-out "cat $remote/results/$id.out" 2>/dev/null
output_rc=$?
status="$(adb shell "cat $q_remote/results/$q_id.status" 2>/dev/null | tr -d '\r')"
status_rc=$?
set -e

# Очищаем оба файла результата после чтения.
adb shell "rm -f $q_remote/results/$q_id.out $q_remote/results/$q_id.status"

if [[ $output_rc -ne 0 || $status_rc -ne 0 ]]; then
    printf '\nОшибка: не удалось полностью прочитать результат задания %s.\n' "$id" >&2
    exit 1
fi

if [[ $status == exit:* ]]; then
    exit_code=${status#exit:}
    if [[ $exit_code =~ ^[0-9]+$ ]] && (( exit_code <= 255 )); then
        exit "$exit_code"
    fi
    printf '\nОшибка: некорректный статус от rootd: %s\n' "$status" >&2
    exit 1
fi

if [[ $status == interrupted ]]; then
    printf '\nЗадание %s прервано до завершения.\n' "$id" >&2
    exit 1
fi

printf '\nОшибка: неизвестный статус от rootd: %s\n' "$status" >&2
exit 1
