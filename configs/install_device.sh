#!/system/bin/sh
# Установщик kit. Запускается из root-сессии (uid 0).
# Раскладывает файлы, метки SELinux и права. Повторный запуск безопасен.
#
# Подмена работающего бинарника идёт через rename, а не cp поверх файла:
# ядро держит исполняемый inode открытым, и cp получает ETXTBSY, а init
# перезапускает rootd каждые 5 секунд — гонка неустранима. Новый файл
# пишется рядом, получает метку и права, затем атомарно переименовывается.

set -eu

STAGE=/data/local/tmp/stage
ODM=/odm
ODM_BIN=$ODM/bin/rootd
ODM_RC=$ODM/etc/init/rootd.rc
LOG_DIR=/data/local/tmp/logs

fail() {
    echo "ERROR: $*"
    exit 1
}

mkdir -p "$LOG_DIR"
echo "=== install $(date) uid=$(id -u) enforce=$(getenforce) ==="

[ "$(id -u)" = "0" ] || fail "нужен uid 0 (запустите через get-root.py / install.sh)"

# 1. Конфиги и esc в /data/local/tmp (shell_data_file — доступен и adbd, и shell).
# Каталоги принадлежат root:root, иначе shell мог бы подменить стартовые скрипты,
# которые rootd выполняет от UID 0.
mkdir -p /data/local/tmp/rootd "$LOG_DIR"
chown 0:0 /data/local/tmp/rootd "$LOG_DIR"
chmod 0755 /data/local/tmp/rootd "$LOG_DIR"

cp "$STAGE/rootup" /data/local/tmp/rootd/rootup
cp "$STAGE/enforce-up.sh" /data/local/tmp/rootd/enforce-up.sh
cp "$STAGE/adbd-watchdog.sh" /data/local/tmp/rootd/adbd-watchdog.sh
chmod 644 /data/local/tmp/rootd/rootup
chmod 755 /data/local/tmp/rootd/enforce-up.sh /data/local/tmp/rootd/adbd-watchdog.sh
chown 0:0 /data/local/tmp/rootd/rootup /data/local/tmp/rootd/enforce-up.sh /data/local/tmp/rootd/adbd-watchdog.sh

# 1a. Файлы, которые rootd открывает при загрузке ещё в Enforcing: журнал и
# вывод стартовых команд. Создать их сам он не может — /data/local/tmp имеет
# права 0771 shell:shell, а у uid 0 в домене adbd нет CAP_DAC_OVERRIDE.
: > /data/local/tmp/rootd/rootup.out
: > /data/local/tmp/rootd.log
chown 0:0 /data/local/tmp/rootd/rootup.out /data/local/tmp/rootd.log
chmod 0644 /data/local/tmp/rootd/rootup.out /data/local/tmp/rootd.log

# esc уже на станции: его загрузил get-root.py, иначе root-сессии не было бы.
[ -x /data/local/tmp/esc ] ||
    fail "/data/local/tmp/esc отсутствует или не исполняется — запустите get-root.py"
chmod 755 /data/local/tmp/esc
chown 0:0 /data/local/tmp/esc

# 2. /odm: бинарник с меткой adbd_exec и rc-файл.
mount -o remount,rw "$ODM" || fail "remount $ODM rw не удался"

cleanup_odm() {
    rm -f "$ODM_BIN.new" "$ODM_RC.new"
    sync
    mount -o remount,ro "$ODM" || echo "WARN: remount $ODM ro не удался — смонтируйте вручную"
}

trap cleanup_odm EXIT

mkdir -p "$ODM/bin" "$ODM/etc/init"

# Бинарник: копия рядом с целью, метка и права на копии, затем атомарный rename.
# cp именно в .new: cp поверх работающего бинарника получает ETXTBSY, потому что
# ядро держит исполняемый inode открытым, а init перезапускает rootd каждые 5 с.
# rm -f перед cp тоже не годится: между удалением и созданием файла rootd
# успевает перезапуститься и снова занять новый inode.
rm -f "$ODM_BIN.new" "$ODM_RC.new"
cp "$STAGE/rootd" "$ODM_BIN.new" || fail "cp в $ODM_BIN.new"
chmod 755 "$ODM_BIN.new"
chown 0:0 "$ODM_BIN.new"
chcon u:object_r:adbd_exec:s0 "$ODM_BIN.new" || fail "chcon $ODM_BIN.new"
mv -f "$ODM_BIN.new" "$ODM_BIN" || fail "mv $ODM_BIN.new -> $ODM_BIN"

# rc-файл: init читает его только при загрузке, rename безопасен по той же причине.
cp "$STAGE/rootd.rc" "$ODM_RC.new" || fail "cp в $ODM_RC.new"
chmod 644 "$ODM_RC.new"
chown 0:0 "$ODM_RC.new"
mv -f "$ODM_RC.new" "$ODM_RC" || fail "mv $ODM_RC.new -> $ODM_RC"

sync
trap - EXIT
cleanup_odm

# 2a. Проверка, что на месте действительно новая версия.
stage_sum=$(sha256sum "$STAGE/rootd" 2>/dev/null | cut -d' ' -f1)
odm_sum=$(sha256sum "$ODM_BIN" 2>/dev/null | cut -d' ' -f1)
[ -n "$stage_sum" ] || fail "sha256sum недоступен — нечем проверить $ODM_BIN"
if [ "$stage_sum" != "$odm_sum" ]; then
    fail "staging проверен, но установленный $ODM_BIN не совпадает со stage ($odm_sum != $stage_sum); причина может быть не только в замене занятого файла"
fi
echo "OK: $ODM_BIN совпадает со staging sha256=$odm_sum"

# 3. Очередь: 0700, владелец shell (2000:2000). rootd читает её через
# CAP_DAC_OVERRIDE, отправитель — как владелец.
mkdir -p /data/local/tmp/rootq/pending /data/local/tmp/rootq/running /data/local/tmp/rootq/results
chown 2000:2000 /data/local/tmp/rootq /data/local/tmp/rootq/pending /data/local/tmp/rootq/running /data/local/tmp/rootq/results
chmod 0700 /data/local/tmp/rootq /data/local/tmp/rootq/pending /data/local/tmp/rootq/running /data/local/tmp/rootq/results

# 4. Проверка.
echo "--- /odm/bin ---"
ls -laZ "$ODM/bin" || true
echo "--- /odm/etc/init ---"
ls -laZ "$ODM/etc/init" || true
echo "--- /data/local/tmp/rootd ---"
ls -laZ /data/local/tmp/rootd || true
echo "--- /data/local/tmp/rootq ---"
ls -laZ /data/local/tmp/rootq || true
echo "--- init mentions /odm/etc/init? ---"
if grep -ac "/odm/etc/init" /init 2>/dev/null; then
    echo "OK: /init содержит /odm/etc/init"
else
    echo "WARN: /init не содержит /odm/etc/init — проверьте разбор rc после перезагрузки"
fi
echo "enforce=$(getenforce)"
echo "=== done rc=0 ==="
