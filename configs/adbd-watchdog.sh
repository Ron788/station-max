#!/system/bin/sh
# adbd-watchdog.sh — держит adb по TCP :5555 после загрузки станции.
#
# Запуск: rootd читает /data/local/tmp/rootd/rootup построчно и ждёт завершения
# каждой строки, поэтому в rootup скрипт стартует в фоне:
#     sh /data/local/tmp/rootd/adbd-watchdog.sh >/dev/null 2>&1 &
# rootup выполняется при каждом старте rootd, поэтому второй экземпляр
# отсекается flock'ом.
#
# Что делает раз в INTERVAL секунд:
#   1. SELinux Permissive?		— нет: только пишет в лог и ничего не трогает;
#   2. adb_enabled=1?			— нет: settings put global adb_enabled 1;
#   3. service.adb.tcp.port=5555?	— нет: setprop;
#   4. есть LISTEN на 5555?		— нет: перезапуск adbd через init (stop/start),
#					  при неудаче — прямой запуск adbd.
#
# Почему в Enforcing ничего не делаем: запись в ctl.* и service.* свойства из
# домена shell запрещена политикой, а неудачный `stop adbd` оставил бы станцию
# без adb до перезагрузки. Служба adbd в init.usb.rc объявлена `disabled` и
# сама не поднимается после stop, поэтому start делаем явно.
#
# Лог: /data/local/tmp/logs/adbd.log

LOG_DIR=/data/local/tmp/logs
LOG=$LOG_DIR/adbd.log
LOCK=$LOG_DIR/adbd.lock

PORT=5555
HEX_PORT=15B3		# 5555 = 0x15B3
INTERVAL=10		# период проверки, с
STARTUP_WAIT=60		# сколько ждать Permissive при старте, с
PORT_GRACE=15		# сколько ждать слушателя до перезапуска adbd, с

mkdir -p "$LOG_DIR" 2>/dev/null

log() {
	echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $*" >> "$LOG" 2>/dev/null
}

permissive() {
	[ "$(getenforce 2>/dev/null)" = "Permissive" ]
}

listening() {
	grep -qi ":$HEX_PORT .* 0A" /proc/net/tcp 2>/dev/null ||
	grep -qi ":$HEX_PORT .* 0A" /proc/net/tcp6 2>/dev/null
}

wait_for_port() {
	i=0
	while [ "$i" -lt "$PORT_GRACE" ]; do
		listening && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

start_adbd() {
	log "adbd does not listen on $PORT, restarting via init"
	stop adbd 2>/dev/null
	sleep 2
	start adbd 2>/dev/null

	i=0
	while [ "$i" -lt 10 ]; do
		sleep 1
		if listening; then
			log "adbd is listening on $PORT after init restart"
			return 0
		fi
		i=$((i + 1))
	done

	# init мог отказать (нет прав, служба в странном состоянии): поднимаем
	# adbd тем же способом, каким его запускает init.usb.rc.
	log "init restart did not help, executing adbd directly"
	/system/bin/adbd --root_seclabel=u:r:su:s0 >/dev/null 2>&1 &
	sleep 3
	if listening; then
		log "adbd is listening on $PORT after direct exec"
		return 0
	fi
	log "ERROR: adbd is still not listening on $PORT"
	return 1
}

apply_settings() {
	cur="$(settings get global adb_enabled 2>/dev/null)"
	if [ "$cur" != "1" ]; then
		settings put global adb_enabled 1 2>/dev/null
		log "adb_enabled: ${cur:-empty} -> 1"
	fi

	if [ "$(getprop service.adb.tcp.port 2>/dev/null)" != "$PORT" ]; then
		setprop service.adb.tcp.port "$PORT"
		log "service.adb.tcp.port -> $PORT"
	fi
}

main() {
	log "start: uid=$(id -u) label=$(cat /proc/self/attr/current 2>/dev/null) enforce=$(getenforce 2>/dev/null)"

	# В rootup мы идём после enforce-up.sh, но он мог не отработать — тогда
	# ждём (возможно, Permissive выставит что-то ещё) и только потом работаем.
	i=0
	while ! permissive && [ "$i" -lt "$STARTUP_WAIT" ]; do
		sleep 2
		i=$((i + 2))
	done
	if ! permissive; then
		log "WARN: SELinux is still $(getenforce 2>/dev/null) after ${STARTUP_WAIT}s wait"
	fi

	enforcing_logged=0
	while :; do
		if ! permissive; then
			if [ "$enforcing_logged" -eq 0 ]; then
				log "SELinux is $(getenforce 2>/dev/null), waiting for Permissive"
				enforcing_logged=1
			fi
			sleep "$INTERVAL"
			continue
		fi
		enforcing_logged=0

		apply_settings

		if ! listening; then
			wait_for_port && log "adbd started listening on $PORT" || start_adbd
		fi

		sleep "$INTERVAL"
	done
}

# Один экземпляр на станцию. Блокировку берём в перенаправлении группы, а не
# через `exec 9>`: на этой прошивке (mksh + toybox 0.7.6) fd, открытый exec'ом,
# помечен CLOEXEC, и flock его не видит ("Bad file descriptor"). fd группы
# наследуется, и блокировка живёт, пока выполняется тело группы.
{ flock -n 9 || { log "another instance holds $LOCK, exit"; exit 0; }; main; } 9>>"$LOCK"
