# ROOTD

## Что это?

Это персистентный root-демон, идея взята из различных реализаций пользователей из ТГ `Yandex Station Extended`. Задача у демона следующая: после перезагрузки станции давать выполнение команд от root без повторного прогона эксплоита

## Как оно работает?

Демон отслеживает каталог `/data/local/tmp/rootq`. Внутри три директории `pending`, `running`, `results`. Подробнее работа описана в [QUEUE-DESIGN.md](QUEUE-DESIGN.md).
При каждом запуске демон сначала читает стартовые команды из `/data/local/tmp/rootd/rootup` и только затем подготавливает очередь: первая команда обычно переводит SELinux в Permissive, без чего очередь (`0700 shell:shell`) недоступна домену `adbd` в Enforcing. Каждая непустая строка запускается через shell по очереди; демон ждёт завершения очередной команды, прежде чем перейти к следующей. Вывод stdout/stderr стартовых команд дописывается в общий файл `/data/local/tmp/rootd/rootup.out`; файл заранее создаёт установщик от root, потому что в Enforcing uid 0 не может создать его сам.

## Как этим пользоваться?

### Сборка

```
binaries/src/rootd/build.sh                    # результат по умолчанию: binaries/rootd
# При необходимости можно явно задать OUT и ANDROID_NKD_HOME
```

Скрипт ищет `aarch64-linux-android28-clang` внутри NDK (`ANDROID_NDK_HOME`, затем `ANDROID_NDK_ROOT`, затем `/opt/android-ndk`), собирает `rootd.c` как C11 с `-O2 -Wall -Wextra -Werror`, `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong` и `-Wl,-z,relro,-z,now`. Бинарник линкуется с bionic, то есть он для самой станции (arm64, Android), а не для хоста.

После пересборки обновите контрольные суммы: `(cd binaries && sha256sum esc rootd > SHA256SUMS)`. `scripts/install.sh` и `scripts/get-root.py` сверяют их перед отправкой бинарников на станцию.

### Лог

Сообщения демона дописываются в `/data/local/tmp/rootd.log` (права 0644). Туда попадает строка `rootd starting` и ошибки syscall'ов с `strerror`; штатные события (взял задание, выполнил) не логируются. Ротации нет.
