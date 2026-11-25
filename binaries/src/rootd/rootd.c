// rootd — root-демон со стартовыми командами и файловой очередью.
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define QUEUE_DIR "/data/local/tmp/rootq"
#define PENDING_DIR QUEUE_DIR "/pending"
#define RUNNING_DIR QUEUE_DIR "/running"
#define RESULTS_DIR QUEUE_DIR "/results"
/* Владелец очереди: uid/gid shell (2000) на Android. Каталоги 0700 и
 * принадлежат отправителю, поэтому adb shell может класть задания и читать
 * результаты, а rootd (uid 0) работает с ними через CAP_DAC_OVERRIDE. */
#define QUEUE_UID 2000
#define QUEUE_GID 2000
#define COMMAND_PATH "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/xbin"
#define SHELL_PATH "/system/bin/sh"

static void logline(const char *s) {
    int f = open("/data/local/tmp/rootd.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (f >= 0) { (void)write(f, s, strlen(s)); (void)write(f, "\n", 1); close(f); }
}

static void log_error(const char *operation, const char *name) {
    char message[1024];
    snprintf(message, sizeof(message), "rootd: %s %s: %s", operation, name, strerror(errno));
    logline(message);
}

static char *make_path(const char *dir, const char *name, const char *suffix) {
    size_t len = strlen(dir) + strlen(name) + strlen(suffix) + 2;
    char *path = malloc(len);
    if (path) snprintf(path, len, "%s/%s%s", dir, name, suffix);
    return path;
}

static int is_job(const char *name) {
    size_t len = strlen(name);
    return len > 4 && strcmp(name + len - 4, ".job") == 0;
}

static char *job_id(const char *name) {
    size_t len = strlen(name) - 4;
    char *id = malloc(len + 1);
    if (id) { memcpy(id, name, len); id[len] = '\0'; }
    return id;
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (mkdir(path, 0700) == 0) {
        /* Best effort: в Enforcing домен adbd не имеет CAP_CHOWN, поэтому
         * chown может не пройти до перевода SELinux в Permissive. Каталоги
         * очереди обычно создаёт установщик заранее — тогда сюда не попадаем. */
        if (chown(path, QUEUE_UID, QUEUE_GID) < 0)
            log_error("chown", path);
        return 0;
    }
    if (errno != EEXIST || stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        log_error("mkdir", path);
        return -1;
    }
    return 0;
}

static int prepare_queue(void) {
    return ensure_dir(QUEUE_DIR) || ensure_dir(PENDING_DIR) ||
           ensure_dir(RUNNING_DIR) || ensure_dir(RESULTS_DIR) ? -1 : 0;
}

static int write_status(const char *id, const char *status) {
    char *path = make_path(RESULTS_DIR, id, ".status");
    if (!path) { log_error("allocate status path", id); return -1; }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { log_error("open status", path); free(path); return -1; }
    size_t left = strlen(status);
    const char *p = status;
    while (left) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n == 0) errno = EIO;
            log_error("write status", path);
            close(fd); free(path); return -1;
        }
        p += n; left -= (size_t)n;
    }
    if (close(fd) < 0) { log_error("close status", path); free(path); return -1; }
    free(path);
    return 0;
}

static void recover_running(void) {
    DIR *dir = opendir(RUNNING_DIR);
    if (!dir) { log_error("open directory", RUNNING_DIR); return; }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!is_job(entry->d_name)) continue;
        char *id = job_id(entry->d_name);
        char *path = make_path(RUNNING_DIR, entry->d_name, "");
        if (!id || !path) { log_error("allocate recovery path", entry->d_name); free(id); free(path); continue; }
        if (write_status(id, "interrupted\n") == 0 && unlink(path) < 0)
            log_error("remove interrupted job", path);
        free(id); free(path);
    }
    closedir(dir);
}

static void run_startup_commands(void) {
    FILE *f = fopen("/data/local/tmp/rootd/rootup", "r");
    if (!f) return;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t n;
    while ((n = getline(&line, &capacity, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (line[0] != '\0') {
            pid_t pid = fork();
            if (pid == 0) {
                /* Вывод — в /data/local/tmp/rootd/rootup.out: файл заранее
                 * создаёт установщик от root, чтобы open() в Enforcing не
                 * упирался в DAC (в /data/local/tmp у uid 0 нет права записи). */
                int out = open("/data/local/tmp/rootd/rootup.out", O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (out < 0 || dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0) _exit(127);
                if (out > STDERR_FILENO) close(out);
                if (setenv("PATH", COMMAND_PATH, 1) < 0) _exit(127);
                execl(SHELL_PATH, "sh", "-c", line, (char *)NULL);
                _exit(127);
            }
            if (pid < 0) log_error("fork startup command", "rootup");
            else {
                int status;
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            }
        }
    }
    free(line);
    fclose(f);
}

static int run_job(const char *job, const char *id) {
    char *outpath = make_path(RESULTS_DIR, id, ".out");
    if (!outpath) { log_error("allocate output path", id); return -1; }
    int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { log_error("open output", outpath); free(outpath); return -1; }
    free(outpath);
    pid_t pid = fork();
    if (pid < 0) { log_error("fork job", job); close(out); return -1; }
    if (pid == 0) {
        int in = open(job, O_RDONLY);
        if (in < 0 || dup2(in, STDIN_FILENO) < 0 || dup2(out, STDOUT_FILENO) < 0 ||
            dup2(out, STDERR_FILENO) < 0) _exit(127);
        if (in > STDERR_FILENO) close(in);
        if (out > STDERR_FILENO) close(out);
        if (setenv("PATH", COMMAND_PATH, 1) < 0) _exit(127);
        execl(SHELL_PATH, "sh", (char *)NULL);
        _exit(127);
    }
    close(out);
    int status;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) { log_error("wait for job", job); return -1; }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) :
               WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
    char result[32];
    snprintf(result, sizeof(result), "exit:%d\n", code);
    return write_status(id, result);
}

static void queue_check(void) {
    DIR *dir = opendir(PENDING_DIR);
    if (!dir) { log_error("open directory", PENDING_DIR); return; }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!is_job(entry->d_name)) continue;
        char *id = job_id(entry->d_name);
        char *pending = make_path(PENDING_DIR, entry->d_name, "");
        char *running = make_path(RUNNING_DIR, entry->d_name, "");
        if (!id || !pending || !running) {
            log_error("allocate job path", entry->d_name);
            free(id); free(pending); free(running); break;
        }
        if (rename(pending, running) < 0) {
            if (errno != ENOENT) log_error("claim job", pending);
        } else if (run_job(running, id) == 0 && unlink(running) < 0) {
            log_error("remove completed job", running);
        }
        free(id); free(pending); free(running);
        break;
    }
    closedir(dir);
}

int main(void) {
    setsid();
    umask(0);
    logline("rootd starting");
    /* Стартовые команды — до очереди: enforce-up.sh переводит SELinux в
     * Permissive, а до этого очередь (0700 shell:shell) домену adbd
     * недоступна — в Enforcing нет CAP_DAC_OVERRIDE, и mkdir падает EACCES. */
    run_startup_commands();
    if (prepare_queue() < 0) return 1;
    recover_running();
    for (;;) {
        queue_check();
        struct timespec delay = {0, 300000000};
        nanosleep(&delay, NULL);
    }
}
