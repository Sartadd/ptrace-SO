#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <time.h>

void log_syscall(pid_t pid, struct user_regs_struct regs, long syscall_ret, int entering) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    if (entering) {
        printf("[PID %d] [%ld.%09ld] Entering syscall: %lld (arg1: %lld, arg2: %lld, arg3: %lld)\n",
               pid, ts.tv_sec, ts.tv_nsec,
               (long long)regs.orig_rax,
               (long long)regs.rdi,
               (long long)regs.rsi,
               (long long)regs.rdx);
    } else {
       printf("[PID %d] [%ld.%09ld] Exiting syscall: %lld -> return: %lld\n",
       pid, ts.tv_sec, ts.tv_nsec,
       (long long)regs.orig_rax,
       (long long)syscall_ret);

    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <comando> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else {
        int status;
        waitpid(child, &status, 0);
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);

        int entering = 1;
        struct user_regs_struct regs;

        while (1) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);

#ifdef __x86_64__
            long syscall_num = regs.orig_rax;
#else
#error Este código é apenas para arquitetura x86_64
#endif

            if (entering) {
                log_syscall(child, regs, 0, 1);
                entering = 0;
            } else {
                long retval = regs.rax;
                log_syscall(child, regs, retval, 0);
                entering = 1;
            }

            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }

    return 0;
}
