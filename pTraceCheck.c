#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    pid_t child;
    long ptrace_ret;

    child = fork();
    if (child == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);  // Replace with any command you want to trace
    } else {
        // Parent process
        wait(NULL);  // Wait for child to stop
        printf("Child stopped, continuing...\n");
        ptrace_ret = ptrace(PTRACE_CONT, child, NULL, NULL);
        if (ptrace_ret == -1) {
            perror("ptrace");
            return 1;
        }
        wait(NULL);  // Wait for child to finish
        printf("Child finished.\n");
    }
    return 0;
}
