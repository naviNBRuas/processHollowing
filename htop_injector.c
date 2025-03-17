#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

#define DEBUG 0

#if DEBUG
#define debug(args...) fprintf(stderr, args)
#else
#define debug(args...)
#endif

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <process-name> <shared-library>\n", argv[0]);
    return 1;
  }

  char *process_name = argv[1];
  char *shared_library = argv[2];

  // Find the process with the given name
  pid_t pid = -1;
  char buffer[1024];
  FILE *fp = popen("ps aux | grep -v grep | grep \" " process_name "\" | awk '{print $2}'", "r");
  if (fp == NULL) {
    perror("popen");
    return 1;
  }
  if (fgets(buffer, sizeof(buffer), fp) != NULL) {
    pid = atoi(buffer);
  }
  pclose(fp);
  if (pid == -1) {
    fprintf(stderr, "Unable to find process named %s\n", process_name);
    return 1;
  }

  // Attach to the process
  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_SEIZE)");
    return 1;
  }
  if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_INTERRUPT)");
    return 1;
  }
  wait(NULL);

  // Inject the shared library
  struct user regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  regs.regs.rax = (long)dlopen;
  regs.regs.rdi = (long)shared_library;
  regs.regs.rsi = (long)RTLD_NOW;
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
  wait(NULL);
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  if (regs.regs.rax == 0) {
    fprintf(stderr, "Error injecting shared library: %s\n", dlerror());
    return 1;
  }

  // Detach from the process
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_DETACH)");
    return 1;
  }

  printf("Injected %s into process %s (PID %d)\n", shared_library, process_name, pid);
  return 0;
}