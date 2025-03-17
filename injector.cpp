#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void inject_code(pid_t pid) {
  // Attach to the target process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    perror("ptrace attach");
    exit(EXIT_FAILURE);
  }

  // Wait for the process to stop
  waitpid(pid, NULL, 0);

  // Injected code
  const char injected_code[] =
      "\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x31\xff\x48\x31\xf6\x48\x31\xd2"
      "\xb2\x0d\x0f\x05\xb0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff"
      "Hello, World!\n";

  size_t code_size = sizeof(injected_code);

  // Get the registers
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
    perror("ptrace getregs");
    exit(EXIT_FAILURE);
  }

  // Save original registers
  struct user_regs_struct original_regs = regs;

  // Allocate memory in the target process using mmap syscall
  regs.rax = 9;         // mmap syscall number
  regs.rdi = 0;         // NULL (let the kernel choose the address)
  regs.rsi = code_size; // size of the allocated memory
  regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // memory protection
  regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;        // flags
  regs.r8 = -1;                                  // file descriptor
  regs.r9 = 0;                                   // offset
  regs.orig_rax = -1; // Clear orig_rax to ensure proper syscall entry
  regs.rip -= 2; // Adjust instruction pointer to ensure correct syscall address

  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
    perror("ptrace setregs");
    exit(EXIT_FAILURE);
  }

  // Run mmap syscall in the target process
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
    perror("ptrace syscall (entry)");
    exit(EXIT_FAILURE);
  }
  waitpid(pid, NULL, 0);

  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
    perror("ptrace syscall (exit)");
    exit(EXIT_FAILURE);
  }
  waitpid(pid, NULL, 0);

  // Get the address of the allocated memory
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
    perror("ptrace getregs");
    exit(EXIT_FAILURE);
  }

  void *remote_code = (void *)regs.rax;

  // Write the injected code to the target process
  for (size_t i = 0; i < code_size; i += sizeof(long)) {
    if (ptrace(PTRACE_POKETEXT, pid, (char *)remote_code + i,
               *(long *)(injected_code + i)) == -1) {
      perror("ptrace poketext");
      exit(EXIT_FAILURE);
    }
  }

  // Restore original registers and set instruction pointer to the injected code
  original_regs.rip = (long)remote_code;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &original_regs) == -1) {
    perror("ptrace setregs");
    exit(EXIT_FAILURE);
  }

  // Detach from the process
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
    perror("ptrace detach");
    exit(EXIT_FAILURE);
  }

  std::cout << "Code injected successfully." << std::endl;
}

int main() {
  pid_t pid;
  std::cout << "Enter PID of the target process: ";
  std::cin >> pid;

  inject_code(pid);

  return 0;
}
