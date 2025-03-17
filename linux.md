# Process Hollowing on Linux using ptrace and Shellcode Injection

This C program demonstrates a technique known as "process hollowing" on Linux systems using the ptrace system call to inject shellcode into a legitimate process (`/bin/ls` in this case). Process hollowing involves injecting malicious code into a running process while maintaining its original functionality.

## Purpose

The purpose of this program (`linux.c`) is to illustrate the following:
- Pausing a child process (`/bin/ls`) using `SIGSTOP`.
- Attaching to the paused process using `ptrace`.
- Finding a suitable writable and executable memory region in the child process.
- Injecting predefined shellcode into the identified memory region.
- Modifying the instruction pointer (`rip`) of the child process to execute the injected shellcode.
- Detaching from the child process and allowing it to resume execution.
- Verifying the execution of the injected code by checking process list output.

## Requirements

- Linux operating system with `gcc` compiler installed.
- Root or sufficient privileges to use `ptrace` for debugging.

## How to Use

1. **Compile the Program:**

```bash
   gcc -o process_hollowing linux.c -Wall
```
2. Run the Program:

```bash
Copiar código
./process_hollowing
```
3. Expected Output:
The program will output debug messages indicating the steps it performs, including:

- Starting the child process (/bin/ls).
- Pausing the child process with SIGSTOP.
- Attaching to the child process using ptrace.
- Finding and selecting a suitable memory region for shellcode injection.
- Injecting predefined shellcode to print "Hello, World!".
- Modifying the instruction pointer of the child process to execute the shellcode.
- Detaching from the child process and allowing it to resume.
- Verifying that /bin/ls is executed and listing its process in the system.
4. Notes:

- The shellcode used in this example prints "Hello, World!" and then exits. Modify the shellcode (shellcode[] array) to suit your specific requirements.
- Ensure that you have appropriate permissions and legal authorization before using techniques like process hollowing.
- This program is intended for educational purposes and understanding of system programming concepts.