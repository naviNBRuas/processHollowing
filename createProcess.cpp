#include <iostream>
#include <unistd.h>
#include <sys/wait.h>

pid_t create_process() {
    pid_t pid = fork();

    if (pid == -1) {
        // Fork failed
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/bin/sleep", "vhost", "10000", NULL); // Use sleep command as an example
        perror("execl"); // This line will only execute if execl fails
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        std::cout << "Child process created with PID: " << pid << std::endl;
        return pid;
    }
}

int main() {
    pid_t pid = create_process();

    int status;
    waitpid(pid, &status, 0); // Wait for the child process to terminate

    if (WIFEXITED(status)) {
        std::cout << "Child process exited with status " << WEXITSTATUS(status) << std::endl;
    } else {
        std::cout << "Child process did not exit normally" << std::endl;
    }

    return 0;
}
