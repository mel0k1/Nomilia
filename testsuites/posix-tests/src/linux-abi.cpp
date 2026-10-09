#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "testsuite.hpp"

extern "C" const unsigned char nomilia_linux_hello_blob[];
extern "C" const unsigned long nomilia_linux_hello_size;

// Nomilia: an unmodified static Linux binary (raw Linux syscalls) must run
// under the linux-sysdeps kernel layer and exit with its own status.
DEFINE_TEST(linux_abi_static_hello, ([] {
        const char *path = "/tmp/nomilia-linux-hello";

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_hello_blob, nomilia_linux_hello_size);
        assert(n == (ssize_t)nomilia_linux_hello_size);
        assert(!close(fd));
        assert(!chmod(path, 0755));

        pid_t pid = fork();
        assert(pid >= 0);
        if(!pid) {
                char *argv[] = { const_cast<char *>(path), nullptr };
                char *envp[] = { nullptr };
                execve(path, argv, envp);
                _exit(127); // execve() failed.
        }

        int status = 0;
        pid_t w = waitpid(pid, &status, 0);
        assert(w == pid);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == 42);

        assert(!unlink(path));
}));
