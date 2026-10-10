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

extern "C" const unsigned char nomilia_linux_files_blob[];
extern "C" const unsigned long nomilia_linux_files_size;

// Nomilia: a static Linux binary exercising the file syscall upcall path.
DEFINE_TEST(linux_abi_files, ([] {
        const char *path = "/tmp/nomilia-linux-files";

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_files_blob, nomilia_linux_files_size);
        assert(n == (ssize_t)nomilia_linux_files_size);
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
        assert(WEXITSTATUS(status) == 43);

        assert(!unlink(path));
}));

extern "C" const unsigned char nomilia_linux_forky_blob[];
extern "C" const unsigned long nomilia_linux_forky_size;

// Nomilia: fork/wait4/exec chain running entirely inside the Linux persona.
DEFINE_TEST(linux_abi_fork_exec, ([] {
        const char *path = "/tmp/nomilia-linux-forky";

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_forky_blob, nomilia_linux_forky_size);
        assert(n == (ssize_t)nomilia_linux_forky_size);
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
        assert(WEXITSTATUS(status) == 45);

        assert(!unlink(path));
}));

extern "C" const unsigned char nomilia_linux_dirstat_blob[];
extern "C" const unsigned long nomilia_linux_dirstat_size;

// Nomilia: getdents64/ioctl/statx/pipe2/faccessat on a Linux binary.
DEFINE_TEST(linux_abi_dirstat, ([] {
        const char *path = "/tmp/nomilia-linux-dirstat";

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_dirstat_blob, nomilia_linux_dirstat_size);
        assert(n == (ssize_t)nomilia_linux_dirstat_size);
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
        printf("posix-tests: linux_abi_dirstat child exit = %d\n", WEXITSTATUS(status));
        assert(WEXITSTATUS(status) == 46);

        assert(!unlink(path));
}));

\
extern "C" const unsigned char nomilia_linux_socksig_blob[];
extern "C" const unsigned long nomilia_linux_socksig_size;

// Nomilia: socketpair roundtrip and rt_sigaction/rt_sigprocmask with a
// handler delivered through the Linux rt_sigframe path.
DEFINE_TEST(linux_abi_socksig, ([] {
        const char *path = "/tmp/nomilia-linux-socksig";

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_socksig_blob, nomilia_linux_socksig_size);
        assert(n == (ssize_t)nomilia_linux_socksig_size);
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
        printf("posix-tests: linux_abi_socksig child exit = %d\n", WEXITSTATUS(status));
        assert(WEXITSTATUS(status) == 47);

        assert(!unlink(path));
}));

extern "C" const unsigned char nomilia_linux_nomilia_ld_blob[];
extern "C" const unsigned long nomilia_linux_nomilia_ld_size;

extern "C" const unsigned char nomilia_linux_dynhello_blob[];
extern "C" const unsigned long nomilia_linux_dynhello_size;

// Nomilia: a dynamic Linux ELF (PT_INTERP) is loaded together with its
// interpreter; the nomilia-ld.so test loader jumps to AT_ENTRY.
DEFINE_TEST(linux_abi_dyn, ([] {
        const char *ldPath = "/tmp/nomilia-ld.so";
        const char *path = "/tmp/nomilia-dynhello";

        int fd = open(ldPath, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        ssize_t n = write(fd, nomilia_linux_nomilia_ld_blob, nomilia_linux_nomilia_ld_size);
        assert(n == (ssize_t)nomilia_linux_nomilia_ld_size);
        assert(!close(fd));
        assert(!chmod(ldPath, 0755));

        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        assert(fd >= 0);
        n = write(fd, nomilia_linux_dynhello_blob, nomilia_linux_dynhello_size);
        assert(n == (ssize_t)nomilia_linux_dynhello_size);
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
        printf("posix-tests: linux_abi_dyn child exit = %d\n", WEXITSTATUS(status));
        assert(WEXITSTATUS(status) == 48);

        assert(!unlink(ldPath));
        assert(!unlink(path));
}));

// Nomilia: real Linux payloads (built by ci/payloads/build-musl-busybox.sh and
// delivered into the image) must run through the linux-abi layer: static
// busybox directly, dynamic binaries through the ld-musl PT_INTERP path.
DEFINE_TEST(linux_abi_payloads, ([] {
        auto spawn = [](const char *path, char *argv[]) -> int {
                pid_t pid = fork();
                assert(pid >= 0);
                if(!pid) {
                        char *envp[] = { nullptr };
                        execve(path, argv, envp);
                        _exit(127); // execve() failed.
                }

                int status = 0;
                pid_t w = waitpid(pid, &status, 0);
                assert(w == pid);
                if(!WIFEXITED(status)) {
                        printf("posix-tests: linux_abi_payloads: %s killed by signal %d\n",
                                        path, WTERMSIG(status));
                        return -1;
                }
                return WEXITSTATUS(status);
        };

        {
                char argv0[] = "busybox";
                char argv1[] = "sh";
                char argv2[] = "-c";
                char argv3[] = "echo nomilia-busybox-static";
                char *argv[] = { argv0, argv1, argv2, argv3, nullptr };
                int r = spawn("/usr/bin/busybox", argv);
                printf("posix-tests: linux_abi_payloads: static busybox exit = %d\n", r);
                assert(r == 0);
        }
        {
                char argv0[] = "hello-dynamic";
                char *argv[] = { argv0, nullptr };
                int r = spawn("/usr/bin/hello-dynamic", argv);
                printf("posix-tests: linux_abi_payloads: hello-dynamic exit = %d\n", r);
                assert(r == 0);
        }
        {
                char argv0[] = "busybox-dynamic";
                char argv1[] = "echo";
                char argv2[] = "nomilia-busybox-dynamic";
                char *argv[] = { argv0, argv1, argv2, nullptr };
                int r = spawn("/usr/bin/busybox-dynamic", argv);
                printf("posix-tests: linux_abi_payloads: busybox-dynamic exit = %d\n", r);
                assert(r == 0);
        }
}));
