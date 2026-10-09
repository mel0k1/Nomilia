#pragma once

#include <array>
#include <cstdint>
#include <memory>

#include <async/result.hpp>
#include <helix/ipc.hpp>

struct Process;

// Result of a Linux syscall served in posix: most calls resume the thread
// with `value` (result or -errno) in RAX; the fork-child and execve-success
// paths manage their own resume.
struct LinuxSyscallOutcome {
	bool resume = true;
	int64_t value = 0;
};

async::result<LinuxSyscallOutcome> handleLinuxSyscall(std::shared_ptr<Process> self,
		helix::BorrowedDescriptor thread, uint64_t nr,
		const std::array<uint64_t, 6> &args);
