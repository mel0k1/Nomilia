#pragma once

#include <stddef.h>

namespace thor {

struct SyscallImageAccessor;

// Nomilia: dispatcher for Linux-ABI (musl/glibc) syscall numbers.
void linuxHandleSyscall(SyscallImageAccessor image);

} // namespace thor
