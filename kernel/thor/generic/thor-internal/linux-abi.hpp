#pragma once

#include <stddef.h>

namespace thor {

struct SyscallImageAccessor;

// Nomilia: dispatcher for Linux-ABI (musl/glibc) syscall numbers.
// Returns true when the syscall already interrupted the thread (exit path);
// the dispatcher must skip handleConditions() in that case.
bool linuxHandleSyscall(SyscallImageAccessor image);

} // namespace thor
