#include <string.h>

#include <async/algorithm.hpp>
#include <async/cancellation.hpp>

#include <hel.h>
#include <thor-internal/address-space.hpp>
#include <thor-internal/arch-generic/cpu.hpp>
#include <thor-internal/arch-generic/timer.hpp>
#include <thor-internal/coroutine.hpp>
#include <thor-internal/debug.hpp>
#include <thor-internal/futex.hpp>
#include <thor-internal/hierarchy.hpp>
#include <thor-internal/irq.hpp>
#include <thor-internal/linux-abi.hpp>
#include <thor-internal/memory-view.hpp>
#include <thor-internal/random.hpp>
#include <thor-internal/thread.hpp>
#include <thor-internal/timer.hpp>

#ifdef __x86_64__
#include <thor-internal/arch/pic.hpp>
#endif

// User-space memory helpers implemented in hel.cpp (external linkage).
bool readUserMemory(void *kernelPtr, const void *userPtr, size_t size);
bool writeUserMemory(void *userPtr, const void *kernelPtr, size_t size);

namespace thor {


namespace {

// Linux x86_64 errno values, returned as negative syscall results.
constexpr uint64_t kLinuxEbadf = 9;
constexpr uint64_t kLinuxEagain = 11;
constexpr uint64_t kLinuxEnomem = 12;
constexpr uint64_t kLinuxEfault = 14;
constexpr uint64_t kLinuxEintr = 4;
constexpr uint64_t kLinuxEinval = 22;
constexpr uint64_t kLinuxEnosys = 38;
constexpr uint64_t kLinuxEtimeout = 110;

// Linux x86_64 syscall numbers (asm-generic/unistd_64.h).
enum LinuxSyscall : uint64_t {
	kLinuxNrRead = 0,
	kLinuxNrWrite = 1,
	kLinuxNrMmap = 9,
	kLinuxNrMprotect = 10,
	kLinuxNrMunmap = 11,
	kLinuxNrBrk = 12,
	kLinuxNrSchedYield = 24,
	kLinuxNrMadvise = 28,
	kLinuxNrGetpid = 39,
	kLinuxNrUname = 63,
	kLinuxNrGettimeofday = 96,
	kLinuxNrGetuid = 102,
	kLinuxNrGetgid = 104,
	kLinuxNrGeteuid = 107,
	kLinuxNrGetegid = 108,
	kLinuxNrTime = 201,
	kLinuxNrFutex = 202,
	kLinuxNrExit = 60,
	kLinuxNrGettid = 186,
	kLinuxNrArchPrctl = 158,
	kLinuxNrSetTidAddress = 218,
	kLinuxNrClockGettime = 228,
	kLinuxNrClockGetres = 229,
	kLinuxNrExitGroup = 231,
	kLinuxNrSetRobustList = 273,
	kLinuxNrGetrandom = 318,
	// Forwarded to the POSIX subsystem via the observe upcall.
	kLinuxNrOpen = 2,
	kLinuxNrClose = 3,
	kLinuxNrStat = 4,
	kLinuxNrFstat = 5,
	kLinuxNrLstat = 6,
	kLinuxNrLseek = 8,
	kLinuxNrPread64 = 17,
	kLinuxNrReadv = 19,
	kLinuxNrWritev = 20,
	kLinuxNrPwrite64 = 18,
	kLinuxNrDup = 32,
	kLinuxNrDup2 = 33,
	kLinuxNrFork = 57,
	kLinuxNrVfork = 58,
	kLinuxNrExecve = 59,
	kLinuxNrWait4 = 61,
	kLinuxNrGetcwd = 79,
	kLinuxNrGetppid = 110,
	kLinuxNrOpenat = 257,
	kLinuxNrFstatat = 262,
	kLinuxNrDup3 = 292,
	kLinuxNrIoctl = 16,
	kLinuxNrPipe = 22,
	kLinuxNrGetdents64 = 217,
	kLinuxNrFaccessat = 269,
	kLinuxNrPipe2 = 293,
	kLinuxNrStatx = 332,
	kLinuxNrFaccessat2 = 439,
	// v4: sockets and signals, also served by the POSIX subsystem.
	kLinuxNrRtSigaction = 13,
	kLinuxNrRtSigprocmask = 14,
	kLinuxNrRtSigreturn = 15,
	kLinuxNrSocket = 41,
	kLinuxNrConnect = 42,
	kLinuxNrAccept = 43,
	kLinuxNrSendto = 44,
	kLinuxNrRecvfrom = 45,
	kLinuxNrSendmsg = 46,
	kLinuxNrRecvmsg = 47,
	kLinuxNrShutdown = 48,
	kLinuxNrBind = 49,
	kLinuxNrListen = 50,
	kLinuxNrGetsockname = 51,
	kLinuxNrGetpeername = 52,
	kLinuxNrSocketpair = 53,
	kLinuxNrSetsockopt = 54,
	kLinuxNrGetsockopt = 55,
	kLinuxNrKill = 62,
	kLinuxNrTgkill = 234,
	kLinuxNrAccept4 = 288,
};

// protocols/posix/supercalls.hpp: superExit. Thor only forwards the number;
// posix performs the full process death flow when it observes it.
constexpr uint64_t kPosixSuperExit = 4;

// protocols/posix/supercalls.hpp: superLinuxSyscall. File/process Linux
// syscalls interrupt the thread; posix observes it, serves the call through
// its VFS and resumes the thread with the result in RAX.
constexpr uint64_t kPosixSuperLinuxSyscall = 19;

// Per-address-space state for the Linux ABI (program break, clear_child_tid).
struct LinuxAsState {
	AddressSpace *space;
	uintptr_t curBrk;
	void *clearTid;
};

constexpr uintptr_t kLinuxBrkBase = 0x10000000;
constexpr uintptr_t kLinuxBrkLimit = 0x8000000; // 128 MiB of Linux heap.

frg::ticket_spinlock gLinuxStateMutex;

	// v1: fixed pool; Linux-personality processes are few.
	constexpr size_t kMaxLinuxStates = 16;
	LinuxAsState gLinuxStatePool[kMaxLinuxStates];
	size_t gLinuxStateCount = 0;

	LinuxAsState *getLinuxState(AddressSpace *space) {
		for(size_t i = 0; i < gLinuxStateCount; i++)
			if(gLinuxStatePool[i].space == space)
				return &gLinuxStatePool[i];
		if(gLinuxStateCount == kMaxLinuxStates)
			return nullptr;
		auto *s = &gLinuxStatePool[gLinuxStateCount++];
		s->space = space;
		s->curBrk = kLinuxBrkBase;
		s->clearTid = nullptr;
		return s;
	}

uint32_t mapLinuxProt(uint64_t prot) {
	uint32_t mapFlags = 0;
	if(prot & 0x1)
		mapFlags |= VirtualSpace::kMapProtRead;
	if(prot & 0x2)
		mapFlags |= VirtualSpace::kMapProtWrite;
	if(prot & 0x4)
		mapFlags |= VirtualSpace::kMapProtExecute;
	return mapFlags;
}

} // anonymous namespace

bool linuxHandleSyscall(SyscallImageAccessor image) {
#ifdef __x86_64__
	// Linux x86_64 passes the syscall number in RAX and the arguments in
	// RDI/RSI/RDX/R10/R8/R9, which are shifted relative to the Hel slots.
	uint64_t nr = *image.in2();
	uint64_t a0 = *image.number();
	uint64_t a1 = *image.in0();
	uint64_t a2 = *image.in1();
	uint64_t a3 = *image.in5();
	uint64_t a4 = *image.in3();
	uint64_t a5 = *image.in4();

	auto thisThread = getCurrentThread();

	// Linux returns the result (or -errno) in RAX.
	auto ret = [&](uint64_t v) { *image.in2() = v; };

	switch(nr) {
	case kLinuxNrMmap: {
		uintptr_t addr = a0;
		size_t length = (size_t)a1;
		uint32_t flags = (uint32_t)a3;
		constexpr uint32_t kLinuxMapPrivate = 0x02;
		constexpr uint32_t kLinuxMapFixed = 0x10;
		constexpr uint32_t kLinuxMapAnon = 0x20;
		if(!length) {
			ret(-kLinuxEinval);
			break;
		}
		// Only anonymous private mappings are supported for now.
		if(!(flags & kLinuxMapAnon) || (intptr_t)a4 != -1
				|| (flags & ~(kLinuxMapPrivate | kLinuxMapFixed | kLinuxMapAnon))) {
			ret(-kLinuxEnosys);
			break;
		}
		length = (length + kPageSize - 1) & ~(kPageSize - 1);
		uint32_t mapFlags = mapLinuxProt(a2);
		if(flags & kLinuxMapFixed) {
			if(!addr || (addr & (kPageSize - 1))) {
				ret(-kLinuxEinval);
				break;
			}
			mapFlags |= VirtualSpace::kMapFixed;
		}else{
			mapFlags |= VirtualSpace::kMapPreferTop;
		}
		auto memoryOutcome = AllocatedMemory::create(rootHierarchy(), length);
		if(!memoryOutcome) {
			ret(-kLinuxEnomem);
			break;
		}
		auto sliceOutcome = MemorySlice::create(std::move(*memoryOutcome), 0, length);
		if(!sliceOutcome) {
			ret(-kLinuxEnomem);
			break;
		}
		auto space = thisThread->getAddressSpace();
		auto mapResult = Thread::asyncBlockCurrent(
			space->map(std::move(*sliceOutcome), (VirtualAddr)addr, 0, length, mapFlags),
			thisThread->pagingWorkQueue().get());
		if(!mapResult) {
			ret(-kLinuxEnomem);
			break;
		}
		ret((uint64_t)mapResult.value());
	} break;
	case kLinuxNrMprotect: {
		uintptr_t addr = a0;
		size_t length = (size_t)a1;
		if(!addr || (addr & (kPageSize - 1)) || !length) {
			ret(-kLinuxEinval);
			break;
		}
		length = (length + kPageSize - 1) & ~(kPageSize - 1);
		auto space = thisThread->getAddressSpace();
		auto outcome = Thread::asyncBlockCurrent(
			space->protect((VirtualAddr)addr, length, mapLinuxProt(a2)),
			thisThread->pagingWorkQueue().get());
		ret(!outcome ? -kLinuxEnomem : 0);
	} break;
	case kLinuxNrMunmap: {
		uintptr_t addr = a0;
		size_t length = (size_t)a1;
		if(!addr || (addr & (kPageSize - 1)) || !length) {
			ret(-kLinuxEinval);
			break;
		}
		length = (length + kPageSize - 1) & ~(kPageSize - 1);
		auto space = thisThread->getAddressSpace();
		auto outcome = Thread::asyncBlockCurrent(
			space->unmap((VirtualAddr)addr, length),
			thisThread->pagingWorkQueue().get());
		ret(!outcome ? -kLinuxEinval : 0);
	} break;
	case kLinuxNrMadvise:
		ret(0); // no-op
		break;
	case kLinuxNrBrk: {
		LinuxAsState *state;
		{
			auto lock = frg::guard(&gLinuxStateMutex);
			state = getLinuxState(thisThread->getAddressSpace().get());
		}
		uintptr_t want = a0;
		if(!state) {
			ret(kLinuxBrkBase);
			break;
		}
		if(!want) {
			ret(state->curBrk);
			break;
		}
		if(want < kLinuxBrkBase || want >= kLinuxBrkBase + kLinuxBrkLimit) {
			// Like Linux: failure returns the current break.
			ret(state->curBrk);
			break;
		}
		uintptr_t oldEnd = (state->curBrk + kPageSize - 1) & ~(kPageSize - 1);
		uintptr_t newEnd = (want + kPageSize - 1) & ~(kPageSize - 1);
		bool ok = true;
		if(newEnd > oldEnd) {
			auto memoryOutcome = AllocatedMemory::create(rootHierarchy(), newEnd - oldEnd);
			smarter::shared_ptr<MemorySlice> slice;
			if(memoryOutcome) {
				auto sliceOutcome = MemorySlice::create(std::move(*memoryOutcome),
					0, newEnd - oldEnd);
				if(sliceOutcome)
					slice = std::move(*sliceOutcome);
			}
			if(slice) {
				auto space = thisThread->getAddressSpace();
				auto mapResult = Thread::asyncBlockCurrent(
					space->map(std::move(slice), (VirtualAddr)oldEnd, 0, newEnd - oldEnd,
						VirtualSpace::kMapFixed | VirtualSpace::kMapProtRead
						| VirtualSpace::kMapProtWrite),
					thisThread->pagingWorkQueue().get());
				if(!mapResult)
					ok = false;
			}else{
				ok = false;
			}
		}else if(newEnd < oldEnd) {
			auto space = thisThread->getAddressSpace();
			auto outcome = Thread::asyncBlockCurrent(
				space->unmap((VirtualAddr)newEnd, oldEnd - newEnd),
				thisThread->pagingWorkQueue().get());
			if(!outcome)
				ok = false;
		}
		if(ok) {
			state->curBrk = want;
			ret(want);
		}else{
			ret(state->curBrk);
		}
	} break;
	case kLinuxNrSchedYield:
		Thread::deferCurrent();
		ret(0);
		break;
	case kLinuxNrUname: {
		struct LinuxUtsname {
			char sysname[65]; char nodename[65]; char release[65];
			char version[65]; char machine[65]; char domainname[65];
		};
		LinuxUtsname buf{};
		memcpy(buf.sysname, "Linux", sizeof("Linux"));
		memcpy(buf.nodename, "nomilia", sizeof("nomilia"));
		memcpy(buf.release, "6.1.0-nomilia", sizeof("6.1.0-nomilia"));
		memcpy(buf.version, "#1 SMP Nomilia (Linux ABI)", sizeof("#1 SMP Nomilia (Linux ABI)"));
		memcpy(buf.machine, "x86_64", sizeof("x86_64"));
		memcpy(buf.domainname, "(none)", sizeof("(none)"));
		if(!writeUserMemory((void *)a0, &buf, sizeof(buf))) {
			ret(-kLinuxEfault);
			break;
		}
		ret(0);
	} break;
	case kLinuxNrGetuid:
	case kLinuxNrGeteuid:
	case kLinuxNrGetgid:
	case kLinuxNrGetegid:
		ret(0); // TODO: real credentials via the POSIX subsystem.
		break;
	case kLinuxNrExit:
	case kLinuxNrExitGroup:
		// Hand the exit to posix via the managarm exit supercall so the full
		// death flow runs (thread killed, parent notified, code propagated).
		*image.in0() = a0; // posix reads the code from the Hel arg0 slot.
		Thread::interruptCurrent(static_cast<Interrupt>(kIntrSuperCall + kPosixSuperExit), image, {});
		return true;
	case kLinuxNrSetTidAddress: {
		auto lock = frg::guard(&gLinuxStateMutex);
		auto *state = getLinuxState(thisThread->getAddressSpace().get());
		if(state)
			state->clearTid = (void *)a0;
		ret(1);
	} break;
	case kLinuxNrSetRobustList:
		ret(0); // Robust futexes are a no-op without thread exits.
		break;
	case kLinuxNrArchPrctl: {
	#ifdef __x86_64__
		// FS base survives the syscall and is restored by save/restoreExecutor.
		constexpr uint64_t kArchSetGs = 0x1001;
		constexpr uint64_t kArchSetFs = 0x1002;
		constexpr uint64_t kArchGetFs = 0x1003;
		if(a0 == kArchSetFs) {
			common::x86::wrmsr(common::x86::kMsrIndexFsBase, a1);
			ret(0);
		}else if(a0 == kArchGetFs) {
			uint64_t v = common::x86::rdmsr(common::x86::kMsrIndexFsBase);
			if(!writeUserMemory((void *)a1, &v, sizeof(v)))
				ret(-kLinuxEfault);
			else
				ret(0);
		}else if(a0 == kArchSetGs) {
			// The user GS base lives in the kernel-GS MSR (swapgs pair).
			common::x86::wrmsr(common::x86::kMsrIndexKernelGsBase, a1);
			ret(0);
		}else{
			ret(-kLinuxEinval);
		}
	#else
		ret(-kLinuxEnosys);
	#endif
	} break;
	case kLinuxNrClockGettime: {
		// CLOCK_REALTIME: 0, MONOTONIC: 1, MONOTONIC_RAW: 4, BOOTTIME: 7.
		if(a0 != 0 && a0 != 1 && a0 != 4 && a0 != 7) {
			ret(-kLinuxEinval);
			break;
		}
		// TODO: wall-clock offset (RTC/clocktracker); boot-relative realtime for now.
		uint64_t nanos = getClockNanos();
		struct { int64_t sec; int64_t nsec; } ts;
		ts.sec = nanos / 1000000000ull;
		ts.nsec = nanos % 1000000000ull;
		if(!writeUserMemory((void *)a1, &ts, sizeof(ts))) {
			ret(-kLinuxEfault);
			break;
		}
		ret(0);
	} break;
	case kLinuxNrClockGetres: {
		struct { int64_t sec; int64_t nsec; } ts{0, 1};
		if(a0 != 0 && a0 != 1 && a0 != 4 && a0 != 7) {
			ret(-kLinuxEinval);
			break;
		}
		if(a1 && !writeUserMemory((void *)a1, &ts, sizeof(ts))) {
			ret(-kLinuxEfault);
			break;
		}
		ret(0);
	} break;
	case kLinuxNrGettimeofday: {
		uint64_t nanos = getClockNanos();
		struct { int64_t sec; int64_t usec; } tv;
		tv.sec = nanos / 1000000000ull;
		tv.usec = (nanos % 1000000000ull) / 1000ull;
		if(a0 && !writeUserMemory((void *)a0, &tv, sizeof(tv))) {
			ret(-kLinuxEfault);
			break;
		}
		ret(0);
	} break;
	case kLinuxNrTime: {
		uint64_t nanos = getClockNanos();
		int64_t sec = nanos / 1000000000ull;
		if(a0 && !writeUserMemory((void *)a0, &sec, sizeof(sec))) {
			ret(-kLinuxEfault);
			break;
		}
		ret((uint64_t)sec);
	} break;
	case kLinuxNrGetrandom: {
		char bounce[128];
		size_t want = (size_t)a1 < 128 ? (size_t)a1 : 128;
		size_t got = generateRandomBytes(bounce, want);
		if(!writeUserMemory((void *)a0, bounce, got)) {
			ret(-kLinuxEfault);
			break;
		}
		ret((uint64_t)got);
	} break;
	case kLinuxNrFutex: {
		uintptr_t uaddr = a0;
		// Strip FUTEX_PRIVATE_FLAG (0x80) and FUTEX_CLOCK_REALTIME (0x100).
		uint32_t cmd = (uint32_t)a1 & ~uint32_t(0x80 | 0x100);
		uint32_t val = (uint32_t)a2;
		auto space = thisThread->getAddressSpace();
		switch(cmd) {
		case 0: { // FUTEX_WAIT
			if(uaddr & (sizeof(int) - 1)) {
				ret(-kLinuxEinval);
				break;
			}
			Error waitErr = Error::success;
			bool timedOut = false;
			if(a3) {
				struct { int64_t sec; int64_t nsec; } ts;
				if(!readUserMemory(&ts, (void *)a3, sizeof(ts))) {
					ret(-kLinuxEfault);
					break;
				}
				// Linux FUTEX_WAIT timeouts are relative.
				uint64_t deadline = getClockNanos()
					+ uint64_t(ts.sec) * 1000000000ull + uint64_t(ts.nsec);
				Thread::asyncBlockCurrentInterruptible(async::lambda([&](async::cancellation_token ct) {
					return async::race_and_cancel(
						async::lambda([&](async::cancellation_token cancellation) -> coroutine<void> {
							waitErr = co_await getGlobalFutexRealm()->wait(
								space->globalFutexSpace(), uaddr, val, cancellation);
						}),
						async::lambda([&](async::cancellation_token cancellation) -> coroutine<void> {
							timedOut = co_await generalTimerEngine()->sleep(deadline, cancellation);
						}),
						async::lambda([ct](async::cancellation_token cancellation) {
							return async::suspend_indefinitely(ct, cancellation);
						}))
					;
				}), thisThread->pagingWorkQueue().get());
				if(waitErr == Error::cancelled)
					ret(timedOut ? -kLinuxEtimeout : -kLinuxEintr);
				else if(waitErr == Error::futexRace)
					ret(-kLinuxEagain);
				else if(waitErr == Error::fault)
					ret(-kLinuxEfault);
				else if(waitErr != Error::success)
					ret(-kLinuxEinval);
				else
					ret(0);
			}else{
				auto outcome = Thread::asyncBlockCurrentInterruptible(
					async::lambda([&](async::cancellation_token ct) {
						return getGlobalFutexRealm()->wait(
							space->globalFutexSpace(), uaddr, val, ct);
					}), thisThread->pagingWorkQueue().get());
				if(outcome == Error::futexRace)
					ret(-kLinuxEagain);
				else if(outcome == Error::fault)
					ret(-kLinuxEfault);
				else if(outcome != Error::success)
					ret(-kLinuxEintr);
				else
					ret(0);
			}
		} break;
		case 1: { // FUTEX_WAKE
			auto result = Thread::asyncBlockCurrent(
				getGlobalFutexRealm()->wake(space->globalFutexSpace(), uaddr, val),
				thisThread->pagingWorkQueue().get());
			// The realm does not report the woken count; report the requested one.
			ret(!result ? -kLinuxEfault : (uint64_t)val);
		} break;
		case 3:
		case 4: { // FUTEX_REQUEUE / FUTEX_CMP_REQUEUE
			unsigned int requeueCount = (uint32_t)a3;
			uintptr_t uaddr2 = a4;
			int expected;
			if(cmd == 4) {
				expected = (int)a5;
			}else{
				// Plain FUTEX_REQUEUE has no comparison; use the current value.
				if(!readUserMemory(&expected, (void *)uaddr, sizeof(int))) {
					ret(-kLinuxEfault);
					break;
				}
			}
			auto result = Thread::asyncBlockCurrent(
				getGlobalFutexRealm()->requeue(space->globalFutexSpace(), uaddr, expected,
					space->globalFutexSpace(), uaddr2, val, requeueCount),
				thisThread->pagingWorkQueue().get());
			if(!result)
				ret(result.error() == Error::futexRace ? -kLinuxEagain : -kLinuxEfault);
			else
				ret((uint64_t)val + requeueCount);
		} break;
		default:
			ret(-kLinuxEnosys);
		}
	} break;
	// File/process syscalls run in the POSIX subsystem. The registers are
	// left untouched so that posix can decode the Linux call from them
	// (nr in RAX, args in RDI/RSI/RDX/R10/R8/R9) and resume with -errno.
	case kLinuxNrRead:
	case kLinuxNrWrite:
	case kLinuxNrOpen:
	case kLinuxNrClose:
	case kLinuxNrStat:
	case kLinuxNrFstat:
	case kLinuxNrLstat:
	case kLinuxNrLseek:
	case kLinuxNrPread64:
	case kLinuxNrReadv:
	case kLinuxNrWritev:
	case kLinuxNrPwrite64:
	case kLinuxNrDup:
	case kLinuxNrDup2:
	case kLinuxNrGetpid:
	case kLinuxNrFork:
	case kLinuxNrVfork:
	case kLinuxNrExecve:
	case kLinuxNrWait4:
	case kLinuxNrGetcwd:
	case kLinuxNrGetppid:
	case kLinuxNrGettid:
	case kLinuxNrOpenat:
	case kLinuxNrFstatat:
	case kLinuxNrDup3:
	case kLinuxNrIoctl:
	case kLinuxNrPipe:
	case kLinuxNrGetdents64:
	case kLinuxNrFaccessat:
	case kLinuxNrFaccessat2:
	case kLinuxNrStatx:
	case kLinuxNrPipe2:
	case kLinuxNrRtSigaction:
	case kLinuxNrRtSigprocmask:
	case kLinuxNrRtSigreturn:
	case kLinuxNrSocket:
	case kLinuxNrConnect:
	case kLinuxNrAccept:
	case kLinuxNrSendto:
	case kLinuxNrRecvfrom:
	case kLinuxNrSendmsg:
	case kLinuxNrRecvmsg:
	case kLinuxNrShutdown:
	case kLinuxNrBind:
	case kLinuxNrListen:
	case kLinuxNrGetsockname:
	case kLinuxNrGetpeername:
	case kLinuxNrSocketpair:
	case kLinuxNrSetsockopt:
	case kLinuxNrGetsockopt:
	case kLinuxNrKill:
	case kLinuxNrTgkill:
	case kLinuxNrAccept4:
		Thread::interruptCurrent(static_cast<Interrupt>(kIntrSuperCall
					+ kPosixSuperLinuxSyscall), image, {});
		return true;
	default:
		warningLogger() << "linux-abi: unimplemented syscall " << nr << frg::endlog;
		ret(-kLinuxEnosys);
	}
	return false;
#else
	// The Linux personality is only implemented on x86_64 so far; the flag
	// is never set on other architectures (exec.cpp gates kHelAbiLinux).
	(void)image;
	return false;
#endif
}

} // namespace thor
