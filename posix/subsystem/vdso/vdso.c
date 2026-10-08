// Nomilia vDSO: fast userspace implementations of the Linux time symbols.
// Reads the kernel clock page (HelClockPage) and the clocktracker page
// (refClock/baseRealtime), both mapped below this object at fixed addresses.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vdso-layout.h"

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7

// kHelClock* values from hel.h.
#define HEL_CLOCK_NONE 0
#define HEL_CLOCK_TSC 1
#define HEL_CLOCK_CNTPCT 2
#define HEL_CLOCK_CNTVCT 3
#define HEL_CLOCK_TIME 4

#define ENOSYS 38
#define EINVAL 22

struct hel_clock_page {
	uint64_t seqlock;
	uint32_t clockType;
	int32_t tickShift;
	uint64_t tickFactor;
};

struct clk_tracker_page {
	uint64_t seqlock;
	int32_t state;
	int32_t padding;
	int64_t refClock;
	int64_t baseRealtime;
};

struct vdso_timespec {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct vdso_timeval {
	int64_t tv_sec;
	int64_t tv_usec;
};

struct vdso_timezone {
	int32_t tz_minuteswest;
	int32_t tz_dsttime;
};

static const struct hel_clock_page *const clockPage =
		(struct hel_clock_page *)(uintptr_t)NOMILIA_VDSO_CLOCK_PAGE;
static const struct clk_tracker_page *const trackerPage =
		(struct clk_tracker_page *)(uintptr_t)NOMILIA_VDSO_TRACK_PAGE;

// Reads the raw tick counter of the given clock; false if this build cannot read it.
static bool read_ticks(uint32_t clockType, uint64_t *ticks) {
#if defined(__x86_64__)
	if(clockType != HEL_CLOCK_TSC)
		return false;
	uint32_t lsw, msw;
	asm volatile ("lfence; rdtsc" : "=a"(lsw), "=d"(msw) : : "memory");
	*ticks = ((uint64_t)msw << 32) | lsw;
	return true;
#elif defined(__aarch64__)
	if(clockType == HEL_CLOCK_CNTVCT) {
		asm volatile ("mrs %0, cntvct_el0" : "=r"(*ticks) : : "memory");
		return true;
	}
	if(clockType == HEL_CLOCK_CNTPCT) {
		asm volatile ("mrs %0, cntpct_el0" : "=r"(*ticks) : : "memory");
		return true;
	}
	return false;
#elif defined(__riscv) && __riscv_xlen == 64
	if(clockType != HEL_CLOCK_TIME)
		return false;
	asm volatile ("rdtime %0" : "=r"(*ticks) : : "memory");
	return true;
#else
	(void)clockType;
	(void)ticks;
	return false;
#endif
}

// Mirrors the HelClockPage contract: (tickFactor * ticks) >> tickShift, in 128-bit math.
static uint64_t ticks_to_nanos(uint64_t tickFactor, int32_t tickShift, uint64_t ticks) {
	unsigned __int128 product = (unsigned __int128)tickFactor * ticks;
	unsigned __int128 quotient = product >> tickShift;
	if(quotient >> 64)
		return UINT64_MAX;
	return (uint64_t)quotient;
}

static bool read_monotonic(uint64_t *nanos) {
	for(int tries = 0; tries < 8; tries++) {
		uint64_t seqlock = __atomic_load_n(&clockPage->seqlock, __ATOMIC_ACQUIRE);
		if(seqlock & 1)
			continue;

		uint32_t clockType = __atomic_load_n(&clockPage->clockType, __ATOMIC_RELAXED);
		int32_t tickShift = __atomic_load_n(&clockPage->tickShift, __ATOMIC_RELAXED);
		uint64_t tickFactor = __atomic_load_n(&clockPage->tickFactor, __ATOMIC_RELAXED);

		uint64_t ticks;
		bool readable = read_ticks(clockType, &ticks);

		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if(!readable || __atomic_load_n(&clockPage->seqlock, __ATOMIC_RELAXED) != seqlock)
			continue;

		*nanos = ticks_to_nanos(tickFactor, tickShift, ticks);
		return *nanos != UINT64_MAX;
	}
	return false;
}

static bool read_realtime(uint64_t *nanos) {
	uint64_t mono;
	if(!read_monotonic(&mono))
		return false;

	uint64_t seqlock = __atomic_load_n(&trackerPage->seqlock, __ATOMIC_ACQUIRE);
	if(seqlock & 1)
		return false;

	int64_t ref = __atomic_load_n(&trackerPage->refClock, __ATOMIC_RELAXED);
	int64_t base = __atomic_load_n(&trackerPage->baseRealtime, __ATOMIC_RELAXED);

	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	if(__atomic_load_n(&trackerPage->seqlock, __ATOMIC_RELAXED) != seqlock)
		return false;

	*nanos = (uint64_t)base + (mono - (uint64_t)ref);
	return true;
}

__attribute__((visibility("default")))
int __vdso_clock_gettime(int clock, struct vdso_timespec *ts) {
	uint64_t nanos;
	if(clock == CLOCK_REALTIME || clock == CLOCK_REALTIME_COARSE) {
		if(!read_realtime(&nanos))
			return -ENOSYS;
	} else if(clock == CLOCK_MONOTONIC || clock == CLOCK_MONOTONIC_RAW
			|| clock == CLOCK_MONOTONIC_COARSE || clock == CLOCK_BOOTTIME) {
		if(!read_monotonic(&nanos))
			return -ENOSYS;
	} else {
		return -EINVAL;
	}

	ts->tv_sec = nanos / 1000000000;
	ts->tv_nsec = nanos % 1000000000;
	return 0;
}

__attribute__((visibility("default")))
int __vdso_clock_getres(int clock, struct vdso_timespec *ts) {
	uint64_t res;
	if(clock == CLOCK_REALTIME_COARSE || clock == CLOCK_MONOTONIC_COARSE) {
		// Matches AT_CLKTCK = 100 advertised in the auxv.
		res = 10000000;
	} else if(clock == CLOCK_REALTIME || clock == CLOCK_MONOTONIC
			|| clock == CLOCK_MONOTONIC_RAW || clock == CLOCK_BOOTTIME) {
		res = 1;
	} else {
		return -EINVAL;
	}

	if(ts) {
		ts->tv_sec = 0;
		ts->tv_nsec = res;
	}
	return 0;
}

__attribute__((visibility("default")))
int __vdso_gettimeofday(struct vdso_timeval *tv, struct vdso_timezone *tz) {
	uint64_t nanos;
	if(!read_realtime(&nanos))
		return -ENOSYS;

	if(tv) {
		tv->tv_sec = nanos / 1000000000;
		tv->tv_usec = (nanos % 1000000000) / 1000;
	}
	if(tz) {
		tz->tz_minuteswest = 0;
		tz->tz_dsttime = 0;
	}
	return 0;
}

__attribute__((visibility("default")))
int64_t __vdso_time(int64_t *t) {
	uint64_t nanos;
	if(!read_realtime(&nanos))
		return 0;

	int64_t secs = nanos / 1000000000;
	if(t)
		*t = secs;
	return secs;
}

// No per-cpu ABI yet; callers fall back to the syscall.
__attribute__((visibility("default")))
int __vdso_getcpu(unsigned *cpu, unsigned *node, void *unused) {
	(void)cpu;
	(void)node;
	(void)unused;
	return -ENOSYS;
}
