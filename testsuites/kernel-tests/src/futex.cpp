#include <cassert>

#include <hel.h>
#include <hel-syscalls.h>

#include "testsuite.hpp"

DEFINE_TEST(futexRequeueSanity, ([] {
	int w1 = 0;
	int w2 = 0;

	// Requeue must reject a stale expected value.
	auto err = helFutexRequeue(&w1, 1, 0, &w2, 0);
	assert(err == kHelErrFutexRace);

	// Requeue with no waiters must succeed.
	HEL_CHECK(helFutexRequeue(&w1, 0, 0, &w2, 0));
}))
