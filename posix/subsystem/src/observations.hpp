#pragma once

#include "process.hpp"

async::result<void> observeThread(std::shared_ptr<Process> self,
		std::shared_ptr<Generation> generation);

// Nomilia: shared with linux-abi.cpp; non-blocking pass over the pending
// signal queues of one thread (mirrors the native kill path).
async::result<bool> handlePendingSignalsFromObservation(Process *self);
