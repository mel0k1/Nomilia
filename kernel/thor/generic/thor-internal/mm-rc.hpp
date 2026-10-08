#pragma once

#include <smarter.hpp>
#include <thor-internal/debug.hpp>

namespace thor {

struct Thread;
struct AddressSpace;

struct BindableHandle {
	BindableHandle() = default;

	explicit BindableHandle(AddressSpace *space)
	: _space{space} { }

	explicit operator bool() const {
		return _space != nullptr;
	}

	void increment() const;
	void decrement() const;

private:
	AddressSpace *_space{nullptr};
};
static_assert(smarter::rc_policy<BindableHandle>);

struct ActiveHandle {
	ActiveHandle() = default;

	explicit ActiveHandle(Thread *thread)
	: _thread{thread} { }

	explicit operator bool() const {
		return _thread != nullptr;
	}

	void increment() const;
	void decrement() const;

	smarter::default_rc_policy
	downcast_policy(smarter::rc_policy_tag<smarter::default_rc_policy>) const;

private:
	Thread *_thread{nullptr};
};
static_assert(smarter::rc_policy<ActiveHandle>);

struct EternalBase : smarter::meta_object_base {
	EternalBase()
	: smarter::meta_object_base{nullptr, nullptr} {
		ctr().setup(smarter::adopt_rc, 1);
		weak_ctr().setup(smarter::adopt_rc, 1);
	}
};

} // namespace thor
