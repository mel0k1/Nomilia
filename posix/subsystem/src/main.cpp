#include <memory>

#include <linux/vt.h>

#if defined(__x86_64__)
#include <cpuid.h>
#endif
#include <iomanip>
#include <sstream>

#include <protocols/mbus/client.hpp>

#include "net.hpp"
#include <core/clock.hpp>
#include "devserver.hpp"
#include "netlink/nl-socket.hpp"
#include "devices/full.hpp"
#include "devices/helout.hpp"
#include "devices/kmsg.hpp"
#include "devices/null.hpp"
#include "devices/random.hpp"
#include "devices/tty.hpp"
#include "devices/tty0.hpp"
#include "devices/ttyn.hpp"
#include "devices/urandom.hpp"
#include "devices/zero.hpp"
#include "pts.hpp"
#include "requests.hpp"
#include "observations.hpp"
#include "ostrace.hpp"

#include <bragi/helpers-std.hpp>
#include <kerncfg.bragi.hpp>
#include <posix.bragi.hpp>

#include "debug-options.hpp"

std::map<
	std::array<char, 16>,
	Process *
> globalCredentialsMap;

std::optional<std::shared_ptr<Process>> findProcessWithCredentials(helix_ng::CredentialsView credentials) {
	std::array<char, 16> creds;
	memcpy(creds.data(), credentials.data(), 16);
	auto it = globalCredentialsMap.find(creds);
	if(it == globalCredentialsMap.end())
		return std::nullopt;
	return it->second->shared_from_this();
}

async::result<void> serveSignals(std::shared_ptr<Process> self,
		std::shared_ptr<Generation> generation) {
	auto thread = self->threadDescriptor();
	async::cancellation_token cancellation = generation->cancelServe;

	uint64_t sequence = 1;
	while(true) {
		if(cancellation.is_cancellation_requested())
			break;
		//std::cout << "Waiting for raise in " << self->pid() << std::endl;
		auto result = co_await self->pollSignal(sequence, UINT64_C(-1), cancellation);
		sequence = std::get<0>(result);
		//std::cout << "Calling helInterruptThread on " << self->pid() << std::endl;
		HEL_CHECK(helInterruptThread(thread.getHandle()));
	}

	if(logCleanup)
		std::cout << "\e[33mposix: Exiting serveSignals()\e[39m" << std::endl;
	generation->signalsDone.raise();
}

async::result<void> serve(std::shared_ptr<Process> self, std::shared_ptr<Generation> generation) {
	auto thread = self->threadDescriptor();

	std::array<char, 16> creds;
	HEL_CHECK(helGetCredentials(thread.getHandle(), 0, creds.data()));
	auto res = globalCredentialsMap.insert({creds, self.get()});
	assert(res.second);

	co_await async::when_all(
		observeThread(self, generation),
		serveSignals(self, generation),
		serveRequests(self, generation)
	);

	std::erase_if(globalCredentialsMap, [&](const auto &p) {
		return !memcmp(p.first.data(), creds.data(), 16);
	});
}

// --------------------------------------------------------

namespace {
	helix::UniqueLane kerncfgLane;
	helix::UniqueLane pmLane;
	size_t affinityMaskSize = 0;
};

helix::UniqueLane &getKerncfgLane() {
	return kerncfgLane;
}

helix::UniqueLane &getPmLane() {
	return pmLane;
}

size_t getAffinityMaskSize() {
	assert(affinityMaskSize);
	return affinityMaskSize;
}

struct CmdlineNode final : public procfs::RegularNode {
	async::result<std::expected<std::string, Error>> show(Process *) override {
		managarm::kerncfg::GetCmdlineRequest req;

		auto [offer, sendReq, recvResp] =
			co_await helix_ng::exchangeMsgs(
				kerncfgLane,
				helix_ng::offer(
					helix_ng::want_lane,
					helix_ng::sendBragiHeadOnly(req, frg::stl_allocator{}),
					helix_ng::recvInline()
				)
			);

		HEL_CHECK(offer.error());
		HEL_CHECK(sendReq.error());
		HEL_CHECK(recvResp.error());

		auto resp = *bragi::parse_head_only<managarm::kerncfg::SvrResponse>(recvResp);
		recvResp.reset();
		assert(resp.error() == managarm::kerncfg::Error::SUCCESS);

		std::vector<char> recvCmdline(resp.size());
		auto [recv_tail] = co_await helix_ng::exchangeMsgs(
			offer.descriptor(),
			helix_ng::recvBuffer(recvCmdline.data(), recvCmdline.size())
		);

		HEL_CHECK(recv_tail.error());

		co_return std::string{(const char *)recvCmdline.data(), recvCmdline.size()} + '\n';
	}

	async::result<void> store(std::string) override {
		throw std::runtime_error("Cannot store to /proc/cmdline");
	}
};

#if defined(__x86_64__)
static std::string cpuFlags() {
	static constexpr struct { unsigned int leaf, reg, bit; const char *name; } knownFlags[] = {
		{1, 3, 0, "fpu"}, {1, 3, 3, "pse"}, {1, 3, 4, "tsc"}, {1, 3, 5, "msr"},
		{1, 3, 6, "pae"}, {1, 3, 9, "apic"}, {1, 3, 11, "sep"}, {1, 3, 13, "pge"},
		{1, 3, 19, "clflush"}, {1, 3, 23, "mmx"}, {1, 3, 24, "fxsr"}, {1, 3, 25, "sse"},
		{1, 3, 26, "sse2"}, {1, 3, 28, "ht"}, {1, 2, 0, "sse3"}, {1, 2, 9, "ssse3"},
		{1, 2, 13, "cx16"}, {1, 2, 19, "sse4_1"}, {1, 2, 20, "sse4_2"}, {1, 2, 23, "popcnt"},
		{1, 2, 25, "aes"}, {1, 2, 28, "avx"}, {1, 2, 31, "hypervisor"},
		{7, 1, 5, "avx2"}, {7, 1, 7, "smep"},
	};

	unsigned int a, b, c, d;
	if(!__get_cpuid(1, &a, &b, &c, &d))
		return "fpu";
	unsigned int basic[4] = {a, b, c, d};
	unsigned int extended[4] = {0, 0, 0, 0};
	if(__get_cpuid_max(0, nullptr) >= 7)
		__get_cpuid_count(7, 0, &extended[0], &extended[1], &extended[2], &extended[3]);

	std::string flags;
	for(auto f : knownFlags) {
		auto &regs = f.leaf == 7 ? extended : basic;
		if(regs[f.reg] & (1u << f.bit)) {
			if(!flags.empty())
				flags += " ";
			flags += f.name;
		}
	}
	return flags;
}

static std::string cpuBrandString() {
	if(__get_cpuid_max(0x80000000, nullptr) < 0x80000004)
		return "unknown";
	char brand[49] = {};
	for(unsigned int leaf = 0; leaf < 3; leaf++) {
		unsigned int r[4];
		__cpuid(0x80000002 + leaf, r[0], r[1], r[2], r[3]);
		memcpy(brand + leaf * 16, r, 16);
	}
	return std::string{brand};
}
#endif

struct MeminfoNode final : public procfs::RegularNode {
	async::result<std::expected<std::string, Error>> show(Process *) override {
		managarm::kerncfg::GetMemoryInformationRequest req;

		auto [offer, sendReq, recvResp] =
				co_await helix_ng::exchangeMsgs(
						kerncfgLane,
						helix_ng::offer(
								helix_ng::sendBragiHeadOnly(req, frg::stl_allocator{}),
								helix_ng::recvInline()
						)
				);

		HEL_CHECK(offer.error());
		HEL_CHECK(sendReq.error());
		HEL_CHECK(recvResp.error());

		auto resp = *bragi::parse_head_only<managarm::kerncfg::GetMemoryInformationResponse>(recvResp);
		recvResp.reset();

		// See man 5 proc for more details; kerncfg reports page counts.
		uint64_t totalKb = resp.total_usable_memory() * resp.memory_unit() / 1024;
		uint64_t freeKb = resp.available_memory() * resp.memory_unit() / 1024;
		std::stringstream stream;
		stream << "MemTotal:     " << std::setw(8) << totalKb << " kB\n";
		stream << "MemFree:      " << std::setw(8) << freeKb << " kB\n";
		stream << "MemAvailable: " << std::setw(8) << freeKb << " kB\n";
		stream << "Buffers:      " << std::setw(8) << 0 << " kB\n";
		stream << "Cached:       " << std::setw(8) << 0 << " kB\n";
		stream << "SwapTotal:    " << std::setw(8) << 0 << " kB\n";
		stream << "SwapFree:     " << std::setw(8) << 0 << " kB\n";
		co_return stream.str();
	}

	async::result<void> store(std::string) override {
		throw std::runtime_error("Cannot store to /proc/meminfo");
	}
};

struct CpuinfoNode final : public procfs::RegularNode {
	async::result<std::expected<std::string, Error>> show(Process *) override {
		managarm::kerncfg::GetNumCpuRequest req;

		auto [offer, sendReq, recvResp] =
				co_await helix_ng::exchangeMsgs(
						kerncfgLane,
						helix_ng::offer(
								helix_ng::sendBragiHeadOnly(req, frg::stl_allocator{}),
								helix_ng::recvInline()
						)
				);

		HEL_CHECK(offer.error());
		HEL_CHECK(sendReq.error());
		HEL_CHECK(recvResp.error());

		auto resp = *bragi::parse_head_only<managarm::kerncfg::GetNumCpuResponse>(recvResp);
		recvResp.reset();

		// See man 5 proc for more details.
		std::stringstream stream;
		for(unsigned int i = 0; i < resp.num_cpu(); i++)
			stream << formatCpu(i);
		co_return stream.str();
	}

	async::result<void> store(std::string) override {
		throw std::runtime_error("Cannot store to /proc/cpuinfo");
	}

private:
	std::string formatCpu(unsigned int index) const;
};

std::string CpuinfoNode::formatCpu(unsigned int index) const {
	std::stringstream stream;
	stream << "processor\t: " << index << "\n";
#if defined(__x86_64__)
	unsigned int a, b, c, d;
	if(!__get_cpuid(1, &a, &b, &c, &d))
		return stream.str();
	char vendor[13] = {};
	memcpy(vendor + 0, &b, 4);
	memcpy(vendor + 4, &d, 4);
	memcpy(vendor + 8, &c, 4);

	stream << "vendor_id\t: " << vendor << "\n";
	stream << "cpu family\t: " << ((a >> 8) & 0xF) << "\n";
	stream << "model\t\t: " << ((a >> 4) & 0xF) << "\n";
	stream << "model name\t: " << cpuBrandString() << "\n";
	stream << "stepping\t: " << (a & 0xF) << "\n";
	// TODO: Report the real frequency once CPU detection lands in thor.
	stream << "cpu MHz\t\t: 0.000\n";
	stream << "flags\t\t: " << cpuFlags() << "\n";
#endif
	return stream.str();
}

async::result<void> enumerateKerncfg() {
	auto filter = mbus_ng::Conjunction{{
		mbus_ng::EqualsFilter{"class", "kerncfg"}
	}};

	auto enumerator = mbus_ng::Instance::global().enumerate(filter);
	auto [_, events] = (co_await enumerator.nextEvents()).unwrap();
	assert(events.size() == 1);

	auto entity = co_await mbus_ng::Instance::global().getEntity(events[0].id);
	kerncfgLane = (co_await entity.getRemoteLane()).unwrap();

	// Determine the size of the affinity masks that thor accepts, i.e., one bit per CPU.
	managarm::kerncfg::GetNumCpuRequest numCpuReq;
	auto [offer, sendReq, recvResp] = co_await helix_ng::exchangeMsgs(
		kerncfgLane,
		helix_ng::offer(
			helix_ng::sendBragiHeadOnly(numCpuReq, frg::stl_allocator{}),
			helix_ng::recvInline()
		)
	);
	HEL_CHECK(offer.error());
	HEL_CHECK(sendReq.error());
	HEL_CHECK(recvResp.error());

	auto numCpuResp = bragi::parse_head_only<managarm::kerncfg::GetNumCpuResponse>(recvResp);
	affinityMaskSize = (numCpuResp->num_cpu() + 7) / 8;

	auto procfsRoot = smarter::static_pointer_cast<procfs::DirectoryNode>(getProcfs()->getTarget());
	procfsRoot->directMkregular(getProcfs().get(), "cmdline", makeFsShared<CmdlineNode>());
	procfsRoot->directMkregular(getProcfs().get(), "cpuinfo", makeFsShared<CpuinfoNode>());
	procfsRoot->directMkregular(getProcfs().get(), "meminfo", makeFsShared<MeminfoNode>());
}

async::result<void> enumeratePm() {
	auto filter = mbus_ng::Conjunction{{
		mbus_ng::EqualsFilter{"class", "pm-interface"}
	}};

	auto enumerator = mbus_ng::Instance::global().enumerate(filter);
	auto [_, events] = (co_await enumerator.nextEvents()).unwrap();
	assert(events.size() == 1);

	auto entity = co_await mbus_ng::Instance::global().getEntity(events[0].id);
	pmLane = (co_await entity.getRemoteLane()).unwrap();
}

// --------------------------------------------------------
// main() function
// --------------------------------------------------------

async::detached runInit() {
	co_await posix::ostContext.create();
	co_await enumerateKerncfg();
	co_await devserver::enumerate();
	async::detach(enumeratePm());
	async::detach(net::enumerateNetserver());
	co_await populateRootView();
	co_await Process::init("usr/bin/posix-init");
}

int main() {
	std::cout << "Starting posix-subsystem" << std::endl;

	async::run(clk::enumerateTracker(), helix::currentDispatcher);

//	HEL_CHECK(helSetPriority(kHelThisThread, 1));

	netlink::nl_socket::setupProtocols();

	charRegistry.install(createHeloutDevice());
	charRegistry.install(pts::createMasterDevice());
	charRegistry.install(createNullDevice());
	charRegistry.install(createFullDevice());
	charRegistry.install(createRandomDevice());
	charRegistry.install(createUrandomDevice());
	charRegistry.install(createZeroDevice());
	charRegistry.install(createKmsgDevice());
	charRegistry.install(createTtyDevice());
	charRegistry.install(createTTY0Device());
	for(int i = 1; i <= MAX_NR_CONSOLES; i++)
		charRegistry.install(createTTYNDevice(i));

	runInit();

	async::run_forever(helix::currentDispatcher);
}
