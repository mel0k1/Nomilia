// Nomilia: Linux syscall personality served by the POSIX subsystem.
// Thor forwards file/process Linux syscalls via the superLinuxSyscall
// observe upcall; this file decodes them from the raw Linux registers and
// re-runs them through the regular POSIX/VFS APIs of the process.
#include <errno.h>
#include <fcntl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <async/result.hpp>
#include <hel.h>

#include <helix/ipc.hpp>

#include "file.hpp"
#include "linux-abi.hpp"
#include "process.hpp"
#include "vfs.hpp"

namespace {

// Linux x86_64 syscall numbers handled in posix.
constexpr uint64_t kLinuxNrRead = 0;
constexpr uint64_t kLinuxNrWrite = 1;
constexpr uint64_t kLinuxNrOpen = 2;
constexpr uint64_t kLinuxNrClose = 3;
constexpr uint64_t kLinuxNrStat = 4;
constexpr uint64_t kLinuxNrFstat = 5;
constexpr uint64_t kLinuxNrLstat = 6;
constexpr uint64_t kLinuxNrLseek = 8;
constexpr uint64_t kLinuxNrPread64 = 17;
constexpr uint64_t kLinuxNrPwrite64 = 18;
constexpr uint64_t kLinuxNrDup = 32;
constexpr uint64_t kLinuxNrDup2 = 33;
constexpr uint64_t kLinuxNrGetpid = 39;
constexpr uint64_t kLinuxNrFork = 57;
constexpr uint64_t kLinuxNrVfork = 58;
constexpr uint64_t kLinuxNrExecve = 59;
constexpr uint64_t kLinuxNrWait4 = 61;
constexpr uint64_t kLinuxNrGetcwd = 79;
constexpr uint64_t kLinuxNrGetppid = 110;
constexpr uint64_t kLinuxNrGettid = 186;
constexpr uint64_t kLinuxNrOpenat = 257;
constexpr uint64_t kLinuxNrFstatat = 262;
constexpr uint64_t kLinuxNrDup3 = 292;

constexpr int kLinuxAtFdcwd = -100;
constexpr size_t kLinuxPathMax = 4096;
constexpr size_t kLinuxStringMax = 65536;
constexpr size_t kLinuxIoMax = 0x400000; // bounce buffer cap (4 MiB).
constexpr uint64_t kLinuxAtSymlinkNofollow = 0x100;
constexpr uint64_t kLinuxWnohang = 1;

int64_t linuxErr(Error e) {
	switch(e) {
	case Error::success: return 0;
	case Error::noSuchFile: return ENOENT;
	case Error::notDirectory: return ENOTDIR;
	case Error::fileClosed: return EBADF;
	case Error::illegalOperationTarget: return EINVAL;
	case Error::seekOnPipe: return ESPIPE;
	case Error::wouldBlock: return EAGAIN;
	case Error::brokenPipe: return EPIPE;
	case Error::illegalArguments: return EINVAL;
	case Error::insufficientPermissions: return EACCES;
	case Error::accessDenied: return EACCES;
	case Error::notConnected: return ENOTCONN;
	case Error::alreadyExists: return EEXIST;
	case Error::notTerminal: return ENOTTY;
	case Error::noBackingDevice: return ENXIO;
	case Error::noSpaceLeft: return ENOSPC;
	case Error::isDirectory: return EISDIR;
	case Error::nameTooLong: return ENAMETOOLONG;
	case Error::ioError: return EIO;
	case Error::noChildProcesses: return ECHILD;
	case Error::alreadyConnected: return EISCONN;
	case Error::unsupportedSocketType: return EINVAL;
	case Error::notSocket: return ENOTSOCK;
	case Error::interrupted: return EINTR;
	case Error::noSuchProcess: return ESRCH;
	case Error::noFileDescriptorsAvailable: return EMFILE;
	case Error::notSupported: return ENOSYS;
	case Error::badFileDescriptor: return EBADF;
	case Error::badProcessCredentials: return EIO;
	default: return EINVAL;
	}
}

int64_t linuxFsErr(protocols::fs::Error e) {
	switch(e) {
	case protocols::fs::Error::none: return 0;
	case protocols::fs::Error::fileNotFound: return ENOENT;
	case protocols::fs::Error::endOfFile: return 0;
	case protocols::fs::Error::illegalArguments: return EINVAL;
	case protocols::fs::Error::wouldBlock: return EAGAIN;
	case protocols::fs::Error::seekOnPipe: return ESPIPE;
	case protocols::fs::Error::brokenPipe: return EPIPE;
	case protocols::fs::Error::accessDenied: return EACCES;
	case protocols::fs::Error::notDirectory: return ENOTDIR;
	case protocols::fs::Error::insufficientPermissions: return EACCES;
	case protocols::fs::Error::alreadyExists: return EEXIST;
	case protocols::fs::Error::illegalOperationTarget: return EINVAL;
	case protocols::fs::Error::noSpaceLeft: return ENOSPC;
	case protocols::fs::Error::notTerminal: return ENOTTY;
	case protocols::fs::Error::noBackingDevice: return ENXIO;
	case protocols::fs::Error::isDirectory: return EISDIR;
	case protocols::fs::Error::directoryNotEmpty: return ENOTEMPTY;
	default: return EINVAL;
	}
}

async::result<bool> memRead(helix::BorrowedDescriptor space, uintptr_t addr,
		size_t len, void *buf) {
	if(!len)
		co_return true;
	auto e = co_await helix_ng::readMemory(space, addr, len, buf);
	co_return e.error() == kHelErrNone;
}

async::result<bool> memWrite(helix::BorrowedDescriptor space, uintptr_t addr,
		size_t len, const void *buf) {
	if(!len)
		co_return true;
	auto e = co_await helix_ng::writeMemory(space, addr, len, buf);
	co_return e.error() == kHelErrNone;
}

// NUL-terminated user string; falls back to byte-wise reads near page ends.
async::result<std::optional<std::string>> memReadString(
		helix::BorrowedDescriptor space, uintptr_t addr, size_t cap) {
	std::string s;
	size_t chunk = 64;
	uintptr_t p = addr;
	while(s.size() < cap) {
		char buf[64];
		size_t n = std::min(chunk, cap - s.size());
		if(!co_await memRead(space, p, n, buf)) {
			if(n == 1)
				co_return std::nullopt; // EFAULT
			chunk = 1;
			continue;
		}
		for(size_t i = 0; i < n; i++) {
			if(!buf[i])
				co_return s;
			s.push_back(buf[i]);
		}
		p += n;
	}
	co_return s;
}

// struct stat for x86_64 Linux (uapi asm/stat.h).
struct LinuxStat {
	uint64_t st_dev;
	uint64_t st_ino;
	uint64_t st_nlink;
	uint32_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t __pad0;
	uint64_t st_rdev;
	int64_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
	int64_t st_atimSec;
	int64_t st_atimNsec;
	int64_t st_mtimSec;
	int64_t st_mtimNsec;
	int64_t st_ctimSec;
	int64_t st_ctimNsec;
	int64_t __spare[3];
};
static_assert(sizeof(LinuxStat) == 144);

void fillLinuxStat(LinuxStat &st, const FileStats &fs) {
	st.st_ino = fs.inodeNumber;
	st.st_nlink = fs.numLinks;
	st.st_mode = fs.mode;
	st.st_uid = fs.uid;
	st.st_gid = fs.gid;
	st.st_size = fs.fileSize;
	st.st_blksize = 4096;
	st.st_blocks = (fs.fileSize + 511) / 512;
	st.st_atimSec = fs.atimeSecs;
	st.st_atimNsec = fs.atimeNanos;
	st.st_mtimSec = fs.mtimeSecs;
	st.st_mtimNsec = fs.mtimeNanos;
	st.st_ctimSec = fs.ctimeSecs;
	st.st_ctimNsec = fs.ctimeNanos;
}

async::result<int64_t> linuxRead(Process *self, int fd, uintptr_t bufPtr, size_t count) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	if(!count)
		co_return 0;
	auto bounce = std::make_unique<char[]>(count);
	auto result = co_await file->readSome(self, bounce.get(), count,
			async::cancellation_token{});
	if(!result)
		co_return -linuxErr(result.error());
	if(result.value() && !co_await memWrite(self->vmContext()->getSpace(),
				bufPtr, result.value(), bounce.get()))
		co_return -EFAULT;
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxWrite(Process *self, int fd, uintptr_t bufPtr, size_t count) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	auto bounce = std::make_unique<char[]>(count ? count : 1);
	if(count && !co_await memRead(self->vmContext()->getSpace(),
				bufPtr, count, bounce.get()))
		co_return -EFAULT;
	auto result = co_await file->writeAll(self, bounce.get(), count);
	if(!result)
		co_return -linuxErr(result.error());
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxLseek(Process *self, int fd, int64_t offset, int whence) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	VfsSeek vfsSeek;
	switch(whence) {
	case 0: vfsSeek = VfsSeek::absolute; break;
	case 1: vfsSeek = VfsSeek::relative; break;
	case 2: vfsSeek = VfsSeek::eof; break;
	default: co_return -EINVAL;
	}
	auto result = co_await file->seek(offset, vfsSeek);
	if(!result)
		co_return -linuxErr(result.error());
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxPread(Process *self, int fd, uintptr_t bufPtr,
		size_t count, int64_t offset) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	auto bounce = std::make_unique<char[]>(count ? count : 1);
	auto result = co_await file->pread(self, offset, bounce.get(), count);
	if(!result)
		co_return -linuxErr(result.error());
	if(result.value() && !co_await memWrite(self->vmContext()->getSpace(),
				bufPtr, result.value(), bounce.get()))
		co_return -EFAULT;
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxPwrite(Process *self, int fd, uintptr_t bufPtr,
		size_t count, int64_t offset) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	auto bounce = std::make_unique<char[]>(count ? count : 1);
	if(count && !co_await memRead(self->vmContext()->getSpace(),
				bufPtr, count, bounce.get()))
		co_return -EFAULT;
	auto result = co_await file->pwrite(self, offset, bounce.get(), count);
	if(!result)
		co_return -linuxErr(result.error());
	co_return (int64_t)result.value();
}

async::result<int64_t> openAtImpl(std::shared_ptr<Process> self, int dirfd,
		std::string path, uint32_t flags, uint32_t mode) {
	if(path.size() > kLinuxPathMax)
		co_return -ENAMETOOLONG;

	SemanticFlags semantic_flags = 0;
	switch(flags & 3) {
	case 0: semantic_flags |= semanticRead; break;
	case 1: semantic_flags |= semanticWrite; break;
	case 2: semantic_flags |= semanticRead | semanticWrite; break;
	}
	if(flags & O_APPEND)
		semantic_flags |= semanticAppend;
	if(flags & O_NONBLOCK)
		semantic_flags |= semanticNonBlock;

	ViewPath relative_to;
	if(dirfd == kLinuxAtFdcwd) {
		relative_to = self->fsContext()->getWorkingDirectory();
	}else{
		auto dir_file = self->fileContext()->getFile(dirfd);
		if(!dir_file)
			co_return -EBADF;
		relative_to = {dir_file->associatedMount(), dir_file->associatedLink()};
	}

	PathResolver resolver;
	resolver.setup(self->fsContext()->getRoot(), relative_to, path, self.get());

	smarter::shared_ptr<File, FileHandle> file;
	if(flags & O_CREAT) {
		auto resolveResult = co_await resolver.resolve(
				resolvePrefix | resolveOpenCreate);
		if(!resolveResult)
			co_return -linuxFsErr(resolveResult.error());

		if(!resolver.hasComponent())
			co_return (semantic_flags & semanticWrite) ? -EISDIR : -EEXIST;

		auto directoryLink = resolver.currentLink();
		auto directory = directoryLink->getTarget();

		auto linkResult = co_await directory->getLinkOrCreate(directoryLink.get(),
				self.get(), resolver.nextComponent(),
				mode & ~self->fsContext()->getUmask(), flags & O_EXCL);
		if(!linkResult)
			co_return -linuxErr(linkResult.error());
		auto link = linkResult.value();
		auto node = link->getTarget();
		if(node->getType() == VfsType::directory)
			co_return -EISDIR;
		auto fileResult = co_await node->open(self.get(), resolver.currentView(),
				std::move(link), semantic_flags);
		if(!fileResult)
			co_return -linuxErr(fileResult.error());
		file = fileResult.value();
	}else{
		ResolveFlags resolveFlags = 0;
		if(flags & O_NOFOLLOW)
			resolveFlags |= resolveDontFollow;

		auto resolveResult = co_await resolver.resolve(resolveFlags);
		if(!resolveResult)
			co_return -linuxFsErr(resolveResult.error());

		auto target = resolver.currentLink()->getTarget();
		if(target->getType() == VfsType::directory && (semantic_flags & semanticWrite))
			co_return -EISDIR;
		if((flags & O_DIRECTORY) && target->getType() != VfsType::directory)
			co_return -ENOTDIR;

		if(flags & O_PATH) {
			auto dummyFile = smarter::make_shared<DummyFile>(
					resolver.currentView(), resolver.currentLink());
			dummyFile->setupWeakFile(dummyFile);
			DummyFile::serve(dummyFile);
			file = File::constructHandle(std::move(dummyFile));
		}else{
			if(target->getType() == VfsType::symlink)
				co_return -ELOOP;
			auto fileResult = co_await target->open(self.get(),
					resolver.currentView(), resolver.currentLink(), semantic_flags);
			if(!fileResult)
				co_return -linuxErr(fileResult.error());
			file = fileResult.value();
		}
	}

	if(!file)
		co_return -ENOENT;

	if(file->isTerminal() && !(flags & O_NOCTTY) && self->pgPointer()
			&& self->pgPointer()->getSession()->getSessionId() == (pid_t)self->pid()
			&& self->pgPointer()->getSession()->getControllingTerminal() == nullptr) {
		// POSIX 1003.1-2017 11.1.3
		auto cts = co_await file->getControllingTerminal();
		if(cts)
			cts.value()->assignSessionOf(self.get());
	}

	if(flags & O_TRUNC) {
		auto result = co_await file->truncate(0);
		if(!result && result.error() != protocols::fs::Error::illegalOperationTarget)
			co_return -linuxFsErr(result.error());
	}

	auto fd = self->fileContext()->attachFile(file, flags & O_CLOEXEC);
	if(!fd)
		co_return -linuxErr(fd.error());
	co_return fd.value();
}

async::result<int64_t> statByPath(std::shared_ptr<Process> self, int dirfd,
		std::string path, bool nofollow, uintptr_t bufPtr) {
	if(path.size() > kLinuxPathMax)
		co_return -ENAMETOOLONG;

	ViewPath relative_to;
	if(dirfd == kLinuxAtFdcwd) {
		relative_to = self->fsContext()->getWorkingDirectory();
	}else{
		auto dir_file = self->fileContext()->getFile(dirfd);
		if(!dir_file)
			co_return -EBADF;
		relative_to = {dir_file->associatedMount(), dir_file->associatedLink()};
	}

	PathResolver resolver;
	resolver.setup(self->fsContext()->getRoot(), relative_to, path, self.get());
	auto resolveResult = co_await resolver.resolve(
			nofollow ? resolveDontFollow : ResolveFlags{0});
	if(!resolveResult)
		co_return -linuxFsErr(resolveResult.error());

	auto link = resolver.currentLink();
	auto stats = co_await link->getTarget()->getStats();
	if(!stats)
		co_return -linuxErr(stats.error());

	if(!bufPtr)
		co_return -EFAULT;
	LinuxStat st{};
	fillLinuxStat(st, stats.value());
	if(!co_await memWrite(self->vmContext()->getSpace(), bufPtr, sizeof(st), &st))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxFstat(Process *self, int fd, uintptr_t bufPtr) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	auto link = file->associatedLink();
	if(!link)
		co_return -ENOSYS; // sockets/pipes: no associated link yet.
	auto stats = co_await link->getTarget()->getStats();
	if(!stats)
		co_return -linuxErr(stats.error());
	if(!bufPtr)
		co_return -EFAULT;
	LinuxStat st{};
	fillLinuxStat(st, stats.value());
	if(!co_await memWrite(self->vmContext()->getSpace(), bufPtr, sizeof(st), &st))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxDup(std::shared_ptr<Process> self, int oldfd) {
	auto file = self->fileContext()->getFile(oldfd);
	if(!file)
		co_return -EBADF;
	auto fd = self->fileContext()->attachFile(file);
	if(!fd)
		co_return -linuxErr(fd.error());
	co_return fd.value();
}

async::result<int64_t> linuxDup2(std::shared_ptr<Process> self, int oldfd,
		int newfd, bool dup3, uint32_t flags) {
	if(newfd < 0)
		co_return -EBADF;
	if(dup3 && (flags & ~O_CLOEXEC))
		co_return -EINVAL;
	auto file = self->fileContext()->getFile(oldfd);
	if(!file)
		co_return -EBADF;
	if(oldfd == newfd) {
		if(dup3 && (flags & O_CLOEXEC))
			co_return -EINVAL;
		co_return newfd;
	}
	// Linux closes newfd silently.
	self->fileContext()->closeFile(newfd);
	auto err = self->fileContext()->attachFile(newfd, file, flags & O_CLOEXEC);
	if(!err)
		co_return -linuxErr(err.error());
	co_return newfd;
}

async::result<int64_t> linuxGetcwd(Process *self, uintptr_t bufPtr, size_t size) {
	auto path = self->fsContext()->getWorkingDirectory()
			.getPath(self->fsContext()->getRoot());
	if(path.size() + 1 > size)
		co_return -ERANGE;
	if(!co_await memWrite(self->vmContext()->getSpace(), bufPtr,
				path.size() + 1, path.c_str()))
		co_return -EFAULT;
	co_return (int64_t)bufPtr;
}

int64_t execErr(Error e) {
	switch(e) {
	case Error::noSuchFile: return ENOENT;
	case Error::badExecutable: return ENOEXEC;
	case Error::eof: return ENOEXEC;
	case Error::insufficientPermissions: return EACCES;
	case Error::accessDenied: return EACCES;
	default: return EIO;
	}
}

// Reads a NUL-terminated vector of user pointers to strings (argv/envp).
async::result<bool> readPointerStringArray(helix::BorrowedDescriptor space,
		uintptr_t arrayPtr, std::vector<std::string> &out) {
	for(size_t i = 0; i < 4096; i++) {
		uint64_t p;
		if(!co_await memRead(space, arrayPtr + i * sizeof(uint64_t), sizeof(p), &p))
			co_return false;
		if(!p)
			co_return true;
		auto s = co_await memReadString(space, p, kLinuxStringMax);
		if(!s)
			co_return false;
		out.push_back(std::move(*s));
	}
	co_return true;
}

async::result<LinuxSyscallOutcome> linuxExecve(std::shared_ptr<Process> self,
		uintptr_t pathPtr, uintptr_t argvPtr, uintptr_t envpPtr) {
	auto space = self->vmContext()->getSpace();

	auto pathOpt = co_await memReadString(space, pathPtr, kLinuxPathMax);
	if(!pathOpt)
		co_return LinuxSyscallOutcome{true, -EFAULT};

	std::vector<std::string> args;
	if(argvPtr && !co_await readPointerStringArray(space, argvPtr, args))
		co_return LinuxSyscallOutcome{true, -EFAULT};
	if(args.empty())
		args.push_back(*pathOpt);

	std::vector<std::string> env;
	if(envpPtr && !co_await readPointerStringArray(space, envpPtr, env))
		co_return LinuxSyscallOutcome{true, -EFAULT};

	auto error = co_await Process::exec(self, *pathOpt, std::move(args),
			std::move(env));
	if(error == Error::success)
		co_return LinuxSyscallOutcome{false, 0}; // Process::exec resumed the new image.

	std::cout << "posix: linux execve(" << *pathOpt << ") failed: "
			<< (int)error << std::endl;
	co_return LinuxSyscallOutcome{true, -execErr(error)};
}

async::result<int64_t> linuxFork(std::shared_ptr<Process> self,
		helix::BorrowedDescriptor thread) {
	auto child = co_await Process::fork(self);

	// Copy registers from the current thread to the new one.
	auto childThread = child->threadDescriptor().getHandle();
	uintptr_t pcrs[2], pgprs[kHelNumGprs], thrs[2];
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsProgram, &pcrs));
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsGeneral, &pgprs));
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsThread, &thrs));

	HEL_CHECK(helStoreRegisters(childThread, kHelRegsProgram, &pcrs));
	HEL_CHECK(helStoreRegisters(childThread, kHelRegsThread, &thrs));

	// Linux fork() returns 0 in the child (RAX slot).
	pgprs[kHelRegArg2] = 0;
	HEL_CHECK(helStoreRegisters(childThread, kHelRegsGeneral, &pgprs));
	HEL_CHECK(helResume(childThread));

	co_return (int64_t)child->pid();
}

async::result<int64_t> linuxWait4(Process *self, int pid, uintptr_t statusPtr,
		uint64_t options) {
	WaitFlags flags = waitExited;
	if(options & kLinuxWnohang)
		flags |= waitNonBlocking;

	auto outcome = co_await self->wait(pid, flags, async::cancellation_token{});
	if(!outcome) {
		if(outcome.error() == Error::wouldBlock)
			co_return 0; // WNOHANG: children exist, none exited.
		co_return -linuxErr(outcome.error());
	}

	int status = 0;
	if(auto *e = std::get_if<TerminationByExit>(&outcome.value().state))
		status = (e->code & 0xff) << 8;
	else if(auto *s = std::get_if<TerminationBySignal>(&outcome.value().state))
		status = s->signo & 0x7f;

	if(statusPtr && !co_await memWrite(self->vmContext()->getSpace(),
				statusPtr, sizeof(int), &status))
		co_return -EFAULT;
	co_return (int64_t)outcome.value().pid;
}

} // anonymous namespace

async::result<LinuxSyscallOutcome> handleLinuxSyscall(std::shared_ptr<Process> self,
		helix::BorrowedDescriptor thread, uint64_t nr,
		const std::array<uint64_t, 6> &args) {
	uint64_t a0 = args[0];
	uint64_t a1 = args[1];
	uint64_t a2 = args[2];
	uint64_t a3 = args[3];

	int64_t ret = 0;
	switch(nr) {
	case kLinuxNrRead:
		ret = co_await linuxRead(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrWrite:
		ret = co_await linuxWrite(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrOpen: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
				a0, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await openAtImpl(self, kLinuxAtFdcwd, std::move(*pathOpt),
				(uint32_t)a1, (uint32_t)a2);
	} break;
	case kLinuxNrClose: {
		auto err = self->fileContext()->closeFile((int)a0);
		ret = err == Error::success ? 0 : -linuxErr(err);
	} break;
	case kLinuxNrStat: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
				a0, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await statByPath(self, kLinuxAtFdcwd, std::move(*pathOpt),
				false, a1);
	} break;
	case kLinuxNrLstat: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
				a0, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await statByPath(self, kLinuxAtFdcwd, std::move(*pathOpt),
				true, a1);
	} break;
	case kLinuxNrFstat:
		ret = co_await linuxFstat(self.get(), (int)a0, a1);
		break;
	case kLinuxNrFstatat: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
				a1, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await statByPath(self, (int)(int64_t)a0, std::move(*pathOpt),
				(a2 & kLinuxAtSymlinkNofollow) != 0, a2);
	} break;
	case kLinuxNrOpenat: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
				a1, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await openAtImpl(self, (int)(int64_t)a0, std::move(*pathOpt),
				(uint32_t)a2, (uint32_t)a3);
	} break;
	case kLinuxNrLseek:
		ret = co_await linuxLseek(self.get(), (int)a0, (int64_t)a1, (int)a2);
		break;
	case kLinuxNrPread64:
		ret = co_await linuxPread(self.get(), (int)a0, a1, a2, (int64_t)a3);
		break;
	case kLinuxNrPwrite64:
		ret = co_await linuxPwrite(self.get(), (int)a0, a1, a2, (int64_t)a3);
		break;
	case kLinuxNrDup:
		ret = co_await linuxDup(self, (int)a0);
		break;
	case kLinuxNrDup2:
		ret = co_await linuxDup2(self, (int)a0, (int)a1, false, 0);
		break;
	case kLinuxNrDup3:
		ret = co_await linuxDup2(self, (int)a0, (int)a1, true, (uint32_t)a2);
		break;
	case kLinuxNrGetpid:
		ret = self->pid();
		break;
	case kLinuxNrGetppid: {
		auto parent = self->getParent();
		ret = parent ? parent->pid() : 1;
	} break;
	case kLinuxNrGettid:
		ret = self->tid();
		break;
	case kLinuxNrGetcwd:
		ret = co_await linuxGetcwd(self.get(), a0, a1);
		break;
	case kLinuxNrFork:
	case kLinuxNrVfork:
		ret = co_await linuxFork(self, thread);
		break;
	case kLinuxNrExecve:
		co_return co_await linuxExecve(self, a0, a1, a2);
	case kLinuxNrWait4:
		ret = co_await linuxWait4(self.get(), (int)(int64_t)a0, a1, a2);
		break;
	default:
		std::cout << "posix: linux-abi: unhandled syscall " << nr << std::endl;
		co_return LinuxSyscallOutcome{true, -ENOSYS};
	}
	co_return LinuxSyscallOutcome{true, ret};
}
