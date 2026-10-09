// Nomilia: Linux syscall personality served by the POSIX subsystem.
// Thor forwards file/process Linux syscalls via the superLinuxSyscall
// observe upcall; this file decodes them from the raw Linux registers and
// re-runs them through the regular POSIX/VFS APIs of the process.
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <asm/ioctls.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <async/result.hpp>
#include <hel.h>

#include <helix/ipc.hpp>

#include "fifo.hpp"
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
constexpr uint64_t kLinuxNrIoctl = 16;
constexpr uint64_t kLinuxNrPipe = 22;
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
constexpr uint64_t kLinuxNrFaccessat = 269;
constexpr uint64_t kLinuxNrGetdents64 = 217;
constexpr uint64_t kLinuxNrPipe2 = 293;
constexpr uint64_t kLinuxNrStatx = 332;
constexpr uint64_t kLinuxNrFaccessat2 = 439;
constexpr uint64_t kLinuxNrDup3 = 292;

constexpr int kLinuxAtFdcwd = -100;
constexpr size_t kLinuxPathMax = 4096;
constexpr size_t kLinuxStringMax = 65536;
constexpr size_t kLinuxIoMax = 0x400000; // bounce buffer cap (4 MiB).
constexpr uint64_t kLinuxAtSymlinkNofollow = 0x100;
constexpr uint64_t kLinuxAtEmptyPath = 0x1000;
constexpr uint64_t kLinuxWnohang = 1;

// statx uapi bits (include/uapi/linux/stat.h).
constexpr uint32_t kStatxType = 0x1;
constexpr uint32_t kStatxMode = 0x2;
constexpr uint32_t kStatxNlink = 0x4;
constexpr uint32_t kStatxUid = 0x8;
constexpr uint32_t kStatxGid = 0x10;
constexpr uint32_t kStatxAtime = 0x20;
constexpr uint32_t kStatxMtime = 0x40;
constexpr uint32_t kStatxCtime = 0x80;
constexpr uint32_t kStatxIno = 0x100;
constexpr uint32_t kStatxSize = 0x200;
constexpr uint32_t kStatxBlocks = 0x400;
constexpr uint32_t kStatxBasicMask = kStatxType | kStatxMode | kStatxNlink | kStatxUid
		| kStatxGid | kStatxAtime | kStatxMtime | kStatxCtime | kStatxIno
		| kStatxSize | kStatxBlocks;

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

// struct linux_dirent64 (uapi): d_type sits before d_name, records are 8-aligned.
struct LinuxDirent64 {
	uint64_t d_ino;
	int64_t d_off;
	uint16_t d_reclen;
	uint8_t d_type;
	char d_name[];
};
constexpr size_t kDirent64NameOff = offsetof(LinuxDirent64, d_name);

constexpr uint8_t kDtUnknown = 0;
constexpr uint8_t kDtFifo = 1;
constexpr uint8_t kDtChr = 2;
constexpr uint8_t kDtDir = 4;
constexpr uint8_t kDtBlk = 6;
constexpr uint8_t kDtReg = 8;
constexpr uint8_t kDtLnk = 10;
constexpr uint8_t kDtSock = 12;

uint8_t mapDtType(int64_t fileType) {
	if(fileType == (int64_t)managarm::fs::FileType::DIRECTORY)
		return kDtDir;
	if(fileType == (int64_t)managarm::fs::FileType::REGULAR)
		return kDtReg;
	if(fileType == (int64_t)managarm::fs::FileType::SYMLINK)
		return kDtLnk;
	if(fileType == (int64_t)managarm::fs::FileType::SOCKET)
		return kDtSock;
	if(fileType == (int64_t)managarm::fs::FileType::CHAR_DEVICE)
		return kDtChr;
	if(fileType == (int64_t)managarm::fs::FileType::BLOCK_DEVICE)
		return kDtBlk;
	if(fileType == (int64_t)managarm::fs::FileType::FIFO)
		return kDtFifo;
	return kDtUnknown;
}

// struct statx (uapi linux/stat.h), 256 bytes on x86_64.
struct LinuxStatxTimestamp {
	int64_t tvSec;
	uint32_t tvNsec;
	int32_t reserved_;
};

struct LinuxStatx {
	uint32_t stxMask;
	uint32_t stxBlksize;
	uint64_t stxAttributes;
	uint32_t stxNlink;
	uint32_t stxUid;
	uint32_t stxGid;
	uint16_t stxMode;
	uint16_t spare0_;
	uint64_t stxIno;
	uint64_t stxSize;
	uint64_t stxBlocks;
	uint64_t stxAttributesMask;
	LinuxStatxTimestamp stxAtime;
	LinuxStatxTimestamp stxBtime;
	LinuxStatxTimestamp stxCtime;
	LinuxStatxTimestamp stxMtime;
	uint32_t stxRdevMajor;
	uint32_t stxRdevMinor;
	uint32_t stxDevMajor;
	uint32_t stxDevMinor;
	uint64_t stxMntId;
	uint64_t stxDioMemAlign;
	uint64_t stxDioOffsetAlign;
	uint64_t spare1_[11];
};
static_assert(sizeof(LinuxStatx) == 256);

void fillLinuxStatx(LinuxStatx &stx, const FileStats &fs) {
	stx.stxMask = kStatxBasicMask;
	stx.stxBlksize = 4096;
	stx.stxAttributesMask = 0;
	stx.stxNlink = fs.numLinks;
	stx.stxUid = fs.uid;
	stx.stxGid = fs.gid;
	stx.stxMode = fs.mode;
	stx.stxIno = fs.inodeNumber;
	stx.stxSize = fs.fileSize;
	stx.stxBlocks = (fs.fileSize + 511) / 512;
	stx.stxAtime = { (int64_t)fs.atimeSecs, (uint32_t)fs.atimeNanos, 0 };
	stx.stxCtime = { (int64_t)fs.ctimeSecs, (uint32_t)fs.ctimeNanos, 0 };
	stx.stxMtime = { (int64_t)fs.mtimeSecs, (uint32_t)fs.mtimeNanos, 0 };
}

// struct termios in the raw x86_64 Linux ABI (uapi asm/termbits.h, 36 bytes);
// managarm mlibc's struct termios (NCCS=32) reuses the same flag values.
struct LinuxTermios {
	uint32_t c_iflag;
	uint32_t c_oflag;
	uint32_t c_cflag;
	uint32_t c_lflag;
	uint8_t c_line;
	uint8_t c_cc[19];
};
static_assert(sizeof(LinuxTermios) == 36);

LinuxTermios toLinuxTermios(const struct termios &m) {
	LinuxTermios t{};
	t.c_iflag = m.c_iflag;
	t.c_oflag = m.c_oflag;
	t.c_cflag = m.c_cflag;
	t.c_lflag = m.c_lflag;
	t.c_line = m.c_line;
	for(size_t i = 0; i < sizeof(t.c_cc); i++)
		t.c_cc[i] = m.c_cc[i];
	return t;
}

struct termios fromLinuxTermios(const LinuxTermios &t) {
	struct termios m{};
	m.c_iflag = t.c_iflag;
	m.c_oflag = t.c_oflag;
	m.c_cflag = t.c_cflag;
	m.c_lflag = t.c_lflag;
	m.c_line = t.c_line;
	for(size_t i = 0; i < sizeof(t.c_cc); i++)
		m.c_cc[i] = t.c_cc[i];
	return m;
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


// Resolves a path relative to dirfd and returns the node stats (-errno on error).
async::result<std::expected<FileStats, int64_t>> statsAt(std::shared_ptr<Process> self,
		int dirfd, std::string path, bool nofollow) {
	if(path.size() > kLinuxPathMax)
		co_return std::unexpected(-ENAMETOOLONG);

	ViewPath relative_to;
	if(dirfd == kLinuxAtFdcwd) {
		relative_to = self->fsContext()->getWorkingDirectory();
	}else{
		auto dir_file = self->fileContext()->getFile(dirfd);
		if(!dir_file)
			co_return std::unexpected(-EBADF);
		relative_to = {dir_file->associatedMount(), dir_file->associatedLink()};
	}

	PathResolver resolver;
	resolver.setup(self->fsContext()->getRoot(), relative_to, path, self.get());
	auto resolveResult = co_await resolver.resolve(
				nofollow ? resolveDontFollow : ResolveFlags{0});
	if(!resolveResult)
		co_return std::unexpected(-linuxFsErr(resolveResult.error()));

	auto stats = co_await resolver.currentLink()->getTarget()->getStats();
	if(!stats)
		co_return std::unexpected(-linuxErr(stats.error()));
	co_return stats.value();
}

async::result<int64_t> linuxGetdents64(Process *self, int fd, uintptr_t bufPtr,
		size_t count) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	if(!count)
		co_return -EINVAL;
	auto bounce = std::make_unique<char[]>(count);

	size_t packed = 0;
	while(true) {
		auto entry = co_await file->readEntries();
		if(!entry) {
			if(entry.error() == managarm::fs::Errors::END_OF_FILE)
				break;
			co_return -linuxErr(entry.error() | toFsProtoError);
		}

		size_t nameLen = entry->name.size();
		size_t reclen = (kDirent64NameOff + nameLen + 1 + 7) & ~size_t(7);
		if(packed + reclen > count) {
			if(!packed)
				co_return -EINVAL; // even one entry does not fit
			break;
		}

		auto *d = reinterpret_cast<LinuxDirent64 *>(bounce.get() + packed);
		d->d_ino = entry->inode;
		d->d_off = entry->offset;
		d->d_reclen = reclen;
		d->d_type = mapDtType(entry->fileType);
		memcpy(d->d_name, entry->name.data(), nameLen);
		d->d_name[nameLen] = '\0';
		memset(bounce.get() + packed + kDirent64NameOff + nameLen + 1, 0,
				reclen - kDirent64NameOff - nameLen - 1);
		packed += reclen;
	}

	if(packed && !co_await memWrite(self->vmContext()->getSpace(),
					bufPtr, packed, bounce.get()))
		co_return -EFAULT;
	co_return (int64_t)packed;
}

async::result<int64_t> linuxIoctl(Process *self, int fd, uint64_t cmd, uintptr_t argPtr) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	auto space = self->vmContext()->getSpace();

	switch(cmd) {
	case TCGETS: {
		auto result = co_await file->getTermios();
		if(!result)
			co_return -ENOTTY;
		auto t = toLinuxTermios(result.value());
		if(!co_await memWrite(space, argPtr, sizeof(t), &t))
			co_return -EFAULT;
		co_return 0;
	}
	case TCSETS: {
		LinuxTermios t{};
		if(!co_await memRead(space, argPtr, sizeof(t), &t))
			co_return -EFAULT;
		auto result = co_await file->setTermios(fromLinuxTermios(t));
		if(!result)
			co_return -ENOTTY;
		co_return 0;
	}
	case TIOCGWINSZ: {
		auto result = co_await file->getWinsize();
		if(!result)
			co_return -ENOTTY;
		struct winsize ws = result.value();
		if(!co_await memWrite(space, argPtr, sizeof(ws), &ws))
			co_return -EFAULT;
		co_return 0;
	}
	case TIOCSWINSZ: {
		struct winsize ws{};
		if(!co_await memRead(space, argPtr, sizeof(ws), &ws))
			co_return -EFAULT;
		auto result = co_await file->setWinsize(ws);
		if(!result)
			co_return -ENOTTY;
		co_return 0;
	}
	default:
		std::cout << "posix: linux-abi: unhandled ioctl 0x"
					<< std::hex << cmd << std::dec << std::endl;
		co_return -ENOTTY;
	}
}

async::result<int64_t> linuxStatx(std::shared_ptr<Process> self, int dirfd,
		std::string path, uint32_t flags, uintptr_t bufPtr) {
	FileStats nodeStats;
	if(path.empty() && (flags & kLinuxAtEmptyPath)) {
		auto file = self->fileContext()->getFile(dirfd);
		if(!file)
			co_return -EBADF;
		auto link = file->associatedLink();
		if(!link)
			co_return -ENOSYS; // sockets/pipes: no associated link yet.
		auto stats = co_await link->getTarget()->getStats();
		if(!stats)
			co_return -linuxErr(stats.error());
		nodeStats = stats.value();
	}else{
		auto stats = co_await statsAt(self, dirfd, std::move(path),
					flags & kLinuxAtSymlinkNofollow);
		if(!stats)
			co_return stats.error();
		nodeStats = stats.value();
	}

	if(!bufPtr)
		co_return -EFAULT;
	LinuxStatx stx{};
	fillLinuxStatx(stx, nodeStats);
	if(!co_await memWrite(self->vmContext()->getSpace(), bufPtr, sizeof(stx), &stx))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxPipe2(Process *self, uintptr_t fdArrayPtr, uint32_t flags) {
	if(flags & ~(O_CLOEXEC | O_NONBLOCK))
		co_return -EINVAL;

	auto pair = fifo::createPair(flags & O_NONBLOCK);
	auto rFd = self->fileContext()->attachFile(pair[0], flags & O_CLOEXEC);
	if(!rFd)
		co_return -linuxErr(rFd.error());
	auto wFd = self->fileContext()->attachFile(pair[1], flags & O_CLOEXEC);
	if(!wFd) {
		self->fileContext()->closeFile(rFd.value());
		co_return -linuxErr(wFd.error());
	}

	int fds[2] = {(int)rFd.value(), (int)wFd.value()};
	if(!co_await memWrite(self->vmContext()->getSpace(), fdArrayPtr,
				sizeof(fds), fds))
		co_return -EFAULT;
	co_return 0;
}

// faccessat/faccessat2: unix permission check against the effective ids.
async::result<int64_t> linuxFAccessat(std::shared_ptr<Process> self, int dirfd,
		std::string path, int mode, bool nofollow) {
	if(mode & ~(R_OK | W_OK | X_OK)) // F_OK == 0
		co_return -EINVAL;

	auto stats = co_await statsAt(self, dirfd, std::move(path), nofollow);
	if(!stats)
		co_return stats.error();

	if(mode == 0)
		co_return 0;

	uint32_t stMode = stats->mode;
	uid_t euid = self->threadGroup()->euid();
	gid_t egid = self->threadGroup()->egid();

	if(euid == 0) {
		// Root needs at least one x bit for execute checks.
		if((mode & X_OK) && !(stMode & 0111))
			co_return -EACCES;
		co_return 0;
	}

	unsigned shift;
	if((int)euid == stats->uid) {
		shift = 6;
	}else if((int)egid == stats->gid) {
		shift = 3;
	}else{
		shift = 0;
	}
	unsigned granted = (stMode >> shift) & 7;
	unsigned want = (unsigned)mode;
	if((want & granted) != want)
		co_return -EACCES;
	co_return 0;
}

} // anonymous namespace

async::result<LinuxSyscallOutcome> handleLinuxSyscall(std::shared_ptr<Process> self,
		helix::BorrowedDescriptor thread, uint64_t nr,
		const std::array<uint64_t, 6> &args) {
	uint64_t a0 = args[0];
	uint64_t a1 = args[1];
	uint64_t a2 = args[2];
	uint64_t a3 = args[3];
	uint64_t a4 = args[4];
	uint64_t a5 = args[5];

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
	case kLinuxNrIoctl:
		ret = co_await linuxIoctl(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrPipe:
	case kLinuxNrPipe2:
		ret = co_await linuxPipe2(self.get(), a0, nr == kLinuxNrPipe ? 0 : (uint32_t)a1);
		break;
	case kLinuxNrGetdents64:
		ret = co_await linuxGetdents64(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrFaccessat:
	case kLinuxNrFaccessat2: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
					a1, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await linuxFAccessat(self, (int)(int64_t)a0, std::move(*pathOpt),
					(int)a2, a3 & kLinuxAtSymlinkNofollow);
	} break;
	case kLinuxNrStatx: {
		auto pathOpt = co_await memReadString(self->vmContext()->getSpace(),
					a1, kLinuxPathMax);
		if(!pathOpt) {
			ret = -EFAULT;
			break;
		}
		ret = co_await linuxStatx(self, (int)(int64_t)a0, std::move(*pathOpt),
					(uint32_t)a2, a4);
	} break;
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
