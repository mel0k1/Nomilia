// Nomilia: Linux syscall personality served by the POSIX subsystem.
// Thor forwards file/process Linux syscalls via the superLinuxSyscall
// observe upcall; this file decodes them from the raw Linux registers and
// re-runs them through the regular POSIX/VFS APIs of the process.
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
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
#include "net.hpp"
#include "extern_socket.hpp"
#include "un-socket.hpp"
#include "process.hpp"
#include "vfs.hpp"
#include "netlink/nl-socket.hpp"
#include <linux/netlink.h>

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

// Linux x86_64 syscall numbers, v4 (sockets and signals).
constexpr uint64_t kLinuxNrRtSigaction = 13;
constexpr uint64_t kLinuxNrRtSigprocmask = 14;
constexpr uint64_t kLinuxNrRtSigreturn = 15;
constexpr uint64_t kLinuxNrSocket = 41;
constexpr uint64_t kLinuxNrConnect = 42;
constexpr uint64_t kLinuxNrAccept = 43;
constexpr uint64_t kLinuxNrSendto = 44;
constexpr uint64_t kLinuxNrRecvfrom = 45;
constexpr uint64_t kLinuxNrSendmsg = 46;
constexpr uint64_t kLinuxNrRecvmsg = 47;
constexpr uint64_t kLinuxNrShutdown = 48;
constexpr uint64_t kLinuxNrBind = 49;
constexpr uint64_t kLinuxNrListen = 50;
constexpr uint64_t kLinuxNrGetsockname = 51;
constexpr uint64_t kLinuxNrGetpeername = 52;
constexpr uint64_t kLinuxNrSocketpair = 53;
constexpr uint64_t kLinuxNrSetsockopt = 54;
constexpr uint64_t kLinuxNrGetsockopt = 55;
constexpr uint64_t kLinuxNrKill = 62;
constexpr uint64_t kLinuxNrTgkill = 234;
constexpr uint64_t kLinuxNrAccept4 = 288;

// Linux uapi bits that the libc headers do not provide under these names.
constexpr uint32_t kLinuxSockTypeMask = 0xF;
constexpr uint32_t kLinuxSaSiginfo = 4;
constexpr uint32_t kLinuxSaOnstack = 0x08000000;
constexpr uint32_t kLinuxSaRestorer = 0x04000000;
constexpr uint32_t kLinuxSaNodefer = 0x40000000;
constexpr uint32_t kLinuxSaResethand = 0x80000000;
constexpr int kLinuxSigBlock = 0;
constexpr int kLinuxSigUnblock = 1;
constexpr int kLinuxSigSetmask = 2;
constexpr uint64_t kLinuxUnblockableSet =
	(UINT64_C(1) << (SIGKILL - 1)) | (UINT64_C(1) << (SIGSTOP - 1));

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

// Linux puts the file type into st_mode; managarm keeps it in VfsType.
uint32_t linuxFileType(VfsType type) {
	switch(type) {
	case VfsType::directory: return 0x4000; // S_IFDIR
	case VfsType::regular: return 0x8000;   // S_IFREG
	case VfsType::charDevice: return 0x2000; // S_IFCHR
	case VfsType::blockDevice: return 0x6000; // S_IFBLK
	case VfsType::fifo: return 0x1000;      // S_IFIFO
	case VfsType::symlink: return 0xA000;   // S_IFLNK
	case VfsType::socket: return 0xC000;    // S_IFSOCK
	default: return 0;
	}
}

void fillLinuxStat(LinuxStat &st, const FileStats &fs, VfsType type) {
	st.st_ino = fs.inodeNumber;
	st.st_nlink = fs.numLinks;
	st.st_mode = linuxFileType(type) | (fs.mode & 07777);
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

void fillLinuxStatx(LinuxStatx &stx, const FileStats &fs, VfsType type) {
	stx.stxMask = kStatxBasicMask;
	stx.stxBlksize = 4096;
	stx.stxAttributesMask = 0;
	stx.stxNlink = fs.numLinks;
	stx.stxUid = fs.uid;
	stx.stxGid = fs.gid;
	stx.stxMode = linuxFileType(type) | (fs.mode & 07777);
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
	fillLinuxStat(st, stats.value(), link->getTarget()->getType());
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
	fillLinuxStat(st, stats.value(), link->getTarget()->getType());
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

// Resolves a path relative to dirfd and returns the node stats plus the
// VFS node type (-errno on error).
async::result<std::expected<std::pair<FileStats, VfsType>, int64_t>> statsAt(
		std::shared_ptr<Process> self, int dirfd, std::string path, bool nofollow) {
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

	auto target = resolver.currentLink()->getTarget();
	auto stats = co_await target->getStats();
	if(!stats)
		co_return std::unexpected(-linuxErr(stats.error()));
	co_return std::make_pair(stats.value(), target->getType());
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
			co_return -linuxFsErr(entry.error() | protocols::fs::toFsProtoError);
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
	VfsType nodeType = VfsType::null;
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
		nodeType = link->getTarget()->getType();
	}else{
		auto stats = co_await statsAt(self, dirfd, std::move(path),
					flags & kLinuxAtSymlinkNofollow);
		if(!stats)
			co_return stats.error();
		nodeStats = stats->first;
		nodeType = stats->second;
	}

	if(!bufPtr)
		co_return -EFAULT;
	LinuxStatx stx{};
	fillLinuxStatx(stx, nodeStats, nodeType);
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

	uint32_t stMode = stats->first.mode;
	uid_t euid = self->threadGroup()->euid();
	gid_t egid = self->threadGroup()->egid();

	if(euid == 0) {
		// Root needs at least one x bit for execute checks.
		if((mode & X_OK) && !(stMode & 0111))
			co_return -EACCES;
		co_return 0;
	}

	unsigned shift;
	if((int)euid == stats->first.uid) {
		shift = 6;
	}else if((int)egid == stats->first.gid) {
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

// ------------------------------------------------------------------
// v4: sockets and signals.

// Linux x86_64 struct msghdr.
struct LinuxMsgHeader {
	uint64_t msgName;
	uint32_t msgNameLen;
	uint32_t pad0;
	uint64_t msgIov;
	uint64_t msgIovLen;
	uint64_t msgControl;
	uint64_t msgControlLen;
	int32_t msgFlags;
	uint32_t pad1;
};
static_assert(sizeof(LinuxMsgHeader) == 56);

// Linux x86_64 ucontext/sigcontext as stored in an rt_sigframe.
// gregs follows the musl/glibc mcontext_t order (REG_R8..REG_CR2).
struct LinuxSigcontext {
	uint64_t gregs[23];
	uint64_t fpregs;
	uint64_t reserved[8];
};
static_assert(sizeof(LinuxSigcontext) == 256);

struct LinuxUcontext {
	uint64_t ucFlags;
	uint64_t ucLink;
	uint64_t ucStackSp;
	uint32_t ucStackFlags;
	uint32_t ucStackPad;
	uint64_t ucStackSize;
	LinuxSigcontext ucMcontext;
	uint64_t ucSigmask;
};
static_assert(sizeof(LinuxUcontext) == 304);

// rt_sigframe: pretcode(8) + siginfo(128) + ucontext(304); the SIMD blob
// saved by the kernel is appended behind the ucontext.
constexpr size_t kLinuxSigframeInfoOff = 8;
constexpr size_t kLinuxSigframeUcOff = 136;
constexpr size_t kLinuxSigframeFpOff = 440;
// At the rt_sigreturn syscall the restorer has just been RET'd to, so RSP
// points at siginfo and the ucontext sits 128 bytes above it.
constexpr size_t kLinuxSigreturnUcDelta = 128;

size_t linuxSimdStateSize() {
	static size_t cached = [] {
		HelRegisterInfo info{};
		HEL_CHECK(helQueryRegisterInfo(kHelRegsSimd, &info));
		return (size_t)info.setSize;
	}();
	return cached;
}

struct ucred linuxCreds(Process *self) {
	struct ucred creds{};
	creds.pid = self->pid();
	creds.uid = self->threadGroup()->euid();
	creds.gid = self->threadGroup()->egid();
	return creds;
}

// --------------------------------------------------------------- sockets

async::result<int64_t> linuxSocket(Process *self, uint64_t domain,
		uint64_t type, uint64_t protocol) {
	if(type & ~uint64_t(kLinuxSockTypeMask | SOCK_NONBLOCK | SOCK_CLOEXEC))
		co_return -EINVAL;
	uint32_t flags = 0;
	if(type & SOCK_NONBLOCK)
		flags |= SOCK_NONBLOCK;
	if(type & SOCK_CLOEXEC)
		flags |= SOCK_CLOEXEC;
	int socktype = type & kLinuxSockTypeMask;

	smarter::shared_ptr<File, FileHandle> file;
	if(domain == AF_UNIX) {
		if(socktype != SOCK_DGRAM && socktype != SOCK_STREAM
				&& socktype != SOCK_SEQPACKET)
			co_return -EPROTOTYPE;
		if(protocol)
			co_return -EPROTONOSUPPORT;
		auto un = un_socket::createSocketFile(flags & SOCK_NONBLOCK, socktype);
		if(!un)
			co_return -linuxErr(un.error());
		file = std::move(un.value());
	}else if(domain == AF_NETLINK) {
		if(socktype != SOCK_RAW && socktype != SOCK_DGRAM)
			co_return -ESOCKTNOSUPPORT;
		if(protocol == NETLINK_ROUTE) {
			file = co_await extern_socket::createSocket(
				co_await net::getNetLane(), domain, socktype,
				protocol, flags & SOCK_NONBLOCK);
		}else if(netlink::nl_socket::protocol_supported(protocol)) {
			file = netlink::nl_socket::createSocketFile(protocol, socktype,
					flags & SOCK_NONBLOCK);
		}else{
			co_return -EPROTONOSUPPORT;
		}
	}else if(domain == AF_INET || domain == AF_PACKET) {
		file = co_await extern_socket::createSocket(
			co_await net::getNetLane(), domain, socktype,
			protocol, flags & SOCK_NONBLOCK);
	}else{
		co_return -EAFNOSUPPORT;
	}

	auto fd = self->fileContext()->attachFile(file, flags & SOCK_CLOEXEC);
	if(!fd)
		co_return -linuxErr(fd.error());
	co_return fd.value();
}

async::result<int64_t> linuxSocketpair(Process *self, uint64_t domain,
		uint64_t type, uint64_t protocol, uint64_t svPtr) {
	if(domain != AF_UNIX)
		co_return -EOPNOTSUPP;
	if(type & ~uint64_t(kLinuxSockTypeMask | SOCK_NONBLOCK | SOCK_CLOEXEC))
		co_return -EINVAL;
	uint32_t flags = 0;
	if(type & SOCK_NONBLOCK)
		flags |= SOCK_NONBLOCK;
	if(type & SOCK_CLOEXEC)
		flags |= SOCK_CLOEXEC;
	int socktype = type & kLinuxSockTypeMask;
	if(socktype != SOCK_DGRAM && socktype != SOCK_STREAM
			&& socktype != SOCK_SEQPACKET)
		co_return -EPROTOTYPE;
	if(protocol && protocol != PF_UNSPEC)
		co_return -EPROTONOSUPPORT;

	auto pair = un_socket::createSocketPair(self,
			flags & SOCK_NONBLOCK, socktype);
	auto fd0 = self->fileContext()->attachFile(std::get<0>(pair),
			flags & SOCK_CLOEXEC);
	auto fd1 = self->fileContext()->attachFile(std::get<1>(pair),
			flags & SOCK_CLOEXEC);
	if(!fd0 || !fd1) {
		if(fd0)
			self->fileContext()->closeFile(fd0.value());
		if(fd1)
			self->fileContext()->closeFile(fd1.value());
		co_return -linuxErr(!fd0 ? fd0.error() : fd1.error());
	}
	int fds[2] = {fd0.value(), fd1.value()};
	if(!co_await memWrite(self->vmContext()->getSpace(), svPtr,
			sizeof(fds), fds))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxBind(Process *self, int fd, uint64_t addrPtr,
		uint64_t addrLen) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	std::byte addrBuf[128];
	if(addrLen > sizeof(addrBuf))
		co_return -EINVAL;
	if(addrLen && !co_await memRead(self->vmContext()->getSpace(), addrPtr,
			addrLen, addrBuf))
		co_return -EFAULT;
	auto e = co_await file->bind(self, addrBuf, addrLen);
	co_return e == protocols::fs::Error::none ? 0 : -linuxFsErr(e);
}

async::result<int64_t> linuxConnect(Process *self, int fd, uint64_t addrPtr,
		uint64_t addrLen) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	std::byte addrBuf[128];
	if(addrLen > sizeof(addrBuf))
		co_return -EINVAL;
	if(addrLen && !co_await memRead(self->vmContext()->getSpace(), addrPtr,
			addrLen, addrBuf))
		co_return -EFAULT;
	auto e = co_await file->connect(self, addrBuf, addrLen);
	co_return e == protocols::fs::Error::none ? 0 : -linuxFsErr(e);
}

async::result<int64_t> linuxListen(Process *self, int fd, int backlog) {
	(void)backlog;
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	auto e = co_await file->listen();
	co_return e == protocols::fs::Error::none ? 0 : -linuxFsErr(e);
}

async::result<int64_t> linuxAccept(Process *self, int fd, uint64_t addrPtr,
		uint64_t addrLenPtr, uint32_t flags) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	auto result = co_await file->accept(self);
	if(!result)
		co_return -linuxErr(result.error());
	auto newFile = result.value();
	if(flags & SOCK_NONBLOCK)
		co_await newFile->setFileFlags(
			co_await newFile->getFileFlags() | O_NONBLOCK);
	auto newFd = self->fileContext()->attachFile(newFile, flags & SOCK_CLOEXEC);
	if(!newFd)
		co_return -linuxErr(newFd.error());

	if(addrPtr) {
		std::byte addrBuf[128];
		size_t written = co_await newFile->sockname(addrBuf, sizeof(addrBuf));
		if(addrLenPtr) {
			uint32_t cap = 0;
			if(!co_await memRead(self->vmContext()->getSpace(), addrLenPtr,
					sizeof(uint32_t), &cap))
				co_return -EFAULT;
			size_t out = std::min<size_t>(written, cap);
			if(out && !co_await memWrite(self->vmContext()->getSpace(),
					addrPtr, out, addrBuf))
				co_return -EFAULT;
			uint32_t real = written;
			if(!co_await memWrite(self->vmContext()->getSpace(), addrLenPtr,
					sizeof(uint32_t), &real))
				co_return -EFAULT;
		}
	}
	co_return newFd.value();
}

async::result<int64_t> linuxSendto(Process *self, int fd, uint64_t bufPtr,
		size_t count, uint32_t flags, uint64_t addrPtr, uint64_t addrLen) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	auto bounce = std::make_unique<char[]>(count ? count : 1);
	if(count && !co_await memRead(self->vmContext()->getSpace(), bufPtr,
			count, bounce.get()))
		co_return -EFAULT;
	std::byte addrBuf[128];
	if(addrLen > sizeof(addrBuf))
		co_return -EINVAL;
	if(addrLen && !co_await memRead(self->vmContext()->getSpace(), addrPtr,
			addrLen, addrBuf))
		co_return -EFAULT;

	auto result = co_await file->sendMsg(self, flags, bounce.get(), count,
			addrBuf, addrPtr ? addrLen : 0, {}, linuxCreds(self));
	if(!result)
		co_return -linuxFsErr(result.error());
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxRecvfrom(Process *self, int fd, uint64_t bufPtr,
		size_t count, uint32_t flags, uint64_t addrPtr, uint64_t addrLenPtr) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	count = std::min<size_t>(count, kLinuxIoMax);
	auto bounce = std::make_unique<char[]>(count ? count : 1);
	std::byte addrBuf[128];
	auto result = co_await file->recvMsg(self, flags, bounce.get(), count,
			addrBuf, sizeof(addrBuf), 0);
	if(std::holds_alternative<protocols::fs::Error>(result))
		co_return -linuxFsErr(std::get<protocols::fs::Error>(result));
	auto &data = std::get<protocols::fs::RecvData>(result);
	if(data.dataLength && !co_await memWrite(self->vmContext()->getSpace(),
			bufPtr, data.dataLength, bounce.get()))
		co_return -EFAULT;
	if(addrPtr && data.addressLength) {
		uint32_t cap = 0;
		if(addrLenPtr && !co_await memRead(self->vmContext()->getSpace(),
				addrLenPtr, sizeof(uint32_t), &cap))
			co_return -EFAULT;
		size_t out = std::min<size_t>(data.addressLength, cap);
		if(out && !co_await memWrite(self->vmContext()->getSpace(),
				addrPtr, out, addrBuf))
			co_return -EFAULT;
		if(addrLenPtr) {
			uint32_t real = data.addressLength;
			if(!co_await memWrite(self->vmContext()->getSpace(), addrLenPtr,
					sizeof(uint32_t), &real))
				co_return -EFAULT;
		}
	}
	co_return (int64_t)data.dataLength;
}

async::result<std::optional<std::vector<std::pair<uint64_t, size_t>>>>
linuxReadIovecs(Process *self, uint64_t iovPtr, uint64_t iovLen) {
	if(iovLen > 1024)
		co_return std::nullopt;
	std::vector<std::pair<uint64_t, size_t>> iovs;
	size_t total = 0;
	for(size_t i = 0; i < iovLen; i++) {
		uint64_t ent[2];
		if(!co_await memRead(self->vmContext()->getSpace(),
				iovPtr + i * sizeof(ent), sizeof(ent), ent))
			co_return std::nullopt;
		total += ent[1];
		if(total > kLinuxIoMax)
			co_return std::nullopt;
		iovs.push_back({ent[0], ent[1]});
	}
	co_return iovs;
}

async::result<int64_t> linuxSendmsg(Process *self, int fd, uint64_t msghdrPtr,
		uint32_t flags) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	LinuxMsgHeader mh;
	if(!co_await memRead(self->vmContext()->getSpace(), msghdrPtr,
			sizeof(mh), &mh))
		co_return -EFAULT;
	if(mh.msgControl && mh.msgControlLen)
		co_return -EINVAL; // v4: no cmsg support
	auto iovs = co_await linuxReadIovecs(self, mh.msgIov, mh.msgIovLen);
	if(!iovs)
		co_return -EINVAL;
	size_t total = 0;
	for(auto &iov : *iovs)
		total += iov.second;
	auto bounce = std::make_unique<char[]>(total ? total : 1);
	size_t off = 0;
	for(auto &iov : *iovs) {
		if(iov.second && !co_await memRead(self->vmContext()->getSpace(),
				iov.first, iov.second, bounce.get() + off))
			co_return -EFAULT;
		off += iov.second;
	}
	std::byte addrBuf[128];
	if(mh.msgNameLen > sizeof(addrBuf))
		co_return -EINVAL;
	if(mh.msgName && mh.msgNameLen && !co_await memRead(
			self->vmContext()->getSpace(), mh.msgName, mh.msgNameLen, addrBuf))
		co_return -EFAULT;

	auto result = co_await file->sendMsg(self, flags, bounce.get(), total,
			addrBuf, mh.msgName ? mh.msgNameLen : 0, {}, linuxCreds(self));
	if(!result)
		co_return -linuxFsErr(result.error());
	co_return (int64_t)result.value();
}

async::result<int64_t> linuxRecvmsg(Process *self, int fd, uint64_t msghdrPtr,
		uint32_t flags) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	LinuxMsgHeader mh;
	if(!co_await memRead(self->vmContext()->getSpace(), msghdrPtr,
			sizeof(mh), &mh))
		co_return -EFAULT;
	if(mh.msgControl && mh.msgControlLen)
		co_return -EINVAL; // v4: no cmsg support
	auto iovs = co_await linuxReadIovecs(self, mh.msgIov, mh.msgIovLen);
	if(!iovs)
		co_return -EINVAL;
	size_t total = 0;
	for(auto &iov : *iovs)
		total += iov.second;
	auto bounce = std::make_unique<char[]>(total ? total : 1);
	std::byte addrBuf[128];
	auto result = co_await file->recvMsg(self, flags, bounce.get(), total,
			addrBuf, sizeof(addrBuf), 0);
	if(std::holds_alternative<protocols::fs::Error>(result))
		co_return -linuxFsErr(std::get<protocols::fs::Error>(result));
	auto &data = std::get<protocols::fs::RecvData>(result);

	// Split the bounce buffer back into the iovec chain.
	size_t off = 0;
	for(auto &iov : *iovs) {
		size_t chunk = std::min(iov.second, total - off);
		if(chunk && !co_await memWrite(self->vmContext()->getSpace(),
				iov.first, chunk, bounce.get() + off))
			co_return -EFAULT;
		off += chunk;
	}

	LinuxMsgHeader out = mh;
	out.msgNameLen = 0;
	out.msgControlLen = 0;
	out.msgFlags = (int32_t)data.flags;
	if(mh.msgName && data.addressLength) {
		out.msgNameLen = std::min<uint32_t>((uint32_t)data.addressLength,
				mh.msgNameLen);
		if(out.msgNameLen && !co_await memWrite(self->vmContext()->getSpace(),
				mh.msgName, out.msgNameLen, addrBuf))
			co_return -EFAULT;
	}
	if(!co_await memWrite(self->vmContext()->getSpace(), msghdrPtr,
			sizeof(out), &out))
		co_return -EFAULT;
	co_return (int64_t)data.dataLength;
}

async::result<int64_t> linuxShutdown(Process *self, int fd, int how) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	if(how < 0 || how > 2)
		co_return -EINVAL;
	auto e = co_await file->shutdown(how);
	co_return e == protocols::fs::Error::none ? 0 : -linuxFsErr(e);
}

async::result<int64_t> linuxSocknameGet(Process *self, int fd,
		uint64_t addrPtr, uint64_t addrLenPtr, bool peer) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	std::byte addrBuf[128];
	uint32_t cap = sizeof(addrBuf);
	if(addrLenPtr && !co_await memRead(self->vmContext()->getSpace(),
			addrLenPtr, sizeof(uint32_t), &cap))
		co_return -EFAULT;
	cap = std::min<uint32_t>(cap, sizeof(addrBuf));

	size_t written = 0;
	if(peer) {
		auto result = co_await file->peername(addrBuf, cap);
		if(!result)
			co_return -linuxFsErr(result.error());
		written = result.value();
	}else{
		written = co_await file->sockname(addrBuf, cap);
	}

	if(addrPtr && written && !co_await memWrite(self->vmContext()->getSpace(),
			addrPtr, written, addrBuf))
		co_return -EFAULT;
	uint32_t real = written;
	if(addrLenPtr && !co_await memWrite(self->vmContext()->getSpace(),
			addrLenPtr, sizeof(uint32_t), &real))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxSetsockopt(Process *self, int fd, int layer,
		int number, uint64_t optPtr, uint64_t optLen) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	if(optLen > 4096)
		co_return -EINVAL;
	std::vector<char> optbuf(optLen);
	if(optLen && !co_await memRead(self->vmContext()->getSpace(), optPtr,
			optLen, optbuf.data()))
		co_return -EFAULT;
	auto e = co_await file->setSocketOption(layer, number, std::move(optbuf));
	co_return e ? 0 : -linuxFsErr(e.error());
}

async::result<int64_t> linuxGetsockopt(Process *self, int fd, int layer,
		int number, uint64_t optPtr, uint64_t optLenPtr) {
	auto file = self->fileContext()->getFile(fd);
	if(!file)
		co_return -EBADF;
	uint32_t optLen = 0;
	if(optLenPtr && !co_await memRead(self->vmContext()->getSpace(),
			optLenPtr, sizeof(uint32_t), &optLen))
		co_return -EFAULT;
	if(optLen > 4096)
		co_return -EINVAL;
	std::vector<char> optbuf(optLen);
	auto e = co_await file->getSocketOption(self, layer, number, optbuf);
	if(!e)
		co_return -linuxFsErr(e.error());
	size_t out = std::min<size_t>(optbuf.size(), optLen);
	if(optPtr && out && !co_await memWrite(self->vmContext()->getSpace(),
			optPtr, out, optbuf.data()))
		co_return -EFAULT;
	uint32_t real = optbuf.size();
	if(optLenPtr && !co_await memWrite(self->vmContext()->getSpace(),
			optLenPtr, sizeof(uint32_t), &real))
		co_return -EFAULT;
	co_return 0;
}

// --------------------------------------------------------------- signals

uint32_t linuxFlagsFromHandler(const SignalHandler &h) {
	uint32_t out = 0;
	if(h.flags & signalInfo)
		out |= kLinuxSaSiginfo;
	if(h.flags & signalOnce)
		out |= kLinuxSaResethand;
	if(h.flags & signalReentrant)
		out |= kLinuxSaNodefer;
	if(h.flags & signalOnStack)
		out |= kLinuxSaOnstack;
	if(h.restorerIp)
		out |= kLinuxSaRestorer;
	return out;
}

SignalHandler linuxHandlerFromUser(uint64_t handler, uint64_t flags,
		uint64_t restorer, uint64_t mask) {
	SignalHandler h{};
	if(handler == 0)
		h.disposition = SignalDisposition::none;
	else if(handler == 1)
		h.disposition = SignalDisposition::ignore;
	else
		h.disposition = SignalDisposition::handle;
	h.handlerIp = handler;
	h.restorerIp = (flags & kLinuxSaRestorer) ? restorer : 0;
	uint32_t mflags = 0;
	if(flags & kLinuxSaSiginfo)
		mflags |= signalInfo;
	if(flags & kLinuxSaResethand)
		mflags |= signalOnce;
	if(flags & kLinuxSaNodefer)
		mflags |= signalReentrant;
	if(flags & kLinuxSaOnstack)
		mflags |= signalOnStack;
	h.flags = mflags;
	h.mask = mask & ~kLinuxUnblockableSet;
	return h;
}

async::result<int64_t> linuxRtSigaction(Process *self, int signo,
		uint64_t actPtr, uint64_t oldPtr, uint64_t sigsetsize) {
	if(signo <= 0 || signo > 64 || sigsetsize != 8)
		co_return -EINVAL;
	auto ctx = self->threadGroup()->signalContext();
	if(actPtr) {
		if(signo == SIGKILL || signo == SIGSTOP)
			co_return -EINVAL;
		uint64_t raw[4];
		if(!co_await memRead(self->vmContext()->getSpace(), actPtr,
				sizeof(raw), raw))
			co_return -EFAULT;
		auto handler = linuxHandlerFromUser(raw[0], raw[1], raw[2], raw[3]);
		auto old = ctx->changeHandler(signo, handler);
		if(oldPtr) {
			uint64_t outraw[4] = {
				old.handlerIp, linuxFlagsFromHandler(old),
				old.restorerIp, old.mask
			};
			if(!co_await memWrite(self->vmContext()->getSpace(), oldPtr,
					sizeof(outraw), outraw))
				co_return -EFAULT;
		}
	}else if(oldPtr) {
		auto old = ctx->getHandler(signo);
		uint64_t outraw[4] = {
			old.handlerIp, linuxFlagsFromHandler(old),
			old.restorerIp, old.mask
		};
		if(!co_await memWrite(self->vmContext()->getSpace(), oldPtr,
				sizeof(outraw), outraw))
			co_return -EFAULT;
	}
	co_return 0;
}

async::result<int64_t> linuxRtSigprocmask(Process *self, int how,
		uint64_t setPtr, uint64_t oldPtr, uint64_t sigsetsize) {
	if(sigsetsize != 8)
		co_return -EINVAL;
	uint64_t former = self->signalMask();
	if(setPtr) {
		uint64_t mask;
		if(!co_await memRead(self->vmContext()->getSpace(), setPtr,
				sizeof(mask), &mask))
			co_return -EFAULT;
		uint64_t updated;
		if(how == kLinuxSigBlock)
			updated = former | mask;
		else if(how == kLinuxSigUnblock)
			updated = former & ~mask;
		else if(how == kLinuxSigSetmask)
			updated = mask;
		else
			co_return -EINVAL;
		self->setSignalMask(updated & ~kLinuxUnblockableSet);
	}
	if(oldPtr && !co_await memWrite(self->vmContext()->getSpace(), oldPtr,
			sizeof(uint64_t), &former))
		co_return -EFAULT;
	co_return 0;
}

async::result<int64_t> linuxKill(Process *self, int64_t pid, int64_t sig) {
	if(sig < 0 || sig > 64)
		co_return -EINVAL;
	UserSignal info{};
	info.pid = self->pid();
	info.uid = self->threadGroup()->uid();
	if(pid > 0) {
		auto tg = ThreadGroup::findThreadGroup(pid);
		if(!tg)
			co_return -ESRCH;
		if(sig)
			tg->issueThreadGroupSignal(sig, info);
	}else if(pid == 0) {
		auto pg = self->pgPointer();
		if(!pg)
			co_return -ESRCH;
		if(sig)
			pg->issueSignalToGroup(sig, info);
	}else if(pid == -1) {
		co_return -EPERM;
	}else{
		auto pg = ProcessGroup::findProcessGroup(-pid);
		if(!pg)
			co_return -ESRCH;
		if(sig)
			pg->issueSignalToGroup(sig, info);
	}
	co_return 0;
}

async::result<int64_t> linuxTgkill(Process *self, int64_t tgid, int64_t tid,
		int64_t sig) {
	if(sig < 0 || sig > 64)
		co_return -EINVAL;
	auto tg = ThreadGroup::findThreadGroup(tgid);
	if(!tg)
		co_return -ESRCH;
	auto target = tg->findThread(tid);
	if(!target)
		co_return -ESRCH;
	if(sig) {
		UserSignal info{};
		info.pid = self->pid();
		info.uid = self->threadGroup()->uid();
		target->issueThreadSignal(sig, info);
	}
	co_return 0;
}

} // anonymous namespace

// Signal delivery for Linux-personality threads: save the register image and
// the kernel SIMD blob into an rt_sigframe on the user stack, then enter the
// handler with the Linux calling convention. The SA_RESTORER trampoline
// (mandatory on x86_64) issues rt_sigreturn, which restores the frame.
async::result<void> raiseLinuxContext(SignalItem *item, Process *process,
		SignalContext::SignalHandling handling) {
#if defined(__x86_64__)
	auto thread = process->threadDescriptor();
	uintptr_t sigregs[19];
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsSignal, &sigregs));

	uint64_t newMask = process->signalMask() | handling.handler.mask;
	if(!(handling.handler.flags & signalReentrant))
		newMask |= UINT64_C(1) << (item->signalNumber - 1);
	process->setSignalMask(newMask);

	auto simdSize = linuxSimdStateSize();
	std::vector<std::byte> simd(simdSize);
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsSimd, simd.data()));

	size_t total = kLinuxSigframeFpOff + simdSize;
	uintptr_t nsp = sigregs[15] - 128; // red zone
	uintptr_t frame = ((nsp - total) & ~uintptr_t(15)) - 8;

	std::vector<std::byte> image(total);
	memset(image.data(), 0, total);
	uint64_t pretcode = handling.handler.restorerIp;
	memcpy(image.data(), &pretcode, sizeof(pretcode));
	if(handling.handler.flags & signalInfo) {
		siginfo_t si;
		memset(&si, 0, sizeof(si));
		si.si_signo = item->signalNumber;
		std::visit(CompileSignalInfo{&si}, item->info);
		memcpy(image.data() + kLinuxSigframeInfoOff, &si,
				std::min(sizeof(si), size_t(128)));
	}
	LinuxUcontext uc;
	memset(&uc, 0, sizeof(uc));
	for(int i = 0; i < 19; i++)
		uc.ucMcontext.gregs[i] = sigregs[i];
	uc.ucMcontext.fpregs = frame + kLinuxSigframeFpOff;
	uc.ucSigmask = newMask;
	memcpy(image.data() + kLinuxSigframeUcOff, &uc, sizeof(uc));
	memcpy(image.data() + kLinuxSigframeFpOff, simd.data(), simdSize);

	auto storeFrame = co_await helix_ng::writeMemory(thread, frame, total,
			image.data());
	HEL_CHECK(storeFrame.error());

	sigregs[8] = item->signalNumber; // rdi = signo
	sigregs[9] = frame + kLinuxSigframeInfoOff; // rsi = siginfo
	sigregs[12] = frame + kLinuxSigframeUcOff; // rdx = ucontext
	sigregs[13] = 0; // rax
	sigregs[15] = frame;
	sigregs[16] = handling.handler.handlerIp;
	HEL_CHECK(helStoreRegisters(thread.getHandle(), kHelRegsSignal, &sigregs));
#else
	(void)item;
	(void)process;
	(void)handling;
#endif
	delete item;
	co_return;
}

// rt_sigreturn has no return value: the register image (including RAX) is
// restored from the frame, so the caller must only resume the thread.
async::result<LinuxSyscallOutcome> linuxRtSigreturn(
		helix::BorrowedDescriptor thread, Process *self) {
#if defined(__x86_64__)
	uintptr_t sigregs[19];
	HEL_CHECK(helLoadRegisters(thread.getHandle(), kHelRegsSignal, &sigregs));
	uintptr_t ucAddr = sigregs[15] + kLinuxSigreturnUcDelta;

	LinuxUcontext uc;
	auto load = co_await helix_ng::readMemory(thread, ucAddr, sizeof(uc), &uc);
	if(load.error() != kHelErrNone) {
		std::cout << "posix: linux-abi: rt_sigreturn with bad frame" << std::endl;
		co_await self->terminate();
		co_await self->threadGroup()->terminateGroup(TerminationBySignal{SIGILL});
		co_return LinuxSyscallOutcome{false, 0, false};
	}

	self->setSignalMask(uc.ucSigmask & ~kLinuxUnblockableSet);

	if(uc.ucMcontext.fpregs) {
		auto simdSize = linuxSimdStateSize();
		std::vector<std::byte> simd(simdSize);
		auto loadSimd = co_await helix_ng::readMemory(thread,
				(uintptr_t)uc.ucMcontext.fpregs, simdSize, simd.data());
		if(loadSimd.error() == kHelErrNone)
			HEL_CHECK(helStoreRegisters(thread.getHandle(), kHelRegsSimd,
					simd.data()));
	}

	for(int i = 0; i < 19; i++)
		sigregs[i] = uc.ucMcontext.gregs[i];
	HEL_CHECK(helStoreRegisters(thread.getHandle(), kHelRegsSignal, &sigregs));

	co_return LinuxSyscallOutcome{false, 0, true};
#else
	(void)thread;
	(void)self;
	co_return LinuxSyscallOutcome{true, -ENOSYS};
#endif
}
async::result<LinuxSyscallOutcome> linuxRtSigreturn(
		helix::BorrowedDescriptor thread, Process *self);
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
	case kLinuxNrSocket:
		ret = co_await linuxSocket(self.get(), a0, a1, a2);
		break;
	case kLinuxNrSocketpair:
		ret = co_await linuxSocketpair(self.get(), a0, a1, a2, a3);
		break;
	case kLinuxNrBind:
		ret = co_await linuxBind(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrConnect:
		ret = co_await linuxConnect(self.get(), (int)a0, a1, a2);
		break;
	case kLinuxNrListen:
		ret = co_await linuxListen(self.get(), (int)a0, (int)a1);
		break;
	case kLinuxNrAccept:
	case kLinuxNrAccept4:
		ret = co_await linuxAccept(self.get(), (int)a0, a1, a2,
				nr == kLinuxNrAccept4 ? (uint32_t)a3 : 0);
		break;
	case kLinuxNrSendto:
		ret = co_await linuxSendto(self.get(), (int)a0, a1, a2,
				(uint32_t)a3, a4, a5);
		break;
	case kLinuxNrRecvfrom:
		ret = co_await linuxRecvfrom(self.get(), (int)a0, a1, a2,
				(uint32_t)a3, a4, a5);
		break;
	case kLinuxNrSendmsg:
		ret = co_await linuxSendmsg(self.get(), (int)a0, a1, (uint32_t)a2);
		break;
	case kLinuxNrRecvmsg:
		ret = co_await linuxRecvmsg(self.get(), (int)a0, a1, (uint32_t)a2);
		break;
	case kLinuxNrShutdown:
		ret = co_await linuxShutdown(self.get(), (int)a0, (int)a1);
		break;
	case kLinuxNrGetsockname:
		ret = co_await linuxSocknameGet(self.get(), (int)a0, a1, a2, false);
		break;
	case kLinuxNrGetpeername:
		ret = co_await linuxSocknameGet(self.get(), (int)a0, a1, a2, true);
		break;
	case kLinuxNrSetsockopt:
		ret = co_await linuxSetsockopt(self.get(), (int)a0, (int)a1, (int)a2,
				a3, a4);
		break;
	case kLinuxNrGetsockopt:
		ret = co_await linuxGetsockopt(self.get(), (int)a0, (int)a1, (int)a2,
				a3, a4);
		break;
	case kLinuxNrKill:
		ret = co_await linuxKill(self.get(), (int64_t)a0, (int64_t)a1);
		break;
	case kLinuxNrTgkill:
		ret = co_await linuxTgkill(self.get(), (int64_t)a0, (int64_t)a1,
				(int64_t)a2);
		break;
	case kLinuxNrRtSigaction:
		ret = co_await linuxRtSigaction(self.get(), (int)a0, a1, a2, a3);
		break;
	case kLinuxNrRtSigprocmask:
		ret = co_await linuxRtSigprocmask(self.get(), (int)a0, a1, a2, a3);
		break;
	case kLinuxNrRtSigreturn:
		co_return co_await linuxRtSigreturn(thread, self.get());
	default:
		std::cout << "posix: linux-abi: unhandled syscall " << nr << std::endl;
		co_return LinuxSyscallOutcome{true, -ENOSYS};
	}
	co_return LinuxSyscallOutcome{true, ret};
}
