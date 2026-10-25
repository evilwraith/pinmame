// license:BSD-3-Clause

// PinMAME Spike 1 subsystem - the game program run natively. See spike1_native.h

#include "spike1_native.h"
#include "spike1_vfs.h"

#include <algorithm>
#include <cstring>

#if defined(__linux__) && defined(__aarch64__)

#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

namespace {

// ARM EABI system call numbers
namespace nr { enum : uint32_t {
	read = 3, write = 4, open = 5, close = 6, execve = 11, mknod = 14, mount = 21, ptrace = 26, sync = 36, kill = 37,
	umount2 = 52, ioctl = 54, fcntl = 55, chroot = 61, sethostname = 74, settimeofday = 79, swapon = 87, reboot = 88,
	setpriority = 97, swapoff = 115, fsync = 118, uname = 122, adjtimex = 124, init_module = 128, delete_module = 129,
	newselect = 142, readv = 145, writev = 146, fdatasync = 148, sched_setparam = 154, sched_setscheduler = 156,
	poll = 168, fcntl64 = 221, sched_setaffinity = 241, set_tid_address = 256, clock_settime = 262, openat = 322,
	mknodat = 324, pselect6 = 335, ppoll = 336, unshare = 337, kexec_load = 347, syncfs = 373, finit_module = 379,
}; }

constexpr int DEVICE_FD = 200, DEVICE_SLOTS = 32;  // the device descriptors: DEVICE_FD .. DEVICE_FD + DEVICE_SLOTS - 1
constexpr uint64_t RECHECK_NS = 1000000;           // as spike1_linux's POLL_RECHECK_NS
constexpr uint32_t O_NONBLOCK_ = 0x800, O_CLOEXEC_ = 0x80000;
constexpr uid_t NOBODY = 65534;
constexpr size_t SMALL_FILE = 64u << 20;           // a file not on disk as a whole is written into the sandbox up to this size

uint64_t mono_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

std::string hex(uint64_t v) { char b[24]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v); return b; }

// ---------------------------------------------------------------- the filter
std::vector<sock_filter> build_filter()
{
	std::vector<sock_filter> f;
	auto stmt = [&](uint16_t code, uint32_t k) { f.push_back(BPF_STMT(code, k)); };
	auto jump = [&](uint32_t k, uint8_t jt, uint8_t jf) { f.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, k, jt, jf)); };
	auto ret_if = [&](uint32_t n, uint32_t action) { jump(n, 0, 1); stmt(BPF_RET | BPF_K, action); };
	const uint32_t arg0 = offsetof(seccomp_data, args); // the low word: the system call's 32-bit argument

	stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
	jump(AUDIT_ARCH_ARM, 1, 0);
	stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW); // the host's own calls up to the exec
	stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr));
	// set_tid_address and uname: the C library's first calls, where the program is held (start())
	for (uint32_t n : { nr::open, nr::openat, nr::newselect, nr::pselect6, nr::poll, nr::ppoll, nr::sync, nr::syncfs, nr::fsync, nr::fdatasync,
			nr::set_tid_address, nr::uname })
		ret_if(n, SECCOMP_RET_USER_NOTIF);
	for (uint32_t n : { nr::sched_setscheduler, nr::sched_setparam, nr::sched_setaffinity, nr::setpriority })
		ret_if(n, SECCOMP_RET_ERRNO | 0); // returns 0, does nothing
	ret_if(nr::execve, SECCOMP_RET_ERRNO | ENOENT);
	for (uint32_t n : { nr::mknod, nr::mknodat, nr::mount, nr::umount2, nr::ptrace, nr::chroot, nr::sethostname, nr::settimeofday,
			nr::swapon, nr::swapoff, nr::reboot, nr::adjtimex, nr::init_module, nr::delete_module, nr::finit_module, nr::clock_settime,
			nr::unshare, nr::kexec_load })
		ret_if(n, SECCOMP_RET_ERRNO | EPERM);
	std::vector<size_t> to_fd_check, to_kill_check;
	for (uint32_t n : { nr::read, nr::write, nr::ioctl, nr::close, nr::readv, nr::writev, nr::fcntl, nr::fcntl64 }) {
		to_fd_check.push_back(f.size());
		jump(n, 0, 0);
	}
	to_kill_check.push_back(f.size());
	jump(nr::kill, 0, 0);
	stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	const size_t fd_check = f.size();          // a device descriptor comes here
	stmt(BPF_LD | BPF_W | BPF_ABS, arg0);
	f.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, DEVICE_FD, 0, 2));
	f.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, DEVICE_FD + DEVICE_SLOTS, 1, 0));
	stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
	stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	const size_t kill_check = f.size();        // kill(-1, ...) would reach every process nobody owns
	stmt(BPF_LD | BPF_W | BPF_ABS, arg0);
	jump(0xffffffffu, 0, 1);
	stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
	stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	for (size_t i : to_fd_check) f[i].jt = uint8_t(fd_check - i - 1);
	for (size_t i : to_kill_check) f[i].jt = uint8_t(kill_check - i - 1);
	return f;
}

// ---------------------------------------------------------------- the child
// The child shares the host's memory until its exec (CLONE_VM | CLONE_VFORK, as posix_spawn does):
// no page tables to copy from a large host, and no GPU mappings inherited. So it runs on
// everything prepared here, and makes raw system calls only: no allocation, no locks, and no C
// library wrapper that thinks it has the host's threads (setresuid would signal them all)
struct child_plan
{
	struct dir { const char *path; mode_t mode; };
	struct wfile { const char *path; const uint8_t *data; size_t size; mode_t mode; };
	struct bind { const char *src, *dst; };
	const dir *dirs = nullptr; size_t ndirs = 0;
	const wfile *files = nullptr; size_t nfiles = 0;
	const bind *binds = nullptr; size_t nbinds = 0;
	const char *root = nullptr, *tmpfs_options = nullptr, *data_src = nullptr, *data_dst = nullptr;
	const char *uid_map = nullptr, *gid_map = nullptr;
	cpu_set_t cpus;
	bool set_cpus = false;
	bool drop_to_nobody = false;   // the host runs as root: the game gets nobody, not root, outside
	sock_fprog prog{};
	int sock = -1;
	const char *exec_path = nullptr;
	char *const *argv = nullptr;
	char *const *envp = nullptr;
};

struct child_report { int32_t step, err; }; // step 0: the listener comes with it

long sys(long n, long a = 0, long b = 0, long c = 0, long d = 0, long e = 0)
{
	const long r = syscall(n, a, b, c, d, e);
	return r < 0 ? -errno : r;
}

[[noreturn]] void child_fail(int sock, int step, long err)
{
	child_report rep{ step, int32_t(-err) };
	iovec iov{ &rep, sizeof(rep) };
	msghdr msg{};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sys(SYS_sendmsg, sock, long(&msg), 0);
	sys(SYS_exit_group, 127);
	for (;;) {}
}

// The steps of the child's set-up, for its report when one fails
enum child_step { STEP_SOCKET = 1, STEP_CLOSE_RANGE, STEP_SETSID, STEP_UNSHARE_NS, STEP_PRIVATE, STEP_TMPFS, STEP_MKDIR, STEP_WRITE,
	STEP_MOUNT_POINT, STEP_BIND, STEP_READ_ONLY, STEP_BIND_DATA, STEP_CHDIR, STEP_SETGROUPS, STEP_SETRESGID, STEP_SETRESUID,
	STEP_DUMPABLE, STEP_UNSHARE_USER, STEP_MAPS, STEP_CHROOT, STEP_AFFINITY, STEP_NO_NEW_PRIVS, STEP_SECCOMP, STEP_SEND, STEP_EXEC };

int child_entry(void *arg)
{
	const child_plan &p = *static_cast<const child_plan *>(arg);
	long r;
#define CHILD_TRY(step, expr) do { if ((r = (expr)) < 0) child_fail(3, step, r); } while (0)
	// the report socket to 3, and nothing else of the host's open
	if (p.sock != 3 && sys(SYS_dup3, p.sock, 3, 0) < 0) child_fail(p.sock, STEP_SOCKET, -EBADF);
	CHILD_TRY(STEP_CLOSE_RANGE, sys(SYS_close_range, 4, ~0u, 0));
	CHILD_TRY(STEP_SETSID, sys(SYS_setsid));
	sys(SYS_umask, 022);
	const long devnull = sys(SYS_openat, AT_FDCWD, long("/dev/null"), O_RDWR);
	if (devnull >= 0) { sys(SYS_dup3, devnull, 0, 0); sys(SYS_close, devnull); }

	// Root to the game, and to the host only who started it: the board runs the game as root, and
	// the game counts on it (it creates its NVRAM files with whatever mode a register holds, then
	// reads them back). Root of a user namespace that maps to the caller's own user gets that and
	// nothing outside; a host that runs as root hands the game to nobody first. Any user may make
	// such a namespace and map itself; the mounts then happen in a mount namespace it owns, and
	// the chroot last, as a chrooted process cannot make a user namespace
	if (p.drop_to_nobody) {
		CHILD_TRY(STEP_SETGROUPS, sys(SYS_setgroups, 0, 0));
		CHILD_TRY(STEP_SETRESGID, sys(SYS_setresgid, NOBODY, NOBODY, NOBODY));
		CHILD_TRY(STEP_SETRESUID, sys(SYS_setresuid, NOBODY, NOBODY, NOBODY));
		CHILD_TRY(STEP_DUMPABLE, sys(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0)); // so it can write its own maps
	}
	CHILD_TRY(STEP_UNSHARE_USER, sys(SYS_unshare, CLONE_NEWUSER));
	const char *const maps[3][2] = { { "/proc/self/setgroups", "deny" }, { "/proc/self/uid_map", p.uid_map }, { "/proc/self/gid_map", p.gid_map } };
	for (const auto &m : maps) {
		const long fd = sys(SYS_openat, AT_FDCWD, long(m[0]), O_WRONLY | O_CLOEXEC);
		if (fd < 0) child_fail(3, STEP_MAPS, fd);
		size_t len = 0;
		while (m[1][len]) len++;
		const long n = sys(SYS_write, fd, long(m[1]), long(len));
		if (n != long(len)) child_fail(3, STEP_MAPS, n < 0 ? n : -EIO);
		sys(SYS_close, fd);
	}

	// the mounts, in a mount namespace of the game's own
	CHILD_TRY(STEP_UNSHARE_NS, sys(SYS_unshare, CLONE_NEWNS));
	CHILD_TRY(STEP_PRIVATE, sys(SYS_mount, 0, long("/"), 0, MS_REC | MS_PRIVATE, 0));
	CHILD_TRY(STEP_TMPFS, sys(SYS_mount, long("tmpfs"), long(p.root), long("tmpfs"), MS_NOSUID | MS_NODEV, long(p.tmpfs_options)));
	for (size_t i = 0; i < p.ndirs; i++) {
		CHILD_TRY(STEP_MKDIR, sys(SYS_mkdirat, AT_FDCWD, long(p.dirs[i].path), p.dirs[i].mode));
		CHILD_TRY(STEP_MKDIR, sys(SYS_fchmodat, AT_FDCWD, long(p.dirs[i].path), p.dirs[i].mode));
	}
	for (size_t i = 0; i < p.nfiles; i++) {
		const long fd = sys(SYS_openat, AT_FDCWD, long(p.files[i].path), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, p.files[i].mode);
		if (fd < 0) child_fail(3, STEP_WRITE, fd);
		for (size_t done = 0; done < p.files[i].size; ) {
			const long n = sys(SYS_write, fd, long(p.files[i].data + done), long(p.files[i].size - done));
			if (n <= 0) child_fail(3, STEP_WRITE, n < 0 ? n : -EIO);
			done += size_t(n);
		}
		sys(SYS_close, fd);
	}
	for (size_t i = 0; i < p.nbinds; i++) {
		const long fd = sys(SYS_openat, AT_FDCWD, long(p.binds[i].dst), O_CREAT | O_WRONLY | O_CLOEXEC, 0444);
		if (fd < 0) child_fail(3, STEP_MOUNT_POINT, fd);
		sys(SYS_close, fd);
		CHILD_TRY(STEP_BIND, sys(SYS_mount, long(p.binds[i].src), long(p.binds[i].dst), 0, MS_BIND, 0));
		// read-only where the source mount's locked flags let a user namespace say so; the game only
		// reads these, so no harm where they do not
		if (sys(SYS_mount, 0, long(p.binds[i].dst), 0, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, 0) < 0)
			sys(SYS_mount, 0, long(p.binds[i].dst), 0, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, 0);
	}
	CHILD_TRY(STEP_BIND_DATA, sys(SYS_mount, long(p.data_src), long(p.data_dst), 0, MS_BIND, 0));
	CHILD_TRY(STEP_CHDIR, sys(SYS_chdir, long(p.root)));
	CHILD_TRY(STEP_CHROOT, sys(SYS_chroot, long(".")));
	CHILD_TRY(STEP_CHROOT, sys(SYS_chdir, long("/")));
	if (p.set_cpus) CHILD_TRY(STEP_AFFINITY, sys(SYS_sched_setaffinity, 0, sizeof(p.cpus), long(&p.cpus)));
	CHILD_TRY(STEP_NO_NEW_PRIVS, sys(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	const long listener = sys(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, long(&p.prog));
	if (listener < 0) child_fail(3, STEP_SECCOMP, listener);
	{
		child_report rep{ 0, 0 };
		iovec iov{ &rep, sizeof(rep) };
		alignas(cmsghdr) char buf[CMSG_SPACE(sizeof(int))] = {};
		msghdr msg{};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);
		cmsghdr *c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		const int fd = int(listener);
		std::memcpy(CMSG_DATA(c), &fd, sizeof(int));
		CHILD_TRY(STEP_SEND, sys(SYS_sendmsg, 3, long(&msg), 0));
	}
	sys(SYS_close, listener);
	// the program gets an empty signal mask (the host's thread may block some), as from a shell
	const uint64_t none = 0;
	sys(SYS_rt_sigprocmask, SIG_SETMASK, long(&none), 0, 8);
	r = sys(SYS_execve, long(p.exec_path), long(p.argv), long(p.envp));
	child_fail(3, STEP_EXEC, r); // the kernel does not run it: no AArch32 support (ENOEXEC), say
#undef CHILD_TRY
}

const char *child_step_name(int step)
{
	static const char *const names[] = { "", "dup the socket", "close_range", "setsid", "unshare the mount namespace", "make mounts private",
		"mount the tmpfs", "make a directory", "write a file", "create a mount point", "bind a set file", "make a set file read-only",
		"bind /data", "chdir", "setgroups", "setresgid", "setresuid", "dumpable", "unshare the user namespace", "write the id maps",
		"chroot", "sched_setaffinity", "no_new_privs", "seccomp", "send the listener", "execve" };
	return step > 0 && size_t(step) < sizeof(names) / sizeof(names[0]) ? names[step] : "set up";
}

// The host file the bytes at data are mapped from, as a whole from its start; empty when they are not
std::string mapped_file(const uint8_t *data, size_t size)
{
	std::ifstream maps("/proc/self/maps");
	std::string line;
	const uintptr_t p = uintptr_t(data);
	while (std::getline(maps, line)) {
		unsigned long long start, end, offset;
		char perms[8];
		int path_at = -1;
		if (std::sscanf(line.c_str(), "%llx-%llx %7s %llx %*s %*s %n", &start, &end, perms, &offset, &path_at) < 4 || path_at < 0) continue;
		if (p < start || p >= end) continue;
		const std::string path = line.substr(size_t(path_at));
		if (path.empty() || path[0] != '/' || offset + (p - start) != 0) return {};
		struct stat st;
		if (path.find(" (deleted)") != std::string::npos || stat(path.c_str(), &st) < 0 || uint64_t(st.st_size) != size) return {};
		return path;
	}
	return {};
}

bool parse_cpus(const std::string &list, cpu_set_t &set)
{
	CPU_ZERO(&set);
	bool any = false;
	for (const char *p = list.c_str(); *p; ) {
		char *end;
		const long a = std::strtol(p, &end, 10);
		if (end == p) return false;
		long b = a;
		if (*end == '-') b = std::strtol(end + 1, &end, 10);
		for (long c = a; c <= b && c < CPU_SETSIZE; c++) { CPU_SET(int(c), &set); any = true; }
		p = *end == ',' ? end + 1 : end;
		if (*end && *end != ',') return false;
	}
	return any;
}

} // anonymous namespace

// ---------------------------------------------------------------- the machine
spike1_native::spike1_native() : m_dev(m_mem) {}
spike1_native::~spike1_native() { stop(); }

bool spike1_native::supported(std::string &why)
{
	// the kernel decides the rest when the sandbox is made: user namespaces, seccomp listeners and
	// AArch32 user mode; start() reports which step it refused
	(void)why;
	return true;
}

uint64_t spike1_native::now_ns() const { return m_t0 ? mono_ns() - m_t0 : 0; }

void spike1_native::log(const std::string &line) const
{
	if (!m_cfg.log) return;
	char t[32];
	std::snprintf(t, sizeof(t), "[%10.6f] ", double(now_ns()) / 1e9);
	m_cfg.log(t + line);
}

uint32_t spike1_native::symbol(const std::string &name) const
{
	auto it = m_symbols.find(name);
	return it == m_symbols.end() ? 0 : it->second;
}

bool spike1_native::start(const config &cfg, std::string &error)
{
	stop();
	m_cfg = cfg;
	if (!supported(error)) return false;
	const file *program = nullptr;
	for (const file &f : m_cfg.files) if (f.name == m_cfg.program) program = &f;
	if (!program || program->size < 52) { error = "the set has no game program"; return false; }

	// the program's symbol table, as spike1_linux::load_elf reads it: objects and functions
	m_symbols.clear();
	m_symbol_sizes.clear();
	{
		const uint8_t *elf = program->data;
		const size_t size = program->size;
		auto u32 = [&](size_t o) { uint32_t v = 0; if (o + 4 <= size) std::memcpy(&v, elf + o, 4); return v; };
		auto u16 = [&](size_t o) { uint16_t v = 0; if (o + 2 <= size) std::memcpy(&v, elf + o, 2); return v; };
		if (std::memcmp(elf, "\x7f" "ELF\x01\x01", 6) != 0 || u16(18) != 40) { error = "the game program is not a 32-bit ARM ELF file"; return false; }
		const uint32_t shoff = u32(32);
		const uint16_t shentsize = u16(46), shnum = u16(48);
		for (uint32_t i = 0; i < shnum && shoff + uint64_t(i + 1) * shentsize <= size; i++) {
			const size_t o = shoff + size_t(i) * shentsize;
			if (u32(o + 4) != 2) continue; // SHT_SYMTAB
			const uint32_t symoff = u32(o + 16), symsize = u32(o + 20), link = u32(o + 24);
			if (link >= shnum) break;
			const uint32_t stroff = u32(shoff + size_t(link) * shentsize + 16);
			for (uint64_t s = symoff; s + 16 <= uint64_t(symoff) + symsize && s + 16 <= size; s += 16) {
				const uint32_t name = u32(size_t(s)), value = u32(size_t(s) + 4);
				const uint8_t type = elf[size_t(s) + 12] & 15;
				if (!value || (type != 1 && type != 2) || uint64_t(stroff) + name >= size) continue;
				const char *n = reinterpret_cast<const char *>(elf + stroff + name);
				m_symbols.emplace(std::string(n, strnlen(n, size - stroff - name)), value);
				m_symbol_sizes.emplace(std::string(n, strnlen(n, size - stroff - name)), u32(size_t(s) + 8));
			}
		}
	}
	for (const auto &s : m_cfg.symbols) { m_symbols[s.name] = s.address; m_symbol_sizes[s.name] = s.size; }
	m_game_files.clear();
	for (const file &f : m_cfg.files) m_game_files.push_back(f.name);

	// our directory: root/ for the sandbox's tmpfs, data/ for /data, filled from the NVRAM block
	char tmpl[] = "/tmp/spike1native.XXXXXX";
	if (!mkdtemp(tmpl)) { error = std::string("mkdtemp: ") + std::strerror(errno); return false; }
	m_dir = tmpl;
	chmod(m_dir.c_str(), 0755);
	mkdir((m_dir + "/root").c_str(), 0755);
	mkdir((m_dir + "/data").c_str(), 0755);
	// the game's root is nobody outside when we are root, else our own user, who owns these already
	const bool as_root = geteuid() == 0;
	if (as_root && chown((m_dir + "/data").c_str(), NOBODY, NOBODY) < 0) { error = std::string("chown: ") + std::strerror(errno); stop(); return false; }
	std::vector<uint8_t> eeproms;
	{
		const std::vector<uint8_t> &b = m_cfg.nvram;
		spike1_vfs vfs;
		bool ok = b.size() >= 5 && std::memcmp(b.data(), "S1ST", 4) == 0 && b[4] == 1;
		size_t p = 5;
		std::vector<std::pair<size_t, size_t>> parts;
		for (int i = 0; ok && i < 2; i++) {
			if (b.size() - p < 4) { ok = false; break; }
			const size_t n = b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (size_t(b[p + 3]) << 24);
			p += 4;
			if (b.size() - p < n) { ok = false; break; }
			parts.push_back({ p, n });
			p += n;
		}
		if (ok) ok = vfs.load(b.data() + parts[0].first, parts[0].second);
		if (ok) {
			eeproms.assign(b.begin() + long(parts[1].first), b.begin() + long(parts[1].first + parts[1].second));
			auto host = [&](const std::string &guest) { return m_dir + guest; };
			for (const std::string &d : vfs.written_directories())
				if (d.rfind("/data/", 0) == 0) { mkdir(host(d).c_str(), 0755); if (as_root) chown(host(d).c_str(), NOBODY, NOBODY); }
			for (const auto &w : vfs.written_files()) {
				if (w.first.rfind("/data/", 0) != 0) continue;
				std::ofstream out(host(w.first), std::ios::binary);
				out.write(reinterpret_cast<const char *>(w.second->data()), std::streamsize(w.second->size()));
				out.close();
				if (as_root) chown(host(w.first).c_str(), NOBODY, NOBODY);
			}
		} else if (!b.empty())
			log("nvram: the saved block is not a Spike 1 NVRAM block; starting with a new machine");
	}

	m_t0 = mono_ns();
	if (!spawn(error)) { stop(); return false; }
	start_devices();
	if (!eeproms.empty()) m_dev.set_nvram(eeproms.data(), eeproms.size());
	m_mem.flush();
	return true;
}

// Starts the program, held at its first system call
bool spike1_native::spawn(std::string &error)
{
	const std::string root = m_dir + "/root", games = root + "/games/" + m_cfg.folder;
	std::vector<std::string> strings; // the plan's text, alive until the child has gone or exec'd
	strings.reserve(4 * m_cfg.files.size() + 16);
	auto keep = [&](const std::string &s) { strings.push_back(s); return strings.back().c_str(); };
	std::vector<child_plan::dir> dirs;
	std::vector<child_plan::wfile> files;
	std::vector<child_plan::bind> binds;
	// where a title's files sit on the card, as spike1_pinmame_start lays them out for the emulated
	// machine: LCD clips (.spv) in video/, the ELG titles' sounds (.wav) in sounds/
	auto ends_with = [](const std::string &name, const char *ext) { return name.size() > 4 && name.compare(name.size() - 4, 4, ext) == 0; };
	auto sub_of = [&](const std::string &name) { return ends_with(name, ".spv") ? "/video/" : ends_with(name, ".wav") ? "/sounds/" : "/"; };
	bool video = false, sounds = false;
	for (const file &f : m_cfg.files) { video |= ends_with(f.name, ".spv"); sounds |= ends_with(f.name, ".wav"); }
	dirs.push_back({ keep(root + "/games"), 0755 });
	dirs.push_back({ keep(games), 0755 });
	if (video) dirs.push_back({ keep(games + "/video"), 0755 });
	if (sounds) dirs.push_back({ keep(games + "/sounds"), 0755 });
	dirs.push_back({ keep(root + "/data"), 0755 });
	dirs.push_back({ keep(root + "/tmp"), 01777 });
	dirs.push_back({ keep(root + "/dev"), 0755 });
	for (const file &f : m_cfg.files) {
		const bool prog = f.name == m_cfg.program;
		const std::string to = games + sub_of(f.name) + f.name;
		const std::string from = prog ? std::string() : mapped_file(f.data, f.size);
		if (!from.empty()) binds.push_back({ keep(from), keep(to) });
		else if (f.size <= SMALL_FILE || prog) files.push_back({ keep(to), f.data, f.size, mode_t(prog ? 0755 : 0444) });
		else { error = f.name + " is not a whole file on disk (a set in a zip?), which a native run needs"; return false; }
	}
	const std::string exec_path = "/games/" + m_cfg.folder + "/" + m_cfg.program;
	std::vector<char *> argv{ const_cast<char *>(keep(exec_path)), nullptr };
	std::vector<std::string> env = m_cfg.environment;
	if (env.empty()) env = { "HOME=/root", "PATH=/bin:/usr/bin:/usr/local/bin", "LANG=C", "LC_ALL=C", "GAMES_PATH=/games" };
	std::vector<char *> envp;
	for (const auto &e : env) envp.push_back(const_cast<char *>(keep(e)));
	envp.push_back(nullptr);
	std::vector<sock_filter> filter = build_filter();

	child_plan plan;
	plan.dirs = dirs.data(); plan.ndirs = dirs.size();
	plan.files = files.data(); plan.nfiles = files.size();
	plan.binds = binds.data(); plan.nbinds = binds.size();
	plan.root = keep(root);
	size_t written = 0;
	for (const auto &f : files) written += f.size;
	plan.tmpfs_options = keep("size=" + std::to_string((written >> 20) + 16) + "m,mode=755");
	plan.data_src = keep(m_dir + "/data");
	plan.data_dst = keep(root + "/data");
	// root in the game's user namespace is nobody outside when the host is root, else the host's user
	plan.drop_to_nobody = geteuid() == 0;
	const uid_t outside_uid = plan.drop_to_nobody ? NOBODY : geteuid();
	const gid_t outside_gid = plan.drop_to_nobody ? NOBODY : getegid();
	plan.uid_map = keep("0 " + std::to_string(outside_uid) + " 1");
	plan.gid_map = keep("0 " + std::to_string(outside_gid) + " 1");
	plan.set_cpus = !m_cfg.cpus.empty() && parse_cpus(m_cfg.cpus, plan.cpus);
	plan.prog = sock_fprog{ uint16_t(filter.size()), filter.data() };
	plan.exec_path = keep(exec_path);
	plan.argv = argv.data();
	plan.envp = envp.data();

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) { error = std::string("socketpair: ") + std::strerror(errno); return false; }
	plan.sock = sv[1];
	const size_t stack_size = 256 * 1024;
	void *stack = mmap(nullptr, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED) { close(sv[0]); close(sv[1]); error = "no memory for the child's stack"; return false; }
	// no handler of the host may run on the child's stack before the exec
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);
	int pidfd = -1;
	const int pid = clone(child_entry, static_cast<char *>(stack) + stack_size, CLONE_VM | CLONE_VFORK | CLONE_PIDFD | SIGCHLD, &plan, &pidfd);
	const int clone_errno = errno;
	pthread_sigmask(SIG_SETMASK, &old, nullptr);
	munmap(stack, stack_size);
	close(sv[1]);
	if (pid < 0) { close(sv[0]); error = std::string("clone: ") + std::strerror(clone_errno); return false; }
	m_child = pid;
	m_pidfd = pidfd;

	// the child's report: the listener, or the step that failed
	child_report rep{ -1, 0 };
	iovec iov{ &rep, sizeof(rep) };
	alignas(cmsghdr) char buf[CMSG_SPACE(sizeof(int))] = {};
	msghdr msg{};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	const ssize_t got = recvmsg(sv[0], &msg, MSG_CMSG_CLOEXEC);
	int listener = -1;
	if (got == ssize_t(sizeof(rep)) && rep.step == 0)
		if (cmsghdr *c = CMSG_FIRSTHDR(&msg); c && c->cmsg_type == SCM_RIGHTS) std::memcpy(&listener, CMSG_DATA(c), sizeof(int));
	// a failed exec reports after the listener: look for that too
	child_report late{ -1, 0 };
	if (listener >= 0) {
		pollfd p{ sv[0], POLLIN, 0 };
		if (poll(&p, 1, 0) > 0 && recv(sv[0], &late, sizeof(late), MSG_DONTWAIT) == ssize_t(sizeof(late))) rep = late;
	}
	close(sv[0]);
	if (listener < 0 || rep.step != 0) {
		if (listener >= 0) close(listener);
		error = got == ssize_t(sizeof(rep)) && rep.step > 0 ?
			std::string("the sandbox: ") + child_step_name(rep.step) + ": " + std::strerror(rep.err) : "the sandbox did not start";
		reap("did not start");
		return false;
	}
	m_listener = listener;
	m_exited = false;
	if (m_notif_buf.empty()) {
		seccomp_notif_sizes sizes{};
		syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
		m_notif_buf.resize(std::max<size_t>(sizes.seccomp_notif, sizeof(seccomp_notif)));
	}
	if (!wait_for_hold(5000000000ull)) {
		error = "the game program did not start (" + (m_stop_reason.empty() ? std::string("no first system call within 5 s") : m_stop_reason) + ")";
		kill_child();
		return false;
	}
	for (const auto &l : m_links) make_link(l.first, l.second);
	log("the program runs natively as process " + std::to_string(m_child) + (plan.set_cpus ? " on cpus " + m_cfg.cpus : std::string()) +
		": " + std::to_string(binds.size()) + " files bound from disk, " + std::to_string(files.size()) + " written");
	return true;
}

// Waits for the program's first system call, which it then holds
bool spike1_native::wait_for_hold(uint64_t max_ns)
{
	const uint64_t until = mono_ns() + max_ns;
	while (!m_held) {
		const uint64_t now = mono_ns();
		if (now >= until || m_exited) return false;
		pollfd p[2] = { { m_listener, POLLIN, 0 }, { m_pidfd, POLLIN, 0 } };
		const uint64_t wait = until - now;
		timespec ts{ time_t(wait / 1000000000ull), long(wait % 1000000000ull) };
		if (ppoll(p, 2, &ts, nullptr) < 0 && errno != EINTR) return false;
		if (p[0].revents & POLLIN) {
			std::fill(m_notif_buf.begin(), m_notif_buf.end(), 0);
			if (ioctl(m_listener, SECCOMP_IOCTL_NOTIF_RECV, m_notif_buf.data()) < 0) continue;
			const seccomp_notif &n = *reinterpret_cast<const seccomp_notif *>(m_notif_buf.data());
			call c;
			c.id = n.id;
			c.pid = int(n.pid);
			c.nr = n.data.nr;
			for (int i = 0; i < 6; i++) c.a[i] = uint32_t(n.data.args[i]);
			m_held = true;
			m_held_call = c;
			return true;
		}
		if (p[1].revents & POLLIN) { reap("exited before its first system call"); return false; }
	}
	return true;
}

void spike1_native::release()
{
	if (!m_held) return;
	m_held = false;
	call c = m_held_call;
	int64_t val = 0;
	const outcome o = handle(c, val);
	if (o == outcome::wait) m_pending.push_back(c);
	else respond(c, o, val);
}

void spike1_native::start_devices()
{
	m_mem.set_remote(m_child);
	if (m_devices_started) return;
	m_devices_started = true;
	spike1_devices::config cfg;
	cfg.trace = m_cfg.trace;
	cfg.log = [this](const std::string &line) { log(line); };
	cfg.symbol = [this](const std::string &n) { auto it = m_symbols.find(n); return it == m_symbols.end() ? 0u : it->second; };
	cfg.symbol_size = [this](const std::string &n) { auto it = m_symbol_sizes.find(n); return it == m_symbol_sizes.end() ? 0u : it->second; };
	cfg.symbols_with_prefix = [this](const std::string &prefix) {
		std::vector<std::string> names;
		for (auto it = m_symbols.lower_bound(prefix); it != m_symbols.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it) names.push_back(it->first);
		return names;
	};
	cfg.game_files = [this]() { return m_game_files; };
	cfg.read_game_file = [this](const std::string &name, std::vector<uint8_t> &out) {
		for (const file &f : m_cfg.files)
			if (f.name == name) { out.assign(f.data, f.data + f.size); return true; }
		return false;
	};
	m_dev.start(cfg);
	m_mem.flush();
}

void spike1_native::make_link(const std::string &path, const std::string &target)
{
	if (!m_child || m_exited || path.empty() || path[0] != '/') return;
	// through the program's own root, as the host's root
	const std::string host = "/proc/" + std::to_string(m_child) + "/root" + path;
	std::error_code ec;
	std::filesystem::create_directories(std::filesystem::path(host).parent_path(), ec);
	unlink(host.c_str());
	if (symlink(target.c_str(), host.c_str()) < 0) log("link " + path + " -> " + target + ": " + std::strerror(errno));
}

bool spike1_native::add_link(const std::string &path, const std::string &target)
{
	m_links[path] = target;
	make_link(path, target);
	return true;
}

void spike1_native::kill_child()
{
	if (!m_child) return;
	if (!m_exited) {
		if (m_pidfd >= 0) syscall(SYS_pidfd_send_signal, m_pidfd, SIGKILL, nullptr, 0);
		else kill(m_child, SIGKILL);
	}
	reap("stopped");
}

// The program is gone (or going): its descriptors, the calls it was making and its process
void spike1_native::reap(const std::string &how)
{
	if (m_pidfd >= 0) {
		siginfo_t info{};
		if (syscall(SYS_waitid, P_PIDFD, m_pidfd, &info, WEXITED, nullptr) == 0) {
			if (info.si_code == CLD_EXITED) m_stop_reason = how + ", exit status " + std::to_string(info.si_status);
			else m_stop_reason = how + ", signal " + std::to_string(info.si_status);
		} else
			m_stop_reason = how;
		close(m_pidfd);
		m_pidfd = -1;
	} else if (m_child)
		waitpid(m_child, nullptr, 0);
	if (m_listener >= 0) { close(m_listener); m_listener = -1; }
	m_exited = true;
	m_held = false;
	m_pending.clear();
	for (slot &s : m_slots) s = slot();
}

void spike1_native::stop()
{
	if (m_threaded) {
		m_quit = true;
		if (m_thread.joinable()) m_thread.join();
		m_threaded = false;
	}
	if (m_child) kill_child();
	m_child = 0;
	m_exited = false;
	m_restart_ns = 0;
	if (!m_dir.empty()) {
		std::error_code ec;
		std::filesystem::remove_all(m_dir, ec);
		m_dir.clear();
	}
	m_mem.set_remote(0);
}

bool spike1_native::running(std::string &reason) const
{
	if (!m_child) { reason = m_stop_reason.empty() ? "not started" : m_stop_reason; return false; }
	if (m_exited && !m_restart_ns) { reason = m_stop_reason; return false; }
	return true;
}

void spike1_native::run_until(uint64_t until_ns)
{
	if (!m_child) return;
	{
		std::lock_guard<std::mutex> guard(m_lock);
		release();
	}
	do step(until_ns); while (m_child && now_ns() < until_ns);
}

void spike1_native::start_thread()
{
	if (!m_child || m_threaded) return;
	{
		std::lock_guard<std::mutex> guard(m_lock);
		release();
	}
	m_quit = false;
	m_threaded = true;
	m_thread = std::thread([this]() { thread_main(); });
}

void spike1_native::thread_main()
{
	while (!m_quit && m_child) step(now_ns() + 20000000ull);
}

void spike1_native::step(uint64_t until_ns)
{
	if (!m_exited) { pump(until_ns); return; }
	{
		std::lock_guard<std::mutex> guard(m_lock);
		if (!m_restart_ns) {
			// game_monitor: the program again, a second later, as a new process; the devices carry on
			m_dev.process_exited();
			m_restart_ns = now_ns() + 1000000000ull;
			log("exit: " + m_stop_reason + "; game_monitor starts the program again in 1 s");
		}
		if (now_ns() >= m_restart_ns) {
			m_restart_ns = 0;
			std::string error;
			if (!spawn(error)) { m_stop_reason = "restart: " + error; log(m_stop_reason); m_child = 0; return; }
			m_restarts++;
			m_mem.set_remote(m_child);
			m_dev.process_started();
			m_mem.flush();
			release();
			return;
		}
	}
	const uint64_t wake = std::min(until_ns, m_restart_ns), now = now_ns();
	if (wake > now) { timespec ts{ time_t((wake - now) / 1000000000ull), long((wake - now) % 1000000000ull) }; nanosleep(&ts, nullptr); }
}

// One wait: for a call from the game, a waiting call's time, or until_ns
bool spike1_native::pump(uint64_t until_ns)
{
	// the wait holds no lock: the host uses the machine meanwhile
	uint64_t now = now_ns();
	uint64_t next = until_ns;
	{
		std::lock_guard<std::mutex> guard(m_lock);
		for (const call &c : m_pending) next = std::min(next, c.wake_ns);
	}
	const uint64_t wait = next > now ? next - now : 0;
	timespec ts{ time_t(wait / 1000000000ull), long(wait % 1000000000ull) };
	pollfd p[2] = { { m_listener, POLLIN, 0 }, { m_pidfd, POLLIN, 0 } };
	if (ppoll(p, 2, &ts, nullptr) < 0 && errno != EINTR) return false;
	std::lock_guard<std::mutex> guard(m_lock);
	if (p[1].revents & POLLIN) { reap("exited"); return false; }
	if (p[0].revents & (POLLHUP | POLLERR)) { reap("exited"); return false; }
	// every call that came in
	while (p[0].revents & POLLIN) {
		std::fill(m_notif_buf.begin(), m_notif_buf.end(), 0);
		if (ioctl(m_listener, SECCOMP_IOCTL_NOTIF_RECV, m_notif_buf.data()) < 0) break;
		const seccomp_notif &n = *reinterpret_cast<const seccomp_notif *>(m_notif_buf.data());
		call c;
		c.id = n.id;
		c.pid = int(n.pid);
		c.nr = n.data.nr;
		for (int i = 0; i < 6; i++) c.a[i] = uint32_t(n.data.args[i]);
		m_notifications++;
		m_counts[c.nr]++;
		int64_t val = 0;
		const outcome o = handle(c, val);
		if (o == outcome::wait) m_pending.push_back(c);
		else respond(c, o, val);
		pollfd again{ m_listener, POLLIN, 0 };
		p[0].revents = poll(&again, 1, 0) > 0 ? again.revents & POLLIN : 0;
	}
	// the calls waiting on a device whose time has come
	now = now_ns();
	for (size_t i = 0; i < m_pending.size(); ) {
		call &c = m_pending[i];
		if (c.wake_ns > now) { i++; continue; }
		uint64_t id = c.id;
		if (ioctl(m_listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) { m_pending.erase(m_pending.begin() + long(i)); continue; } // a signal took the caller away
		int64_t val = 0;
		const outcome o = handle(c, val);
		if (o == outcome::wait) { i++; continue; }
		respond(c, o, val);
		m_pending.erase(m_pending.begin() + long(i));
	}
	return true;
}

void spike1_native::respond(const call &c, outcome o, int64_t val)
{
	seccomp_notif_resp r{};
	r.id = c.id;
	if (o == outcome::pass) r.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	else if (val < 0) r.error = int32_t(val);
	else r.val = val;
	ioctl(m_listener, SECCOMP_IOCTL_NOTIF_SEND, &r); // ENOENT: the caller has gone (a signal), nothing to do
}

spike1_native::slot *spike1_native::device(int fd)
{
	const int i = fd - DEVICE_FD;
	return i >= 0 && i < DEVICE_SLOTS && m_slots[i].used ? &m_slots[i] : nullptr;
}

bool spike1_native::child_read(int pid, uint32_t addr, void *dst, size_t len) const
{
	iovec local{ dst, len }, remote{ reinterpret_cast<void *>(uintptr_t(addr)), len };
	return len == 0 || process_vm_readv(pid, &local, 1, &remote, 1, 0) == ssize_t(len);
}

bool spike1_native::child_write(int pid, uint32_t addr, const void *src, size_t len) const
{
	iovec local{ const_cast<void *>(src), len }, remote{ reinterpret_cast<void *>(uintptr_t(addr)), len };
	return len == 0 || process_vm_writev(pid, &local, 1, &remote, 1, 0) == ssize_t(len);
}

bool spike1_native::child_string(int pid, uint32_t addr, std::string &out) const
{
	out.clear();
	while (out.size() < 4096) {
		char chunk[4096];
		const uint32_t n = 4096 - (addr & 4095);
		if (!child_read(pid, addr, chunk, n)) return false;
		for (uint32_t i = 0; i < n; i++) {
			if (!chunk[i]) return true;
			out.push_back(chunk[i]);
		}
		addr += n;
	}
	return false;
}

// Puts a descriptor of ours into the calling process: at `at`, or the lowest free one when -1
int spike1_native::add_fd(const call &c, int src, int at, bool cloexec)
{
	seccomp_notif_addfd a{};
	a.id = c.id;
	a.srcfd = uint32_t(src);
	if (at >= 0) { a.flags = SECCOMP_ADDFD_FLAG_SETFD; a.newfd = uint32_t(at); }
	a.newfd_flags = cloexec ? O_CLOEXEC : 0;
	const int r = ioctl(m_listener, SECCOMP_IOCTL_NOTIF_ADDFD, &a);
	return r < 0 ? -errno : r;
}

// What poll() would say now of one of the game's own descriptors
short spike1_native::native_revents(int fd, short events)
{
	const int dup = m_pidfd < 0 ? -1 : int(syscall(SYS_pidfd_getfd, m_pidfd, fd, 0));
	if (dup < 0) return POLLNVAL;
	pollfd p{ dup, events, 0 };
	poll(&p, 1, 0);
	close(dup);
	return p.revents;
}

spike1_native::outcome spike1_native::open_call(call &c, int64_t &val)
{
	const bool at = c.nr == nr::openat;
	const uint32_t addr = c.a[at ? 1 : 0], flags = c.a[at ? 2 : 1];
	std::string path;
	if (!child_string(c.pid, addr, path)) { val = -EFAULT; return outcome::reply; }
	if (path.rfind("/dev/", 0) != 0) return outcome::pass; // the sandbox has the title's files
	const bool cloexec = (flags & O_CLOEXEC_) != 0;
	if (path == "/dev/null" || path == "/dev/zero" || path == "/dev/random" || path == "/dev/urandom") {
		const int h = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
		val = h < 0 ? -errno : add_fd(c, h, -1, cloexec);
		if (h >= 0) close(h);
		return outcome::reply;
	}
	if (path == "/dev/console" || path == "/dev/tty") { // the game's console: the host's output
		val = add_fd(c, 1, -1, cloexec);
		return outcome::reply;
	}
	int i = 0;
	while (i < DEVICE_SLOTS && m_slots[i].used) i++;
	if (i == DEVICE_SLOTS) { val = -EMFILE; return outcome::reply; }
	const int h = ::open("/dev/null", O_RDWR | O_CLOEXEC);
	val = h < 0 ? -errno : add_fd(c, h, DEVICE_FD + i, cloexec);
	if (h >= 0) close(h);
	if (val < 0) return outcome::reply;
	slot &s = m_slots[i];
	s = slot();
	s.used = true;
	s.flags = flags;
	s.h.type = spike1_devices::kind_for_path(path);
	s.h.path = path;
	if (m_cfg.trace) log("open device " + path + " -> fd " + std::to_string(val));
	return outcome::reply;
}

// select and poll: answered here when they wait on a device, as spike1_linux::sys_poll does
spike1_native::outcome spike1_native::poll_call(call &c, int64_t &val)
{
	const uint32_t *a = c.a;
	const bool is_poll = c.nr == nr::poll || c.nr == nr::ppoll;
	const uint64_t now = now_ns();

	std::vector<uint8_t> pfds;
	std::vector<uint32_t> in_r, in_w, out_r, out_w;
	bool any_device = false;
	if (is_poll) {
		pfds.resize(size_t(a[1]) * 8);
		if (!child_read(c.pid, a[0], pfds.data(), pfds.size())) { val = -EFAULT; return outcome::reply; }
		for (uint32_t i = 0; i < a[1]; i++) { int32_t fd; std::memcpy(&fd, &pfds[8 * i], 4); if (device(fd)) any_device = true; }
	} else {
		const uint32_t words = (a[0] + 31) / 32;
		in_r.assign(words, 0); in_w.assign(words, 0); out_r.assign(words, 0); out_w.assign(words, 0);
		if (a[1] && !child_read(c.pid, a[1], in_r.data(), words * 4)) { val = -EFAULT; return outcome::reply; }
		if (a[2] && !child_read(c.pid, a[2], in_w.data(), words * 4)) { val = -EFAULT; return outcome::reply; }
		for (uint32_t fd = 0; fd < a[0]; fd++)
			if (((in_r[fd / 32] | in_w[fd / 32]) >> (fd & 31) & 1) && device(int(fd))) any_device = true;
	}
	if (!any_device) return outcome::pass;

	int64_t timeout_ns = -1;
	if (c.nr == nr::poll) { if (int32_t(a[2]) >= 0) timeout_ns = int64_t(int32_t(a[2])) * 1000000; }
	else {
		const uint32_t ptr = c.nr == nr::ppoll ? a[2] : a[4];
		uint32_t t[2];
		if (ptr) {
			if (!child_read(c.pid, ptr, t, 8)) { val = -EFAULT; return outcome::reply; }
			timeout_ns = int64_t(t[0]) * 1000000000 + int64_t(t[1]) * (c.nr == nr::newselect ? 1000 : 1); // timeval, or timespec
		}
	}
	uint64_t look_again = UINT64_MAX;
	auto readable = [&](int fd) {
		if (slot *s = device(fd)) {
			const uint64_t when = m_dev.readable_at(s->h, now);
			if (when <= now) return true;
			look_again = std::min(look_again, when == spike1_devices::NEVER ? now + RECHECK_NS : when);
			return false;
		}
		if (native_revents(fd, POLLIN) & (POLLIN | POLLHUP)) return true;
		look_again = std::min(look_again, now + RECHECK_NS);
		return false;
	};
	int32_t ready = 0;
	if (is_poll) {
		for (uint32_t i = 0; i < a[1]; i++) {
			int32_t fd; uint16_t events, revents = 0;
			std::memcpy(&fd, &pfds[8 * i], 4);
			std::memcpy(&events, &pfds[8 * i + 4], 2);
			if (fd >= 0) {
				if ((events & POLLIN) && readable(fd)) revents |= POLLIN;
				if (events & POLLOUT) revents |= device(fd) ? POLLOUT : (native_revents(fd, POLLOUT) & POLLOUT);
			}
			std::memcpy(&pfds[8 * i + 6], &revents, 2);
			if (revents) ready++;
		}
	} else {
		for (uint32_t fd = 0; fd < a[0]; fd++) {
			const uint32_t bit = 1u << (fd & 31);
			if ((in_r[fd / 32] & bit) && readable(int(fd))) { out_r[fd / 32] |= bit; ready++; }
			if ((in_w[fd / 32] & bit) && (device(int(fd)) || (native_revents(int(fd), POLLOUT) & POLLOUT))) { out_w[fd / 32] |= bit; ready++; }
		}
	}
	if (!c.poll_deadline) c.poll_deadline = timeout_ns < 0 ? UINT64_MAX : now + uint64_t(timeout_ns);
	if (ready || timeout_ns == 0 || now >= c.poll_deadline) {
		if (is_poll) child_write(c.pid, a[0], pfds.data(), pfds.size());
		else {
			const uint32_t bytes = uint32_t(out_r.size() * 4);
			std::vector<uint32_t> none(out_r.size(), 0);
			if (a[1]) child_write(c.pid, a[1], out_r.data(), bytes);
			if (a[2]) child_write(c.pid, a[2], out_w.data(), bytes);
			if (a[3]) child_write(c.pid, a[3], none.data(), bytes);
		}
		val = ready;
		return outcome::reply;
	}
	c.wake_ns = std::min(c.poll_deadline, look_again);
	return outcome::wait;
}

spike1_native::outcome spike1_native::handle(call &c, int64_t &val)
{
	const int fd = int(int32_t(c.a[0]));
	const uint32_t a1 = c.a[1], a2 = c.a[2];
	switch (c.nr) {
	case nr::open: case nr::openat: return open_call(c, val);
	case nr::newselect: case nr::pselect6: case nr::poll: case nr::ppoll: return poll_call(c, val);
	case nr::sync: case nr::syncfs: case nr::fsync: case nr::fdatasync: m_syncs++; return outcome::pass;
	case nr::set_tid_address: case nr::uname: return outcome::pass;
	default: break;
	}
	slot *s = device(fd);
	if (!s) return outcome::pass; // a descriptor in the device range the game made itself (dup2)
	const uint64_t now = now_ns();
	uint64_t wait_ns = 0;
	std::string note;
	int32_t r = 0;
	auto report = [&](const char *what) {
		if (!note.empty()) log(std::string(what) + " " + s->h.path + ": " + note);
	};
	switch (c.nr) {
	case nr::close:
		s->used = false;
		return outcome::pass; // closes the placeholder
	case nr::fcntl: case nr::fcntl64:
		if (a1 == 4) s->flags = (s->flags & ~O_NONBLOCK_) | (a2 & O_NONBLOCK_); // F_SETFL
		return outcome::pass;
	case nr::read:
		if (!a2) { val = 0; return outcome::reply; }
		r = m_dev.read(s->h, a1, a2, now, wait_ns, note);
		m_mem.flush();
		report("read");
		if (r == spike1_devices::WAIT || r == 0) { // no data yet: a blocking read waits for it
			if (s->flags & O_NONBLOCK_) { val = -EAGAIN; return outcome::reply; }
			c.wake_ns = r == 0 ? now + RECHECK_NS : wait_ns;
			return outcome::wait;
		}
		val = r;
		return outcome::reply;
	case nr::write:
		r = m_dev.write(s->h, a1, a2, now, wait_ns, note);
		m_mem.flush();
		report("write");
		if (r == spike1_devices::WAIT) {
			if (s->flags & O_NONBLOCK_) { val = -EAGAIN; return outcome::reply; }
			c.wake_ns = wait_ns;
			return outcome::wait;
		}
		val = r;
		return outcome::reply;
	case nr::ioctl:
		if (a1 == 0x541b) { // FIONREAD
			const uint32_t zero = 0;
			val = child_write(c.pid, a2, &zero, 4) ? 0 : -EFAULT;
			return outcome::reply;
		}
		r = m_dev.ioctl(s->h, a1, a2, now, wait_ns, note);
		m_mem.flush();
		report("ioctl");
		if (r == spike1_devices::WAIT) { c.wake_ns = wait_ns; return outcome::wait; }
		val = r;
		return outcome::reply;
	default:
		log("not modelled on a device: system call " + std::to_string(c.nr) + " on " + s->h.path);
		val = -EINVAL;
		return outcome::reply;
	}
}

bool spike1_native::power_down(uint64_t max_ns)
{
	uint64_t syncs;
	{
		std::lock_guard<std::mutex> guard(m_lock);
		if (!m_child || m_exited) return false;
		release();
		m_dev.power_off();
		syncs = m_syncs;
	}
	// The commit is a run of syncs, one per file pair for Game of Thrones, and the game runs on while
	// the block is read: wait until the syncs have stopped, not for the first one
	constexpr uint64_t QUIET_NS = 250000000ull;
	const uint64_t until = now_ns() + max_ns;
	uint64_t seen = syncs, last_ns = 0;
	for (;;) {
		{
			std::lock_guard<std::mutex> guard(m_lock);
			const uint64_t now = now_ns();
			if (m_syncs != seen) { seen = m_syncs; last_ns = now; }
			if (m_exited || now >= until || (last_ns && now - last_ns >= QUIET_NS)) break;
		}
		if (m_threaded) { timespec ts{ 0, 2000000 }; nanosleep(&ts, nullptr); } // the thread answers the game
		else pump(std::min<uint64_t>(until, now_ns() + 10000000ull));
	}
	std::lock_guard<std::mutex> guard(m_lock);
	const bool synced = m_syncs != syncs;
	log(synced ? "nvram: the game committed and synced after the power failed" : "nvram: the game did not sync after the power failed");
	return synced;
}

std::vector<uint8_t> spike1_native::nvram() const
{
	// /data as spike1_vfs's written layer, then the EEPROMs, in spike1_linux::nvram()'s block
	spike1_vfs vfs;
	vfs.add_directory("/data");
	if (!m_dir.empty()) {
		std::error_code ec;
		std::vector<std::filesystem::path> dirs, files;
		const std::filesystem::path base = m_dir + "/data";
		// the game makes its files with the mode it passes, which can leave out the owner's read bit
		// (Game of Thrones opens its data files with 054): root in the game's user namespace reads
		// them regardless, we read them as their owner outside it
		auto let_owner = [](const std::filesystem::path &p, mode_t bits) {
			struct stat st;
			if (stat(p.c_str(), &st) == 0 && (st.st_mode & bits) != bits) chmod(p.c_str(), (st.st_mode & 07777) | bits);
		};
		let_owner(base, S_IRUSR | S_IXUSR);
		for (auto it = std::filesystem::recursive_directory_iterator(base, ec); !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
			if (it->is_directory(ec)) { let_owner(it->path(), S_IRUSR | S_IXUSR); dirs.push_back(it->path()); }
			else if (it->is_regular_file(ec)) { let_owner(it->path(), S_IRUSR); files.push_back(it->path()); }
		}
		std::sort(dirs.begin(), dirs.end());
		auto guest = [&](const std::filesystem::path &p) { return "/data/" + p.lexically_relative(base).generic_string(); };
		for (const auto &d : dirs) vfs.make_directory(guest(d));
		for (const auto &f : files) {
			std::ifstream in(f, std::ios::binary);
			// a file that cannot be read is left out rather than kept empty: the game then finds it
			// missing, not wiped under a checksum that no longer matches
			if (!in) { log("nvram: cannot read " + guest(f) + "; left out of the block"); continue; }
			auto bytes = vfs.open_write(guest(f), true);
			if (!bytes) continue;
			bytes->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
		}
	}
	std::vector<uint8_t> out{ 'S', '1', 'S', 'T', 1 };
	for (const std::vector<uint8_t> &part : { vfs.save(), m_dev.nvram() }) {
		for (int i = 0; i < 4; i++) out.push_back(uint8_t(uint32_t(part.size()) >> (8 * i)));
		out.insert(out.end(), part.begin(), part.end());
	}
	return out;
}

bool spike1_native::game_cpu(double &seconds, unsigned &threads) const
{
	if (!m_child || m_exited) return false;
	std::ifstream in("/proc/" + std::to_string(m_child) + "/stat");
	std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	const size_t p = s.rfind(')');
	if (p == std::string::npos) return false;
	std::vector<std::string> f;
	for (size_t i = p + 2; i < s.size(); ) {
		const size_t e = s.find(' ', i);
		f.push_back(s.substr(i, e - i));
		if (e == std::string::npos) break;
		i = e + 1;
	}
	if (f.size() < 18) return false;
	seconds = double(std::strtoull(f[11].c_str(), nullptr, 10) + std::strtoull(f[12].c_str(), nullptr, 10)) / double(sysconf(_SC_CLK_TCK));
	threads = unsigned(std::strtoul(f[17].c_str(), nullptr, 10));
	return true;
}

#else // not Linux on arm64: the emulated machine is the only one

spike1_native::spike1_native() : m_dev(m_mem) {}
spike1_native::~spike1_native() {}
bool spike1_native::supported(std::string &why) { why = "a native run needs Linux on arm64"; return false; }
void spike1_native::start_thread() {}
bool spike1_native::start(const config &, std::string &error) { supported(error); return false; }
void spike1_native::stop() {}
void spike1_native::run_until(uint64_t) {}
uint64_t spike1_native::now_ns() const { return 0; }
bool spike1_native::running(std::string &reason) const { reason = "not started"; return false; }
bool spike1_native::power_down(uint64_t) { return false; }
std::vector<uint8_t> spike1_native::nvram() const { return {}; }
bool spike1_native::add_link(const std::string &, const std::string &) { return false; }
uint32_t spike1_native::symbol(const std::string &) const { return 0; }
bool spike1_native::game_cpu(double &, unsigned &) const { return false; }

#endif
