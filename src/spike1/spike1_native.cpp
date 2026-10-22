// license:BSD-3-Clause

// PinMAME Spike 1 subsystem - native harness (Linux, on an ARM host that runs 32-bit ARM programs)
//
// spike1boot runs the game program on MAME's ARM9 interpreter. A host whose kernel runs AArch32
// user programs (arm64 with CONFIG_COMPAT, on a CPU with AArch32 at EL0) can run the program as
// itself instead: a real process whose threads the host schedules. Only what the board's hardware
// would answer is handled here, by the same spike1_devices the emulated machine uses.
//
// - The child gets a private mount namespace and a chroot holding /games/<folder> (the set's files
//   bound read-only; the program itself copied, as the set may sit on a noexec mount), /data (the
//   state directory's data/, where the game keeps its NVRAM files), /tmp and an empty /dev. It
//   runs in its own session, as root of a user namespace that maps to nobody, with no_new_privs.
// - A seccomp filter passes everything through natively except: open/openat, select/poll and the
//   sync calls, which come here and go on natively unless a device is involved; read, write,
//   ioctl, close and fcntl on the device descriptors (DEVICE_FD up), which the device model
//   answers; sched_setscheduler and the like, answered 0 without effect (the game asks for SCHED_RR
//   97 for its threads, which would preempt the host's own); execve, mount, reboot and the like,
//   refused.
// - A device open gets a placeholder descriptor (/dev/null) at a fixed number, so the filter can
//   tell device calls apart by their descriptor. The device model reaches the game's memory with
//   process_vm_readv/writev (spike1_memory's remote mode).
// - Time is the host's monotonic clock from the program's start. A device call that would wait
//   (WAIT) is asked again at its time; until then the calling thread sleeps in the kernel.
//
//   spike1native --files <set dir> --game /games/<folder>/game [--state <dir>] [--seconds <n>]
//                [--switch <s>:<name>[:<ms>]]... [--dmd <s>] [--stats <s>] [--cpus <list>]
//                [--encoder-motor <node>:<motor>:<low>:<high>:<counts a second>] [--trace]
//
// Run as root: the game runs as nobody, and the supervisor reads its memory and hands it descriptors.

#include "spike1_devices.h"
#include "spike1_memory.h"

#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

// ARM EABI system call numbers
namespace nr { enum : uint32_t {
	read = 3, write = 4, open = 5, close = 6, execve = 11, mknod = 14, mount = 21, ptrace = 26, sync = 36, kill = 37,
	umount2 = 52, ioctl = 54, fcntl = 55, chroot = 61, sethostname = 74, settimeofday = 79, swapon = 87, reboot = 88,
	setpriority = 97, swapoff = 115, fsync = 118, adjtimex = 124, init_module = 128, delete_module = 129,
	newselect = 142, readv = 145, writev = 146, fdatasync = 148, sched_setparam = 154, sched_setscheduler = 156,
	poll = 168, fcntl64 = 221, sched_setaffinity = 241, clock_settime = 262, openat = 322, mknodat = 324,
	pselect6 = 335, ppoll = 336, unshare = 337, kexec_load = 347, syncfs = 373, finit_module = 379,
}; }

constexpr int DEVICE_FD = 200, DEVICE_SLOTS = 32;  // the device descriptors: DEVICE_FD .. DEVICE_FD + DEVICE_SLOTS - 1
constexpr uint64_t RECHECK_NS = 1000000;           // as spike1_linux's POLL_RECHECK_NS
constexpr uint32_t O_NONBLOCK_ = 0x800, O_CLOEXEC_ = 0x80000;
constexpr uid_t NOBODY = 65534;

struct options
{
	std::string files, game, state = "spike1_native_state", cpus;
	double seconds = 30.0, dmd_every = 0.0, stats_every = 10.0;
	bool trace = false;
	struct press { double at, held_ms; std::string name; bool down = false, up = false; };
	std::vector<press> presses;
	struct encoder_motor { int node, motor, low, high; unsigned counts_per_s; };
	std::vector<encoder_motor> encoder_motors;
};

uint64_t mono_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

[[noreturn]] void child_fail(const char *what)
{
	std::fprintf(stderr, "spike1native child: %s: %s\n", what, std::strerror(errno));
	_exit(127);
}

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
	for (uint32_t n : { nr::open, nr::openat, nr::newselect, nr::pselect6, nr::poll, nr::ppoll, nr::sync, nr::syncfs, nr::fsync, nr::fdatasync })
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
void send_fd(int sock, int fd)
{
	char dummy = 0;
	iovec iov{ &dummy, 1 };
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
	std::memcpy(CMSG_DATA(c), &fd, sizeof(int));
	if (sendmsg(sock, &msg, 0) < 0) child_fail("sendmsg");
}

int receive_fd(int sock)
{
	char dummy;
	iovec iov{ &dummy, 1 };
	alignas(cmsghdr) char buf[CMSG_SPACE(sizeof(int))] = {};
	msghdr msg{};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	if (recvmsg(sock, &msg, 0) <= 0) return -1;
	cmsghdr *c = CMSG_FIRSTHDR(&msg);
	if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
	int fd;
	std::memcpy(&fd, CMSG_DATA(c), sizeof(int));
	return fd;
}

void mkdirs(const std::string &path, mode_t mode)
{
	std::error_code ec;
	std::filesystem::create_directories(path, ec);
	chmod(path.c_str(), mode);
}

[[noreturn]] void child_main(const options &o, const std::string &root, const std::string &data_dir, int sock)
{
	const std::string folder = o.game.substr(0, o.game.rfind('/'));
	const std::string program = o.game.substr(o.game.rfind('/') + 1);
	setsid();
	umask(022); // the chroot is for the game to read
	const int devnull = ::open("/dev/null", O_RDWR);
	if (devnull >= 0) { dup2(devnull, 0); close(devnull); }

	// The mounts, as the host's root, in a mount namespace of the game's own
	if (unshare(CLONE_NEWNS) < 0) child_fail("unshare mount namespace");
	if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) child_fail("mount private");
	if (mount("tmpfs", root.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,mode=755") < 0) child_fail("mount tmpfs");
	const std::string games = root + folder;
	mkdirs(games, 0755);
	std::error_code ec;
	for (const auto &e : std::filesystem::directory_iterator(o.files, ec)) {
		if (!e.is_regular_file()) continue;
		const std::string name = e.path().filename().string(), to = games + "/" + name;
		if (name == program) { // copied: the set may be on a noexec mount
			if (!std::filesystem::copy_file(e.path(), to, ec)) child_fail("copy program");
			chmod(to.c_str(), 0755);
			continue;
		}
		const int t = ::open(to.c_str(), O_CREAT | O_WRONLY, 0444);
		if (t < 0) child_fail("create mount point");
		close(t);
		if (mount(e.path().c_str(), to.c_str(), nullptr, MS_BIND, nullptr) < 0) child_fail("bind set file");
		if (mount(nullptr, to.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, nullptr) < 0) child_fail("remount set file read-only");
	}
	mkdirs(root + "/data", 0755);
	if (mount(data_dir.c_str(), (root + "/data").c_str(), nullptr, MS_BIND, nullptr) < 0) child_fail("bind /data");
	mkdirs(root + "/tmp", 01777);
	mkdirs(root + "/dev", 0755);
	if (chdir(root.c_str()) < 0) child_fail("chdir");

	// Nobody to the host, root to the game. The board runs the game as root, and the game counts on
	// it: it creates its NVRAM files with whatever mode a register holds (open without a mode
	// argument), then reads them back. Root of a user namespace mapped to nobody gets that, and
	// nothing outside. The process stays dumpable so it can write its own maps; the chroot comes
	// last, as a chrooted process cannot make a user namespace
	if (setgroups(0, nullptr) < 0 || setresgid(NOBODY, NOBODY, NOBODY) < 0 || setresuid(NOBODY, NOBODY, NOBODY) < 0) child_fail("drop to nobody");
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	if (unshare(CLONE_NEWUSER) < 0) child_fail("unshare user namespace");
	auto write_file = [](const char *path, const std::string &text) {
		const int f = ::open(path, O_WRONLY);
		if (f < 0 || ::write(f, text.data(), text.size()) != ssize_t(text.size())) child_fail(path);
		close(f);
	};
	write_file("/proc/self/setgroups", "deny");
	write_file("/proc/self/uid_map", "0 " + std::to_string(NOBODY) + " 1");
	write_file("/proc/self/gid_map", "0 " + std::to_string(NOBODY) + " 1");
	if (chroot(".") < 0 || chdir("/") < 0) child_fail("chroot");

	if (!o.cpus.empty()) {
		cpu_set_t set;
		CPU_ZERO(&set);
		for (const char *p = o.cpus.c_str(); *p; ) {
			char *end;
			const long a = std::strtol(p, &end, 10);
			long b = a;
			if (*end == '-') b = std::strtol(end + 1, &end, 10);
			for (long c = a; c <= b; c++) CPU_SET(int(c), &set);
			p = *end == ',' ? end + 1 : end;
			if (end == p && *p) break;
		}
		if (sched_setaffinity(0, sizeof(set), &set) < 0) child_fail("sched_setaffinity");
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) child_fail("no_new_privs");
	std::vector<sock_filter> filter = build_filter();
	sock_fprog prog{ uint16_t(filter.size()), filter.data() };
	const int listener = int(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog));
	if (listener < 0) child_fail("seccomp");
	send_fd(sock, listener);
	close(listener);
	close(sock);

	const std::string path = o.game;
	char *argv[] = { const_cast<char *>(path.c_str()), nullptr };
	const char *env[] = { "HOME=/root", "PATH=/bin:/usr/bin:/usr/local/bin", "LANG=C", "LC_ALL=C", "GAMES_PATH=/games", nullptr };
	execve(path.c_str(), argv, const_cast<char **>(env));
	child_fail("execve");
}

// ---------------------------------------------------------------- the supervisor
class supervisor
{
public:
	supervisor(const options &o) : m_opt(o), m_dev(m_mem) {}
	int run();

private:
	struct call { seccomp_notif n; uint64_t wake_ns = 0, poll_deadline = 0; };
	struct slot { bool used = false; spike1_devices::handle h; uint32_t flags = 0; };
	enum class outcome { reply, pass, wait };

	options m_opt;
	spike1_memory m_mem;
	spike1_devices m_dev;
	int m_listener = -1, m_pidfd = -1;
	pid_t m_child = 0;
	uint64_t m_t0 = 0;
	bool m_started = false;
	slot m_slots[DEVICE_SLOTS];
	std::vector<call> m_pending;
	std::map<uint32_t, uint64_t> m_counts;      // notifications per system call
	uint64_t m_notifications = 0, m_syncs = 0;
	std::map<std::string, uint32_t> m_symbols, m_symbol_sizes;
	std::vector<std::string> m_set_files;
	std::string m_nvram_path;

	uint64_t now_ns() const { return mono_ns() - m_t0; }
	void log(const std::string &line) const { std::printf("[%10.6f] %s\n", double(now_ns()) / 1e9, line.c_str()); std::fflush(stdout); }
	bool load_symbols(const std::string &path);
	void start_devices();
	slot *device(int fd) { const int i = fd - DEVICE_FD; return i >= 0 && i < DEVICE_SLOTS && m_slots[i].used ? &m_slots[i] : nullptr; }
	bool child_string(pid_t pid, uint32_t addr, std::string &out);
	bool child_read(pid_t pid, uint32_t addr, void *dst, size_t len);
	bool child_write(pid_t pid, uint32_t addr, const void *src, size_t len);
	int add_fd(const call &c, int src, int at, bool cloexec);
	short native_revents(int fd, short events);
	outcome handle(call &c, int64_t &val);
	outcome open_call(call &c, int64_t &val);
	outcome poll_call(call &c, int64_t &val);
	void respond(const call &c, outcome o, int64_t val);
	void print_dmd();
	void tick(uint64_t now);
	bool child_cpu(double &seconds, unsigned &threads) const;
};

bool supervisor::load_symbols(const std::string &path)
{
	std::ifstream in(path, std::ios::binary);
	std::vector<uint8_t> elf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	if (elf.size() < 52) return false;
	auto u32 = [&](size_t o) { uint32_t v = 0; if (o + 4 <= elf.size()) std::memcpy(&v, &elf[o], 4); return v; };
	auto u16 = [&](size_t o) { uint16_t v = 0; if (o + 2 <= elf.size()) std::memcpy(&v, &elf[o], 2); return v; };
	// as spike1_linux::load_elf: objects and functions of the program's symbol table
	const uint32_t shoff = u32(32);
	const uint16_t shentsize = u16(46), shnum = u16(48);
	for (uint32_t i = 0; i < shnum && shoff + uint64_t(i + 1) * shentsize <= elf.size(); i++) {
		const size_t o = shoff + size_t(i) * shentsize;
		if (u32(o + 4) != 2) continue; // SHT_SYMTAB
		const uint32_t symoff = u32(o + 16), symsize = u32(o + 20), link = u32(o + 24);
		if (link >= shnum) break;
		const uint32_t stroff = u32(shoff + size_t(link) * shentsize + 16);
		for (uint64_t s = symoff; s + 16 <= uint64_t(symoff) + symsize && s + 16 <= elf.size(); s += 16) {
			const uint32_t name = u32(size_t(s)), value = u32(size_t(s) + 4);
			const uint8_t type = elf[size_t(s) + 12] & 15;
			if (!value || (type != 1 && type != 2) || uint64_t(stroff) + name >= elf.size()) continue;
			m_symbols.emplace(reinterpret_cast<const char *>(&elf[stroff + name]), value);
			m_symbol_sizes.emplace(reinterpret_cast<const char *>(&elf[stroff + name]), u32(size_t(s) + 8));
		}
	}
	return !m_symbols.empty();
}

// The machine's devices start once the program is loaded: the node bus reads the game's own board
// tables from its memory
void supervisor::start_devices()
{
	m_started = true;
	m_mem.set_remote(m_child);
	spike1_devices::config cfg;
	cfg.trace = m_opt.trace;
	cfg.log = [this](const std::string &line) { log(line); };
	cfg.symbol = [this](const std::string &n) { auto it = m_symbols.find(n); return it == m_symbols.end() ? 0u : it->second; };
	cfg.symbol_size = [this](const std::string &n) { auto it = m_symbol_sizes.find(n); return it == m_symbol_sizes.end() ? 0u : it->second; };
	cfg.symbols_with_prefix = [this](const std::string &prefix) {
		std::vector<std::string> names;
		for (auto it = m_symbols.lower_bound(prefix); it != m_symbols.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it) names.push_back(it->first);
		return names;
	};
	cfg.game_files = [this]() { return m_set_files; };
	cfg.read_game_file = [this](const std::string &name, std::vector<uint8_t> &out) {
		std::ifstream in(m_opt.files + "/" + name, std::ios::binary);
		if (!in) return false;
		out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
		return true;
	};
	m_dev.start(cfg);
	for (const auto &m : m_opt.encoder_motors)
		m_dev.link_encoder_motor(uint8_t(m.node), uint8_t(m.motor), int16_t(m.low), int16_t(m.high), uint16_t(m.counts_per_s));
	std::ifstream nv(m_nvram_path, std::ios::binary);
	std::vector<uint8_t> block((std::istreambuf_iterator<char>(nv)), std::istreambuf_iterator<char>());
	if (!block.empty()) m_dev.set_nvram(block.data(), block.size());
	m_mem.flush();
	log("devices: " + std::to_string(m_dev.switches().size()) + " switches, " + std::to_string(m_dev.coils().size()) + " coils, " +
		std::to_string(m_dev.leds().size()) + " LED channels" + (block.empty() ? "" : ", EEPROMs from " + m_nvram_path));
}

bool supervisor::child_read(pid_t pid, uint32_t addr, void *dst, size_t len)
{
	iovec local{ dst, len }, remote{ reinterpret_cast<void *>(uintptr_t(addr)), len };
	return process_vm_readv(pid, &local, 1, &remote, 1, 0) == ssize_t(len);
}

bool supervisor::child_write(pid_t pid, uint32_t addr, const void *src, size_t len)
{
	iovec local{ const_cast<void *>(src), len }, remote{ reinterpret_cast<void *>(uintptr_t(addr)), len };
	return process_vm_writev(pid, &local, 1, &remote, 1, 0) == ssize_t(len);
}

bool supervisor::child_string(pid_t pid, uint32_t addr, std::string &out)
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

// Puts a descriptor of ours into the calling process (at `at`, or the lowest free one when -1)
int supervisor::add_fd(const call &c, int src, int at, bool cloexec)
{
	seccomp_notif_addfd a{};
	a.id = c.n.id;
	a.srcfd = uint32_t(src);
	if (at >= 0) { a.flags = SECCOMP_ADDFD_FLAG_SETFD; a.newfd = uint32_t(at); }
	a.newfd_flags = cloexec ? O_CLOEXEC : 0;
	const int r = ioctl(m_listener, SECCOMP_IOCTL_NOTIF_ADDFD, &a);
	return r < 0 ? -errno : r;
}

// What poll() would say now of one of the game's own descriptors
short supervisor::native_revents(int fd, short events)
{
	if (m_pidfd < 0) m_pidfd = int(syscall(SYS_pidfd_open, m_child, 0));
	const int dup = m_pidfd < 0 ? -1 : int(syscall(SYS_pidfd_getfd, m_pidfd, fd, 0));
	if (dup < 0) return POLLNVAL;
	pollfd p{ dup, events, 0 };
	::poll(&p, 1, 0);
	close(dup);
	return p.revents;
}

supervisor::outcome supervisor::open_call(call &c, int64_t &val)
{
	const bool at = c.n.data.nr == nr::openat;
	const uint32_t addr = uint32_t(c.n.data.args[at ? 1 : 0]), flags = uint32_t(c.n.data.args[at ? 2 : 1]);
	std::string path;
	if (!child_string(pid_t(c.n.pid), addr, path)) { val = -EFAULT; return outcome::reply; }
	if (path.rfind("/dev/", 0) != 0) return outcome::pass; // the chroot has the title's files
	const bool cloexec = (flags & O_CLOEXEC_) != 0;
	if (path == "/dev/null" || path == "/dev/zero" || path == "/dev/random" || path == "/dev/urandom") {
		const int h = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
		val = h < 0 ? -errno : add_fd(c, h, -1, cloexec);
		if (h >= 0) close(h);
		return outcome::reply;
	}
	if (path == "/dev/console" || path == "/dev/tty") { // the game's console: our output
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
	if (!m_started) start_devices();
	slot &s = m_slots[i];
	s = slot();
	s.used = true;
	s.flags = flags;
	s.h.type = spike1_devices::kind_for_path(path);
	s.h.path = path;
	log("open device " + path + " -> fd " + std::to_string(val));
	return outcome::reply;
}

// select and poll: answered here when they wait on a device, as spike1_linux::sys_poll does
supervisor::outcome supervisor::poll_call(call &c, int64_t &val)
{
	const uint32_t n = c.n.data.nr;
	uint32_t a[6];
	for (int i = 0; i < 6; i++) a[i] = uint32_t(c.n.data.args[i]);
	const pid_t pid = pid_t(c.n.pid);
	const bool is_poll = n == nr::poll || n == nr::ppoll;
	const uint64_t now = now_ns();

	std::vector<uint8_t> pfds;
	std::vector<uint32_t> in_r, in_w, out_r, out_w;
	bool any_device = false;
	if (is_poll) {
		pfds.resize(size_t(a[1]) * 8);
		if (!pfds.empty() && !child_read(pid, a[0], pfds.data(), pfds.size())) { val = -EFAULT; return outcome::reply; }
		for (uint32_t i = 0; i < a[1]; i++) { int32_t fd; std::memcpy(&fd, &pfds[8 * i], 4); if (device(fd)) any_device = true; }
	} else {
		const uint32_t words = (a[0] + 31) / 32;
		in_r.assign(words, 0); in_w.assign(words, 0); out_r.assign(words, 0); out_w.assign(words, 0);
		if (a[1] && !child_read(pid, a[1], in_r.data(), words * 4)) { val = -EFAULT; return outcome::reply; }
		if (a[2] && !child_read(pid, a[2], in_w.data(), words * 4)) { val = -EFAULT; return outcome::reply; }
		for (uint32_t fd = 0; fd < a[0]; fd++)
			if (((in_r[fd / 32] | in_w[fd / 32]) >> (fd & 31) & 1) && device(int(fd))) any_device = true;
	}
	if (!any_device) return outcome::pass;

	int64_t timeout_ns = -1;
	if (n == nr::poll) { if (int32_t(a[2]) >= 0) timeout_ns = int64_t(int32_t(a[2])) * 1000000; }
	else {
		const uint32_t ptr = n == nr::ppoll ? a[2] : a[4];
		uint32_t t[2];
		if (ptr) {
			if (!child_read(pid, ptr, t, 8)) { val = -EFAULT; return outcome::reply; }
			timeout_ns = int64_t(t[0]) * 1000000000 + int64_t(t[1]) * (n == nr::newselect ? 1000 : 1); // timeval, or timespec
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
		if (is_poll) child_write(pid, a[0], pfds.data(), pfds.size());
		else {
			const uint32_t bytes = uint32_t(out_r.size() * 4);
			std::vector<uint32_t> none(out_r.size(), 0);
			if (a[1]) child_write(pid, a[1], out_r.data(), bytes);
			if (a[2]) child_write(pid, a[2], out_w.data(), bytes);
			if (a[3]) child_write(pid, a[3], none.data(), bytes);
		}
		val = ready;
		return outcome::reply;
	}
	c.wake_ns = std::min(c.poll_deadline, look_again);
	return outcome::wait;
}

supervisor::outcome supervisor::handle(call &c, int64_t &val)
{
	const uint32_t n = c.n.data.nr;
	const int fd = int(int32_t(uint32_t(c.n.data.args[0])));
	const uint32_t a1 = uint32_t(c.n.data.args[1]), a2 = uint32_t(c.n.data.args[2]);
	switch (n) {
	case nr::open: case nr::openat: return open_call(c, val);
	case nr::newselect: case nr::pselect6: case nr::poll: case nr::ppoll: return poll_call(c, val);
	case nr::sync: case nr::syncfs: case nr::fsync: case nr::fdatasync: m_syncs++; return outcome::pass;
	default: break;
	}
	slot *s = device(fd);
	if (!s) return outcome::pass; // a device descriptor the game did not get from us (dup2 onto one)
	const uint64_t now = now_ns();
	uint64_t wait_ns = 0;
	std::string note;
	int32_t r = 0;
	switch (n) {
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
		if (!note.empty()) log("read fd " + std::to_string(fd) + ": " + note);
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
		if (!note.empty()) log("write fd " + std::to_string(fd) + ": " + note);
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
			val = child_write(pid_t(c.n.pid), a2, &zero, 4) ? 0 : -EFAULT;
			return outcome::reply;
		}
		r = m_dev.ioctl(s->h, a1, a2, now, wait_ns, note);
		m_mem.flush();
		if (!note.empty()) log("ioctl fd " + std::to_string(fd) + ": " + note);
		if (r == spike1_devices::WAIT) { c.wake_ns = wait_ns; return outcome::wait; }
		val = r;
		return outcome::reply;
	default:
		log("not modelled on a device: system call " + std::to_string(n) + " on fd " + std::to_string(fd));
		val = -EINVAL;
		return outcome::reply;
	}
}

void supervisor::respond(const call &c, outcome o, int64_t val)
{
	seccomp_notif_resp r{};
	r.id = c.n.id;
	if (o == outcome::pass) r.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	else if (val < 0) r.error = int32_t(val);
	else r.val = val;
	ioctl(m_listener, SECCOMP_IOCTL_NOTIF_SEND, &r); // ENOENT: the caller has gone (a signal), nothing to do
}

void supervisor::print_dmd()
{
	static const char shades[] = " .,:;-=+*%#&$@@@";
	const uint8_t *dots = m_dev.dmd_frame();
	std::printf("DMD at %.3f s, frame %llu\n", double(now_ns()) / 1e9, (unsigned long long)m_dev.dmd_frame_count());
	for (uint32_t y = 0; y < spike1_devices::DMD_HEIGHT; y++) {
		char line[spike1_devices::DMD_WIDTH + 3];
		line[0] = '|';
		for (uint32_t x = 0; x < spike1_devices::DMD_WIDTH; x++) line[1 + x] = shades[dots[y * spike1_devices::DMD_WIDTH + x] & 15];
		line[spike1_devices::DMD_WIDTH + 1] = '|';
		line[spike1_devices::DMD_WIDTH + 2] = 0;
		std::printf("%s\n", line);
	}
	std::fflush(stdout);
}

// The game's CPU time so far (all its threads), from /proc
bool supervisor::child_cpu(double &seconds, unsigned &threads) const
{
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

void supervisor::tick(uint64_t now)
{
	if (!m_started) return;
	const double now_s = double(now) / 1e9;
	for (auto &p : m_opt.presses) {
		const auto *s = m_dev.find_switch(p.name);
		if (!s) continue;
		if (!p.down && now_s >= p.at) {
			p.down = true;
			m_dev.set_switch(s->node, s->position, !m_dev.switch_closed(s->node, s->position), now);
			log("switch " + s->name + (m_dev.switch_closed(s->node, s->position) ? " closed" : " opened"));
		} else if (p.down && !p.up && now_s >= p.at + p.held_ms / 1000.0) {
			p.up = true;
			m_dev.set_switch(s->node, s->position, !m_dev.switch_closed(s->node, s->position), now);
			log("switch " + s->name + (m_dev.switch_closed(s->node, s->position) ? " closed" : " opened"));
		}
	}
	m_mem.flush();
	// the samples nobody plays: a host would take them here
	int16_t audio[2 * 1024];
	while (m_dev.audio_take(audio, 1024)) {}
}

int supervisor::run()
{
	const std::string program = m_opt.game.substr(m_opt.game.rfind('/') + 1);
	std::error_code ec;
	for (const auto &e : std::filesystem::directory_iterator(m_opt.files, ec)) if (e.is_regular_file()) m_set_files.push_back(e.path().filename().string());
	if (m_set_files.empty()) { std::fprintf(stderr, "no files in %s\n", m_opt.files.c_str()); return 2; }
	if (!load_symbols(m_opt.files + "/" + program)) std::fprintf(stderr, "the program has no symbol table\n");
	mkdirs(m_opt.state, 0755);
	const std::string data_dir = std::filesystem::absolute(m_opt.state + "/data").string();
	mkdirs(data_dir, 0777);
	m_nvram_path = m_opt.state + "/eeproms.bin";
	char root_tmpl[] = "/tmp/spike1native.XXXXXX";
	if (!mkdtemp(root_tmpl)) { std::perror("mkdtemp"); return 1; }
	const std::string root = root_tmpl;
	prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) { std::perror("socketpair"); return 1; }
	std::fflush(stdout);
	m_t0 = mono_ns();
	m_child = fork();
	if (m_child < 0) { std::perror("fork"); return 1; }
	if (m_child == 0) { close(sv[0]); child_main(m_opt, root, data_dir, sv[1]); }
	close(sv[1]);
	m_listener = receive_fd(sv[0]);
	close(sv[0]);
	if (m_listener < 0) {
		int status = 0;
		waitpid(m_child, &status, 0);
		std::fprintf(stderr, "the child did not start (status %d)\n", status);
		rmdir(root.c_str());
		return 1;
	}
	log("child " + std::to_string(m_child) + " runs " + m_opt.game + (m_opt.cpus.empty() ? "" : " on cpus " + m_opt.cpus));

	const uint64_t end_ns = uint64_t(m_opt.seconds * 1e9);
	uint64_t next_tick = 0, next_dmd = m_opt.dmd_every > 0 ? uint64_t(m_opt.dmd_every * 1e9) : UINT64_MAX;
	uint64_t next_stats = m_opt.stats_every > 0 ? uint64_t(m_opt.stats_every * 1e9) : UINT64_MAX;
	uint64_t power_off_at = 0, syncs_at_power_off = 0;
	double last_cpu = 0, last_sup = 0, last_stats_s = 0;
	uint64_t last_notifications = 0, last_frames = 0;
	bool child_gone = false;
	auto sup_cpu = []() { rusage u; getrusage(RUSAGE_SELF, &u); return double(u.ru_utime.tv_sec + u.ru_stime.tv_sec) + double(u.ru_utime.tv_usec + u.ru_stime.tv_usec) / 1e6; };
	std::vector<uint8_t> notif_buf;
	seccomp_notif_sizes sizes{};
	syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
	notif_buf.resize(std::max<size_t>(sizes.seccomp_notif, sizeof(seccomp_notif)));

	for (;;) {
		uint64_t now = now_ns();
		if (!power_off_at && now >= end_ns) {
			if (!m_started) break;
			// switched off like a machine: the game commits what it keeps in memory, then syncs
			m_dev.power_off();
			power_off_at = now;
			syncs_at_power_off = m_syncs;
			log("power off");
		}
		if (power_off_at && (m_syncs > syncs_at_power_off || now - power_off_at > 5000000000ull)) {
			log(m_syncs > syncs_at_power_off ? "nvram: the game synced after the power failed" : "nvram: no sync within 5 s of the power failing");
			break;
		}
		if (now >= next_tick) {
			tick(now);
			next_tick = now + 1000000;
			int status;
			if (waitpid(m_child, &status, WNOHANG) == m_child) {
				log(WIFEXITED(status) ? "the program exited with " + std::to_string(WEXITSTATUS(status)) : "the program ended on signal " + std::to_string(WTERMSIG(status)));
				child_gone = true;
				break;
			}
		}
		if (now >= next_dmd && m_started) { print_dmd(); next_dmd += uint64_t(m_opt.dmd_every * 1e9); }
		if (now >= next_stats) {
			double cpu = 0;
			unsigned threads = 0;
			child_cpu(cpu, threads);
			const double sup = sup_cpu(), now_s = double(now) / 1e9, span = now_s - last_stats_s;
			std::printf("[%10.6f] stats: game %.1f%% of a core (%u threads), supervisor %.1f%%, %.0f notifications/s, %.1f DMD frames/s\n",
				now_s, 100.0 * (cpu - last_cpu) / span, threads, 100.0 * (sup - last_sup) / span,
				double(m_notifications - last_notifications) / span, double(m_dev.dmd_frame_count() - last_frames) / span);
			std::fflush(stdout);
			last_cpu = cpu; last_sup = sup; last_stats_s = now_s;
			last_notifications = m_notifications; last_frames = m_dev.dmd_frame_count();
			next_stats += uint64_t(m_opt.stats_every * 1e9);
		}

		// calls waiting on a device, due now
		for (size_t i = 0; i < m_pending.size(); ) {
			call &c = m_pending[i];
			if (c.wake_ns > now) { i++; continue; }
			uint64_t id = c.n.id;
			if (ioctl(m_listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) { m_pending.erase(m_pending.begin() + long(i)); continue; } // interrupted
			int64_t val = 0;
			const outcome o = handle(c, val);
			if (o == outcome::wait) { i++; continue; }
			respond(c, o, val);
			m_pending.erase(m_pending.begin() + long(i));
		}

		uint64_t next = std::min(next_tick, next_dmd);
		for (const call &c : m_pending) next = std::min(next, c.wake_ns);
		now = now_ns();
		const uint64_t wait = next > now ? next - now : 0;
		timespec ts{ time_t(wait / 1000000000ull), long(wait % 1000000000ull) };
		pollfd p{ m_listener, POLLIN, 0 };
		if (ppoll(&p, 1, &ts, nullptr) < 0 && errno != EINTR) { std::perror("ppoll"); break; }
		if (p.revents & POLLHUP) { log("the program and its children have all exited"); child_gone = true; break; }
		while (p.revents & POLLIN) {
			std::fill(notif_buf.begin(), notif_buf.end(), 0);
			if (ioctl(m_listener, SECCOMP_IOCTL_NOTIF_RECV, notif_buf.data()) < 0) break;
			call c;
			std::memcpy(&c.n, notif_buf.data(), sizeof(seccomp_notif));
			m_notifications++;
			m_counts[c.n.data.nr]++;
			int64_t val = 0;
			const outcome o = handle(c, val);
			if (o == outcome::wait) m_pending.push_back(c);
			else respond(c, o, val);
			p.revents = 0;
			pollfd again{ m_listener, POLLIN, 0 };
			if (::poll(&again, 1, 0) > 0) p.revents = again.revents & POLLIN;
		}
	}

	double cpu = 0;
	unsigned threads = 0;
	const bool have_cpu = !child_gone && child_cpu(cpu, threads);
	if (m_opt.dmd_every > 0 && m_started) print_dmd();
	if (!child_gone) { kill(m_child, SIGKILL); waitpid(m_child, nullptr, 0); }
	if (m_started) {
		const std::vector<uint8_t> nv = m_dev.nvram();
		if (FILE *f = std::fopen(m_nvram_path.c_str(), "wb")) { std::fwrite(nv.data(), 1, nv.size(), f); std::fclose(f); }
	}
	close(m_listener);
	if (m_pidfd >= 0) close(m_pidfd);
	rmdir(root.c_str());
	const double wall = double(now_ns()) / 1e9;
	std::printf("\nnative run: %.3f s; game CPU %s; supervisor CPU %.3f s; %llu notifications, %llu DMD frames\n", wall,
		have_cpu ? (std::to_string(cpu) + " s (" + std::to_string(int(100.0 * cpu / wall)) + "% of a core)").c_str() : "n/a",
		sup_cpu(), (unsigned long long)m_notifications, (unsigned long long)m_dev.dmd_frame_count());
	std::string per;
	for (const auto &c : m_counts) per += " " + std::to_string(c.first) + ":" + std::to_string(c.second);
	std::printf("notifications by system call:%s\n", per.c_str());
	return 0;
}

} // namespace

int main(int argc, char **argv)
{
	options o;
	for (int i = 1; i < argc; i++) {
		const std::string arg = argv[i];
		auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
		if (arg == "--files") o.files = next();
		else if (arg == "--game") o.game = next();
		else if (arg == "--state") o.state = next();
		else if (arg == "--seconds") o.seconds = std::atof(next().c_str());
		else if (arg == "--dmd") o.dmd_every = std::atof(next().c_str());
		else if (arg == "--stats") o.stats_every = std::atof(next().c_str());
		else if (arg == "--cpus") o.cpus = next();
		else if (arg == "--trace") o.trace = true;
		else if (arg == "--switch") {
			const std::string v = next();
			const size_t a = v.find(':'), b = v.rfind(':');
			options::press p{ std::atof(v.c_str()), 200.0, v.substr(a + 1) };
			if (b != a && b + 1 < v.size() && std::isdigit(uint8_t(v[b + 1]))) { p.held_ms = std::atof(v.c_str() + b + 1); p.name = v.substr(a + 1, b - a - 1); }
			o.presses.push_back(p);
		}
		else if (arg == "--encoder-motor") {
			options::encoder_motor m{};
			if (std::sscanf(next().c_str(), "%d:%d:%d:%d:%u", &m.node, &m.motor, &m.low, &m.high, &m.counts_per_s) != 5) {
				std::fprintf(stderr, "--encoder-motor takes <node>:<motor>:<low stop>:<high stop>:<counts a second>\n");
				return 2;
			}
			o.encoder_motors.push_back(m);
		}
		else { std::fprintf(stderr, "unknown argument %s\n", arg.c_str()); return 2; }
	}
	if (o.files.empty() || o.game.empty() || o.game[0] != '/') {
		std::fprintf(stderr, "usage: spike1native --files <set dir> --game /games/<folder>/game [--state <dir>] [--seconds <n>] [--dmd <s>] [--switch <s>:<name>[:<ms>]]...\n");
		return 2;
	}
	o.files = std::filesystem::absolute(o.files).string();
	supervisor s(o);
	return s.run();
}
