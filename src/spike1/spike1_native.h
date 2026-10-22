// license:BSD-3-Clause

// PinMAME Spike 1 subsystem - the game program run natively, as a 32-bit ARM process of its own
//
// spike1_linux runs the game program on MAME's ARM9 interpreter. A Linux host whose kernel runs
// AArch32 user programs (arm64 with CONFIG_COMPAT, on a CPU with AArch32 at EL0: the RK3588's
// cores, a Raspberry Pi 4 or 5) can run it as itself instead, its threads scheduled by the host.
// What the board's hardware answers is answered here by the same spike1_devices, so the machine
// looks the same from PinMAME's side: same switches, outputs, DMD, sound and NVRAM block.
//
// - The program runs in a sandbox: a private mount namespace and a chroot holding /games/<folder>
//   (the title's files: the on-disk ones bound read-only, the rest written into a tmpfs), /data
//   (the game's NVRAM files, a host directory filled from the NVRAM block), /tmp and an empty
//   /dev; in a session of its own, as root of a user namespace that maps to nobody (the game
//   creates its NVRAM files with an undefined mode and relies on root to read them back), with
//   no_new_privs.
// - A seccomp filter passes everything through natively except: open/openat, select/poll and the
//   sync calls, which come to the supervisor and go on natively unless a device is involved;
//   read, write, ioctl, close and fcntl on the device descriptors (DEVICE_FD up), which the device
//   model answers; sched_setscheduler and the like, answered 0 without effect (the game asks for
//   SCHED_RR 97, which would preempt the host's own threads); execve, mount, reboot and the like,
//   refused. A device open gets a placeholder descriptor at a fixed number, so the filter can tell
//   device calls apart. The model reaches the game's memory with process_vm_readv/writev
//   (spike1_memory's remote mode).
// - Time is the host's monotonic clock from the start. The supervisor answers the game from the
//   machine's thread, in run_until(); a device call that would wait (WAIT) is asked again at its
//   time, the caller asleep in the kernel until then.
// - The program is held at its first system call until the first run_until(): its image is
//   loaded, so the devices read the game's tables from it as they do in the emulated machine, and
//   a host can link motors, provide a video key or a display link first.
// - When the program exits (a slam tilt), it starts again a second later as the board's
//   game_monitor does; /data and the devices carry on.
//
// Needs Linux, an arm64 build and root (for the mount namespace and the chroot); start() fails
// with the reason otherwise, or when the kernel cannot run the program, and the host falls back
// to the emulated machine.

#pragma once

#include "spike1_devices.h"
#include "spike1_memory.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class spike1_native
{
public:
	struct file { std::string name; const uint8_t *data = nullptr; size_t size = 0; };
	struct named_address { std::string name; uint32_t address = 0, size = 0; };
	struct config
	{
		std::string folder;                   // the game folder: the program runs as /games/<folder>/game
		std::vector<file> files;              // the folder's files; the caller keeps the bytes alive until stop()
		std::vector<named_address> symbols;   // for a program without a symbol table
		std::vector<uint8_t> nvram;           // what nvram() gave the last time (spike1_linux's format); empty for a new machine
		std::vector<std::string> environment;
		std::string cpus;                     // the CPUs the game may use, e.g. "0,5-7"; empty for any
		bool trace = false;
		std::function<void (const std::string &)> log;
	};

	spike1_native();
	~spike1_native();
	spike1_native(const spike1_native &) = delete;
	spike1_native &operator=(const spike1_native &) = delete;

	// Whether this build and host can run a program natively at all (Linux, arm64, root)
	static bool supported(std::string &why);

	bool start(const config &cfg, std::string &error);
	void stop();

	// Answers the game until now_ns() reaches until_ns (at once when it already has); restarts the
	// program after it exited
	void run_until(uint64_t until_ns);
	// Or: answers the game from a thread of its own, until stop(). The host then holds lock() for
	// every other use of the machine - devices(), nvram(), running(), add_link() - except
	// power_down() and stop(), which take it themselves
	void start_thread();
	std::mutex &lock() { return m_lock; }
	uint64_t now_ns() const;
	bool running(std::string &reason) const;

	// The mains go away: the game commits its NVRAM files and syncs. Answers it until it has, for at
	// most max_ns; true when it synced
	bool power_down(uint64_t max_ns);
	// The NVRAM block, in spike1_linux::nvram()'s format: /data's files, then the EEPROMs
	std::vector<uint8_t> nvram() const;
	// A symbolic link in the program's root filesystem (/usr/local/spike/display.hex)
	bool add_link(const std::string &path, const std::string &target);

	spike1_devices &devices() { return m_dev; }
	const spike1_devices &devices() const { return m_dev; }
	uint32_t symbol(const std::string &name) const;

	// For a host's diagnostics
	uint64_t notifications() const { return m_notifications; }
	uint32_t restarts() const { return m_restarts; }
	bool game_cpu(double &seconds, unsigned &threads) const; // the program's CPU time, all threads
	const std::map<uint32_t, uint64_t> &notification_counts() const { return m_counts; }

private:
	// A system call the filter sent here: the notification's fields this side uses
	struct call { uint64_t id = 0; int pid = 0; uint32_t nr = 0; uint32_t a[6] = {}; uint64_t wake_ns = 0, poll_deadline = 0; };
	struct slot { bool used = false; spike1_devices::handle h; uint32_t flags = 0; };
	enum class outcome { reply, pass, wait, hold };

	config m_cfg;
	spike1_memory m_mem;
	spike1_devices m_dev;
	bool m_devices_started = false;
	std::map<std::string, uint32_t> m_symbols, m_symbol_sizes;
	std::vector<std::string> m_game_files;

	std::string m_dir;           // our temporary directory: root/ (the chroot's mount point), data/ (/data)
	int m_listener = -1, m_pidfd = -1;
	int m_child = 0;
	uint64_t m_t0 = 0;
	bool m_held = false;         // the program waits at its first system call
	call m_held_call;
	bool m_exited = false;
	uint64_t m_restart_ns = 0;   // the program exited: when it starts again (0: not waiting)
	uint32_t m_restarts = 0;
	std::string m_stop_reason;
	slot m_slots[32];
	std::vector<call> m_pending;  // device calls that wait
	std::vector<uint8_t> m_notif_buf;
	std::map<uint32_t, uint64_t> m_counts;
	uint64_t m_notifications = 0, m_syncs = 0;
	std::map<std::string, std::string> m_links;
	std::mutex m_lock;
	std::thread m_thread;
	std::atomic<bool> m_quit{ false };
	bool m_threaded = false;

	void log(const std::string &line) const;
	bool spawn(std::string &error);
	void reap(const std::string &how);
	bool wait_for_hold(uint64_t max_ns);
	void release();
	void kill_child();
	void step(uint64_t until_ns);   // one wait and its answers, or the restart of an exited program
	void thread_main();
	void start_devices();
	bool pump(uint64_t until_ns);   // one wait for the game and its answers; false when the program is gone
	void respond(const call &c, outcome o, int64_t val);
	outcome handle(call &c, int64_t &val);
	outcome open_call(call &c, int64_t &val);
	outcome poll_call(call &c, int64_t &val);
	slot *device(int fd);
	int add_fd(const call &c, int src, int at, bool cloexec);
	short native_revents(int fd, short events);
	bool child_read(int pid, uint32_t addr, void *dst, size_t len) const;
	bool child_write(int pid, uint32_t addr, const void *src, size_t len) const;
	bool child_string(int pid, uint32_t addr, std::string &out) const;
	void make_link(const std::string &path, const std::string &target);
};
