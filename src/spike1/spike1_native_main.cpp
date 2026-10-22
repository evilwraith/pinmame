// license:BSD-3-Clause

// PinMAME Spike 1 subsystem - native harness: a title's game program run as itself (spike1_native)
//
//   spike1native --files <set dir> --game <folder> [--state <dir>] [--seconds <n>] [--dmd <s>]
//                [--stats <s>] [--cpus <list>] [--switch <s>:<name>[:<ms>]]...
//                [--encoder-motor <node>:<motor>:<low>:<high>:<counts a second>] [--trace]
//
// The set's files are mapped from disk, as PinMAME's ROM loader maps them; the machine's NVRAM is
// kept between runs as <state>/spike1.nv, in the emulated machine's format (spike1boot reads it
// too). Run as root.

#include "spike1_native.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

void print_dmd(spike1_native &m)
{
	static const char shades[] = " .,:;-=+*%#&$@@@";
	const uint8_t *dots = m.devices().dmd_frame();
	std::printf("DMD at %.3f s, frame %llu\n", double(m.now_ns()) / 1e9, (unsigned long long)m.devices().dmd_frame_count());
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

double self_cpu()
{
	rusage u;
	getrusage(RUSAGE_SELF, &u);
	return double(u.ru_utime.tv_sec + u.ru_stime.tv_sec) + double(u.ru_utime.tv_usec + u.ru_stime.tv_usec) / 1e6;
}

} // namespace

int main(int argc, char **argv)
{
	std::string files_dir, folder, state = "spike1_native_state";
	double seconds = 30.0, dmd_every = 0.0, stats_every = 10.0;
	spike1_native::config cfg;
	struct press { double at, held_ms; std::string name; bool down = false, up = false; };
	std::vector<press> presses;
	struct encoder_motor { int node, motor, low, high; unsigned counts_per_s; };
	std::vector<encoder_motor> encoders;
	for (int i = 1; i < argc; i++) {
		const std::string arg = argv[i];
		auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
		if (arg == "--files") files_dir = next();
		else if (arg == "--game") folder = next();
		else if (arg == "--state") state = next();
		else if (arg == "--seconds") seconds = std::atof(next().c_str());
		else if (arg == "--dmd") dmd_every = std::atof(next().c_str());
		else if (arg == "--stats") stats_every = std::atof(next().c_str());
		else if (arg == "--cpus") cfg.cpus = next();
		else if (arg == "--trace") cfg.trace = true;
		else if (arg == "--switch") {
			const std::string v = next();
			const size_t a = v.find(':'), b = v.rfind(':');
			press p{ std::atof(v.c_str()), 200.0, v.substr(a + 1) };
			if (b != a && b + 1 < v.size() && std::isdigit(uint8_t(v[b + 1]))) { p.held_ms = std::atof(v.c_str() + b + 1); p.name = v.substr(a + 1, b - a - 1); }
			presses.push_back(p);
		}
		else if (arg == "--encoder-motor") {
			encoder_motor m{};
			if (std::sscanf(next().c_str(), "%d:%d:%d:%d:%u", &m.node, &m.motor, &m.low, &m.high, &m.counts_per_s) != 5) {
				std::fprintf(stderr, "--encoder-motor takes <node>:<motor>:<low stop>:<high stop>:<counts a second>\n");
				return 2;
			}
			encoders.push_back(m);
		}
		else { std::fprintf(stderr, "unknown argument %s\n", arg.c_str()); return 2; }
	}
	if (files_dir.empty() || folder.empty()) {
		std::fprintf(stderr, "usage: spike1native --files <set dir> --game <folder> [--state <dir>] [--seconds <n>] [--dmd <s>] [--switch <s>:<name>[:<ms>]]...\n");
		return 2;
	}
	cfg.folder = folder;
	std::error_code ec;
	for (const auto &e : std::filesystem::directory_iterator(files_dir, ec)) {
		if (!e.is_regular_file()) continue;
		const int fd = open(e.path().c_str(), O_RDONLY | O_CLOEXEC);
		struct stat st;
		if (fd < 0 || fstat(fd, &st) < 0 || !st.st_size) { if (fd >= 0) close(fd); continue; }
		void *p = mmap(nullptr, size_t(st.st_size), PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (p == MAP_FAILED) { std::perror(e.path().c_str()); return 1; }
		cfg.files.push_back({ e.path().filename().string(), static_cast<const uint8_t *>(p), size_t(st.st_size) });
	}
	std::filesystem::create_directories(state, ec);
	const std::string nv_path = state + "/spike1.nv";
	{
		std::ifstream in(nv_path, std::ios::binary);
		cfg.nvram.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	}
	cfg.log = [](const std::string &line) { std::printf("%s\n", line.c_str()); std::fflush(stdout); };

	spike1_native m;
	std::string error;
	const auto t0 = std::chrono::steady_clock::now();
	if (!m.start(cfg, error)) { std::fprintf(stderr, "start failed: %s\n", error.c_str()); return 1; }
	const double start_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	std::printf("started in %.3f s: %zu switches, %zu coils, %zu LED channels\n", start_s,
		m.devices().switches().size(), m.devices().coils().size(), m.devices().leds().size());
	for (const auto &e : encoders) m.devices().link_encoder_motor(uint8_t(e.node), uint8_t(e.motor), int16_t(e.low), int16_t(e.high), uint16_t(e.counts_per_s));
	for (const auto &p : presses)
		if (!m.devices().find_switch(p.name)) { std::fprintf(stderr, "no switch named \"%s\"\n", p.name.c_str()); return 2; }

	const uint64_t end_ns = uint64_t(seconds * 1e9);
	uint64_t next_dmd = dmd_every > 0 ? uint64_t(dmd_every * 1e9) : UINT64_MAX;
	uint64_t next_stats = stats_every > 0 ? uint64_t(stats_every * 1e9) : UINT64_MAX;
	double last_game = 0, last_self = self_cpu(), last_s = double(m.now_ns()) / 1e9;
	uint64_t last_notifications = 0, last_frames = 0;
	std::string reason;
	int16_t audio[2 * 1024];
	// the harness's own I/O every millisecond, as PinMAME's I/O timer does it
	for (uint64_t t = m.now_ns(); t < end_ns && m.running(reason); t += 1000000) {
		m.run_until(t);
		const uint64_t now = m.now_ns();
		const double now_s = double(now) / 1e9;
		for (auto &p : presses) {
			const auto *s = m.devices().find_switch(p.name);
			if ((!p.down && now_s >= p.at) || (p.down && !p.up && now_s >= p.at + p.held_ms / 1000.0)) {
				(p.down ? p.up : p.down) = true;
				m.devices().set_switch(s->node, s->position, !m.devices().switch_closed(s->node, s->position), now);
				std::printf("[%10.6f] switch %s %s\n", now_s, s->name.c_str(), m.devices().switch_closed(s->node, s->position) ? "closed" : "opened");
			}
		}
		while (m.devices().audio_take(audio, 1024)) {} // a host plays these
		if (now >= next_dmd) { print_dmd(m); next_dmd += uint64_t(dmd_every * 1e9); }
		if (now >= next_stats) {
			double game = 0;
			unsigned threads = 0;
			m.game_cpu(game, threads);
			const double self = self_cpu(), span = now_s - last_s;
			std::printf("[%10.6f] stats: game %.1f%% of a core (%u threads), supervisor %.1f%%, %.0f notifications/s, %.1f DMD frames/s, %u restarts\n",
				now_s, 100.0 * (game - last_game) / span, threads, 100.0 * (self - last_self) / span,
				double(m.notifications() - last_notifications) / span, double(m.devices().dmd_frame_count() - last_frames) / span, m.restarts());
			std::fflush(stdout);
			last_game = game; last_self = self; last_s = now_s;
			last_notifications = m.notifications(); last_frames = m.devices().dmd_frame_count();
			next_stats += uint64_t(stats_every * 1e9);
		}
	}
	if (!m.running(reason)) std::printf("the program stopped: %s\n", reason.c_str());
	m.power_down(5000000000ull);
	const std::vector<uint8_t> nv = m.nvram();
	if (FILE *f = std::fopen(nv_path.c_str(), "wb")) { std::fwrite(nv.data(), 1, nv.size(), f); std::fclose(f); }
	if (dmd_every > 0) print_dmd(m);
	std::string per;
	for (const auto &c : m.notification_counts()) per += " " + std::to_string(c.first) + ":" + std::to_string(c.second);
	std::printf("\nnative run: %.3f s, %llu notifications, %llu DMD frames, NVRAM %zu bytes -> %s\nnotifications by system call:%s\n",
		double(m.now_ns()) / 1e9, (unsigned long long)m.notifications(), (unsigned long long)m.devices().dmd_frame_count(), nv.size(), nv_path.c_str(), per.c_str());
	m.stop();
	return 0;
}
