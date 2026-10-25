// license:BSD-3-Clause

// PinMAME SPIKE 1 subsystem - the PinMAME-facing side of the machine
//
// src/wpc/spike1.c is compiled as part of PinMAME and knows nothing about the subsystem's C++
// types; the functions below (spike1_public.h) are the whole contract between them. The title's
// files arrive as PinMAME ROM regions, which spike1.c passes in: the subsystem opens no files.
//
// Two machines answer the contract. Where the host can run the game program as itself (Linux on
// arm64 with AArch32 user mode and user namespaces: spike1_native), it does, and the program runs at the
// host CPU's speed; everywhere else, or when that fails to start, MAME's ARM9 core runs it
// (spike1_linux). Both have the same devices, so the rest is the same. SPIKE1_NATIVE=0 in the
// environment keeps to the emulated machine; SPIKE1_NATIVE_CPUS=<list> (e.g. 0,5-7) puts the
// native program on those CPUs.

#include "spike1_public.h"
#include "spike1_cpu.h"
#include "spike1_debug.h"
#include "spike1_linux.h"
#include "spike1_memory.h"
#include "spike1_native.h"

#include <cstdio>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

extern machine_config *p2k_active_config;

namespace {

// The shim's device world for one machine: its config, the CPU's address space over the guest memory, and Linux on top
struct machine
{
	running_machine running;
	machine_config config;
	spike1_memory memory;
	std::unique_ptr<address_space> space;
	spike1_cpu_device *cpu = nullptr;
	std::unique_ptr<spike1_linux> os;
};

std::unique_ptr<machine> g_machine;
#if SPIKE1_DEBUG
bool g_log_all = false;
#else
constexpr bool g_log_all = false; // without SPIKE1_DEBUG the subsystem only reports a stop and the NVRAM's fate
#endif

// The native machine, when it runs. It answers the game from a thread of its own, started at the
// first run(); every use of its devices holds its lock (native_guard())
std::unique_ptr<spike1_native> g_native;
bool g_native_started = false;

std::unique_lock<std::mutex> native_guard()
{
	return g_native ? std::unique_lock<std::mutex>(g_native->lock()) : std::unique_lock<std::mutex>();
}

void copy_text(const std::string &s, char *dst, unsigned size)
{
	if (!dst || !size) return;
	std::snprintf(dst, size, "%s", s.c_str());
}

// Outside the CPU's fast windows: a file view the memory holds beyond them (the bus context), or a fault
u32 unmapped_read(void *ctx, offs_t addr, u32)
{
	uint32_t value = 0;
	if (ctx && static_cast<const spike1_memory *>(ctx)->read_view(addr, value)) return value;
	if (g_machine && g_machine->os) g_machine->os->fault(addr, false);
	return 0;
}
void unmapped_write(void *, offs_t addr, u32, u32) { if (g_machine && g_machine->os) g_machine->os->fault(addr, true); }

spike1_devices *devices()
{
	if (g_native) return &g_native->devices();
	return g_machine && g_machine->os ? &g_machine->os->devices() : nullptr;
}
uint64_t now_ns()
{
	if (g_native) return g_native->now_ns();
	return g_machine && g_machine->os ? g_machine->os->now_ns() : 0;
}

void log_line(const std::string &line)
{
	// a stop is worth seeing in any build; the rest only when asked for
	if (g_log_all || line.rfind("stop:", 0) == 0 || line.find("nvram:") != std::string::npos || line.rfind("native:", 0) == 0 ||
		line.find("] exit:") != std::string::npos || line.find("the program runs natively") != std::string::npos)
		std::fprintf(stderr, "[spike1] %s\n", line.c_str());
}

// The game program as itself, when the host can: false (and the emulated machine runs) otherwise
bool start_native(const char *game, const char *program, const spike1_file *files, unsigned count, const spike1_symbol *symbols,
                  const unsigned char *nvram, unsigned nvram_size)
{
	const char *env = std::getenv("SPIKE1_NATIVE");
	if (env && std::strcmp(env, "0") == 0) return false;
	std::string why;
	if (!spike1_native::supported(why)) {
		if (env || g_log_all) log_line("native: " + why + "; the game program runs on the emulated CPU");
		return false;
	}
	spike1_native::config cfg;
	cfg.folder = game ? game : "";
	cfg.program = program ? program : "game";
	for (unsigned i = 0; i < count; i++)
		if (files[i].name && files[i].data) cfg.files.push_back({ files[i].name, files[i].data, files[i].size });
	for (const spike1_symbol *s = symbols; s && s->name; s++) cfg.symbols.push_back({ s->name, s->address, s->size });
	if (nvram && nvram_size) cfg.nvram.assign(nvram, nvram + nvram_size);
	cfg.environment = { "HOME=/root", "PATH=/bin:/usr/bin:/usr/local/bin", "LANG=C", "LC_ALL=C", "GAMES_PATH=/games" };
	if (const char *cpus = std::getenv("SPIKE1_NATIVE_CPUS")) cfg.cpus = cpus;
	cfg.log = log_line;
	auto native = std::make_unique<spike1_native>();
	if (!native->start(cfg, why)) {
		log_line("native: " + why + "; the game program runs on the emulated CPU");
		return false;
	}
	g_native = std::move(native);
	g_native_started = false;
	return true;
}

} // anonymous namespace

extern "C" {

int spike1_pinmame_start(const char *game, const char *program, const spike1_file *files, unsigned count, const spike1_symbol *symbols,
                         const unsigned char *nvram, unsigned nvram_size, char *error, unsigned error_size)
{
	g_machine.reset();
	g_native.reset();
#if SPIKE1_DEBUG
	g_log_all = std::getenv("SPIKE1_LOG") != nullptr; // SPIKE1_LOG=1: the subsystem's whole log on stderr
#endif
	if (start_native(game, program, files, count, symbols, nvram, nvram_size)) return 1;
	auto m = std::make_unique<machine>();
	device_t::s_machine = &m->running;
	p2k_active_config = &m->config;

	m->cpu = &SPIKE1_CPU(m->config, "maincpu", SPIKE1_CPU_HZ);
	p2k_bus_callbacks bus{ unmapped_read, unmapped_write, &m->memory };
	m->space = std::make_unique<address_space>(bus);
	m->memory.attach(*m->space);
	m->cpu->p2k_set_space(AS_PROGRAM, m->space.get());
	for (auto &dev : m->config.devices) dev->p2k_resolve();
	for (auto &dev : m->config.devices) dev->p2k_start();
	for (auto &dev : m->config.devices) dev->p2k_reset();

	spike1_linux::config cfg;
	const std::string dir = std::string("/games/") + (game ? game : "");
	// A set's files sit side by side; on the card a title's LCD clips (.spv) are in its video folder,
	// and the ELG titles' sounds (.wav) in its sounds folder
	auto ends_with = [](const std::string &name, const char *ext) { return name.size() > 4 && name.compare(name.size() - 4, 4, ext) == 0; };
	for (unsigned i = 0; i < count; i++)
		if (files[i].name && files[i].data) {
			const std::string& name = files[i].name;
			const char *sub = ends_with(name, ".spv") ? "/video/" : ends_with(name, ".wav") ? "/sounds/" : "/";
			cfg.files.push_back({ dir + sub + name, files[i].data, files[i].size });
		}
	cfg.executable = dir + "/" + (program ? program : "game");
	for (const spike1_symbol *s = symbols; s && s->name; s++) cfg.symbols.push_back({ s->name, s->address, s->size });
	cfg.environment = { "HOME=/root", "PATH=/bin:/usr/bin:/usr/local/bin", "LANG=C", "LC_ALL=C", "GAMES_PATH=/games" };
	cfg.clock_hz = SPIKE1_CPU_HZ;
	if (nvram && nvram_size) cfg.nvram.assign(nvram, nvram + nvram_size);
	cfg.log = log_line;
	m->os = std::make_unique<spike1_linux>(*m->cpu, m->memory);
	g_machine = std::move(m); // before start(): a fault during it reports through g_machine
	std::string reason;
	if (!g_machine->os->start(cfg, reason)) {
		copy_text(reason, error, error_size);
		g_machine.reset();
		return 0;
	}
	return 1;
}

void spike1_pinmame_stop(void)
{
	g_native.reset();
	if (g_machine && p2k_active_config == &g_machine->config) p2k_active_config = nullptr;
	if (g_machine && device_t::s_machine == &g_machine->running) device_t::s_machine = nullptr;
	g_machine.reset();
}

int spike1_pinmame_running(char *reason, unsigned reason_size)
{
	const auto guard = native_guard();
	if (g_native) {
		std::string why;
		if (g_native->running(why)) return 1;
		copy_text(why, reason, reason_size);
		return 0;
	}
	if (!g_machine) { copy_text("not started", reason, reason_size); return 0; }
	if (g_machine->os->state() == spike1_linux::status::running) return 1;
	copy_text(g_machine->os->stop_reason(), reason, reason_size);
	return 0;
}

int spike1_pinmame_run(int cycles)
{
	if (g_native) {
		// The native program runs at its own pace, answered by the machine's own thread, which
		// starts here: after MACHINE_INIT has linked motors and provided keys and links, which the
		// held program must find. PinMAME paces itself with its throttle, as for any driver
		if (!g_native_started) { g_native_started = true; g_native->start_thread(); }
		return cycles;
	}
	if (g_machine && cycles > 0 && g_machine->os->state() == spike1_linux::status::running)
		g_machine->os->run(cycles);
	return cycles;
}

unsigned spike1_pinmame_nvram(unsigned char *dst, unsigned capacity)
{
	const auto guard = native_guard();
	if (!g_machine && !g_native) return 0;
	const std::vector<uint8_t> block = g_native ? g_native->nvram() : g_machine->os->nvram();
	if (dst && block.size() <= capacity) std::memcpy(dst, block.data(), block.size());
	return unsigned(block.size());
}

int spike1_pinmame_power_down(unsigned max_ms)
{
	if (g_native) return g_native->power_down(uint64_t(max_ms) * 1000000ull) ? 1 : 0;
	if (!g_machine || g_machine->os->state() != spike1_linux::status::running) return 0;
	return g_machine->os->power_down(uint64_t(max_ms) * 1000000ull, SPIKE1_CPU_HZ / 100) ? 1 : 0;
}

int spike1_pinmame_switch(unsigned index, int *number, int *closed_at_rest, const char **name)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d || index >= d->switches().size()) return 0;
	const auto &s = d->switches()[index];
	if (number) *number = s.number;
	if (closed_at_rest) *closed_at_rest = d->switch_closed(s.node, s.position);
	if (name) *name = s.name.c_str();
	return 1;
}

int spike1_pinmame_find_switch(const char *name)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	const spike1_devices::switch_info *s = d && name ? d->find_switch(name) : nullptr;
	return s ? s->number : -1;
}

void spike1_pinmame_set_switch(int number, int closed)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	if (!d) return;
	for (const auto &s : d->switches())
		if (s.number == number && d->switch_closed(s.node, s.position) != (closed != 0))
			d->set_switch(s.node, s.position, closed != 0, now_ns());
}

int spike1_pinmame_coil(unsigned index, int *number, const char **name)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d || index >= d->coils().size()) return 0;
	if (number) *number = d->coils()[index].number;
	if (name) *name = d->coils()[index].name.c_str();
	return 1;
}

int spike1_pinmame_coil_reflex_armed(int number)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d) return 0;
	for (const auto &c : d->coils())
		if (c.number == number) return d->reflex_armed(c.node, c.position) ? 1 : 0;
	return 0;
}

unsigned spike1_pinmame_coil_output(int number)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	if (!d) return 0;
	for (const auto &c : d->coils())
		if (c.number == number) return d->coil_output(c.node, c.position, now_ns());
	return 0;
}

unsigned spike1_pinmame_led_count(void)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	return d ? unsigned(d->leds().size()) : 0;
}

int spike1_pinmame_led(unsigned index, int *number, int *kind, const char **name)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d || index >= d->leds().size()) return 0;
	const auto &led = d->leds()[index];
	if (number) *number = led.number;
	if (kind) *kind = led.kind;
	if (name) *name = led.name.c_str();
	return 1;
}

int spike1_pinmame_motor(unsigned index, int *position, int *moving)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	int16_t p = 0;
	bool m = false;
	if (!d || !d->motor_at(index, p, m, now_ns())) return 0;
	if (position) *position = p;
	if (moving) *moving = m;
	return 1;
}

void spike1_pinmame_encoder_motor(unsigned node, unsigned motor, int low_stop, int high_stop, unsigned counts_per_s)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	if (d && node < 128 && motor < 8)
		d->link_encoder_motor(uint8_t(node), uint8_t(motor), int16_t(low_stop), int16_t(high_stop), uint16_t(counts_per_s > 65535 ? 65535 : counts_per_s));
}

int spike1_pinmame_stepper_home(unsigned node, unsigned stepper, int switch_number)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	return d && node < 128 && stepper <= 4 && switch_number >= 0 &&
		d->link_stepper_home(uint8_t(node), uint8_t(stepper), uint16_t(switch_number));
}

int spike1_pinmame_limit_motor(int forward_lamp, int backward_lamp, int home_switch, int away_switch, unsigned travel_ms)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	return d && forward_lamp >= 0 && backward_lamp >= 0 && home_switch >= 0 && away_switch >= 0 &&
		d->link_limit_motor(uint16_t(forward_lamp), uint16_t(backward_lamp), uint16_t(home_switch), uint16_t(away_switch), travel_ms);
}

unsigned spike1_pinmame_led_level(unsigned index)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d || index >= d->leds().size()) return 0;
	return d->led_level(d->leds()[index].node, d->leds()[index].position, now_ns());
}

unsigned spike1_pinmame_dmd(unsigned char *dots)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d) return 0;
	if (dots) std::memcpy(dots, d->dmd_frame(), SPIKE1_DMD_WIDTH * SPIKE1_DMD_HEIGHT);
	return unsigned(d->dmd_frame_count());
}

int spike1_pinmame_insert_present(void)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	return d && d->insert_present();
}

int spike1_pinmame_insert(unsigned short *rgb565, unsigned *backlight)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	const uint16_t *px = d ? d->insert_pixels(now_ns()) : nullptr;
	if (backlight) *backlight = d ? d->insert_backlight() : 0;
	if (!px) return 0;
	if (rgb565) std::memcpy(rgb565, px, SPIKE1_INSERT_WIDTH * SPIKE1_INSERT_HEIGHT * sizeof(uint16_t));
	return 1;
}

int spike1_pinmame_insert_frame(void)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	return d ? d->insert_frame_index(now_ns()) : -1;
}

int spike1_pinmame_lcd(unsigned short *rgb565)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	return d && rgb565 && d->lcd_picture(rgb565);
}

unsigned spike1_pinmame_rgb(unsigned short *rgb565)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	if (!d) return 0;
	if (rgb565) std::memcpy(rgb565, d->rgb_frame(), SPIKE1_RGB_WIDTH * SPIKE1_RGB_HEIGHT * sizeof(uint16_t));
	return unsigned(d->rgb_frame_count());
}

unsigned spike1_pinmame_alnum(unsigned char *levels)
{
	const spike1_devices *d = devices();
	if (!d) return 0;
	if (levels) std::memcpy(levels, d->alnum_frame(), SPIKE1_ALNUM_CHARS * SPIKE1_ALNUM_SEGMENTS);
	return unsigned(d->alnum_frame_count());
}

int spike1_pinmame_display_link(const char *target)
{
	const auto guard = native_guard();
	if (g_native) return target && g_native->add_link("/usr/local/spike/display.hex", target) ? 1 : 0;
	if (!g_machine || !g_machine->os || !target) return 0;
	g_machine->os->add_link("/usr/local/spike/display.hex", target);
	return 1;
}

int spike1_pinmame_video_key(const unsigned char *key)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	return d && key && d->provide_video_key(key);
}

int spike1_pinmame_needs_video_key(void)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	return d && d->needs_video_key();
}

unsigned spike1_pinmame_audio_rate(void)
{
	const auto guard = native_guard();
	const spike1_devices *d = devices();
	return d ? d->audio_rate() : 44100;
}

unsigned spike1_pinmame_audio(short *dst, unsigned frames)
{
	const auto guard = native_guard();
	spike1_devices *d = devices();
	return d && dst ? unsigned(d->audio_take(dst, frames)) : 0;
}

} // extern "C"

static_assert(SPIKE1_LED_MOTOR == spike1_devices::LED_KIND_MOTOR, "the LED class bits differ");
static_assert(SPIKE1_DMD_WIDTH == spike1_devices::DMD_WIDTH && SPIKE1_DMD_HEIGHT == spike1_devices::DMD_HEIGHT, "the DMD sizes differ");
static_assert(SPIKE1_INSERT_WIDTH == spike1_devices::INSERT_WIDTH && SPIKE1_INSERT_HEIGHT == spike1_devices::INSERT_HEIGHT, "the insert sizes differ");
static_assert(SPIKE1_RGB_WIDTH == spike1_devices::RGB_WIDTH && SPIKE1_RGB_HEIGHT == spike1_devices::RGB_HEIGHT, "the RGB matrix sizes differ");
static_assert(SPIKE1_ALNUM_CHARS == spike1_devices::ALNUM_CHARS && SPIKE1_ALNUM_SEGMENTS == spike1_devices::ALNUM_SEGMENTS, "the alphanumeric display sizes differ");
