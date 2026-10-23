// license:BSD-3-Clause

// PinMAME Spike 1 subsystem - a set's folder made from Stern's .spk update package
//
// Stern ships its updates as .spk packages (Heavy Metal only as one). A set's ROMs are the files of
// the title's game folder, which a package holds uncompressed: so a .spk in a roms directory can
// stand in for the set, and the ROM loader asks for the set's folder to be made from it when the
// set is not there (src/common.c, rom_load). See spike1_public.h.
//
// The package, as scripts/spike1/Build-Spike1RomSet.ps1 reads it: 'SPKS', a CRC and a version,
// then groups, each 'SPK0' and its size: an index ('SIDX' and its size: the group's name in 16
// bytes, at 0x28 the file count, at 0x30 'STRS', its size and the path table, then per file
// 'FINF', the record's size, and the path's offset, the size, the data offset, the stored size and
// the mode), then 'SDAT', a size and the files' bytes. The game folder is the group holding
// <name>/game; a title's LCD clips sit in <name>/video/, and a set holds them under their own names.
//
// The group a set comes from is the one whose game program has the set's CRC. Its files are
// written into <set>.partial beside the package, each checked against the set's size and CRC,
// and the folder takes the set's name only once every file is in: an interrupted run leaves no set
// that looks whole.

#include "spike1_public.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

uint32_t crc32_update(uint32_t crc, const uint8_t *p, size_t n)
{
	static uint32_t table[256];
	static bool ready = false;
	if (!ready) {
		for (uint32_t i = 0; i < 256; i++) {
			uint32_t c = i;
			for (int k = 0; k < 8; k++) c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
			table[i] = c;
		}
		ready = true;
	}
	crc = ~crc;
	for (size_t i = 0; i < n; i++) crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
	return ~crc;
}

uint32_t u32(const uint8_t *p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }

struct entry { uint64_t offset = 0, size = 0; };      // a file of a group: where its bytes are in the package
struct group { std::string name; std::map<std::string, entry> files; }; // files by their name in the set

// The package's groups; false when it is not a package this reader knows
bool read_groups(std::ifstream &in, uint64_t length, std::vector<group> &out)
{
	uint8_t head[12];
	if (!in.read(reinterpret_cast<char *>(head), 12) || std::memcmp(head, "SPKS", 4) != 0) return false;
	for (uint64_t pos = 12; pos + 16 <= length; ) {
		uint8_t g[16];
		in.seekg(std::streamoff(pos));
		if (!in.read(reinterpret_cast<char *>(g), 16) || std::memcmp(g, "SPK0", 4) != 0 || std::memcmp(g + 8, "SIDX", 4) != 0) break;
		const uint64_t start = pos + 8, next = start + u32(g + 4);
		std::vector<uint8_t> sidx(u32(g + 12));
		if (sidx.size() < 0x38 || !in.read(reinterpret_cast<char *>(sidx.data()), std::streamsize(sidx.size()))) return false;
		if (std::memcmp(sidx.data() + 0x30, "STRS", 4) != 0) return false;
		group grp;
		grp.name.assign(reinterpret_cast<const char *>(sidx.data()), strnlen(reinterpret_cast<const char *>(sidx.data()), 16));
		const uint32_t count = u32(sidx.data() + 0x28), strs_at = 0x38, strs_size = u32(sidx.data() + 0x34);
		const uint64_t data = start + 8 + sidx.size() + 8; // past 'SDAT' and its size
		size_t fo = strs_at + strs_size;
		for (uint32_t i = 0; i < count; i++) {
			if (fo + 24 > sidx.size() || std::memcmp(sidx.data() + fo, "FINF", 4) != 0) return false;
			const uint8_t *f = sidx.data() + fo + 8;
			const size_t name_at = strs_at + u32(f);
			const uint64_t size = u32(f + 4), offset = u32(f + 8), stored = u32(f + 12);
			fo += 8 + u32(sidx.data() + fo + 4);
			if (name_at >= sidx.size()) return false;
			const std::string path(reinterpret_cast<const char *>(sidx.data() + name_at), strnlen(reinterpret_cast<const char *>(sidx.data() + name_at), sidx.size() - name_at));
			if (path.compare(0, grp.name.size() + 1, grp.name + "/") != 0 || stored != size) continue; // not the group's own, or compressed
			std::string rel = path.substr(grp.name.size() + 1);
			if (rel.compare(0, 6, "video/") == 0) rel = rel.substr(6);
			if (rel.find('/') != std::string::npos) continue;
			grp.files[rel] = { data + offset, size };
		}
		out.push_back(std::move(grp));
		if (next <= pos) break;
		pos = next;
	}
	return true;
}

// The CRC of len bytes at offset; false when the package ends early
bool crc_of(std::ifstream &in, uint64_t offset, uint64_t len, uint32_t &crc, std::ofstream *copy = nullptr)
{
	std::vector<uint8_t> buf(1 << 20);
	in.seekg(std::streamoff(offset));
	crc = 0;
	while (len) {
		const size_t n = size_t(std::min<uint64_t>(len, buf.size()));
		if (!in.read(reinterpret_cast<char *>(buf.data()), std::streamsize(n))) return false;
		crc = crc32_update(crc, buf.data(), n);
		if (copy && !copy->write(reinterpret_cast<const char *>(buf.data()), std::streamsize(n))) return false;
		len -= n;
	}
	return true;
}

bool is_spk(const fs::path &p)
{
	std::string ext = p.extension().string();
	for (auto &c : ext) c = char(std::tolower(uint8_t(c)));
	return ext == ".spk";
}

} // namespace

extern "C" int spike1_spk_make_set(const char *roms_dir, const char *set, const spike1_set_file *files, unsigned count,
                                   void (*progress)(const char *message, void *context), void *context, char *error, unsigned error_size)
{
	auto fail = [&](const std::string &why) { if (error && error_size) std::snprintf(error, error_size, "%s", why.c_str()); return 0; };
	auto say = [&](const std::string &what) { if (progress) progress(what.c_str(), context); };
	if (error && error_size) *error = 0;
	const spike1_set_file *game = nullptr;
	for (unsigned i = 0; i < count; i++) if (files[i].name && std::strcmp(files[i].name, "game") == 0) game = &files[i];
	if (!roms_dir || !set || !game) return 0;

	std::error_code ec;
	std::vector<fs::path> packages;
	for (const auto &e : fs::directory_iterator(fs::u8path(roms_dir), ec))
		if (e.is_regular_file(ec) && is_spk(e.path())) packages.push_back(e.path());
	for (const fs::path &pkg : packages) {
		std::ifstream in(pkg, std::ios::binary);
		std::vector<group> groups;
		if (!in || !read_groups(in, fs::file_size(pkg, ec), groups)) continue;
		for (const group &g : groups) {
			// the group whose game program is the set's
			const auto prog = g.files.find("game");
			uint32_t crc = 0;
			if (prog == g.files.end() || prog->second.size != game->size || !crc_of(in, prog->second.offset, prog->second.size, crc) || crc != game->crc)
				continue;
			for (unsigned i = 0; i < count; i++)
				if (!g.files.count(files[i].name) || g.files.at(files[i].name).size != files[i].size)
					return fail(pkg.filename().u8string() + " has " + g.name + "'s game program for " + set + " but not its " + files[i].name);

			const fs::path dir = fs::u8path(roms_dir), partial = dir / (std::string(set) + ".partial"), final_dir = dir / set;
			say("making " + std::string(set) + " from " + pkg.filename().u8string() + " (" + g.name + ")");
			fs::remove_all(partial, ec);
			if (!fs::create_directories(partial, ec)) return fail("cannot create " + partial.u8string() + ": " + ec.message());
			for (unsigned i = 0; i < count; i++) {
				const entry &src = g.files.at(files[i].name);
				say(std::string("extracting ") + files[i].name);
				std::ofstream out(partial / files[i].name, std::ios::binary | std::ios::trunc);
				uint32_t c = 0;
				if (!out || !crc_of(in, src.offset, src.size, c, &out) || !out.flush()) {
					out.close();
					fs::remove_all(partial, ec);
					return fail(std::string("cannot write ") + files[i].name + " into " + partial.u8string());
				}
				out.close();
				if (c != files[i].crc) {
					fs::remove_all(partial, ec);
					char why[160];
					std::snprintf(why, sizeof(why), "%s in %s has CRC %08x, the set wants %08x", files[i].name, pkg.filename().u8string().c_str(), c, files[i].crc);
					return fail(why);
				}
			}
			fs::rename(partial, final_dir, ec);
			if (ec) {
				const std::string why = ec.message();
				fs::remove_all(partial, ec);
				return fail("cannot rename the set's folder into place: " + why);
			}
			say("made " + final_dir.u8string());
			return 1;
		}
	}
	return 0;
}
