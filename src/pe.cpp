#include "pe.h"

#include <string>
#include <vector>

namespace {

constexpr uint16_t kDllDynamicBase = 0x0040;
constexpr uint16_t kDllHighEntropyVa = 0x0020;
constexpr uint16_t kDllNxCompat = 0x0100;
constexpr uint16_t kDllGuardCf = 0x4000;

constexpr size_t kDirImport = 1;
constexpr size_t kDirLoadConfig = 10;

std::string machineName(uint16_t machine) {
    switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x86-64";
    case 0x01c0: return "ARM";
    case 0xaa64: return "ARM64";
    case 0x0200: return "IA-64";
    default: return "unknown (" + std::to_string(machine) + ")";
    }
}

struct PeSection {
    std::string name;
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;
    uint32_t rawSize = 0;
    uint32_t rawOffset = 0;
    uint32_t characteristics = 0;
};

} // namespace

Report parsePe(const Reader& r, const std::string& fileName) {
    if (r.size() < 64) {
        throw ParseError("file too small for a DOS header");
    }
    if (r.u8(0) != 'M' || r.u8(1) != 'Z') {
        throw ParseError("bad DOS magic");
    }
    const uint32_t peOff = r.u32(0x3c);
    if (peOff > r.size() || r.size() - peOff < 24) {
        throw ParseError("PE header offset out of range");
    }
    if (r.u8(peOff) != 'P' || r.u8(peOff + 1) != 'E' || r.u8(peOff + 2) != 0 ||
        r.u8(peOff + 3) != 0) {
        throw ParseError("bad PE signature");
    }

    const uint64_t coff = peOff + 4;
    const uint16_t machine = r.u16(coff);
    const uint16_t sectionCount = r.u16(coff + 2);
    const uint16_t optSize = r.u16(coff + 16);
    if (sectionCount > 96) {
        throw ParseError("unreasonable section count");
    }
    const uint64_t opt = coff + 20;
    if (optSize < 96) {
        throw ParseError("optional header too small");
    }
    const uint16_t magic = r.u16(opt);
    bool is64 = false;
    if (magic == 0x20b) {
        is64 = true;
    } else if (magic != 0x10b) {
        throw ParseError("unknown optional header magic");
    }

    Report rep;
    rep.file = fileName;
    rep.format = "PE";
    rep.bits = is64 ? 64 : 32;
    rep.architecture = machineName(machine);
    rep.type = is64 ? "PE32+" : "PE32";
    rep.entryPoint = r.u32(opt + 16);

    const uint32_t sizeOfHeaders = r.u32(opt + 60);
    const uint16_t dllChars = r.u16(opt + 70);
    const uint64_t dirBase = opt + (is64 ? 112 : 96);
    const uint32_t dirCount = r.u32(opt + (is64 ? 108 : 92));

    auto directory = [&](size_t index, uint32_t& rva, uint32_t& size) {
        rva = 0;
        size = 0;
        if (index >= dirCount) {
            return;
        }
        const uint64_t off = dirBase + index * 8;
        if (off + 8 > opt + optSize) {
            return;
        }
        rva = r.u32(off);
        size = r.u32(off + 4);
    };

    const uint64_t sectionTable = opt + optSize;
    std::vector<PeSection> sections;
    for (uint16_t i = 0; i < sectionCount; ++i) {
        const uint64_t off = sectionTable + static_cast<uint64_t>(i) * 40;
        PeSection sec;
        std::string name;
        for (int j = 0; j < 8; ++j) {
            const char c = static_cast<char>(r.u8(off + j));
            if (c == '\0') {
                break;
            }
            name.push_back(c);
        }
        sec.name = name;
        sec.virtualSize = r.u32(off + 8);
        sec.virtualAddress = r.u32(off + 12);
        sec.rawSize = r.u32(off + 16);
        sec.rawOffset = r.u32(off + 20);
        sec.characteristics = r.u32(off + 36);
        sections.push_back(sec);

        SectionInfo info;
        info.name = sec.name;
        info.address = sec.virtualAddress;
        info.size = sec.virtualSize;
        info.rawSize = sec.rawSize;
        info.hasCharacteristics = true;
        info.characteristics = sec.characteristics;
        rep.sections.push_back(info);
    }

    auto rvaToOffset = [&](uint32_t rva) -> uint64_t {
        if (rva < sizeOfHeaders) {
            return rva;
        }
        for (const PeSection& sec : sections) {
            const uint32_t span = sec.virtualSize > sec.rawSize
                                      ? sec.virtualSize
                                      : sec.rawSize;
            if (span == 0) {
                continue;
            }
            if (rva >= sec.virtualAddress && rva - sec.virtualAddress < span) {
                const uint64_t delta = rva - sec.virtualAddress;
                if (delta >= sec.rawSize) {
                    throw ParseError("RVA lands in zero-filled section tail");
                }
                return static_cast<uint64_t>(sec.rawOffset) + delta;
            }
        }
        throw ParseError("RVA has no file mapping");
    };

    uint32_t importRva = 0;
    uint32_t importSize = 0;
    directory(kDirImport, importRva, importSize);
    if (importRva != 0) {
        const uint64_t base = rvaToOffset(importRva);
        for (uint64_t i = 0; i < 4096; ++i) {
            const uint64_t off = base + i * 20;
            const uint32_t origThunk = r.u32(off);
            const uint32_t nameRva = r.u32(off + 12);
            const uint32_t firstThunk = r.u32(off + 16);
            const uint32_t timeStamp = r.u32(off + 4);
            if (origThunk == 0 && nameRva == 0 && firstThunk == 0 &&
                timeStamp == 0) {
                break;
            }
            if (nameRva == 0) {
                continue;
            }
            const uint64_t nameOff = rvaToOffset(nameRva);
            rep.libraries.push_back(r.cstr(nameOff, r.size()));
        }
    }

    uint32_t loadConfigRva = 0;
    uint32_t loadConfigSize = 0;
    directory(kDirLoadConfig, loadConfigRva, loadConfigSize);
    rep.hasLoadConfig = loadConfigRva != 0 && loadConfigSize != 0;
    if (rep.hasLoadConfig) {
        // Touch the offset so a bogus directory is reported, not hidden.
        (void)rvaToOffset(loadConfigRva);
    }

    auto addCheck = [&](const char* name, uint16_t flag, const char* onText,
                        const char* offText) {
        Check check;
        check.name = name;
        if (dllChars & flag) {
            check.status = "pass";
            check.detail = onText;
        } else {
            check.status = "fail";
            check.detail = offText;
        }
        rep.checks.push_back(check);
    };

    addCheck("aslr", kDllDynamicBase,
             "DYNAMIC_BASE set, image can load at a random base",
             "DYNAMIC_BASE clear, image loads at its fixed base");
    addCheck("high-entropy-aslr", kDllHighEntropyVa,
             "HIGH_ENTROPY_VA set, 64-bit address space is used for ASLR",
             "HIGH_ENTROPY_VA clear, ASLR uses a smaller range");
    addCheck("dep-nx", kDllNxCompat,
             "NX_COMPAT set, data pages stay non-executable",
             "NX_COMPAT clear, the loader may allow executable data pages");
    addCheck("cfg", kDllGuardCf,
             "GUARD_CF set, Control Flow Guard metadata is present",
             "GUARD_CF clear, no Control Flow Guard");

    return rep;
}
