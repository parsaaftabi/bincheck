#include "elf.h"

#include <string>
#include <vector>

namespace {

constexpr uint16_t kTypeNone = 0;
constexpr uint16_t kTypeRel = 1;
constexpr uint16_t kTypeExec = 2;
constexpr uint16_t kTypeDyn = 3;
constexpr uint16_t kTypeCore = 4;

constexpr uint32_t kPtNull = 0;
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtDynamic = 2;
constexpr uint32_t kPtInterp = 3;
constexpr uint32_t kPtNote = 4;
constexpr uint32_t kPtShlib = 5;
constexpr uint32_t kPtPhdr = 6;
constexpr uint32_t kPtTls = 7;
constexpr uint32_t kPtGnuEhFrame = 0x6474e550;
constexpr uint32_t kPtGnuStack = 0x6474e551;
constexpr uint32_t kPtGnuRelro = 0x6474e552;
constexpr uint32_t kPtGnuProperty = 0x6474e553;

constexpr uint32_t kPfX = 1;
constexpr uint32_t kPfW = 2;
constexpr uint32_t kPfR = 4;

constexpr uint32_t kShtDynSym = 11;
constexpr uint32_t kShtDynamic = 6;

constexpr int64_t kDtNull = 0;
constexpr int64_t kDtNeeded = 1;
constexpr int64_t kDtStrTab = 5;
constexpr int64_t kDtStrSz = 10;
constexpr int64_t kDtBindNow = 24;
constexpr int64_t kDtFlags = 30;
constexpr int64_t kDtFlags1 = 0x6ffffffb;
constexpr uint64_t kDfBindNow = 0x8;
constexpr uint64_t kDf1Now = 0x1;

std::string machineName(uint16_t machine) {
    switch (machine) {
    case 3: return "x86";
    case 8: return "MIPS";
    case 20: return "PowerPC";
    case 40: return "ARM";
    case 62: return "x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    default: return "unknown (" + std::to_string(machine) + ")";
    }
}

std::string typeName(uint16_t type) {
    switch (type) {
    case kTypeNone: return "ET_NONE";
    case kTypeRel: return "ET_REL";
    case kTypeExec: return "ET_EXEC";
    case kTypeDyn: return "ET_DYN";
    case kTypeCore: return "ET_CORE";
    default: return "ET_" + std::to_string(type);
    }
}

std::string segmentTypeName(uint32_t type) {
    switch (type) {
    case kPtNull: return "PT_NULL";
    case kPtLoad: return "PT_LOAD";
    case kPtDynamic: return "PT_DYNAMIC";
    case kPtInterp: return "PT_INTERP";
    case kPtNote: return "PT_NOTE";
    case kPtShlib: return "PT_SHLIB";
    case kPtPhdr: return "PT_PHDR";
    case kPtTls: return "PT_TLS";
    case kPtGnuEhFrame: return "PT_GNU_EH_FRAME";
    case kPtGnuStack: return "PT_GNU_STACK";
    case kPtGnuRelro: return "PT_GNU_RELRO";
    case kPtGnuProperty: return "PT_GNU_PROPERTY";
    default: {
        const char* digits = "0123456789abcdef";
        std::string out = "PT_0x";
        for (int shift = 28; shift >= 0; shift -= 4) {
            out.push_back(digits[(type >> shift) & 0xf]);
        }
        return out;
    }
    }
}

std::string segmentFlags(uint32_t flags) {
    std::string out;
    out.push_back(flags & kPfR ? 'R' : '-');
    out.push_back(flags & kPfW ? 'W' : '-');
    out.push_back(flags & kPfX ? 'X' : '-');
    return out;
}

struct Segment {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t offset = 0;
    uint64_t vaddr = 0;
    uint64_t fileSize = 0;
    uint64_t memSize = 0;
};

struct Section {
    uint32_t nameOffset = 0;
    uint32_t type = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t addr = 0;
    uint32_t link = 0;
    uint64_t entrySize = 0;
    std::string name;
};

struct DynamicEntry {
    int64_t tag = 0;
    uint64_t value = 0;
};

} // namespace

Report parseElf(const Reader& r, const std::string& fileName) {
    if (r.size() < 16) {
        throw ParseError("file too small for an ELF header");
    }
    if (r.u8(0) != 0x7f || r.u8(1) != 'E' || r.u8(2) != 'L' || r.u8(3) != 'F') {
        throw ParseError("bad ELF magic");
    }
    const uint8_t elfClass = r.u8(4);
    if (elfClass != 1 && elfClass != 2) {
        throw ParseError("bad ELF class");
    }
    const bool is64 = elfClass == 2;
    if (r.u8(5) != 1) {
        throw ParseError("only little-endian ELF files are supported");
    }

    Report rep;
    rep.file = fileName;
    rep.format = "ELF";
    rep.bits = is64 ? 64 : 32;

    const uint16_t type = r.u16(16);
    const uint16_t machine = r.u16(18);
    rep.architecture = machineName(machine);
    rep.type = typeName(type);

    uint64_t phoff = 0;
    uint64_t shoff = 0;
    uint64_t phEntrySize = 0;
    uint64_t shEntrySize = 0;
    uint64_t phCountRaw = 0;
    uint64_t shCountRaw = 0;
    uint64_t shStrIndexRaw = 0;
    if (is64) {
        rep.entryPoint = r.u64(24);
        phoff = r.u64(32);
        shoff = r.u64(40);
        phEntrySize = r.u16(54);
        phCountRaw = r.u16(56);
        shEntrySize = r.u16(58);
        shCountRaw = r.u16(60);
        shStrIndexRaw = r.u16(62);
    } else {
        rep.entryPoint = r.u32(24);
        phoff = r.u32(28);
        shoff = r.u32(32);
        phEntrySize = r.u16(42);
        phCountRaw = r.u16(44);
        shEntrySize = r.u16(46);
        shCountRaw = r.u16(48);
        shStrIndexRaw = r.u16(50);
    }

    const uint64_t wantPhSize = is64 ? 56 : 32;
    const uint64_t wantShSize = is64 ? 64 : 40;
    if (phCountRaw > 0 && phEntrySize != wantPhSize) {
        throw ParseError("unsupported program header entry size");
    }
    if (shCountRaw > 0 && shEntrySize != wantShSize && shEntrySize != 0) {
        throw ParseError("unsupported section header entry size");
    }

    auto readSegment = [&](uint64_t index) {
        Segment seg;
        const uint64_t off = phoff + index * phEntrySize;
        if (is64) {
            seg.type = r.u32(off);
            seg.flags = r.u32(off + 4);
            seg.offset = r.u64(off + 8);
            seg.vaddr = r.u64(off + 16);
            seg.fileSize = r.u64(off + 32);
            seg.memSize = r.u64(off + 40);
        } else {
            seg.type = r.u32(off);
            seg.offset = r.u32(off + 4);
            seg.vaddr = r.u32(off + 8);
            seg.fileSize = r.u32(off + 16);
            seg.memSize = r.u32(off + 20);
            seg.flags = r.u32(off + 24);
        }
        return seg;
    };

    auto readSection = [&](uint64_t index) {
        Section sec;
        const uint64_t off = shoff + index * shEntrySize;
        if (is64) {
            sec.nameOffset = r.u32(off);
            sec.type = r.u32(off + 4);
            sec.addr = r.u64(off + 16);
            sec.offset = r.u64(off + 24);
            sec.size = r.u64(off + 32);
            sec.link = r.u32(off + 40);
            sec.entrySize = r.u64(off + 56);
        } else {
            sec.nameOffset = r.u32(off);
            sec.type = r.u32(off + 4);
            sec.addr = r.u32(off + 12);
            sec.offset = r.u32(off + 16);
            sec.size = r.u32(off + 20);
            sec.link = r.u32(off + 24);
            sec.entrySize = r.u32(off + 36);
        }
        return sec;
    };

    // Extended counts live in section header 0 when the raw fields overflow.
    uint64_t shCount = shCountRaw;
    uint64_t shStrIndex = shStrIndexRaw;
    uint64_t phCount = phCountRaw;
    if (shoff != 0 && shEntrySize != 0) {
        if (shCount == 0 || shStrIndex == 0xffff || phCount == 0xffff) {
            const Section zero = readSection(0);
            if (shCount == 0) {
                shCount = zero.size;
            }
            if (shStrIndex == 0xffff) {
                shStrIndex = zero.link;
            }
            if (phCount == 0xffff) {
                const uint64_t off = shoff;
                phCount = is64 ? r.u32(off + 44) : r.u32(off + 28);
            }
        }
    }
    if (phoff == 0) {
        phCount = 0;
    }
    if (shoff == 0) {
        shCount = 0;
    }
    if (shCount > 0x10000 || phCount > 0x10000) {
        throw ParseError("unreasonable header count");
    }

    std::vector<Segment> segments;
    for (uint64_t i = 0; i < phCount; ++i) {
        segments.push_back(readSegment(i));
    }
    for (const Segment& seg : segments) {
        ProgramHeaderInfo info;
        info.type = segmentTypeName(seg.type);
        info.flags = segmentFlags(seg.flags);
        info.offset = seg.offset;
        info.vaddr = seg.vaddr;
        info.fileSize = seg.fileSize;
        rep.programHeaders.push_back(info);
    }

    std::vector<Section> sections;
    for (uint64_t i = 0; i < shCount; ++i) {
        sections.push_back(readSection(i));
    }
    if (shStrIndex < sections.size()) {
        const Section& strTab = sections[static_cast<size_t>(shStrIndex)];
        const uint64_t limit = strTab.offset + strTab.size;
        for (Section& sec : sections) {
            if (sec.nameOffset == 0) {
                sec.name = "";
            } else {
                sec.name = r.cstr(strTab.offset + sec.nameOffset, limit);
            }
        }
    }
    for (const Section& sec : sections) {
        SectionInfo info;
        info.name = sec.name;
        info.address = sec.addr;
        info.size = sec.size;
        rep.sections.push_back(info);
    }

    // Dynamic entries come from the PT_DYNAMIC segment. The .dynamic
    // section works as a fallback when no such segment exists.
    std::vector<DynamicEntry> dynamic;
    auto readDynamicAt = [&](uint64_t offset, uint64_t size) {
        const uint64_t entrySize = is64 ? 16 : 8;
        const uint64_t count = size / entrySize;
        if (count > 0x100000) {
            throw ParseError("unreasonable dynamic entry count");
        }
        for (uint64_t i = 0; i < count; ++i) {
            DynamicEntry entry;
            const uint64_t off = offset + i * entrySize;
            if (is64) {
                entry.tag = static_cast<int64_t>(r.u64(off));
                entry.value = r.u64(off + 8);
            } else {
                entry.tag = static_cast<int32_t>(r.u32(off));
                entry.value = r.u32(off + 4);
            }
            dynamic.push_back(entry);
            if (entry.tag == kDtNull) {
                break;
            }
        }
    };
    bool haveDynamic = false;
    for (const Segment& seg : segments) {
        if (seg.type == kPtDynamic) {
            readDynamicAt(seg.offset, seg.fileSize);
            haveDynamic = true;
            break;
        }
    }
    if (!haveDynamic) {
        for (const Section& sec : sections) {
            if (sec.type == kShtDynamic) {
                readDynamicAt(sec.offset, sec.size);
                break;
            }
        }
    }

    uint64_t strTabAddr = 0;
    uint64_t strTabSize = 0;
    bool bindNow = false;
    std::vector<uint64_t> neededOffsets;
    for (const DynamicEntry& entry : dynamic) {
        if (entry.tag == kDtNeeded) {
            neededOffsets.push_back(entry.value);
        } else if (entry.tag == kDtStrTab) {
            strTabAddr = entry.value;
        } else if (entry.tag == kDtStrSz) {
            strTabSize = entry.value;
        } else if (entry.tag == kDtBindNow) {
            bindNow = true;
        } else if (entry.tag == kDtFlags && (entry.value & kDfBindNow)) {
            bindNow = true;
        } else if (entry.tag == kDtFlags1 && (entry.value & kDf1Now)) {
            bindNow = true;
        }
    }

    auto vaddrToOffset = [&](uint64_t vaddr) -> uint64_t {
        for (const Segment& seg : segments) {
            if (seg.type != kPtLoad) {
                continue;
            }
            if (vaddr >= seg.vaddr && vaddr - seg.vaddr < seg.fileSize) {
                return seg.offset + (vaddr - seg.vaddr);
            }
        }
        throw ParseError("virtual address has no file mapping");
    };

    if (!neededOffsets.empty()) {
        uint64_t strTabOff = 0;
        bool haveStrTab = false;
        if (strTabAddr != 0) {
            strTabOff = vaddrToOffset(strTabAddr);
            haveStrTab = true;
        } else {
            for (const Section& sec : sections) {
                if (sec.name == ".dynstr") {
                    strTabOff = sec.offset;
                    if (strTabSize == 0) {
                        strTabSize = sec.size;
                    }
                    haveStrTab = true;
                    break;
                }
            }
        }
        if (!haveStrTab) {
            throw ParseError("dynamic string table not found");
        }
        const uint64_t limit = strTabSize != 0 ? strTabOff + strTabSize : r.size();
        for (uint64_t nameOff : neededOffsets) {
            rep.libraries.push_back(r.cstr(strTabOff + nameOff, limit));
        }
    }

    // Stack canary: __stack_chk_fail must appear in the dynamic symbols.
    bool haveDynSym = false;
    bool canary = false;
    for (const Section& sec : sections) {
        if (sec.type != kShtDynSym) {
            continue;
        }
        haveDynSym = true;
        if (sec.link >= sections.size() || sec.entrySize == 0) {
            continue;
        }
        const Section& strs = sections[sec.link];
        const uint64_t symSize = is64 ? 24 : 16;
        if (sec.entrySize < symSize) {
            continue;
        }
        const uint64_t count = sec.size / sec.entrySize;
        if (count > 0x1000000) {
            throw ParseError("unreasonable symbol count");
        }
        for (uint64_t i = 0; i < count; ++i) {
            const uint64_t off = sec.offset + i * sec.entrySize;
            const uint32_t nameOff = r.u32(off);
            if (nameOff == 0) {
                continue;
            }
            const std::string name =
                r.cstr(strs.offset + nameOff, strs.offset + strs.size);
            if (name == "__stack_chk_fail") {
                canary = true;
                break;
            }
        }
        if (canary) {
            break;
        }
    }

    // Hardening checks.
    Check pie;
    pie.name = "pie";
    if (type == kTypeDyn) {
        pie.status = "pass";
        pie.detail = "type is ET_DYN";
    } else if (type == kTypeExec) {
        pie.status = "fail";
        pie.detail = "type is ET_EXEC, a fixed load address";
    } else {
        pie.status = "n/a";
        pie.detail = "type is " + typeName(type);
    }
    rep.checks.push_back(pie);

    bool haveGnuStack = false;
    bool stackExec = false;
    bool haveRelro = false;
    for (const Segment& seg : segments) {
        if (seg.type == kPtGnuStack) {
            haveGnuStack = true;
            stackExec = (seg.flags & kPfX) != 0;
        }
        if (seg.type == kPtGnuRelro) {
            haveRelro = true;
        }
    }

    Check nx;
    nx.name = "nx-stack";
    if (!haveGnuStack) {
        nx.status = "fail";
        nx.detail = "no PT_GNU_STACK segment, stack may be executable";
    } else if (stackExec) {
        nx.status = "fail";
        nx.detail = "PT_GNU_STACK has the execute flag";
    } else {
        nx.status = "pass";
        nx.detail = "PT_GNU_STACK lacks the execute flag";
    }
    rep.checks.push_back(nx);

    Check relro;
    relro.name = "relro";
    if (haveRelro) {
        relro.status = "pass";
        relro.detail = bindNow ? "PT_GNU_RELRO present, BIND_NOW set"
                                : "PT_GNU_RELRO present";
    } else {
        relro.status = "fail";
        relro.detail = "no PT_GNU_RELRO segment";
    }
    rep.checks.push_back(relro);

    Check fullRelro;
    fullRelro.name = "full-relro";
    if (!haveRelro) {
        fullRelro.status = "n/a";
        fullRelro.detail = "no PT_GNU_RELRO segment";
    } else if (bindNow) {
        fullRelro.status = "pass";
        fullRelro.detail = "BIND_NOW set, relocations resolve at load time";
    } else {
        fullRelro.status = "fail";
        fullRelro.detail = "BIND_NOW not set, RELRO stays writable until first use";
    }
    rep.checks.push_back(fullRelro);

    Check canaryCheck;
    canaryCheck.name = "stack-canary";
    if (!haveDynSym) {
        canaryCheck.status = "n/a";
        canaryCheck.detail = "no dynamic symbol table";
    } else if (canary) {
        canaryCheck.status = "pass";
        canaryCheck.detail = "__stack_chk_fail found in dynamic symbols";
    } else {
        canaryCheck.status = "fail";
        canaryCheck.detail = "__stack_chk_fail not in dynamic symbols";
    }
    rep.checks.push_back(canaryCheck);

    return rep;
}
