#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct SectionInfo {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    uint64_t rawSize = 0;
    bool hasCharacteristics = false;
    uint32_t characteristics = 0;
};

struct ProgramHeaderInfo {
    std::string type;
    std::string flags;
    uint64_t offset = 0;
    uint64_t vaddr = 0;
    uint64_t fileSize = 0;
};

struct Check {
    std::string name;
    std::string status; // "pass", "fail" or "n/a"
    std::string detail;
};

struct Report {
    std::string file;
    std::string format; // "ELF" or "PE"
    int bits = 0;
    std::string architecture;
    std::string type;
    uint64_t entryPoint = 0;
    std::vector<SectionInfo> sections;
    std::vector<ProgramHeaderInfo> programHeaders;
    std::vector<std::string> libraries; // DT_NEEDED names or imported DLLs
    bool hasLoadConfig = false;
    std::vector<Check> checks;
};
