#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "elf.h"
#include "pe.h"
#include "reader.h"
#include "report.h"

namespace {

std::string hexNum(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(value));
    return buf;
}

std::string hexPad(uint32_t value) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08x", value);
    return buf;
}

std::string jsonEscape(const std::string& text) {
    std::string out;
    for (char ch : text) {
        const unsigned char c = static_cast<unsigned char>(ch);
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    return out;
}

void printJson(const Report& rep) {
    std::cout << "{\n";
    std::cout << "  \"file\": \"" << jsonEscape(rep.file) << "\",\n";
    std::cout << "  \"format\": \"" << rep.format << "\",\n";
    std::cout << "  \"bits\": " << rep.bits << ",\n";
    std::cout << "  \"architecture\": \"" << jsonEscape(rep.architecture)
              << "\",\n";
    std::cout << "  \"type\": \"" << jsonEscape(rep.type) << "\",\n";
    std::cout << "  \"entry_point\": \"" << hexNum(rep.entryPoint) << "\",\n";
    std::cout << "  \"sections\": [";
    for (size_t i = 0; i < rep.sections.size(); ++i) {
        const SectionInfo& sec = rep.sections[i];
        std::cout << (i ? ", " : "") << "{\"name\": \""
                  << jsonEscape(sec.name) << "\", \"address\": \""
                  << hexNum(sec.address) << "\", \"size\": " << sec.size;
        if (sec.hasCharacteristics) {
            std::cout << ", \"characteristics\": \""
                      << hexPad(sec.characteristics) << "\"";
        }
        std::cout << "}";
    }
    std::cout << "],\n";
    if (rep.format == "ELF") {
        std::cout << "  \"program_headers\": [";
        for (size_t i = 0; i < rep.programHeaders.size(); ++i) {
            const ProgramHeaderInfo& ph = rep.programHeaders[i];
            std::cout << (i ? ", " : "") << "{\"type\": \"" << ph.type
                      << "\", \"flags\": \"" << ph.flags << "\", \"offset\": "
                      << ph.offset << ", \"virtual_address\": \""
                      << hexNum(ph.vaddr) << "\", \"file_size\": "
                      << ph.fileSize << "}";
        }
        std::cout << "],\n";
        std::cout << "  \"needed\": [";
        for (size_t i = 0; i < rep.libraries.size(); ++i) {
            std::cout << (i ? ", " : "") << "\""
                      << jsonEscape(rep.libraries[i]) << "\"";
        }
        std::cout << "],\n";
    } else {
        std::cout << "  \"imports\": [";
        for (size_t i = 0; i < rep.libraries.size(); ++i) {
            std::cout << (i ? ", " : "") << "\""
                      << jsonEscape(rep.libraries[i]) << "\"";
        }
        std::cout << "],\n";
        std::cout << "  \"load_config\": "
                  << (rep.hasLoadConfig ? "true" : "false") << ",\n";
    }
    std::cout << "  \"hardening\": [";
    for (size_t i = 0; i < rep.checks.size(); ++i) {
        const Check& check = rep.checks[i];
        std::cout << (i ? ", " : "") << "{\"name\": \"" << check.name
                  << "\", \"status\": \"" << check.status << "\", \"detail\": \""
                  << jsonEscape(check.detail) << "\"}";
    }
    std::cout << "]\n";
    std::cout << "}\n";
}

void printHuman(const Report& rep) {
    std::cout << "File: " << rep.file << "\n";
    std::cout << "Format: " << rep.format << " " << rep.bits << "-bit ("
              << rep.type << ")\n";
    std::cout << "Architecture: " << rep.architecture << "\n";
    std::cout << "Entry point: " << hexNum(rep.entryPoint) << "\n";

    std::cout << "\nSections (" << rep.sections.size() << "):\n";
    for (const SectionInfo& sec : rep.sections) {
        std::cout << "  " << (sec.name.empty() ? "(unnamed)" : sec.name)
                  << "  size " << sec.size << "  at " << hexNum(sec.address);
        if (sec.hasCharacteristics) {
            std::cout << "  characteristics " << hexPad(sec.characteristics);
        }
        std::cout << "\n";
    }

    if (rep.format == "ELF" && !rep.programHeaders.empty()) {
        std::cout << "\nProgram headers (" << rep.programHeaders.size()
                  << "):\n";
        for (const ProgramHeaderInfo& ph : rep.programHeaders) {
            std::cout << "  " << ph.type << "  flags " << ph.flags
                      << "  file size " << ph.fileSize << "  at "
                      << hexNum(ph.vaddr) << "\n";
        }
    }

    if (rep.format == "ELF") {
        std::cout << "\nNeeded libraries (" << rep.libraries.size() << "):\n";
    } else {
        std::cout << "\nImported libraries (" << rep.libraries.size()
                  << "):\n";
    }
    for (const std::string& lib : rep.libraries) {
        std::cout << "  " << lib << "\n";
    }
    if (rep.format == "PE") {
        std::cout << "\nLoad config directory: "
                  << (rep.hasLoadConfig ? "present" : "absent") << "\n";
    }

    std::cout << "\nHardening:\n";
    for (const Check& check : rep.checks) {
        std::string status = check.status;
        for (char& c : status) {
            if (c >= 'a' && c <= 'z') {
                c = static_cast<char>(c - 'a' + 'A');
            }
        }
        if (status == "N/A") {
            status = "N/A ";
        }
        std::cout << "  " << check.name;
        for (size_t i = check.name.size(); i < 18; ++i) {
            std::cout << ' ';
        }
        std::cout << status << "  " << check.detail << "\n";
    }
}

void printUsage() {
    std::cerr << "usage: bincheck [--json] [--strict] <file>\n";
}

} // namespace

int main(int argc, char** argv) {
    bool json = false;
    bool strict = false;
    std::string path;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--json") {
            json = true;
        } else if (arg == "--strict") {
            strict = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "bincheck inspects an ELF or PE binary and reports "
                         "its layout and hardening state.\n";
            printUsage();
            return 0;
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "bincheck: unknown option " << arg << "\n";
            printUsage();
            return 2;
        } else if (path.empty()) {
            path = arg;
        } else {
            std::cerr << "bincheck: only one file at a time\n";
            printUsage();
            return 2;
        }
    }
    if (path.empty()) {
        printUsage();
        return 2;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "bincheck: " << path << ": cannot open file\n";
        return 2;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    if (in.bad()) {
        std::cerr << "bincheck: " << path << ": read failed\n";
        return 2;
    }

    Report rep;
    try {
        Reader reader(data);
        if (data.size() >= 4 && data[0] == 0x7f && data[1] == 'E' &&
            data[2] == 'L' && data[3] == 'F') {
            rep = parseElf(reader, path);
        } else if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
            rep = parsePe(reader, path);
        } else {
            throw ParseError("unrecognized format, not an ELF or PE file");
        }
    } catch (const ParseError& err) {
        std::cerr << "bincheck: " << path << ": " << err.what() << "\n";
        return 2;
    }

    if (json) {
        printJson(rep);
    } else {
        printHuman(rep);
    }

    if (strict) {
        for (const Check& check : rep.checks) {
            if (check.status == "fail") {
                return 1;
            }
        }
    }
    return 0;
}
