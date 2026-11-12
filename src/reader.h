#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

class ParseError : public std::runtime_error {
public:
    explicit ParseError(const std::string& message) : std::runtime_error(message) {}
};

// Bounds-checked little-endian reads over an in-memory file image.
// Every read validates its range and throws ParseError on bad input.
class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& data) : data_(data) {}

    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    uint8_t u8(uint64_t off) const {
        need(off, 1);
        return data_[static_cast<size_t>(off)];
    }

    uint16_t u16(uint64_t off) const {
        need(off, 2);
        return static_cast<uint16_t>(data_[static_cast<size_t>(off)]) |
               static_cast<uint16_t>(data_[static_cast<size_t>(off) + 1] << 8);
    }

    uint32_t u32(uint64_t off) const {
        need(off, 4);
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v |= static_cast<uint32_t>(data_[static_cast<size_t>(off) + i]) << (8 * i);
        }
        return v;
    }

    uint64_t u64(uint64_t off) const {
        need(off, 8);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<uint64_t>(data_[static_cast<size_t>(off) + i]) << (8 * i);
        }
        return v;
    }

    // Reads a NUL-terminated string starting at off. The string must end
    // before limit, which must itself be inside the file.
    std::string cstr(uint64_t off, uint64_t limit) const {
        if (limit > data_.size()) {
            limit = data_.size();
        }
        if (off >= limit) {
            throw ParseError("string offset out of range");
        }
        std::string out;
        for (uint64_t i = off; i < limit; ++i) {
            char c = static_cast<char>(data_[static_cast<size_t>(i)]);
            if (c == '\0') {
                return out;
            }
            out.push_back(c);
        }
        throw ParseError("unterminated string");
    }

private:
    void need(uint64_t off, uint64_t count) const {
        if (off > data_.size() || count > data_.size() - static_cast<size_t>(off)) {
            throw ParseError("read past end of file");
        }
    }

    const std::vector<uint8_t>& data_;
};
