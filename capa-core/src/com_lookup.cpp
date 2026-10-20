#include "com_database.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

#include <zlib.h>

namespace capa {

namespace {

using ComTable = std::unordered_map<std::string, std::vector<std::string>>;

std::string base64_decode(const char* const* chunks, std::size_t count) {
    static const auto table = [] {
        std::array<int, 256> t{};
        t.fill(-1);
        const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int k = 0; k < 64; ++k) t[static_cast<unsigned char>(alphabet[k])] = k;
        return t;
    }();
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (std::size_t c = 0; c < count; ++c) {
        for (const char* p = chunks[c]; *p; ++p) {
            const int v = table[static_cast<unsigned char>(*p)];
            if (v < 0) continue;  // '=' padding
            acc = (acc << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<char>((acc >> bits) & 0xff));
            }
        }
    }
    return out;
}

std::string inflate_all(const std::string& in) {
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) throw std::runtime_error("inflateInit failed");
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    std::string out;
    char buf[1 << 16];
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        zs.next_out = reinterpret_cast<Bytef*>(buf);
        zs.avail_out = sizeof(buf);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&zs);
            throw std::runtime_error("corrupt embedded COM database");
        }
        out.append(buf, sizeof(buf) - zs.avail_out);
    }
    inflateEnd(&zs);
    return out;
}

ComTable load(const char* const* chunks, std::size_t count) {
    ComTable table;
    const std::string text = inflate_all(base64_decode(chunks, count));
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t nl = text.find('\n', start);
        if (nl == std::string::npos) nl = text.size();
        const std::string_view line(text.data() + start, nl - start);
        const std::size_t tab = line.find('\t');
        if (tab != std::string_view::npos) {
            std::vector<std::string>& guids = table[std::string(line.substr(0, tab))];
            std::string_view rest = line.substr(tab + 1);
            while (!rest.empty()) {
                const std::size_t comma = rest.find(',');
                guids.emplace_back(rest.substr(0, comma));
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
        }
        start = nl + 1;
    }
    return table;
}

}  // namespace

const char* com_prefix(ComType type) { return type == ComType::Class ? "CLSID_" : "IID_"; }

const std::vector<std::string>* com_guids(ComType type, const std::string& name) {
    static const ComTable classes = load(com_data::kClasses, com_data::kClassesCount);
    static const ComTable interfaces = load(com_data::kInterfaces, com_data::kInterfacesCount);
    const ComTable& table = type == ComType::Class ? classes : interfaces;
    auto it = table.find(name);
    return it == table.end() ? nullptr : &it->second;
}

}  // namespace capa
