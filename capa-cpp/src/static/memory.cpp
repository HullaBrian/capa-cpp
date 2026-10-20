#include "static/memory.h"

#include <algorithm>
#include <utility>

#if defined(_WIN32)
// windows.h is here only for the file mapping. NOMINMAX because its min/max macros
// otherwise eat the std::min below -- and every other one in this translation unit.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace capa::stat {

MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if (this != &o) {
        close();
        file_ = std::exchange(o.file_, nullptr);
        mapping_ = std::exchange(o.mapping_, nullptr);
        data_ = std::exchange(o.data_, nullptr);
        size_ = std::exchange(o.size_, 0);
    }
    return *this;
}

#if defined(_WIN32)
void MappedFile::close() {
    if (data_ != nullptr) ::UnmapViewOfFile(data_);
    if (mapping_ != nullptr) ::CloseHandle(mapping_);
    if (file_ != nullptr && file_ != INVALID_HANDLE_VALUE) ::CloseHandle(file_);
    file_ = mapping_ = nullptr;
    data_ = nullptr;
    size_ = 0;
}

bool MappedFile::open(const std::string& path) {
    close();
    // FILE_SHARE_* across the board: these snapshots are somebody else's output and
    // holding an exclusive handle on them for the length of a scan is not our place.
    HANDLE fh = ::CreateFileA(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return false;
    file_ = fh;

    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(fh, &sz) || sz.QuadPart <= 0) {
        close();
        return false;
    }
    // A 32-bit build cannot map a file larger than its address space, and a snapshot
    // that big is not one we could scan anyway.
    if (static_cast<std::uint64_t>(sz.QuadPart) > static_cast<std::uint64_t>(SIZE_MAX)) {
        close();
        return false;
    }

    mapping_ = ::CreateFileMappingA(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping_ == nullptr) {
        close();
        return false;
    }
    data_ = static_cast<const std::uint8_t*>(::MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0));
    if (data_ == nullptr) {
        close();
        return false;
    }
    size_ = static_cast<std::size_t>(sz.QuadPart);
    return true;
}
#else
void MappedFile::close() {
    if (data_ != nullptr) ::munmap(const_cast<std::uint8_t*>(data_), size_);
    data_ = nullptr;
    size_ = 0;
}

bool MappedFile::open(const std::string& path) {
    close();
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_size <= 0 ||
        static_cast<std::uint64_t>(st.st_size) > static_cast<std::uint64_t>(SIZE_MAX)) {
        ::close(fd);
        return false;
    }
    const auto sz = static_cast<std::size_t>(st.st_size);
    // The mapping holds its own reference to the file, so the descriptor can go now.
    void* view = ::mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (view == MAP_FAILED) return false;
    data_ = static_cast<const std::uint8_t*>(view);
    size_ = sz;
    return true;
}
#endif


namespace {
// Same printable set as vivisect's readString (deliberately narrower than
// helpers::is_printable_char, which is the FLOSS scan's).
bool is_printable_ascii(std::uint8_t c) { return c == 0x09 || (c >= 0x20 && c <= 0x7e); }
constexpr std::size_t MAX_STRING_LEN = 1024;
}  // namespace

void MemoryImage::add(std::uint64_t base, std::vector<std::uint8_t> bytes,
                      std::uint32_t flags) {
    if (bytes.empty()) return;
    store_.push_back(std::move(bytes));
    const std::vector<std::uint8_t>& b = store_.back();
    segs_.push_back(Segment{base, b.size(), flags, b.data()});
}

void MemoryImage::add_view(std::uint64_t base, const std::uint8_t* data, std::uint64_t size,
                           std::uint32_t flags) {
    if (!data || size == 0) return;
    segs_.push_back(Segment{base, size, flags, data});
}

void MemoryImage::finalize() {
    // Base ascending, then size DESCENDING: segment_at() requires non-overlapping
    // ranges, so one of any overlapping pair has to go, and the tiebreak decides
    // which. Sorting on base alone leaves that to std::sort's unspecified ordering of
    // equivalent elements -- so two segments mapped at the same base could keep
    // either one, run to run. Largest wins, deterministically.
    std::sort(segs_.begin(), segs_.end(), [](const Segment& a, const Segment& b) {
        if (a.base != b.base) return a.base < b.base;
        return a.size > b.size;
    });
    std::vector<Segment> out;
    out.reserve(segs_.size());
    for (const Segment& s : segs_) {
        if (!out.empty() && s.base < out.back().base + out.back().size) continue;
        out.push_back(s);
    }
    segs_.swap(out);
    last_hit_ = 0;
}

const Segment* MemoryImage::segment_at(std::uint64_t va) const {
    if (segs_.empty()) return nullptr;
    if (last_hit_ < segs_.size() && segs_[last_hit_].contains(va)) return &segs_[last_hit_];

    // the last segment with base <= va
    auto it = std::upper_bound(segs_.begin(), segs_.end(), va,
                               [](std::uint64_t v, const Segment& s) { return v < s.base; });
    if (it == segs_.begin()) return nullptr;
    --it;
    if (!it->contains(va)) return nullptr;
    last_hit_ = static_cast<std::size_t>(it - segs_.begin());
    return &*it;
}

std::span<const std::uint8_t> MemoryImage::view(std::uint64_t va) const {
    const Segment* s = segment_at(va);
    if (!s) return {};
    std::size_t off = static_cast<std::size_t>(va - s->base);
    return std::span<const std::uint8_t>(s->data + off, static_cast<std::size_t>(s->size) - off);
}

std::vector<std::uint8_t> MemoryImage::read(std::uint64_t va, std::size_t n) const {
    std::span<const std::uint8_t> v = view(va);
    if (v.empty()) return {};
    std::size_t take = std::min(n, v.size());
    return std::vector<std::uint8_t>(v.begin(), v.begin() + take);
}

std::optional<std::uint64_t> MemoryImage::read_pointer(std::uint64_t va, int psize) const {
    std::span<const std::uint8_t> v = view(va);
    if (psize <= 0 || v.size() < static_cast<std::size_t>(psize)) return std::nullopt;
    std::uint64_t p = 0;
    for (int k = psize - 1; k >= 0; --k) p = (p << 8) | v[static_cast<std::size_t>(k)];
    return p;
}

std::optional<std::string> MemoryImage::read_string(std::uint64_t va) const {
    std::span<const std::uint8_t> v = view(va);
    if (v.empty()) return std::nullopt;
    const std::size_t end = v.size();

    // ASCII
    std::size_t a = 0;
    while (a < end && a < MAX_STRING_LEN && is_printable_ascii(v[a])) ++a;
    if (a > 0 && (a == end || v[a] == 0x00))
        return std::string(reinterpret_cast<const char*>(v.data()), a);

    // UTF-16LE
    std::string u;
    std::size_t p = 0;
    while (p + 1 < end && u.size() < MAX_STRING_LEN && is_printable_ascii(v[p]) &&
           v[p + 1] == 0x00) {
        u.push_back(static_cast<char>(v[p]));
        p += 2;
    }
    if (!u.empty() && (p + 1 >= end || (v[p] == 0x00 && v[p + 1] == 0x00))) return u;

    return std::nullopt;
}

bool MemoryImage::is_probably_string(std::uint64_t va) const {
    auto s = read_string(va);
    return s && s->size() >= 4;
}

MemoryImage MemoryImage::single(std::uint64_t base, std::vector<std::uint8_t> bytes) {
    MemoryImage m;
    m.add(base, std::move(bytes), SEG_EXEC);
    m.finalize();
    return m;
}

}  // namespace capa::stat
