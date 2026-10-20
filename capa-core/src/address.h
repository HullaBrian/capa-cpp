// Address model for capa-cpp.
//
// Ports capa/features/address.py plus the freeze AddressType serialization from
// capa/features/freeze/__init__.py. Every address kind capa defines is here, because a
// freeze file from any capa backend may carry any of them:
//   - AbsoluteVirtualAddress : code locations, file imports/exports/sections
//   - ProcessAddress(ppid,pid)
//   - ThreadAddress(process,tid)
//   - DynamicCallAddress(thread,id)
//   - FileOffsetAddress      : file-scope strings / embedded PEs
//   - RelativeVirtualAddress : deprecated upstream (capa#3072), still loadable
//   - DNTokenAddress         : a .NET metadata token (dnfile backend)
//   - DNTokenOffsetAddress   : an offset into the IL of a .NET method (dnfile backend)
//   - NoAddress              : global/file features without a location
//
// Edge case kept from capa, on purpose: capa's integer-like addresses (absolute,
// relative, file offset, dn token) are `int` subclasses and so compare *equal* to each
// other when their values are equal. Nothing in capa relies on that, and capa-cpp keeps
// the kinds distinct; it can only matter for a location set holding two different kinds
// with the same number, which no backend produces.
//
// An Address is a small value type with total ordering and hashing so it can live
// in unordered_set / ordered containers, mirroring the Python __hash__/__eq__/__lt__.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <string>
#include <tuple>
#include <vector>

namespace capa {

// New kinds are appended: `key()` leads with the enum's integer value, so reordering
// would change how addresses sort against each other.
enum class AddressType {
    NO_ADDRESS,
    ABSOLUTE,
    PROCESS,
    THREAD,
    CALL,
    FILE_OFFSET,
    RELATIVE_VA,  // not RELATIVE: wingdi.h defines that as a macro
    DN_TOKEN,
    DN_TOKEN_OFFSET,  // value = token, id = offset
};

// A single value type covering every address kind on the dynamic path.
// Unused fields are simply zero for kinds that don't need them.
//
// Field ORDER here is chosen for packing, not for reading: the four 32-bit members
// come first so they fill two 8-byte slots, which makes this 32 bytes instead of the
// 40 a value-first layout costs. Address is the most replicated object in the
// program -- every FeatureSet key set, every Result::locations, every layout entry is
// made of them -- so the eight bytes are worth more than the tidier declaration
// order. Nothing depends on the layout; every access is by name and key() fixes the
// comparison order independently.
struct Address {
    AddressType type = AddressType::NO_ADDRESS;
    // PROCESS/THREAD/CALL: ppid/pid/tid/id are used as needed.
    std::uint32_t ppid = 0;
    std::uint32_t pid = 0;
    std::uint32_t tid = 0;
    // ABSOLUTE / FILE_OFFSET: value holds the virtual address or file offset.
    std::uint64_t value = 0;
    std::uint64_t id = 0;  // call index within a thread

    static Address no_address() { return Address{}; }

    static Address absolute(std::uint64_t va) {
        Address a;
        a.type = AddressType::ABSOLUTE;
        a.value = va;
        return a;
    }

    static Address file_offset(std::uint64_t off) {
        Address a;
        a.type = AddressType::FILE_OFFSET;
        a.value = off;
        return a;
    }

    static Address relative(std::uint64_t rva) {
        Address a;
        a.type = AddressType::RELATIVE_VA;
        a.value = rva;
        return a;
    }

    static Address dn_token(std::uint64_t token) {
        Address a;
        a.type = AddressType::DN_TOKEN;
        a.value = token;
        return a;
    }

    static Address dn_token_offset(std::uint64_t token, std::uint64_t offset) {
        Address a;
        a.type = AddressType::DN_TOKEN_OFFSET;
        a.value = token;
        a.id = offset;
        return a;
    }

    static Address process(std::uint32_t pid, std::uint32_t ppid = 0) {
        Address a;
        a.type = AddressType::PROCESS;
        a.pid = pid;
        a.ppid = ppid;
        return a;
    }

    static Address thread(const Address& proc, std::uint32_t tid) {
        Address a;
        a.type = AddressType::THREAD;
        a.ppid = proc.ppid;
        a.pid = proc.pid;
        a.tid = tid;
        return a;
    }

    static Address call(const Address& thread, std::uint64_t id) {
        Address a;
        a.type = AddressType::CALL;
        a.ppid = thread.ppid;
        a.pid = thread.pid;
        a.tid = thread.tid;
        a.id = id;
        return a;
    }

    // The process/thread this address belongs to (for THREAD/CALL addresses).
    Address process_part() const { return Address::process(pid, ppid); }
    Address thread_part() const {
        Address t;
        t.type = AddressType::THREAD;
        t.ppid = ppid;
        t.pid = pid;
        t.tid = tid;
        return t;
    }

    bool is_no_address() const { return type == AddressType::NO_ADDRESS; }

    // Tuple used for equality/ordering; the leading type discriminates kinds so that,
    // like capa's freeze Address.__lt__, addresses sort by type first then value.
    std::tuple<int, std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint64_t>
    key() const {
        return {static_cast<int>(type), value, ppid, pid, tid, id};
    }

    bool operator==(const Address& o) const { return key() == o.key(); }
    bool operator!=(const Address& o) const { return !(*this == o); }
    bool operator<(const Address& o) const { return key() < o.key(); }

    std::string repr() const;
};

// A sorted, unique set of addresses held flat.
//
// Interface-compatible with the `std::set<Address>` it replaces, for the operations this
// codebase uses, and it iterates in the same order -- so what renders from it is
// unchanged. The reason to replace it is size. A red-black tree wraps every 32-byte
// address in three pointers and a colour and gives it its own heap block, roughly
// tripling it; and a scope's feature set is one address per *occurrence*, so a
// two-million-call trace reaches nearly five million of them. Flat, the set is the
// addresses and nothing else.
//
// The walk visits calls in increasing order, so the operations that matter are shaped
// around ascending input: a new address almost always sorts after the last one (a
// push_back), and a merge is almost always of two disjoint ascending runs (an append).
// Anything out of order still works, by positioned insert and by set_union.
class AddressSet {
public:
    using value_type = Address;
    using const_iterator = std::vector<Address>::const_iterator;

    AddressSet() = default;
    AddressSet(std::initializer_list<Address> init) {
        for (const Address& a : init) insert(a);
    }

    const_iterator begin() const { return v_.begin(); }
    const_iterator end() const { return v_.end(); }
    std::size_t size() const { return v_.size(); }
    bool empty() const { return v_.empty(); }
    void clear() { v_.clear(); }

    // True when `a` was not already present. std::set::insert reports this through the
    // second of a pair; the mutate-and-undo path in the matcher needs it, to know whether
    // it has an addition of its own to take back out.
    bool insert(const Address& a) {
        if (v_.empty() || v_.back() < a) {  // the ascending-walk case
            v_.push_back(a);
            return true;
        }
        auto it = std::lower_bound(v_.begin(), v_.end(), a);
        if (it != v_.end() && !(a < *it)) return false;
        v_.insert(it, a);
        return true;
    }

    // Generic range insert. Element-wise, which is linear for ascending input and is
    // what every caller of this overload supplies.
    template <class It>
    void insert(It first, It last) {
        for (; first != last; ++first) insert(*first);
    }

    // Union with another set. Linear whatever the overlap, unlike the element-wise
    // version, which is what makes it right for merging two large sets.
    void insert(const AddressSet& other) {
        if (other.empty()) return;
        if (v_.empty()) {
            v_ = other.v_;
            return;
        }
        if (v_.back() < other.v_.front()) {
            v_.insert(v_.end(), other.v_.begin(), other.v_.end());
            return;
        }
        unite(other.v_);
    }

    // std::set::merge's role: take everything from `other`, leaving it empty. (std::set
    // leaves duplicates behind; every caller here clears the source straight after, so
    // emptying it outright is the same thing to them and cheaper.)
    void merge(AddressSet& other) {
        if (other.empty()) return;
        if (v_.empty()) {
            v_.swap(other.v_);
            return;
        }
        if (v_.back() < other.v_.front()) {  // disjoint ascending runs: append
            v_.insert(v_.end(), other.v_.begin(), other.v_.end());
        } else {
            unite(other.v_);
        }
        other.v_.clear();
    }

    void erase(const Address& a) {
        auto it = std::lower_bound(v_.begin(), v_.end(), a);
        if (it != v_.end() && !(a < *it)) v_.erase(it);
    }

    std::size_t count(const Address& a) const {
        auto it = std::lower_bound(v_.begin(), v_.end(), a);
        return (it != v_.end() && !(a < *it)) ? 1 : 0;
    }

private:
    void unite(const std::vector<Address>& other) {
        std::vector<Address> out;
        out.reserve(v_.size() + other.size());
        std::set_union(v_.begin(), v_.end(), other.begin(), other.end(),
                       std::back_inserter(out));
        v_.swap(out);
    }

    std::vector<Address> v_;
};

}  // namespace capa

namespace std {
template <>
struct hash<capa::Address> {
    size_t operator()(const capa::Address& a) const noexcept {
        auto k = a.key();
        size_t h = std::hash<int>{}(std::get<0>(k));
        auto mix = [&h](std::uint64_t v) {
            h ^= std::hash<std::uint64_t>{}(v) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        };
        mix(std::get<1>(k));
        mix(std::get<2>(k));
        mix(std::get<3>(k));
        mix(std::get<4>(k));
        mix(std::get<5>(k));
        return h;
    }
};
}  // namespace std
