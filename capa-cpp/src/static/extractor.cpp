#include "static/extractor.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <unordered_map>
#include <vector>

#include "extract_helpers.h"
#include "symbols.h"

namespace capa::stat {

namespace {

using helpers::MAX_BYTES_FEATURE_SIZE;
using helpers::MAX_STRUCTURE_SIZE;
using helpers::MIN_STACKSTRING_LEN;

void add(std::vector<FeaturePair>& out, Feature f, const Address& a) {
    out.emplace_back(std::move(f), a);
}
Address va_addr(std::uint64_t va) { return Address::absolute(va); }

// recursively follow a pointer, collecting the valid addresses along the way (viv derefs).
std::vector<std::uint64_t> derefs(const Workspace& ws, std::uint64_t p) {
    std::vector<std::uint64_t> out;
    int depth = 0;
    for (;;) {
        if (!ws.is_valid_pointer(p)) return out;
        out.push_back(p);
        if (ws.is_probably_string(p)) return out;  // don't deref strings that look like pointers
        auto next = ws.read_pointer(p);
        if (!next) return out;
        if (*next == p) return out;
        if (++depth > 10) return out;
        p = *next;
    }
}

// ---- stack string helpers (viv basicblock.py) ----
bool is_mov_imm_to_stack(const DecodedInsn& insn) {
    if (insn.mnem.rfind("mov", 0) != 0) return false;
    if (insn.opers.size() != 2) return false;
    const Operand& dst = insn.opers[0];
    const Operand& src = insn.opers[1];
    if (!src.is_immediate) return false;
    if (dst.kind != OperKind::Sib && dst.kind != OperKind::RegMem) return false;
    return dst.base_is_stack;  // base reg present and is (e/r)bp/(e/r)sp
}

int printable_len(const Operand& src) {
    return helpers::printable_len(static_cast<std::uint64_t>(src.value), src.size);
}

// ---- security cookie check (viv insn.py is_security_cookie) ----
bool is_security_cookie(const Function& f, const BasicBlock& bb, const DecodedInsn& insn) {
    if (insn.opers.size() < 2) return false;
    const Operand& oper = insn.opers[1];
    if (oper.kind == OperKind::Reg && !oper.base_is_stack) return false;
    const BasicBlock& bb0 = f.blocks.empty() ? bb : f.blocks[0];
    constexpr std::uint64_t DELTA = helpers::SECURITY_COOKIE_BYTES_DELTA;
    if (bb.va == bb0.va && insn.va < bb.va + DELTA) return true;
    const DecodedInsn& last = bb.insns.back();
    if (last.is_return() && insn.va > bb.va + bb.size - DELTA) return true;
    return false;
}

}  // namespace

StaticExtractor::StaticExtractor(std::uint64_t base, std::vector<std::uint8_t> bytes,
                                 std::vector<std::uint64_t> entries,
                                 std::vector<std::uint64_t> executed, Arch arch,
                                 const FeatureFilter* filter)
    : ws_(base, std::move(bytes), std::move(entries), std::move(executed), arch),
      filter_(filter) {
    init_globals(arch);
}

StaticExtractor::StaticExtractor(const MemoryImage& mem, std::uint64_t region_base,
                                 std::uint64_t region_size, std::vector<std::uint64_t> entries,
                                 std::vector<std::uint64_t> executed, Arch arch,
                                 const ModuleContext* ctx, const FeatureFilter* filter)
    : ws_(mem, region_base, region_size, std::move(entries), std::move(executed), arch),
      ctx_(ctx),
      filter_(filter) {
    init_globals(arch);
}

void StaticExtractor::init_globals(Arch arch) {
    // A context that knows its container replaces these outright, which is how a
    // module region gets `format: pe` and a shellcode region gets sc32 / sc64.
    if (ctx_ && !ctx_->global_features().empty()) {
        global_features_ = ctx_->global_features();
        return;
    }
    add(global_features_, Feature::os(OS_WINDOWS), Address::no_address());
    add(global_features_, Feature::arch(arch == Arch::X86 ? ARCH_I386 : ARCH_AMD64),
        Address::no_address());
}

std::vector<FeaturePair> StaticExtractor::extract_file_features() const {
    std::span<const std::uint8_t> buf = ws_.region_bytes();
    std::vector<FeaturePair> out;
    // this backend reports file-scope hits at their mapped VA, not a file offset:
    // a reconstructed region has no file to be an offset into.
    for (std::size_t off : helpers::carve_embedded_pe(buf))
        add(out, Feature::characteristic("embedded pe"), va_addr(ws_.base() + off));

    // Tested as each string is carved, not collected and then filtered: on a module-sized
    // region the strings no rule can match are the overwhelming majority, and holding all
    // of them to throw most away is the single largest allocation a snapshot scan makes.
    auto take_string = [this, &out](std::string&& value, std::size_t offset) {
        Feature feature = Feature::string(std::move(value));
        if (filter_ != nullptr && !filter_->keep(feature)) return;
        add(out, std::move(feature), va_addr(ws_.base() + offset));
    };
    helpers::scan_ascii_strings(buf, take_string);
    helpers::scan_unicode_strings(buf, take_string);
    // sections, exports (incl. forwarders), imports and function names -- everything
    // that needs a real PE container behind the region.
    if (ctx_)
        for (const FeaturePair& fp : ctx_->file_features()) out.push_back(fp);
    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_function_features(const Function& f) const {
    std::vector<FeaturePair> out;

    // calls to: every code xref (call/jmp) targeting the function entry.
    for (std::uint64_t src : ws_.xrefs_to(f.va))
        add(out, Feature::characteristic("calls to"), va_addr(src));

    // loop: does the function's BB graph contain a cycle?
    std::vector<std::pair<std::uint64_t, std::uint64_t>> edges;
    for (const BasicBlock& bb : f.blocks) {
        if (bb.insns.empty()) continue;
        const DecodedInsn& last = bb.insns.back();
        for (const Branch& br : insn_branches(last)) {
            if (!br.target) continue;
            if ((br.flags & BR_COND) || (br.flags & BR_FALL) || (br.flags & BR_TABLE) ||
                last.mnem == "jmp")
                edges.emplace_back(bb.va, *br.target);
        }
    }
    if (!edges.empty() && helpers::has_loop(edges))
        add(out, Feature::characteristic("loop"), va_addr(f.va));

    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_basic_block_features(const Function& f,
                                                                       const BasicBlock& bb) const {
    std::vector<FeaturePair> out;
    add(out, Feature::basic_block(), va_addr(bb.va));

    // tight loop: last instruction is a conditional branch back to the block start.
    if (!bb.insns.empty()) {
        const DecodedInsn& last = bb.insns.back();
        for (const Branch& br : insn_branches(last))
            if ((br.flags & BR_COND) && br.target && *br.target == bb.va) {
                add(out, Feature::characteristic("tight loop"), va_addr(bb.va));
                break;
            }
    }

    // stack string: enough constant bytes moved onto the stack within this block.
    int count = 0;
    bool emitted = false;
    for (const DecodedInsn& insn : bb.insns) {
        if (is_mov_imm_to_stack(insn)) count += printable_len(insn.opers[1]);
        if (count > MIN_STACKSTRING_LEN) {
            emitted = true;
            break;
        }
    }
    if (emitted) add(out, Feature::characteristic("stack string"), va_addr(bb.va));

    (void)f;
    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_insn_features(const Function& f,
                                                               const BasicBlock& bb,
                                                               const DecodedInsn& insn) const {
    std::vector<FeaturePair> out;
    const Address ih = va_addr(insn.va);
    const auto& ops = insn.opers;

    // ---- bytes ----
    if (insn.mnem != "call") {
        for (const Operand& oper : ops) {
            std::int64_t v = 0;
            bool have = true;
            switch (oper.kind) {
                case OperKind::Imm: v = oper.value; break;
                case OperKind::RegMem: v = oper.disp; break;
                case OperKind::Sib: v = oper.abs; break;
                case OperKind::RipRel: v = static_cast<std::int64_t>(oper.addr); break;
                default: have = false; break;
            }
            if (!have) continue;
            for (std::uint64_t vv : derefs(ws_, static_cast<std::uint64_t>(v))) {
                std::vector<std::uint8_t> buf = ws_.read(vv, MAX_BYTES_FEATURE_SIZE);
                if (buf.empty() || helpers::all_zeros(buf)) continue;
                if (ws_.is_probably_string(vv)) continue;
                add(out, Feature::bytes(std::string(buf.begin(), buf.end())), ih);
            }
        }
    }

    // ---- nzxor ----
    if ((insn.mnem == "xor" || insn.mnem == "xorpd" || insn.mnem == "xorps" ||
         insn.mnem == "pxor") &&
        ops.size() >= 2 && !operand_equal(ops[0], ops[1]) && !is_security_cookie(f, bb, insn)) {
        add(out, Feature::characteristic("nzxor"), ih);
    }

    // ---- mnemonic ----
    add(out, Feature::mnemonic(insn.mnem), ih);

    // ---- call $+5 ----
    if (insn.mnem == "call" && !ops.empty()) {
        const Operand& o0 = ops[0];
        const std::uint64_t next5 = mask_address(insn.va + 5, insn.arch);
        if (o0.kind == OperKind::PcRel && next5 == static_cast<std::uint64_t>(o0.value))
            add(out, Feature::characteristic("call $+5"), ih);
        else if ((o0.kind == OperKind::ImmMem || o0.kind == OperKind::RipRel) &&
                 next5 == o0.addr)
            add(out, Feature::characteristic("call $+5"), ih);
    }

    // ---- peb access ----
    if (insn.mnem == "push" || insn.mnem == "mov") {
        if (insn.seg_prefix == "fs") {
            for (const Operand& oper : ops)
                if ((oper.kind == OperKind::RegMem && oper.disp == 0x30) ||
                    (oper.kind == OperKind::ImmMem && oper.addr == 0x30)) {
                    add(out, Feature::characteristic("peb access"), ih);
                    break;
                }
        } else if (insn.seg_prefix == "gs") {
            for (const Operand& oper : ops)
                if ((oper.kind == OperKind::RegMem && oper.disp == 0x60) ||
                    (oper.kind == OperKind::Sib && oper.abs == 0x60) ||
                    (oper.kind == OperKind::ImmMem && oper.addr == 0x60)) {
                    add(out, Feature::characteristic("peb access"), ih);
                    break;
                }
        }
    }

    // ---- fs / gs access ----
    if (insn.seg_prefix == "fs") add(out, Feature::characteristic("fs access"), ih);
    if (insn.seg_prefix == "gs") add(out, Feature::characteristic("gs access"), ih);

    // ---- calls from / recursive call ----
    if (insn.mnem == "call" && !ops.empty()) {
        const Operand& o0 = ops[0];
        bool have_target = false;
        std::uint64_t target = 0;
        if (o0.kind == OperKind::ImmMem) {
            target = o0.addr;
            have_target = true;
        } else if (o0.kind == OperKind::PcRel) {
            target = static_cast<std::uint64_t>(o0.value);
            have_target = true;
        } else if (o0.kind == OperKind::RipRel) {
            target = o0.addr;
            have_target = true;
        }
        if (have_target) {
            add(out, Feature::characteristic("calls from"), va_addr(target));
            if (target == f.va) add(out, Feature::characteristic("recursive call"), va_addr(target));
        }
    }

    // ---- indirect call ----
    if (insn.mnem == "call" && !ops.empty()) {
        OperKind k = ops[0].kind;
        if (k == OperKind::Reg || k == OperKind::RegMem || k == OperKind::Sib)
            add(out, Feature::characteristic("indirect call"), ih);
    }

    // ---- api ----
    //
    // Ports capa/features/extractors/viv/insn.py::extract_insn_api_features. The
    // context does the resolving (it owns the export and IAT maps); this only turns
    // a hit into the name variants capa's rules are written against.
    if (ctx_ && (insn.mnem == "call" || insn.mnem == "jmp")) {
        thread_local std::vector<ResolvedApi> apis;
        apis.clear();
        ctx_->resolve_api(ws_, bb, insn, apis);
        for (const ResolvedApi& a : apis)
            for (const std::string& name : generate_symbols(a.dll, a.symbol))
                add(out, Feature::api(name), ih);
    }

    // ---- cross section flow ----
    if (ctx_ && (insn.is_call || insn.is_cond_branch || insn.is_uncond_jmp) &&
        insn.branch_target) {
        int from = ctx_->section_index(insn.va);
        int to = ctx_->section_index(*insn.branch_target);
        if (from >= 0 && to >= 0 && from != to)
            add(out, Feature::characteristic("cross section flow"), ih);
    }

    // ---- operand number / offset / string ----
    for (std::size_t i = 0; i < ops.size(); ++i) {
        const Operand& oper = ops[i];

        // number
        if (oper.kind == OperKind::Imm || oper.kind == OperKind::ImmMem) {
            std::int64_t v = oper.kind == OperKind::Imm ? oper.value
                                                        : static_cast<std::int64_t>(oper.addr);
            bool skip = ws_.is_valid_pointer(static_cast<std::uint64_t>(v));
            if (!skip && insn.mnem == "add" && !ops.empty() && ops[0].kind == OperKind::Reg &&
                ops[0].reg_is_sp)
                skip = true;
            if (!skip) {
                // The immediate is masked to its operand width, like viv's: an unsigned
                // machine word, which is how capa compares it against a rule's number.
                add(out, Feature::number(v).as_unsigned(), ih);
                add(out, Feature::operand_number(static_cast<int>(i), v).as_unsigned(), ih);
                if (insn.mnem == "add" && v > 0 && v < MAX_STRUCTURE_SIZE &&
                    oper.kind == OperKind::Imm) {
                    add(out, Feature::offset(v), ih);
                    add(out, Feature::operand_offset(static_cast<int>(i), v), ih);
                }
            }
        }

        // offset
        if (oper.kind == OperKind::RegMem) {
            if (!oper.base_is_stack) {
                std::int64_t v = oper.disp;
                add(out, Feature::offset(v), ih);
                add(out, Feature::operand_offset(static_cast<int>(i), v), ih);
                if (insn.mnem == "lea" && i == 1 && !ws_.is_valid_pointer(static_cast<std::uint64_t>(v))) {
                    add(out, Feature::number(v), ih);
                    add(out, Feature::operand_number(static_cast<int>(i), v), ih);
                }
            }
        } else if (oper.kind == OperKind::Sib) {
            std::int64_t v = oper.disp;
            add(out, Feature::offset(v), ih);
            add(out, Feature::operand_offset(static_cast<int>(i), v), ih);
        }

        // string
        std::int64_t sv = 0;
        bool have_sv = true;
        switch (oper.kind) {
            case OperKind::Imm: sv = oper.value; break;
            case OperKind::ImmMem: sv = static_cast<std::int64_t>(oper.addr); break;
            case OperKind::Sib: sv = oper.abs; break;
            case OperKind::RipRel: sv = static_cast<std::int64_t>(oper.addr); break;
            default: have_sv = false; break;
        }
        if (have_sv) {
            for (std::uint64_t vv : derefs(ws_, static_cast<std::uint64_t>(sv))) {
                auto s = ws_.read_string(vv);
                if (!s) continue;
                // rstrip trailing NULs (viv .rstrip("\x00"))
                while (!s->empty() && s->back() == '\0') s->pop_back();
                if (s->size() >= 4) add(out, Feature::string(*s), ih);
            }
        }
    }

    return out;
}

// ---------------------------------------------------------------------------
// StaticFeatureExtractor adapters
//
// `inner` points into the Workspace's own storage (its functions vector and the
// blocks/instructions nested inside), which outlives every handle we hand out.
// ---------------------------------------------------------------------------

std::vector<FunctionHandle> StaticExtractor::get_functions() const {
    std::vector<FunctionHandle> out;
    out.reserve(ws_.functions().size());
    for (const Function& f : ws_.functions()) {
        // A thunk only forwards: its one behaviour is the API it reaches, which a caller's
        // own `call` already resolves through it, and in a trace the call is recorded where
        // it happens. Matched here as well, it became a capability of the stub itself,
        // reported every time anything ran through it.
        if (f.thunk) continue;
        out.push_back({va_addr(f.va), &f});
    }
    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_function_features(
    const FunctionHandle& fh) const {
    return extract_function_features(*static_cast<const Function*>(fh.inner));
}

std::vector<BBHandle> StaticExtractor::get_basic_blocks(const FunctionHandle& fh) const {
    const Function& f = *static_cast<const Function*>(fh.inner);
    std::vector<BBHandle> out;
    out.reserve(f.blocks.size());
    for (const BasicBlock& bb : f.blocks) out.push_back({va_addr(bb.va), &bb});
    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_basic_block_features(
    const FunctionHandle& fh, const BBHandle& bbh) const {
    return extract_basic_block_features(*static_cast<const Function*>(fh.inner),
                                        *static_cast<const BasicBlock*>(bbh.inner));
}

std::vector<InsnHandle> StaticExtractor::get_instructions(const FunctionHandle&,
                                                          const BBHandle& bbh) const {
    const BasicBlock& bb = *static_cast<const BasicBlock*>(bbh.inner);
    std::vector<InsnHandle> out;
    out.reserve(bb.insns.size());
    for (const DecodedInsn& insn : bb.insns) out.push_back({va_addr(insn.va), &insn});
    return out;
}

std::vector<FeaturePair> StaticExtractor::extract_insn_features(const FunctionHandle& fh,
                                                                const BBHandle& bbh,
                                                                const InsnHandle& ih) const {
    return extract_insn_features(*static_cast<const Function*>(fh.inner),
                                 *static_cast<const BasicBlock*>(bbh.inner),
                                 *static_cast<const DecodedInsn*>(ih.inner));
}

}  // namespace capa::stat
