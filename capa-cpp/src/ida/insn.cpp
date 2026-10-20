// Ports capa/features/extractors/ida/insn.py: the thirteen instruction-scope handlers.
//
// Several of these scrape the disassembly *text* (PEB access, fs/gs access, stack
// cookie detection) rather than reading structured operand data. That is what capa's
// Python does (mandiant/capa#1605) and reproducing it is deliberate: a cleaner
// implementation would fire on a different set of instructions.
#include "ida/extractor.h"

#include <algorithm>
#include <cctype>
#include <string>

#include "extract_helpers.h"
#include "symbols.h"

namespace capa::ida {

namespace {

void add(std::vector<FeaturePair>& out, Feature f, const Address& a) {
    out.emplace_back(std::move(f), a);
}
Address va(ea_t ea) { return Address::absolute(static_cast<std::uint64_t>(ea)); }

std::string canon_mnem(const insn_t& insn) {
    const char* m = insn.get_canon_mnem(PH);
    return m ? std::string(m) : std::string();
}

// ---------------------------------------------------------------------------
// api
// ---------------------------------------------------------------------------

// Follow chained thunks to a reasonable depth looking for an entry in `funcs`.
const ImportInfo* check_for_api_call(const insn_t& insn, const std::map<ea_t, ImportInfo>& funcs) {
    const ImportInfo* info = nullptr;
    ea_t ref = insn.ea;

    for (int i = 0; i < helpers::THUNK_CHAIN_DEPTH_DELTA; ++i) {
        // assume a single code/data ref when resolving a "call" or "jmp"
        std::vector<ea_t> crefs = code_refs_from(ref, /*flow=*/false);
        if (!crefs.empty()) {
            ref = crefs[0];
        } else {
            std::vector<ea_t> drefs = data_refs_from(ref);  // thunks may be data refs
            if (drefs.empty()) break;
            ref = drefs[0];
        }

        auto it = funcs.find(ref);
        if (it != funcs.end()) {
            info = &it->second;
            break;
        }

        if (!(get_func_flags_at(ref) & FUNC_THUNK)) break;
    }
    return info;
}

// strip a "_<digits>" suffix IDA appends to repeated names, e.g. VirtualFree_0
std::string strip_repeat_suffix(const std::string& name) {
    std::size_t us = name.rfind('_');
    if (us == std::string::npos || us == 0 || us + 1 >= name.size()) return name;
    for (std::size_t i = us + 1; i < name.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(name[i]))) return name;
    return name.substr(0, us);
}

// Resolve a call through the export/IAT maps read from the .dmp, for a database where
// IDA itself has no names to offer. Mirrors the standalone minidump backend's ladder:
// the import entry first, because its name is the documented API a rule is written
// against, then the slot's stored value, then the branch target.
//
// `hops` is shared by the whole slot/thunk chain: a slot whose value points at
// `jmp [that same slot]` is a cycle, and a per-step counter would not bound it.
bool resolve_from_dump(const IdaExtractor& ex, ea_t slot_or_target, bool is_slot,
                       std::string& dll, std::string& symbol, int hops) {
    if (hops <= 0) return false;
    const capa::mdmp::SymbolMap& syms = ex.dump_symbols();

    if (is_slot) {
        if (const capa::mdmp::SymRef* s = syms.iat_slot(slot_or_target)) {
            dll = syms.dll(*s);
            symbol = syms.symbol(*s);
            return true;
        }
        // The slot's stored pointer. This is what names an IAT the loader already
        // filled in, a bound delay-load slot, and a table shellcode built for itself
        // with GetProcAddress -- none of which has an import entry to read.
        std::uint64_t value = 0;
        if (!read_pointer_at(slot_or_target, value)) return false;
        return resolve_from_dump(ex, static_cast<ea_t>(value), /*is_slot=*/false, dll, symbol,
                                 hops - 1);
    }

    if (const capa::mdmp::SymRef* s = syms.export_at(slot_or_target)) {
        dll = syms.dll(*s);
        symbol = syms.symbol(*s);
        return true;
    }
    // Not an export: follow a thunk if that is what it is. IDA has already decoded
    // this address, so ask it rather than decoding again.
    insn_t thunk;
    if (!decode_at(static_cast<ea_t>(slot_or_target), thunk)) return false;
    if (canon_mnem(thunk) != "jmp" || thunk.ops[0].type == o_void) return false;
    if (thunk.ops[0].type == o_mem)
        return resolve_from_dump(ex, thunk.ops[0].addr, /*is_slot=*/true, dll, symbol, hops - 1);
    if (thunk.ops[0].type == o_near || thunk.ops[0].type == o_far)
        return resolve_from_dump(ex, thunk.ops[0].addr, /*is_slot=*/false, dll, symbol,
                                 hops - 1);
    return false;
}

// The dump-symbol fallback, tried only once IDA's own sources have come up empty.
bool extract_api_from_dump(const IdaExtractor& ex, const insn_t& insn,
                           std::vector<FeaturePair>& out) {
    if (!ex.has_dump_symbols()) return false;

    std::string dll, symbol;
    bool ok = false;
    const int hops = helpers::THUNK_CHAIN_DEPTH_DELTA;

    if (insn.ops[0].type == o_mem) {
        // call [0x40a018] / call [rip+0x1234]: the operand names a slot.
        ok = resolve_from_dump(ex, insn.ops[0].addr, /*is_slot=*/true, dll, symbol, hops);
    } else if (insn.ops[0].type == o_near || insn.ops[0].type == o_far) {
        ok = resolve_from_dump(ex, insn.ops[0].addr, /*is_slot=*/false, dll, symbol, hops);
    } else {
        // An indirect call through a register. IDA's own xref is the best available
        // answer for where it goes.
        std::vector<ea_t> targets = code_refs_from(insn.ea, /*flow=*/false);
        if (targets.empty()) return false;
        ok = resolve_from_dump(ex, targets[0], /*is_slot=*/false, dll, symbol, hops);
    }
    if (!ok) return false;

    for (const std::string& name : generate_symbols(dll, symbol))
        add(out, Feature::api(name), va(insn.ea));
    return true;
}

void extract_insn_api_features(const IdaExtractor& ex, const insn_t& insn,
                               std::vector<FeaturePair>& out) {
    const std::string mnem = canon_mnem(insn);
    if (mnem != "call" && mnem != "jmp") return;

    const Address ih = va(insn.ea);

    // a call to an imported function
    if (const ImportInfo* api = check_for_api_call(insn, ex.imports())) {
        for (const std::string& name : generate_symbols(api->library, api->function))
            add(out, Feature::api(name), ih);
        return;  // a call reaches one function; stop once an import is resolved
    }

    // a call to an extern
    if (const ImportInfo* api = check_for_api_call(insn, ex.externs())) {
        add(out, Feature::api(api->function), ih);
        return;
    }

    // Names read from the .dmp. Placed here, ahead of the heuristics below, because it
    // is the same evidence IDA's import table would have been -- a real export table
    // and a real IAT -- just read from the dump instead of from a database that never
    // had them.
    if (extract_api_from_dump(ex, insn, out)) return;

    // dynamically resolved APIs stored in renamed globals (e.g. via renimp.idc).
    // When a global is renamed after an API, IDA also gives it a function type, so
    // requiring both a non-default name and type information avoids false hits.
    if (insn.ops[0].type == o_mem) {
        ea_t op_addr = insn.ops[0].addr;
        std::string op_name = get_ea_name(op_addr);
        if (op_name.rfind("off_", 0) != 0 && has_type_info(op_addr)) {
            op_name = strip_repeat_suffix(op_name);
            // the global's name carries no DLL, so none is passed
            for (const std::string& name : generate_symbols("", op_name))
                add(out, Feature::api(name), ih);
        }
    }

    // APIs IDA/FLIRT recognized
    std::vector<ea_t> targets = code_refs_from(insn.ea, /*flow=*/false);
    if (targets.empty()) return;

    ea_t target = targets[0];
    ea_t target_start = func_start_of(target);
    if (target_start == BADADDR || target_start != target) return;  // not a function start

    std::string name = get_ea_name(target_start);
    if ((get_func_flags_at(target_start) & FUNC_LIB) || name.rfind("sub_", 0) != 0) {
        if (name.empty()) return;
        add(out, Feature::api(name), ih);
        if (name.front() == '_') {
            // some linkers prefix linked routines with `_`; match both spellings.
            add(out, Feature::api(name.substr(1)), ih);
        }
        for (const std::string& altname : get_function_alternative_names(target_start)) {
            add(out, Feature::function_name(altname), ih);
            add(out, Feature::api(altname), ih);
        }
    }
}

// ---------------------------------------------------------------------------
// number / bytes / string / offset
// ---------------------------------------------------------------------------

void extract_insn_number_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    if (is_ret_insn(insn)) return;      // e.g. `retn 8`
    if (is_sp_modified(insn)) return;   // e.g. `add esp, 0Ch`

    const Address ih = va(insn.ea);
    for (int i = 0; i < UA_MAXOP; ++i) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;
        if (op.type != o_imm && op.type != o_mem) continue;
        // e.g. `shr eax, offset loc_C`
        if (is_op_offset(insn, op)) continue;

        std::int64_t konst = op.type == o_imm ? static_cast<std::int64_t>(mask_op_val(op))
                                              : static_cast<std::int64_t>(op.addr);

        // mask_op_val and op.addr are unsigned in capa's IDA backend too, so a qword
        // immediate of all ones is 0xFFFFFFFFFFFFFFFF there, not -1.
        add(out, Feature::number(konst).as_unsigned(), ih);
        add(out, Feature::operand_number(i, konst).as_unsigned(), ih);

        if (insn.itype == NN_add && konst > 0 &&
            konst < static_cast<std::int64_t>(helpers::MAX_STRUCTURE_SIZE) && op.type == o_imm) {
            // `add eax, 0x10`: assume 0x10 may be a structure offset (eax a pointer).
            add(out, Feature::offset(konst), ih);
            add(out, Feature::operand_offset(i, konst), ih);
        }
    }
}

void extract_insn_bytes_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    if (is_call_insn(insn)) return;

    ea_t ref = find_data_reference_from_insn(insn);
    if (ref == insn.ea) return;

    std::vector<std::uint8_t> bytes = read_bytes_at(ref, helpers::MAX_BYTES_FEATURE_SIZE);
    if (bytes.empty() || helpers::all_zeros(bytes)) return;
    if (!find_string_at(ref).empty()) return;  // obvious strings become String features

    add(out, Feature::bytes(std::string(bytes.begin(), bytes.end())), va(insn.ea));
}

void extract_insn_string_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    ea_t ref = find_data_reference_from_insn(insn);
    if (ref == insn.ea) return;
    std::string found = find_string_at(ref);
    if (!found.empty()) add(out, Feature::string(found), va(insn.ea));
}

void extract_insn_offset_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    const Address ih = va(insn.ea);
    for (int i = 0; i < UA_MAXOP; ++i) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;
        if (op.type != o_phrase && op.type != o_displ) continue;
        if (is_op_stack_var(insn.ea, op.n)) continue;

        PhraseInfo p = get_op_phrase_info(op);
        if (!p.ok) continue;
        // e.g. `mov esi, dword_1005B148[esi]` — an absolute address, not a struct offset
        if (is_mapped(static_cast<ea_t>(p.offset))) continue;

        // IDA encodes displacements as two's complement in a u32; x86-64 has no
        // 64-bit displacement.
        std::int64_t op_off = twos_complement(p.offset, 32);

        add(out, Feature::offset(op_off), ih);
        add(out, Feature::operand_offset(i, op_off), ih);

        // `lea eax, [ebx + 1]`: assume 1 is also a number (imagine ebx is zero).
        // o_displ covers both [eax+1] and [eax+ebx+2]; only the latter has a SIB, and
        // that form is not what this is about.
        if (insn.itype == NN_lea && i == 1 && op.type == o_displ && !has_sib(op)) {
            add(out, Feature::number(op_off), ih);
            add(out, Feature::operand_number(i, op_off), ih);
        }
    }
}

// ---------------------------------------------------------------------------
// nzxor (with stack-cookie suppression)
// ---------------------------------------------------------------------------

bool contains_stack_cookie_keywords(const std::string& s_in) {
    if (s_in.empty()) return false;
    std::string s = s_in;
    // strip + lowercase
    std::size_t b = s.find_first_not_of(" \t\r\n");
    std::size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return false;
    s = s.substr(b, e - b + 1);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (s.find("cookie") == std::string::npos) return false;
    return s.find("stack") != std::string::npos || s.find("security") != std::string::npos;
}

// Registers a block writes while executing something that mentions a stack cookie.
// Assumes the cookie load and the nzxor live in the same block and the cookie register
// is not reassigned in between.
std::vector<int> bb_stack_cookie_registers(const IdaBB& bb) {
    std::vector<int> regs;
    for (const insn_t& insn : bb.insns) {
        if (!contains_stack_cookie_keywords(disasm_line(insn.ea))) continue;
        for (int i = 0; i < UA_MAXOP; ++i) {
            const op_t& op = insn.ops[i];
            if (op.type == o_void) break;
            if (op.type != o_reg) continue;
            if (is_op_write(insn, op)) regs.push_back(op.reg);
        }
    }
    return regs;
}

bool is_nzxor_stack_cookie_delta(const IdaFunc& f, const IdaBB& bb, const insn_t& insn) {
    // a security cookie check uses SP or BP
    if (!is_frame_register(insn.ops[1].reg)) return false;
    if (f.blocks.empty()) return false;

    const IdaBB& first = f.blocks.front();
    // expect the cookie to be set up in the first block, within its first bytes
    if (bb.start_ea == first.start_ea && bb.end_ea == first.end_ea && bb.type == first.type &&
        insn.ea < bb.start_ea + helpers::SECURITY_COOKIE_BYTES_DELTA)
        return true;

    // ... or in the last bytes before a return
    if (bb.is_return() &&
        insn.ea > bb.start_ea + bb.size() - helpers::SECURITY_COOKIE_BYTES_DELTA)
        return true;

    return false;
}

bool is_nzxor_stack_cookie(const IdaFunc& f, const IdaBB& bb, const insn_t& insn) {
    qstring cmt;
    if (get_cmt(&cmt, insn.ea, false) > 0 && contains_stack_cookie_keywords(cmt.c_str()))
        return true;  // e.g. `xor ecx, ebp ; StackCookie`
    if (is_nzxor_stack_cookie_delta(f, bb, insn)) return true;

    std::vector<int> cookie_regs = bb_stack_cookie_registers(bb);
    for (int reg : {static_cast<int>(insn.ops[0].reg), static_cast<int>(insn.ops[1].reg)})
        if (std::find(cookie_regs.begin(), cookie_regs.end(), reg) != cookie_regs.end())
            return true;  // e.g. `mov eax, ___security_cookie` then `xor eax, ebp`
    return false;
}

void extract_insn_nzxor_characteristic_features(const IdaFunc& f, const IdaBB& bb,
                                                const insn_t& insn,
                                                std::vector<FeaturePair>& out) {
    if (insn.itype != NN_xor && insn.itype != NN_xorpd && insn.itype != NN_xorps &&
        insn.itype != NN_pxor)
        return;
    if (is_operand_equal(insn.ops[0], insn.ops[1])) return;  // zeroing xor
    if (is_nzxor_stack_cookie(f, bb, insn)) return;
    add(out, Feature::characteristic("nzxor"), va(insn.ea));
}

// ---------------------------------------------------------------------------
// the short handlers
// ---------------------------------------------------------------------------

void extract_insn_mnemonic_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    qstring mnem;
    if (print_insn_mnem(&mnem, insn.ea)) add(out, Feature::mnemonic(mnem.c_str()), va(insn.ea));
}

void extract_insn_obfs_call_plus_5_characteristic_features(const insn_t& insn,
                                                           std::vector<FeaturePair>& out) {
    if (!is_call_insn(insn)) return;
    if (static_cast<std::int64_t>(insn.ea) + 5 == idc_operand_value(insn, 0))
        add(out, Feature::characteristic("call $+5"), va(insn.ea));
}

bool has_mem_operand(const insn_t& insn) {
    for (int i = 0; i < UA_MAXOP; ++i) {
        if (insn.ops[i].type == o_void) break;
        if (insn.ops[i].type == o_mem) return true;
    }
    return false;
}

void extract_insn_peb_access_characteristic_features(const insn_t& insn,
                                                     std::vector<FeaturePair>& out) {
    // fs:[0x30] on x86, gs:[0x60] on x64
    if (insn.itype != NN_push && insn.itype != NN_mov) return;
    if (!has_mem_operand(insn)) return;

    const std::string disasm = disasm_line(insn.ea);
    if (disasm.find(" fs:30h") != std::string::npos ||
        disasm.find(" gs:60h") != std::string::npos)
        add(out, Feature::characteristic("peb access"), va(insn.ea));
}

void extract_insn_segment_access_features(const insn_t& insn, std::vector<FeaturePair>& out) {
    if (!has_mem_operand(insn)) return;

    const std::string disasm = disasm_line(insn.ea);
    if (disasm.find(" fs:") != std::string::npos)
        add(out, Feature::characteristic("fs access"), va(insn.ea));
    if (disasm.find(" gs:") != std::string::npos)
        add(out, Feature::characteristic("gs access"), va(insn.ea));
}

void extract_insn_cross_section_cflow(const IdaExtractor& ex, const insn_t& insn,
                                      std::vector<FeaturePair>& out) {
    SegInfo here;
    bool have_here = segment_of(insn.ea, here);

    for (ea_t ref : code_refs_from(insn.ea, /*flow=*/false)) {
        if (ex.imports().count(ref)) continue;  // ignore API calls
        SegInfo there;
        if (!segment_of(ref, there)) continue;  // IDA API quirk: no segment for the ref
        if (have_here && there.start_ea == here.start_ea) continue;
        add(out, Feature::characteristic("cross section flow"), va(insn.ea));
    }
}

void extract_function_calls_from(const insn_t& insn, std::vector<FeaturePair>& out) {
    if (!is_call_insn(insn)) return;
    for (ea_t ref : code_refs_from(insn.ea, /*flow=*/false))
        add(out, Feature::characteristic("calls from"), va(ref));
}

void extract_function_indirect_call_characteristic_features(const insn_t& insn,
                                                            std::vector<FeaturePair>& out) {
    // `call eax` / `call dword ptr [edx+4]`, but not `call ds:dword_ABD4974`
    if (!is_call_insn(insn)) return;
    optype_t t = static_cast<optype_t>(insn.ops[0].type);
    if (t == o_reg || t == o_phrase || t == o_displ)
        add(out, Feature::characteristic("indirect call"), va(insn.ea));
}

}  // namespace

void extract_insn_features(const IdaExtractor& ex, const IdaFunc& f, const IdaBB& bb,
                           const insn_t& insn, std::vector<FeaturePair>& out) {
    extract_insn_api_features(ex, insn, out);
    extract_insn_number_features(insn, out);
    extract_insn_bytes_features(insn, out);
    extract_insn_string_features(insn, out);
    extract_insn_offset_features(insn, out);
    extract_insn_nzxor_characteristic_features(f, bb, insn, out);
    extract_insn_mnemonic_features(insn, out);
    extract_insn_obfs_call_plus_5_characteristic_features(insn, out);
    extract_insn_peb_access_characteristic_features(insn, out);
    extract_insn_cross_section_cflow(ex, insn, out);
    extract_insn_segment_access_features(insn, out);
    extract_function_calls_from(insn, out);
    extract_function_indirect_call_characteristic_features(insn, out);
}

}  // namespace capa::ida
