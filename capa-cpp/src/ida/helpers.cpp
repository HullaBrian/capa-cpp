#include "ida/helpers.h"

#include <algorithm>
#include <cctype>
#include <exception>

#include "minidump/mdmp.h"
#include "module_filter.h"

namespace capa::ida {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// idautils.Heads(start, end)
std::vector<ea_t> heads_in_range(ea_t start, ea_t end) {
    std::vector<ea_t> out;
    if (start == BADADDR || end == BADADDR || start >= end) return out;
    ea_t ea = start;
    if (!is_head(get_flags(ea))) ea = next_head(ea, end);
    while (ea != BADADDR && ea < end) {
        out.push_back(ea);
        ea = next_head(ea, end);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// functions
// ---------------------------------------------------------------------------

std::vector<ea_t> all_function_eas() {
    std::vector<ea_t> out;
    std::size_t n = get_func_qty();
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        ea_t ea = get_func_ea_by_num(i);
        if (ea != BADADDR) out.push_back(ea);
    }
    return out;
}

std::vector<ea_t> function_eas_in_range(ea_t start, ea_t end) {
    std::vector<ea_t> out;
    for (ea_t ea : all_function_eas())
        if (ea >= start && ea < end) out.push_back(ea);
    return out;
}

std::uint64_t get_func_flags_at(ea_t ea) {
    ea_t f = get_func_start(ea);
    if (f == BADADDR) return 0;
    return get_func_flags(f);
}

ea_t func_start_of(ea_t ea) { return get_func_start(ea); }

bool func_contains(ea_t func_ea, ea_t ea) {
    if (func_ea == BADADDR) return false;
    return function_contains(func_ea, ea);
}

void build_function_blocks(IdaFunc& f) {
    if (f.blocks_built) return;
    f.blocks_built = true;

    // FC_NOEXT: ignore the external blocks a function may reference, matching capa's
    // get_function_blocks(). (FC_PREDS is gone in SDK 9.x — predecessors are always
    // computed now.)
    qflow_chart_ea_t fc("", f.start_ea, BADADDR, BADADDR, FC_NOEXT);
    f.blocks.reserve(fc.blocks.size());
    for (std::size_t i = 0; i < fc.blocks.size(); ++i) {
        const qbasic_block_t& qb = fc.blocks[i];
        IdaBB bb;
        bb.start_ea = qb.start_ea;
        bb.end_ea = qb.end_ea;
        bb.type = fc.calc_block_type(i);
        bb.succs.assign(qb.succ.begin(), qb.succ.end());
        bb.preds.assign(qb.pred.begin(), qb.pred.end());
        bb.insns = decode_instructions_in_range(bb.start_ea, bb.end_ea);
        f.blocks.push_back(std::move(bb));
    }
}

void build_function_loop_edges(IdaFunc& f) {
    if (f.loop_edges_built) return;
    f.loop_edges_built = true;

    // capa's extract_function_loop builds a *default-flags* FlowChart, unlike
    // get_basic_blocks' FC_NOEXT one, so the loop test sees external blocks too.
    // Reproduced deliberately: the two graphs differ and that changes which
    // functions get the "loop" characteristic.
    qflow_chart_ea_t fc("", f.start_ea, BADADDR, BADADDR, 0);
    for (std::size_t i = 0; i < fc.blocks.size(); ++i) {
        const qbasic_block_t& qb = fc.blocks[i];
        for (int s : qb.succ) {
            if (s < 0 || static_cast<std::size_t>(s) >= fc.blocks.size()) continue;
            f.loop_edges.emplace_back(qb.start_ea, fc.blocks[s].start_ea);
        }
    }
}

bool is_function_recursive(const IdaFunc& f) {
    for (ea_t ref : code_refs_to(f.start_ea, true))
        if (func_contains(f.start_ea, ref)) return true;
    return false;
}

bool is_basic_block_tight_loop(const IdaBB& bb) {
    ea_t bb_end = prev_head(bb.end_ea, bb.start_ea);
    if (bb_end == BADADDR) return false;
    if (bb.start_ea >= bb_end) return false;
    for (ea_t ref : code_refs_from(bb_end, true))
        if (ref == bb.start_ea) return true;
    return false;
}

// ---------------------------------------------------------------------------
// segments
// ---------------------------------------------------------------------------

std::vector<SegInfo> get_segments(bool skip_header_segments) {
    std::vector<SegInfo> out;
    int n = get_segm_qty();
    for (int i = 0; i < n; ++i) {
        segment_info_t si;
        if (!get_segment_info_by_num(&si, i, GSI_NAME)) continue;
        if (skip_header_segments && si.is_header_segm()) continue;
        SegInfo s;
        s.start_ea = si.start_ea;
        s.end_ea = si.end_ea;
        s.type = si.get_type();
        qstring name;
        si.visible_name(&name);
        s.name = name.c_str();
        out.push_back(std::move(s));
    }
    return out;
}

bool segment_of(ea_t ea, SegInfo& out) {
    segment_info_t si;
    if (!get_segment_info(&si, ea, GSI_NAME)) return false;
    out.start_ea = si.start_ea;
    out.end_ea = si.end_ea;
    out.type = si.get_type();
    qstring name;
    si.visible_name(&name);
    out.name = name.c_str();
    return true;
}

std::vector<std::uint8_t> get_segment_buffer(const SegInfo& seg) {
    // Shrink the request a page at a time until IDA can serve it: a segment may be
    // only partially backed by the input file.
    std::int64_t sz = static_cast<std::int64_t>(seg.end_ea - seg.start_ea);
    while (sz > 0) {
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz));
        if (get_bytes(buf.data(), static_cast<ssize_t>(sz), seg.start_ea) > 0) return buf;
        sz -= 0x1000;
    }
    return {};
}

// ---------------------------------------------------------------------------
// modules
// ---------------------------------------------------------------------------

std::string input_file_path() {
    char path[QMAXPATH] = {};
    if (get_input_file_path(path, sizeof(path)) <= 0) return {};
    return path;
}

bool input_is_minidump() {
    const std::string path = input_file_path();
    return !path.empty() && capa::mdmp::looks_like_minidump(path);
}

namespace {

std::string basename_lower(const std::string& path) {
    std::size_t at = path.find_last_of("\\/");
    return to_lower(at == std::string::npos ? path : path.substr(at + 1));
}

// Does this name look like `debug001`? That is what IDA calls a memory region it
// cannot attribute to any module -- which for a process dump means it was allocated
// at runtime, and is exactly what a memory-forensics pass is looking for.
bool is_debug_segment_name(const std::string& name) {
    if (name.rfind("debug", 0) != 0) return false;
    if (name.size() == 5) return false;
    for (std::size_t i = 5; i < name.size(); ++i)
        if (name[i] < '0' || name[i] > '9') return false;
    return true;
}

// Fallback for when only a basename is known, because no debugger session backs the
// database and the classification has to come off a segment name. Deliberately a
// short list of the modules that are always present in a Windows process rather than
// an attempt to enumerate System32: a name that is not here is treated as the
// sample's, which is the safe way to be wrong.
bool is_known_system_module_name(const std::string& name) {
    static const char* kNames[] = {
        "ntdll.dll",     "kernel32.dll",  "kernelbase.dll", "user32.dll",   "gdi32.dll",
        "gdi32full.dll", "advapi32.dll",  "msvcrt.dll",     "ucrtbase.dll", "sechost.dll",
        "rpcrt4.dll",    "combase.dll",   "ole32.dll",      "oleaut32.dll", "shell32.dll",
        "shlwapi.dll",   "shcore.dll",    "ws2_32.dll",     "wow64.dll",    "wow64cpu.dll",
        "wow64win.dll",  "win32u.dll",    "imm32.dll",      "bcryptprimitives.dll",
        "msvcp_win.dll", "crypt32.dll",   "cryptbase.dll",  "clbcatq.dll",  "psapi.dll",
        "version.dll",   "setupapi.dll",  "cfgmgr32.dll",   "powrprof.dll", "winmm.dll",
    };
    for (const char* n : kNames)
        if (name == n) return true;
    return false;
}

// Modules read straight out of the .dmp IDA was opened on.
//
// This is the case that matters most in practice and the one the debugger list cannot
// serve: a minidump opened as a FILE has no debugger behind it, so `dbg` is null and
// there is no module list to ask for. The dump's own ModuleListStream has exactly what
// is needed -- full path, base and SizeOfImage for every module -- and IDA maps a dump
// at its recorded addresses, so those bases are the database's addresses too.
//
// Verified rather than assumed: if none of the module bases is mapped in the IDB then
// this file is not what this database was built from (or IDA rebased it), and the
// caller falls through to the next source.
std::vector<capa::ModuleEntry> modules_from_input_dump(std::string* why) {
    std::vector<capa::ModuleEntry> out;

    char path[QMAXPATH] = {};
    if (get_input_file_path(path, sizeof(path)) <= 0) {
        if (why) *why = "IDA does not record an input file for this database";
        return out;
    }
    if (!capa::mdmp::looks_like_minidump(path)) {
        if (why) *why = std::string("input file \"") + path + "\" is not a minidump";
        return out;
    }

    try {
        capa::mdmp::Dump dump = capa::mdmp::Dump::open(path);
        for (const capa::mdmp::Module& m : dump.modules()) {
            if (m.size == 0) continue;
            out.push_back({m.base, m.size, m.path, m.name});
        }
    } catch (const std::exception& e) {
        if (why) *why = std::string("could not read \"") + path + "\": " + e.what();
        return {};
    }
    if (out.empty()) {
        if (why) *why = std::string("\"") + path + "\" carries no module list";
        return out;
    }

    // Verified rather than assumed: the dump's addresses only mean something here if
    // the database actually covers that memory.
    //
    // The test is SEGMENT EXISTENCE, deliberately not is_mapped(). is_mapped asks
    // whether the byte at an address has a known value, and IDA creates sparse
    // segments for a dump's larger regions -- so a module can be perfectly well
    // covered by a segment while every probe of its bytes comes back false. Asking the
    // wrong question there fails every module and silently turns the whole filter off.
    std::size_t mapped = 0;
    for (const capa::ModuleEntry& m : out) {
        const ea_t base = static_cast<ea_t>(m.base);
        SegInfo seg;
        if (segment_of(base, seg) || segment_of(base + 0x1000, seg) ||
            segment_of(base + static_cast<ea_t>(m.size / 2), seg))
            ++mapped;
    }
    if (mapped == 0) {
        // Nothing lined up, which for a dump means IDA rebased it. That is recoverable
        // rather than fatal: a rebase shifts the whole address space by one constant,
        // so try the shift that puts the lowest module where the database begins and
        // see whether the rest falls into place.
        std::uint64_t lowest = out.front().base;
        for (const capa::ModuleEntry& m : out) lowest = std::min(lowest, m.base);
        const std::int64_t delta =
            static_cast<std::int64_t>(inf_get_min_ea()) - static_cast<std::int64_t>(lowest);

        std::size_t shifted = 0;
        for (const capa::ModuleEntry& m : out) {
            const ea_t base = static_cast<ea_t>(static_cast<std::int64_t>(m.base) + delta);
            SegInfo seg;
            if (segment_of(base, seg) || segment_of(base + 0x1000, seg)) ++shifted;
        }
        // A majority, not just one: a single accidental hit proves nothing.
        if (delta != 0 && shifted * 2 >= out.size()) {
            for (capa::ModuleEntry& m : out)
                m.base = static_cast<std::uint64_t>(static_cast<std::int64_t>(m.base) + delta);
            if (why) {
                char buf[256];
                qsnprintf(buf, sizeof(buf),
                          "%d module(s) from the input dump, rebased by %+lld (%d "
                          "address-checked)",
                          static_cast<int>(out.size()), static_cast<long long>(delta),
                          static_cast<int>(shifted));
                *why = buf;
            }
            return out;
        }

        // Say so precisely: without the numbers this is indistinguishable from "the
        // feature does not work".
        char buf[512];
        qsnprintf(buf, sizeof(buf),
                  "%d module(s) in \"%s\" but none of their addresses is mapped here "
                  "(dump puts %s at %a; this database starts at %a, ends at %a) -- the "
                  "dump's addresses cannot be used",
                  static_cast<int>(out.size()), path, out.front().name.c_str(),
                  static_cast<ea_t>(out.front().base), inf_get_min_ea(), inf_get_max_ea());
        if (why) *why = buf;
        return {};
    }

    if (why) {
        char buf[256];
        qsnprintf(buf, sizeof(buf), "%d module(s) from the input dump (%d address-checked)",
                  static_cast<int>(out.size()), static_cast<int>(mapped));
        *why = buf;
    }
    return out;
}

// Segment-derived modules, for a database no debugger backs. A segment whose name
// looks like a module file becomes a module; a debugNNN segment becomes Dynamic;
// anything else is left alone.
std::vector<capa::ModuleEntry> modules_from_segments() {
    std::vector<capa::ModuleEntry> out;
    for (const SegInfo& seg : get_segments()) {
        const std::string name = to_lower(seg.name);
        if (is_debug_segment_name(name)) continue;  // Dynamic is the default anyway
        const bool looks_like_module =
            name.size() > 4 &&
            (name.rfind(".dll") == name.size() - 4 || name.rfind(".exe") == name.size() - 4 ||
             name.rfind(".sys") == name.size() - 4 || name.rfind(".drv") == name.size() - 4);
        if (!looks_like_module) continue;

        capa::ModuleEntry m;
        m.base = seg.start_ea;
        m.size = seg.end_ea - seg.start_ea;
        m.path = seg.name;
        m.name = name;
        out.push_back(std::move(m));
    }
    // A segment name carries no path, so the shared path test cannot classify these.
    // Fall back to the well-known names.
    for (capa::ModuleEntry& m : out)
        if (is_known_system_module_name(m.name)) m.cls = capa::ModuleClass::SystemModule;
    return out;
}

std::vector<capa::ModuleEntry> modules_from_debugger() {
    std::vector<capa::ModuleEntry> out;
    // `dbg` is null unless a debugger module is loaded, and get_first_module has
    // nothing to answer with in that case.
    if (dbg == nullptr) return out;
    modinfo_t mi;
    for (bool ok = get_first_module(&mi); ok; ok = get_next_module(&mi)) {
        if (mi.base == BADADDR) continue;
        out.push_back({mi.base, mi.size ? mi.size : 1, mi.name.c_str(), {}});
    }
    return out;
}

}  // namespace

std::vector<ModuleRange> get_process_modules(std::string* why) {
    // In order of how much each source actually knows. The debugger's list has full
    // paths but exists only during a session; the input .dmp has full paths and is
    // what answers for a dump opened as a FILE, which is the common case; segment
    // names are a last resort because they carry no path to classify by.
    std::string dump_why;
    std::vector<capa::ModuleEntry> mods = modules_from_debugger();
    const char* source = "the debugger's module list";
    bool from_segments = false;
    if (!mods.empty() && why) {
        char buf[128];
        qsnprintf(buf, sizeof(buf), "%d module(s) from the debugger", static_cast<int>(mods.size()));
        dump_why = buf;
    }
    if (mods.empty()) {
        mods = modules_from_input_dump(&dump_why);
        source = "the input dump";
    }
    if (mods.empty()) {
        mods = modules_from_segments();
        from_segments = true;
        source = "segment names";
    }
    if (mods.empty()) {
        if (why)
            *why = "no module list: " + dump_why +
                   "; and no segment is named after a module. Nothing will be filtered.";
        return {};
    }

    // Classified by the same code capa-cpp.exe uses, so `--dump-modules` on the same
    // file previews exactly what this filters. Segment-derived entries were already
    // classified by name above and must not be re-tested against a path they lack.
    if (!from_segments) {
        const ea_t image = get_imagebase();
        capa::classify_modules(mods, image == BADADDR ? 0 : static_cast<std::uint64_t>(image));
    }

    std::vector<ModuleRange> out;
    out.reserve(mods.size());
    for (const capa::ModuleEntry& m : mods)
        out.push_back({static_cast<ea_t>(m.base), static_cast<ea_t>(m.base + m.size), m.path,
                       m.name, m.cls});
    std::sort(out.begin(), out.end(),
              [](const ModuleRange& a, const ModuleRange& b) { return a.start_ea < b.start_ea; });

    if (why) {
        std::size_t sys = 0, keep = 0;
        for (const ModuleRange& m : out)
            (m.cls == ModuleClass::SystemModule ? sys : keep)++;
        char buf[512];
        qsnprintf(buf, sizeof(buf), "%s (%s): %d to scan, %d system", dump_why.c_str(), source,
                  static_cast<int>(keep), static_cast<int>(sys));
        *why = buf;
    }
    return out;
}

ModuleClass classify_ea(const std::vector<ModuleRange>& mods, ea_t ea) {
    // the last module with start_ea <= ea
    auto it = std::upper_bound(mods.begin(), mods.end(), ea,
                               [](ea_t v, const ModuleRange& m) { return v < m.start_ea; });
    if (it == mods.begin()) return ModuleClass::Dynamic;
    --it;
    if (ea >= it->end_ea) return ModuleClass::Dynamic;
    return it->cls;
}

// ---------------------------------------------------------------------------
// imports / externs
// ---------------------------------------------------------------------------

namespace {

struct ImportCtx {
    std::map<ea_t, ImportInfo>* imports;
    std::string library;
};

int idaapi inspect_import(ea_t ea, const char* name, uval_t ord, void* param) {
    auto* ctx = static_cast<ImportCtx*>(param);
    std::string function = name ? name : "";

    // mangled PE imports, e.g. "__imp_CreateFileA"
    const std::string imp_prefix = "__imp_";
    if (function.rfind(imp_prefix, 0) == 0) function = function.substr(imp_prefix.size());

    // mangled ELF imports, e.g. "fopen@@glibc_2.2.5"
    std::size_t at = function.find("@@");
    if (at != std::string::npos) function = function.substr(0, at);

    ImportInfo info;
    info.library = to_lower(ctx->library);
    info.function = std::move(function);
    info.ordinal = static_cast<std::int64_t>(ord);
    (*ctx->imports)[ea] = std::move(info);
    return 1;
}

}  // namespace

std::map<ea_t, ImportInfo> get_file_imports() {
    std::map<ea_t, ImportInfo> imports;
    uint n = get_import_module_qty();
    for (uint i = 0; i < n; ++i) {
        qstring modname;
        if (!get_import_module_name(&modname, static_cast<int>(i))) continue;
        if (modname.empty()) continue;

        std::string library = modname.c_str();
        // IDA uses section names as the "library" for ELF imports; those are not
        // useful as a DLL name.
        if (library == ".dynsym") library.clear();

        ImportCtx ctx{&imports, library};
        enum_import_names(static_cast<int>(i), inspect_import, &ctx);
    }
    return imports;
}

std::map<ea_t, ImportInfo> get_file_externs() {
    std::map<ea_t, ImportInfo> externs;
    for (const SegInfo& seg : get_segments(/*skip_header_segments=*/true)) {
        if (seg.type != SEG_XTRN) continue;
        for (ea_t ea : function_eas_in_range(seg.start_ea, seg.end_ea)) {
            ImportInfo info;
            info.function = get_function_name_at(ea);
            info.ordinal = -1;
            externs[ea] = std::move(info);
        }
    }
    return externs;
}

// ---------------------------------------------------------------------------
// instructions and operands
// ---------------------------------------------------------------------------

bool decode_at(ea_t ea, insn_t& out) { return decode_insn(&out, ea) > 0; }

std::vector<insn_t> decode_instructions_in_range(ea_t start, ea_t end) {
    std::vector<insn_t> out;
    for (ea_t head : heads_in_range(start, end)) {
        insn_t insn;
        if (decode_at(head, insn)) out.push_back(insn);
    }
    return out;
}

bool is_operand_equal(const op_t& a, const op_t& b) {
    return a.flags == b.flags && a.dtype == b.dtype && a.type == b.type && a.reg == b.reg &&
           a.phrase == b.phrase && a.value == b.value && a.addr == b.addr;
}

bool is_op_write(const insn_t& insn, const op_t& op) {
    return has_cf_chg(insn.get_canon_feature(PH), op.n);
}

bool is_op_read(const insn_t& insn, const op_t& op) {
    return has_cf_use(insn.get_canon_feature(PH), op.n);
}

bool is_op_offset(const insn_t& insn, const op_t& op) {
    return is_off(get_flags(insn.ea), op.n);
}

bool is_op_stack_var(ea_t ea, int index) { return is_stkvar(get_flags(ea), index); }

namespace {
// iterate the instruction's explicit operands (stop at the first o_void, so we don't
// walk all UA_MAXOP slots).
template <typename F>
void for_each_op(const insn_t& insn, F&& fn) {
    for (int i = 0; i < UA_MAXOP; ++i) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) break;
        fn(i, op);
    }
}
}  // namespace

bool is_sp_modified(const insn_t& insn) {
    bool found = false;
    for_each_op(insn, [&](int, const op_t& op) {
        if (found) return;
        if (op.type != o_reg) return;
        if (op.reg == R_sp && is_op_write(insn, op)) found = true;
    });
    return found;
}

bool is_bp_modified(const insn_t& insn) {
    bool found = false;
    for_each_op(insn, [&](int, const op_t& op) {
        if (found) return;
        if (op.type != o_reg) return;
        if (op.reg == R_bp && is_op_write(insn, op)) found = true;
    });
    return found;
}

bool is_frame_register(int reg) { return reg == R_sp || reg == R_bp; }

bool has_sib(const op_t& op) { return op.specflag1 == 1; }

std::uint64_t mask_op_val(const op_t& op) {
    std::uint64_t mask;
    switch (op.dtype) {
        case dt_byte: mask = 0xFFull; break;
        case dt_word: mask = 0xFFFFull; break;
        case dt_dword: mask = 0xFFFFFFFFull; break;
        case dt_qword: mask = 0xFFFFFFFFFFFFFFFFull; break;
        // capa's dict lookup falls back to the value itself, so `v & v == v`.
        default: return static_cast<std::uint64_t>(op.value);
    }
    return mask & static_cast<std::uint64_t>(op.value);
}

PhraseInfo get_op_phrase_info(const op_t& op) {
    PhraseInfo out;
    if (op.type != o_phrase && op.type != o_displ) return out;

    int scale = 1 << ((op.specflag2 & 0xC0) >> 6);
    // ea_t may be 64-bit, but an x86 displacement is at most 32 bits.
    std::uint64_t offset = static_cast<std::uint64_t>(op.addr) & 0xFFFFFFFFull;

    int index, base;
    if (op.specflag1 == 0) {
        index = -1;
        base = op.reg;
    } else if (op.specflag1 == 1) {
        index = (op.specflag2 & 0x38) >> 3;
        base = (op.specflag2 & 0x07) >> 0;
        if (op.reg == 0xC) {  // REX-extended registers
            if (base & 4) base += 8;
            if (index & 4) index += 8;
        }
    } else {
        return out;
    }

    // `[esp + ...]` (and rsp) sets both index and base to esp even though esp cannot
    // be an index. Drop the bogus index so the offset parses correctly.
    if (index == base && index == R_sp && scale == 1) index = -1;

    out.ok = true;
    out.base = base;
    out.index = index;
    out.scale = scale;
    out.offset = offset;
    return out;
}

std::int64_t idc_operand_value(const insn_t& insn, int n) {
    if (n < 0 || n >= UA_MAXOP) return -1;
    const op_t& op = insn.ops[n];
    switch (op.type) {
        case o_mem:
        case o_far:
        case o_near:
        case o_displ: return static_cast<std::int64_t>(op.addr);
        case o_reg: return op.reg;
        case o_imm: return static_cast<std::int64_t>(op.value);
        case o_phrase: return op.phrase;
        default: return -1;
    }
}

// ---------------------------------------------------------------------------
// memory, names, text
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> read_bytes_at(ea_t ea, std::size_t count) {
    if (!is_loaded(ea)) return {};

    SegInfo seg;
    std::size_t n = count;
    if (segment_of(ea, seg) && ea + count > seg.end_ea)
        n = static_cast<std::size_t>(seg.end_ea - ea);
    if (n == 0) return {};

    std::vector<std::uint8_t> buf(n);
    ssize_t got = get_bytes(buf.data(), static_cast<ssize_t>(n), ea);
    if (got <= 0) return {};
    buf.resize(static_cast<std::size_t>(got));
    return buf;
}

std::string find_string_at(ea_t ea, std::size_t min_len) {
    qstring found;
    if (get_strlit_contents(&found, ea, static_cast<std::size_t>(-1), STRTYPE_C) <= 0) return {};
    std::string s = found.c_str();
    if (s.size() < min_len) return {};

    // must be pure ASCII (Python decodes as ascii and gives up on failure)
    for (unsigned char c : s)
        if (c > 0x7f) return {};

    // IDA's get_strlit_contents reads UTF-16 in ASCII mode as "myy__uunniiccoodde";
    // detect the doubling and undo it.
    if (s.size() >= 3) {
        std::string odd, even;
        for (std::size_t i = 1; i < s.size(); i += 2) odd.push_back(s[i]);
        for (std::size_t i = 2; i < s.size(); i += 2) even.push_back(s[i]);
        if (odd == even) s = std::string(1, s[0]) + odd;
    }
    return s;
}

ea_t find_data_reference_from_insn(const insn_t& insn, int max_depth) {
    int depth = 0;
    ea_t ea = insn.ea;

    for (;;) {
        std::vector<ea_t> refs = data_refs_from(ea);
        // more than one ref means this is not a simple pointer chain
        if (refs.size() != 1) break;
        if (ea == refs[0]) break;         // circular
        if (!is_mapped(refs[0])) break;   // unmapped
        if (++depth > max_depth) break;
        ea = refs[0];
    }
    return ea;
}

std::vector<ea_t> code_refs_from(ea_t ea, bool flow) {
    std::vector<ea_t> out;
    xrefblk_t xb;
    // idautils.CodeRefsFrom(ea, flow): flow=False excludes ordinary fall-through.
    for (bool ok = xb.first_from(ea, flow ? XREF_FLOW : XREF_NOFLOW); ok; ok = xb.next_from()) {
        if (!xb.iscode) continue;
        out.push_back(xb.to);
    }
    return out;
}

std::vector<ea_t> code_refs_to(ea_t ea, bool flow) {
    std::vector<ea_t> out;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, flow ? XREF_FLOW : XREF_NOFLOW); ok; ok = xb.next_to()) {
        if (!xb.iscode) continue;
        out.push_back(xb.from);
    }
    return out;
}

std::vector<ea_t> data_refs_from(ea_t ea) {
    std::vector<ea_t> out;
    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_DATA); ok; ok = xb.next_from()) {
        if (xb.iscode) continue;
        out.push_back(xb.to);
    }
    return out;
}

std::string get_ea_name(ea_t ea) {
    qstring name;
    if (get_name(&name, ea) <= 0) return {};
    return name.c_str();
}

std::string get_function_name_at(ea_t ea) {
    qstring name;
    if (get_func_name(&name, ea) <= 0) return {};
    return name.c_str();
}

std::string disasm_line(ea_t ea) {
    qstring line;
    if (!generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS)) return {};
    return line.c_str();
}

bool has_type_info(ea_t ea) { return has_ti(ea); }

namespace {

// "Alternative name is '<name>'" lines out of a comment.
void find_alternative_names(const std::string& cmt, std::vector<std::string>& out) {
    static const std::string prefix = "Alternative name is '";
    std::size_t pos = 0;
    while (pos <= cmt.size()) {
        std::size_t nl = cmt.find('\n', pos);
        std::string line = cmt.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        // tolerate CRLF comments
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() > prefix.size() && line.rfind(prefix, 0) == 0 && line.back() == '\'')
            out.push_back(line.substr(prefix.size(), line.size() - prefix.size() - 1));
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
}

}  // namespace

std::vector<std::string> get_function_alternative_names(ea_t fva) {
    std::vector<std::string> out;
    qstring cmt;
    if (get_cmt(&cmt, fva, false) > 0) find_alternative_names(cmt.c_str(), out);
    qstring fcmt;
    if (get_func_cmt_ea(&fcmt, fva, false) > 0) find_alternative_names(fcmt.c_str(), out);
    return out;
}

std::vector<ea_t> find_byte_sequence(ea_t start, ea_t end, const std::vector<std::uint8_t>& seq) {
    std::vector<ea_t> out;
    if (seq.empty() || start >= end) return out;
    ea_t at = start;
    for (;;) {
        ea_t ea = bin_search(at, end, seq.data(), nullptr, seq.size(),
                             BIN_SEARCH_FORWARD | BIN_SEARCH_CASE | BIN_SEARCH_NOSHOW);
        if (ea == BADADDR) break;
        out.push_back(ea);
        at = ea + 1;
        if (at >= end) break;
    }
    return out;
}

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

bool is_metapc() { return inf_get_procname() == "metapc"; }
bool is_64bit() { return inf_is_64bit(); }

bool read_pointer_at(ea_t ea, std::uint64_t& out) {
    const int psize = is_64bit() ? 8 : 4;
    if (!is_mapped(ea) || !is_mapped(ea + psize - 1)) return false;
    std::uint8_t buf[8] = {};
    if (get_bytes(buf, psize, ea) != psize) return false;
    std::uint64_t v = 0;
    for (int k = psize - 1; k >= 0; --k) v = (v << 8) | buf[k];
    out = v;
    return true;
}
bool is_32bit() { return inf_is_32bit_exactly(); }

std::string file_type_name() {
    char buf[256] = {0};
    get_file_type_name(buf, sizeof(buf));
    return buf;
}

namespace {
std::string to_hex(const uchar* p, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(digits[p[i] >> 4]);
        s.push_back(digits[p[i] & 0xf]);
    }
    return s;
}
}  // namespace

std::string input_file_md5() {
    uchar hash[16] = {0};
    if (!retrieve_input_file_md5(hash)) return {};
    return to_hex(hash, sizeof(hash));
}

std::string input_file_sha256() {
    uchar hash[32] = {0};
    if (!retrieve_input_file_sha256(hash)) return {};
    return to_hex(hash, sizeof(hash));
}

}  // namespace capa::ida
