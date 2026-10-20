// IDA SDK glue for capa-cpp's IDA backend.
//
// Ports capa/features/extractors/ida/helpers.py. Everything that touches the SDK
// directly lives here; the per-scope feature handlers (ida/file.cpp, ida/insn.cpp, ...)
// are written against these.
//
// Where capa's Python scrapes the disassembly text or works around an IDA quirk, this
// port does the same thing rather than a cleaner equivalent — matching Python capa's
// output is the point, and those hacks change which features fire.
//
// Written against SDK 9.4, which deprecated the func_t*/segment_t* pointer API in
// favour of ea_t-based accessors and value-type info structs. This uses the new API.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ida/sdk.h"
#include "module_filter.h"

namespace capa::ida {

// ---------------------------------------------------------------------------
// code model
//
// The extractor owns these; handles point into them. A basic block's `insns` are
// decoded once, when the block is built.
// ---------------------------------------------------------------------------

struct IdaBB {
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    fc_block_type_t type = fcb_normal;
    std::vector<int> succs;
    std::vector<int> preds;
    std::vector<insn_t> insns;

    ea_t size() const { return end_ea - start_ea; }
    bool is_return() const { return type == fcb_ret; }
};

struct IdaFunc {
    ea_t start_ea = BADADDR;
    std::uint64_t flags = 0;
    std::vector<IdaBB> blocks;
    bool blocks_built = false;
    // CFG edges from a *default-flags* flow chart. capa's extract_function_loop uses
    // FlowChart(f) while get_basic_blocks uses FC_NOEXT, so the two graphs differ and
    // the loop test has to see the wider one.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> loop_edges;
    bool loop_edges_built = false;
};

// ---------------------------------------------------------------------------
// functions
// ---------------------------------------------------------------------------

// Function entry addresses, in address order (idautils.Functions).
std::vector<ea_t> all_function_eas();
std::vector<ea_t> function_eas_in_range(ea_t start, ea_t end);

std::uint64_t get_func_flags_at(ea_t ea);   // 0 if `ea` is not in a function
ea_t func_start_of(ea_t ea);                // BADADDR if `ea` is not in a function
bool func_contains(ea_t func_ea, ea_t ea);

// Fill `blocks` from the function's flow chart (FC_NOEXT, as capa's
// get_function_blocks does) and decode each block's instructions.
void build_function_blocks(IdaFunc& f);
// Fill `loop_edges` from a default-flags flow chart.
void build_function_loop_edges(IdaFunc& f);

bool is_function_recursive(const IdaFunc& f);
bool is_basic_block_tight_loop(const IdaBB& bb);

// ---------------------------------------------------------------------------
// segments
// ---------------------------------------------------------------------------

struct SegInfo {
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    uchar type = 0;
    std::string name;
};

std::vector<SegInfo> get_segments(bool skip_header_segments = false);
// Segment contents; shrinks the request by a page at a time until IDA can serve it,
// exactly as capa's get_segment_buffer does. Empty if nothing could be read.
std::vector<std::uint8_t> get_segment_buffer(const SegInfo& seg);
// The segment containing `ea`, or nullopt-ish: returns false when there is none.
bool segment_of(ea_t ea, SegInfo& out);

// ---------------------------------------------------------------------------
// modules
// ---------------------------------------------------------------------------
//
// A database opened over a process dump or a live debug session holds the whole
// address space: the sample, every DLL Windows loaded behind it, and whatever was
// allocated at runtime. capa has no reason to report ntdll's capabilities as if they
// were the sample's, so the extractor needs to know which is which.

// The classification itself is shared with capa-cpp.exe (see module_filter.h) so the
// two backends cannot drift: `capa-cpp <dump> --dump-modules` prints exactly what this
// plugin will filter.
using ModuleClass = capa::ModuleClass;
using capa::module_class_name;

struct ModuleRange {
    ea_t start_ea = BADADDR;
    ea_t end_ea = BADADDR;
    std::string path;  // as the source reports it; may be a bare name
    std::string name;  // lowercased basename
    ModuleClass cls = ModuleClass::Module;
};

// Every module backing this database, sorted by base and classified.
//
// Prefers the debugger's module list, which carries full paths and so can be
// classified exactly. Falls back to segment names when no debugger backs the
// database, which is less certain -- a bare `kernel32.dll` has no path to test, so it
// is matched against the well-known system module names instead. Empty when neither
// source says anything, in which case nothing is filtered.
// `why`, when given, receives a one-line account of which source answered and what it
// found -- including why a source that should have answered did not. The filter is
// invisible when it works and indistinguishable from a no-op when it does not, so it
// has to be able to explain itself.
std::vector<ModuleRange> get_process_modules(std::string* why = nullptr);

// Which kind of memory `ea` is in. Anything outside every known module is Dynamic:
// that is the unbacked, runtime-allocated memory a dump's debugNNN segments hold, and
// it is the most interesting thing in the database, not the least.
ModuleClass classify_ea(const std::vector<ModuleRange>& mods, ea_t ea);

// The file this database was built from, "" if IDA does not know. For a dump opened
// directly this is the .dmp, which is where the module list comes from.
std::string input_file_path();

// Whether this database was opened on a Windows minidump, judged from the input
// file's own header rather than from IDA's name for the loader.
bool input_is_minidump();

// ---------------------------------------------------------------------------
// imports / externs
// ---------------------------------------------------------------------------

struct ImportInfo {
    std::string library;  // lowercased; "" for ELF ".dynsym" and for externs
    std::string function;
    std::int64_t ordinal = 0;  // -1 for externs, as capa uses
};

std::map<ea_t, ImportInfo> get_file_imports();
std::map<ea_t, ImportInfo> get_file_externs();

// ---------------------------------------------------------------------------
// instructions and operands
// ---------------------------------------------------------------------------

std::vector<insn_t> decode_instructions_in_range(ea_t start, ea_t end);
bool decode_at(ea_t ea, insn_t& out);

bool is_operand_equal(const op_t& a, const op_t& b);
bool is_op_write(const insn_t& insn, const op_t& op);
bool is_op_read(const insn_t& insn, const op_t& op);
bool is_op_offset(const insn_t& insn, const op_t& op);
bool is_op_stack_var(ea_t ea, int index);
bool is_sp_modified(const insn_t& insn);
bool is_bp_modified(const insn_t& insn);
bool is_frame_register(int reg);
bool has_sib(const op_t& op);

// Mask an immediate by its data type. Works around an IDA AMD64 bug where a dword
// immediate of 0xFFFFFFFF is reported as 0xFFFFFFFFFFFFFFFF.
std::uint64_t mask_op_val(const op_t& op);

struct PhraseInfo {
    bool ok = false;
    int base = 0;
    int index = -1;  // -1 == none
    int scale = 1;
    std::uint64_t offset = 0;
};

// Decode the SIB/displacement of an o_phrase / o_displ operand (Sark-derived, same as
// capa's get_op_phrase_info, including the `[esp + ...]` special case).
PhraseInfo get_op_phrase_info(const op_t& op);

// IDC get_operand_value(ea, n) semantics, which capa's `call $+5` check relies on.
std::int64_t idc_operand_value(const insn_t& insn, int n);

// ---------------------------------------------------------------------------
// memory, names, text
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> read_bytes_at(ea_t ea, std::size_t count);
// An ASCII string literal at `ea`, or "". Includes capa's fix-up for IDA returning
// UTF-16 read in ASCII mode as "myy__uunniiccoodde".
std::string find_string_at(ea_t ea, std::size_t min_len = 4);
// Follow single data references from an instruction; returns insn.ea if there is none.
ea_t find_data_reference_from_insn(const insn_t& insn, int max_depth = 10);

std::vector<ea_t> code_refs_from(ea_t ea, bool flow);
std::vector<ea_t> code_refs_to(ea_t ea, bool flow);
std::vector<ea_t> data_refs_from(ea_t ea);

std::string get_ea_name(ea_t ea);
std::string get_function_name_at(ea_t ea);
// idc.GetDisasm(ea): the disassembly line with colour tags removed.
std::string disasm_line(ea_t ea);
// True when `ea` carries type information (IDC get_type would return non-None).
bool has_type_info(ea_t ea);

// Alternative names recorded as "Alternative name is '<name>'" in an address or
// function comment. A fork-specific extension: ida-ttd writes these when it recovers
// symbols from a trace, and capa turns them into FunctionName/API features.
std::vector<std::string> get_function_alternative_names(ea_t fva);

// Every address in [start, end) where `seq` occurs.
std::vector<ea_t> find_byte_sequence(ea_t start, ea_t end, const std::vector<std::uint8_t>& seq);

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

bool is_metapc();       // the x86/x64 processor module; capa supports no other
bool is_64bit();

// Read a pointer-width little-endian value from the database. False if `ea` is not
// mapped. Width follows the database's bitness, which for a process dump is the
// process's.
bool read_pointer_at(ea_t ea, std::uint64_t& out);
bool is_32bit();
std::string file_type_name();
std::string input_file_md5();
std::string input_file_sha256();

}  // namespace capa::ida
