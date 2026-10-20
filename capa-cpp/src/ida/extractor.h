// IDA Pro feature extractor for capa-cpp.
//
// Ports capa/features/extractors/ida/extractor.py: a StaticFeatureExtractor backed by
// the database IDA currently has open. Only usable in-process (a plugin), since every
// call goes through the SDK against the open IDB.
//
// Ownership: the handles the driver receives point into `funcs_`, a deque so that
// growing it never moves existing elements. Blocks and their decoded instructions are
// built lazily, the first time a function's basic blocks are asked for.
#pragma once

#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "address.h"
#include "feature.h"
#include "feature_extractor.h"
#include "ida/helpers.h"
#include "minidump/process.h"

namespace capa::ida {

class IdaExtractor : public StaticFeatureExtractor {
public:
    // `skip_system_modules` drops functions that live in a Windows system module, and
    // only in a database opened on a minidump: a dump holds the whole address space,
    // and ntdll's and kernel32's capabilities describe Windows, not the sample. The
    // main executable, other modules, and unbacked runtime-allocated memory (IDA's
    // debugNNN segments) are always scanned. Any other database is scanned whole, as
    // capa's IDA backend does, whatever this says. Off by default for the same reason.
    explicit IdaExtractor(bool skip_system_modules = false);

    Address get_base_address() const override { return Address::absolute(base_); }
    const SampleHashes& get_sample_hashes() const override { return hashes_; }

    const std::vector<FeaturePair>& extract_global_features() const override {
        return global_features_;
    }
    std::vector<FeaturePair> extract_file_features() const override;

    std::vector<FunctionHandle> get_functions() const override;
    std::vector<FeaturePair> extract_function_features(const FunctionHandle& fh) const override;

    std::vector<BBHandle> get_basic_blocks(const FunctionHandle& fh) const override;
    std::vector<FeaturePair> extract_basic_block_features(const FunctionHandle& fh,
                                                          const BBHandle& bbh) const override;

    std::vector<InsnHandle> get_instructions(const FunctionHandle& fh,
                                             const BBHandle& bbh) const override;
    std::vector<FeaturePair> extract_insn_features(const FunctionHandle& fh, const BBHandle& bbh,
                                                   const InsnHandle& ih) const override;

    // Import / extern tables, built once. capa's Python rebuilds these per function
    // (its per-function `ctx` dict starts empty), which is a cost, not a semantic.
    const std::map<ea_t, ImportInfo>& imports() const { return imports_; }
    const std::map<ea_t, ImportInfo>& externs() const { return externs_; }

    // Export and import-slot names read from the .dmp this database was opened on, or
    // an empty map when the input is not a dump.
    //
    // IDA parses no PE import directory for a memory image and knows no export names
    // for it, so its own api: resolution -- import table, extern segment, FLIRT-named
    // call target -- has nothing to work with and every `call [rip+0x1234]` stays
    // anonymous. That silently disables the ~500 capa rules written against `api:`,
    // which is most of the rule set. The dump's module headers still have the tables.
    const capa::mdmp::SymbolMap& dump_symbols() const { return dump_symbols_; }
    bool has_dump_symbols() const { return dump_symbols_.export_count() > 0; }
    // Whether the database was opened on a minidump, judged from the input file
    // itself rather than from IDA's name for its loader.
    bool is_dump() const { return is_dump_; }
    // Whether the system-module filter is in effect: asked for, and a dump.
    bool filters_system_modules() const { return skip_system_modules_ && is_dump_; }

    // What the system-module filter left out, so the caller can say so rather than
    // leaving the user to wonder why a 200-module dump reported four functions.
    const std::vector<ModuleRange>& modules() const { return modules_; }
    // One line describing which source the module list came from and what it found,
    // or why there is none. Always worth printing: a filter nobody can see is a filter
    // nobody can tell is broken.
    const std::string& modules_note() const { return modules_note_; }
    std::size_t skipped_system_functions() const { return skipped_system_functions_; }
    // Distinct system modules that actually held at least one skipped function.
    std::vector<std::string> skipped_system_modules() const;

private:
    IdaFunc& func_at(ea_t ea) const;

    std::uint64_t base_ = 0;
    bool skip_system_modules_ = false;
    bool is_dump_ = false;
    std::vector<ModuleRange> modules_;
    std::string modules_note_;
    capa::mdmp::SymbolMap dump_symbols_;
    mutable std::size_t skipped_system_functions_ = 0;
    mutable std::vector<std::string> skipped_system_names_;
    SampleHashes hashes_;
    std::vector<FeaturePair> global_features_;

    std::map<ea_t, ImportInfo> imports_;
    std::map<ea_t, ImportInfo> externs_;

    // deque: handles hold pointers to these, and get_functions() may be called more
    // than once, so elements must never move.
    mutable std::deque<IdaFunc> funcs_;
    mutable std::unordered_map<ea_t, IdaFunc*> funcs_by_ea_;
};

// ---- per-scope handlers (one file each, mirroring capa's module layout) ----

// ida/global_.cpp
void extract_global_features(std::vector<FeaturePair>& out, bool is_dump);
// ida/file.cpp
void extract_file_features(std::vector<FeaturePair>& out);
// ida/function.cpp
void extract_function_features(IdaFunc& f, std::vector<FeaturePair>& out);
// ida/basicblock.cpp
void extract_basic_block_features(const IdaFunc& f, const IdaBB& bb,
                                  std::vector<FeaturePair>& out);
// ida/insn.cpp
void extract_insn_features(const IdaExtractor& ex, const IdaFunc& f, const IdaBB& bb,
                           const insn_t& insn, std::vector<FeaturePair>& out);

}  // namespace capa::ida
