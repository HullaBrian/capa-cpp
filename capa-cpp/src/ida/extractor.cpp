#include "ida/extractor.h"

namespace capa::ida {

IdaExtractor::IdaExtractor(bool skip_system_modules)
    : skip_system_modules_(skip_system_modules) {
    base_ = static_cast<std::uint64_t>(get_imagebase());
    // Built once: get_functions() may be called more than once, and enumerating the
    // debugger's module list is not free.
    modules_ = get_process_modules(&modules_note_);
    msg("capa: modules: %s\n", modules_note_.c_str());

    // If this database was opened on a .dmp, read the module export and import tables
    // out of it. Without them `api:` resolves to nothing here; see dump_symbols().
    const std::string input = dump_input_path();
    is_dump_ = !input.empty();
    if (is_dump_) {
        try {
            dump_symbols_ = capa::mdmp::build_symbol_map(capa::mdmp::Dump::open(input));
            msg("capa: read %zu export(s) and %zu import slot(s) from %s\n",
                dump_symbols_.export_count(), dump_symbols_.import_count(), input.c_str());
        } catch (const std::exception& e) {
            // Not fatal: analysis still runs, it just cannot name APIs.
            msg("capa: could not read symbols from %s (%s); api: features will be "
                "limited to what IDA itself named.\n",
                input.c_str(), e.what());
        }
    }
    hashes_.md5 = input_file_md5();
    hashes_.sha1 = "(unknown)";  // IDA does not record a SHA-1 of the input
    hashes_.sha256 = input_file_sha256();

    // qualified: the class has a same-named member that would otherwise hide this
    ida::extract_global_features(global_features_, is_dump_);

    // Built once here rather than per function: capa's Python rebuilds them for every
    // function because each FunctionHandle carries a fresh `ctx` dict.
    imports_ = get_file_imports();
    externs_ = get_file_externs();
}

std::vector<FeaturePair> IdaExtractor::extract_file_features() const {
    std::vector<FeaturePair> out;
    ida::extract_file_features(out);
    return out;
}

IdaFunc& IdaExtractor::func_at(ea_t ea) const {
    auto it = funcs_by_ea_.find(ea);
    if (it != funcs_by_ea_.end()) return *it->second;

    IdaFunc f;
    f.start_ea = ea;
    f.flags = get_func_flags_at(ea);
    funcs_.push_back(std::move(f));
    IdaFunc* p = &funcs_.back();
    funcs_by_ea_[ea] = p;
    return *p;
}

std::vector<FunctionHandle> IdaExtractor::get_functions() const {
    std::vector<FunctionHandle> out;
    skipped_system_functions_ = 0;
    skipped_system_names_.clear();
    for (ea_t ea : all_function_eas()) {
        std::uint64_t flags = get_func_flags_at(ea);
        // skip thunks and library functions, as capa's IdaFeatureExtractor does
        if (flags & (FUNC_THUNK | FUNC_LIB)) continue;

        // Windows' own code, when the database covers a whole process. Note what was
        // dropped and where, so the caller can report it -- a filter that silently
        // removes most of the database is worse than no filter.
        if (filters_system_modules() && !modules_.empty() &&
            classify_ea(modules_, ea) == ModuleClass::SystemModule) {
            ++skipped_system_functions_;
            auto it = std::upper_bound(
                modules_.begin(), modules_.end(), ea,
                [](ea_t v, const ModuleRange& m) { return v < m.start_ea; });
            if (it != modules_.begin()) {
                const std::string& n = (--it)->name;
                if (std::find(skipped_system_names_.begin(), skipped_system_names_.end(), n) ==
                    skipped_system_names_.end())
                    skipped_system_names_.push_back(n);
            }
            continue;
        }

        IdaFunc& f = func_at(ea);
        out.push_back({Address::absolute(static_cast<std::uint64_t>(ea)), &f});
    }
    return out;
}

std::vector<std::string> IdaExtractor::skipped_system_modules() const {
    std::vector<std::string> out = skipped_system_names_;
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<FeaturePair> IdaExtractor::extract_function_features(const FunctionHandle& fh) const {
    // const_cast: the loop-edge cache is filled on demand; the database is untouched.
    IdaFunc& f = *const_cast<IdaFunc*>(static_cast<const IdaFunc*>(fh.inner));
    std::vector<FeaturePair> out;
    ida::extract_function_features(f, out);
    return out;
}

std::vector<BBHandle> IdaExtractor::get_basic_blocks(const FunctionHandle& fh) const {
    IdaFunc& f = *const_cast<IdaFunc*>(static_cast<const IdaFunc*>(fh.inner));
    build_function_blocks(f);

    std::vector<BBHandle> out;
    out.reserve(f.blocks.size());
    for (const IdaBB& bb : f.blocks)
        out.push_back({Address::absolute(static_cast<std::uint64_t>(bb.start_ea)), &bb});
    return out;
}

std::vector<FeaturePair> IdaExtractor::extract_basic_block_features(const FunctionHandle& fh,
                                                                    const BBHandle& bbh) const {
    std::vector<FeaturePair> out;
    ida::extract_basic_block_features(*static_cast<const IdaFunc*>(fh.inner),
                                      *static_cast<const IdaBB*>(bbh.inner), out);
    return out;
}

std::vector<InsnHandle> IdaExtractor::get_instructions(const FunctionHandle&,
                                                       const BBHandle& bbh) const {
    const IdaBB& bb = *static_cast<const IdaBB*>(bbh.inner);
    std::vector<InsnHandle> out;
    out.reserve(bb.insns.size());
    for (const insn_t& insn : bb.insns)
        out.push_back({Address::absolute(static_cast<std::uint64_t>(insn.ea)), &insn});
    return out;
}

std::vector<FeaturePair> IdaExtractor::extract_insn_features(const FunctionHandle& fh,
                                                             const BBHandle& bbh,
                                                             const InsnHandle& ih) const {
    std::vector<FeaturePair> out;
    ida::extract_insn_features(*this, *static_cast<const IdaFunc*>(fh.inner),
                               *static_cast<const IdaBB*>(bbh.inner),
                               *static_cast<const insn_t*>(ih.inner), out);
    return out;
}

}  // namespace capa::ida
