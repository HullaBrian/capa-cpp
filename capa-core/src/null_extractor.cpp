#include "null_extractor.h"

namespace capa {

// ---- static ----
//
// Handles carry a pointer to the scope's record, so a lookup happens once per handle
// rather than once per call to an extract_* method.

std::vector<FunctionHandle> NullStaticFeatureExtractor::get_functions() const {
    std::vector<FunctionHandle> out;
    out.reserve(functions.size());
    for (const auto& [addr, f] : functions) out.push_back(FunctionHandle{addr, &f});
    return out;
}

std::vector<FeaturePair> NullStaticFeatureExtractor::extract_function_features(
    const FunctionHandle& fh) const {
    return static_cast<const NullFunction*>(fh.inner)->features;
}

std::vector<BBHandle> NullStaticFeatureExtractor::get_basic_blocks(const FunctionHandle& fh) const {
    std::vector<BBHandle> out;
    for (const auto& [addr, bb] : static_cast<const NullFunction*>(fh.inner)->basic_blocks)
        out.push_back(BBHandle{addr, &bb});
    return out;
}

std::vector<FeaturePair> NullStaticFeatureExtractor::extract_basic_block_features(
    const FunctionHandle&, const BBHandle& bbh) const {
    return static_cast<const NullBasicBlock*>(bbh.inner)->features;
}

std::vector<InsnHandle> NullStaticFeatureExtractor::get_instructions(const FunctionHandle&,
                                                                     const BBHandle& bbh) const {
    std::vector<InsnHandle> out;
    for (const auto& [addr, insn] : static_cast<const NullBasicBlock*>(bbh.inner)->instructions)
        out.push_back(InsnHandle{addr, &insn});
    return out;
}

std::vector<FeaturePair> NullStaticFeatureExtractor::extract_insn_features(
    const FunctionHandle&, const BBHandle&, const InsnHandle& ih) const {
    return static_cast<const NullInstruction*>(ih.inner)->features;
}

// ---- dynamic ----

std::vector<ProcessHandle> NullDynamicFeatureExtractor::get_processes() const {
    std::vector<ProcessHandle> out;
    for (const auto& [addr, p] : processes) out.push_back(ProcessHandle{addr, &p});
    return out;
}

std::vector<FeaturePair> NullDynamicFeatureExtractor::extract_process_features(
    const ProcessHandle& ph) const {
    return static_cast<const NullProcess*>(ph.inner)->features;
}

std::string NullDynamicFeatureExtractor::get_process_name(const ProcessHandle& ph) const {
    return static_cast<const NullProcess*>(ph.inner)->name;
}

std::vector<ThreadHandle> NullDynamicFeatureExtractor::get_threads(const ProcessHandle& ph) const {
    std::vector<ThreadHandle> out;
    for (const auto& [addr, t] : static_cast<const NullProcess*>(ph.inner)->threads)
        out.push_back(ThreadHandle{addr, &t});
    return out;
}

std::vector<FeaturePair> NullDynamicFeatureExtractor::extract_thread_features(
    const ProcessHandle&, const ThreadHandle& th) const {
    return static_cast<const NullThread*>(th.inner)->features;
}

void NullDynamicFeatureExtractor::index_calls() {
    calls_by_thread_.clear();
    for (const auto& [paddr, p] : processes)
        for (const auto& [taddr, t] : p.threads) {
            auto& calls = calls_by_thread_[taddr];
            for (const auto& [caddr, c] : t.calls) calls.emplace_back(caddr, &c);
        }
}

std::size_t NullDynamicFeatureExtractor::call_count(const ProcessHandle&,
                                                    const ThreadHandle& th) const {
    auto it = calls_by_thread_.find(th.address);
    return it == calls_by_thread_.end() ? 0 : it->second.size();
}

CallHandle NullDynamicFeatureExtractor::call_at(const ProcessHandle&, const ThreadHandle& th,
                                                std::size_t idx) const {
    auto it = calls_by_thread_.find(th.address);
    if (it == calls_by_thread_.end() || idx >= it->second.size()) return {};
    return CallHandle{it->second[idx].first, it->second[idx].second};
}

std::vector<FeaturePair> NullDynamicFeatureExtractor::extract_call_features(
    const ProcessHandle&, const ThreadHandle&, const CallHandle& ch) const {
    const auto* call = static_cast<const NullCall*>(ch.inner);
    return call ? call->features : std::vector<FeaturePair>{};
}

std::string NullDynamicFeatureExtractor::get_call_name(const ProcessHandle&, const ThreadHandle&,
                                                       const CallHandle& ch) const {
    const auto* call = static_cast<const NullCall*>(ch.inner);
    return call ? call->name : std::string();
}

}  // namespace capa
