// Feature extractors over features someone else already extracted.
//
// Ports capa/features/extractors/null.py. A NullStaticFeatureExtractor or
// NullDynamicFeatureExtractor is filled with features -- from a freeze file (freeze.h),
// or by a test that writes them out by hand -- and replays them to the capabilities
// drivers exactly as a live backend would. This is what makes the engine usable, and
// testable, with no analysis backend at all.
//
// Like capa's, every scope's children come back sorted by address, and each scope's
// features in the order they were given.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "feature_extractor.h"

namespace capa {

struct NullInstruction {
    std::vector<FeaturePair> features;
};

struct NullBasicBlock {
    std::vector<FeaturePair> features;
    std::map<Address, NullInstruction> instructions;
};

struct NullFunction {
    std::vector<FeaturePair> features;
    std::map<Address, NullBasicBlock> basic_blocks;
};

class NullStaticFeatureExtractor final : public StaticFeatureExtractor {
public:
    Address base_address;
    SampleHashes sample_hashes;
    std::vector<FeaturePair> global_features;  // all at NO_ADDRESS
    std::vector<FeaturePair> file_features;
    std::map<Address, NullFunction> functions;

    Address get_base_address() const override { return base_address; }
    const SampleHashes& get_sample_hashes() const override { return sample_hashes; }
    const std::vector<FeaturePair>& extract_global_features() const override { return global_features; }
    std::vector<FeaturePair> extract_file_features() const override { return file_features; }

    std::vector<FunctionHandle> get_functions() const override;
    std::vector<FeaturePair> extract_function_features(const FunctionHandle& fh) const override;
    std::vector<BBHandle> get_basic_blocks(const FunctionHandle& fh) const override;
    std::vector<FeaturePair> extract_basic_block_features(const FunctionHandle& fh,
                                                          const BBHandle& bbh) const override;
    std::vector<InsnHandle> get_instructions(const FunctionHandle& fh,
                                             const BBHandle& bbh) const override;
    std::vector<FeaturePair> extract_insn_features(const FunctionHandle& fh, const BBHandle& bbh,
                                                   const InsnHandle& ih) const override;
};

struct NullCall {
    std::string name;
    std::vector<FeaturePair> features;
};

struct NullThread {
    std::vector<FeaturePair> features;
    std::map<Address, NullCall> calls;
};

struct NullProcess {
    std::string name;
    std::vector<FeaturePair> features;
    std::map<Address, NullThread> threads;
};

class NullDynamicFeatureExtractor final : public DynamicFeatureExtractor {
public:
    Address base_address;
    SampleHashes sample_hashes;
    std::vector<FeaturePair> global_features;  // all at NO_ADDRESS
    std::vector<FeaturePair> file_features;
    std::map<Address, NullProcess> processes;

    Address get_base_address() const override { return base_address; }
    const SampleHashes& get_sample_hashes() const override { return sample_hashes; }
    const std::vector<FeaturePair>& extract_global_features() const override { return global_features; }
    std::vector<FeaturePair> extract_file_features() const override { return file_features; }

    std::vector<ProcessHandle> get_processes() const override;
    std::vector<FeaturePair> extract_process_features(const ProcessHandle& ph) const override;
    std::string get_process_name(const ProcessHandle& ph) const override;
    std::vector<ThreadHandle> get_threads(const ProcessHandle& ph) const override;
    std::vector<FeaturePair> extract_thread_features(const ProcessHandle& ph,
                                                     const ThreadHandle& th) const override;
    std::size_t call_count(const ProcessHandle& ph, const ThreadHandle& th) const override;
    CallHandle call_at(const ProcessHandle& ph, const ThreadHandle& th,
                       std::size_t idx) const override;
    std::vector<FeaturePair> extract_call_features(const ProcessHandle& ph, const ThreadHandle& th,
                                                   const CallHandle& ch) const override;
    std::string get_call_name(const ProcessHandle& ph, const ThreadHandle& th,
                              const CallHandle& ch) const override;

    // call_at is indexed; this flattens each thread's calls once, after the extractor is
    // filled in. Called by the freeze loader; call it again after editing `processes`.
    void index_calls();

private:
    std::map<Address, std::vector<std::pair<Address, const NullCall*>>> calls_by_thread_;
};

}  // namespace capa
