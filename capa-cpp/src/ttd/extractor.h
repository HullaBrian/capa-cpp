// TTD dynamic feature extractor for capa-cpp.
//
// Ports capa/features/extractors/ttd/{extractor,file,process,thread,call,global_,
// helpers}.py. Consumes a parsed ttd::Report and yields capa Features per scope.
//
// Implements capa's DynamicFeatureExtractor interface (feature_extractor.h), so the
// backend-neutral dynamic capabilities driver runs over it exactly as it runs over a
// freeze file or any other dynamic backend.
#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"
#include "feature_extractor.h"
#include "ttd/models.h"

namespace capa::ttd {

using capa::CallHandle;
using capa::FeaturePair;
using capa::ProcessHandle;
using capa::ThreadHandle;

// ProcessHandle::inner points at the ttd::Process; CallHandle::inner at the ttd::Call.
class TtdExtractor final : public DynamicFeatureExtractor {
public:
    static constexpr int CURRENT_VERSION = 1;

    explicit TtdExtractor(Report report);

    // sample hashes
    const std::string& md5() const { return report_.sample.md5; }
    const std::string& sha1() const { return report_.sample.sha1; }
    const std::string& sha256() const { return report_.sample.sha256; }
    const Report& report() const { return report_; }
    const SampleHashes& get_sample_hashes() const override { return hashes_; }

    const std::vector<FeaturePair>& extract_global_features() const override {
        return global_features_;
    }
    std::vector<FeaturePair> extract_file_features() const override;

    std::vector<ProcessHandle> get_processes() const override;
    std::vector<FeaturePair> extract_process_features(const ProcessHandle& ph) const override;
    std::string get_process_name(const ProcessHandle& ph) const override;

    std::vector<ThreadHandle> get_threads(const ProcessHandle& ph) const override;
    std::vector<FeaturePair> extract_thread_features(const ProcessHandle& ph,
                                                     const ThreadHandle& th) const override;

    // The calls are handed out one at a time rather than as a vector: a handle per call
    // in the thread -- forty bytes each, and the whole vector live before the first call
    // is looked at -- is, on a trace with millions of calls in one thread, hundreds of
    // megabytes held to iterate a list the caller only ever walks forwards.
    std::size_t call_count(const ProcessHandle& ph, const ThreadHandle& th) const override;
    // `idx` must be below call_count for the same handles; out of range yields an empty
    // handle, which extract_call_features reads as a call with no features.
    CallHandle call_at(const ProcessHandle& ph, const ThreadHandle& th,
                       std::size_t idx) const override;
    std::vector<FeaturePair> extract_call_features(const ProcessHandle& ph,
                                                   const ThreadHandle& th,
                                                   const CallHandle& ch) const override;
    std::string get_call_name(const ProcessHandle& ph, const ThreadHandle& th,
                              const CallHandle& ch) const override;

    // The call's TTD position and return position, for --top-level-calls.
    std::optional<CallSpan> get_call_span(const ProcessHandle& ph, const ThreadHandle& th,
                                          const CallHandle& ch) const override;

private:
    struct ThreadEntry {
        Address address;
        std::vector<const Call*> calls;  // sorted by seq
    };
    struct ProcEntry {
        Address address;
        const Process* proc = nullptr;
        std::vector<ThreadEntry> threads;  // insertion order (declared then discovered)
    };

    const ProcEntry* find_proc(const Address& addr) const;
    const ThreadEntry* find_thread(const ProcEntry& pe, const Address& addr) const;

    Report report_;
    SampleHashes hashes_;
    std::vector<FeaturePair> global_features_;
    std::vector<ProcEntry> procs_;
};

}  // namespace capa::ttd
