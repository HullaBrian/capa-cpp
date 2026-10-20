// Backend-neutral feature-extractor interfaces for capa-cpp.
//
// Ports capa/features/extractors/base_extractor.py: the handle types and the
// StaticFeatureExtractor / DynamicFeatureExtractor abstract bases that every backend
// implements. The capabilities drivers (static_caps.h, capabilities.h) and the result
// document only ever see these interfaces, which is what lets the core library run
// with no analysis backend at all (see null_extractor.h and freeze.h).
//
// A handle is an address plus an opaque `inner` pointer the backend owns; it stands
// in for Python's `dataclass(address, inner: Any)`. The pointee must outlive every
// handle the backend hands out — in practice each backend keeps its own stable
// storage (a Workspace, a deque of per-function records) and points into it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"

namespace capa {

// One extracted feature and where it was found.
using FeaturePair = std::pair<Feature, Address>;

struct SampleHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

struct FunctionHandle {
    Address address;
    const void* inner = nullptr;
};

struct BBHandle {
    Address address;
    const void* inner = nullptr;
};

struct InsnHandle {
    Address address;
    const void* inner = nullptr;
};

class StaticFeatureExtractor {
public:
    virtual ~StaticFeatureExtractor() = default;

    virtual Address get_base_address() const = 0;
    virtual const SampleHashes& get_sample_hashes() const = 0;

    // Global features are yielded at every scope, including once per instruction, so
    // they are precomputed and handed out by reference rather than rebuilt each time.
    virtual const std::vector<FeaturePair>& extract_global_features() const = 0;
    virtual std::vector<FeaturePair> extract_file_features() const = 0;

    virtual std::vector<FunctionHandle> get_functions() const = 0;
    virtual std::vector<FeaturePair> extract_function_features(const FunctionHandle& fh) const = 0;

    virtual std::vector<BBHandle> get_basic_blocks(const FunctionHandle& fh) const = 0;
    virtual std::vector<FeaturePair> extract_basic_block_features(const FunctionHandle& fh,
                                                                  const BBHandle& bbh) const = 0;

    virtual std::vector<InsnHandle> get_instructions(const FunctionHandle& fh,
                                                     const BBHandle& bbh) const = 0;
    virtual std::vector<FeaturePair> extract_insn_features(const FunctionHandle& fh,
                                                           const BBHandle& bbh,
                                                           const InsnHandle& ih) const = 0;

    // Optional: backends that can recognize library code report it here so the driver
    // can skip those functions (capa StaticFeatureExtractor.is_library_function).
    virtual bool is_library_function(const Address&) const { return false; }
    virtual std::string get_function_name(const Address&) const { return {}; }
};

struct ProcessHandle {
    Address address;
    const void* inner = nullptr;
};

struct ThreadHandle {
    Address address;
    const void* inner = nullptr;
};

struct CallHandle {
    Address address;
    const void* inner = nullptr;
};

// Where a call sits in a recorded execution: the trace position it was made at, and the
// position it returned at. Only a time-travel trace knows this; see get_call_span.
struct CallSpan {
    std::pair<std::uint64_t, std::uint64_t> position;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> return_position;
};

class DynamicFeatureExtractor {
public:
    virtual ~DynamicFeatureExtractor() = default;

    // capa's dynamic extractors have no base address; the freeze format still records
    // one (the sample's image base, for sandboxes that report it).
    virtual Address get_base_address() const { return Address::no_address(); }
    virtual const SampleHashes& get_sample_hashes() const = 0;

    virtual const std::vector<FeaturePair>& extract_global_features() const = 0;
    virtual std::vector<FeaturePair> extract_file_features() const = 0;

    virtual std::vector<ProcessHandle> get_processes() const = 0;
    virtual std::vector<FeaturePair> extract_process_features(const ProcessHandle& ph) const = 0;
    virtual std::string get_process_name(const ProcessHandle& ph) const = 0;

    virtual std::vector<ThreadHandle> get_threads(const ProcessHandle& ph) const = 0;
    virtual std::vector<FeaturePair> extract_thread_features(const ProcessHandle& ph,
                                                             const ThreadHandle& th) const = 0;

    // capa's get_calls, one call at a time. A trace can hold millions of calls in a
    // single thread, and a vector of handles for all of them would be live before the
    // first one is looked at; the drivers only ever walk them forwards.
    virtual std::size_t call_count(const ProcessHandle& ph, const ThreadHandle& th) const = 0;
    // `idx` must be below call_count for the same handles.
    virtual CallHandle call_at(const ProcessHandle& ph, const ThreadHandle& th,
                               std::size_t idx) const = 0;
    virtual std::vector<FeaturePair> extract_call_features(const ProcessHandle& ph,
                                                           const ThreadHandle& th,
                                                           const CallHandle& ch) const = 0;
    virtual std::string get_call_name(const ProcessHandle& ph, const ThreadHandle& th,
                                      const CallHandle& ch) const = 0;

    // capa-cpp extension, for `--top-level-calls`: the recorded span of a call, when the
    // backend has one. Not part of capa; every capa backend returns nothing here.
    virtual std::optional<CallSpan> get_call_span(const ProcessHandle&, const ThreadHandle&,
                                                  const CallHandle&) const {
        return std::nullopt;
    }

    // Convenience over call_count/call_at, for callers that do want them all.
    std::vector<CallHandle> get_calls(const ProcessHandle& ph, const ThreadHandle& th) const {
        std::vector<CallHandle> out;
        const std::size_t n = call_count(ph, th);
        out.reserve(n);
        for (std::size_t idx = 0; idx < n; ++idx) out.push_back(call_at(ph, th, idx));
        return out;
    }
};

}  // namespace capa
