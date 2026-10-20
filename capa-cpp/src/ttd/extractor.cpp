#include "ttd/extractor.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

#include "symbols.h"

namespace capa::ttd {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// global_.py: format is always PE; os from trace.os; arch from trace.arch.
std::vector<FeaturePair> compute_global_features(const Report& r) {
    std::vector<FeaturePair> out;
    out.emplace_back(Feature::format(FORMAT_PE), Address::no_address());

    std::string os = to_lower(r.trace.os);
    if (os == OS_LINUX)
        out.emplace_back(Feature::os(OS_LINUX), Address::no_address());
    else
        out.emplace_back(Feature::os(OS_WINDOWS), Address::no_address());

    std::string arch = to_lower(r.trace.arch);
    if (arch == "x86" || arch == "i386" || arch == "32")
        out.emplace_back(Feature::arch(ARCH_I386), Address::no_address());
    else
        out.emplace_back(Feature::arch(ARCH_AMD64), Address::no_address());

    return out;
}

// Python repr() of a call argument, for get_call_name display.
std::string repr_arg(const Arg& a, const Report& report) {
    if (a.kind == Arg::Kind::Str) {
        std::string out = "'";
        for (char c : report.arg_str(a)) {
            if (c == '\'' || c == '\\') out += '\\';
            out += c;
        }
        out += "'";
        return out;
    }
    if (a.kind == Arg::Kind::Bool) return a.i ? "True" : "False";
    return std::to_string(a.i);
}

// "SEQ:STEPS" in hex, as the report writes positions; nullopt for an empty or malformed one.
std::optional<std::pair<std::uint64_t, std::uint64_t>> parse_position(const std::string& text) {
    const std::size_t colon = text.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 == text.size()) return std::nullopt;
    char* end = nullptr;
    const std::uint64_t seq = std::strtoull(text.c_str(), &end, 16);
    if (end != text.c_str() + colon) return std::nullopt;
    const std::uint64_t steps = std::strtoull(text.c_str() + colon + 1, &end, 16);
    if (*end != '\0') return std::nullopt;
    return std::make_pair(seq, steps);
}

}  // namespace

TtdExtractor::TtdExtractor(Report report) : report_(std::move(report)) {
    hashes_ = SampleHashes{report_.sample.md5, report_.sample.sha1, report_.sample.sha256};
    global_features_ = compute_global_features(report_);

    // index_calls: bucket calls per process/thread, preserving thread insertion order
    // (declared threads first, then any discovered via calls), and sort calls by seq.
    for (const auto& proc : report_.processes) {
        ProcEntry pe;
        pe.address = Address::process(static_cast<std::uint32_t>(proc.pid),
                                      static_cast<std::uint32_t>(proc.ppid));
        pe.proc = &proc;

        std::unordered_map<std::int64_t, std::size_t> tid_to_index;

        auto ensure_thread = [&](std::int64_t tid) -> ThreadEntry& {
            auto it = tid_to_index.find(tid);
            if (it != tid_to_index.end()) return pe.threads[it->second];
            ThreadEntry te;
            te.address = Address::thread(pe.address, static_cast<std::uint32_t>(tid));
            tid_to_index[tid] = pe.threads.size();
            pe.threads.push_back(std::move(te));
            return pe.threads.back();
        };

        // seed declared threads so idle threads still appear
        for (std::int64_t tid : proc.threads) ensure_thread(tid);
        // then bucket calls
        for (const auto& call : proc.calls) ensure_thread(call.tid).calls.push_back(&call);

        // stable-sort each thread's calls by seq
        for (auto& te : pe.threads) {
            std::stable_sort(te.calls.begin(), te.calls.end(),
                             [](const Call* a, const Call* b) { return a->seq < b->seq; });
        }

        procs_.push_back(std::move(pe));
    }
}

const TtdExtractor::ProcEntry* TtdExtractor::find_proc(const Address& addr) const {
    for (const auto& pe : procs_)
        if (pe.address == addr) return &pe;
    return nullptr;
}

const TtdExtractor::ThreadEntry* TtdExtractor::find_thread(const ProcEntry& pe,
                                                           const Address& addr) const {
    for (const auto& te : pe.threads)
        if (te.address == addr) return &te;
    return nullptr;
}

std::vector<FeaturePair> TtdExtractor::extract_file_features() const {
    std::vector<FeaturePair> out;
    // imports: expanded via generate_symbols(dll, name, include_dll=true)
    for (const auto& imp : report_.file.imports) {
        if (imp.name.empty()) continue;
        for (const auto& name : generate_symbols(imp.dll, imp.name, /*include_dll=*/true))
            out.emplace_back(Feature::import_(name), Address::absolute(imp.va));
    }
    for (const auto& exp : report_.file.exports) {
        if (exp.name.empty()) continue;
        out.emplace_back(Feature::export_(exp.name), Address::absolute(exp.va));
    }
    for (const auto& sec : report_.file.sections) {
        out.emplace_back(Feature::section(sec.name), Address::absolute(sec.va));
    }
    for (const auto& s : report_.file.strings) {
        out.emplace_back(Feature::string(s), Address::no_address());
    }
    return out;
}

std::vector<ProcessHandle> TtdExtractor::get_processes() const {
    std::vector<ProcessHandle> out;
    for (const auto& pe : procs_) out.push_back(ProcessHandle{pe.address, pe.proc});
    return out;
}

std::vector<FeaturePair> TtdExtractor::extract_process_features(const ProcessHandle& ph) const {
    std::vector<FeaturePair> out;
    const auto* proc = static_cast<const Process*>(ph.inner);
    if (!proc) return out;
    for (const auto& v : proc->environ_strings) {
        if (!v.empty()) out.emplace_back(Feature::string(v), ph.address);
    }
    return out;
}

std::string TtdExtractor::get_process_name(const ProcessHandle& ph) const {
    const auto* proc = static_cast<const Process*>(ph.inner);
    return proc ? proc->name : std::string();
}

std::vector<ThreadHandle> TtdExtractor::get_threads(const ProcessHandle& ph) const {
    std::vector<ThreadHandle> out;
    const ProcEntry* pe = find_proc(ph.address);
    if (!pe) return out;
    for (const auto& te : pe->threads) out.push_back(ThreadHandle{te.address});
    return out;
}

std::vector<FeaturePair> TtdExtractor::extract_thread_features(const ProcessHandle&,
                                                              const ThreadHandle&) const {
    return {};  // thread.py emits no features
}

std::size_t TtdExtractor::call_count(const ProcessHandle& ph, const ThreadHandle& th) const {
    const ProcEntry* pe = find_proc(ph.address);
    if (!pe) return 0;
    const ThreadEntry* te = find_thread(*pe, th.address);
    return te ? te->calls.size() : 0;
}

CallHandle TtdExtractor::call_at(const ProcessHandle& ph, const ThreadHandle& th,
                                 std::size_t idx) const {
    const ProcEntry* pe = find_proc(ph.address);
    if (!pe) return {};
    const ThreadEntry* te = find_thread(*pe, th.address);
    if (!te || idx >= te->calls.size()) return {};
    return CallHandle{Address::call(te->address, idx), te->calls[idx]};
}

std::vector<FeaturePair> TtdExtractor::extract_call_features(const ProcessHandle&,
                                                            const ThreadHandle&,
                                                            const CallHandle& ch) const {
    std::vector<FeaturePair> out;
    const auto* call = static_cast<const Call*>(ch.inner);
    if (!call) return out;

    // arguments right-to-left, like disassembly. bool skipped.
    const std::span<const Arg> args = report_.args_of(*call);
    for (auto it = args.rbegin(); it != args.rend(); ++it) {
        if (it->kind == Arg::Kind::Bool) continue;
        if (it->kind == Arg::Kind::Int)
            // Arguments are machine words: unsigned, as capa's sandbox backends report them.
            out.emplace_back(Feature::number(it->i).as_unsigned(), ch.address);
        else if (it->kind == Arg::Kind::Str)
            out.emplace_back(Feature::string(report_.arg_str(*it)), ch.address);
    }

    // API name variants; only include DLL prefix when a module was resolved.
    const std::string& module = report_.str(call->module);
    bool include_dll = !module.empty();
    for (const auto& name : generate_symbols(module, report_.str(call->api), include_dll))
        out.emplace_back(Feature::api(name), ch.address);

    return out;
}

std::string TtdExtractor::get_call_name(const ProcessHandle&, const ThreadHandle&,
                                        const CallHandle& ch) const {
    const auto* call = static_cast<const Call*>(ch.inner);
    if (!call) return "";

    const std::string& module = report_.str(call->module);
    const std::string& api_name = report_.str(call->api);
    std::string api = module.empty() ? api_name : (module + "." + api_name);

    std::string args;
    const std::span<const Arg> call_args = report_.args_of(*call);
    for (std::size_t k = 0; k < call_args.size(); ++k) {
        if (k) args += ", ";
        args += repr_arg(call_args[k], report_);
    }

    std::string ret;
    if (call->ret.has_value()) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), " -> 0x%llx",
                      static_cast<unsigned long long>(*call->ret));
        ret = buf;
    }

    std::string pos = call->position.empty() ? "" : (" @TTD " + call->position);
    return api + "(" + args + ")" + ret + pos;
}

std::optional<CallSpan> TtdExtractor::get_call_span(const ProcessHandle&, const ThreadHandle&,
                                                    const CallHandle& ch) const {
    const auto* call = static_cast<const Call*>(ch.inner);
    if (!call) return std::nullopt;
    const auto at = parse_position(call->position);
    if (!at) return std::nullopt;
    return CallSpan{*at, parse_position(call->return_position)};
}

}  // namespace capa::ttd
