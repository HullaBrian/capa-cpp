#include "memprobe.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// PSAPI_VERSION 2 is what makes psapi.h declare the K32-prefixed entry points, which
// live in kernel32 -- so this costs no extra import library.
#define PSAPI_VERSION 2
#include <psapi.h>
#elif defined(__linux__)
#include <cstdlib>
#include <fstream>
#include <string>
#endif

namespace capa {

#if defined(_WIN32)
MemUsage process_memory() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!K32GetProcessMemoryInfo(GetCurrentProcess(),
                                 reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                                 sizeof(counters)))
        return {};

    MemUsage out;
    out.peak_working_set = static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
    out.working_set = static_cast<std::uint64_t>(counters.WorkingSetSize);
    // PrivateUsage is the committed private bytes, which is the number that actually
    // decides whether the next allocation throws: a process can be trimmed out of its
    // working set and still be at the commit limit.
    out.peak_commit = static_cast<std::uint64_t>(counters.PeakPagefileUsage);
    return out;
}
#elif defined(__linux__)
MemUsage process_memory() {
    // VmHWM and VmRSS are the peak and current resident set, in kB. Linux keeps no
    // high-water mark for committed memory, so peak_commit stays zero.
    std::ifstream in("/proc/self/status");
    MemUsage out;
    std::string line;
    while (std::getline(in, line)) {
        std::uint64_t* field = nullptr;
        if (line.starts_with("VmHWM:"))
            field = &out.peak_working_set;
        else if (line.starts_with("VmRSS:"))
            field = &out.working_set;
        if (field != nullptr) *field = std::strtoull(line.c_str() + 6, nullptr, 10) * 1024;
    }
    return out;
}
#else
MemUsage process_memory() { return {}; }
#endif

}  // namespace capa
