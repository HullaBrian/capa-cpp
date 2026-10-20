// Process memory counters, for the optional CAPA_CPP_TIMING probe.
//
// The point of these is attribution: a wall-clock lap tells you which stage is slow,
// and the peak alongside it tells you which stage is what runs the machine out of
// memory. Peak counters are what matter rather than current ones -- the largest
// structures here are transient (a JSON DOM freed the moment the model is built, a
// match corpus copied and dropped), so a reading taken between stages sees none of them.
//
// Deliberately behind its own translation unit: on Windows <psapi.h> drags in
// <windows.h>, whose min/max macros and Feature/Result-adjacent typedefs have no
// business in the rest of the codebase. Linux reads /proc/self/status and has no peak
// commit counter; other platforms report zeros.
#pragma once

#include <cstdint>

namespace capa {

struct MemUsage {
    std::uint64_t peak_working_set = 0;  // bytes, high-water RSS
    std::uint64_t peak_commit = 0;       // bytes, high-water private commit (Windows only)
    std::uint64_t working_set = 0;       // bytes, current RSS
};

// Zeroed if the query fails; the probe is diagnostic, so it never reports an error.
MemUsage process_memory();

}  // namespace capa
