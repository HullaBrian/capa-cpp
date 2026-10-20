// The one place capa-cpp includes the IDA SDK.
//
// pro.h is invasive: it poisons the standard file/string functions unless told not
// to, and it defines `strtoull` to a name that does not exist in namespace std,
// which breaks any header including <charconv>/<string> machinery afterwards. So the
// rule for this project is:
//
//   * every translation unit that needs the SDK includes THIS header, never the SDK
//     headers directly;
//   * anything that also uses nlohmann/json or yaml-cpp must include those FIRST
//     (the plugin's pch.h does exactly that).
#pragma once

// pro.h auto-detects __NT__/__LINUX__/__MAC__ from the compiler's own predefined
// macros when none of the three is already set, so nothing needs to be forced here
// on any platform.

// Keep pro.h from redefining fgetc/fopen/strcpy/... to dont_use_* stubs, which would
// break every standard header included after it.
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif
#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif
#ifndef NO_OBSOLETE_FUNCS
#define NO_OBSOLETE_FUNCS
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// wingdi.h defines ABSOLUTE as 1, which collides with capa's AddressType::ABSOLUTE
// (and would with any enumerator of that name). Nothing here draws anything.
#undef ABSOLUTE
#endif  // _WIN32

#include <pro.h>

// allins.hpp has no include guard and intel.hpp already includes it, so it must not
// be included here as well: doing so redefines every NN_* enumerator.
#include <bytes.hpp>
// For the process module list. A database opened over a dump or a live session is
// debugger-backed, and its module list is the only place full module PATHS live --
// segment names carry at most a basename.
#include <dbg.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
