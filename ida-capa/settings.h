// Per-database settings and result cache for ida-capa.
//
// Everything lives in one netnode inside the IDB, so a rules directory chosen once
// and a completed analysis both survive closing and reopening the database. The
// rules directory is also remembered in IDA's registry, as the default for
// databases that have none of their own.
#pragma once

#include "pch.h"

#include <string>

namespace idacapa {

// The rules directory capa should load from: this database's own, else the one last
// chosen in any database (if it still exists), else "".
std::string rules_dir();
// Sets this database's directory and remembers it for databases that have none.
void set_rules_dir(const std::string& path);

// Ask the user to pick a rules directory, seeding the dialog with the current one.
// Returns "" if they cancelled. Does not store the result; the caller decides.
std::string ask_rules_dir();

// Cached results: the serialized match table from the last successful analysis,
// plus the rules directory it was produced from (so a changed setting invalidates it).
std::string cached_results();
std::string cached_results_rules_dir();
void set_cached_results(const std::string& json, const std::string& rules_dir);
void clear_cached_results();

// What annotate() wrote, so it can be undone exactly. See annotate.h.
std::string annotation_record();
void set_annotation_record(const std::string& json);
void clear_annotation_record();

// View toggles, mirroring capa explorer's two checkboxes. Persisted so the window
// comes back the way it was left.
bool show_results_by_function();
void set_show_results_by_function(bool on);
bool limit_to_current_function();
void set_limit_to_current_function(bool on);

// Scan the Windows system modules too (ntdll, kernel32, ...). Off by default: a
// database opened over a process dump holds the whole address space, and Microsoft's
// capabilities are not the sample's. Turning it on is for when the question really is
// "what does the loaded ntdll do" -- an inline hook, a patched export.
bool scan_system_modules();
void set_scan_system_modules(bool on);

// Show the results as a flat list, with the namespace in its own column, instead of
// as a folder tree. The tree is nicer when it works, but it depends on IDA rendering a
// dirtree inside an EMBEDDED chooser -- every dirtree chooser IDA ships (Functions,
// Structures) is a standalone window, and the SDK's own embedded-chooser examples are
// all flat. This mode owes nothing to any of that.
bool flat_results();
void set_flat_results(bool on);

}  // namespace idacapa
