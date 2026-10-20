#include "settings.h"

#include <registry.hpp>

namespace idacapa {

namespace {

// One netnode per database holds every setting and the cached results. The `$ `
// prefix is IDA's convention for a private, non-user-visible node.
const char* const NODE_NAME = "$ com.capa-cpp.v1";

// supval slots
enum : nodeidx_t {
    IDX_RULES_DIR = 0,
    IDX_RESULTS = 1,
    IDX_RESULTS_RULES_DIR = 2,
    IDX_BY_FUNCTION = 3,
    IDX_LIMIT_TO_FUNCTION = 4,
    IDX_SCAN_SYSTEM_MODULES = 5,
    IDX_FLAT_RESULTS = 6,
};

netnode node() { return netnode(NODE_NAME, 0, /*do_create=*/true); }

std::string get_str(nodeidx_t idx) {
    qstring buf;
    netnode n = node();
    if (n.supstr(&buf, idx) <= 0) return {};
    return buf.c_str();
}

void set_str(nodeidx_t idx, const std::string& value) {
    netnode n = node();
    if (value.empty())
        n.supdel(idx);
    else
        n.supset(idx, value.c_str(), value.size() + 1);
}

// The results blob easily exceeds the ~1KB a supval can hold, so these get blobs.
const uchar RESULTS_TAG = 'R';
const uchar ANNOTATION_TAG = 'A';

std::string get_blob(uchar tag) {
    netnode n = node();
    qstring blob;
    if (n.getblob(&blob, 0, tag) <= 0) return {};
    return blob.c_str();
}

void set_blob(uchar tag, const std::string& value) {
    netnode n = node();
    if (value.empty())
        n.delblob(0, tag);
    else
        n.setblob(value.data(), value.size(), 0, tag);
}

bool get_flag(nodeidx_t idx, bool dflt) {
    const std::string s = get_str(idx);
    if (s.empty()) return dflt;
    return s == "1";
}

}  // namespace

// IDA's registry (the Windows registry, or ida.reg elsewhere): shared by every
// database, so a new one starts from the directory last used anywhere.
const char* const REG_SUBKEY = "capa-cpp";
const char* const REG_RULES_DIR = "rules_dir";

std::string rules_dir() {
    std::string dir = get_str(IDX_RULES_DIR);
    if (!dir.empty()) return dir;
    qstring last;
    // A remembered directory that has since gone would only fail to load; asking
    // again is the better outcome.
    if (reg_read_string(&last, REG_RULES_DIR, REG_SUBKEY) && qisdir(last.c_str()))
        return last.c_str();
    return {};
}

void set_rules_dir(const std::string& path) {
    set_str(IDX_RULES_DIR, path);
    if (!path.empty()) reg_write_string(REG_RULES_DIR, path.c_str(), REG_SUBKEY);
}

std::string ask_rules_dir() {
    // IDA has no directory picker; HIST_DIR at least gives the text field a history
    // of directories the user has typed before.
    qstring path(rules_dir().c_str());
    if (!ask_str(&path, HIST_DIR, "%s", "Path to capa's rules directory")) return {};
    return path.c_str();
}

std::string cached_results() { return get_blob(RESULTS_TAG); }

std::string cached_results_rules_dir() { return get_str(IDX_RESULTS_RULES_DIR); }

void set_cached_results(const std::string& json, const std::string& rules) {
    set_blob(RESULTS_TAG, json);
    set_str(IDX_RESULTS_RULES_DIR, rules);
}

void clear_cached_results() {
    set_blob(RESULTS_TAG, "");
    set_str(IDX_RESULTS_RULES_DIR, "");
}

std::string annotation_record() { return get_blob(ANNOTATION_TAG); }
void set_annotation_record(const std::string& json) { set_blob(ANNOTATION_TAG, json); }
void clear_annotation_record() { set_blob(ANNOTATION_TAG, ""); }

bool show_results_by_function() { return get_flag(IDX_BY_FUNCTION, false); }
void set_show_results_by_function(bool on) { set_str(IDX_BY_FUNCTION, on ? "1" : "0"); }

bool limit_to_current_function() { return get_flag(IDX_LIMIT_TO_FUNCTION, false); }
void set_limit_to_current_function(bool on) { set_str(IDX_LIMIT_TO_FUNCTION, on ? "1" : "0"); }

bool scan_system_modules() { return get_flag(IDX_SCAN_SYSTEM_MODULES, false); }
void set_scan_system_modules(bool on) { set_str(IDX_SCAN_SYSTEM_MODULES, on ? "1" : "0"); }

bool flat_results() { return get_flag(IDX_FLAT_RESULTS, false); }
void set_flat_results(bool on) { set_str(IDX_FLAT_RESULTS, on ? "1" : "0"); }

}  // namespace idacapa
