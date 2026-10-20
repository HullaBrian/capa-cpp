// Ports capa/features/extractors/ida/global_.py (+ file.py::extract_file_format,
// which capa also yields as a global feature).
#include "ida/extractor.h"

namespace capa::ida {

namespace {

void add(std::vector<FeaturePair>& out, Feature f) {
    out.emplace_back(std::move(f), Address::no_address());
}

// capa/features/extractors/ida/file.py::extract_file_format
void extract_file_format(std::vector<FeaturePair>& out) {
    filetype_t ft = inf_get_filetype();
    if (ft == f_PE || ft == f_COFF) {
        add(out, Feature::format(FORMAT_PE));
    } else if (ft == f_ELF) {
        add(out, Feature::format(FORMAT_ELF));
    }
    // f_BIN (shellcode) has no format feature, and capa raises on anything else.
    // Raising would take the plugin down mid-analysis, so unknown formats simply
    // contribute no format feature and rules that need one will not match.
}

void extract_os(std::vector<FeaturePair>& out, bool is_dump) {
    const std::string format_name = file_type_name();
    if (format_name.find("PE") != std::string::npos) {
        add(out, Feature::os(OS_WINDOWS));
    } else if (is_dump) {
        // Not in capa, whose IDA backend has no dump support. IDA names a minidump
        // "Windows Crash Dump File (Minidump)" -- no "PE" in it -- yet every dump is of
        // a Windows process, and capa-cpp's own minidump backend says so too. Keyed
        // off the input file rather than that name, which IDA is free to change.
        add(out, Feature::os(OS_WINDOWS));
    }
    // ELF would need capa's detect_elf_os(), which parses the ELF headers to tell
    // Linux from the BSDs. Not ported: without it we would have to guess, and a wrong
    // OS feature is worse than none. See the README's known gaps.
}

void extract_arch(std::vector<FeaturePair>& out) {
    if (!is_metapc()) return;  // capa supports no other processor module
    if (is_64bit())
        add(out, Feature::arch(ARCH_AMD64));
    else if (is_32bit())
        add(out, Feature::arch(ARCH_I386));
}

}  // namespace

void extract_global_features(std::vector<FeaturePair>& out, bool is_dump) {
    extract_file_format(out);
    extract_os(out, is_dump);
    extract_arch(out);
}

}  // namespace capa::ida
