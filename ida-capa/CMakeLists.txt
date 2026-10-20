# Linux (and, incidentally, Mac) build of the ida-capa plugin, using the IDA SDK's
# own CMake helpers. Windows keeps building via ida-capa.vcxproj / build.ps1; this
# file is not used there.
#
# Usage:
#   cmake -S ida-capa -B build/ida-capa -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/ida-capa -j
#
# The IDA SDK is found automatically at ../ida-sdk/src (the git submodule). Point
# elsewhere with -DIDASDK=/path/to/sdk or the IDASDK environment variable.
#
# Dependencies come from the system: nlohmann-json is header-only, and yaml-cpp
# links statically (into the plugin) when a static build of it is available, so the
# target system needs no libyaml-cpp of its own -- only IDA itself.
#   Fedora:  sudo dnf install json-devel yaml-cpp-devel yaml-cpp-static
#            (-devel for headers, -static for the static archive; both are needed)
#   Debian:  sudo apt install nlohmann-json3-dev libyaml-cpp-dev
#            (Debian/Ubuntu don't package a static libyaml-cpp.a; on those distros
#            this falls back to linking libyaml-cpp.so, which then must be present
#            on the target system too)
cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED ENV{IDASDK} AND NOT DEFINED IDASDK)
    set(ENV{IDASDK} "${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk/src")
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/../ida-sdk/src/cmake/idasdk_init.cmake")

project(ida-capa CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Land the plugin under build/ida-capa/ rather than the SDK's own bin/plugins/
# (its default): keeps every build artifact under this repo's build/ like the
# Windows build does, and out of the ida-sdk submodule's tree.
set(IDA_PLUGIN_DIR "${CMAKE_BINARY_DIR}")

find_package(idasdk REQUIRED)
find_package(nlohmann_json REQUIRED)

# Fedora ships static yaml-cpp as a separate package/CMake config (yaml-cpp-static)
# from the shared one (yaml-cpp), both exporting the same yaml-cpp::yaml-cpp
# target. Prefer it so the plugin carries its own copy and the target system needs
# no libyaml-cpp installed; fall back to the shared target where only that exists.
#
# find_package(yaml-cpp-static) itself can't be used: Fedora's own
# yaml-cpp-static-config.cmake (0.8.0-4.fc43) has a packaging bug where it
# `include()`s the *shared* package's yaml-cpp-targets.cmake instead of its own, so
# find_package would silently hand back the shared, dynamically-linked target. The
# static package's own yaml-cpp-targets.cmake (which defines the STATIC IMPORTED
# yaml-cpp::yaml-cpp target correctly) is self-contained, so it's included directly,
# skipping the broken wrapper.
find_file(YAML_CPP_STATIC_TARGETS_FILE
    NAMES yaml-cpp-targets.cmake
    PATH_SUFFIXES lib64/cmake/yaml-cpp-static lib/cmake/yaml-cpp-static)
if(YAML_CPP_STATIC_TARGETS_FILE)
    include("${YAML_CPP_STATIC_TARGETS_FILE}")
    message(STATUS "yaml-cpp: linking statically (${YAML_CPP_STATIC_TARGETS_FILE})")
else()
    find_package(yaml-cpp REQUIRED)
    message(WARNING
        "yaml-cpp: static package not found, linking libyaml-cpp.so instead -- "
        "the built plugin will need libyaml-cpp installed on the target system too")
endif()

set(CAPA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../capa-cpp/src")

# NDEBUG in every configuration: on Windows this avoids linking the debug CRT
# against IDA's release CRT (see ida-capa.vcxproj); kept here too so a Debug build
# behaves the same on every platform.
ida_add_plugin(ida-capa
    SOURCES
        # Shared capa-cpp core. Compiled a second time here (rather than linked from
        # a library shared with capa-cpp.exe) to keep the two build graphs
        # independent -- see the equivalent comment in ida-capa.vcxproj.
        ${CAPA_SRC_DIR}/address.cpp
        ${CAPA_SRC_DIR}/feature.cpp
        ${CAPA_SRC_DIR}/engine.cpp
        ${CAPA_SRC_DIR}/rules.cpp
        ${CAPA_SRC_DIR}/symbols.cpp
        ${CAPA_SRC_DIR}/extract_helpers.cpp
        ${CAPA_SRC_DIR}/static_caps.cpp
        ${CAPA_SRC_DIR}/feature_filter.cpp
        ${CAPA_SRC_DIR}/module_filter.cpp
        ${CAPA_SRC_DIR}/minidump/mdmp.cpp
        ${CAPA_SRC_DIR}/static/memory.cpp
        ${CAPA_SRC_DIR}/static/symbol_map.cpp
        ${CAPA_SRC_DIR}/minidump/pe.cpp
        ${CAPA_SRC_DIR}/minidump/process.cpp
        # The IDA backend: only ever built into the plugin, never into capa-cpp.exe.
        ${CAPA_SRC_DIR}/ida/helpers.cpp
        ${CAPA_SRC_DIR}/ida/global_.cpp
        ${CAPA_SRC_DIR}/ida/file.cpp
        ${CAPA_SRC_DIR}/ida/function.cpp
        ${CAPA_SRC_DIR}/ida/basicblock.cpp
        ${CAPA_SRC_DIR}/ida/insn.cpp
        ${CAPA_SRC_DIR}/ida/extractor.cpp
        # The plugin itself.
        settings.cpp
        analysis.cpp
        view_results.cpp
        view_details.cpp
        annotate.cpp
        pseudocode.cpp
        plugin.cpp
    LIBRARIES
        nlohmann_json::nlohmann_json
        yaml-cpp::yaml-cpp
    INCLUDES
        ${CAPA_SRC_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
    DEFINES
        NDEBUG
)

# dllmain.cpp is Windows-only (a Linux plugin needs no DLL entry point); it is a
# no-op there (see the #if defined(_WIN32) guard inside it), so it is only added to
# the target on Windows.
if(IDA_NT)
    target_sources(ida-capa PRIVATE dllmain.cpp)
endif()
