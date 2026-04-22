# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
#
# CMake recipe for sleep_patcher.dll. Build with MSVC x64 (the
# SandGNAT Windows guest is always 64-bit).
#
# Usage:
#     cd guest_agent/stealth/sleep_patcher
#     cmake -S . -B build -A x64
#     cmake --build build --config Release
# Output: build/Release/sleep_patcher.dll
#
# Requires MinHook vendored under third_party/minhook/ (see README.md).

cmake_minimum_required(VERSION 3.20)
project(sleep_patcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "sleep_patcher is Windows-only (MSVC x64).")
endif()

# --- MinHook --------------------------------------------------------------
# Vendor the upstream source under third_party/minhook. README explains
# the one-line git submodule / clone that populates it.

set(MINHOOK_ROOT "${CMAKE_SOURCE_DIR}/third_party/minhook")
if(NOT EXISTS "${MINHOOK_ROOT}/include/MinHook.h")
    message(FATAL_ERROR
        "MinHook not found at ${MINHOOK_ROOT}. "
        "Run: git clone https://github.com/TsudaKageyu/minhook.git "
        "third_party/minhook (see README.md).")
endif()

# MinHook ships its own CMakeLists but building it as a subdirectory
# keeps all output in one tree and guarantees ABI/flags match.
add_subdirectory("${MINHOOK_ROOT}" minhook_build EXCLUDE_FROM_ALL)

# --- sleep_patcher.dll ----------------------------------------------------

add_library(sleep_patcher SHARED
    src/sleep_patcher.cpp
    src/logger.cpp
    src/logger.h
)

target_include_directories(sleep_patcher PRIVATE
    "${MINHOOK_ROOT}/include"
)

target_link_libraries(sleep_patcher PRIVATE minhook)

if(MSVC)
    target_compile_options(sleep_patcher PRIVATE /W4 /WX /permissive- /GR- /EHsc)
    target_compile_definitions(sleep_patcher PRIVATE
        _WIN32_WINNT=0x0A00       # Windows 10 / 11
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    # Strip the CRT runtime reference where possible; we don't use
    # iostreams or exceptions across boundaries.
    set_target_properties(sleep_patcher PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )
endif()

install(TARGETS sleep_patcher
    RUNTIME DESTINATION dist
    LIBRARY DESTINATION dist
)
