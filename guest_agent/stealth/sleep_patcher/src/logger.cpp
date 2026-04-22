// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bill Halpin

#include "logger.h"

#include <cstdio>
#include <cstring>
#include <ctime>

namespace sandgnat {

namespace {

FILE* g_log_fp = nullptr;
CRITICAL_SECTION g_lock;
bool g_initialised = false;

void iso8601_utc_now(char* buf, size_t n) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::snprintf(
        buf, n,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

}  // namespace

bool logger_init() {
    if (g_initialised) {
        return g_log_fp != nullptr;
    }
    InitializeCriticalSection(&g_lock);
    g_initialised = true;

    char path[MAX_PATH];
    DWORD len = GetEnvironmentVariableA(
        "SANDGNAT_SLEEP_PATCH_LOG", path, sizeof(path));
    if (len == 0 || len >= sizeof(path)) {
        // No path configured — patch silently. Not an error.
        return false;
    }

    // fopen is fine here: each hook call takes the critical section
    // before touching g_log_fp, so we never race the FILE* itself.
    g_log_fp = std::fopen(path, "ab");
    return g_log_fp != nullptr;
}

void logger_shutdown() {
    if (!g_initialised) {
        return;
    }
    EnterCriticalSection(&g_lock);
    if (g_log_fp != nullptr) {
        std::fflush(g_log_fp);
        std::fclose(g_log_fp);
        g_log_fp = nullptr;
    }
    LeaveCriticalSection(&g_lock);
    DeleteCriticalSection(&g_lock);
    g_initialised = false;
}

void logger_emit(const char* fn, uint64_t requested_ms, uint64_t patched_ms) {
    if (!g_initialised || g_log_fp == nullptr) {
        return;
    }
    char ts[32];
    iso8601_utc_now(ts, sizeof(ts));
    DWORD tid = GetCurrentThreadId();

    EnterCriticalSection(&g_lock);
    std::fprintf(
        g_log_fp,
        "{\"t\":\"%s\",\"tid\":%lu,\"fn\":\"%s\","
        "\"requested_ms\":%llu,\"patched_ms\":%llu}\n",
        ts, (unsigned long)tid, fn,
        (unsigned long long)requested_ms,
        (unsigned long long)patched_ms);
    std::fflush(g_log_fp);
    LeaveCriticalSection(&g_lock);
}

}  // namespace sandgnat
