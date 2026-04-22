// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bill Halpin
//
// sleep_patcher.dll — MinHook-based user-mode hooks that truncate
// long sleep calls inside a detonating sample.
//
// Phase E of the anti-analysis mitigation plan
// (docs/explanation/anti-analysis-evasion.md). Commodity malware
// stalls for minutes-to-hours at a time to outlast default sandbox
// windows; truncating every call over 30s to 2s restores the
// behavioural timeline without tripping most sleep-pattern detectors
// (which typically check for Sleep(0) / Sleep(<100ms) oddities, not
// the reverse).
//
// Hooks:
//   kernel32!Sleep             - DWORD ms
//   kernel32!SleepEx           - DWORD ms, BOOL bAlertable
//   ntdll!NtDelayExecution     - LARGE_INTEGER timeout (100ns units)
//   ntdll!NtWaitForSingleObject - LARGE_INTEGER timeout (when non-NULL
//                                 and non-INFINITE; benign waits on
//                                 real events are NOT truncated, only
//                                 waits with a finite, large timeout)
//
// Build: see ../CMakeLists.txt and ../README.md.  Deploys as a single
// DLL the Python-side injector LoadLibraryW's into the target sample.
//
// Log output is a JSONL file at $SANDGNAT_SLEEP_PATCH_LOG; see logger.h.

#include <windows.h>
#include <winternl.h>
#include <cstdint>

#include "MinHook.h"

#include "logger.h"

namespace {

// Threshold (ms) above which a sleep is considered stalling.
constexpr uint32_t kThresholdMs = 30'000;

// Post-truncation sleep (ms). Non-zero so a tight poll loop doesn't
// starve the scheduler; small enough that even 100 such calls stay
// well inside the detonation window.
constexpr uint32_t kTruncatedMs = 2'000;

// --- Sleep ---------------------------------------------------------------

using Sleep_t = VOID(WINAPI*)(DWORD);
Sleep_t real_Sleep = nullptr;

VOID WINAPI hook_Sleep(DWORD ms) {
    if (ms > kThresholdMs) {
        sandgnat::logger_emit("Sleep", ms, kTruncatedMs);
        real_Sleep(kTruncatedMs);
        return;
    }
    real_Sleep(ms);
}

// --- SleepEx -------------------------------------------------------------

using SleepEx_t = DWORD(WINAPI*)(DWORD, BOOL);
SleepEx_t real_SleepEx = nullptr;

DWORD WINAPI hook_SleepEx(DWORD ms, BOOL alertable) {
    if (ms > kThresholdMs) {
        sandgnat::logger_emit("SleepEx", ms, kTruncatedMs);
        return real_SleepEx(kTruncatedMs, alertable);
    }
    return real_SleepEx(ms, alertable);
}

// --- NtDelayExecution ----------------------------------------------------
//
// Timeout is a LARGE_INTEGER in 100ns units. Negative = relative
// (interpret magnitude); positive = absolute UTC file-time.
// Absolute waits are rare in malware and harder to reason about,
// so we only truncate relative (negative) values.

using NtDelayExecution_t = NTSTATUS(NTAPI*)(BOOLEAN, PLARGE_INTEGER);
NtDelayExecution_t real_NtDelayExecution = nullptr;

NTSTATUS NTAPI hook_NtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER timeout) {
    if (timeout != nullptr && timeout->QuadPart < 0) {
        // Convert 100ns units to milliseconds.
        uint64_t requested_ms =
            (uint64_t)(-timeout->QuadPart) / 10'000ULL;
        if (requested_ms > kThresholdMs) {
            sandgnat::logger_emit(
                "NtDelayExecution", requested_ms, kTruncatedMs);
            LARGE_INTEGER truncated;
            truncated.QuadPart =
                -((LONGLONG)kTruncatedMs * 10'000LL);
            return real_NtDelayExecution(alertable, &truncated);
        }
    }
    return real_NtDelayExecution(alertable, timeout);
}

// --- NtWaitForSingleObject ----------------------------------------------
//
// We only touch this when a finite, large timeout is supplied. A
// NULL timeout means "wait forever"; that's real synchronisation we
// must not break. A zero timeout is a poll — also fine.

using NtWaitForSingleObject_t =
    NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
NtWaitForSingleObject_t real_NtWaitForSingleObject = nullptr;

NTSTATUS NTAPI hook_NtWaitForSingleObject(
    HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout) {
    if (timeout != nullptr && timeout->QuadPart < 0) {
        uint64_t requested_ms =
            (uint64_t)(-timeout->QuadPart) / 10'000ULL;
        if (requested_ms > kThresholdMs) {
            sandgnat::logger_emit(
                "NtWaitForSingleObject", requested_ms, kTruncatedMs);
            LARGE_INTEGER truncated;
            truncated.QuadPart =
                -((LONGLONG)kTruncatedMs * 10'000LL);
            return real_NtWaitForSingleObject(handle, alertable, &truncated);
        }
    }
    return real_NtWaitForSingleObject(handle, alertable, timeout);
}

// --- Install / uninstall -------------------------------------------------

bool install_hooks() {
    if (MH_Initialize() != MH_OK) {
        return false;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntd = GetModuleHandleA("ntdll.dll");
    if (k32 == nullptr || ntd == nullptr) {
        return false;
    }

    struct Spec {
        HMODULE module;
        const char* name;
        LPVOID detour;
        LPVOID* original;
    };

    Spec specs[] = {
        {k32, "Sleep",                 (LPVOID)hook_Sleep,
         (LPVOID*)&real_Sleep},
        {k32, "SleepEx",               (LPVOID)hook_SleepEx,
         (LPVOID*)&real_SleepEx},
        {ntd, "NtDelayExecution",      (LPVOID)hook_NtDelayExecution,
         (LPVOID*)&real_NtDelayExecution},
        {ntd, "NtWaitForSingleObject", (LPVOID)hook_NtWaitForSingleObject,
         (LPVOID*)&real_NtWaitForSingleObject},
    };

    for (const auto& s : specs) {
        FARPROC target = GetProcAddress(s.module, s.name);
        if (target == nullptr) {
            continue;  // Missing on this Windows build — skip, don't abort.
        }
        if (MH_CreateHook((LPVOID)target, s.detour, s.original) != MH_OK) {
            return false;
        }
        if (MH_EnableHook((LPVOID)target) != MH_OK) {
            return false;
        }
    }
    return true;
}

void uninstall_hooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

}  // namespace

// -------------------------------------------------------------------------
// DllMain. Be frugal here — the loader lock is held, so no networking,
// no threads, no C++ runtime construction beyond what the statics already
// did. logger_init uses fopen which is safe here.
// -------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(nullptr);
        sandgnat::logger_init();
        if (!install_hooks()) {
            // Best-effort: if MinHook fails we keep running without
            // hooks so the sample still detonates. Evasion detector
            // will flag the import pattern post-hoc.
            return TRUE;
        }
        break;
    case DLL_PROCESS_DETACH:
        uninstall_hooks();
        sandgnat::logger_shutdown();
        break;
    }
    return TRUE;
}
