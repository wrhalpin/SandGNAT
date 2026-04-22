<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
-->

# sleep_patcher.dll

Phase E of the anti-analysis mitigation plan
(`docs/explanation/anti-analysis-evasion.md`). User-mode hooks
truncating any Sleep / SleepEx / NtDelayExecution /
NtWaitForSingleObject call requested with a timeout > 30 s down to
2 s, and logging each truncation.

Injected into the sample process at detonation start by the Python
side (`guest_agent/stealth/injector.py`).

## Target platform

Windows 10 / 11 x64. We never hook on Windows 7 / 8.x — the syscall
stubs in ntdll changed after 19H1 and we don't carry bytes for
pre-10.

## Vendoring MinHook

```bash
cd guest_agent/stealth/sleep_patcher
git clone --depth=1 https://github.com/TsudaKageyu/minhook.git \
    third_party/minhook
```

MinHook's `third_party/` directory is gitignored — the vendored
source is a build-time dependency, not a runtime one, and lives in
whatever dev machine builds the DLL.

## Build

From an "x64 Native Tools Command Prompt for VS 2022" (or later):

```powershell
cd guest_agent\stealth\sleep_patcher
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output: `build\Release\sleep_patcher.dll`. Copy (or the PyInstaller
bundle spec picks it up from) `dist\sleep_patcher.dll` alongside the
frozen guest agent.

## Behaviour

- **Threshold**: 30 s. Below that we pass through untouched so real
  synchronisation (1-5s retries, brief UI waits) is unaffected.
- **Truncated value**: 2 s. Non-zero so a tight `while (true)
  Sleep(60000)` loop doesn't burn CPU; small enough that a 100-call
  stall compresses to ~3 min (well inside the detonation window).
- **NtWaitForSingleObject**: only truncates when an explicit finite
  relative timeout is supplied. A NULL timeout (infinite wait) is
  real synchronisation — we leave it alone or risk deadlocking a
  legitimate wait on a real event.
- **Failure mode**: if MinHook fails to initialise (rare — unknown
  syscall layout) the DLL logs nothing and the sample runs at full
  speed. Phase G's evasion detector still flags the import pattern.

## Logging

Every truncated call emits one JSON object to
`%SANDGNAT_SLEEP_PATCH_LOG%`:

```
{"t":"2026-04-22T15:30:17.123Z","tid":4242,"fn":"Sleep",
 "requested_ms":600000,"patched_ms":2000}
```

The host reads this file at detonation teardown via
`guest_agent/stealth/log_parser.py` and feeds the events into the
evasion detector — each patched call is itself a high-severity
indicator.

## Not in scope

- **RDTSC patching**. Hooking the TSC requires kernel-mode (a
  signed driver, which we don't carry). The plan documents this as
  a known gap; samples that use RDTSC-based stalling instead of
  kernel32!Sleep will still waste their budget and hit our
  detonation-window timeout.
- **Clock-drift replay**. A sample that stores `time()` + a large
  delta and polls until the deadline isn't caught by truncating
  Sleep. Detected post-hoc by comparing detonation wall time to
  sample-observed time in the ProcMon CSV; that's a follow-up.
- **Signed-DLL packaging**. We inject via CreateRemoteThread +
  LoadLibraryW; the DLL is self-signed if needed. Samples that
  enumerate modules and reject unsigned DLLs loaded after process
  start *will* flag us; that's the same signal the evasion detector
  records.

## Verification

Manual smoke test inside a detonation VM:

```cpp
// harness.cpp — build as a normal exe, inject sleep_patcher.dll
#include <windows.h>
#include <cstdio>

int main() {
    DWORD t0 = GetTickCount();
    Sleep(300000);  // 5 minutes
    DWORD elapsed = GetTickCount() - t0;
    std::printf("elapsed: %lu ms\n", elapsed);
    return 0;
}
```

Without injection: ~300,000 ms. With `sleep_patcher.dll` injected:
~2,000 ms, and one JSONL line in the log file.
