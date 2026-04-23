// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bill Halpin
//
// Append-only JSONL writer for sleep-patch events. Shared across the
// four hook functions; internally serialised with a critical section
// so concurrent Sleep() calls from the sample's threads don't interleave.
//
// Format (one JSON object per line):
//   {"t":"2026-04-22T15:30:17.123Z","tid":4242,"fn":"Sleep",
//    "requested_ms":600000,"patched_ms":2000}
//
// The host runner (orchestrator/parsers/sleep_patches.py, forthcoming)
// consumes this file after detonation.

#pragma once

#include <windows.h>
#include <cstdint>

namespace sandgnat {

// Open the log file named by the SANDGNAT_SLEEP_PATCH_LOG env var.
// Returns true on success; a false return means we swallow logging
// silently (patching still happens — we never block the sample on
// our own logging failure).
bool logger_init();

// Close + flush. Idempotent.
void logger_shutdown();

// Emit one event. `fn` must be a NUL-terminated literal such as
// "Sleep", "SleepEx", "NtDelayExecution", "NtWaitForSingleObject".
void logger_emit(const char* fn, uint64_t requested_ms, uint64_t patched_ms);

}  // namespace sandgnat
