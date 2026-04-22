# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""CreateRemoteThread + LoadLibraryW DLL injection.

Python side of Phase E. Given a running sample PID and a DLL path,
open the target process, allocate a buffer for the DLL path, write it
into the target, resolve kernel32!LoadLibraryW's address (identical
across processes since kernel32 is mapped at the same base in 64-bit
Windows 10/11), and fire CreateRemoteThread to invoke LoadLibraryW
with our allocated buffer as the argument. The remote thread returns
once DllMain returns — at which point the hooks are installed.

Import-safe on Linux: the ctypes bindings live behind an
`_IS_WINDOWS` guard and the public `inject_dll` returns
`InjectResult(ok=False, reason='not_windows')` off-platform. Unit
tests exercise the plumbing on both paths.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)


def _is_windows() -> bool:
    # Evaluated at call time so the SANDGNAT_FAKE_WIN32 shim works
    # from within a test that monkeypatches the env var after import.
    return sys.platform == "win32" or os.environ.get("SANDGNAT_FAKE_WIN32") == "1"


@dataclass(frozen=True, slots=True)
class InjectResult:
    """Outcome of a single DLL injection attempt."""

    ok: bool
    reason: str = ""
    pid: int | None = None
    dll_path: str | None = None


def inject_dll(pid: int, dll_path: Path) -> InjectResult:
    """Inject `dll_path` into the process identified by `pid`.

    On success returns `InjectResult(ok=True, ...)`. On failure
    returns `InjectResult(ok=False, reason=<human-readable>)`. The
    runner should log failures but never raise — a missing DLL is a
    warning, not a crash, because the detonation can still proceed
    without sleep patching (Phase G will pick up the import-pattern
    signal).
    """
    if not _is_windows():
        return InjectResult(ok=False, reason="not_windows", pid=pid)
    if not dll_path.exists():
        return InjectResult(ok=False, reason=f"dll_not_found:{dll_path}", pid=pid)
    return _inject_win32(pid, dll_path)


# --------------------------------------------------------------------------
# Windows-only implementation.
# --------------------------------------------------------------------------


def _inject_win32(pid: int, dll_path: Path) -> InjectResult:
    import ctypes
    from ctypes import wintypes

    PROCESS_ALL_ACCESS = 0x001F0FFF
    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000
    MEM_RELEASE = 0x00008000
    PAGE_READWRITE = 0x04

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.CreateRemoteThread.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.CreateRemoteThread.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD,
    ]
    kernel32.VirtualFreeEx.restype = wintypes.BOOL

    def _fail(reason: str) -> InjectResult:
        err = ctypes.get_last_error()
        suffix = f" (GetLastError={err})" if err else ""
        return InjectResult(ok=False, reason=f"{reason}{suffix}", pid=pid)

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        return _fail("OpenProcess_failed")

    remote_buf = None
    thread = None
    try:
        path_str = str(dll_path)
        path_bytes = (path_str + "\0").encode("utf-16-le")
        remote_buf = kernel32.VirtualAllocEx(
            handle, None, len(path_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        )
        if not remote_buf:
            return _fail("VirtualAllocEx_failed")

        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            handle, remote_buf, path_bytes, len(path_bytes), ctypes.byref(written)
        ):
            return _fail("WriteProcessMemory_failed")

        k32_local = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_w = kernel32.GetProcAddress(k32_local, b"LoadLibraryW")
        if not load_library_w:
            return _fail("GetProcAddress_LoadLibraryW_failed")

        tid = wintypes.DWORD(0)
        thread = kernel32.CreateRemoteThread(
            handle, None, 0,
            ctypes.c_void_p(load_library_w),
            remote_buf, 0, ctypes.byref(tid),
        )
        if not thread:
            return _fail("CreateRemoteThread_failed")

        # 10 s is generous for LoadLibraryW + our DllMain. If we hit
        # this timeout something is badly wrong (loader deadlock);
        # surface it rather than hang the detonation pipeline.
        WAIT_OBJECT_0 = 0
        if kernel32.WaitForSingleObject(thread, 10_000) != WAIT_OBJECT_0:
            return _fail("WaitForSingleObject_timeout")

        return InjectResult(ok=True, pid=pid, dll_path=path_str)

    finally:
        if thread:
            kernel32.CloseHandle(thread)
        if remote_buf:
            kernel32.VirtualFreeEx(handle, remote_buf, 0, MEM_RELEASE)
        kernel32.CloseHandle(handle)
