# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Thin ctypes shim over the Win32 input/window APIs used by activity/.

On Windows every public function resolves to a real user32/kernel32
call. On every other platform the module still imports, but calls
return sentinel values (usually 0 / False / (0, 0)) so the activity
loops exit cleanly during unit tests on Linux CI.

Keep this module pure bindings — no scheduling, no randomness. Policy
lives in the individual activity modules so the bindings stay trivial
to stub in tests.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32" or os.environ.get("SANDGNAT_FAKE_WIN32") == "1"


@dataclass(frozen=True, slots=True)
class ScreenBounds:
    width: int
    height: int


# --------------------------------------------------------------------------
# Stub implementations: used on non-Windows hosts and inside unit tests.
# --------------------------------------------------------------------------


def _stub_screen_bounds() -> ScreenBounds:
    return ScreenBounds(width=1920, height=1080)


def _stub_cursor_pos() -> tuple[int, int]:
    return (0, 0)


def _stub_set_cursor_pos(_x: int, _y: int) -> bool:
    return False


def _stub_mouse_move(_dx: int, _dy: int) -> bool:
    return False


def _stub_mouse_click(_button: str = "left") -> bool:
    return False


def _stub_send_key(_vk: int, _down: bool = True) -> bool:
    return False


def _stub_send_unicode(_text: str) -> int:
    return 0


def _stub_open_app(_executable: str) -> int | None:
    return None


def _stub_close_process(_pid: int) -> bool:
    return False


# --------------------------------------------------------------------------
# Windows implementations.
# --------------------------------------------------------------------------

# INPUT structure constants from WinUser.h.
_INPUT_MOUSE = 0
_INPUT_KEYBOARD = 1
_MOUSEEVENTF_MOVE = 0x0001
_MOUSEEVENTF_LEFTDOWN = 0x0002
_MOUSEEVENTF_LEFTUP = 0x0004
_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_UNICODE = 0x0004


if IS_WINDOWS:  # pragma: no cover - Windows-only branch
    import subprocess

    class _MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
        ]

    class _KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
        ]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT)]

    class _INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    _user32.SendInput.restype = wintypes.UINT
    _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    _user32.GetSystemMetrics.restype = ctypes.c_int
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _user32.GetCursorPos.restype = wintypes.BOOL
    _user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    _user32.SetCursorPos.restype = wintypes.BOOL

    def screen_bounds() -> ScreenBounds:
        return ScreenBounds(
            width=_user32.GetSystemMetrics(0),
            height=_user32.GetSystemMetrics(1),
        )

    def cursor_pos() -> tuple[int, int]:
        point = wintypes.POINT()
        if not _user32.GetCursorPos(ctypes.byref(point)):
            return (0, 0)
        return (point.x, point.y)

    def set_cursor_pos(x: int, y: int) -> bool:
        return bool(_user32.SetCursorPos(x, y))

    def _send_mouse(flags: int, dx: int = 0, dy: int = 0) -> bool:
        inp = _INPUT(type=_INPUT_MOUSE)
        inp.mi = _MOUSEINPUT(
            dx=dx, dy=dy, mouseData=0, dwFlags=flags, time=0, dwExtraInfo=None
        )
        return _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT)) == 1

    def mouse_move(dx: int, dy: int) -> bool:
        return _send_mouse(_MOUSEEVENTF_MOVE, dx=dx, dy=dy)

    def mouse_click(button: str = "left") -> bool:
        if button != "left":
            return False
        down = _send_mouse(_MOUSEEVENTF_LEFTDOWN)
        up = _send_mouse(_MOUSEEVENTF_LEFTUP)
        return down and up

    def send_key(vk: int, down: bool = True) -> bool:
        inp = _INPUT(type=_INPUT_KEYBOARD)
        flags = 0 if down else _KEYEVENTF_KEYUP
        inp.ki = _KEYBDINPUT(
            wVk=vk, wScan=0, dwFlags=flags, time=0, dwExtraInfo=None
        )
        return _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT)) == 1

    def send_unicode(text: str) -> int:
        sent = 0
        for ch in text:
            inp = _INPUT(type=_INPUT_KEYBOARD)
            inp.ki = _KEYBDINPUT(
                wVk=0,
                wScan=ord(ch),
                dwFlags=_KEYEVENTF_UNICODE,
                time=0,
                dwExtraInfo=None,
            )
            if _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT)) == 1:
                sent += 1
        return sent

    def open_app(executable: str) -> int | None:
        try:
            proc = subprocess.Popen([executable], close_fds=True)
        except OSError:
            return None
        return proc.pid

    def close_process(pid: int) -> bool:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], timeout=5, check=False)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

else:
    # Non-Windows: bind stubs so imports still resolve.
    screen_bounds = _stub_screen_bounds
    cursor_pos = _stub_cursor_pos
    set_cursor_pos = _stub_set_cursor_pos
    mouse_move = _stub_mouse_move
    mouse_click = _stub_mouse_click
    send_key = _stub_send_key
    send_unicode = _stub_send_unicode
    open_app = _stub_open_app
    close_process = _stub_close_process
