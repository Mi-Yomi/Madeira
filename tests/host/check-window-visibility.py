#!/usr/bin/env python3
"""Compile the actual WindowPosChanged visibility decision on a POSIX host.

Checks hidden-window moves/resizes, repeated show/hide, empty geometry and
child HWND style handling. Source assertions verify the current Wine style is
passed to the helper and that the result reaches CALayer.hidden. This does not
run Wine/UIKit or establish ancestor visibility and window-stacking behavior.
CC defaults to cc; CFLAGS may enable address/undefined sanitizers.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
driver = (root / "build/win32u-unix/driver_ios.c").read_text()
native = (root / "app/Madeira/Winios/Winios.m").read_text()
start = driver.index("static BOOL winios_window_frame_visible(")
helper = driver[start:driver.index("/* end winios_window_frame_visible */", start)]
changed = driver[driver.index("static void winios_drv_window_pos_changed("):]
assert "int visible = winios_window_frame_visible( v, swp_flags, get_window_long( hwnd, GWL_STYLE ) );" in changed
assert "winios_window_frame( hwnd, v->left, v->top, v->right - v->left, v->bottom - v->top, visible," in changed
frame = native[native.index("void winios_window_frame("):native.index("/* MADEIRA_DUMP_SURFACES=1:")]
assert "l.hidden = !visible;" in frame
assert "winios_census_note_frame(hwnd, x, y, w, h, visible);" in frame

prefix = r'''
#include <assert.h>
#include <stdio.h>
typedef unsigned int UINT;
typedef int BOOL;
typedef struct { int left, top, right, bottom; } RECT;
#define WS_VISIBLE 0x10000000u
#define WS_CHILD 0x40000000u
#define SWP_NOSIZE 0x0001u
#define SWP_NOMOVE 0x0002u
#define SWP_NOZORDER 0x0004u
#define SWP_SHOWWINDOW 0x0040u
#define SWP_HIDEWINDOW 0x0080u
static BOOL IsRectEmpty(const RECT *rect) {
    return rect->left >= rect->right || rect->top >= rect->bottom;
}
'''
checks = r'''
int main(void) {
    const RECT normal = {20, 30, 620, 430};
    const RECT moved = {70, 80, 700, 480};
    const RECT offscreen = {-300, -200, -100, -50};
    const RECT empty[] = {{0,0,0,50}, {0,0,50,0}, {10,10,0,0}};
    const UINT updates[] = {0, SWP_NOSIZE, SWP_NOMOVE, SWP_NOZORDER,
                           SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER};
    for (unsigned i = 0; i < sizeof(updates) / sizeof(updates[0]); ++i) {
        assert(!winios_window_frame_visible(&normal, updates[i], 0));
        assert(winios_window_frame_visible(&normal, updates[i], WS_VISIBLE));
        assert(!winios_window_frame_visible(&normal, updates[i], WS_CHILD));
        assert(winios_window_frame_visible(&normal, updates[i], WS_CHILD | WS_VISIBLE));
    }
    assert(!winios_window_frame_visible(&normal, SWP_SHOWWINDOW, 0));
    assert(winios_window_frame_visible(&normal, SWP_SHOWWINDOW, WS_VISIBLE));
    assert(!winios_window_frame_visible(&normal, SWP_HIDEWINDOW, WS_VISIBLE));
    assert(!winios_window_frame_visible(&normal, SWP_HIDEWINDOW | SWP_SHOWWINDOW, WS_VISIBLE));
    for (unsigned i = 0; i < sizeof(empty) / sizeof(empty[0]); ++i)
        assert(!winios_window_frame_visible(&empty[i], SWP_SHOWWINDOW, WS_VISIBLE));
    assert(winios_window_frame_visible(&offscreen, 0, WS_VISIBLE)); /* no new clipping policy */

    /* Same dialog: hidden positioning, show, move, hide, background resize,
     * then show again. A move/resize alone must never resurrect the layer. */
    assert(!winios_window_frame_visible(&normal, SWP_NOZORDER, 0));
    assert(winios_window_frame_visible(&normal, SWP_SHOWWINDOW, WS_VISIBLE));
    assert(winios_window_frame_visible(&moved, SWP_NOZORDER, WS_VISIBLE));
    assert(!winios_window_frame_visible(&moved, SWP_HIDEWINDOW, 0));
    assert(!winios_window_frame_visible(&normal, SWP_NOMOVE, 0));
    assert(winios_window_frame_visible(&normal, SWP_SHOWWINDOW, WS_VISIBLE));
    puts("PASS: hidden moves/resizes, show/hide/reopen, child HWND style, empty and offscreen geometry");
    return 0;
}
'''

with tempfile.TemporaryDirectory() as temp:
    source = Path(temp) / "window-visibility.c"
    executable = Path(temp) / "window-visibility"
    source.write_text(prefix + helper + checks)
    command = shlex.split(os.environ.get("CC", "cc"))
    command += ["-std=c11", "-Wall", "-Wextra", "-Werror"]
    command += shlex.split(os.environ.get("CFLAGS", "-O2"))
    command += [str(source), "-o", str(executable)]
    subprocess.run(command, check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
print("PASS: live window style reaches compositor hidden state and window census")
