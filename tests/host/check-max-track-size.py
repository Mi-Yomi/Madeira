#!/usr/bin/env python3
"""Compile the production iOS metrics and virtual-mode callbacks on the host.

The iOS branch of get_system_metrics, ios_screen_size, the standard mode table,
mode-setting policy and ios_virtual_change_display_settings are read verbatim
from production C. Wine device-name lookup and UI/server publication are inert
hooks. This does not execute a guest, UIKit, a window, or a full win32u build.
Use CFLAGS=-fsanitize=undefined for arithmetic checks; CC selects the compiler.
--source tests another revision; --probe prints before/after metrics only.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, default=ROOT / "build/win32u-unix/sysparams_ios.c")
parser.add_argument("--probe", action="store_true")
args = parser.parse_args()
source = args.source.read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]


metrics = function("int get_system_metrics( int index )")
ios_metrics = metrics.split("#ifdef WINE_IOS\n", 1)[1].split("#endif", 1)[0]
dpi_metrics = function("static int get_system_metrics_for_dpi(")
for metric in ("SM_CXMAXTRACK", "SM_CYMAXTRACK"):
    assert not re.search(r"case\s+" + metric + r"\s*:", dpi_metrics)
assert "default:\n        return get_system_metrics( index );" in dpi_metrics
state_start = source.index("static int ios_screen_cur_w, ios_screen_cur_h;")
state_end = source.index("static void ios_screen_size", state_start)
table_start = source.index("static const struct { short w, h; } ios_standard_modes[]")
table_end = source.index("\n};", table_start) + 3

harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
_Static_assert(INT_MAX == 2147483647, "tests require 32-bit int, as on iOS");
#define WINE_IOS 1
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TRUE 1
#define FALSE 0
typedef int BOOL;
typedef int32_t LONG;
typedef uint32_t DWORD;
typedef unsigned int UINT;
typedef int64_t INT64;
typedef struct { int unused; } UNICODE_STRING;
typedef struct { DWORD dmFields, dmPelsWidth, dmPelsHeight; } DEVMODEW;
/* Stable Win32 constants. No Windows ABI or guest code is involved. */
enum { SM_CXSCREEN = 0, SM_CYSCREEN = 1,
       SM_CXFULLSCREEN = 16, SM_CYFULLSCREEN = 17,
       SM_CXMIN = 28, SM_CYMIN = 29, SM_CXMINTRACK = 34, SM_CYMINTRACK = 35,
       SM_CXMAXTRACK = 59, SM_CYMAXTRACK = 60,
       SM_CXMAXIMIZED = 61, SM_CYMAXIMIZED = 62 };
#define DM_PELSWIDTH 0x00080000u
#define DM_PELSHEIGHT 0x00100000u
#define CDS_TEST 0x00000002u
#define CDS_NORESET 0x10000000u
#define DISP_CHANGE_SUCCESSFUL 0
#define DISP_CHANGE_BADMODE (-2)
#define DISP_CHANGE_BADPARAM (-5)
static unsigned publications, initial_publications;
static BOOL ios_virtual_device_name(const UNICODE_STRING *name) { return !name; }
static void ios_publish_screen_size(BOOL broadcast) { assert(broadcast); ++publications; }
static void ios_publish_screen_size_once(void) { ++initial_publications; }
@STATE@
@SCREEN_SIZE@
@STANDARD_MODES@
@MODE_POLICY@
@CHANGE_MODE@
int get_system_metrics(int index)
{
@IOS_METRICS@
    fprintf(stderr, "unexpected non-iOS metric %d\n", index);
    abort();
}

static void env(const char *name, const char *value)
{
    assert((value ? setenv(name, value, 1) : unsetenv(name)) == 0);
}

static void session(const char *width, const char *height)
{
    ios_screen_cur_w = ios_screen_cur_h = 0;
    ios_screen_def_w = ios_screen_def_h = 0;
    publications = initial_publications = 0;
    env("MADEIRA_SCREEN_W", width);
    env("MADEIRA_SCREEN_H", height);
    env("MADEIRA_SCREEN_SRC", "host-test");
}

static void expect(int metric, int value)
{
    int actual = get_system_metrics(metric);
    if (actual != value)
    {
        fprintf(stderr, "FAIL: metric %d for session %sx%s (current %dx%d): expected %d, got %d\n",
                metric, getenv("MADEIRA_SCREEN_W"), getenv("MADEIRA_SCREEN_H"),
                ios_screen_cur_w, ios_screen_cur_h, value, actual);
        exit(1);
    }
}

static void tracks(int width, int height)
{
    unsigned before = initial_publications;
    expect(SM_CXMAXTRACK, width);
    expect(SM_CYMAXTRACK, height);
    /* These queries read the current size without extra server/UI work. */
    assert(initial_publications == before);
}

static void existing_metrics(int width, int height)
{
    expect(SM_CXMIN, 132); expect(SM_CYMIN, 38);
    expect(SM_CXMINTRACK, 132); expect(SM_CYMINTRACK, 38);
    expect(SM_CXSCREEN, width); expect(SM_CYSCREEN, height);
    expect(SM_CXFULLSCREEN, width); expect(SM_CYFULLSCREEN, height - 23);
    expect(SM_CXMAXIMIZED, width + 16); expect(SM_CYMAXIMIZED, height + 8);
}

static LONG change_mode(DWORD width, DWORD height, DWORD flags)
{
    const DEVMODEW mode = { DM_PELSWIDTH | DM_PELSHEIGHT, width, height };
    return ios_virtual_change_display_settings(NULL, &mode, flags);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--probe"))
    {
        const char *modes[][2] = {{"1408", "648"}, {"1920", "1080"},
                                  {"1728", "1200"}, {"2560", "1440"},
                                  {"3840", "2160"}, {"2147483647", "2147483647"}};
        for (unsigned i = 0; i < ARRAY_SIZE(modes); ++i)
        {
            session(modes[i][0], modes[i][1]);
            printf("screen=%sx%s max-track=%dx%d\n", modes[i][0], modes[i][1],
                   get_system_metrics(SM_CXMAXTRACK), get_system_metrics(SM_CYMAXTRACK));
        }
        return 0;
    }
    env("MADEIRA_VIRTUAL_MODE_SET", argc > 1 ? "0" : "1");
    session("2560", "1440");
    if (argc > 1)
    {
        assert(change_mode(800, 600, 0) == DISP_CHANGE_SUCCESSFUL);
        tracks(2576, 1456); existing_metrics(2560, 1440);
        assert(publications == 0);
        puts("PASS: disabled mode programming retains current metrics");
        return 0;
    }
    session(NULL, NULL); tracks(1920, 1080); existing_metrics(1024, 768);
    session("1408", "648"); tracks(1920, 1080); existing_metrics(1408, 648);
    session("1280", "720"); tracks(1920, 1080); existing_metrics(1280, 720);
    session("2560", "1440"); tracks(2576, 1456); existing_metrics(2560, 1440);
    session("1728", "1200"); tracks(1920, 1216); existing_metrics(1728, 1200);
    session("2560", "720"); tracks(2576, 1080); existing_metrics(2560, 720);
    session("1080", "1920"); tracks(1920, 1936); existing_metrics(1080, 1920);
    session("3840", "2160"); tracks(3856, 2176); existing_metrics(3840, 2160);
    session("1904", "1064"); tracks(1920, 1080); existing_metrics(1904, 1064);
    session("1905", "1065"); tracks(1921, 1081); existing_metrics(1905, 1065);
    session("1920", "1080"); tracks(1936, 1096); existing_metrics(1920, 1080);
    puts("PASS: small, large, one-axis, portrait and boundary metrics");

    /* Real production mode callback: growth, test/noreset, shrink and restore. */
    session("1280", "720"); tracks(1920, 1080);
    env("MADEIRA_SCREEN_W", "3840"); env("MADEIRA_SCREEN_H", "2160");
    tracks(1920, 1080); /* Later environment edits are not mode changes. */
    assert(change_mode(2560, 1440, CDS_TEST) == DISP_CHANGE_SUCCESSFUL);
    tracks(1920, 1080); assert(publications == 0);
    assert(change_mode(2560, 1440, CDS_NORESET) == DISP_CHANGE_SUCCESSFUL);
    tracks(1920, 1080); assert(publications == 0);
    assert(change_mode(2560, 1440, 0) == DISP_CHANGE_SUCCESSFUL);
    tracks(2576, 1456); existing_metrics(2560, 1440); assert(publications == 1);
    assert(change_mode(800, 600, 0) == DISP_CHANGE_SUCCESSFUL);
    tracks(1920, 1080); existing_metrics(800, 600); assert(publications == 2);
    assert(ios_virtual_change_display_settings(NULL, NULL, 0) == DISP_CHANGE_SUCCESSFUL);
    tracks(1920, 1080); existing_metrics(1280, 720); assert(publications == 3);
    assert(change_mode(0, 0, 0) == DISP_CHANGE_BADMODE);
    assert(change_mode(UINT32_MAX, UINT32_MAX, 0) == DISP_CHANGE_BADMODE);
    assert(change_mode(12345, 6789, 0) == DISP_CHANGE_BADMODE);
    tracks(1920, 1080); existing_metrics(1280, 720); assert(publications == 3);
    assert(ios_screen_def_w == 1280 && ios_screen_def_h == 720);
    puts("PASS: changed modes, test/noreset, session restore and rejected sizes");

    session("0", "-20"); tracks(1920, 1080); existing_metrics(1024, 768);
    session("nonsense", ""); tracks(1920, 1080); existing_metrics(1024, 768);
    session("2560", "0"); tracks(2576, 1080); existing_metrics(2560, 768);
    session("1", "1"); tracks(1920, 1080);
    /* Do not query unrelated maximized metrics here: their old +16/+8
     * arithmetic is outside this fix. All supplied env values fit int. */
    session("2147483630", "2147483630"); tracks(INT_MAX - 1, INT_MAX - 1);
    session("2147483631", "2147483631"); tracks(INT_MAX, INT_MAX);
    session("2147483632", "2147483632"); tracks(INT_MAX, INT_MAX);
    session("2147483647", "2147483647"); tracks(INT_MAX, INT_MAX);
    puts("PASS: invalid env fallback, tiny sizes and INT_MAX saturation");
    return 0;
}
'''

for marker, fragment in {
    "STATE": source[state_start:state_end],
    "SCREEN_SIZE": function("static void ios_screen_size("),
    "STANDARD_MODES": source[table_start:table_end],
    "MODE_POLICY": function("static int ios_virtual_mode_set_enabled("),
    "CHANGE_MODE": function("static LONG ios_virtual_change_display_settings("),
    "IOS_METRICS": ios_metrics,
}.items():
    harness = harness.replace("@" + marker + "@", fragment)

with tempfile.TemporaryDirectory(prefix="madeira-max-track-") as directory:
    directory = Path(directory)
    c_file, binary = directory / "metrics.c", directory / "metrics"
    c_file.write_text(harness)
    command = shlex.split(os.environ.get("CC", "cc"))
    command += ["-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror"]
    command += shlex.split(os.environ.get("CFLAGS", ""))
    subprocess.run(command + [str(c_file), "-o", str(binary)], check=True)
    subprocess.run([str(binary)] + (["--probe"] if args.probe else []), check=True)
    if not args.probe:
        subprocess.run([str(binary), "--mode-programming-disabled"], check=True)
        print("PASS: source check confirms max-track DPI delegation is unchanged")
