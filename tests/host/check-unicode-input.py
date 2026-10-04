#!/usr/bin/env python3
"""Compile the production text queue and Unicode driver bridge on a POSIX host.

No Wine submodule or iOS SDK is needed. CC defaults to cc; CFLAGS can enable
ASan/UBSan. Also executes the extracted Swift encoder when swiftc is available;
otherwise reports that part as skipped, never as device/1C verification.
"""
from pathlib import Path
import os
import shlex
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
app = root / 'app/Madeira'
header = (app / 'Winios/Winios.h').read_text()
native = (app / 'Winios/Winios.m').read_text()
driver = (root / 'build/win32u-unix/driver_ios.c').read_text()
content = (app / 'ContentView.swift').read_text()
library = (app / 'Library.swift').read_text()


def function(source, name):
    start = source.index(name)
    left = source.index('{', start)
    level = 1
    end = left + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


api = header[header.index('#define WINIOS_TEXT_MAX_UNITS'):header.index('/* S2 desktop compositor placement.')]
queue = native[native.index('#define WINIOS_RING_SIZE'):native.index('/* end winios_reset_input */')]
unicode_driver = function(driver, 'void winios_drv_post_unicode(')

# Verify the actual callback route, frontend use, and downstream Wine contract.
assert 'winios_reset_input();' in function(native, 'void winios_session_reset(')
assert 'return winios_drain_input();' in function(native, 'BOOL winios_pProcessEvents(')
assert 'winios_user_driver.pProcessEvents       = winios_pProcessEvents;' in driver
for source, name in ((content, 'extension MetalBackedView: UIKeyInput'), (library, 'final class LibraryKeyInput:')):
    section = source[source.index(name):]
    insert = function(section, 'func insertText(')
    assert 'SoftwareTextInput.insert(' in insert and 'else { continue }' not in insert
    assert 'var keyboardType: UIKeyboardType { get { .default } set {} }' in section
assert 'if HardwareInput.shared.handlesTyping { return }' in function(content, 'func insertText(')
assert 'shiftHeld: held.contains(0x10)' in library
assert 'text.utf16.prefix(limit + 1).count <= limit' in content
assert 'String(ch).utf16' in content
assert 'if accepted == 0' in content and 'UIAlertController(title: "Text was not entered"' in content
assert 'presentedViewController is UIAlertController ? super.hitTest' in library
assert 'ch.uppercased()' not in function(content, 'static func vkForChar(')
server = (root / 'build/wineserver/queue_ios.c').read_text()
messages = (root / 'build/win32u-unix/message_ios.c').read_text()
assert 'if (unicode) vkey = hook_vkey = VK_PACKET;' in server
assert 'if (!unicode || input->kbd.vkey)' in server
assert 'NtUserPostMessage( msg->hwnd, message, HIWORD(msg->lParam), LOWORD(msg->lParam) );' in messages

prefix = r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#define KEYEVENTF_UNICODE 4
#define KEYEVENTF_KEYUP 0x0002
#define INPUT_KEYBOARD 1
#define WINIOS_TEST_CAPACITY 20000
typedef int NTSTATUS;
typedef struct { unsigned short wVk, wScan; unsigned int dwFlags, time; uintptr_t dwExtraInfo; } KEYBDINPUT;
typedef struct { unsigned int type; KEYBDINPUT ki; } INPUT;
static int winios_drain_input(void);
static void winios_drv_post_key(unsigned short, unsigned int);
static void winios_drv_post_mouse(int, int, unsigned int, unsigned int, void *);
static NTSTATUS send_hardware_message(void *, unsigned int, const INPUT *, long);
static _Atomic unsigned int allocations;
static int fail_allocation;
static void *test_malloc(size_t size) {
    if (fail_allocation) return NULL;
    void *ptr = malloc(size);
    if (ptr) atomic_fetch_add(&allocations, 1);
    return ptr;
}
static void test_free(void *ptr) {
    assert(ptr);
    atomic_fetch_sub(&allocations, 1);
    free(ptr);
}
#define malloc test_malloc
#define free test_free
'''
harness = r'''
#undef malloc
#undef free
struct event { int kind; unsigned short value; unsigned int flags; };
static struct event events[WINIOS_TEST_CAPACITY];
static unsigned int event_count;
static int recursion_check, capacity_check;
static _Atomic int pause_first, dispatch_paused, resume_dispatch, reset_started, reset_done;
static void record(int kind, unsigned short value, unsigned int flags) {
    assert(event_count < WINIOS_TEST_CAPACITY);
    events[event_count++] = (struct event){kind, value, flags};
    if (atomic_exchange(&pause_first, 0)) {
        atomic_store(&dispatch_paused, 1);
        while (!atomic_load(&resume_dispatch)) sched_yield();
    }
    if (recursion_check) assert(!winios_drain_input());
    if (capacity_check) {
        winios_text_key key = {0x0410, WINIOS_TEXT_UNICODE};
        assert(!winios_post_text(&key, 1)); /* inflight batch still counts */
    }
}
static void winios_drv_post_key(unsigned short value, unsigned int flags) { record(1, value, flags); }
static void winios_drv_post_mouse(int x, int y, unsigned int flags, unsigned int data, void *hwnd) {
    (void)x; (void)y; (void)data; (void)hwnd;
    record(0, 0, flags);
}
static NTSTATUS send_hardware_message(void *hwnd, unsigned int flags, const INPUT *input, long lparam) {
    assert(!hwnd && !flags && !lparam);
    assert(input->type == INPUT_KEYBOARD && input->ki.wVk == 0);
    assert(!input->ki.time && !input->ki.dwExtraInfo);
    record(2, input->ki.wScan, input->ki.dwFlags);
    return 0;
}
static void expect(unsigned int i, int kind, unsigned short value, unsigned int flags) {
    assert(i < event_count);
    assert(events[i].kind == kind && events[i].value == value && events[i].flags == flags);
}
static void drain_all(void) {
    while (winios_drain_input()) {}
}
static void clean(void) {
    assert(!winios_drain_input());
    assert(g_input_q.head == g_input_q.tail && !g_input_q.text_units && !atomic_load(&allocations));
    event_count = 0;
}
static _Atomic int producers_done;
static void *produce(void *arg) {
    unsigned short unit = (unsigned short)(uintptr_t)arg;
    winios_text_key keys[10];
    for (unsigned int i = 0; i < 10; ++i) keys[i] = (winios_text_key){unit, WINIOS_TEXT_UNICODE};
    for (unsigned int i = 0; i < 100; ++i) {
        while (!winios_post_text(keys, 10)) sched_yield();
    }
    atomic_fetch_add(&producers_done, 1);
    return NULL;
}
static void *consume(void *unused) {
    (void)unused;
    while (atomic_load(&producers_done) != 3) {
        winios_drain_input();
        sched_yield();
    }
    winios_drain_input();
    return NULL;
}
static void *pump_once(void *unused) {
    (void)unused;
    winios_drain_input();
    return NULL;
}
static void *reset_session(void *unused) {
    (void)unused;
    atomic_store(&reset_started, 1);
    winios_reset_input();
    atomic_store(&reset_done, 1);
    return NULL;
}
int main(void) {
    winios_text_key keys[WINIOS_TEXT_MAX_UNITS];
    assert(winios_post_text(NULL, 0));
    assert(!winios_post_text(NULL, 1));
    assert(!winios_post_text(keys, WINIOS_TEXT_MAX_UNITS + 1));
    keys[0] = (winios_text_key){0x41, 3};
    assert(!winios_post_text(keys, 1));
    keys[0] = (winios_text_key){0x100, 0};
    assert(!winios_post_text(keys, 1));
    clean();

    /* Real Cyrillic, numero sign, combining accent, and an emoji surrogate pair. */
    unsigned short units[] = {0x0411, 0x0443, 0x0445, 0x0451, 0x0401, 0x2116, 0x0301, 0xd83d, 0xde00};
    for (unsigned int i = 0; i < sizeof(units)/sizeof(*units); ++i)
        keys[i] = (winios_text_key){units[i], WINIOS_TEXT_UNICODE};
    assert(winios_post_text(keys, sizeof(units)/sizeof(*units)));
    keys[0].value = 0; /* queue owns a copy, not the caller's buffer */
    recursion_check = 1;
    assert(winios_drain_input());
    drain_all();
    recursion_check = 0;
    assert(event_count == 2 * sizeof(units)/sizeof(*units));
    for (unsigned int i = 0; i < sizeof(units)/sizeof(*units); ++i) {
        expect(i*2, 2, units[i], KEYEVENTF_UNICODE);
        expect(i*2+1, 2, units[i], KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
    }
    clean();

    /* All 16 bits survive; neither layout mapping nor scan-byte truncation. */
    for (unsigned int base = 0; base < 65536; base += WINIOS_TEXT_MAX_UNITS) {
        for (unsigned int i = 0; i < WINIOS_TEXT_MAX_UNITS; ++i)
            keys[i] = (winios_text_key){base + i, WINIOS_TEXT_UNICODE};
        assert(winios_post_text(keys, WINIOS_TEXT_MAX_UNITS));
        assert(!winios_post_text(keys, 1));
        capacity_check = 1;
        assert(winios_drain_input());
    drain_all();
        capacity_check = 0;
        assert(event_count == WINIOS_TEXT_MAX_UNITS * 2);
        for (unsigned int i = 0; i < WINIOS_TEXT_MAX_UNITS; ++i) {
            expect(i*2, 2, base+i, 4);
            expect(i*2+1, 2, base+i, 6);
        }
        clean();
    }

    /* ASCII symbols/shortcuts still use virtual keys, with balanced shift. */
    keys[0] = (winios_text_key){0x41, WINIOS_TEXT_SHIFT};
    keys[1] = (winios_text_key){0x42, 0};
    winios_q_push_ev(WINIOS_EV_KEY, 0x11, 0, 0, 0); /* held Ctrl */
    assert(winios_post_text(keys, 2));
    winios_q_push_ev(WINIOS_EV_KEY, 0x11, 0, 2, 0);
    assert(winios_drain_input());
    drain_all();
    assert(event_count == 8);
    expect(0, 1, 0x11, 0); expect(1, 1, 0x10, 0);
    expect(2, 1, 0x41, 0); expect(3, 1, 0x41, 2);
    expect(4, 1, 0x10, 2); expect(5, 1, 0x42, 0);
    expect(6, 1, 0x42, 2); expect(7, 1, 0x11, 2);
    clean();

    /* Ring pressure and allocator failure reject the entire insertion. */
    for (unsigned int i = 0; i < WINIOS_RING_SIZE - 1; ++i)
        winios_q_push_ev(WINIOS_EV_MOUSE, 0, 0, 1, 0);
    assert(!winios_post_text(keys, 2));
    assert(!g_input_q.text_units && !atomic_load(&allocations));
    assert(winios_drain_input());
    drain_all();
    assert(event_count == WINIOS_RING_SIZE - 1);
    clean();
    fail_allocation = 1;
    assert(!winios_post_text(keys, 2));
    fail_allocation = 0;
    clean();
    assert(winios_post_text(keys, 2)); /* retry succeeds after pressure clears */
    assert(winios_drain_input());
    drain_all();
    assert(event_count == 6);
    clean();

    /* Capacity is global, not per batch; no unchecked multi-paste growth. */
    for (unsigned int i = 0; i < WINIOS_TEXT_MAX_UNITS; ++i)
        keys[i] = (winios_text_key){0x0410, WINIOS_TEXT_UNICODE};
    assert(winios_post_text(keys, 2048));
    assert(!winios_post_text(keys, 2049));
    assert(winios_post_text(keys, 2048));
    assert(!winios_post_text(keys, 1));
    assert(winios_drain_input());
    drain_all();
    assert(event_count == 8192);
    clean();

    /* A pump is bounded, and session reset frees partially drained batches. */
    assert(winios_post_text(keys, WINIOS_TEXT_MAX_UNITS));
    assert(winios_drain_input());
    assert(event_count == WINIOS_INPUT_DRAIN_BUDGET * 2);
    assert(g_input_q.text_units == WINIOS_TEXT_MAX_UNITS);
    winios_reset_input();
    clean();
    assert(winios_post_text(keys, WINIOS_TEXT_MAX_UNITS));
    winios_reset_input();
    clean();

    /* A simultaneous reset waits for an in-flight record before freeing it. */
    assert(winios_post_text(keys, WINIOS_TEXT_MAX_UNITS));
    atomic_store(&pause_first, 1);
    pthread_t pump, resetter;
    assert(!pthread_create(&pump, NULL, pump_once, NULL));
    while (!atomic_load(&dispatch_paused)) sched_yield();
    assert(!pthread_create(&resetter, NULL, reset_session, NULL));
    while (!atomic_load(&reset_started)) sched_yield();
    assert(!atomic_load(&reset_done));
    atomic_store(&resume_dispatch, 1);
    assert(!pthread_join(pump, NULL));
    assert(!pthread_join(resetter, NULL));
    assert(atomic_load(&reset_done));
    assert(event_count == WINIOS_INPUT_DRAIN_BUDGET * 2);
    clean();

    /* Parallel producers and pumps must never interleave a down/up pair. */
    pthread_t producers[3], consumers[2];
    for (uintptr_t i = 0; i < 3; ++i) assert(!pthread_create(&producers[i], NULL, produce, (void *)(0x0410+i)));
    for (unsigned int i = 0; i < 2; ++i) assert(!pthread_create(&consumers[i], NULL, consume, NULL));
    for (unsigned int i = 0; i < 3; ++i) assert(!pthread_join(producers[i], NULL));
    for (unsigned int i = 0; i < 2; ++i) assert(!pthread_join(consumers[i], NULL));
    drain_all();
    assert(event_count == 6000);
    unsigned int counts[3] = {0};
    for (unsigned int i = 0; i < event_count; i += 2) {
        assert(events[i].value >= 0x0410 && events[i].value <= 0x0412);
        expect(i, 2, events[i].value, 4);
        expect(i+1, 2, events[i].value, 6);
        ++counts[events[i].value - 0x0410];
    }
    assert(counts[0] == 1000 && counts[1] == 1000 && counts[2] == 1000);
    clean();
    puts("PASS: Unicode bridge, atomic/bounded queue, retries, reentrancy and concurrent pumps");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-unicode-') as tmp:
    tmp = Path(tmp)
    cfile, exe = tmp / 'text.c', tmp / 'text'
    cfile.write_text('\n'.join((prefix, api, unicode_driver, queue, harness)))
    cmd = [os.environ.get('CC', 'cc'), '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra', '-Werror', '-pthread']
    cmd += shlex.split(os.environ.get('CFLAGS', ''))
    subprocess.run(cmd + [str(cfile), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30)

    swiftc = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
    if swiftc:
        hfile = tmp / 'text.h'
        hfile.write_text(api)
        stub = tmp / 'swift-bridge.c'
        stub.write_text('#include "text.h"\nint winios_post_text(const winios_text_key *keys, unsigned int count) { return !count || (keys && count <= WINIOS_TEXT_MAX_UNITS); }\n')
        subprocess.run([os.environ.get('CC', 'cc'), '-c', str(stub), '-o', str(tmp / 'swift-bridge.o')], check=True)
        sfile = tmp / 'text.swift'
        sfile.write_text('enum MetalBackedView {\n' + function(content, 'static func vkForChar(') + '\n}\n'
                        + 'enum SoftwareTextInput {\n' + function(content, 'static func keys(for text:') + '\n}\n' + r'''
let text = "Проверка Ёё №1 C:\\Базы\\Бухгалтерия 😀 e\u{0301} ß ı ſ ﬀ"
let keys = SoftwareTextInput.keys(for: text, shiftHeld: false)!
let accepted = keys.withUnsafeBufferPointer { winios_post_text($0.baseAddress, UInt32($0.count)) }
assert(accepted == 1)
assert([winios_text_key]().withUnsafeBufferPointer { winios_post_text($0.baseAddress, UInt32($0.count)) } == 1)
let fallback = keys.filter { $0.flags == WINIOS_TEXT_UNICODE }.map { $0.value }
let expected = text.filter { MetalBackedView.vkForChar($0) == nil }.utf16
assert(fallback == Array(expected))
assert(SoftwareTextInput.keys(for: String(repeating: "Я", count: 4096), shiftHeld: false)!.count == 4096)
assert(SoftwareTextInput.keys(for: String(repeating: "Я", count: 4097), shiftHeld: false) == nil)
assert(SoftwareTextInput.keys(for: String(repeating: "😀", count: 2048), shiftHeld: false)!.count == 4096)
assert(SoftwareTextInput.keys(for: String(repeating: "😀", count: 2049), shiftHeld: false) == nil)
let shifted = SoftwareTextInput.keys(for: "Aa_", shiftHeld: false)!
assert(shifted.map { $0.value } == [0x41, 0x41, 0xbd])
assert(shifted.map { $0.flags } == [2, 0, 2])
assert(SoftwareTextInput.keys(for: "A_", shiftHeld: true)!.allSatisfy { $0.flags == 0 })
assert(SoftwareTextInput.keys(for: "", shiftHeld: false)!.isEmpty)
print("PASS: production Swift Unicode/ASCII encoding, held shift, and UTF-16 limits")
''')
        subprocess.run([swiftc, '-import-objc-header', str(hfile), str(sfile), str(tmp / 'swift-bridge.o'), '-o', str(tmp / 'swift-text')], check=True)
        subprocess.run([str(tmp / 'swift-text')], check=True, timeout=30)
    else:
        print('SKIP: Swift execution (swiftc not installed); frontend wiring checked from source')
print('PASS: frontend wiring and existing Wine VK_PACKET/WM_CHAR contract')
