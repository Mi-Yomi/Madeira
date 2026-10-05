#!/usr/bin/env python3
"""Compile the production clipboard-text encoder and user-action wrapper.

Mocks UIKit identity/lifecycle and the system pasteboard; never reads the host
clipboard. The native copy/queue behavior is covered by check-unicode-input.py.
This does not validate Apple's permission UI or Windows/1C field behavior.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-only', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
content = (root / 'app/Madeira/ContentView.swift').read_text()
library = (root / 'app/Madeira/Library.swift').read_text()
hardware = (root / 'app/Madeira/HardwareInput.swift').read_text()
header = (root / 'app/Madeira/Winios/Winios.h').read_text()


def require(value, message):
    if not value:
        raise SystemExit('FAIL: ' + message)


def block(source, start):
    left = source.index(start)
    brace = source.index('{', left)
    level, end = 1, brace + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[left:end]


encoder = block(content, '@MainActor enum ClipboardTextInput')
wrapper = block(library, '    private func typeClipboardText()')
held_edges = block(hardware, 'struct HeldEdges<')
focus_gate = block(hardware, 'struct FocusGate<')
held_getter = block(hardware, '    var hasHeldKeys: Bool')
quit_request = block(library, '    func requestQuit()')
require(quit_request.index('LibraryKeyboard.hide()') < quit_request.index('quitRequested = true'),
        'quit cancels the exact keyboard before requesting exit')
require('LibraryKeyboard.hide()' in block(library, '    private func finish()'),
        'session completion cancels the keyboard even for the same library entry')
require(wrapper.count('UIPasteboard.general.string') == 1, 'one explicit pasteboard read')
require(library.count('UIPasteboard.general.string') == 2,
        'only explicit text read and existing shortcut-link write')
require('paste.addAction(UIAction { [weak self] _ in self?.typeClipboardText() }, for: .touchUpInside)' in library,
        'text insertion must be a user action')
require('paste.setTitle("Type clipboard text"' in library, 'label must describe text insertion')
require('text.utf16.prefix(limit + 1).count <= limit' in encoder, 'bound UTF-16 before conversion')
require(encoder.index('text.utf16.prefix') < encoder.index('var keys:'), 'check bound before allocating keys')
require('HardwareInput.shared.hasHeldKeys' in wrapper and 'self.held.isEmpty' in wrapper
        and 'winios_text_keys_held() == 0' in wrapper,
        'hardware, accessory and shared native key guards')
require('var hasHeldKeys: Bool { !keys.physical.isEmpty || !keysPosted.down.isEmpty }' in hardware,
        'physical/posted keys must both block text insertion')
require('winios_post_key' not in wrapper + encoder, 'literal text must not become keyboard shortcuts')
require('LogStore' not in encoder and 'print(' not in encoder, 'clipboard text must not be logged')
require('check-clipboard-text.py' in (root / '.github/workflows/desktop-compatibility.yml').read_text(),
        'compiled check is in CI')
print('PASS: explicit-only read, bounded Unicode conversion, wiring, key guards and CI', flush=True)
if args.source_only:
    print('SKIP: compiled clipboard behavior (--source-only)')
    raise SystemExit(0)
compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
require(compiler, 'swiftc missing; set SWIFTC or explicitly use --source-only')
limit = re.search(r'#define WINIOS_TEXT_MAX_UNITS\s+(\d+)', header).group(1)
unicode_flag = re.search(r'#define WINIOS_TEXT_UNICODE\s+(\d+)', header).group(1)
stubs = r'''
import Foundation
let WINIOS_TEXT_MAX_UNITS = LIMIT
let WINIOS_TEXT_UNICODE = UNICODE_FLAG
struct winios_text_key: Equatable { var value: UInt16; var flags: UInt16 }
@MainActor final class UIViewController { var presentedViewController: UIViewController? }
@MainActor final class UIWindowScene {
    enum State { case foregroundActive, background }
    var activationState = State.foregroundActive
}
@MainActor final class UIWindow {
    var isKeyWindow = true
    var windowScene: UIWindowScene? = UIWindowScene()
    var rootViewController: UIViewController? = UIViewController()
}
@MainActor class UIView { var window: UIWindow?; var isFirstResponder = true }
@MainActor final class UIApplication {
    static let shared = UIApplication()
    enum State { case active, inactive }
    var applicationState = State.active
}
@MainActor final class UIPasteboard {
    static let general = UIPasteboard()
    var reads = 0
    var read: () -> String? = { "Тест" }
    var string: String? { reads += 1; return read() }
}
@MainActor final class LibraryModel {
    static let shared = LibraryModel()
    var current: UUID? = UUID()
    var menu = false
}
@MainActor final class HardwareInput {
    static let shared = HardwareInput()
    var keys = FocusGate<Int32>()
    var keysPosted = HeldEdges<Int32>()
HELD_GETTER
}
@MainActor enum LibraryKeyboard {
    static var input: InputStub?
    static var window: UIWindow?
}
@MainActor enum SoftwareTextInput {
    static var rejections: [String] = []
    static func rejected(_ reason: String, from view: UIView) { rejections.append(reason) }
}
@MainActor enum Queue {
    static var running: Int32 = 1
    static var accepts = true
    static var held = false
    static var batches: [[winios_text_key]] = []
}
@MainActor func wine_process_is_running() -> Int32 { Queue.running }
@MainActor func winios_text_keys_held() -> Int32 { Queue.held ? 1 : 0 }
@MainActor func winios_post_literal_text(_ keys: UnsafePointer<winios_text_key>?, _ count: UInt32) -> Int32 {
    if !Queue.accepts || Queue.held { return 0 }
    precondition(count <= WINIOS_TEXT_MAX_UNITS)
    Queue.batches.append(Array(UnsafeBufferPointer(start: keys, count: Int(count))))
    return 1
}
@MainActor final class InputStub: UIView {
    var held = Set<Int32>()
    private var clipboardReadInFlight = false
    func tap() { typeClipboardText() }
WRAPPER
}
'''.replace('LIMIT', limit).replace('UNICODE_FLAG', unicode_flag).replace('WRAPPER', wrapper).replace('HELD_GETTER', held_getter) + '\n' + held_edges + '\n' + focus_gate
tests = r'''
@main struct Tests {
    @MainActor static func ready() -> InputStub {
        let view = InputStub(); view.window = UIWindow()
        LibraryKeyboard.input = view; LibraryKeyboard.window = view.window
        LibraryModel.shared.current = UUID(); LibraryModel.shared.menu = false
        UIApplication.shared.applicationState = .active
        HardwareInput.shared.keys.reset(); _ = HardwareInput.shared.keysPosted.update([])
        UIPasteboard.general.reads = 0; UIPasteboard.general.read = { "Тест" }
        SoftwareTextInput.rejections = []; Queue.running = 1; Queue.accepts = true; Queue.held = false; Queue.batches = []
        return view
    }
    @MainActor static func expect(_ text: String?, _ outcome: ClipboardTextInput.Outcome) -> [winios_text_key] {
        var result: [winios_text_key] = []
        let actual = ClipboardTextInput.insert(readText: { text }, isCurrent: { true }, submit: { result = $0; return true })
        precondition(actual == outcome)
        if actual != .inserted { precondition(result.isEmpty) }
        return result
    }
    @MainActor static func main() {
        // Literal ASCII must stay literal under non-US Windows layouts. Include
        // Cyrillic, Kazakh, numero, emoji, a combining accent and a ZWJ sequence.
        let text = "C:\\Базы\\Бухгалтерия 1C: Ёё №1 Әә Ққ Іі 😀 e\u{0301} 👩‍💻 Aa_!"
        let keys = expect(text, .inserted)
        precondition(keys.map(\.value) == Array(text.utf16))
        precondition(keys.allSatisfy { $0.flags == WINIOS_TEXT_UNICODE })
        precondition(expect(String(repeating: "Я", count: 4096), .inserted).count == 4096)
        _ = expect(String(repeating: "Я", count: 4097), .tooLong)
        precondition(expect(String(repeating: "😀", count: 2048), .inserted).count == 4096)
        _ = expect(String(repeating: "😀", count: 2049), .tooLong)
        _ = expect("e" + String(repeating: "\u{0301}", count: 4096), .tooLong)
        _ = expect(String(repeating: "x", count: 2_000_000), .tooLong)
        _ = expect(nil, .unavailable); _ = expect("", .unavailable)
        for n in Array(0...0x1f) + Array(0x7f...0x9f) + [0x2028, 0x2029] {
            _ = expect("before" + String(UnicodeScalar(n)!) + "after", .notSingleLine)
        }
        // No silent partial insertion when a control follows otherwise valid text.
        _ = expect(String(repeating: "x", count: 4095) + "\n", .notSingleLine)
        print("PASS: exact Unicode, supplementary/combining text, bounds and all control rejections")

        // Real hardware getter: focus-blocked physical keys and posted keys
        // each block insertion until their own release/reset is observed.
        _ = ready()
        let hardware = HardwareInput.shared
        precondition(!hardware.hasHeldKeys)
        hardware.keys.press(0xa2, focused: false); precondition(hardware.hasHeldKeys)
        hardware.keys.release(0xa2); precondition(!hardware.hasHeldKeys)
        _ = hardware.keysPosted.update([0xa4]); precondition(hardware.hasHeldKeys)
        _ = hardware.keysPosted.update([]); precondition(!hardware.hasHeldKeys)
        var view = ready()
        var callerText = text
        UIPasteboard.general.read = { callerText }
        view.tap(); callerText = "changed later"
        precondition(UIPasteboard.general.reads == 1 && Queue.batches == [keys])
        precondition(SoftwareTextInput.rejections.isEmpty)
        // Permission denial/no plain-text result must never call submit.
        view = ready(); UIPasteboard.general.read = { nil }; view.tap()
        precondition(Queue.batches.isEmpty && SoftwareTextInput.rejections.count == 1)
        // Busy queues report a rejection, and one later user action can retry.
        view = ready(); Queue.accepts = false; view.tap()
        precondition(Queue.batches.isEmpty && SoftwareTextInput.rejections.count == 1)
        Queue.accepts = true; view.tap(); precondition(Queue.batches.count == 1)
        // A reentrant tap during the system read cannot trigger another read.
        view = ready(); let reentrant = view
        UIPasteboard.general.read = { reentrant.tap(); return "text" }
        view.tap(); precondition(UIPasteboard.general.reads == 1 && Queue.batches.count == 1)
        // A producer can change native state after the final UI guard. The
        // atomic native admission remains authoritative and reports rejection.
        _ = ready()
        let lateKey = ClipboardTextInput.insert(readText: { "text" }, isCurrent: { true }, submit: { keys in
            Queue.held = true
            return keys.withUnsafeBufferPointer { winios_post_literal_text($0.baseAddress, UInt32($0.count)) != 0 }
        })
        precondition(lateKey == .queueBusy && Queue.batches.isEmpty)
        print("PASS: production action, copied payload lifetime, denied reads, retry, reentrancy and late key refusal")

        // Every target guard is checked both before a read and after a potentially
        // reentrant permission read. No read just to discover disabled state.
        let changes: [(InputStub) -> Void] = [
            { _ in LibraryKeyboard.input = nil },
            { _ in LibraryKeyboard.input = InputStub() }, // same app/session, new keyboard
            { _ in LibraryKeyboard.window = UIWindow() },
            { $0.window = nil }, { $0.window = UIWindow() },
            { $0.isFirstResponder = false }, { $0.window?.isKeyWindow = false },
            { $0.window?.windowScene?.activationState = .background },
            { $0.window?.rootViewController?.presentedViewController = UIViewController() },
            { _ in UIApplication.shared.applicationState = .inactive },
            { _ in LibraryModel.shared.current = nil },
            { _ in LibraryModel.shared.menu = true },
            { _ in Queue.running = 0 }, { $0.held.insert(0x11) },
            { _ in HardwareInput.shared.keys.press(0xa2, focused: false) },
            { _ in Queue.held = true },
        ]
        for change in changes {
            let before = ready(); change(before); before.tap()
            precondition(UIPasteboard.general.reads == 0 && Queue.batches.isEmpty)
            let after = ready()
            UIPasteboard.general.read = { change(after); return "must not arrive" }
            after.tap()
            precondition(UIPasteboard.general.reads == 1 && Queue.batches.isEmpty)
        }
        view = ready()
        UIPasteboard.general.read = { LibraryModel.shared.current = UUID(); return "old session text" }
        view.tap(); precondition(UIPasteboard.general.reads == 1 && Queue.batches.isEmpty)
        // Encoding itself cannot commit after the final target guard fails.
        var checks = 0, submissions = 0
        let cancelled = ClipboardTextInput.insert(readText: { "hello" }, isCurrent: { checks += 1; return checks < 3 },
                                                   submit: { _ in submissions += 1; return true })
        precondition(cancelled == .cancelled && submissions == 0)
        print("PASS: 16 invalid target states before/after reading, changed session, final commit guard")
    }
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-clipboard-text-') as tmp:
    tmp = Path(tmp)
    source, binary = tmp / 'main.swift', tmp / 'check'
    source.write_text(stubs + '\n' + encoder + '\n' + tests)
    subprocess.run([compiler, '-module-cache-path', str(tmp / 'module-cache'), '-parse-as-library', '-swift-version', '5', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
