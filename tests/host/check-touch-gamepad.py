#!/usr/bin/env python3
"""Exercise the production touch ownership/arbitration logic without an iOS SDK."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/TouchGamepad.swift').read_text()
pure = source.split('// MARK: - Pure touch state', 1)[1].split('// MARK: - UIKit touch lifetime', 1)[0]
pure = pure[pure.index('struct GamepadSample'):]
tests = r'''
let a = UUID(), b = UUID(), owner1 = UUID(), owner2 = UUID()
var state = TouchGamepadState()
assert(!state.connected)
state.configure([a, b])
assert(state.connected && state.sample == GamepadSample())
state.update(owner: owner1, control: a, value: TouchPadAction.sample("A"))
state.update(owner: owner2, control: b, value: TouchPadAction.sample("A"))
state.update(owner: owner1, control: a, value: nil)
assert(state.sample.buttons == 0x1000) // one release cannot cancel another finger
state.update(owner: owner2, control: b, value: nil)
assert(state.sample.buttons == 0)
state.update(owner: owner1, control: UUID(), value: TouchPadAction.sample("B"))
assert(state.sample.buttons == 0) // stale/removed control cannot create a hold
state.update(owner: owner1, control: a, value: TouchPadAction.sample("LT"))
state.update(owner: owner2, control: b, value: TouchPadAction.sample("RT"))
assert(state.sample.lt == 255 && state.sample.rt == 255)
state.clear() // background/cancel: neutral but virtual pad stays connected
assert(state.connected && state.sample == GamepadSample())
state.update(owner: owner1, control: a, value: TouchPadAction.sample("X"))
state.configure([]) // hidden/portrait/disappeared
assert(!state.connected && state.sample == GamepadSample())
state.update(owner: owner1, control: a, value: TouchPadAction.sample("X"))
assert(state.sample == GamepadSample())
state.configure([a])
state.update(owner: owner1, control: a, value: TouchPadAction.sample("B"))
state.configure([a]) // remap preserving the same ID must release old action
assert(state.sample == GamepadSample())
let left = TouchPadAction.sample("LS", x: -1, y: 0)
let up = TouchPadAction.sample("RS", x: 0, y: 1)
assert(left.lx == -32768 && left.ly == 0)
assert(up.ry == 32767 && up.rx == 0)
let diagonal = TouchPadAction.sample("LS", x: 1, y: 1)
assert(diagonal.lx == 23170 && diagonal.ly == 23170)
assert(TouchPadAction.sample("LS", x: .nan, y: 1) == GamepadSample())
assert(GamepadSample.axis(-2) == -32768 && GamepadSample.axis(2) == 32767)
var physical = GamepadSample(buttons: 0x1000, lt: 37, lx: 1000, ly: 2000)
assert(GamepadSample.merge(physical: physical, touch: GamepadSample()) == physical)
var touch = TouchPadAction.sample("B")
touch.lt = 255; touch.rx = 10000
var combined = GamepadSample.merge(physical: physical, touch: touch)
assert(combined.buttons == 0x3000 && combined.lt == 255 && combined.rx == 10000)
assert(combined.lx == 1000 && combined.ly == 2000)
physical.lx = 20000
combined = GamepadSample.merge(physical: physical, touch: left)
assert(combined.lx == 20000) // deflected physical stick wins arbitration
physical.lx = 0; physical.ly = 0
assert(GamepadSample.merge(physical: physical, touch: left).lx == -32768)
assert(GamepadSample.merge(physical: physical, touch: GamepadSample()).buttons == 0x1000)
for (name, mask) in TouchPadAction.buttons {
    assert(TouchPadAction.supported(name) && TouchPadAction.sample(name).buttons == mask)
}
assert(!TouchPadAction.supported("unknown"))
// Multiple touches on analogue controls aggregate deterministically.
state.configure([a, b])
state.update(owner: owner1, control: a, value: left)
state.update(owner: owner2, control: b, value: TouchPadAction.sample("LS", x: 0.5))
assert(state.sample.lx == -32768)
state.update(owner: owner1, control: a, value: nil)
assert(state.sample.lx == 16384)
// ml1990: a session reservation keeps player 1 connected at rest.
var session = TouchGamepadState()
session.reserved = true
assert(session.connected && session.sample == GamepadSample())
session.configure([a])
session.update(owner: owner1, control: a, value: TouchPadAction.sample("A"))
assert(session.sample.buttons == 0x1000)
session.configure([]) // hidden/portrait: holds released, slot kept
assert(session.connected && session.sample == GamepadSample())
session.update(owner: owner1, control: a, value: TouchPadAction.sample("A"))
assert(session.sample == GamepadSample())
session.clear()
assert(session.connected)
// Opening the session menu to show the keyboard must not hot-unplug the pad.
var keyboardMenu = TouchGamepadState()
keyboardMenu.configure([a], acceptingInput: false) // game still launching
assert(!keyboardMenu.connected) // do not change the opt-in early-slot policy
keyboardMenu.configure([a])
keyboardMenu.update(owner: owner1, control: a, value: TouchPadAction.sample("A"))
assert(keyboardMenu.connected && keyboardMenu.sample.buttons == 0x1000)
for _ in 0..<3 {
    keyboardMenu.configure([a], acceptingInput: false) // menu / control editor
    assert(keyboardMenu.connected && keyboardMenu.sample == GamepadSample())
    keyboardMenu.update(owner: owner2, control: a, value: TouchPadAction.sample("B"))
    assert(keyboardMenu.sample == GamepadSample()) // delayed touches stay blocked
    keyboardMenu.clear() // lifecycle interruption retains the suspended identity
    assert(keyboardMenu.connected)
    keyboardMenu.configure([a]) // menu closed, keyboard shown then dismissed
    assert(keyboardMenu.connected && keyboardMenu.sample == GamepadSample())
    keyboardMenu.update(owner: owner1, control: a, value: TouchPadAction.sample("LS", x: 1))
    assert(keyboardMenu.sample.lx == 32767) // fresh input reaches the same pad
}
keyboardMenu.configure([], acceptingInput: false) // user actually hides/removes controls
assert(!keyboardMenu.connected && keyboardMenu.sample == GamepadSample())
keyboardMenu.configure([a], acceptingInput: false)
assert(!keyboardMenu.connected) // hidden source cannot resurrect during a menu
keyboardMenu.configure([a], acceptingInput: false)
assert(!keyboardMenu.connected) // repeated launch updates still cannot expose it
session.configure([], acceptingInput: false)
assert(session.connected && session.sample == GamepadSample()) // opt-in reservation survives
session.configure([a], acceptingInput: false)
session.update(owner: owner1, control: a, value: TouchPadAction.sample("A"))
assert(session.connected && session.sample == GamepadSample())
// The app requires process restart for another Wine session. A new state must
// not inherit the old process's reservation or suspended identity.
session = TouchGamepadState()
session.configure([a], acceptingInput: false)
assert(!session.connected && session.sample == GamepadSample())
print("PASS: touch mappings, independent holds, lifecycle clearing, analogue ranges, physical merge and session slot")
'''

# Compile the actual overlay selection and bridge methods, not copies of their
# decision logic. Replace only iOS/UI, config storage, logging and queue/snapshot
# sinks. The FIFO is deterministic: this exercises pending callback order, not
# Dispatch scheduling or UIKit gesture cancellation on a device.
bridge = (root / 'app/Madeira/GamepadInput.swift').read_text()
overlay = (root / 'app/Madeira/ContentView.swift').read_text()


def section(text, start, end):
    assert text.count(start) == 1, start
    tail = text.split(start, 1)[1]
    assert end in tail, end
    return start + tail.split(end, 1)[0]


configuration = section(bridge, '    @MainActor static let enabled: Bool',
                        '    /// Publish player 1 before the game looks')
touch_method = section(bridge, '    @MainActor func touch(owner:',
                       '    /// Keyboard-and-mouse mode')
active_method = section(bridge, '    private func setActive(_ value:',
                        '    private func updateTimer()')
selection = section(overlay, '    private func configureGamepad(landscape:',
                    '    /// ml1970: with MADEIRA_CONTROLS_XBOX_DEFAULT')
disappear_line = '.onDisappear { GamepadInput.shared.configureTouch(controls: []) }'
assert overlay.count(disappear_line) == 1, 'overlay teardown must release mappings'
disappear = disappear_line.split('{ ', 1)[1].rsplit(' }', 1)[0]
assert '.onChange(of: landscape) { _, _ in configureGamepad(landscape: landscape) }' in overlay, \
    'portrait session teardown must reconfigure when session-derived eligibility changes'
for observed in ('m.controls', 'm.visible', 'm.editing', 'library.blocksGameplayTouch'):
    assert f'.onChange(of: {observed})' in overlay, observed

adapters = r'''
enum MadeiraConfig { static func get(_ key: String) -> String? { nil } }
final class LogStore {
    static let shared = LogStore()
    var lines: [String] = []
    func log(_ line: String) { lines.append(line) }
}
final class PadKeyboardMouse {
    static let shared = PadKeyboardMouse()
    func releaseAll(_ reason: String) {}
}
final class PendingQueue {
    private var pending: [() -> Void] = []
    func async(execute: @escaping () -> Void) { pending.append(execute) }
    func drain() {
        while !pending.isEmpty { pending.removeFirst()() }
    }
}
final class GamepadInput: @unchecked Sendable {
    static let shared = GamepadInput()
    let queue = PendingQueue()
    var touchState = TouchGamepadState()
    private var active = true
    private var keyboardMouse: Bool? = nil
    var snapshots: [(connected: Bool, value: GamepadSample)] = []
    func sample() { snapshots.append((touchState.connected, touchState.sample)) }
    private func updateTimer() {}
    func changeActive(_ value: Bool) { setActive(value) }
''' + configuration + touch_method + active_method + r'''
}
struct TestAction { var padName: String? }
struct TestControl { var id: UUID; var action: TestAction }
final class TestControls {
    var visible = true, editing = false
    var controls: [TestControl] = []
}
final class TestLibrary { var blocksGameplayTouch = false }
@MainActor final class OverlayHarness {
    let m = TestControls(), library = TestLibrary()
    func configure(_ landscape: Bool = true) { configureGamepad(landscape: landscape) }
    func disappear() { ''' + disappear + r''' }
''' + selection + r'''
}
'''

bridge_tests = r'''
MainActor.assumeIsolated {
    let pad = GamepadInput.shared, ui = OverlayHarness()
    let button = UUID(), trigger = UUID(), stick = UUID(), other = UUID(), unsupported = UUID()
    let owners = (0..<5).map { _ in UUID() }
    ui.m.controls = [TestControl(id: button, action: TestAction(padName: "A")),
                     TestControl(id: trigger, action: TestAction(padName: "LT")),
                     TestControl(id: stick, action: TestAction(padName: "LS")),
                     TestControl(id: other, action: TestAction(padName: nil)),
                     TestControl(id: unsupported, action: TestAction(padName: "unknown"))]
    func flush() { pad.queue.drain() }
    func neutral(connected: Bool) {
        assert(pad.touchState.connected == connected)
        assert(pad.touchState.sample == GamepadSample())
        assert(pad.snapshots.last?.connected == connected)
        assert(pad.snapshots.last?.value == GamepadSample())
    }
    let disabled = CommandLine.arguments.contains("disabled")
    assert(GamepadInput.touchEnabled != disabled)
    // Initial inhibited startup must remain disconnected on every update.
    ui.library.blocksGameplayTouch = true
    for _ in 0..<3 { ui.configure(); flush(); neutral(connected: false) }
    ui.library.blocksGameplayTouch = false
    ui.configure(); flush(); neutral(connected: !disabled)
    if disabled {
        pad.touch(owner: owners[0], control: button, value: TouchPadAction.sample("A"))
        ui.library.blocksGameplayTouch = true; ui.configure()
        ui.library.blocksGameplayTouch = false; ui.configure()
        flush(); neutral(connected: false)
        print("PASS: production bridge honors disabled touch/global XInput")
    } else {
        func pressAll() {
            pad.touch(owner: owners[0], control: button, value: TouchPadAction.sample("A"))
            pad.touch(owner: owners[1], control: trigger, value: TouchPadAction.sample("LT"))
            pad.touch(owner: owners[2], control: trigger, value: TouchPadAction.sample("RT"))
            pad.touch(owner: owners[3], control: stick, value: TouchPadAction.sample("LS", x: -1))
            pad.touch(owner: owners[4], control: stick, value: TouchPadAction.sample("RS", y: 1))
        }
        for _ in 0..<3 {
            let cycleStart = pad.snapshots.count
            pressAll(); flush()
            assert(pad.touchState.sample == GamepadSample(buttons: 0x1000, lt: 255,
                rt: 255, lx: -32768, ry: 32767))
            assert(pad.snapshots.last?.value == pad.touchState.sample)
            // Queue a pending update before inhibition and late events after it.
            pressAll()
            ui.library.blocksGameplayTouch = true; ui.configure()
            pressAll(); flush(); neutral(connected: true)
            let priorLogs = LogStore.shared.lines.count
            ui.configure(); flush(); neutral(connected: true)
            assert(LogStore.shared.lines.count == priorLogs) // transition-only diagnostics
            // Releasing during inhibition and lifecycle clearing retain identity.
            pad.touch(owner: owners[0], control: button, value: nil)
            pad.changeActive(false); pressAll(); flush(); neutral(connected: true)
            pad.changeActive(true); flush(); neutral(connected: true)
            ui.library.blocksGameplayTouch = false; ui.configure(); flush()
            neutral(connected: true)
            pad.touch(owner: UUID(), control: stick, value: TouchPadAction.sample("LS", x: 0.5))
            flush(); assert(pad.touchState.sample.lx == 16384)
            assert(pad.snapshots.last?.value == pad.touchState.sample)
            assert(pad.snapshots[cycleStart...].allSatisfy { $0.connected })
        }
        // Editor remaps preserve identity and ignore events while inhibited.
        ui.m.editing = true; ui.configure(); flush(); neutral(connected: true)
        ui.m.controls[0].action.padName = "B" // same ID, changed mapping
        ui.configure(); pressAll(); flush(); neutral(connected: true)
        let replacement = UUID()
        ui.m.controls[0].id = replacement
        ui.configure(); flush(); neutral(connected: true)
        ui.m.editing = false; ui.configure(); flush(); neutral(connected: true)
        pad.touch(owner: owners[0], control: button, value: TouchPadAction.sample("A"))
        flush(); neutral(connected: true) // removed mapping rejected
        pad.touch(owner: owners[0], control: other, value: TouchPadAction.sample("A"))
        flush(); neutral(connected: true) // keyboard-only mapping rejected independently
        pad.touch(owner: owners[0], control: unsupported, value: TouchPadAction.sample("A"))
        flush(); neutral(connected: true) // unsupported controller action rejected
        pad.touch(owner: UUID(), control: replacement, value: TouchPadAction.sample("B"))
        flush(); assert(pad.touchState.sample.buttons == 0x2000)
        assert(pad.snapshots.last?.value == pad.touchState.sample)
        // Explicit hide/removal and overlay disappearance still disconnect.
        ui.m.visible = false; ui.configure(); flush(); neutral(connected: false)
        ui.m.visible = true; ui.library.blocksGameplayTouch = true
        ui.configure(); flush(); neutral(connected: false)
        ui.library.blocksGameplayTouch = false; ui.configure(); flush()
        ui.disappear(); flush(); neutral(connected: false)
        ui.configure(); flush(); neutral(connected: true)
        // Portrait session ends: derived landscape changes without size/layout changes.
        ui.configure(false); flush(); neutral(connected: false)
        ui.library.blocksGameplayTouch = true; ui.configure(true)
        flush(); neutral(connected: false)
        ui.library.blocksGameplayTouch = false; ui.configure(true)
        flush(); neutral(connected: true)
        ui.m.controls = []; ui.configure(); flush(); neutral(connected: false)
        print("PASS: production selection/bridge, queued holds, repeated suppression, editing, hide and teardown")
    }
}
'''

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--emit-swift', type=Path, help='write the generated harness without compiling or running it')
args = parser.parse_args()
program = 'import Foundation\n' + pure + adapters + tests + bridge_tests
if args.emit_swift:
    args.emit_swift.write_text(program)
    print(f'WROTE (not compiled or run): {args.emit_swift}')
    raise SystemExit(0)

with tempfile.TemporaryDirectory(prefix='madeira-touch-pad-') as tmp:
    src, exe = Path(tmp) / 'main.swift', Path(tmp) / 'check'
    src.write_text(program)
    subprocess.run([os.environ.get('SWIFTC', 'swiftc'), str(src), '-o', str(exe)], check=True)
    environment = os.environ.copy()
    for flag in ('MADEIRA_XINPUT', 'MADEIRA_TOUCH_XINPUT'):
        environment.pop(flag, None)
    subprocess.run([str(exe)], env=environment, check=True)
    for flag in ('MADEIRA_XINPUT', 'MADEIRA_TOUCH_XINPUT'):
        subprocess.run([str(exe), 'disabled'], env={**environment, flag: '0'}, check=True)
