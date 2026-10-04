#!/usr/bin/env python3
"""Check GCMouse wheel axes without an iOS SDK or the Wine submodule.

The source checks pin the ingress conversion and leave the UIKit fallback in
view-point coordinates. The behavioral checks compile the exact production
GCMouse callback and pure WheelAccumulator with a small GameController stub,
then verify the Windows events. This does not exercise Apple's event delivery.

Needs python3 and swiftc (SWIFTC to override). --source-only explicitly skips
the compiled behavioral checks, for hosts without a Swift toolchain.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-only', action='store_true', help='skip compiled Swift behavioral checks')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/HardwareInput.swift').read_text()

callback_match = re.search(
    r'm\.scroll\.valueChangedHandler = \{ \[weak self\] _, x, y in\n.*?\n        \}',
    source, re.S)
assert callback_match, 'GCMouse scroll callback not found'
callback = callback_match.group()
callback_code = re.sub(r'//[^\n]*', '', callback)
compact_callback = re.sub(r'\s+', '', callback_code)
assert 'self?.scrolled(Double(y),-Double(x))' in compact_callback, (
    'GCMouse must map first axis to negative vertical and second axis to horizontal')

uikit_match = re.search(r'func uikitScroll\([^\n]+\) \{\n.*?\n    \}', source, re.S)
assert uikit_match, 'UIKit scroll fallback not found'
assert 'scrolled(Double(dxPoints) / 14.0, Double(dyPoints) / 14.0)' in uikit_match.group(), (
    'UIKit scroll uses view-point x/y, not the GCMouse axis convention')
assert 'guard Self.enabled, !gcLive else { return }' in uikit_match.group(), (
    'UIKit must stand aside while the GCMouse stream is live')

print('PASS: GCMouse ingress axes/sign and unchanged UIKit fallback routing', flush=True)
if args.source_only:
    print('SKIP: compiled Swift wheel behavior (--source-only)')
    raise SystemExit(0)

compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
if not compiler:
    raise SystemExit('FAIL: swiftc not found; set SWIFTC or use --source-only for source checks only')

pure = source.split('// MARK: - Pure input mapping', 1)[1].split('// MARK: - Device glue', 1)[0]
harness = r'''
final class ScrollStub {
    var valueChangedHandler: ((ScrollStub, Float, Float) -> Void)?
}

final class MouseStub {
    let scroll = ScrollStub()
}

final class InputStub {
    var wheel = WheelAccumulator()
    var events: [(flags: UInt32, delta: Int32)] = []

    func scrolled(_ x: Double, _ y: Double) {
        events += wheel.add(x, y)
    }

    func attach(_ m: MouseStub) {
        CALLBACK
    }
}

func expect(_ samples: [(Float, Float)], _ expected: [(UInt32, Int32)]) {
    let input = InputStub()
    let mouse = MouseStub()
    input.attach(mouse)
    for (first, second) in samples {
        mouse.scroll.valueChangedHandler!(mouse.scroll, first, second)
    }
    assert(input.events.count == expected.count,
           "wrong number of wheel notches for \(samples): \(input.events)")
    for (event, want) in zip(input.events, expected) {
        assert(event.flags == want.0 && event.delta == want.1,
               "wrong wheel axis/sign for \(samples): \(input.events)")
    }
}

// Raw GameController vertical: first value, negative for up. Windows WHEEL:
// +120 for up, -120 for down. Never emit HWHEEL for vertical-only input.
expect([(-1, 0)], [(0x0800, 120)])
expect([(1, 0)], [(0x0800, -120)])
expect([(-2, 0)], [(0x0800, 120), (0x0800, 120)])

// Horizontal: second value, positive to the right, preserved for HWHEEL.
expect([(0, 1)], [(0x1000, 120)])
expect([(0, -1)], [(0x1000, -120)])
expect([(-1, -1)], [(0x0800, 120), (0x1000, -120)])
expect([(1, 1)], [(0x0800, -120), (0x1000, 120)])

// Precision-wheel fractions accumulate independently on each normalized axis.
expect([(-0.25, 0), (-0.25, 0), (-0.25, 0)], [])
expect([(-0.25, 0), (-0.25, 0), (-0.25, 0), (-0.25, 0)], [(0x0800, 120)])
expect([(0.5, -0.5), (0.5, -0.5)], [(0x0800, -120), (0x1000, -120)])
expect([(-0.5, 0.5), (0.5, -0.5)], [])

// Empty and malformed input cannot inject an event or poison the next sample.
expect([(0, 0)], [])
expect([(.nan, 0), (0, .infinity), (-1, 0)], [(0x0800, 120)])
expect([(-1000, 0), (0, 0)], Array(repeating: (0x0800, 120), count: WheelAccumulator.maxNotchesPerEvent))

// UIKit already reports x/y view points, so its vertical path stays vertical.
var uikitWheel = WheelAccumulator()
let fallback = uikitWheel.add(0 / 14.0, 14 / 14.0)
assert(fallback.count == 1 && fallback[0].flags == 0x0800 && fallback[0].delta == 120)
print("PASS: compiled production GCMouse callback and wheel accumulator behavior")
'''.replace('CALLBACK', callback)

with tempfile.TemporaryDirectory(prefix='madeira-mouse-wheel-') as tmp:
    main, executable = Path(tmp) / 'main.swift', Path(tmp) / 'check'
    main.write_text('import Foundation\n' + pure + '\n' + harness)
    subprocess.run([compiler, str(main), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
