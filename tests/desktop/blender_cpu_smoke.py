"""Run inside Blender in background mode; never opens user projects.

Example:
  blender --background --factory-startup --disable-autoexec --python-exit-code 1 \
    --python tests/desktop/blender_cpu_smoke.py -- --output-dir /tmp/madeira-probes

Start with --stage python on a new target; --stage render adds a tiny CPU-only
Cycles render. A native-host pass validates this probe, NOT Madeira/iOS support.
Each invocation creates a new output folder and checkpoints report.json so an
interrupted guest still leaves its last completed stage visible.
"""
import argparse
import json
import math
from pathlib import Path
import platform
import struct
import sys
import tempfile
import time

import bpy
from mathutils import Vector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--stage', choices=['python', 'render'], default='python')
    args = parser.parse_args(sys.argv[sys.argv.index('--') + 1:] if '--' in sys.argv else [])
    if not bpy.app.background:
        raise RuntimeError('This destructive test scene is allowed only in --background mode')

    base = Path(args.output_dir)
    base.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='blender-cpu-', dir=str(base)))
    started = time.monotonic()
    report = {
        'schema': 1, 'status': 'running', 'stage_requested': args.stage,
        'blender_version': bpy.app.version_string,
        'platform': sys.platform, 'machine': platform.machine(),
        'background': bool(bpy.app.background), 'checks': [],
        'scope': 'headless Python/file I/O and optional CPU render; not GUI or GPU acceptance',
    }

    def checkpoint(check=None):
        if check:
            report['checks'].append(check)
            print('[madeira-blender-probe] PASS ' + check, flush=True)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

    try:
        checkpoint('python-import')
        bpy.ops.wm.read_factory_settings(use_empty=True)
        bpy.ops.mesh.primitive_cube_add()
        cube = bpy.context.object
        cube.name = 'Куб Madeira'
        cube['madeira_probe'] = 'База / scene round trip'
        scene = bpy.context.scene
        scene['madeira_probe'] = True
        checkpoint('scene-created')

        # Spaces and non-ASCII paths expose argument/path/encoding regressions.
        project = output / 'Мой проект.blend'
        bpy.ops.wm.save_as_mainfile(filepath=str(project), check_existing=False)
        if not project.is_file() or project.stat().st_size == 0:
            raise RuntimeError('Blender did not save the disposable test project')
        bpy.ops.wm.open_mainfile(filepath=str(project), load_ui=False, use_scripts=False)
        cube = bpy.data.objects.get('Куб Madeira')
        if cube is None or cube.get('madeira_probe') != 'База / scene round trip':
            raise RuntimeError('Saved scene did not round-trip its Unicode data')
        checkpoint('unicode-save-reopen')

        if args.stage == 'render':
            scene = bpy.context.scene
            scene.render.engine = 'CYCLES'
            scene.cycles.device = 'CPU'
            scene.cycles.samples = 1
            scene.cycles.use_denoising = False
            scene.render.threads_mode = 'FIXED'
            scene.render.threads = 1
            scene.render.resolution_x = scene.render.resolution_y = 32
            scene.render.resolution_percentage = 100
            scene.render.use_compositing = False
            scene.render.use_sequencer = False

            bpy.ops.object.camera_add(location=(4, -6, 4))
            camera = bpy.context.object
            camera.rotation_euler = (-Vector(camera.location)).to_track_quat('-Z', 'Y').to_euler()
            scene.camera = camera
            bpy.ops.object.light_add(type='AREA', location=(2, -3, 4))
            bpy.context.object.data.energy = 500
            bpy.context.object.data.size = 4
            world = bpy.data.worlds.new('Madeira probe world')
            world.use_nodes = True
            world.node_tree.nodes['Background'].inputs['Color'].default_value = (0.2, 0.3, 0.4, 1)
            world.node_tree.nodes['Background'].inputs['Strength'].default_value = 0.8
            scene.world = world
            image_path = output / 'cpu-render.png'
            scene.render.image_settings.file_format = 'PNG'
            scene.render.filepath = str(image_path)
            checkpoint('cycles-cpu-configured')
            bpy.ops.render.render(write_still=True)
            header = image_path.read_bytes()[:24]
            if header[:8] != b'\x89PNG\r\n\x1a\n' or struct.unpack('>II', header[16:24]) != (32, 32):
                raise RuntimeError('CPU render did not produce a 32x32 PNG')
            image = bpy.data.images.load(str(image_path), check_existing=False)
            pixels = list(image.pixels)
            rgb = [value for i, value in enumerate(pixels) if i % 4 != 3]
            if not rgb or not all(math.isfinite(v) for v in rgb) or max(rgb) <= 0:
                raise RuntimeError('CPU render pixels are missing, non-finite or all black')
            checkpoint('cycles-cpu-render-32x32')

        report['status'] = 'passed'
        checkpoint()
        print('[madeira-blender-probe] RESULT ' + str(output / 'report.json'), flush=True)
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        checkpoint()
        print('[madeira-blender-probe] FAILED; report: ' + str(output / 'report.json'), flush=True)
        raise


if __name__ == '__main__':
    main()
