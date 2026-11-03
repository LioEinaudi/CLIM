#!/usr/bin/env python3
"""Freeze fixture Hook dependencies for human review, without trusting a Hook."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

if __package__:
    from .attempt_capture import _create_private, _outside, _verify_fixture
else:
    from attempt_capture import _create_private, _outside, _verify_fixture


def collect(project: Path, operator: Path, runtime: Path) -> dict:
    project = project.resolve(strict=True)
    operator = _outside(operator, project)
    runtime = _outside(runtime, project)
    _verify_fixture(project)
    setup_path = operator/'capture-setup.json'
    hook = project/'.codex/hooks.json'
    here = Path(__file__).resolve().parent
    adapter, pilot = here/'attempt_capture.py', here/'pilot.py'
    if any(p.is_symlink() or not p.is_file() for p in (setup_path, hook, adapter, pilot)):
        raise ValueError('Expected regular Hook and pilot files')
    setup = json.loads(setup_path.read_text())
    hook_hash = hashlib.sha256(hook.read_bytes()).hexdigest()
    adapter_hash = hashlib.sha256(adapter.read_bytes()).hexdigest()
    if (setup.get('schema') != 'clim-fixture-capture-setup-v1' or setup.get('hook_sha256') != hook_hash
            or setup.get('adapter_sha256') != adapter_hash
            or setup.get('project_root_sha256') != hashlib.sha256(os.fsencode(str(project))).hexdigest()):
        raise ValueError('Capture setup, Hook or adapter changed; configure a fresh fixture')
    package_dirs = list((runtime/'lib').glob('python*/site-packages/clim_agent_guard'))
    if len(package_dirs) != 1 or package_dirs[0].is_symlink():
        raise ValueError('Expected one regular installed CLIM package')
    package = package_dirs[0]
    files = sorted(p for p in package.rglob('*') if p.is_file() and p.suffix in ('.py', '.patch'))
    if not files or not (package/'contract_runtime/codex_observer.py').is_file() or any(p.is_symlink() for p in files):
        raise ValueError('Installed CLIM package is incomplete or contains symlinks')
    per_file = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    runtime_hash = hashlib.sha256(json.dumps(per_file, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema':'clim-fixture-review-manifest-v1', 'project_root_sha256':setup['project_root_sha256'],
            'hook_sha256':hook_hash, 'adapter_sha256':adapter_hash,
            'pilot_sha256':hashlib.sha256(pilot.read_bytes()).hexdigest(),
            'clim_runtime_manifest_sha256':runtime_hash, 'clim_runtime_files':len(files),
            'note':'Hashes detect changes; they do not prove human review or Host enforcement.'}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',required=True);parser.add_argument('--operator',required=True);parser.add_argument('--runtime',required=True)
    args=parser.parse_args()
    try:
        project=Path(args.project).expanduser().resolve(strict=True);operator=_outside(Path(args.operator),project)
        result=collect(project,operator,Path(args.runtime).expanduser())
        _create_private(operator/'review-manifest.json',(json.dumps(result,indent=2)+'\n').encode())
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,TypeError) as exc:
        print('ERROR:',exc,file=sys.stderr);return 2


if __name__=='__main__':
    raise SystemExit(main())
