#!/usr/bin/env python3
"""Public self-contained unit regression runner, no model/network dependence.
Does NOT imply a hardcoded 140-test count; machine output records actual count.
"""
import argparse
import subprocess
import sys
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',default='test-results/clim-pytest.xml')
    ap.add_argument('--suite',default='.', help='Default: every committed offline suite, including examples and benchmarks')
    args=ap.parse_args()
    target=Path(args.suite)
    if not target.is_dir():
        print(f'ERROR: missing {target}; publish complete test sources first',file=sys.stderr)
        return 2
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    cmd=[sys.executable,'-m','pytest','-q',str(target),'--junitxml',str(out)]
    print('Running:', ' '.join(cmd),flush=True)
    return subprocess.call(cmd)


if __name__=='__main__':raise SystemExit(main())
