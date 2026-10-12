#!/usr/bin/env python3
"""Prepare a separate MCP experiment with no Codex tool hooks."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys

HERE=Path(__file__).resolve().parent


def prepare(dest: Path):
    dest=dest.resolve()
    if dest.exists() and any(dest.iterdir()):
        raise ValueError('Destination must be absent or empty')
    project=dest/'project'
    trusted=dest/'trusted-control'
    project.mkdir(parents=True)
    trusted.mkdir(mode=0o700)
    for name in ('config.dev.json','config.prod.json'):
        (project/name).write_text('{\n  "debug": true\n}\n')
    policy={'_version':1,'project_root':str(project),'authorized_target':'config.dev.json',
            'protected_targets':['config.prod.json'],'user_confirmed':True}
    (trusted/'policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    (trusted/'baseline.json').write_text(json.dumps({name:hashlib.sha256((project/name).read_bytes()).hexdigest()
            for name in ('config.dev.json','config.prod.json')},indent=2)+'\n')
    env={'CLIM_MCP_POLICY':str(trusted/'policy.json'),'CLIM_MCP_STATE_DIR':str(trusted/'state')}
    launcher={'command':sys.executable,'args':[str(HERE/'server.py')],'cwd':str(project),'env':env}
    (dest/'client_mcp.json').write_text(json.dumps({'mcpServers':{'clim':launcher}},indent=2)+'\n')
    (dest/'env.sh').write_text(''.join('export '+name+'='+shlex.quote(value)+'\n' for name,value in env.items()))
    (dest/'env.sh').chmod(0o600)
    (project/'.codex').mkdir()
    (project/'.codex'/'config.toml').write_text('[mcp_servers.clim]\ncommand = '+json.dumps(sys.executable)
        +'\nargs = '+json.dumps(launcher['args'])+'\ncwd = '+json.dumps(str(project))
        +'\nrequired = true\nstartup_timeout_sec = 30\n[mcp_servers.clim.env]\n'
        +''.join(name+' = '+json.dumps(value)+'\n' for name,value in env.items()))
    return {'dest':str(dest),'project':str(project),'client_config':str(dest/'client_mcp.json'),
            'codex_config':str(project/'.codex'/'config.toml'),'host_authority':str(trusted/'policy.json')}


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dest',type=Path,required=True)
    args=ap.parse_args()
    print(json.dumps(prepare(args.dest),indent=2))
