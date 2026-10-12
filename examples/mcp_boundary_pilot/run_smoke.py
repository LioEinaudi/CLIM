#!/usr/bin/env python3
"""Real official SDK client/server stdio test; no LLM calls."""
import argparse
import hashlib
import json
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters


async def run(dest):
    config=json.loads((dest/'client_mcp.json').read_text())['mcpServers']['clim']
    records=[]
    async with Client(StdioServerParameters(**config)) as client:
        tools=await client.list_tools()
        records.append({'phase':'CONNECTED','protocol_version':client.protocol_version,
                        'server_info':client.server_info.model_dump(),
                        'tools':[t.name for t in tools.tools]})
        assert [t.name for t in tools.tools]==['clim_set_debug']
        for case,args in [
            ('prod_deny',{'path':'config.prod.json','debug':False,'operation_id':'smoke-prod'}),
            ('dev_allow',{'path':'config.dev.json','debug':False,'operation_id':'smoke-dev'}),
            ('duplicate_deny',{'path':'config.dev.json','debug':False,'operation_id':'smoke-dev'})]:
            result=await client.call_tool('clim_set_debug',args)
            record={'case':case,'tool_name':'clim_set_debug','arguments':args,
                    'result':result.model_dump(mode='json',by_alias=True,exclude_none=True)}
            records.append(record)
            if case=='dev_allow':
                assert not result.is_error and result.structured_content['code']=='EFFECT_VERIFIED'
            else:
                assert result.is_error
                code='TARGET_NOT_AUTHORIZED' if case=='prod_deny' else 'DUPLICATE_SIDE_EFFECT'
                assert code in '\n'.join(b.text for b in result.content if b.type=='text')
    project=dest/'project'
    before=json.loads((dest/'trusted-control/baseline.json').read_text())
    after={name:hashlib.sha256((project/name).read_bytes()).hexdigest() for name in before}
    assert before['config.prod.json']==after['config.prod.json']
    assert before['config.dev.json']!=after['config.dev.json']
    assert json.loads((project/'config.dev.json').read_text())['debug'] is False
    result={'kind':'REAL_MCP_STDIO_SDK_CLIENT_NO_LLM','accepted':True,'records':records,
            'before_hashes':before,'after_hashes':after}
    (dest/'sdk_smoke.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dest',type=Path,required=True)
    args=ap.parse_args()
    anyio.run(run,args.dest.resolve())
