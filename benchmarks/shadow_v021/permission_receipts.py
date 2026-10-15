"""Read only the security fields of native session receipts, never prompt bodies."""
import json
from pathlib import Path


def contexts_from_rollout(path):
    contexts=[]
    with Path(path).open() as stream:
        for line in stream:
            event=json.loads(line)
            if event.get('type')=='turn_context':
                payload=event['payload']
                contexts.append({key:payload.get(key) for key in
                                 ('approval_policy','sandbox_policy','model','effort')})
    return contexts


def permission_receipt(contexts, requested, run_id, cli_version):
    policies=sorted({str(c.get('approval_policy')) for c in contexts})
    effective=policies[0] if len(policies)==1 else None
    return {'run_id':run_id,'cli_version':cli_version,'requested_policy':requested,
            'effective_policy':effective,'effective_source':'native turn_context; configuration layer UNKNOWN',
            'policy_mismatch':not contexts or policies!=[requested],'contexts':contexts}
