"""HC01 local hash links. Consistency checks, NOT authentication or immutability."""
from __future__ import annotations
import copy
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def append(events, kind, data):
    row={'seq':len(events)+1,'prev_hash':events[-1]['event_hash'] if events else '0'*64,
         'kind':kind,'data':copy.deepcopy(data)}
    row['canonical_payload_hash']=digest({'kind':kind,'data':data})
    row['event_hash']=digest(row)
    events.append(row)
    return row


def verify(events):
    try:
        previous='0'*64
        for i,row in enumerate(events,1):
            payload={k:v for k,v in row.items() if k!='event_hash'}
            if (row['seq']!=i or row['prev_hash']!=previous or
                row['canonical_payload_hash']!=digest({'kind':row['kind'],'data':row['data']}) or
                row['event_hash']!=digest(payload)):return False
            previous=row['event_hash']
        return True
    except (KeyError,TypeError,ValueError):return False


def rechain(events):
    """Deliberately demonstrates the limitation of an unanchored local chain."""
    result=[]
    for row in events:append(result,row['kind'],row['data'])
    return result
