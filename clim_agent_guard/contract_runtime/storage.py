"""Transactional SQLite event ledger with logical append-only history.

SQLite's physical WAL is *not* the audit history. The 'events' and
'contract_versions' tables are logical histories; same-UID tampering remains
possible. The connection is one transaction per mutation and has bounded reads.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Protocol, Iterator, Any
from .scope import ContractError, require

SCHEMA_VERSION=1
ZERO='0'*64

def canonical(value: Any) -> str:
    try:
        result=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
        result.encode('utf-8')
        return result
    except (TypeError,ValueError,UnicodeError,RecursionError) as error:
        raise ContractError('INVALID_JSON_VALUE') from error

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

class EvidenceSink(Protocol):
    def transaction(self) -> Iterator[sqlite3.Connection]: ...
    def append(self, conn: sqlite3.Connection, kind: str, data: dict, *, session_id: str|None=None,
               actor_id: str|None=None, window_id: str|None=None, trace_id: str|None=None,
               span_id: str|None=None, parent_span_id: str|None=None) -> dict: ...
    def verify(self) -> dict: ...

class SQLiteEvidenceSink:
    """Local-only SQL storage. A transaction serializes seq assignment and state updates."""
    def __init__(self, path: Path):
        self.path=Path(path)
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        # Do not follow a symlink masquerading as the database.
        require(not self.path.is_symlink(), 'UNSAFE_DATABASE_PATH')
        self._init()

    def _connect(self) -> sqlite3.Connection:
        c=sqlite3.connect(str(self.path),timeout=10, isolation_level=None)
        try:
            c.row_factory=sqlite3.Row
            c.execute('PRAGMA busy_timeout=10000')
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=FULL')
            c.execute('PRAGMA foreign_keys=ON')
        except BaseException:
            c.close()
            raise
        return c

    def _init(self):
        with self.transaction() as c:
            c.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            c.execute('''CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY, event_hash TEXT NOT NULL, previous_hash TEXT NOT NULL,
                record_json TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS contract_versions (
                contract_id TEXT NOT NULL, revision INTEGER NOT NULL, status TEXT NOT NULL,
                payload_json TEXT NOT NULL, event_seq INTEGER NOT NULL,
                PRIMARY KEY(contract_id,revision), FOREIGN KEY(event_seq) REFERENCES events(seq))''')
            c.execute('''CREATE TABLE IF NOT EXISTS windows (
                window_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool_use_id TEXT NOT NULL,
                status TEXT NOT NULL, opened_seq INTEGER NOT NULL, closed_seq INTEGER,
                coverage TEXT NOT NULL, target_json TEXT NOT NULL,
                UNIQUE(session_id,tool_use_id))''')
            # Application-level append-only tables; same-UID SQLite administration
            # can still drop triggers and rewrite records, so this is NOT tamperproof.
            c.execute('''CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                         BEGIN SELECT RAISE(ABORT,'EVENT_HISTORY_APPEND_ONLY'); END''')
            c.execute('''CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                         BEGIN SELECT RAISE(ABORT,'EVENT_HISTORY_APPEND_ONLY'); END''')
            c.execute('''CREATE TRIGGER IF NOT EXISTS versions_no_update BEFORE UPDATE ON contract_versions
                         BEGIN SELECT RAISE(ABORT,'CONTRACT_HISTORY_APPEND_ONLY'); END''')
            c.execute('''CREATE TRIGGER IF NOT EXISTS versions_no_delete BEFORE DELETE ON contract_versions
                         BEGIN SELECT RAISE(ABORT,'CONTRACT_HISTORY_APPEND_ONLY'); END''')
            c.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1')")
            require(c.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0]=='1','INCOMPATIBLE_LEDGER_SCHEMA')
        try:os.chmod(self.path,0o600)
        except OSError:pass

    @contextmanager
    def transaction(self):
        c=self._connect()
        try:
            c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:c.close()

    @contextmanager
    def read(self):
        c=self._connect()
        try:
            # All verification/status queries must observe one WAL snapshot.
            c.execute('BEGIN')
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:c.close()

    def get(self,c:sqlite3.Connection,key:str,default=None):
        row=c.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()
        return json.loads(row[0]) if row and key != 'schema_version' else default

    def set(self,c:sqlite3.Connection,key:str,value):
        c.execute('INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key,canonical(value)))

    def append(self,c:sqlite3.Connection,kind:str,data:dict,*,session_id=None,actor_id=None,
               window_id=None,trace_id=None,span_id=None,parent_span_id=None):
        last=c.execute('SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        seq=(last['seq']+1) if last else 1
        prev=last['event_hash'] if last else ZERO
        record={'schema_version':SCHEMA_VERSION,'event_seq':seq,'event_id':f'evt-{seq:012d}',
            'event_time_utc':datetime.now(timezone.utc).isoformat(), 'causal_epoch':seq,
            'kind':kind,'data':data,'session_id':session_id,'actor_id':actor_id,
            'window_id':window_id,'trace_id':trace_id,'span_id':span_id,
            'parent_span_id':parent_span_id,'lease_id':None}
        fingerprint=hashlib.sha256((prev+'\n'+canonical(record)).encode()).hexdigest()
        c.execute('INSERT INTO events(seq,event_hash,previous_hash,record_json) VALUES(?,?,?,?)',
            (seq,fingerprint,prev,canonical(record)))
        return {**record,'previous_hash':prev,'event_hash':fingerprint}

    def version(self,c:sqlite3.Connection,contract_id:str,status:str,payload:dict,event_seq:int):
        last=c.execute('SELECT MAX(revision) FROM contract_versions WHERE contract_id=?',(contract_id,)).fetchone()[0]
        rev=1 if last is None else last+1
        c.execute('INSERT INTO contract_versions VALUES(?,?,?,?,?)',
                  (contract_id,rev,status,canonical(payload),event_seq))
        return rev

    def latest(self,c:sqlite3.Connection,contract_id:str):
        row=c.execute('SELECT * FROM contract_versions WHERE contract_id=? ORDER BY revision DESC LIMIT 1',(contract_id,)).fetchone()
        if row is None:raise ContractError('CONTRACT_NOT_FOUND')
        return {'contract_id':contract_id,'revision':row['revision'],'status':row['status'],
                'payload':json.loads(row['payload_json']),'event_seq':row['event_seq']}

    def verify(self) -> dict:
        with self.read() as c:
            prev=ZERO;expect=1;count=0;windows={};versions={};revisions={}
            for row in c.execute('SELECT * FROM events ORDER BY seq'):
                if row['seq']!=expect or row['previous_hash']!=prev:
                    raise ContractError('AUDIT_CHAIN_INCONSISTENT')
                try:record=json.loads(row['record_json'])
                except (json.JSONDecodeError,TypeError) as e:raise ContractError('AUDIT_CHAIN_INCONSISTENT') from e
                require(isinstance(record,dict),'AUDIT_CHAIN_INCONSISTENT')
                actual=hashlib.sha256((prev+'\n'+canonical(record)).encode()).hexdigest()
                if record.get('event_seq')!=expect or actual!=row['event_hash']:
                    raise ContractError('AUDIT_CHAIN_INCONSISTENT')
                prev=actual;expect+=1;count+=1
                kind=record.get('kind')
                if kind in ('TASK_REGISTERED','CONTRACT_ACCEPTED','CONTRACT_ACTIVATED','STAGE_COMPLETED'):
                    data=record.get('data')
                    require(isinstance(data,dict),'CONTRACT_HISTORY_INCONSISTENT')
                    cid='ROOT' if kind=='TASK_REGISTERED' else data.get('contract_id')
                    require(isinstance(cid,str),'CONTRACT_HISTORY_INCONSISTENT')
                    revision=revisions.get(cid,0)+1;revisions[cid]=revision
                    status={'TASK_REGISTERED':'ACTIVE','CONTRACT_ACCEPTED':'ACCEPTED',
                            'CONTRACT_ACTIVATED':'ACTIVE','STAGE_COMPLETED':'CLOSED'}[kind]
                    payload_digest=data.get('payload_digest') or data.get('candidate_digest') or data.get('root_contract_sha256')
                    require(isinstance(payload_digest,str),'CONTRACT_HISTORY_INCONSISTENT')
                    versions[(cid,revision)]=(status,row['seq'],payload_digest)
                if kind in ('WINDOW_PRE_OBSERVED','WINDOW_POST_OBSERVED','RECOVERY_EFFECT_UNKNOWN'):
                    wid=record.get('window_id');data=record.get('data')
                    require(isinstance(wid,str) and isinstance(data,dict),'WINDOW_INDEX_INCONSISTENT')
                    if kind=='WINDOW_PRE_OBSERVED':
                        require(wid not in windows and isinstance(data.get('targets'),list),
                                'WINDOW_INDEX_INCONSISTENT')
                        require(isinstance(data.get('tool_use_id'),str),
                                'LEGACY_WINDOW_IDENTITY_UNVERIFIED')
                        windows[wid]={'window_id':wid,'session_id':record['session_id'],
                            'tool_use_id':data['tool_use_id'],'status':'PENDING',
                            'opened_seq':row['seq'],'closed_seq':None,
                            'coverage':'UNKNOWN_PENDING','targets':data['targets']}
                    else:
                        require(wid in windows and windows[wid]['status']=='PENDING' and
                                windows[wid]['session_id']==record['session_id'],
                                'WINDOW_INDEX_INCONSISTENT')
                        windows[wid].update(status='CLOSED' if kind=='WINDOW_POST_OBSERVED' else 'RECOVERED_UNKNOWN',
                            closed_seq=row['seq'],coverage=data.get('coverage') if kind=='WINDOW_POST_OBSERVED' else 'EFFECT_UNKNOWN')
            actual_windows={}
            for row in c.execute('SELECT * FROM windows'):
                item=dict(row)
                try:item['targets']=json.loads(item.pop('target_json'))
                except (ValueError,TypeError) as error:raise ContractError('WINDOW_INDEX_INCONSISTENT') from error
                actual_windows[item['window_id']]=item
            require(actual_windows==windows,'WINDOW_INDEX_INCONSISTENT')
            # Check the entire derived index, including missing/extra rows and
            # identity/lifecycle fields, against the immutable event receipts.
            rows=c.execute('SELECT * FROM contract_versions').fetchall()
            require(len(rows)==len(versions),'CONTRACT_HISTORY_INCONSISTENT')
            for row in rows:
                try:
                    payload=json.loads(row['payload_json'])
                    require(versions.get((row['contract_id'],row['revision']))==
                            (row['status'],row['event_seq'],digest(payload)),
                            'CONTRACT_HISTORY_INCONSISTENT')
                except (ValueError,TypeError,KeyError) as e:
                    raise ContractError('CONTRACT_HISTORY_INCONSISTENT') from e
            checkpoint=None
            for item in c.execute('SELECT record_json FROM events ORDER BY seq DESC'):
                candidate=json.loads(item[0])
                if candidate.get('kind')=='STATE_CHECKPOINT':
                    checkpoint=candidate
                    break
            if checkpoint is not None:
                state_row=c.execute("SELECT value FROM metadata WHERE key='current_state'").fetchone()
                if state_row is None or digest(json.loads(state_row[0]))!=checkpoint['data']['state_digest']:
                    raise ContractError('MATERIALIZED_STATE_INCONSISTENT')
            integrity=c.execute('PRAGMA integrity_check').fetchone()[0]
            require(integrity=='ok','SQLITE_INTEGRITY_FAILED')
        return {'event_count':count,'last_hash':prev,'integrity':'LOCAL_CONSISTENCY_ONLY',
                'tamper_proof':False,'origin_authenticated':False}
