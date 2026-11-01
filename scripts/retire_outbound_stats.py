#!/usr/bin/env python3
"""Retire only confirmed legacy outbound measurements after an online backup.
Node identities, aliases, quotas, grants and all inbound rows are preserved.
Dry-run by default. Never infer an inbound's traffic from an outbound counter.
"""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

MEASUREMENTS = ('history', 'counters', 'daily_flow', 'monthly_flow', 'monthly', 'billing_usage', 'exit_cache')
PROTECTED = ('users', 'sessions', 'servers', 'grants', 'server_grants', 'host_grants', 'nodes', 'aliases', 'node_metadata', 'control_permissions', 'preferences', 'settings', 'epochs', 'audit')

def fingerprint(db, table, inbound_only=False):
    where=" WHERE substr(tag,1,8)='inbound:'" if inbound_only else ''
    rows=db.execute(f'SELECT * FROM {table}'+where).fetchall()
    return hashlib.sha256(repr(sorted(rows, key=repr)).encode()).hexdigest()

def retire(database, backup=None, apply=False):
    db=sqlite3.connect(database, timeout=15)
    db.execute('PRAGMA foreign_keys=ON')
    # A server is eligible only if it reports a nonempty, wholly inbound inventory.
    eligible=[]
    for sid,raw in db.execute('SELECT id,report FROM servers WHERE report IS NOT NULL'):
        tags=json.loads(raw).get('tags',[])
        if tags and all(t.get('identity')=='inbound' and t.get('name')=='inbound:'+t.get('inbound_tag','') for t in tags):
            eligible.append(sid)
    candidates=[]
    for sid in eligible:
        candidates.extend(db.execute("SELECT server,tag FROM nodes WHERE server=? AND substr(tag,1,8)!='inbound:'",(sid,)).fetchall())
    counts={table:sum(db.execute(f'SELECT count(*) FROM {table} WHERE server=? AND tag=?',key).fetchone()[0] for key in candidates) for table in MEASUREMENTS}
    result={'apply':apply,'legacy_identities':len(candidates),'removed_rows':counts,'backup':str(backup) if apply else None}
    if not apply:
        db.close();return result
    if not backup:
        raise ValueError('An explicit new backup path is required')
    backup=Path(backup)
    if backup.exists():
        raise FileExistsError('Refusing to overwrite a backup')
    backup.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Exclusive creation prevents overwriting an existing file through a race.
    fd=__import__('os').open(backup,__import__('os').O_CREAT|__import__('os').O_EXCL|__import__('os').O_WRONLY,0o600)
    __import__('os').close(fd)
    dst=sqlite3.connect(backup)
    db.backup(dst)
    assert dst.execute('PRAGMA quick_check').fetchone()[0]=='ok'
    dst.close()
    try:
        db.execute('BEGIN IMMEDIATE')
        before={t:fingerprint(db,t) for t in PROTECTED}
        inbound={t:fingerprint(db,t,True) for t in MEASUREMENTS}
        for table in MEASUREMENTS:
            for sid,tag in candidates:
                # Revalidate that no exporter has reverted to an outbound report.
                raw=db.execute('SELECT report FROM servers WHERE id=?',(sid,)).fetchone()[0]
                tags=json.loads(raw).get('tags',[])
                if not tags or any(t.get('identity')!='inbound' for t in tags):
                    raise RuntimeError('Inventory changed; cleanup cancelled')
                db.execute(f'DELETE FROM {table} WHERE server=? AND tag=?',(sid,tag))
        assert before=={t:fingerprint(db,t) for t in PROTECTED},'Protected data changed'
        assert inbound=={t:fingerprint(db,t,True) for t in MEASUREMENTS},'Inbound data changed'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        db.commit()
        result['protected_tables_unchanged']=True
        result['inbound_measurements_unchanged']=True
    except BaseException:
        db.rollback();raise
    finally:
        db.close()
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database',required=True)
    p.add_argument('--backup')
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    print(json.dumps(retire(a.database,a.backup,a.apply),ensure_ascii=False,indent=2))
