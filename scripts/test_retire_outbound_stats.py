import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from retire_outbound_stats import retire, MEASUREMENTS, PROTECTED, fingerprint

class Retirement(unittest.TestCase):
    def test_scoped_backup_idempotence_preserves_inbound_and_accounts(self):
        # Use the project's real schema instead of a simplified lookalike.
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'test.db'
            db=sqlite3.connect(path)
            source=(Path(__file__).resolve().parent.parent/'internal/store/store.go').read_text()
            schema=source.split('db.Exec(`',1)[1].split('`)',1)[0]
            db.executescript(schema)
            db.execute("INSERT INTO users VALUES(1,'viewer','user',0,'synthetic')")
            report=json.dumps({'tags':[{'name':'inbound:a','inbound_tag':'a','identity':'inbound'}]})
            db.execute("INSERT INTO servers(id,name,token,report) VALUES('s','test','synthetic',?)",(report,))
            db.execute("INSERT INTO nodes VALUES('old','s','direct','保留名称',123),('new','s','inbound:a','入站',456)")
            db.execute("INSERT INTO aliases VALUES(1,'old','保留别名')")
            db.execute("INSERT INTO grants VALUES(1,'s','direct')")
            for tag in ('direct','inbound:a'):
                db.execute("INSERT INTO history VALUES('s',?,1,0,0,7,9)",(tag,))
                db.execute("INSERT INTO counters VALUES('s',?,'e',7,9,7,9,1)",(tag,))
                db.execute("INSERT INTO daily_flow VALUES('s',?,'d',7,9)",(tag,))
                db.execute("INSERT INTO monthly_flow VALUES('s',?,'m',7,9)",(tag,))
                db.execute("INSERT INTO monthly VALUES('s',?,'m',16)",(tag,))
                db.execute("INSERT INTO billing_usage VALUES('s',?,1,16)",(tag,))
                db.execute("INSERT INTO exit_cache VALUES('s',?,'{}')",(tag,))
            db.commit()
            before={t:fingerprint(db,t) for t in PROTECTED}
            self.assertEqual(retire(path)['removed_rows']['history'],1)
            out=retire(path,Path(td)/'backup.db',True)
            self.assertTrue(out['protected_tables_unchanged'])
            self.assertEqual(before,{t:fingerprint(db,t) for t in PROTECTED})
            for table in MEASUREMENTS:
                self.assertEqual(db.execute(f'SELECT tag FROM {table}').fetchall(),[('inbound:a',)])
            backup=sqlite3.connect(Path(td)/'backup.db')
            self.assertEqual(backup.execute('SELECT count(*) FROM history').fetchone()[0],2)
            backup.close()
            self.assertTrue(all(v==0 for v in retire(path,Path(td)/'second.db',True)['removed_rows'].values()))
            db.close()

if __name__=='__main__':unittest.main()
