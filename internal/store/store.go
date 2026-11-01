package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

type Store struct{ *sql.DB }
type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
	Hash     string `json:"-"`
}
type Server struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}
type Grant struct {
	Server string `json:"server"`
	Tag    string `json:"tag"`
}

func Open(path string) (*Store, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db}
	_, e = db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK(role IN ('admin','user')),disabled INTEGER NOT NULL DEFAULT 0,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,name TEXT NOT NULL,token TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,epoch TEXT NOT NULL DEFAULT '',seq INTEGER NOT NULL DEFAULT 0,seen INTEGER NOT NULL DEFAULT 0,report BLOB);
CREATE TABLE IF NOT EXISTS grants(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,server TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,tag TEXT NOT NULL,PRIMARY KEY(user_id,server,tag));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,name TEXT NOT NULL,ip TEXT NOT NULL,event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history(server TEXT NOT NULL,tag TEXT NOT NULL,minute INTEGER NOT NULL,up REAL NOT NULL,down REAL NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,PRIMARY KEY(server,tag,minute));
CREATE TABLE IF NOT EXISTS epochs(server TEXT NOT NULL,epoch TEXT NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(server,epoch));
CREATE TABLE IF NOT EXISTS counters(server TEXT NOT NULL,tag TEXT NOT NULL,epoch TEXT NOT NULL,rawup INTEGER NOT NULL,rawdown INTEGER NOT NULL,totalup INTEGER NOT NULL,totaldown INTEGER NOT NULL,at INTEGER NOT NULL,PRIMARY KEY(server,tag));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
INSERT OR IGNORE INTO settings VALUES('sample_seconds',2),('retention_days',30),('show_raw_tag',0),('show_expiry',0),('show_quota',1);
CREATE TABLE IF NOT EXISTS control_permissions(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,action TEXT NOT NULL CHECK(action IN ('change','restore','copy','import_shadowrocket','import_v2rayn','view')),PRIMARY KEY(user_id,action));
CREATE TABLE IF NOT EXISTS preferences(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO preferences VALUES('default_node_name','节点');
CREATE TABLE IF NOT EXISTS identity_migrations(server TEXT NOT NULL,legacy TEXT NOT NULL,current TEXT NOT NULL,PRIMARY KEY(server,legacy),UNIQUE(server,current));
CREATE TABLE IF NOT EXISTS nodes(id TEXT NOT NULL UNIQUE,server TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,tag TEXT NOT NULL,name TEXT NOT NULL DEFAULT '',quota INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(server,tag));
CREATE TABLE IF NOT EXISTS node_metadata(node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL DEFAULT 0,billing_day INTEGER NOT NULL DEFAULT 1,timezone TEXT NOT NULL DEFAULT 'UTC',alert_threshold INTEGER NOT NULL DEFAULT 80);
CREATE TABLE IF NOT EXISTS billing_usage(server TEXT NOT NULL,tag TEXT NOT NULL,start INTEGER NOT NULL,used INTEGER NOT NULL,PRIMARY KEY(server,tag,start));
CREATE TABLE IF NOT EXISTS server_grants(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,server TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,PRIMARY KEY(user_id,server));
CREATE TABLE IF NOT EXISTS host_grants(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,server TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,PRIMARY KEY(user_id,server));
CREATE TABLE IF NOT EXISTS aliases(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,name TEXT NOT NULL,PRIMARY KEY(user_id,node_id));
CREATE TABLE IF NOT EXISTS exit_cache(server TEXT NOT NULL,tag TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(server,tag));
CREATE TABLE IF NOT EXISTS daily_flow(server TEXT NOT NULL,tag TEXT NOT NULL,day TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,PRIMARY KEY(server,tag,day));
CREATE TABLE IF NOT EXISTS monthly_flow(server TEXT NOT NULL,tag TEXT NOT NULL,month TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,PRIMARY KEY(server,tag,month));
CREATE TABLE IF NOT EXISTS monthly(server TEXT NOT NULL,tag TEXT NOT NULL,month TEXT NOT NULL,used INTEGER NOT NULL,PRIMARY KEY(server,tag,month));
BEGIN IMMEDIATE;
INSERT OR IGNORE INTO server_grants SELECT DISTINCT user_id,server FROM grants WHERE NOT EXISTS(SELECT 1 FROM preferences WHERE key='server_grants_initialized');
INSERT OR IGNORE INTO preferences VALUES('server_grants_initialized','1');
INSERT OR IGNORE INTO nodes(id,server,tag) SELECT lower(hex(randomblob(24))),s.id,json_extract(j.value,'$.name') FROM servers s,json_each(s.report,'$.tags') j WHERE json_extract(j.value,'$.name') IS NOT NULL;
INSERT OR IGNORE INTO host_grants SELECT user_id,server FROM grants WHERE tag='*';
INSERT OR IGNORE INTO grants SELECT g.user_id,g.server,n.tag FROM grants g JOIN nodes n ON n.server=g.server WHERE g.tag='*';
DELETE FROM grants WHERE tag='*';
INSERT INTO daily_flow SELECT server,tag,strftime('%Y-%m-%d',minute*60,'unixepoch'),SUM(upload),SUM(download) FROM history WHERE NOT EXISTS(SELECT 1 FROM preferences WHERE key='flow_history_initialized') GROUP BY server,tag,strftime('%Y-%m-%d',minute*60,'unixepoch') ON CONFLICT DO NOTHING;
INSERT INTO monthly_flow SELECT server,tag,strftime('%Y-%m',minute*60,'unixepoch'),SUM(upload),SUM(download) FROM history WHERE NOT EXISTS(SELECT 1 FROM preferences WHERE key='flow_history_initialized') GROUP BY server,tag,strftime('%Y-%m',minute*60,'unixepoch') ON CONFLICT DO NOTHING;
INSERT OR IGNORE INTO preferences VALUES('flow_history_initialized','1');
INSERT INTO monthly(server,tag,month,used)
SELECT server,tag,strftime('%Y-%m',minute*60,'unixepoch'),SUM(upload+download) FROM history
WHERE NOT EXISTS(SELECT 1 FROM preferences WHERE key='monthly_history_initialized')
GROUP BY server,tag,strftime('%Y-%m',minute*60,'unixepoch')
ON CONFLICT(server,tag,month) DO UPDATE SET used=MAX(monthly.used,excluded.used);
INSERT OR IGNORE INTO preferences VALUES('monthly_history_initialized','1');
COMMIT;`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Init(name, password string) error {
	if !auth.ValidPassword(password) {
		return fmt.Errorf("password must be nonempty Unicode")
	}
	var n int
	s.QueryRow("SELECT count(*) FROM users").Scan(&n)
	if n != 0 {
		return fmt.Errorf("users already initialized")
	}
	_, e := s.Exec("INSERT INTO users(name,role,hash) VALUES(?,'admin',?)", name, auth.Hash(password))
	return e
}
func (s *Store) User(id int64) (User, error) {
	var u User
	e := s.QueryRow("SELECT id,name,role,disabled,hash FROM users WHERE id=?", id).Scan(&u.ID, &u.Name, &u.Role, &u.Disabled, &u.Hash)
	return u, e
}
func (s *Store) ByName(name string) (User, error) {
	var id int64
	e := s.QueryRow("SELECT id FROM users WHERE name=?", name).Scan(&id)
	if e != nil {
		return User{}, e
	}
	return s.User(id)
}
func (s *Store) Session(token string) (User, string, error) {
	var id int64
	var csrf string
	e := s.QueryRow("SELECT user_id,csrf FROM sessions WHERE token=? AND expires>?", auth.Digest(token), time.Now().Unix()).Scan(&id, &csrf)
	if e != nil {
		return User{}, "", e
	}
	u, e := s.User(id)
	if u.Disabled {
		return User{}, "", fmt.Errorf("disabled")
	}
	return u, csrf, e
}
func (s *Store) Allowed(u User, server, tag string) bool {
	if u.Role == "admin" {
		return true
	}
	var n int
	if tag == "*" {
		s.QueryRow("SELECT count(*) FROM host_grants h JOIN server_grants s ON s.user_id=h.user_id AND s.server=h.server JOIN servers v ON v.id=h.server WHERE h.user_id=? AND h.server=? AND v.enabled=1", u.ID, server).Scan(&n)
		if n > 0 {
			return true
		}
	}
	s.QueryRow("SELECT count(*) FROM grants g JOIN server_grants s ON s.user_id=g.user_id AND s.server=g.server JOIN servers v ON v.id=g.server WHERE g.user_id=? AND g.server=? AND v.enabled=1 AND (g.tag='*' OR g.tag=?)", u.ID, server, tag).Scan(&n)
	return n > 0
}
func (s *Store) Views(u User) ([]model.View, error)           { return s.views(u, false) }
func (s *Store) ManagementViews(u User) ([]model.View, error) { return s.views(u, true) }
func (s *Store) views(u User, management bool) ([]model.View, error) {
	rows, e := s.Query("SELECT id,name,enabled,seen,report FROM servers ORDER BY name")
	if e != nil {
		return nil, e
	}
	type raw struct {
		id, name string
		enabled  bool
		seen     int64
		b        []byte
	}
	rs := []raw{}
	for rows.Next() {
		var r raw
		if e = rows.Scan(&r.id, &r.name, &r.enabled, &r.seen, &r.b); e != nil {
			rows.Close()
			return nil, e
		}
		rs = append(rs, r)
	}
	rows.Close()
	out := []model.View{}
	ordinal := 0
	for _, r := range rs {
		var report model.Report
		if len(r.b) > 0 {
			if json.Unmarshal(r.b, &report) != nil {
				continue
			}
		}
		tags := []model.Tag{}
		var diagnostics *model.Diagnostics
		if u.Role == "admin" {
			diagnostics = s.diagnose(u, r.id, report)
		}
		inboundInventory := false
		for _, t := range report.Tags {
			inboundInventory = inboundInventory || t.Identity == "inbound"
		}
		for _, t := range report.Tags {
			if inboundInventory && t.Identity != "inbound" {
				continue
			}
			if s.Allowed(u, r.id, t.Name) {
				if t.Identity != "inbound" && t.Egress != "" && !s.Allowed(u, r.id, t.Egress) {
					t.Egress = ""
					t.IP = nil
				}
				if e := s.Present(u, r.id, &t); e != nil {
					return nil, e
				}
				if !management && s.Setting("show_raw_tag", 0) == 0 {
					t.RawTag = ""
				}
				if !management {
					if s.Setting("show_expiry", 0) == 0 {
						t.ExpiresAt = 0
					}
					if s.Setting("show_quota", 1) == 0 {
						t.Quota = 0
						t.BillingDay = 0
						t.Timezone = ""
						t.AlertThreshold = 0
						t.PeriodStart = 0
					}
					if t.IP != nil {
						t.IP.Error = ""
						t.IP.QualityError = ""
					}
				}
				if (management && t.Kind == "actual") || (!management && t.DisplayEligible) {
					ordinal++
					if !management && t.FallbackName {
						t.Name = fmt.Sprintf("%s %02d", s.DefaultName(), ordinal)
					}
					tags = append(tags, t)
				}
			}
		}
		for _, logical := range report.Tags {
			if inboundInventory {
				break
			}
			kind, _ := model.OutboundType(logical.Type)
			if kind != "logical" || logical.Egress == "" || !s.Allowed(u, r.id, logical.Name) || !s.Allowed(u, r.id, logical.Egress) {
				continue
			}
			var id string
			s.QueryRow("SELECT id FROM nodes WHERE server=? AND tag=?", r.id, logical.Egress).Scan(&id)
			if e := s.Present(u, r.id, &logical); e != nil {
				return nil, e
			}
			for i := range tags {
				if tags[i].ID == id {
					tags[i].Relations = append(tags[i].Relations, logical.Name)
				}
			}
		}
		full := s.Allowed(u, r.id, "*")
		if !full && len(tags) == 0 {
			continue
		}
		report.Tags = tags
		report.Error = ""
		if u.Role != "admin" {
			report.Epoch = ""
			report.Discovery = nil
		}
		if !full {
			report.UnattributedConnections = 0
			report.Host = nil
		}
		online := r.enabled && r.seen > time.Now().Unix()-int64(max(10, report.Interval*4))
		if !online {
			for i := range report.Tags {
				report.Tags[i].State = "unknown"
				if report.Tags[i].Verification == "verified" {
					report.Tags[i].Verification = "stale"
				}
				report.Tags[i].Up = nil
				report.Tags[i].Down = nil
				report.Tags[i].Active = nil
			}
		}
		out = append(out, model.View{Diagnostics: diagnostics, ID: r.id, Name: r.name, Online: online, Seen: r.seen, Report: &report})
	}
	return out, nil
}
func (s *Store) Setting(k string, def int) int {
	var v int
	if s.QueryRow("SELECT value FROM settings WHERE key=?", k).Scan(&v) != nil {
		return def
	}
	return v
}
func (s *Store) Cleanup() {
	days := s.Setting("retention_days", 30)
	s.Exec("DELETE FROM history WHERE minute<?", time.Now().Add(-time.Duration(days)*24*time.Hour).Unix()/60)
	s.Exec("DELETE FROM epochs WHERE at<?", time.Now().Add(-7*24*time.Hour).Unix())
	s.Exec("DELETE FROM sessions WHERE expires<?", time.Now().Unix())
	s.Exec("DELETE FROM audit WHERE at<?", time.Now().Add(-90*24*time.Hour).Unix())
	s.Exec("PRAGMA incremental_vacuum(100)")
}
