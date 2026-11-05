package server

import (
	"crypto/subtle"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
	"unicode"
	"unicode/utf8"
)

var valid = regexp.MustCompile(`^[a-zA-Z0-9_.@:-]{1,128}$`)

func validTag(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type bucket struct {
	n     int
	until time.Time
}
type App struct {
	routeMu        sync.Mutex
	policyCache    policyCache
	DB             *store.Store
	Prefix, Origin string
	TrustedProxy   string
	Static         http.Handler
	mu             sync.Mutex
	limits         map[string]bucket
	sockets        map[int64]map[*websocket.Conn]bool
	hashSem        chan struct{}
	ControlSocket  string
	ControlServer  string
	controlNonces  map[string]controlNonce
	uuidJobs       map[string]bool
	uuidMu         sync.Mutex
	dummy          string
}

func New(db *store.Store, prefix, origin string, static http.Handler) *App {
	return &App{DB: db, Prefix: prefix, Origin: origin, Static: static, limits: map[string]bucket{}, sockets: map[int64]map[*websocket.Conn]bool{}, hashSem: make(chan struct{}, 2), dummy: auth.Hash(auth.Random())}
}
func reply(w http.ResponseWriter, n int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(n)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, n int) { reply(w, n, map[string]string{"error": http.StatusText(n)}) }
func read(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400)
		return false
	}
	var extra any
	if d.Decode(&extra) == io.EOF {
		return true
	}
	fail(w, 400)
	return false
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(r.URL.Path, a.Prefix+"/") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, a.Prefix)
	if path == "/healthz" && r.Method == "GET" {
		if a.DB.Ping() != nil {
			fail(w, 503)
		} else {
			reply(w, 200, map[string]bool{"ok": true})
		}
		return
	}
	if path == "/api/agent/report" {
		a.report(w, r)
		return
	}
	if path == "/api/login" {
		a.login(w, r)
		return
	}
	if !strings.HasPrefix(path, "/api/") && path != "/ws" {
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		if path == "/" {
			path = "/index.html"
		}
		rr := r.Clone(r.Context())
		rr.URL = new(url.URL)
		*rr.URL = *r.URL
		rr.URL.Path = path
		if path == "/index.html" {
			rr.URL.Path = "/"
		}
		a.Static.ServeHTTP(w, rr)
		return
	}
	c, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	u, csrf, e := a.DB.Session(c.Value)
	if e != nil {
		fail(w, 401)
		return
	}
	if r.Method != "GET" {
		if r.Header.Get("Origin") != a.Origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
			fail(w, 403)
			return
		}
	}
	if path == "/ws" {
		a.ws(w, r, u, c.Value)
		return
	}
	if path == "/api/password" {
		a.changePassword(w, r, u)
		return
	}
	if path == "/api/me" && r.Method == "GET" {
		reply(w, 200, map[string]any{"user": u, "csrf": csrf, "operations": a.operations(u)})
		return
	}
	if path == "/api/logout" && r.Method == "POST" {
		a.mu.Lock()
		a.DB.Exec("DELETE FROM sessions WHERE token=?", auth.Digest(c.Value))
		a.disconnect(u.ID)
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "tz_session", Value: "", Path: a.Prefix + "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		reply(w, 200, map[string]bool{"ok": true})
		return
	}
	if path == "/api/node-policy" {
		a.nodePolicy(w, r, u)
		return
	}
	if path == "/api/node-inspect" {
		a.inspectNode(w, r, u)
		return
	}
	if path == "/api/snapshot" && r.Method == "GET" {
		a.mu.Lock()
		defer a.mu.Unlock()
		u, _, e = a.DB.Session(c.Value)
		if e != nil {
			fail(w, 401)
			return
		}
		v, e := a.DB.Views(u)
		if e != nil {
			fail(w, 500)
			return
		}
		a.overlayPolicies(u, v)
		reply(w, 200, v)
		return
	}
	if path == "/api/alias" {
		a.mu.Lock()
		defer a.mu.Unlock()
		u, _, e = a.DB.Session(c.Value)
		if e != nil {
			fail(w, 401)
			return
		}
		a.nodeSettings(w, r, u, false)
		return
	}
	if (path == "/api/history" || path == "/api/export") && r.Method == "GET" {
		a.mu.Lock()
		defer a.mu.Unlock()
		u, _, e = a.DB.Session(c.Value)
		if e != nil {
			fail(w, 401)
			return
		}
		a.history(w, r, u)
		return
	}
	// Outcome queries remain available while the mutation holds routeMu.
	if path == "/api/control/transaction" && r.Method == "GET" {
		a.configOperationStatus(w, r, u, r.URL.Query().Get("id"))
		return
	}
	// Serialize configuration mutations with grants and revocations. Snapshots
	// retain their own short lock and never wait for a network operation.
	if strings.HasPrefix(path, "/api/control/") || strings.HasPrefix(path, "/api/admin/") || path == "/api/personal-outbounds" {
		a.routeMu.Lock()
		defer a.routeMu.Unlock()
		u, _, e = a.DB.Session(c.Value)
		if e != nil {
			fail(w, 401)
			return
		}
	}
	if path == "/api/personal-outbounds" {
		a.personalOutbounds(w, r, u)
		return
	}
	if strings.HasPrefix(path, "/api/control/") {
		a.controlAPI(w, r, u, strings.TrimPrefix(path, "/api/control/"))
		return
	}
	if strings.HasPrefix(path, "/api/admin/") {
		if u.Role != "admin" {
			fail(w, 403)
			return
		}
		a.admin(w, r, u, strings.TrimPrefix(path, "/api/admin/"))
		return
	}
	http.NotFound(w, r)
}
func (a *App) rate(key string, maxn int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.limits) > 2000 {
		for k, v := range a.limits {
			if now.After(v.until) {
				delete(a.limits, k)
			}
		}
		if len(a.limits) > 2000 {
			return false
		}
	}
	b := a.limits[key]
	if now.After(b.until) {
		b = bucket{until: now.Add(time.Minute)}
	}
	b.n++
	a.limits[key] = b
	return b.n <= maxn
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	if r.Header.Get("Origin") != a.Origin {
		fail(w, 403)
		return
	}
	var v struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !read(w, r, &v) {
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !a.rate("ip:"+ip, 30) || !a.rate("name:"+v.Name, 8) {
		fail(w, 429)
		return
	}
	if !valid.MatchString(v.Name) || !auth.ValidPassword(v.Password) {
		fail(w, 400)
		return
	}
	select {
	case a.hashSem <- struct{}{}:
		defer func() { <-a.hashSem }()
	default:
		fail(w, 429)
		return
	}
	u, e := a.DB.ByName(v.Name)
	h := a.dummy
	if e == nil {
		h = u.Hash
	}
	ok := auth.Check(h, v.Password) && e == nil && !u.Disabled
	event := "login_failed"
	if ok {
		event = "login_ok"
	}
	a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), v.Name, ip, event)
	if !ok {
		fail(w, 401)
		return
	}
	token, csrf := auth.Random(), auth.Random()
	_, e = a.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", auth.Digest(token), u.ID, csrf, time.Now().Add(12*time.Hour).Unix())
	if e != nil {
		fail(w, 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "tz_session", Value: token, Path: a.Prefix + "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	reply(w, 200, map[string]any{"user": u, "csrf": csrf, "operations": a.operations(u)})
}
func (a *App) disconnect(id int64) {
	for key, n := range a.controlNonces {
		if n.User == id {
			delete(a.controlNonces, key)
		}
	}
	for c := range a.sockets[id] {
		c.Close()
	}
	delete(a.sockets, id)
}
func (a *App) ws(w http.ResponseWriter, r *http.Request, u store.User, token string) {
	if r.Method != "GET" || r.Header.Get("Origin") != a.Origin {
		fail(w, 403)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, v := range a.sockets {
		n += len(v)
	}
	if n >= 64 || len(a.sockets[u.ID]) >= 3 {
		fail(w, 429)
		return
	}
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == a.Origin }}
	c, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	if a.sockets[u.ID] == nil {
		a.sockets[u.ID] = map[*websocket.Conn]bool{}
	}
	a.sockets[u.ID][c] = true
	done := make(chan struct{})
	c.SetReadLimit(1024)
	c.SetReadDeadline(time.Now().Add(45 * time.Second))
	c.SetPongHandler(func(string) error { return c.SetReadDeadline(time.Now().Add(45 * time.Second)) })
	go func() {
		defer close(done)
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	}()
	go func() {
		defer c.Close()
		defer func() { a.mu.Lock(); delete(a.sockets[u.ID], c); a.mu.Unlock() }()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			a.mu.Lock()
			fresh, _, err := a.DB.Session(token)
			if err != nil {
				a.mu.Unlock()
				return
			}
			v, err := a.DB.Views(fresh)
			if err == nil {
				a.overlayPolicies(fresh, v)
				c.SetWriteDeadline(time.Now().Add(3 * time.Second))
				err = c.WriteJSON(v)
			}
			if err == nil {
				err = c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second))
			}
			a.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
}
func (a *App) history(w http.ResponseWriter, r *http.Request, u store.User) {
	server, tag := r.URL.Query().Get("server"), r.URL.Query().Get("tag")
	if id := r.URL.Query().Get("node_id"); id != "" {
		var err error
		server, tag, err = a.DB.Resolve(u, id)
		if err != nil {
			fail(w, 403)
			return
		}
	} else if u.Role != "admin" {
		fail(w, 403)
		return
	}
	if !a.DB.Allowed(u, server, tag) {
		fail(w, 403)
		return
	}
	// Once an Agent supplies true inbound identities, retired outbound history
	// is unavailable through the new monitoring/export API as well as the UI.
	if !strings.HasPrefix(tag, "inbound:") && !(strings.HasPrefix(tag, "identity:") && model.ValidAuthID(strings.TrimPrefix(tag, "identity:"))) {
		var raw []byte
		if a.DB.QueryRow("SELECT report FROM servers WHERE id=?", server).Scan(&raw) == nil {
			var report model.Report
			if json.Unmarshal(raw, &report) == nil {
				for _, t := range report.Tags {
					if t.Identity == "inbound" {
						fail(w, 403)
						return
					}
				}
			}
		}
	}
	duration, bucket := 24*time.Hour, int64(2)
	switch r.URL.Query().Get("range") {
	case "", "24h":
	case "1h":
		duration = time.Hour
		bucket = 1
	case "7d":
		duration = 7 * 24 * time.Hour
		bucket = 14
	case "30d":
		duration = 30 * 24 * time.Hour
		bucket = 60
	default:
		fail(w, 400)
		return
	}
	rows, e := a.DB.Query("SELECT (minute/?)*?,AVG(up),AVG(down),SUM(upload),SUM(download) FROM history WHERE server=? AND tag=? AND minute>=? GROUP BY minute/? ORDER BY minute DESC LIMIT 720", bucket, bucket, server, tag, time.Now().Add(-duration).Unix()/60, bucket)
	if e != nil {
		fail(w, 500)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var m, ul, dl int64
		var up, down float64
		rows.Scan(&m, &up, &down, &ul, &dl)
		out = append(out, map[string]any{"at": m * 60, "up": up, "down": down, "upload": ul, "download": dl})
	}
	reply(w, 200, out)
}
func (a *App) admin(w http.ResponseWriter, r *http.Request, u store.User, path string) {
	switch path {
	case "outbounds":
		a.outboundAdmin(w, r, u)
		return
	case "node-catalog", "node-preview", "node-create", "node-transaction", "node-delete", "node-state":
		a.uuidAdmin(w, r, u, path)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch path {
	case "nodes":
		if r.Method == "GET" {
			v, e := a.DB.ManagementViews(u)
			if e != nil {
				fail(w, 500)
			} else {
				reply(w, 200, v)
			}
			return
		}
		a.nodeSettings(w, r, u, true)
	case "users":
		if r.Method == "GET" {
			rows, e := a.DB.Query("SELECT id,name,role,disabled FROM users ORDER BY id")
			if e != nil {
				fail(w, 500)
				return
			}
			out := []store.User{}
			for rows.Next() {
				var x store.User
				rows.Scan(&x.ID, &x.Name, &x.Role, &x.Disabled)
				out = append(out, x)
			}
			rows.Close()
			reply(w, 200, out)
			return
		}
		var v struct {
			ID       int64   `json:"id"`
			Name     string  `json:"name"`
			Password *string `json:"password"`
			Disabled *bool   `json:"disabled"`
		}
		if !read(w, r, &v) {
			return
		}
		var err error
		if r.Method == "POST" {
			if !valid.MatchString(v.Name) || (v.Password == nil || !auth.ValidPassword(*v.Password)) {
				fail(w, 400)
				return
			}
			_, err = a.DB.Exec("INSERT INTO users(id,name,role,hash) SELECT coalesce(max(v),0)+1,?,'user',? FROM (SELECT id AS v FROM users UNION ALL SELECT owner AS v FROM outbound_registry)", v.Name, auth.Hash(*v.Password))
		} else if r.Method == "PATCH" || r.Method == "DELETE" {
			if r.Method == "PATCH" && (v.Password == nil) == (v.Disabled == nil) {
				fail(w, 400)
				return
			}

			target, e := a.DB.User(v.ID)
			if e != nil || target.Role == "admin" {
				fail(w, 403)
				return
			}
			if v.Password != nil && !auth.ValidPassword(*v.Password) {
				fail(w, 400)
				return
			}
			a.disconnect(v.ID)
			a.DB.Exec("DELETE FROM sessions WHERE user_id=?", v.ID)
			if r.Method == "DELETE" {
				_, err = a.DB.Exec("DELETE FROM users WHERE id=?", v.ID)
			} else if v.Password != nil {
				_, err = a.DB.Exec("UPDATE users SET hash=? WHERE id=?", auth.Hash(*v.Password), v.ID)
			} else {
				_, err = a.DB.Exec("UPDATE users SET disabled=? WHERE id=?", *v.Disabled, v.ID)
			}
		} else {
			fail(w, 405)
			return
		}
		if err != nil {
			fail(w, 400)
			return
		}
		a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "user_change")
		reply(w, 200, map[string]bool{"ok": true})
	case "operations":
		a.operationAdmin(w, r, u)
		return
	case "server-grants":
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		rs, e := a.DB.Query("SELECT user_id,server FROM server_grants ORDER BY user_id,server")
		if e != nil {
			fail(w, 500)
			return
		}
		defer rs.Close()
		out := []map[string]any{}
		for rs.Next() {
			var id int64
			var server string
			rs.Scan(&id, &server)
			out = append(out, map[string]any{"user_id": id, "server": server})
		}
		reply(w, 200, out)
	case "grants":
		if r.Method == "GET" {
			rows, e := a.DB.Query("SELECT user_id,server,tag FROM grants UNION ALL SELECT user_id,server,'*' FROM host_grants")
			if e != nil {
				fail(w, 500)
				return
			}
			out := []map[string]any{}
			for rows.Next() {
				var id int64
				var s, t string
				rows.Scan(&id, &s, &t)
				out = append(out, map[string]any{"user_id": id, "server": s, "tag": t})
			}
			rows.Close()
			reply(w, 200, out)
			return
		}
		if r.Method != "PUT" {
			fail(w, 405)
			return
		}
		var v struct {
			UserID  int64         `json:"user_id"`
			Grants  []store.Grant `json:"grants"`
			Servers []string      `json:"servers"`
			Hosts   []string      `json:"hosts"`
		}
		if !read(w, r, &v) {
			return
		}
		target, e := a.DB.User(v.UserID)
		if e != nil || target.Role == "admin" || len(v.Grants) > 512 {
			fail(w, 400)
			return
		}
		// Compatibility: '*' selects today's nodes and host metrics, never future nodes.
		current, e := a.DB.ManagementViews(u)
		if e != nil {
			fail(w, 500)
			return
		}
		explicit := []store.Grant{}
		unique := map[store.Grant]bool{}
		for _, g := range v.Grants {
			if g.Tag == "*" {
				v.Hosts = append(v.Hosts, g.Server)
				for _, s := range current {
					if s.ID == g.Server && s.Report != nil {
						for _, t := range s.Report.Tags {
							ng := store.Grant{Server: g.Server, Tag: t.RawTag}
							if !unique[ng] {
								explicit = append(explicit, ng)
								unique[ng] = true
							}
						}
					}
				}
			} else if !unique[g] {
				explicit = append(explicit, g)
				unique[g] = true
			}
		}
		v.Grants = explicit
		tx, e := a.DB.Begin()
		if e != nil {
			fail(w, 500)
			return
		}
		defer tx.Rollback()
		_, e = tx.Exec("DELETE FROM server_grants WHERE user_id=?", v.UserID)
		for _, server := range v.Servers {
			if !valid.MatchString(server) {
				fail(w, 400)
				return
			}
			if e == nil {
				_, e = tx.Exec("INSERT OR IGNORE INTO server_grants VALUES(?,?)", v.UserID, server)
			}
		}
		if e == nil {
			_, e = tx.Exec("DELETE FROM host_grants WHERE user_id=?", v.UserID)
		}
		for _, server := range v.Hosts {
			if !valid.MatchString(server) {
				fail(w, 400)
				return
			}
			if e == nil {
				_, e = tx.Exec("INSERT OR IGNORE INTO host_grants VALUES(?,?)", v.UserID, server)
			}
		}
		if e == nil {
			_, e = tx.Exec("DELETE FROM grants WHERE user_id=?", v.UserID)
		}
		for _, g := range v.Grants {
			if !valid.MatchString(g.Server) || (g.Tag != "*" && !validTag(g.Tag) && !(strings.HasPrefix(g.Tag, "inbound:") && validTag(strings.TrimPrefix(g.Tag, "inbound:")))) {
				fail(w, 400)
				return
			}
			if e == nil {
				_, e = tx.Exec("INSERT INTO grants VALUES(?,?,?)", v.UserID, g.Server, g.Tag)
			}
		}
		if e != nil {
			fail(w, 400)
			return
		}
		a.disconnect(v.UserID)
		if tx.Commit() != nil {
			fail(w, 500)
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	case "servers":
		if r.Method == "GET" {
			rows, e := a.DB.Query("SELECT id,name,enabled FROM servers ORDER BY id")
			if e != nil {
				fail(w, 500)
				return
			}
			out := []store.Server{}
			for rows.Next() {
				var s store.Server
				rows.Scan(&s.ID, &s.Name, &s.Enabled)
				out = append(out, s)
			}
			rows.Close()
			reply(w, 200, out)
			return
		}
		var v struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		}
		if !read(w, r, &v) {
			return
		}
		if !valid.MatchString(v.ID) {
			fail(w, 400)
			return
		}
		var e error
		if r.Method == "POST" {
			if len(v.Name) < 1 || len(v.Name) > 128 {
				fail(w, 400)
				return
			}
			token := auth.Random()
			_, e = a.DB.Exec("INSERT INTO servers(id,name,token) VALUES(?,?,?)", v.ID, v.Name, auth.Digest(token))
			if e != nil {
				fail(w, 400)
				return
			}
			reply(w, 201, map[string]string{"token": token, "id": v.ID})
			return
		} else if r.Method == "PATCH" {
			if len(v.Name) < 1 || len(v.Name) > 128 {
				fail(w, 400)
				return
			}
			_, e = a.DB.Exec("UPDATE servers SET name=?,enabled=? WHERE id=?", v.Name, v.Enabled, v.ID)
		} else if r.Method == "DELETE" {
			tx, err := a.DB.Begin()
			if err != nil {
				fail(w, 500)
				return
			}
			defer tx.Rollback()
			_, e = tx.Exec("DELETE FROM history WHERE server=?", v.ID)
			if e == nil {
				_, e = tx.Exec("DELETE FROM counters WHERE server=?", v.ID)
				if e == nil {
					_, e = tx.Exec("DELETE FROM monthly WHERE server=?", v.ID)
				}
			}
			if e == nil {
				_, e = tx.Exec("DELETE FROM servers WHERE id=?", v.ID)
			}
			if e == nil {
				e = tx.Commit()
			}
		} else {
			fail(w, 405)
			return
		}
		for id := range a.sockets {
			a.disconnect(id)
		}
		if e != nil {
			fail(w, 500)
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	case "settings":
		if r.Method == "GET" {
			reply(w, 200, map[string]any{"sample_seconds": a.DB.Setting("sample_seconds", 2), "retention_days": a.DB.Setting("retention_days", 30), "show_raw_tag": a.DB.Setting("show_raw_tag", 0) == 1, "default_node_name": a.DB.DefaultName(), "show_expiry": a.DB.Setting("show_expiry", 0) == 1, "show_quota": a.DB.Setting("show_quota", 1) == 1})
			return
		}
		if r.Method != "PUT" {
			fail(w, 405)
			return
		}
		var v struct {
			Sample      int    `json:"sample_seconds"`
			Retention   int    `json:"retention_days"`
			Show        bool   `json:"show_raw_tag"`
			ShowExpiry  bool   `json:"show_expiry"`
			ShowQuota   *bool  `json:"show_quota"`
			DefaultName string `json:"default_node_name"`
		}
		if !read(w, r, &v) {
			return
		}
		if v.Sample < 2 || v.Sample > 60 || v.Retention < 1 || v.Retention > 90 {
			fail(w, 400)
			return
		}
		if v.DefaultName == "" {
			v.DefaultName = a.DB.DefaultName()
		}
		if !validTag(v.DefaultName) {
			fail(w, 400)
			return
		}
		tx, e := a.DB.Begin()
		if e != nil {
			fail(w, 500)
			return
		}
		defer tx.Rollback()
		_, e = tx.Exec("UPDATE settings SET value=CASE key WHEN 'sample_seconds' THEN ? WHEN 'retention_days' THEN ? WHEN 'show_raw_tag' THEN ? ELSE value END", v.Sample, v.Retention, v.Show)
		if e == nil {
			quota := true
			if v.ShowQuota != nil {
				quota = *v.ShowQuota
			}
			_, e = tx.Exec("UPDATE settings SET value=CASE key WHEN 'show_expiry' THEN ? WHEN 'show_quota' THEN ? ELSE value END", v.ShowExpiry, quota)
		}
		if e == nil {
			_, e = tx.Exec("UPDATE preferences SET value=? WHERE key='default_node_name'", v.DefaultName)
		}
		if e == nil {
			_, e = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "settings_change: show_raw_tag, default_name, sampling, retention")
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			fail(w, 500)
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	case "monitor-diagnostics":
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		target := u
		if value := r.URL.Query().Get("user_id"); value != "" {
			id, e := strconv.ParseInt(value, 10, 64)
			if e != nil {
				fail(w, 400)
				return
			}
			target, e = a.DB.User(id)
			if e != nil {
				fail(w, 404)
				return
			}
		}
		data, e := a.DB.MonitorDiagnostics(target)
		if e != nil {
			fail(w, 500)
			return
		}
		reply(w, 200, data)
	case "audit":
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		rows, e := a.DB.Query("SELECT at,name,ip,event FROM audit ORDER BY id DESC LIMIT 200")
		if e != nil {
			fail(w, 500)
			return
		}
		out := []map[string]any{}
		for rows.Next() {
			var t int64
			var name, ip, event string
			rows.Scan(&t, &name, &ip, &event)
			out = append(out, map[string]any{"at": t, "name": name, "ip": ip, "event": event})
		}
		rows.Close()
		reply(w, 200, out)
	default:
		http.NotFound(w, r)
	}
}
func (a *App) report(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if r.TLS == nil && !(a.TrustedProxy != "" && peer == a.TrustedProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
		fail(w, 426)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var v model.Report
	if json.NewDecoder(r.Body).Decode(&v) != nil || !valid.MatchString(v.ServerID) || len(v.Tags) > 512 || v.Interval < 2 || v.Interval > 60 || v.At < time.Now().Unix()-60 || v.At > time.Now().Unix()+15 || len(v.Epoch) != 43 || v.Seq < 1 {
		fail(w, 400)
		return
	}
	seen := map[string]bool{}
	for _, t := range v.Tags {
		if (t.Identity == "inbound" && (!validTag(t.InboundTag) || t.Name != model.IdentityName(t.InboundTag, t.AuthID) || (t.AuthID != "" && !model.ValidAuthID(t.AuthID)))) || (t.Identity != "inbound" && !validTag(t.Name)) || seen[t.Name] || len(t.Type) > 64 || len([]rune(t.AuthName)) > 128 || len(t.AccountingReason) > 1024 || len(t.Egress) > 128 || (t.Upload != nil && *t.Upload < 0) || (t.Download != nil && *t.Download < 0) {
			fail(w, 400)
			return
		}
		if (t.AuthScheme != "" && t.AuthScheme != "uuid-v1") || (t.LegacyAuthID != "" && (t.AuthScheme != "uuid-v1" || t.AuthID == "" || !model.ValidAuthID(t.LegacyAuthID))) {
			fail(w, 400)
			return
		}
		seen[t.Name] = true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(token) != 43 {
		fail(w, 401)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, e := a.DB.Begin()
	if e != nil {
		fail(w, 503)
		return
	}
	defer tx.Rollback()
	var want, epoch string
	var seq int64
	var enabled bool
	e = tx.QueryRow("SELECT token,enabled,epoch,seq FROM servers WHERE id=?", v.ServerID).Scan(&want, &enabled, &epoch, &seq)
	if e != nil || !enabled || subtle.ConstantTimeCompare([]byte(want), []byte(auth.Digest(token))) != 1 {
		fail(w, 401)
		return
	}
	if epoch == v.Epoch && v.Seq <= seq {
		fail(w, 409)
		return
	}
	if epoch != v.Epoch {
		if _, e = tx.Exec("INSERT INTO epochs(server,epoch,at) VALUES(?,?,?)", v.ServerID, v.Epoch, v.At); e != nil {
			fail(w, 409)
			return
		}
	}
	if e = store.MigrateUUIDIdentities(tx, v.ServerID, v.Tags); e != nil {
		fail(w, 409)
		return
	}
	for i := range v.Tags {
		t := &v.Tags[i]
		t.Classify()
		if t.Kind != "actual" || t.Accounting == "unavailable" {
			t.Upload = nil
			t.Download = nil
			t.Up = nil
			t.Down = nil
			t.Active = nil
			t.IP = nil
		}
		if t.IP != nil && t.IP.Verified && t.IP.Error == "" && t.IP.Updated > 0 {
			data, _ := json.Marshal(t.IP)
			if _, e = tx.Exec("INSERT INTO exit_cache VALUES(?,?,?) ON CONFLICT(server,tag) DO UPDATE SET data=excluded.data", v.ServerID, t.Name, data); e != nil {
				fail(w, 500)
				return
			}
		}
		_, e = tx.Exec("INSERT OR IGNORE INTO nodes(id,server,tag) VALUES(?,?,?)", auth.Random(), v.ServerID, t.Name)
		if e != nil {
			fail(w, 500)
			return
		}
		if t.Upload == nil || t.Download == nil {
			continue
		}
		var oldepoch string
		var ru, rd, tu, td int64
		tx.QueryRow("SELECT epoch,rawup,rawdown,totalup,totaldown FROM counters WHERE server=? AND tag=?", v.ServerID, t.Name).Scan(&oldepoch, &ru, &rd, &tu, &td)
		du, dd := *t.Upload, *t.Download
		if oldepoch == v.Epoch {
			du = max(0, du-ru)
			dd = max(0, dd-rd)
		}
		_, e = tx.Exec("INSERT INTO counters VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET epoch=excluded.epoch,rawup=excluded.rawup,rawdown=excluded.rawdown,totalup=excluded.totalup,totaldown=excluded.totaldown", v.ServerID, t.Name, v.Epoch, *t.Upload, *t.Download, tu+du, td+dd, v.At)
		if e != nil {
			fail(w, 500)
			return
		}
		_, e = tx.Exec("INSERT INTO monthly VALUES(?,?,?,?) ON CONFLICT(server,tag,month) DO UPDATE SET used=monthly.used+excluded.used", v.ServerID, t.Name, time.Unix(v.At, 0).UTC().Format("2006-01"), du+dd)
		if e != nil {
			fail(w, 500)
			return
		}
		var day int
		var zone string
		if err := tx.QueryRow("SELECT m.billing_day,m.timezone FROM node_metadata m JOIN nodes n ON n.id=m.node_id WHERE n.server=? AND n.tag=?", v.ServerID, t.Name).Scan(&day, &zone); err == nil && (day != 1 || zone != "UTC") {
			start := store.BillingStart(time.Unix(v.At, 0), day, zone).Unix()
			if _, e = tx.Exec("INSERT INTO billing_usage VALUES(?,?,?,?) ON CONFLICT(server,tag,start) DO UPDATE SET used=used+excluded.used", v.ServerID, t.Name, start, du+dd); e != nil {
				fail(w, 500)
				return
			}
		}
		for _, period := range []struct{ table, format string }{{"daily_flow", "2006-01-02"}, {"monthly_flow", "2006-01"}} {
			_, e = tx.Exec("INSERT INTO "+period.table+" VALUES(?,?,?,?,?) ON CONFLICT DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download", v.ServerID, t.Name, time.Unix(v.At, 0).UTC().Format(period.format), du, dd)
			if e != nil {
				fail(w, 500)
				return
			}
		}
		up, down := 0., 0.
		if t.Up != nil {
			up = *t.Up
		}
		if t.Down != nil {
			down = *t.Down
		}
		_, e = tx.Exec("INSERT INTO history VALUES(?,?,?,?,?,?,?) ON CONFLICT(server,tag,minute) DO UPDATE SET up=excluded.up,down=excluded.down,upload=history.upload+excluded.upload,download=history.download+excluded.download", v.ServerID, t.Name, v.At/60, up, down, du, dd)
		if e != nil {
			fail(w, 500)
			return
		}
		t.Upload = new(int64)
		*t.Upload = tu + du
		t.Download = new(int64)
		*t.Download = td + dd
	}
	b, e := json.Marshal(v)
	if e != nil {
		fail(w, 400)
		return
	}
	_, e = tx.Exec("UPDATE servers SET epoch=?,seq=?,seen=?,report=? WHERE id=?", v.Epoch, v.Seq, time.Now().Unix(), b, v.ServerID)
	if e != nil || tx.Commit() != nil {
		fail(w, 500)
		return
	}
	reply(w, 200, map[string]int{"sample_seconds": a.DB.Setting("sample_seconds", 2)})
}
