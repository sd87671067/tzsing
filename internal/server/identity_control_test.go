package server

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestIdentityControlUsesCurrentReportAndRejectsInboundMutation(t *testing.T) {
	f := setup(t)
	id := model.AuthID("alice")
	raw := model.IdentityName("shared", id)
	report := model.Report{ServerID: "one", At: time.Now().Unix(), Tags: []model.Tag{{Name: raw, InboundTag: "shared", AuthID: id, Identity: "inbound", Type: "vless", Accounting: "unavailable"}}}
	b, _ := json.Marshal(report)
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('identity-node','one',?)", raw)
	for _, action := range []string{"copy", "change", "restore"} {
		f.db.Exec("INSERT INTO control_permissions VALUES(1,?)", action)
	}
	socket := filepath.Join(t.TempDir(), "control.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	host := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["auth_id"] != id || payload["tag"] != "shared" {
			t.Error("identity lost at host boundary")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/status" {
			w.Write([]byte(`{"share":true,"apply":false,"restore":false,"preview":false,"profiles":[{"id":"only-alice","label":"alice"}]}`))
		} else {
			w.Write([]byte(`{"link":"vless://synthetic-alice@example.org:443"}`))
		}
	})}
	go host.Serve(ln)
	defer host.Close()
	f.app.ControlSocket = socket
	f.app.ControlServer = "one"
	r := f.req(t, "GET", "/api/control/status?node_id=identity-node", nil, f.admin, "")
	var status map[string]any
	json.NewDecoder(r.Body).Decode(&status)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("identity status", r.StatusCode)
	}
	payload := map[string]string{"node_id": "identity-node", "nonce": status["nonce"].(string), "action": "copy", "profile": "only-alice"}
	r = f.req(t, "POST", "/api/control/share", payload, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("identity share", r.StatusCode)
	}
	for _, path := range []string{"preview", "apply", "restore-preview", "restore"} {
		r = f.req(t, "POST", "/api/control/"+path, payload, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 409 {
			t.Fatal("missing/reused nonce accepted", path, r.StatusCode)
		}
	}
	if calls != 2 {
		t.Fatal("blocked operation reached host", calls)
	}
	f.db.Exec("UPDATE servers SET report=? WHERE id='one'", `{"server_id":"one","tags":[]}`)
	r = f.req(t, "GET", "/api/control/status?node_id=identity-node", nil, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("stale identity accepted", r.StatusCode)
	}
	if calls != 2 {
		t.Fatal("stale identity reached host")
	}
	var events string
	f.db.QueryRow("SELECT COALESCE(group_concat(event),'') FROM audit").Scan(&events)
	if strings.Contains(events, "synthetic-alice") {
		t.Fatal("credential logged")
	}
}

func TestDeleteProtocolIdentityBoundaryAndAdminPermission(t *testing.T) {
	for _, typ := range []string{"vless", "shadowsocks", "trojan", "socks", "http"} {
		t.Run(typ, func(t *testing.T) {
			f := setup(t)
			id := model.AuthID("alice")
			raw := model.IdentityName("target", id)
			report, _ := json.Marshal(model.Report{ServerID: "one", At: time.Now().Unix(), Tags: []model.Tag{{Name: raw, InboundTag: "target", AuthID: id, Identity: "inbound", Type: typ}}})
			f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", report, time.Now().Unix())
			f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('delete-target','one',?)", raw)
			f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
			f.db.Exec("INSERT INTO user_operations VALUES(2,'change')")
			f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
			socket := filepath.Join(t.TempDir(), "delete.sock")
			ln, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			applies := 0
			host := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var v map[string]string
				json.NewDecoder(r.Body).Decode(&v)
				if r.URL.Path != "/outbound-catalog" && (v["tag"] != "target" || v["auth_id"] != id) {
					t.Error("lost protocol identity")
				}
				switch r.URL.Path {
				case "/outbound-catalog":
					w.Write([]byte(`{"items":[],"mappings":{}}`))
				case "/status":
					w.Write([]byte(`{"delete":true,"apply":false}`))
				case "/preview":
					if v["action"] != "delete" {
						t.Error("not a deletion")
					}
					w.Write([]byte(`{"plan":"delete-plan","writable":true,"effects":{}}`))
				case "/apply":
					applies++
					if v["plan"] != "delete-plan" {
						t.Error("wrong plan")
					}
					w.Write([]byte(`{"ok":true}`))
				default:
					t.Error("unexpected controller operation", r.URL.Path)
				}
			})}
			go host.Serve(ln)
			defer host.Close()
			f.app.ControlSocket = socket
			f.app.ControlServer = "one"
			call := func(method, path string, body any, admin bool, want int) map[string]any {
				t.Helper()
				cookie, csrf := f.user, f.ucs
				if admin {
					cookie, csrf = f.admin, f.acs
				}
				res := f.req(t, method, "/api/control/"+path, body, cookie, csrf)
				defer res.Body.Close()
				v := map[string]any{}
				json.NewDecoder(res.Body).Decode(&v)
				if res.StatusCode != want {
					t.Fatal(path, res.StatusCode, v)
				}
				return v
			}
			viewer := call("GET", "status?node_id=delete-target", nil, false, 200)
			if viewer["delete"] != false {
				t.Fatal("viewer advertised deletion")
			}
			call("POST", "preview", map[string]any{"node_id": "delete-target", "nonce": viewer["nonce"], "action": "delete"}, false, 403)
			g := call("GET", "status?node_id=delete-target", nil, true, 200)
			if g["delete"] != true {
				t.Fatal("admin deletion missing")
			}
			p := call("POST", "preview", map[string]any{"node_id": "delete-target", "nonce": g["nonce"], "action": "delete"}, true, 200)
			call("POST", "apply", map[string]any{"node_id": "delete-target", "nonce": p["nonce"]}, true, 200)
			call("POST", "apply", map[string]any{"node_id": "delete-target", "nonce": p["nonce"]}, true, 409)
			if applies != 1 {
				t.Fatal("unexpected apply count", applies)
			}
		})
	}
}
