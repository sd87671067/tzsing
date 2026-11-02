package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

var syncBase = []byte(`{"inbounds":[{"tag":"shared","type":"vless","listen":"127.0.0.1","listen_port":443,"tls":{"reality":{"private_key":"keep-key","short_id":["abcd"]}},"users":[{"name":"a","uuid":"keep-a"},{"name":"b","uuid":"keep-b"}]}],"outbounds":[{"tag":"direct","type":"direct"},{"tag":"relay","type":"selector","outbounds":["direct"],"default":"direct"}],"route":{"rules":[{"inbound":["shared"],"auth_user":["a"],"action":"route","outbound":"direct"},{"inbound":["shared"],"auth_user":["b"],"action":"route","outbound":"direct"},{"inbound":["shared"],"action":"reject"}]},"extension":{"precise":9007199254740993,"nested":[1,2]}}`)

func changeSyncUser(raw []byte, name, out string) []byte {
	var c map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.Decode(&c)
	for _, v := range array(object(c["route"])["rules"]) {
		r := object(v)
		if reflect.DeepEqual(r["auth_user"], []any{name}) {
			r["outbound"] = out
		}
	}
	b, _ := json.Marshal(c)
	return b
}
func TestSharedMergeDisjointUUIDConflictExtensionsAndOrder(t *testing.T) {
	a := changeSyncUser(syncBase, "a", "relay")
	b := changeSyncUser(syncBase, "b", "relay")
	merged, e := mergeConfig(syncBase, a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(merged, []byte("9007199254740993")) || !bytes.Contains(merged, []byte("keep-key")) {
		t.Fatal("opaque fields lost")
	}
	want := changeSyncUser(b, "a", "relay")
	if !reflect.DeepEqual(canonicalJSON(merged), canonicalJSON(want)) {
		t.Fatal("disjoint change lost")
	}
	conflicting := changeSyncUser(syncBase, "a", "other")
	if _, e = mergeConfig(syncBase, a, conflicting); e == nil {
		t.Fatal("same UUID silently overwritten")
	}
	// An unrelated manager's added route stays at its precise position.
	latest := candidateMap(b)
	r := object(latest["route"])
	r["rules"] = append([]any{map[string]any{"domain": []any{"keep.example"}, "action": "reject"}}, array(r["rules"])...)
	merged, e = mergeConfig(syncBase, a, canonical(latest))
	if e != nil {
		t.Fatal(e)
	}
	rules := array(object(candidateMap(merged)["route"])["rules"])
	if text(object(rules[0])["action"]) != "reject" || len(rules) != 4 {
		t.Fatal("foreign route lost or reordered")
	}
}
func newSyncController(t *testing.T) (*Controller, string, *int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, syncBase, 0600)
	activated := 0
	c := &Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &ApplyHooks{Check: func(raw []byte) error {
		if !json.Valid(raw) {
			return errors.New("invalid")
		}
		return nil
	}, Activate: func() error { activated++; return nil }, Healthy: func(map[string]any) error { return nil }, Probe: func(map[string]any) error { return nil }}}
	return c, path, &activated
}
func syncPost(c *Controller, base, desired []byte) *httptest.ResponseRecorder {
	body := canonical(map[string]any{"base": json.RawMessage(base), "hash": digest(base), "candidate": json.RawMessage(desired)})
	r := httptest.NewRequest("POST", "/sbbot-apply", bytes.NewReader(body))
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w
}
func TestSharedControllerBothDirectionsRollbackAndFileLock(t *testing.T) {
	for _, scenario := range []string{"bot-then-web", "web-then-bot", "conflict", "check", "health", "flock", "noop"} {
		t.Run(scenario, func(t *testing.T) {
			c, path, activated := newSyncController(t)
			a := changeSyncUser(syncBase, "a", "relay")
			b := changeSyncUser(syncBase, "b", "relay")
			switch scenario {
			case "flock":
				f, e := os.OpenFile(filepath.Join(c.Config.State, "apply.lock"), os.O_CREATE|os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
				defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				if w := syncPost(c, syncBase, a); w.Code != 409 {
					t.Fatal("separate file description lock ignored", w.Code)
				}
			case "bot-then-web":
				if w := syncPost(c, syncBase, a); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				if e := c.apply(plan{Base: syncBase, Hash: digest(syncBase), Candidate: b, Action: "test-web"}); e != nil {
					t.Fatal(e)
				}
			case "web-then-bot":
				if e := c.apply(plan{Hash: digest(syncBase), Candidate: b, Action: "test-web"}); e != nil {
					t.Fatal(e)
				}
				if w := syncPost(c, syncBase, a); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			case "conflict":
				os.WriteFile(path, changeSyncUser(syncBase, "a", "other"), 0600)
				before, _ := os.ReadFile(path)
				if w := syncPost(c, syncBase, a); w.Code != 409 {
					t.Fatal("accepted stale edit")
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(before, after) {
					t.Fatal("conflict changed disk")
				}
				return
			case "check":
				c.Hooks.Check = func(raw []byte) error {
					if !bytes.Equal(raw, syncBase) {
						return errors.New("bad candidate")
					}
					return nil
				}
				if w := syncPost(c, syncBase, a); w.Code == 200 {
					t.Fatal("bad check accepted")
				}
			case "health":
				c.Hooks.Healthy = func(map[string]any) error {
					if *activated == 1 {
						return errors.New("failed health")
					}
					return nil
				}
				if w := syncPost(c, syncBase, a); w.Code == 200 {
					t.Fatal("failed health accepted")
				}
				if *activated != 2 {
					t.Fatal("did not activate rollback")
				}
			case "noop":
				if w := syncPost(c, syncBase, syncBase); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				if *activated != 0 {
					t.Fatal("formatting-only restart")
				}
			}
			after, _ := os.ReadFile(path)
			if scenario == "bot-then-web" || scenario == "web-then-bot" {
				expected := changeSyncUser(b, "a", "relay")
				if !reflect.DeepEqual(canonicalJSON(after), canonicalJSON(expected)) {
					t.Fatal("bidirectional update lost")
				}
			} else if !bytes.Equal(after, syncBase) {
				t.Fatal("failure/noop did not keep exact original")
			}
			if _, e := os.Stat(filepath.Join(c.Config.State, "transaction.json")); !os.IsNotExist(e) {
				t.Fatal("unresolved transaction")
			}
		})
	}
}
func TestSharedRootEndpointRejectsWebPeer(t *testing.T) {
	c, _, _ := newSyncController(t)
	c.Hooks = nil
	w := syncPost(c, syncBase, changeSyncUser(syncBase, "a", "relay"))
	if w.Code != 403 {
		t.Fatal("unprivileged peer may use Bot endpoint", w.Code)
	}
}

func TestSharedHAProxyAndSingBoxRollbackTogether(t *testing.T) {
	c, path, _ := newSyncController(t)
	hap := filepath.Join(c.Config.State, "haproxy.cfg")
	old := []byte("frontend tls\n    acl reality req.ssl_sni -i old.example\n    acl web req.ssl_sni -i web.example\n")
	os.WriteFile(hap, old, 0600)
	c.Hooks.HapPath = hap
	c.Hooks.HapCheck = func([]byte) error { return nil }
	reloads := 0
	c.Hooks.HapReload = func() error { reloads++; return nil }
	count := 0
	c.Hooks.Activate = func() error {
		count++
		if count == 1 {
			return errors.New("start failure")
		}
		return nil
	}
	desired := changeSyncUser(syncBase, "a", "relay")
	e := c.apply(plan{Hash: digest(syncBase), Candidate: desired, Action: "sbbot", HapSNI: "new.example"})
	if e == nil {
		t.Fatal("failure reported success")
	}
	now, _ := os.ReadFile(hap)
	config, _ := os.ReadFile(path)
	if !bytes.Equal(now, old) || !bytes.Equal(config, syncBase) || reloads != 2 {
		t.Fatal("coordinated rollback failed", reloads)
	}
}
func TestSharedStaleWebEditRetainsOpeningSnapshot(t *testing.T) {
	c, path, _ := newSyncController(t)
	base := []byte(`{"inbounds":[{"tag":"a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}],"route":{"rules":[]}}`)
	os.WriteFile(path, base, 0600)
	post := func(route string, body map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", route, bytes.NewReader(canonical(body)))
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		return w
	}
	w := post("/status", map[string]string{"tag": "a"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var status map[string]any
	json.Unmarshal(w.Body.Bytes(), &status)
	hash, _ := status["edit_version"].(string)
	if hash != digest(base) {
		t.Fatal("missing edit version")
	}
	current := candidateMap(base)
	current["peer-extension"] = "keep"
	os.WriteFile(path, canonical(current), 0600)
	w = post("/preview", map[string]string{"tag": "a", "outbound": "direct", "hash": hash})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var preview map[string]any
	json.Unmarshal(w.Body.Bytes(), &preview)
	token, _ := preview["plan"].(string)
	w = post("/apply", map[string]string{"tag": "a", "plan": token})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	now, _ := os.ReadFile(path)
	if text(candidateMap(now)["peer-extension"]) != "keep" {
		t.Fatal("opening snapshot overwrote peer edit")
	}
	w = post("/preview", map[string]string{"tag": "a", "outbound": "direct", "hash": "expired"})
	if w.Code != 409 {
		t.Fatal("expired opening version accepted")
	}
}

func TestSharedPersistedSnapshotNumericCompatibility(t *testing.T) {
	c, path, _ := newSyncController(t)
	raw, id := deletionFixture(t)
	os.WriteFile(path, raw, 0600)
	out := map[string]any{"type": "socks", "tag": managedTag(identityKey("shared", id)), "server": "1.1.1.1", "server_port": 1080}
	changed, s, e := ChangeIdentity(raw, "shared", id, out, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(raw), Candidate: changed, Tag: "shared", AuthID: id, Snapshot: s}); e != nil {
		t.Fatal(e)
	}
	journals, e := c.journals()
	if e != nil {
		t.Fatal(e)
	}
	now, _ := os.ReadFile(path)
	if _, e = DeleteInbound(now, "shared", id, journals); e != nil {
		t.Fatal("persisted snapshot falsely conflicts", e)
	}
}
