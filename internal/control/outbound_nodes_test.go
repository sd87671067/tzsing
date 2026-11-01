package control

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"tzsingbox/internal/model"
)

func TestExistingOutboundBindingSharedByUUIDsAndRestored(t *testing.T) {
	raw := uuidFixture()
	var e error
	raw, _, e = UUIDCandidate(raw, UUIDNodeRequest{Inbound: "shared", Name: "second", UUID: "22222222-2222-4222-8222-222222222222", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	original := raw
	config := candidateMap(raw)
	out := findOutbound(config, "relay")
	u := array(findInbound(config, "shared")["users"])
	snapshots := []Snapshot{}
	ids := []string{}
	for _, v := range u {
		user := object(v)
		id := identityDigest(user)
		ids = append(ids, id)
		var s Snapshot
		before := candidateMap(raw)
		raw, s, e = changeIdentity(raw, "shared", id, out, nil, true)
		if e != nil {
			t.Fatal(e)
		}
		for i := range snapshots {
			if snapshots[i].BaselineHash == snapshotBaseline(before, snapshots[i]) {
				snapshots[i].BaselineHash = snapshotBaseline(candidateMap(raw), snapshots[i])
			}
		}
		snapshots = append(snapshots, s)
	}
	c := candidateMap(raw)
	if len(array(c["outbounds"])) != 2 {
		t.Fatal("outbound cloned")
	}
	if len(outboundRefs(c, "relay")) < 2 {
		t.Fatal("bindings missing")
	}
	if _, _, e = outboundCandidate(raw, OutboundNodeRequest{Tag: "relay"}, "delete"); e == nil {
		t.Fatal("referenced outbound deleted")
	}
	for i := len(ids) - 1; i >= 0; i-- {
		before := candidateMap(raw)
		raw, e = RestoreIdentity(raw, "shared", ids[i], snapshots[i])
		if e != nil {
			t.Fatal(e)
		}
		for j := 0; j < i; j++ {
			if snapshots[j].BaselineHash == snapshotBaseline(before, snapshots[j]) {
				snapshots[j].BaselineHash = snapshotBaseline(candidateMap(raw), snapshots[j])
			}
		}
	}
	if !reflect.DeepEqual(canonicalJSON(original), canonicalJSON(raw)) {
		t.Fatal("restore altered original")
	}
}
func identityDigest(u map[string]any) string { return model.UUIDAuthID(text(u["uuid"])) }

func TestOutboundTransactionProbeRollbackAndReplay(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	original := uuidFixture()
	os.WriteFile(config, original, 0600)
	activated := 0
	broken := false
	c := &Controller{Config: ServiceConfig{State: dir, Config: config, WriteEnabled: true}, Hooks: &ApplyHooks{Check: func([]byte) error { return nil }, Probe: func(map[string]any) error {
		if broken {
			return errors.New("proxy authentication rejected")
		}
		return nil
	}, Activate: func() error { activated++; return nil }, Healthy: func(map[string]any) error {
		if activated == 1 {
			return errors.New("candidate unhealthy")
		}
		return nil
	}}}
	request := func(path string, v any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(canonical(v))))
		return w
	}
	v := map[string]any{"action": "save", "outbound_node": map[string]any{"config": map[string]any{"type": "direct"}}}
	broken = true
	if w := request("/outbound-preview", v); w.Code != 422 {
		t.Fatal("probe failure accepted", w.Code)
	}
	broken = false
	w := request("/outbound-preview", v)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	p := candidateMap(w.Body.Bytes())
	w = request("/outbound-apply", map[string]any{"plan": p["plan"]})
	if w.Code != 409 {
		t.Fatal("failed health not rolled back", w.Code)
	}
	got, _ := os.ReadFile(config)
	if !bytes.Equal(got, original) || activated != 2 {
		t.Fatal("rollback failed")
	}
	if w = request("/outbound-apply", map[string]any{"plan": p["plan"]}); w.Code != 409 {
		t.Fatal("replayed plan accepted")
	}
}
func TestProxyBareSpecialCharactersAndIPv6(t *testing.T) {
	for _, raw := range []string{"u:p@ss:#%word@[2001:db8::1]:8080", "http://u:p%40ss%3A%23%25word@[2001:db8::1]:8080"} {
		l, e := Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		o, e := l.Outbound("test")
		if e != nil || o["type"] != "http" || o["username"] != "u" || o["password"] != "p@ss:#%word" || o["server"] != "2001:db8::1" {
			t.Fatal("proxy authentication or IPv6 changed")
		}
	}
}

func TestBareProxyPasswordWhitespaceIsEncodedOnce(t *testing.T) {
	l, e := Parse("user:pass word@proxy.example.org:8080")
	if e != nil {
		t.Fatal(e)
	}
	o, e := l.Outbound("test")
	if e != nil || o["password"] != "pass word" {
		t.Fatal("bare password changed")
	}
}

func TestNodeStateRemainsVisibleWithoutQuotaExecutor(t *testing.T) {
	dir := t.TempDir()
	raw := uuidFixture()
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	raw, e := IdentityMutation(raw, "shared", id, "disable")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, raw, 0600)
	c := &Controller{Config: ServiceConfig{State: dir, Config: path, WriteEnabled: true}, Hooks: &ApplyHooks{}}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/policy-status", bytes.NewReader([]byte(`{}`))))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	out := candidateMap(w.Body.Bytes())
	state := object(object(out["items"])[model.IdentityName("shared", id)])
	if out["ready"] != false || state["status"] != "disabled" {
		t.Fatal("configuration state lost or executor claimed", out)
	}
	w = httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/policy-preview", bytes.NewReader(canonical(map[string]any{"tag": "shared", "auth_id": id, "policy": map[string]any{"quota": 1}}))))
	if w.Code != 503 {
		t.Fatal("quota saved without executor", w.Code)
	}
}
