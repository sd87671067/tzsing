package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"tzsingbox/policy"
)

// Exercise the HTTP plan/commit boundary against the same durable ledger read
// by the executor, with fourteen exact UUID/name registrations.
func TestPolicyEditsHTTPPersistenceAndIdentityBoundary(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "config.json")
	dbpath := filepath.Join(d, "policy.db")
	users := []any{}
	l, e := policy.Open(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if e = l.Heartbeat(); e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for i := 0; i < 14; i++ {
		id := fmt.Sprintf("%08x-1111-4111-8111-%012x", i+1, i+1)
		name := fmt.Sprintf("user-%d", i)
		ids = append(ids, policy.UUIDKey(id))
		users = append(users, map[string]any{"name": name, "uuid": id})
		if e = l.RegisterIdentity("shared", ids[i], name); e != nil {
			t.Fatal(e)
		}
	}
	if e = l.MarkInboundStarted("shared"); e != nil {
		t.Fatal(e)
	}
	config := map[string]any{"inbounds": []any{map[string]any{"tag": "shared", "type": "vless", "listen_port": 443, "users": users, "tls": map[string]any{"enabled": true, "reality": map[string]any{"enabled": true}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
	raw := canonical(config)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	c := &Controller{Config: ServiceConfig{Config: path, State: d, PolicyDB: dbpath, WriteEnabled: true}, Hooks: &ApplyHooks{}}
	call := func(route string, v map[string]any) (map[string]any, int) {
		t.Helper()
		b, _ := json.Marshal(v)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", route, bytes.NewReader(b)))
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out, w.Code
	}
	cases := []policy.Limit{{ExpiresAt: 2000000001}, {Quota: 107374182}, {Quota: 2 << 30, ExpiresAt: 2000000002}, {Quota: 2 << 30}, {}}
	for _, v := range cases {
		if e = l.Heartbeat(); e != nil {
			t.Fatal(e)
		}
		payload := map[string]any{"tag": "shared", "auth_id": ids[0], "policy": v}
		p, status := call("/policy-preview", payload)
		if status != 200 {
			t.Fatal("preview", status, p)
		}
		before, _ := l.State("shared", ids[0])
		payload["plan"] = p["plan"]
		delete(payload, "policy")
		out, status := call("/policy-apply", payload)
		if status != 200 {
			t.Fatal("apply", status, out, before)
		}
		if _, status = call("/policy-apply", payload); status != 409 {
			t.Fatal("plan reused", status)
		}
		reader, e := policy.Open(dbpath)
		if e != nil {
			t.Fatal(e)
		}
		state, e := reader.State("shared", ids[0])
		reader.Close()
		want, _ := policy.Normalize(v)
		if e != nil || state.Limit != want {
			t.Fatal("persisted policy mismatch", state, e, want)
		}
		for _, id := range ids[1:] {
			s, e := l.State("shared", id)
			if e != nil || s.Quota != 0 || s.ExpiresAt != 0 || s.Used != 0 {
				t.Fatal("peer changed", s, e)
			}
		}
	}
	// A stale/mismatched registration must still fail closed.
	if e = l.RegisterIdentity("shared", ids[0], "wrong-name"); e != nil {
		t.Fatal(e)
	}
	if _, status := call("/policy-preview", map[string]any{"tag": "shared", "auth_id": ids[0], "policy": cases[0]}); status != 503 {
		t.Fatal("capability bypass", status)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("policy edit changed shared configuration")
	}
}
