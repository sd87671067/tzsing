package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tzsingbox/internal/model"
)

func TestIdentityShareBoundaryAndSharedListenerPreserved(t *testing.T) {
	alice := map[string]any{"name": "alice", "uuid": "11111111-1111-4111-8111-111111111111"}
	bob := map[string]any{"name": "bob", "uuid": "22222222-2222-4222-8222-222222222222"}
	in := map[string]any{"tag": "shared", "type": "vless", "listen_port": 443, "users": []any{alice, bob}, "tls": map[string]any{"enabled": true, "server_name": "example.com", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}}}
	raw := canonical(map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ep := Endpoint{Host: "example.org", Port: 443, Verified: true}
	c := &Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true, Endpoints: map[string]Endpoint{"shared": ep}}}
	call := func(route string, body map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", route, bytes.NewReader(b)))
		return w
	}
	body := map[string]string{"tag": "shared", "auth_id": model.AuthID("alice")}
	w := call("/status", body)
	var status struct {
		Apply, Restore, Preview bool
		Profiles                []ShareProfile
	}
	json.Unmarshal(w.Body.Bytes(), &status)
	if w.Code != 200 || status.Apply || status.Restore || status.Preview || len(status.Profiles) != 1 || status.Profiles[0].ID != profileID(text(alice["uuid"])) {
		t.Fatal("identity status boundary", w.Code)
	}
	body["profile"] = profileID(text(bob["uuid"]))
	if w = call("/share", body); w.Code != 422 || strings.Contains(w.Body.String(), text(bob["uuid"])) {
		t.Fatal("cross identity share")
	}
	body["profile"] = status.Profiles[0].ID
	w = call("/share", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), text(alice["uuid"])) || strings.Contains(w.Body.String(), text(bob["uuid"])) {
		t.Fatal("wrong profile shared")
	}
	for _, route := range []string{"/preview", "/restore-preview", "/apply", "/diagnostics", "/intel"} {
		if w = call(route, body); w.Code != 403 {
			t.Fatal("identity escalated to inbound", route, w.Code)
		}
	}
	body["auth_id"] = model.AuthID("missing")
	if w = call("/status", body); w.Code != 403 {
		t.Fatal("deleted identity accepted")
	}
	scoped, e := IdentityInbound(in, model.AuthID("alice"))
	if e != nil || len(array(scoped["users"])) != 1 || len(array(in["users"])) != 2 {
		t.Fatal("mutated shared inbound")
	}
	in["users"] = []any{alice, alice}
	if _, e = IdentityInbound(in, model.AuthID("alice")); e == nil {
		t.Fatal("ambiguous identity accepted")
	}
	in["type"] = "shadowsocks"
	if _, e = IdentityInbound(in, model.AuthID("alice")); e == nil {
		t.Fatal("unsupported user format accepted")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, after) {
		t.Fatal("configuration/listener changed")
	}
}
