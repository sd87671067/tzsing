package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func uuidFixture() []byte {
	return canonical(map[string]any{"inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": 443, "users": []any{map[string]any{"name": "existing", "uuid": "11111111-1111-4111-8111-111111111111"}}, "tls": map[string]any{"enabled": true, "server_name": "example.com", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "handshake": map[string]any{"server": "example.com", "server_port": 443}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "socks", "tag": "relay", "server": "192.0.2.1", "server_port": 1080}}, "route": map[string]any{"rules": []any{map[string]any{"ip_cidr": []string{"192.0.2.0/24"}, "action": "reject"}}, "final": "direct"}})
}
func TestUUIDCandidateOneListenerAndSecurityPolicies(t *testing.T) {
	original := uuidFixture()
	raw := original
	for i := 0; i < 11; i++ {
		var e error
		raw, _, e = UUIDCandidate(raw, UUIDNodeRequest{Inbound: "shared", Name: "测试节点", Outbound: "relay", Enabled: true})
		if e != nil {
			t.Fatal(e)
		}
	}
	config := candidateMap(raw)
	in := findInbound(config, "shared")
	if len(array(config["inbounds"])) != 1 || len(array(in["users"])) != 12 || in["listen_port"] != float64(443) {
		t.Fatal("shared listener changed")
	}
	old := findInbound(candidateMap(original), "shared")
	if !reflect.DeepEqual(old["tls"], in["tls"]) || !reflect.DeepEqual(array(old["users"])[0], array(in["users"])[0]) {
		t.Fatal("old credentials or shared handshake changed")
	}
	rules := array(object(config["route"])["rules"])
	if text(object(rules[0])["action"]) != "reject" {
		t.Fatal("reject lost priority")
	}
	for _, v := range rules[1:] {
		r := object(v)
		if len(array(r["inbound"])) != 1 || len(array(r["auth_user"])) != 1 {
			t.Fatal("route not per UUID")
		}
	}
	req := UUIDNodeRequest{Inbound: "shared", Name: "测试", Enabled: true, UUID: "11111111-1111-4111-8111-111111111111"}
	if _, _, e := UUIDCandidate(original, req); e == nil {
		t.Fatal("duplicate UUID accepted")
	}
	req.UUID = "123"
	if _, _, e := UUIDCandidate(original, req); e == nil {
		t.Fatal("bad UUID accepted")
	}
	for _, req := range []UUIDNodeRequest{{Inbound: "shared", Name: "x", Enabled: true, UploadLimit: 1}, {Inbound: "shared", Name: "x", Enabled: true, DownloadLimit: 1}, {Inbound: "shared", Name: "x", Quota: -1}, {Inbound: "shared", Name: "x", ExpiresAt: -1}} {
		if _, _, e := UUIDCandidate(original, req); e == nil {
			t.Fatal("invalid or unsupported policy accepted")
		}
	}
	for _, req := range []UUIDNodeRequest{{Inbound: "shared", Name: "x", Enabled: true, Quota: 1024}, {Inbound: "shared", Name: "x", Enabled: true, ExpiresAt: 1}} {
		if _, _, e := UUIDCandidate(original, req); e != nil {
			t.Fatal("supported policy rejected", e)
		}
	}

	config = candidateMap(original)
	object(config["route"])["rules"] = append(array(object(config["route"])["rules"]), map[string]any{"inbound": []string{"shared"}, "outbound": "direct"})
	if _, _, e := UUIDCandidate(canonical(config), UUIDNodeRequest{Inbound: "shared", Name: "x", Enabled: true, Outbound: "relay"}); e == nil {
		t.Fatal("overrode existing routing priority")
	}
}
func TestUUIDPreviewIsReadOnlyEvenWithWriteEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := uuidFixture()
	os.WriteFile(path, raw, 0600)
	checks := 0
	c := Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &ApplyHooks{Check: func([]byte) error { checks++; return nil }, Activate: func() error { t.Fatal("activation attempted"); return nil }}}
	body, _ := json.Marshal(map[string]any{"node": UUIDNodeRequest{Inbound: "shared", Name: "候选", Enabled: true}})
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/uuid-preview", bytes.NewReader(body)))
	if w.Code != 200 || checks != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("config changed")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("uuid\"")) {
		t.Fatal("candidate credential returned")
	}
}

func TestUUIDCapabilitiesNeverClaimSavedOrEffective(t *testing.T) {
	caps := UUIDCatalog(uuidFixture())["capabilities"].(map[string]any)
	for _, key := range []string{"quota", "upload_limit", "download_limit", "expires_at", "enabled", "outbound"} {
		c, ok := caps[key].(map[string]any)
		if !ok || c["saved"] != false || c["effective"] != false || c["reason"] == "" || (c["state"] != "unsupported" && c["state"] != "disabled") {
			t.Fatalf("false execution capability: %s", key)
		}
	}
}
