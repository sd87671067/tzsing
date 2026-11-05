package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

func TestApplyDurableReceiptLostResponseReplayAndRollback(t *testing.T) {
	for _, kind := range []string{"outbound", "route"} {
		for _, outcome := range []string{"success", "rollback", "uncertain", "validation"} {
			t.Run(kind+"/"+outcome, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "config.json")
				base := uuidFixture()
				os.WriteFile(path, base, 0600)
				active := 0
				badCheck := false
				c := &Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &ApplyHooks{Check: func([]byte) error {
					if badCheck {
						return errors.New("validation rejected")
					}
					return nil
				}, Probe: func(map[string]any) error { return nil }, Activate: func() error {
					active++
					if outcome == "uncertain" {
						return errors.New("activation failed")
					}
					return nil
				}, Healthy: func(map[string]any) error {
					if outcome == "rollback" && active == 1 {
						return errors.New("candidate unhealthy")
					}
					return nil
				}}}
				call := func(path string, body any) *httptest.ResponseRecorder {
					b, _ := json.Marshal(body)
					w := httptest.NewRecorder()
					c.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(b)))
					return w
				}
				preview, apply := "/outbound-preview", "/outbound-apply"
				body := map[string]any{"action": "save", "outbound_node": OutboundNodeRequest{CreateTag: "custom-new", Config: map[string]any{"type": "direct"}}}
				authID := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
				if kind == "route" {
					preview, apply = "/preview", "/apply"
					body = map[string]any{"tag": "shared", "auth_id": authID, "outbound": "relay"}
				}
				w := call(preview, body)
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
				v := candidateMap(w.Body.Bytes())
				token := v["plan"].(string)
				request := map[string]string{"plan": token}
				if kind == "route" {
					request["tag"] = "shared"
					request["auth_id"] = authID
				}
				badCheck = outcome == "validation"
				call(apply, request) // Deliberately lose the HTTP response after application.
				c = &Controller{Config: c.Config, Hooks: c.Hooks}
				beforeReplay := active
				for i := 0; i < 3; i++ {
					w = call(apply, request)
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body.String())
					}
				}
				w = call("/apply-result", map[string]string{"plan": token})
				v = candidateMap(w.Body.Bytes())
				want := "failed"
				if outcome == "success" {
					want = "succeeded"
				}
				if outcome == "uncertain" {
					want = "uncertain"
				}
				if v["state"] != want || active != beforeReplay {
					t.Fatal(v, active, beforeReplay)
				}
				got, _ := os.ReadFile(path)
				if (outcome == "rollback" || outcome == "validation") && !bytes.Equal(got, base) {
					t.Fatal("rollback lost original bytes")
				}
				if want != "succeeded" && v["error"] == "" {
					t.Fatal("real failure reason missing")
				}
			})
		}
	}
}
func TestApplyStatusIndependentOfMutationLock(t *testing.T) {
	c := &Controller{Config: ServiceConfig{State: t.TempDir()}}
	c.saveApplyResult(auth.Digest("token"), applyResult{State: "running"})
	c.mu.Lock()
	defer c.mu.Unlock()
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/apply-result", bytes.NewBufferString(`{"plan":"token"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e := c.recoverApplyResults(); e != nil {
		t.Fatal(e)
	}
	v, _ := c.loadApplyResult(auth.Digest("token"))
	if v.State != "failed" {
		t.Fatal(v)
	}
}
func TestCustomOutboundTagAndUUIDAuthName(t *testing.T) {
	base := uuidFixture()
	for _, tag := range []string{"direct", "shared", "bad tag", "bad\nname"} {
		if _, _, e := outboundCandidate(base, OutboundNodeRequest{CreateTag: tag, Config: map[string]any{"type": "direct"}}, "save"); e == nil {
			t.Fatal("conflict accepted", tag)
		}
	}
	raw, out, e := outboundCandidate(base, OutboundNodeRequest{CreateTag: "custom.direct-01", Config: map[string]any{"type": "direct"}}, "save")
	if e != nil || text(out["tag"]) != "custom.direct-01" {
		t.Fatal(e, out)
	}
	if _, _, e = outboundCandidate(raw, OutboundNodeRequest{CreateTag: "custom.direct-01", Config: map[string]any{"type": "direct"}}, "save"); e == nil {
		t.Fatal("overwrote duplicate")
	}
	for _, name := range []string{"existing", "bad\nname", " "} {
		if _, _, e = UUIDCandidate(base, UUIDNodeRequest{Inbound: "shared", Name: "display", AuthName: name, Enabled: true}); e == nil {
			t.Fatal("invalid NAME accepted", name)
		}
	}
	raw, _, e = UUIDCandidate(base, UUIDNodeRequest{Inbound: "shared", Name: "display alias", AuthName: "authentication name", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	in := findInbound(candidateMap(raw), "shared")
	old := findInbound(candidateMap(base), "shared")
	if in["name"] != nil || in["tag"] != old["tag"] || string(canonical(in["tls"])) != string(canonical(old["tls"])) || in["listen_port"] != old["listen_port"] {
		t.Fatal("listener changed")
	}
	users := array(in["users"])
	if text(object(users[1])["name"]) != "authentication name" || string(canonical(users[0])) != string(canonical(array(old["users"])[0])) {
		t.Fatal("identity name changed")
	}
}
