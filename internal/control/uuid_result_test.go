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
)

func TestUUIDDurableResultDisconnectedReplayAndRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[rollback], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			base := uuidFixture()
			os.WriteFile(path, base, 0600)
			active := 0
			c := &Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &ApplyHooks{Probe: func(map[string]any) error { return nil },
				Check: func([]byte) error { return nil }, Activate: func() error { active++; return nil },
				Healthy: func(map[string]any) error {
					if rollback && active == 1 {
						return errors.New("isolated unhealthy")
					}
					return nil
				},
			}}
			call := func(c *Controller, path string, body any) *httptest.ResponseRecorder {
				b, _ := json.Marshal(body)
				w := httptest.NewRecorder()
				c.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(b)))
				return w
			}
			w := call(c, "/uuid-preview", map[string]any{"node": UUIDNodeRequest{Inbound: "shared", Name: "ck", Enabled: true}})
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var v map[string]any
			json.Unmarshal(w.Body.Bytes(), &v)
			plan := v["plan"].(string)
			// Discard the apply response completely, as when the browser proxy dies.
			call(c, "/uuid-apply", map[string]string{"plan": plan})
			c = &Controller{Config: c.Config, Hooks: c.Hooks} // plans lost; only durable receipt remains
			if e := c.recoverUUIDResults(); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 3; i++ {
				w = call(c, "/uuid-apply", map[string]string{"plan": plan})
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
			}
			w = call(c, "/uuid-result", map[string]string{"plan": plan})
			json.Unmarshal(w.Body.Bytes(), &v)
			want := "succeeded"
			wantActive := 1
			if rollback {
				want = "failed"
				wantActive = 2
			}
			if v["state"] != want || active != wantActive {
				t.Fatal(v, active)
			}
			after, _ := os.ReadFile(path)
			if rollback && !bytes.Equal(after, base) {
				t.Fatal("rollback bytes changed")
			}
			if !rollback && len(array(findInbound(candidateMap(after), "shared")["users"])) != 2 {
				t.Fatal("UUID duplicated")
			}
		})
	}
}
func TestUUIDStatusDoesNotBlockBehindApply(t *testing.T) {
	c := &Controller{Config: ServiceConfig{State: t.TempDir()}}
	key := auth.Digest("confirmation")
	c.saveUUIDResult(key, uuidResult{State: "running"})
	c.mu.Lock()
	defer c.mu.Unlock()
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/uuid-result", bytes.NewBufferString(`{"plan":"confirmation"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if e := c.recoverUUIDResults(); e != nil {
		t.Fatal(e)
	}
	v, e := c.loadUUIDResult(key)
	if e != nil || v.State != "failed" {
		t.Fatal(v, e)
	}
}
