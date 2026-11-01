package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyValidationCASFailureAndAutomaticRollback(t *testing.T) {
	raw := []byte(`{"inbounds":[{"tag":"a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct","rules":[]}}`)
	for _, scenario := range []string{"success", "check-failure", "stale", "activate-failure", "health-failure", "post-probe-failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			os.WriteFile(path, raw, 0600)
			candidate, s, e := Change(raw, "a", map[string]any{"type": "socks", "tag": managedTag("a"), "server": "example.com", "server_port": 1080}, nil)
			if e != nil {
				t.Fatal(e)
			}
			activated, probes := 0, 0
			c := &Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{
				Check: func([]byte) error {
					if scenario == "check-failure" {
						return errors.New("invalid fixture")
					}
					return nil
				},
				Activate: func() error {
					activated++
					if scenario == "activate-failure" && activated == 1 {
						return errors.New("fixture start failure")
					}
					return nil
				},
				Healthy: func(map[string]any) error {
					if scenario == "health-failure" && activated == 1 {
						return errors.New("fixture unhealthy")
					}
					return nil
				},
				Probe: func(map[string]any) error {
					probes++
					if scenario == "post-probe-failure" && probes == 2 {
						return errors.New("fixture path failure")
					}
					return nil
				},
			}}
			p := plan{Hash: digest(raw), Tag: "a", Candidate: candidate, Snapshot: s, Expires: time.Now().Add(time.Minute)}
			if scenario == "stale" {
				p.Hash = "other"
			}
			e = c.apply(p)
			after, _ := os.ReadFile(path)
			if scenario == "success" {
				if e != nil || digest(after) != digest(candidate) {
					t.Fatal("apply", e)
				}
				j, _ := c.journals()
				base, e := Restore(after, "a", j["a"])
				if e != nil {
					t.Fatal(e)
				}
				if e = c.apply(plan{Hash: digest(after), Tag: "a", Candidate: base, Restore: true}); e != nil {
					t.Fatal("restore", e)
				}
				after, _ = os.ReadFile(path)
				if string(canonical(canonicalJSON(after))) != string(canonical(canonicalJSON(raw))) {
					t.Fatal("restored guessed config")
				}
			} else {
				if e == nil || digest(after) != digest(raw) {
					t.Fatal("failed operation modified original", e)
				}
				if scenario == "check-failure" || scenario == "stale" {
					if activated != 0 {
						t.Fatal("invalid config activated")
					}
				} else if activated != 2 {
					t.Fatal("failure did not activate rollback", activated)
				}
			}
			if _, e = os.Stat(filepath.Join(dir, "transaction.json")); !os.IsNotExist(e) {
				t.Fatal("transaction not resolved")
			}
		})
	}
}
