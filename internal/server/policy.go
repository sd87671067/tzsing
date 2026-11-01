package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
	"tzsingbox/policy"
)

type policyCache struct {
	at    time.Time
	items map[string]policy.State
}

// Called with App.mu; cached once per report tick, independent of viewer count.
func (a *App) overlayPolicies(u store.User, views []model.View) {
	if a.ControlSocket == "" {
		return
	}
	if time.Since(a.policyCache.at) > time.Second {
		a.policyCache.at = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		out, status := a.hostControl(ctx, "policy-status", map[string]string{})
		a.policyCache.items = nil
		if status == 200 {
			b, _ := json.Marshal(out["items"])
			json.Unmarshal(b, &a.policyCache.items)
		}
	}
	for i := range views {
		v := &views[i]
		if v.ID != a.ControlServer || v.Report == nil {
			continue
		}
		for j := range v.Report.Tags {
			t := &v.Report.Tags[j]
			_, raw, e := a.DB.Resolve(u, t.ID)
			if e != nil {
				continue
			}
			s, ok := a.policyCache.items[raw]
			if !ok {
				continue
			}
			t.PolicyState = s.Status
			t.ShowExpiry = u.Role == "admin" || a.DB.Setting("show_expiry", 0) == 1
			t.ShowQuota = u.Role == "admin" || a.DB.Setting("show_quota", 1) == 1
			if t.ShowExpiry {
				t.ExpiresAt = s.ExpiresAt
				t.Timezone = s.Timezone
			} else {
				t.ExpiresAt = 0
			}
			if t.ShowQuota {
				t.Quota = s.Quota
				t.BillingDay = s.BillingDay
				t.Timezone = s.Timezone
				t.PeriodStart = s.Start
				t.MeteringSince = s.Since
				if s.Since > 0 {
					used := s.Used
					t.BillableUsed = &used
				}
			} else {
				t.Quota = 0
				t.BillableUsed = nil
				t.MeteringSince = 0
				t.PeriodStart = 0
				t.BillingDay = 0
			}
		}
	}
}
func (a *App) nodePolicy(w http.ResponseWriter, r *http.Request, u store.User) {
	if u.Role != "admin" || !a.controlPermission(u, "change") {
		fail(w, 403)
		return
	}
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	var v struct {
		ID     string        `json:"node_id"`
		Action string        `json:"action"`
		Policy *policy.Limit `json:"policy,omitempty"`
		Nonce  string        `json:"nonce,omitempty"`
	}
	if !read(w, r, &v) {
		return
	}
	if v.Action != "preview" && v.Action != "apply" {
		fail(w, 400)
		return
	}
	server, raw, e := a.DB.Resolve(u, v.ID)
	if e != nil || server != a.ControlServer || !strings.HasPrefix(raw, "identity:") {
		fail(w, 403)
		return
	}
	t, ok := a.currentInbound(store.User{Role: "admin"}, v.ID)
	if !ok || t.AuthID == "" {
		fail(w, 403)
		return
	}
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	payload := map[string]any{"tag": t.InboundTag, "auth_id": t.AuthID, "policy": v.Policy}
	if v.Action == "apply" {
		a.mu.Lock()
		n, exists := a.controlNonces[auth.Digest(v.Nonce)]
		delete(a.controlNonces, auth.Digest(v.Nonce))
		a.mu.Unlock()
		if !exists || n.Action != "policy" || n.Node != v.ID || n.User != u.ID || n.Session != auth.Digest(cookie.Value) || time.Now().After(n.Expires) {
			fail(w, 409)
			return
		}
		payload["plan"] = n.Plan
	}
	out, status := a.hostControl(r.Context(), "policy-"+v.Action, payload)
	if status == 200 && v.Action == "preview" {
		plan, _ := out["plan"].(string)
		delete(out, "plan")
		if plan == "" {
			fail(w, 502)
			return
		}
		token := auth.Random()
		a.mu.Lock()
		if a.controlNonces == nil {
			a.controlNonces = map[string]controlNonce{}
		}
		for k, n := range a.controlNonces {
			if time.Now().After(n.Expires) {
				delete(a.controlNonces, k)
			}
		}
		if len(a.controlNonces) >= 1024 {
			a.mu.Unlock()
			fail(w, 429)
			return
		}
		a.controlNonces[auth.Digest(token)] = controlNonce{User: u.ID, Session: auth.Digest(cookie.Value), Node: v.ID, Plan: plan, Action: "policy", Expires: time.Now().Add(2 * time.Minute)}
		a.mu.Unlock()
		out["nonce"] = token
	}
	if status == 200 && v.Action == "apply" {
		a.mu.Lock()
		a.policyCache.at = time.Time{}
		a.mu.Unlock()
	}
	reply(w, status, out)
}
