package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/store"
)

// Only opaque controller plan IDs and management metadata are persisted.
func (a *App) replayConfigOperation(w http.ResponseWriter, r *http.Request, u store.User, token, kind, node string) bool {
	var owner int64
	var storedKind, storedNode string
	err := a.DB.QueryRow("SELECT user_id,kind,node FROM config_operations WHERE id=? AND server=?", auth.Digest(token), a.ControlServer).Scan(&owner, &storedKind, &storedNode)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		fail(w, 500)
		return true
	}
	if owner != u.ID || kind != storedKind || node != storedNode {
		fail(w, 403)
		return true
	}
	a.configOperationStatus(w, r, u, token)
	return true
}
func (a *App) saveConfigOperation(token string, u store.User, kind, node, name string, payload map[string]string, cleanup bool) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	_, e = a.DB.Exec("INSERT INTO config_operations(id,user_id,server,kind,node,plan,payload,name,cleanup,created) VALUES(?,?,?,?,?,?,?,?,?,?)", auth.Digest(token), u.ID, a.ControlServer, kind, node, payload["plan"], b, name, cleanup, time.Now().Unix())
	return e
}
func (a *App) runConfigOperation(id string) {
	// Reuse the job guard; no status query queues behind this worker or routeMu.
	job := "config:" + id
	a.mu.Lock()
	if a.uuidJobs == nil {
		a.uuidJobs = map[string]bool{}
	}
	if a.uuidJobs[job] {
		a.mu.Unlock()
		return
	}
	a.uuidJobs[job] = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.uuidJobs, job); a.mu.Unlock() }()
	var kind, state string
	var payload []byte
	if a.DB.QueryRow("SELECT kind,state,payload FROM config_operations WHERE id=?", id).Scan(&kind, &state, &payload) != nil || state != "pending" {
		return
	}
	var v map[string]string
	if json.Unmarshal(payload, &v) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 175*time.Second)
	defer cancel()
	out, status := a.hostControl(ctx, kind, v)
	if status == 200 && out["state"] == nil {
		out["state"] = "succeeded"
	}
	if status != 200 {
		q, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		receipt, code := a.hostControl(q, "apply-result", map[string]string{"plan": v["plan"]})
		if code == 200 {
			out = receipt
		} else if code == 404 && (status == 409 || status == 422) {
			out = map[string]any{"state": "failed", "error": out["error"]}
		} else {
			return
		}
	}
	a.finishConfigOperation(id, out)
}
func (a *App) finishConfigOperation(id string, out map[string]any) error {
	state, _ := out["state"].(string)
	if state != "succeeded" && state != "failed" && state != "uncertain" {
		return nil
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var kind, node, name, old string
	var cleanup bool
	if e = tx.QueryRow("SELECT kind,node,name,cleanup,state FROM config_operations WHERE id=?", id).Scan(&kind, &node, &name, &cleanup, &old); e != nil {
		return e
	}
	if old != "pending" && old != "uncertain" {
		return nil
	}
	if state == "succeeded" {
		if kind == "outbound-apply" {
			tag, _ := out["tag"].(string)
			if out["deleted"] == true {
				_, e = tx.Exec("DELETE FROM nodes WHERE server=? AND tag=?", a.ControlServer, tag)
			} else if tag != "" {
				_, e = tx.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=excluded.name", auth.Random(), a.ControlServer, tag, name)
				if e == nil {
					_, e = tx.Exec("UPDATE outbound_registry SET name=? WHERE server=? AND tag=?", name, a.ControlServer, tag)
				}
			}
		} else if cleanup {
			_, e = tx.Exec("DELETE FROM uuid_bindings WHERE node_id=?", node)
		}
		if e != nil {
			return e
		}
	}
	b, e := json.Marshal(out)
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE config_operations SET state=?,result=? WHERE id=? AND state IN ('pending','uncertain')", state, b, id); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO audit(at,name,ip,event) SELECT ?,u.name,'local',? FROM users u JOIN config_operations o ON o.user_id=u.id WHERE o.id=?", time.Now().Unix(), "config_"+state+":"+id, id); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *App) configOperationStatus(w http.ResponseWriter, r *http.Request, u store.User, token string) {
	w.Header().Set("Cache-Control", "no-store")
	id := auth.Digest(token)
	var owner int64
	var state, plan string
	var data []byte
	err := a.DB.QueryRow("SELECT user_id,state,plan,result FROM config_operations WHERE id=? AND server=?", id, a.ControlServer).Scan(&owner, &state, &plan, &data)
	if err == sql.ErrNoRows {
		fail(w, 404)
		return
	}
	if err != nil {
		fail(w, 500)
		return
	}
	if owner != u.ID {
		fail(w, 403)
		return
	}
	if state == "pending" || state == "uncertain" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, status := a.hostControl(ctx, "apply-result", map[string]string{"plan": plan})
		if status == 200 {
			if a.finishConfigOperation(id, out) != nil {
				fail(w, 503)
				return
			}
		} else if status == 404 {
			go a.runConfigOperation(id)
		}
		if a.DB.QueryRow("SELECT state,result FROM config_operations WHERE id=?", id).Scan(&state, &data) != nil {
			fail(w, 500)
			return
		}
	}
	out := map[string]any{"state": state}
	if len(data) > 0 {
		json.Unmarshal(data, &out)
	}
	reply(w, 200, out)
}
