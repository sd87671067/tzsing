package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

// Persist before dispatch. A lost HTTP response can only resume this intent.
func (a *App) startUUIDOperation(id string) {
	a.mu.Lock()
	if a.uuidJobs == nil {
		a.uuidJobs = map[string]bool{}
	}
	if a.uuidJobs[id] {
		a.mu.Unlock()
		return
	}
	a.uuidJobs[id] = true
	a.mu.Unlock()
	go func() {
		defer func() { a.mu.Lock(); delete(a.uuidJobs, id); a.mu.Unlock() }()
		var plan, state string
		if a.DB.QueryRow("SELECT plan,state FROM uuid_operations WHERE id=?", id).Scan(&plan, &state) != nil || state != "pending" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 175*time.Second)
		defer cancel()
		out, status := a.hostControl(ctx, "uuid-apply", map[string]string{"plan": plan})
		// Transport failure is not evidence that a mutation failed.
		if status == 200 {
			a.finishUUIDOperation(id, out)
		} else {
			queryCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			receipt, code := a.hostControl(queryCtx, "uuid-result", map[string]string{"plan": plan})
			if code == 200 {
				a.finishUUIDOperation(id, receipt)
			} else if code == 404 && (status == 409 || status == 422) {
				a.finishUUIDOperation(id, map[string]any{"state": "failed", "error": out["error"]})
			}
		}
	}()
}
func (a *App) finishUUIDOperation(id string, out map[string]any) error {
	state, _ := out["state"].(string)
	if state != "succeeded" && state != "failed" && state != "uncertain" {
		return nil
	}
	data, e := json.Marshal(out)
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var server, tag, name string
	if e = tx.QueryRow("SELECT server,tag,name FROM uuid_operations WHERE id=?", id).Scan(&server, &tag, &name); e != nil {
		return e
	}
	// The identity and name were bound by preview, never by mutable Agent names.
	if state == "succeeded" {
		inbound, _ := out["inbound"].(string)
		identity, _ := out["auth_id"].(string)
		if !model.ValidAuthID(identity) || model.IdentityName(inbound, identity) != tag {
			return errors.New("controller identity mismatch")
		}
		if _, e = tx.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=CASE WHEN nodes.name='' THEN excluded.name ELSE nodes.name END", auth.Random(), server, tag, name); e != nil {
			return e
		}
	}
	changed, e := tx.Exec("UPDATE uuid_operations SET state=?,result=? WHERE id=? AND state='pending'", state, data, id)
	if e != nil {
		return e
	}
	count, e := changed.RowsAffected()
	if e != nil {
		return e
	}
	if count > 0 {
		if _, e = tx.Exec("INSERT INTO audit(at,name,ip,event) SELECT ?,u.name,'local',? FROM users u JOIN uuid_operations o ON o.user_id=u.id WHERE o.id=?", time.Now().Unix(), "uuid_create_"+state+":"+id, id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (a *App) uuidOperationStatus(w http.ResponseWriter, r *http.Request, u store.User) {
	id := auth.Digest(r.URL.Query().Get("id"))
	var owner int64
	var plan, state string
	var data []byte
	err := a.DB.QueryRow("SELECT user_id,plan,state,result FROM uuid_operations WHERE id=? AND server=?", id, a.ControlServer).Scan(&owner, &plan, &state, &data)
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
	if state == "pending" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, status := a.hostControl(ctx, "uuid-result", map[string]string{"plan": plan})
		if status == 200 {
			if err = a.finishUUIDOperation(id, out); err != nil {
				fail(w, 500)
				return
			}
		} else if status == 404 {
			a.startUUIDOperation(id)
		}
		if err = a.DB.QueryRow("SELECT state,result FROM uuid_operations WHERE id=?", id).Scan(&state, &data); err != nil {
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
