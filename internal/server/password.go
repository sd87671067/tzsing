package server

import (
	"net/http"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/store"
)

// The shared request cap and hash semaphore bound cost, not password length.
func (a *App) changePassword(w http.ResponseWriter, r *http.Request, u store.User) {
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	var v struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !read(w, r, &v) {
		return
	}
	if !auth.ValidPassword(v.Current) || !auth.ValidPassword(v.Password) {
		fail(w, 400)
		return
	}
	if !a.rate("password:"+u.Name, 8) {
		fail(w, 429)
		return
	}
	select {
	case a.hashSem <- struct{}{}:
		defer func() { <-a.hashSem }()
	default:
		fail(w, 429)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fresh, err := a.DB.User(u.ID)
	if err != nil || fresh.Disabled || !auth.Check(fresh.Hash, v.Current) {
		fail(w, 403)
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		fail(w, 500)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE users SET hash=? WHERE id=?", auth.Hash(v.Password), u.ID)
	if err == nil {
		_, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", u.ID)
	}
	if err == nil {
		_, err = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "password_change")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500)
		return
	}
	a.disconnect(u.ID)
	reply(w, 200, map[string]bool{"ok": true})
}
