package store

import "tzsingbox/internal/auth"

type Outbound struct {
	ID     string `json:"id"`
	Server string `json:"-"`
	Tag    string `json:"-"`
	Name   string `json:"name"`
	Owner  int64  `json:"owner"`
}
type UUIDPermission struct {
	User      int64    `json:"user_id"`
	Node      string   `json:"node_id"`
	Change    bool     `json:"change"`
	Add       bool     `json:"add"`
	Edit      bool     `json:"edit"`
	Delete    bool     `json:"delete"`
	Outbounds []string `json:"outbounds"`
}

func (s *Store) RegisterOutbound(server, tag, name string, owner int64) (Outbound, error) {
	_, e := s.Exec("INSERT OR IGNORE INTO outbound_registry(id,server,tag,name,owner) VALUES(?,?,?,?,?)", auth.Random(), server, tag, name, owner)
	if e != nil {
		return Outbound{}, e
	}
	return s.OutboundByTag(server, tag)
}
func (s *Store) OutboundByTag(server, tag string) (o Outbound, e error) {
	e = s.QueryRow("SELECT id,server,tag,name,owner FROM outbound_registry WHERE server=? AND tag=?", server, tag).Scan(&o.ID, &o.Server, &o.Tag, &o.Name, &o.Owner)
	return
}
func (s *Store) Outbound(id string) (o Outbound, e error) {
	e = s.QueryRow("SELECT id,server,tag,name,owner FROM outbound_registry WHERE id=?", id).Scan(&o.ID, &o.Server, &o.Tag, &o.Name, &o.Owner)
	return
}
func (s *Store) UUIDPermission(user int64, node string) UUIDPermission {
	p := UUIDPermission{User: user, Node: node, Outbounds: []string{}}
	s.QueryRow("SELECT can_change,can_add,can_edit,can_delete FROM uuid_permissions WHERE user_id=? AND node_id=?", user, node).Scan(&p.Change, &p.Add, &p.Edit, &p.Delete)
	rows, e := s.Query("SELECT outbound_id FROM uuid_outbound_grants WHERE user_id=? AND node_id=?", user, node)
	if e == nil {
		defer rows.Close()
		for rows.Next() {
			var id string
			rows.Scan(&id)
			p.Outbounds = append(p.Outbounds, id)
		}
	}
	return p
}
func (s *Store) CanBind(u User, node, id string) bool {
	if u.Disabled {
		return false
	}
	server, _, e := s.Resolve(u, node)
	if e != nil {
		return false
	}
	o, e := s.Outbound(id)
	if e != nil || o.Server != server {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	p := s.UUIDPermission(u.ID, node)
	if !p.Change {
		return false
	}
	// A personal outbound is still scoped to each UUID's explicit grant.
	for _, v := range p.Outbounds {
		if v == id {
			return true
		}
	}
	return false
}
