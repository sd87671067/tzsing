package store

import "tzsingbox/internal/auth"

type Outbound struct {
	ID     string `json:"id"`
	Server string `json:"-"`
	Tag    string `json:"-"`
	Name   string `json:"name"`
	Owner  int64  `json:"owner"`
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
