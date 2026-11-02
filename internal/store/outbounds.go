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

// OutboundDisplayName reuses nodes.name as the shared display-name mapping.
// The registry's stable ID and ownership remain independent of display names.
func (s *Store) OutboundDisplayName(server, tag string) string {
	var name string
	s.QueryRow("SELECT name FROM nodes WHERE server=? AND tag=?", server, tag).Scan(&name)
	if name == "" {
		s.QueryRow("SELECT name FROM outbound_registry WHERE server=? AND tag=?", server, tag).Scan(&name)
	}
	if name == "" {
		return tag
	}
	return name
}

func (s *Store) SetOutboundDisplayName(server, tag, name string) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=excluded.name", auth.Random(), server, tag, name)
	if err == nil {
		_, err = tx.Exec("UPDATE outbound_registry SET name=? WHERE server=? AND tag=?", name, server, tag)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
