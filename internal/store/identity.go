package store

import (
	"database/sql"
	"fmt"
	"tzsingbox/internal/model"
)

// MigrateUUIDIdentities runs inside the authenticated Agent report transaction.
// Each legacy binding is consumed once, including when no old node exists.
// Later UUID rotations or recycled user names never inherit the old grants.
func MigrateUUIDIdentities(tx *sql.Tx, server string, tags []model.Tag) error {
	seen := map[string]bool{}
	for _, t := range tags {
		if t.AuthScheme != "uuid-v1" || t.LegacyAuthID == "" {
			continue
		}
		if t.Identity != "inbound" || t.Type != "vless" || !model.ValidAuthID(t.AuthID) || !model.ValidAuthID(t.LegacyAuthID) {
			return fmt.Errorf("invalid identity migration")
		}
		old := model.IdentityName(t.InboundTag, t.LegacyAuthID)
		current := model.IdentityName(t.InboundTag, t.AuthID)
		if seen[old] {
			return fmt.Errorf("ambiguous legacy identity")
		}
		seen[old] = true
		var bound string
		err := tx.QueryRow("SELECT current FROM identity_migrations WHERE server=? AND legacy=?", server, old).Scan(&bound)
		alreadyBound := err == nil
		if alreadyBound && bound != current {
			continue
		}
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if alreadyBound {
			var oldExists, currentExists int
			if err = tx.QueryRow("SELECT count(*) FROM nodes WHERE server=? AND tag=?", server, old).Scan(&oldExists); err != nil {
				return err
			}
			if err = tx.QueryRow("SELECT count(*) FROM nodes WHERE server=? AND tag=?", server, current).Scan(&currentExists); err != nil {
				return err
			}
			// Rollback may restore legacy keys while retaining migration journals.
			// Reapply only the exact already-recorded binding, never a rotation.
			if oldExists == 0 || currentExists > 0 {
				continue
			}
		}
		if !alreadyBound {
			if err = tx.QueryRow("SELECT current FROM identity_migrations WHERE server=? AND current=?", server, current).Scan(&bound); err == nil {
				continue
			} else if err != sql.ErrNoRows {
				return err
			}
		}
		var count, oldCount int
		if err = tx.QueryRow("SELECT count(*) FROM nodes WHERE server=? AND tag=?", server, current).Scan(&count); err != nil {
			return err
		}
		if err = tx.QueryRow("SELECT count(*) FROM nodes WHERE server=? AND tag=?", server, old).Scan(&oldCount); err != nil {
			return err
		}
		if count > 0 && oldCount > 0 {
			return fmt.Errorf("identity migration target already exists")
		}
		if !alreadyBound {
			if _, err = tx.Exec("INSERT INTO identity_migrations VALUES(?,?,?)", server, old, current); err != nil {
				return err
			}
		}
		// Keep the opaque ID, name, metadata and personal aliases. Preserve all history.
		for _, table := range []string{"nodes", "grants", "history", "counters", "daily_flow", "monthly_flow", "monthly", "billing_usage", "exit_cache"} {
			if _, err = tx.Exec("UPDATE "+table+" SET tag=? WHERE server=? AND tag=?", current, server, old); err != nil {
				return err
			}
		}
	}
	return nil
}
