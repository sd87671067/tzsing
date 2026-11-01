package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func ValidAuthID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == id
}
func AuthID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// Server ID is the existing outer database key. The inner identity is unambiguous
// even when inbound tags contain delimiters. Existing inbound keys never change.
func IdentityName(inbound, auth string) string {
	if auth == "" {
		return "inbound:" + inbound
	}
	sum := sha256.Sum256([]byte(inbound + "\x00" + auth))
	return "identity:" + hex.EncodeToString(sum[:])
}

// UUIDAuthID is private inventory identity, never the public node ID. A UUID
// rotation creates a new identity; labels and user names do not define accounts.
func UUIDAuthID(uuid string) string { return AuthID("vless-uuid-v1\x00" + strings.ToLower(uuid)) }
