package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

var identities = struct {
	sync.RWMutex
	values map[string]string
}{values: map[string]string{}}

func UUIDKey(uuid string) string {
	v := sha256.Sum256([]byte("vless-uuid-v1\x00" + strings.ToLower(uuid)))
	return hex.EncodeToString(v[:])
}

// Registration preserves sing-box's original metadata.User and auth_user routing.
// Only the ledger key uses the stable UUID digest.
func Register(in, name, uuid string) error {
	if os.Getenv("TZSING_POLICY_DB") == "" {
		return nil
	}
	if name == "" || uuid == "" {
		return fmt.Errorf("policy requires unambiguous named UUID identities")
	}
	identities.Lock()
	defer identities.Unlock()
	k := in + "\x00" + name
	v := UUIDKey(uuid)
	if old, ok := identities.values[k]; ok && old != v {
		return fmt.Errorf("ambiguous authentication identity")
	}
	identities.values[k] = v
	return nil
}
func Identity(in, name string) string {
	identities.RLock()
	defer identities.RUnlock()
	return identities.values[in+"\x00"+name]
}
