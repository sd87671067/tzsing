package control

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Extra fail-closed guard for the known local independent writer. This is NOT
// writer coordination: an operator must still establish a sole writer or a
// shared transaction entry before enabling writes. A process can start later.
func knownWriterConflict(proc string) error {
	entries, e := os.ReadDir(proc)
	if e != nil {
		return errors.New("无法核实配置写入者；未应用")
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		b, e := os.ReadFile(filepath.Join(proc, entry.Name(), "comm"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return errors.New("无法核实配置写入者；未应用")
		}
		if strings.TrimSpace(string(b)) == "sbbot" {
			return errors.New("sbbot 未接入共享写锁，配置应用暂不可用")
		}
	}
	return nil
}
