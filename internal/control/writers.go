package control

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Complement the transaction flock and version checks with generic detection of
// open writable configuration descriptors. Sole-writer ownership must also be
// established operationally: closed or sandbox-inaccessible descriptors cannot
// reveal a future writer. Configuration CAS checks remain mandatory.
func configWriterConflict(proc, config string) error {
	target, err := os.Stat(config)
	if err != nil {
		return errors.New("无法核实配置版本；未应用")
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return errors.New("无法核实外部写入；未应用")
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid == os.Getpid() {
			continue
		}
		base := filepath.Join(proc, entry.Name())
		fds, e := os.ReadDir(filepath.Join(base, "fd"))
		if os.IsNotExist(e) || os.IsPermission(e) {
			continue
		}
		if e != nil {
			return errors.New("无法检查外部配置描述符；未应用")
		}
		for _, fd := range fds {
			st, e := os.Stat(filepath.Join(base, "fd", fd.Name()))
			if e != nil || !os.SameFile(target, st) {
				continue
			}
			info, e := os.ReadFile(filepath.Join(base, "fdinfo", fd.Name()))
			if e != nil {
				return errors.New("无法检查外部写权限；未应用")
			}
			for _, line := range strings.Split(string(info), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "flags:" {
					flags, e := strconv.ParseUint(fields[1], 8, 64)
					if e != nil || flags&3 != 0 {
						return errors.New("发现外部配置写入描述符；未应用")
					}
				}
			}
		}
	}
	return nil
}
