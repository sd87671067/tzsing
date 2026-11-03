package control

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Contains only identity hashes and outcome; never UUID credentials or plans.
type uuidResult struct {
	State   string `json:"state"`
	OK      bool   `json:"ok"`
	Inbound string `json:"inbound"`
	AuthID  string `json:"auth_id"`
	Error   string `json:"error,omitempty"`
}

func (c *Controller) uuidResultPath(id string) string {
	return filepath.Join(c.Config.State, "uuid-result-"+id+".json")
}
func (c *Controller) loadUUIDResult(id string) (uuidResult, error) {
	var v uuidResult
	b, e := os.ReadFile(c.uuidResultPath(id))
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func (c *Controller) saveUUIDResult(id string, v uuidResult) error {
	return atomicFile(c.uuidResultPath(id), canonical(v), 0600)
}
func (c *Controller) recoverUUIDResults() error {
	files, e := filepath.Glob(filepath.Join(c.Config.State, "uuid-result-*.json"))
	if e != nil {
		return e
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		var v uuidResult
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		if v.State == "running" {
			v.State = "failed"
			v.Error = "控制器重启；中断事务已恢复，未重新提交 UUID"
			if e = atomicFile(file, canonical(v), 0600); e != nil {
				return e
			}
		}
	}
	return nil
}
