package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"tzsingbox/internal/auth"
)

// Separate from UUID receipts to preserve the existing create recovery protocol.
type applyResult struct {
	State   string `json:"state"`
	OK      bool   `json:"ok"`
	Tag     string `json:"tag,omitempty"`
	IP      string `json:"ip,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (c *Controller) applyResultPath(id string) string {
	return filepath.Join(c.Config.State, "apply-result-"+id+".json")
}
func (c *Controller) loadApplyResult(id string) (v applyResult, e error) {
	b, e := os.ReadFile(c.applyResultPath(id))
	if e == nil {
		e = json.Unmarshal(b, &v)
	}
	return
}
func (c *Controller) saveApplyResult(id string, v applyResult) error {
	return atomicFile(c.applyResultPath(id), canonical(v), 0600)
}
func (c *Controller) applyWithReceipt(p plan, token string) error {
	p.Operation = auth.Digest(token)
	if e := c.saveApplyResult(p.Operation, applyResult{State: "running", Tag: p.Tag}); e != nil {
		return e
	}
	execute := func() error {
		if p.Action == "outbound-save" {
			if e := c.probe(p.Snapshot.Outbound); e != nil {
				return e
			}
		}
		return c.apply(p)
	}
	if e := execute(); e != nil {
		state := "failed"
		if _, err := os.Stat(filepath.Join(c.Config.State, "transaction.json")); err == nil {
			state = "uncertain"
		}
		if err := c.saveApplyResult(p.Operation, applyResult{State: state, Tag: p.Tag, Error: e.Error()}); err != nil {
			return err
		}
		return e
	}
	return nil
}
func (c *Controller) recoverApplyResults() error {
	files, e := filepath.Glob(filepath.Join(c.Config.State, "apply-result-*.json"))
	if e != nil {
		return e
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		var v applyResult
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		if v.State == "running" || v.State == "uncertain" {
			v.State = "failed"
			v.Error = "控制器中断；原事务已恢复，未重复应用配置"
			if e = atomicFile(file, canonical(v), 0600); e != nil {
				return e
			}
		}
	}
	return nil
}
