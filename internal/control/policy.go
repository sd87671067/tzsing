package control

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/policy"
)

func (c *Controller) policyReady() bool {
	if !policy.Qualified || c.Config.PolicyDB == "" {
		return false
	}
	l, e := policy.Open(c.Config.PolicyDB)
	if e != nil {
		return false
	}
	defer l.Close()
	if !l.Ready() {
		return false
	}
	raw, e := os.ReadFile(c.Config.Config)
	if e != nil {
		return false
	}
	config := candidateMap(raw)
	for _, v := range array(config["inbounds"]) {
		in := object(v)
		if !realityInbound(in) {
			continue
		}
		users := array(in["users"])
		if l.RegisteredCount(text(in["tag"])) != len(users) {
			return false
		}
		for _, v := range users {
			u := object(v)
			if !l.Registered(text(in["tag"]), model.UUIDAuthID(text(u["uuid"])), text(u["name"])) {
				return false
			}
		}
	}
	return true
}
func (c *Controller) policyRequest(w http.ResponseWriter, r *http.Request, v serviceRequest, raw []byte, writeEnabled bool) {
	fail := func(n int, s string) { w.WriteHeader(n); json.NewEncoder(w).Encode(map[string]string{"error": s}) }
	send := func(v any) { json.NewEncoder(w).Encode(v) }
	if r.URL.Path == "/policy-status" && c.Config.PolicyDB == "" {
		config := candidateMap(raw)
		items := map[string]policy.State{}
		for _, v := range array(config["inbounds"]) {
			in := object(v)
			if !realityInbound(in) {
				continue
			}
			for _, v := range array(in["users"]) {
				u := object(v)
				if !uuid(text(u["uuid"])) || text(u["name"]) == "" {
					continue
				}
				id := model.UUIDAuthID(text(u["uuid"]))
				status := "enabled"
				if identityDisabled(config, text(in["tag"]), id) {
					status = "disabled"
				}
				items[model.IdentityName(text(in["tag"]), id)] = policy.State{Status: status}
			}
		}
		send(map[string]any{"ready": false, "items": items})
		return
	}
	if !policy.Qualified || c.Config.PolicyDB == "" {
		fail(503, "可靠限制执行器未配置")
		return
	}
	l, e := policy.Open(c.Config.PolicyDB)
	if e != nil {
		fail(503, "策略数据库不可用")
		return
	}
	defer l.Close()
	ready := c.policyReady()
	config := candidateMap(raw)
	if r.URL.Path == "/policy-status" {
		items := map[string]policy.State{}
		for _, v := range array(config["inbounds"]) {
			in := object(v)
			if !realityInbound(in) {
				continue
			}
			for _, v := range array(in["users"]) {
				u := object(v)
				if !uuid(text(u["uuid"])) || text(u["name"]) == "" {
					continue
				}
				id := model.UUIDAuthID(text(u["uuid"]))
				s, err := l.State(text(in["tag"]), id)
				if err != nil {
					continue
				}
				if !ready {
					s.Status = "executor_unavailable"
				} else if identityDisabled(config, text(in["tag"]), id) {
					s.Status = "disabled"
				}
				items[model.IdentityName(text(in["tag"]), id)] = s
			}
		}
		send(map[string]any{"ready": ready, "items": items})
		return
	}
	if !writeEnabled || !ready {
		fail(503, "可靠数据路径执行器尚未运行；设置未保存")
		return
	}
	if !realityInbound(findInbound(config, v.Tag)) {
		fail(422, "此入站不支持 UUID 限制执行")
		return
	}
	u, e := identityUser(config, v.Tag, v.AuthID)
	if e != nil {
		fail(403, "目标 UUID 不可用")
		return
	}
	name := model.UUIDAuthID(text(u["uuid"]))
	if r.URL.Path == "/policy-preview" {
		if v.Policy == nil {
			fail(400, "缺少策略参数")
			return
		}
		next, e := policy.Normalize(*v.Policy)
		if e != nil {
			fail(422, e.Error())
			return
		}
		token := auth.Random()
		if c.plans == nil {
			c.plans = map[string]plan{}
		}
		for k, p := range c.plans {
			if time.Now().After(p.Expires) {
				delete(c.plans, k)
			}
		}
		if len(c.plans) >= 128 {
			fail(429, "预览过多")
			return
		}
		c.plans[auth.Digest(token)] = plan{Hash: digest(raw), Tag: v.Tag, AuthID: v.AuthID, Action: "policy", Policy: &next, Expires: time.Now().Add(2 * time.Minute)}
		current, e := l.State(v.Tag, name)
		if e != nil {
			fail(503, "读取策略失败")
			return
		}
		send(map[string]any{"plan": token, "current": current, "policy": next, "restart": false, "reason": "仅更新此 UUID 的持久策略。新连接立即重新评估，无需重启共享监听器。扣费从首次策略启用起计，历史采样不计入可靠账期；实际结算与未完成预留分别记录；崩溃未决预留保守占用当前账期余额，余额足够即可恢复；未决项不计为实际已用。"})
		return
	}
	p, ok := c.plans[auth.Digest(v.Plan)]
	delete(c.plans, auth.Digest(v.Plan))
	latest, e := os.ReadFile(c.Config.Config)
	if !ok || p.Action != "policy" || p.Tag != v.Tag || p.AuthID != v.AuthID || time.Now().After(p.Expires) || e != nil || digest(latest) != p.Hash {
		fail(409, "配置或确认已变化，请重新预览")
		return
	}
	if c.Hooks == nil {
		if e = configWriterConflict("/proc", c.Config.Config); e != nil {
			fail(409, e.Error())
			return
		}
	}
	if e = c.audit("policy_apply_started", identityKey(v.Tag, v.AuthID)); e != nil {
		fail(503, "审计不可写，未保存")
		return
	}
	if e = l.Set(v.Tag, name, *p.Policy); e != nil {
		log.Printf("policy transaction failed node_hash=%s: %v", digest([]byte(identityKey(v.Tag, v.AuthID)))[:16], e)
		c.audit("policy_apply_failed", identityKey(v.Tag, v.AuthID))
		fail(503, "策略事务未提交，原策略保留")
		return
	}
	state, e := l.State(v.Tag, name)
	if e != nil {
		fail(503, "策略已提交，状态读取失败")
		return
	}
	c.audit("policy_applied", identityKey(v.Tag, v.AuthID))
	send(map[string]any{"ok": true, "state": state, "restart": false})
}

// A newly created expired/exhausted identity is expected to reject payload.
// Peer health plus the live versioned gate verifies this state without treating
// a deliberately enforced policy as a failed rollout.
func (c *Controller) policyDenies(tag, id string) bool {
	if !c.policyReady() {
		return false
	}
	l, e := policy.Open(c.Config.PolicyDB)
	if e != nil {
		return false
	}
	defer l.Close()
	s, e := l.State(tag, id)
	return e == nil && (s.ExpiresAt > 0 && s.ExpiresAt <= time.Now().Unix() || s.Quota > 0 && s.Used+s.Reserved >= s.Quota)
}
