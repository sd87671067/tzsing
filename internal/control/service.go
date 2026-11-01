package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

type ServiceConfig struct {
	AgentConfig    string              `json:"agent_config,omitempty"`
	Config         string              `json:"config"`
	State          string              `json:"state"`
	Socket         string              `json:"socket"`
	Binary         string              `json:"binary"`
	Unit           string              `json:"unit"`
	PeerUID        uint32              `json:"peer_uid"`
	PeerGID        int                 `json:"peer_gid"`
	ExitFile       string              `json:"exit_file"`
	DisabledReason string              `json:"disabled_reason"`
	WriteEnabled   bool                `json:"write_enabled"`
	Endpoints      map[string]Endpoint `json:"endpoints"`
}
type plan struct {
	Hash, Tag      string
	AuthID, Action string
	Candidate      []byte
	Snapshot       Snapshot
	Restore        bool
	Expires        time.Time
}
type Controller struct {
	inspectLast  map[string]time.Time
	inspectExits map[string]observedExit
	lastIP       string
	Config       ServiceConfig
	mu           sync.Mutex
	plans        map[string]plan
	Hooks        *ApplyHooks
}
type ApplyHooks struct {
	Check    func([]byte) error
	Activate func() error
	Healthy  func(map[string]any) error
	Probe    func(map[string]any) error
}
type serviceRequest struct {
	Outbound     string           `json:"outbound,omitempty"`
	RouteVersion string           `json:"route_version,omitempty"`
	Node         *UUIDNodeRequest `json:"node,omitempty"`
	AuthID       string           `json:"auth_id,omitempty"`
	Source       string           `json:"source,omitempty"`
	PreviousIPv4 string           `json:"previous_ipv4,omitempty"`
	PreviousIPv6 string           `json:"previous_ipv6,omitempty"`
	Tag          string           `json:"tag"`
	Link         string           `json:"link"`
	Plan         string           `json:"plan"`
	Action       string           `json:"action,omitempty"`
	Profile      string           `json:"profile"`
	Label        string           `json:"label"`
}
type transaction struct {
	Hash     string              `json:"hash"`
	After    string              `json:"after"`
	Before   []byte              `json:"before"`
	Journals map[string]Snapshot `json:"journals"`
}

func atomicFile(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".tzsing-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (c *Controller) journals() (map[string]Snapshot, error) {
	b, e := os.ReadFile(filepath.Join(c.Config.State, "snapshots.json"))
	if os.IsNotExist(e) {
		return map[string]Snapshot{}, nil
	}
	var v map[string]Snapshot
	if e != nil || json.Unmarshal(b, &v) != nil {
		return nil, ErrScope
	}
	return v, nil
}
func (c *Controller) check(b []byte) error {
	if c.Hooks != nil && c.Hooks.Check != nil {
		return c.Hooks.Check(b)
	}
	f, e := os.CreateTemp(c.Config.State, ".tzsing-check-*.json")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	f.Chmod(0600)
	_, e = f.Write(b)
	f.Close()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// No shell, untrusted executable, command argument, environment or stderr export.
	cmd := exec.CommandContext(ctx, c.Config.Binary, "check", "-c", f.Name())
	cmd.Dir = filepath.Dir(c.Config.Config)
	if cmd.Run() != nil {
		return errors.New("sing-box 配置校验失败；未应用")
	}
	return nil
}
func (c *Controller) activate() error {
	if c.Hooks != nil && c.Hooks.Activate != nil {
		return c.Hooks.Activate()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", c.Config.Unit).Run()
}
func (c *Controller) healthy(config map[string]any) error {
	if c.Hooks != nil && c.Hooks.Healthy != nil {
		return c.Hooks.Healthy(config)
	}
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", c.Config.Unit).Run()
		cancel()
		good := e == nil
		for _, v := range array(config["inbounds"]) {
			in := object(v)
			port, _ := in["listen_port"].(float64)
			if port == 0 {
				continue
			}
			typ := text(in["type"])
			if typ == "hysteria" || typ == "hysteria2" || typ == "tuic" {
				continue
			}
			host := text(in["listen"])
			if host == "" || host == "::" || host == "0.0.0.0" {
				host = "127.0.0.1"
			}
			conn, e := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 250*time.Millisecond)
			if e != nil {
				good = false
			} else {
				conn.Close()
			}
		}
		if good {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("sing-box 运行或入站监听检查失败")
}
func (c *Controller) audit(event, tag string) error {
	path := filepath.Join(c.Config.State, "audit.jsonl")
	if st, e := os.Stat(path); e == nil && st.Size() > 4<<20 {
		os.Rename(path, path+".previous")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(map[string]any{"at": time.Now().Unix(), "event": event, "node_hash": digest([]byte(tag))[:16]}); e != nil {
		return e
	}
	return f.Sync()
}

func (c *Controller) apply(p plan) error {
	if c.Hooks == nil {
		if e := configWriterConflict("/proc", c.Config.Config); e != nil {
			return e
		}
	}
	if e := c.audit("apply_started", planKey(p)); e != nil {
		return errors.New("审计日志不可写；未应用")
	}
	raw, e := os.ReadFile(c.Config.Config)
	if e != nil || digest(raw) != p.Hash {
		return ErrScope
	}
	if !p.Restore && p.Action == "" && c.Hooks == nil && text(p.Snapshot.Outbound["type"]) != "direct" {
		pinned, err := pinPublic(p.Snapshot.Outbound)
		if err != nil {
			return err
		}
		candidate := candidateMap(p.Candidate)
		outs := array(candidate["outbounds"])
		found := false
		for i, o := range outs {
			if text(object(o)["tag"]) == managedTag(planKey(p)) {
				outs[i] = pinned
				found = true
			}
		}
		if !found {
			return ErrScope
		}
		candidate["outbounds"] = outs
		p.Candidate = canonical(candidate)
		p.Snapshot.Outbound = pinned
	}
	if c.Hooks == nil && p.Action == "" && !supportsNode(findInbound(candidateMap(p.Candidate), p.Tag)) {
		return errors.New("目标入站尚未完成实际路径校验，禁止应用")
	}
	if e = c.check(raw); e != nil {
		return errors.New("原配置无法验证，不能保证安全回滚")
	}
	if e = c.healthy(candidateMap(raw)); e != nil {
		return errors.New("原服务不健康，不能保证安全回滚")
	}
	if e = c.check(p.Candidate); e != nil {
		return e
	}
	var candidate, original map[string]any
	json.Unmarshal(p.Candidate, &candidate)
	json.Unmarshal(raw, &original)
	if !p.Restore && p.Action == "" {
		if e = c.probe(p.Snapshot.Outbound); e != nil {
			return e
		}
	}
	journals, e := c.journals()
	if e != nil {
		return e
	}
	oldJournals := map[string]Snapshot{}
	for k, v := range journals {
		oldJournals[k] = v
	}
	before := transaction{Hash: digest(raw), After: digest(p.Candidate), Before: raw, Journals: oldJournals}
	backup := filepath.Join(c.Config.State, "backup-"+time.Now().UTC().Format("20060102T150405.000000000")+"-"+before.Hash[:12]+".json")
	if e = atomicFile(backup, raw, 0600); e != nil {
		return e
	}
	txPath := filepath.Join(c.Config.State, "transaction.json")
	if e = atomicFile(txPath, canonical(before), 0600); e != nil {
		return e
	}
	// A last CAS under the controller's cross-process flock detects external edits.
	latest, e := os.ReadFile(c.Config.Config)
	if e != nil || digest(latest) != p.Hash {
		os.Remove(txPath)
		return ErrScope
	}
	stat, e := os.Stat(c.Config.Config)
	if e != nil {
		return e
	}
	if e = atomicFile(c.Config.Config, p.Candidate, stat.Mode().Perm()); e != nil {
		return e
	}
	rollback := func(cause error) error {
		current, readErr := os.ReadFile(c.Config.Config)
		if readErr != nil || digest(current) != digest(p.Candidate) {
			c.audit("rollback_conflict_manual_recovery_required", p.Tag)
			return errors.New("外部配置发生并发变更；已保留备份，需人工恢复")
		}
		if atomicFile(c.Config.Config, raw, stat.Mode().Perm()) != nil || c.activate() != nil || c.healthy(original) != nil {
			c.audit("rollback_failed_manual_recovery_required", p.Tag)
			return errors.New("回滚验证失败；需人工恢复")
		}
		if atomicFile(filepath.Join(c.Config.State, "snapshots.json"), canonical(oldJournals), 0600) != nil {
			return errors.New("回滚快照持久化失败")
		}
		os.Remove(txPath)
		c.audit("rolled_back", p.Tag)
		return fmt.Errorf("%s；已恢复原配置并验证服务", cause.Error())
	}
	if e = c.activate(); e != nil {
		return rollback(errors.New("服务切换失败"))
	}
	if e = c.healthy(candidate); e != nil {
		return rollback(e)
	}
	if !p.Restore && p.Action == "" {
		if e = c.probe(p.Snapshot.Outbound); e != nil {
			return rollback(e)
		}
	}
	if p.Action != "" && c.Hooks == nil {
		peers := candidateMap(p.Candidate)
		in := findInbound(peers, p.Tag)
		users := []any{}
		for _, v := range array(in["users"]) {
			u := object(v)
			if model.UUIDAuthID(text(u["uuid"])) != p.AuthID {
				users = append(users, v)
			}
		}
		if len(users) == 0 {
			return rollback(errors.New("没有可验证的未受影响 UUID"))
		}
		in["users"] = users
		if e = c.probeNode(peers, p.Tag); e != nil {
			return rollback(errors.New("其他 UUID 健康检查失败"))
		}
	}
	expectedExit := c.lastIP
	if p.Action == "" || (p.Action == "create" && !identityDisabled(candidate, p.Tag, p.AuthID)) {
		checked := candidateMap(p.Candidate)
		if p.AuthID != "" {
			scoped, err := IdentityInbound(findInbound(checked, p.Tag), p.AuthID)
			if err != nil {
				return rollback(err)
			}
			for _, v := range array(checked["inbounds"]) {
				in := object(v)
				if text(in["tag"]) == p.Tag {
					in["users"] = scoped["users"]
				}
			}
		}
		if e = c.probeNode(checked, p.Tag); e != nil {
			return rollback(e)
		}
		if p.Action == "" && !p.Restore && expectedExit != "" && c.lastIP != expectedExit {
			return rollback(errors.New("UUID 实际出口与目标出站不一致"))
		}
	}
	currentAfter, readErr := os.ReadFile(c.Config.Config)
	if readErr != nil || digest(currentAfter) != digest(p.Candidate) {
		return rollback(errors.New("应用期间发生外部写入"))
	}
	if c.Config.ExitFile != "" && c.lastIP != "" {
		receipt := map[string]any{"config_hash": digest(p.Candidate), "tag": p.Tag, "outbound": text(p.Snapshot.Outbound["tag"]), "ip": c.lastIP, "at": time.Now().Unix()}
		atomicFile(c.Config.ExitFile, canonical(receipt), 0644)
	}
	// Rebase only snapshots whose baseline exactly matches the validated input.
	// Trusted internal identity changes can evolve policy; external edits cannot.
	for key, snapshot := range journals {
		if snapshot.BaselineHash == baselineHash(original) {
			snapshot.BaselineHash = baselineHash(candidate)
			journals[key] = snapshot
		}
	}
	if p.Restore {
		delete(journals, planKey(p))
	} else {
		if p.Action == "" {
			journals[planKey(p)] = p.Snapshot
		}
		if p.Action == "disable" || (p.Action == "create" && identityDisabled(candidate, p.Tag, p.AuthID)) {
			p.Snapshot = Snapshot{BaselineHash: baselineHash(candidate)}
			journals[planKey(p)+":disabled"] = p.Snapshot
		}
		if p.Action == "enable" || p.Action == "delete" {
			delete(journals, planKey(p)+":disabled")
		}
	}
	if e = atomicFile(filepath.Join(c.Config.State, "snapshots.json"), canonical(journals), 0600); e != nil {
		return rollback(errors.New("恢复快照持久化失败"))
	}
	os.Remove(txPath)
	c.audit("applied", p.Tag)
	return nil
}
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	fail := func(n int, msg string) { w.WriteHeader(n); json.NewEncoder(w).Encode(map[string]string{"error": msg}) }
	if r.Method != "POST" {
		fail(405, "操作不支持")
		return
	}
	var v serviceRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		fail(400, "请求无效")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(400, "请求无效")
		return
	}
	if v.AuthID != "" && r.URL.Path != "/status" && r.URL.Path != "/share" && r.URL.Path != "/diagnostics" && r.URL.Path != "/intel" && r.URL.Path != "/preview" && r.URL.Path != "/restore-preview" && r.URL.Path != "/apply" {
		fail(403, "认证身份的独立路由或检测尚不可用")
		return
	}
	if r.URL.Path == "/diagnostics" || r.URL.Path == "/intel" {
		if !c.mu.TryLock() {
			fail(429, "已有检测或配置操作进行中")
			return
		}
		defer c.mu.Unlock()
		c.inspect(w, r, v)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lock, e := os.OpenFile(filepath.Join(c.Config.State, "apply.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		fail(503, "控制锁不可用")
		return
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		fail(409, "已有配置操作进行中")
		return
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, e := os.ReadFile(c.Config.Config)
	var config map[string]any
	if e != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &config) != nil {
		fail(503, "配置不可用")
		return
	}
	writeEnabled := c.Config.WriteEnabled
	writerReason := c.Config.DisabledReason
	if writeEnabled && c.Hooks == nil {
		if e := configWriterConflict("/proc", c.Config.Config); e != nil {
			writeEnabled = false
			writerReason = e.Error()
		}
	}
	if r.URL.Path == "/uuid-catalog" {
		catalog := UUIDCatalog(raw)
		catalog["apply"] = writeEnabled
		if writeEnabled {
			caps := catalog["capabilities"].(map[string]any)
			for _, key := range []string{"enabled", "outbound"} {
				caps[key] = map[string]any{"state": "ready", "saved": false, "effective": false, "reason": "预览及二次确认后，校验、原子写入、重启和健康检查。"}
			}
		}
		catalog["reason"] = writerReason
		if writeEnabled {
			catalog["reason"] = "需二次确认；重启整个 sing-box，共享 443 连接可能中断。"
		}
		json.NewEncoder(w).Encode(catalog)
		return
	}
	if r.URL.Path == "/uuid-preview" {
		if v.Node == nil {
			fail(400, "缺少节点参数")
			return
		}
		candidate, summary, err := UUIDCandidate(raw, *v.Node)
		if err != nil {
			fail(422, err.Error())
			return
		}
		if err = c.check(candidate); err != nil {
			fail(422, err.Error())
			return
		}
		if c.plans == nil {
			c.plans = map[string]plan{}
		}
		for k, old := range c.plans {
			if time.Now().After(old.Expires) {
				delete(c.plans, k)
			}
		}
		if len(c.plans) >= 128 {
			fail(429, "预览过多")
			return
		}
		id := auth.Random()
		authID := text(summary["auth_id"])
		delete(summary, "auth_id")
		c.plans[auth.Digest(id)] = plan{Hash: digest(raw), Tag: v.Node.Inbound, AuthID: authID, Action: "create", Candidate: candidate, Expires: time.Now().Add(2 * time.Minute)}
		summary["plan"] = id
		summary["writable"] = writeEnabled
		summary["effects"] = impact(config, v.Node.Inbound, "")
		summary["impact"] = "重启整个 sing-box；共享 443 连接可能中断，失败自动回滚。"
		c.audit("uuid_candidate_checked", v.Node.Inbound)
		json.NewEncoder(w).Encode(summary)
		return
	}
	if r.URL.Path == "/uuid-apply" {
		key := auth.Digest(v.Plan)
		p, ok := c.plans[key]
		delete(c.plans, key)
		if !writeEnabled {
			fail(503, "生产写入未启用")
			return
		}
		if !ok || p.Action != "create" || time.Now().After(p.Expires) {
			fail(409, "确认过期或已使用")
			return
		}
		if err := c.apply(p); err != nil {
			fail(409, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "auth_id": p.AuthID, "inbound": p.Tag})
		return
	}
	in := findInbound(config, v.Tag)
	if in == nil {
		fail(403, "目标不可用")
		return
	}
	// Resolve only the requested identity before sharing or previewing a route.
	if v.AuthID != "" {
		if r.URL.Path != "/status" && r.URL.Path != "/share" && r.URL.Path != "/preview" && r.URL.Path != "/restore-preview" && r.URL.Path != "/apply" {
			fail(403, "认证身份的独立路由应用尚不可用；禁止修改整个入站")
			return
		}
		in, e = IdentityInbound(in, v.AuthID)
		if e != nil {
			fail(403, "认证身份已变化或不存在")
			return
		}
	}
	journalKey := v.Tag
	if v.AuthID != "" {
		journalKey = identityKey(v.Tag, v.AuthID)
	}
	journals, e := c.journals()
	if e != nil {
		fail(503, "恢复快照不可用")
		return
	}
	respond := func(x any) { json.NewEncoder(w).Encode(x) }
	switch r.URL.Path {
	case "/status":
		reason := "配置应用需要重启 sing-box，所有现有连接会短暂断开并重连"
		if !writeEnabled && writerReason != "" {
			reason = writerReason
		}
		impact := "仅替换目标入站路由结果；保留认证、拒绝规则及其他入站配置"
		if v.AuthID != "" {
			impact = "仅修改当前 UUID；应用需重启整个实例"
			if writeEnabled {
				reason = "应用需重启整个 sing-box 实例"
			}
		}
		restoreReason := ""
		if journals[journalKey].Outbound == nil {
			restoreReason = "该 UUID 尚无 tzsing 切换快照；完成更换后才能恢复，不能猜测原路由"
		} else if !writeEnabled {
			restoreReason = reason
		}
		respond(map[string]any{"restore_reason": restoreReason, "apply": writeEnabled && supportsNode(in) && (v.AuthID != "" || len(array(in["users"])) <= 1), "restore": writeEnabled && (v.AuthID != "" || len(array(in["users"])) <= 1) && journals[journalKey].Outbound != nil, "share": len(Profiles(in, c.Config.Endpoints[v.Tag])) > 0, "profiles": Profiles(in, c.Config.Endpoints[v.Tag]), "outbounds": UUIDCatalog(raw)["outbounds"], "preview": true, "reason": reason, "impact": impact})
	case "/share":
		link, e := Share(in, c.Config.Endpoints[v.Tag], v.Profile, v.Label)
		if e != nil {
			fail(422, "此入站或认证资料不支持分享")
			return
		}
		c.audit("share", v.Tag)
		respond(map[string]string{"link": link})
	case "/preview", "/restore-preview":
		if v.AuthID == "" && len(array(in["users"])) > 1 {
			fail(403, "共享监听器必须选择单个 UUID")
			return
		}
		if c.plans == nil {
			c.plans = map[string]plan{}
		}
		for k, p := range c.plans {
			if time.Now().After(p.Expires) {
				delete(c.plans, k)
			}
		}
		if len(c.plans) >= 128 {
			fail(429, "操作过于频繁")
			return
		}
		p := plan{Hash: digest(raw), Tag: v.Tag, AuthID: v.AuthID, Action: v.Action, Expires: time.Now().Add(2 * time.Minute)}
		var preview any
		if r.URL.Path == "/restore-preview" {
			s, ok := journals[journalKey]
			if !ok {
				fail(409, "没有原始快照")
				return
			}
			if v.AuthID != "" {
				p.Candidate, e = RestoreIdentity(raw, v.Tag, v.AuthID, s)
			} else {
				p.Candidate, e = Restore(raw, v.Tag, s)
			}
			p.Restore = true
			preview = map[string]any{"protocol": "原始映射", "server": "已保存的实际原配置", "port": 0}
		} else if v.Action != "" {
			if v.AuthID == "" {
				fail(403, "必须指定单个 UUID")
				return
			}
			if v.Action == "enable" && journals[journalKey+":disabled"].BaselineHash != baselineHash(config) {
				fail(409, "停用规则来源或配置版本已变化，不能安全启用")
				return
			}
			if v.Action == "delete" && journals[journalKey].Outbound != nil {
				fail(409, "请先恢复原始出站")
				return
			}
			p.Candidate, e = IdentityMutation(raw, v.Tag, v.AuthID, v.Action)
			if e == nil && v.Action == "disable" {
				p.Snapshot = Snapshot{BaselineHash: baselineHash(candidateMap(p.Candidate))}
			}
			preview = map[string]any{"operation": v.Action}
		} else {
			var o map[string]any
			if v.Outbound != "" {
				for _, item := range array(config["outbounds"]) {
					current := object(item)
					kind, _ := model.OutboundType(text(current["type"]))
					if text(current["tag"]) == v.Outbound && kind == "actual" {
						o = candidateMap(canonical(current))
						o["tag"] = managedTag(journalKey)
					}
				}
				if o == nil {
					fail(422, "请选择已有 Direct 或实际中转出站")
					return
				}
				preview = map[string]any{"protocol": o["type"], "server": "已有出站：" + v.Outbound, "port": o["server_port"]}
			} else {
				l, err := Parse(v.Link)
				if err != nil {
					fail(400, ErrLink.Error())
					return
				}
				o, err = l.Outbound(managedTag(journalKey))
				if err != nil {
					fail(422, "该链接参数尚不支持安全应用")
					return
				}
				preview = l.Preview()
			}
			var prior *Snapshot
			if s, ok := journals[journalKey]; ok {
				prior = &s
			}
			if v.AuthID != "" {
				p.Candidate, p.Snapshot, e = ChangeIdentity(raw, v.Tag, v.AuthID, o, prior)
			} else {
				p.Candidate, p.Snapshot, e = Change(raw, v.Tag, o, prior)
			}
		}
		if e != nil {
			fail(409, ErrScope.Error())
			return
		}
		if e = c.check(p.Candidate); e != nil {
			fail(422, e.Error())
			return
		}
		id := auth.Random()
		c.plans[auth.Digest(id)] = p
		c.audit("preview", v.Tag)
		respond(map[string]any{"preview": preview, "plan": id, "impact": "应用将重启整个 sing-box 实例，现有连接可能中断。", "effects": impact(config, v.Tag, v.AuthID), "writable": writeEnabled, "reason": writerReason})
	case "/apply":
		key := auth.Digest(v.Plan)
		p, ok := c.plans[key]
		delete(c.plans, key)
		if !c.Config.WriteEnabled {
			fail(503, "生产配置写入未启用")
			return
		}
		if !ok || p.Tag != v.Tag || p.AuthID != v.AuthID || time.Now().After(p.Expires) {
			fail(409, "确认已过期或被使用，请重新预览")
			return
		}
		if e = c.apply(p); e != nil {
			c.audit("apply_failed", v.Tag)
			fail(409, e.Error())
			return
		}
		respond(map[string]bool{"ok": true})
	default:
		fail(404, "操作不支持")
	}
}
func RunController(ctx context.Context, path string) error {
	b, e := os.ReadFile(path)
	var cfg ServiceConfig
	if e != nil || json.Unmarshal(b, &cfg) != nil {
		return errors.New("受限控制配置无效")
	}
	if !filepath.IsAbs(cfg.Config) || !filepath.IsAbs(cfg.State) || !filepath.IsAbs(cfg.Socket) || cfg.Binary != "/usr/local/bin/sing-box" || cfg.Unit != "sing-box.service" {
		return errors.New("控制路径或服务不允许")
	}
	if e = os.MkdirAll(cfg.State, 0700); e != nil {
		return e
	}
	os.Chmod(cfg.State, 0700)
	serviceLock, e := os.OpenFile(filepath.Join(cfg.State, "service.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer serviceLock.Close()
	if syscall.Flock(int(serviceLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("控制服务已经运行")
	}
	defer syscall.Flock(int(serviceLock.Fd()), syscall.LOCK_UN)
	c := &Controller{Config: cfg}
	// An interrupted application is recovered before accepting any new operation.
	txPath := filepath.Join(cfg.State, "transaction.json")
	if b, e := os.ReadFile(txPath); e == nil {
		if !cfg.WriteEnabled {
			return errors.New("生产配置写入未启用；保留中断事务，禁止自动恢复")
		}
		if e := configWriterConflict("/proc", cfg.Config); e != nil {
			return e
		}
		var tx transaction
		if json.Unmarshal(b, &tx) != nil || digest(tx.Before) != tx.Hash {
			return errors.New("中断事务备份无效")
		}
		current, err := os.ReadFile(cfg.Config)
		if err != nil || (digest(current) != tx.After && digest(current) != tx.Hash) {
			return errors.New("中断事务与外部配置冲突；保留备份，禁止自动覆盖")
		}
		var original map[string]any
		json.Unmarshal(tx.Before, &original)
		if c.check(tx.Before) != nil || atomicFile(cfg.Config, tx.Before, 0600) != nil || c.activate() != nil || c.healthy(original) != nil {
			return errors.New("中断事务恢复失败")
		}
		if atomicFile(filepath.Join(cfg.State, "snapshots.json"), canonical(tx.Journals), 0600) != nil {
			return errors.New("中断事务快照恢复失败")
		}
		os.Remove(txPath)
		c.audit("interrupted_transaction_recovered", "")
	}
	if e = os.MkdirAll(filepath.Dir(cfg.Socket), 0750); e != nil {
		return e
	}
	os.Chown(filepath.Dir(cfg.Socket), 0, cfg.PeerGID)
	if st, e := os.Lstat(cfg.Socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("控制路径不是 socket")
		}
		os.Remove(cfg.Socket)
	}
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if e != nil {
		return e
	}
	defer ln.Close()
	os.Chown(cfg.Socket, 0, cfg.PeerGID)
	os.Chmod(cfg.Socket, 0660)
	server := &http.Server{Handler: c, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			allowed := false
			if u, ok := conn.(*net.UnixConn); ok {
				rc, _ := u.SyscallConn()
				rc.Control(func(fd uintptr) {
					cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					allowed = e == nil && (cred.Uid == cfg.PeerUID || cred.Uid == 0)
				})
			}
			if !allowed {
				conn.Close()
			}
			return ctx
		}}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
}

func candidateMap(b []byte) map[string]any { var c map[string]any; json.Unmarshal(b, &c); return c }

func planKey(p plan) string {
	if p.AuthID != "" {
		return identityKey(p.Tag, p.AuthID)
	}
	return p.Tag
}
