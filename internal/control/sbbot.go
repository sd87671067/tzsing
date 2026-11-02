package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"tzsingbox/internal/model"
)

type rootPeerKey struct{}

// Root peer authentication is set exclusively by SO_PEERCRED on the Unix socket.
// No executable, shell command, path or systemd unit comes from the Bot.
func (c *Controller) sbbotRequest(w http.ResponseWriter, r *http.Request, v serviceRequest, raw []byte, enabled bool) {
	fail := func(code int, e error) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
	}
	send := func(x any) { json.NewEncoder(w).Encode(x) }
	switch r.URL.Path {
	case "/sbbot-haproxy":
		b, e := os.ReadFile(haproxyPath)
		if e != nil {
			fail(503, e)
			return
		}
		send(map[string]string{"config": string(b)})
	case "/sbbot-status":
		send(map[string]any{"writable": enabled, "hash": digest(raw)})
	case "/sbbot-probe":
		conf := candidateMap(raw)
		c.lastIP = ""
		var e error
		if v.AuthID != "" {
			scoped := candidateMap(raw)
			in := findInbound(scoped, v.Tag)
			var chosen []any
			for _, item := range array(in["users"]) {
				u := object(item)
				if text(u["name"]) == v.AuthID || model.UUIDAuthID(text(u["uuid"])) == v.AuthID {
					chosen = append(chosen, u)
				}
			}
			if len(chosen) != 1 {
				fail(409, ErrScope)
				return
			}
			in["users"] = chosen
			e = c.probeNode(c.publicProbeConfig(scoped, v.Tag), v.Tag)
		} else {
			var out map[string]any
			for _, item := range array(conf["outbounds"]) {
				o := object(item)
				if text(o["tag"]) == v.Tag {
					out = o
				}
			}
			if out == nil {
				fail(409, ErrScope)
				return
			}
			e = c.probe(out)
		}
		if e != nil {
			fail(422, e)
			return
		}
		send(map[string]any{"ip": c.lastIP})
	case "/sbbot-apply":
		if !enabled {
			fail(503, errors.New("生产配置写入不可用"))
			return
		}
		base := v.BaseBytes
		if len(base) == 0 {
			base = v.Base
		}
		if len(base) == 0 || digest(base) != v.Hash || !json.Valid(v.Candidate) {
			fail(409, ErrScope)
			return
		}
		merged, e := mergeConfig(base, v.Candidate, raw)
		if e != nil {
			fail(409, e)
			return
		}
		// Existing generic transaction owns backup, check, activation, health and CAS.
		p := plan{Hash: digest(raw), Action: "sbbot", Candidate: merged, HapSNI: v.RealitySNI, VerifyTag: v.Tag, VerifyUser: v.AuthID, ExpectedIP: v.ExpectedIP}
		if e = c.apply(p); e != nil {
			fail(409, e)
			return
		}
		now, e := os.ReadFile(c.Config.Config)
		if e != nil {
			fail(503, e)
			return
		}
		send(map[string]any{"ok": true, "hash": digest(now)})
	default:
		fail(404, errors.New("操作不支持"))
	}
}

func (c *Controller) verifyIdentity(config map[string]any, tag, user, ip string) error {
	scoped := candidateMap(documentBytes(config))
	in := findInbound(scoped, tag)
	if in == nil {
		return ErrScope
	}
	var chosen []any
	for _, v := range array(in["users"]) {
		u := object(v)
		if text(u["name"]) == user {
			chosen = append(chosen, u)
		}
	}
	if len(chosen) != 1 {
		return ErrScope
	}
	in["users"] = chosen
	c.lastIP = ""
	if e := c.probeNode(c.publicProbeConfig(scoped, tag), tag); e != nil {
		return e
	}
	if ip != "" && ip != c.lastIP {
		return errors.New("用户实际出口与目标不一致")
	}
	return nil
}

func (c *Controller) publicProbeConfig(config map[string]any, tag string) map[string]any {
	scoped := candidateMap(documentBytes(config))
	ep := c.Config.Endpoints[tag]
	if ep.Verified && ep.Port > 0 && ep.Port <= 65535 && ep.Host != "" {
		if in := findInbound(scoped, tag); in != nil {
			in["listen"] = ep.Host
			in["listen_port"] = ep.Port
		}
	}
	return scoped
}
