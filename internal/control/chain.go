package control

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Resolve dynamic members from the running instance. Never use a guessed default.
func (c *Controller) liveSelections(config, root map[string]any) (map[string]string, error) {
	needs := false
	by := map[string]map[string]any{}
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		by[text(o["tag"])] = o
	}
	seen := map[string]bool{}
	var visit func(map[string]any)
	visit = func(o map[string]any) {
		tag := text(o["tag"])
		if seen[tag] {
			return
		}
		seen[tag] = true
		k := text(o["type"])
		if k == "selector" || k == "urltest" {
			needs = true
		}
		if d := text(o["detour"]); d != "" {
			visit(by[d])
		}
	}
	visit(root)
	if !needs {
		return nil, nil
	}
	api := object(object(config["experimental"])["clash_api"])
	address := text(api["external_controller"])
	host, _, e := net.SplitHostPort(address)
	if e != nil || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		return nil, errors.New("动态链路未知：缺少本机运行时选择证明")
	}
	req, e := http.NewRequest("GET", "http://"+address+"/proxies", nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+text(api["secret"]))
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return nil, errors.New("动态链路未知：运行时选择读取失败")
	}
	defer res.Body.Close()
	var data struct {
		Proxies map[string]struct {
			Now string `json:"now"`
		} `json:"proxies"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&data) != nil {
		return nil, errors.New("动态链路未知：运行时选择响应无效")
	}
	out := map[string]string{}
	for tag, v := range data.Proxies {
		out[tag] = v.Now
	}
	return out, nil
}

// Preserve the client nearest the destination as the egress. Detour nodes only
// carry its transport; their server addresses never become an IP result.
func probeGraph(config, root map[string]any, selected map[string]string) ([]any, error) {
	by := map[string]map[string]any{}
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		by[text(o["tag"])] = o
	}
	by[text(root["tag"])] = root
	visiting := map[string]bool{}
	done := map[string]bool{}
	out := []any{}
	var walk func(string) error
	walk = func(tag string) error {
		if visiting[tag] {
			return errors.New("出站链包含循环")
		}
		if done[tag] {
			return nil
		}
		o := by[tag]
		if o == nil {
			return errors.New("出站链引用不存在")
		}
		visiting[tag] = true
		copy := candidateMap(documentBytes(o))
		kind := text(o["type"])
		if kind == "selector" || kind == "urltest" {
			member := selected[tag]
			found := false
			for _, v := range array(o["outbounds"]) {
				if text(v) == member {
					found = true
				}
			}
			if !found || member == "" {
				return errors.New("动态链路未知：当前成员未获证明")
			}
			if e := walk(member); e != nil {
				return e
			}
			copy = map[string]any{"type": "selector", "tag": tag, "outbounds": []any{member}, "default": member}
		} else {
			if kind != "direct" {
				if !safeOutbound(copy) && text(copy["detour"]) == "" {
					return errors.New("出站链包含不支持的本地依赖")
				}
				validation := candidateMap(documentBytes(copy))
				delete(validation, "detour")
				if !safeOutbound(validation) {
					return errors.New("出站链包含不支持的本地依赖")
				}
				pinned, e := pinPublic(copy)
				if e != nil {
					return e
				}
				copy = pinned
			}
			if d := text(o["detour"]); d != "" {
				if e := walk(d); e != nil {
					return e
				}
			}
		}
		for k := range copy {
			if strings.Contains(k, "file") {
				return errors.New("出站链包含本地文件依赖")
			}
		}
		visiting[tag] = false
		done[tag] = true
		out = append(out, copy)
		return nil
	}
	if e := walk(text(root["tag"])); e != nil {
		return nil, e
	}
	return out, nil
}
