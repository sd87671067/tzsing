package control

import (
	"strings"
	"sync"
)

// Diagnostic output is bounded, retained in memory only, and reduced to an enum.
// Raw sing-box errors may contain an endpoint or userinfo and are never exported.
type probeLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *probeLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(b)
	if len(l.data) < 16384 {
		left := 16384 - len(l.data)
		if len(b) > left {
			b = b[:left]
		}
		l.data = append(l.data, b...)
	}
	return n, nil
}
func (l *probeLog) reason() string {
	l.mu.Lock()
	s := strings.ToLower(string(l.data))
	l.mu.Unlock()
	switch {
	case strings.Contains(s, "407"), strings.Contains(s, "authentication"), strings.Contains(s, "auth failed"):
		return "代理认证失败（HTTP 407 或 SOCKS 认证拒绝），请核对用户名和密码"
	case strings.Contains(s, "connection refused"):
		return "代理 TCP 连接被拒绝，请核对地址和端口"
	case strings.Contains(s, "certificate"), strings.Contains(s, "tls:"):
		return "TLS 握手或证书校验失败，请核对 HTTPS 协议和服务名"
	case strings.Contains(s, "no such host"), strings.Contains(s, "dns"):
		return "代理或目标 DNS 解析失败"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
		return "实际出站连接超时，代理或 HTTPS 目标未在时限内响应"
	case strings.Contains(s, "403"):
		return "代理拒绝 HTTP CONNECT（403），请核对代理访问策略"
	case strings.Contains(s, "502"), strings.Contains(s, "503"):
		return "代理无法建立到 HTTPS 目标的隧道（502/503）"
	case strings.Contains(s, "eof"), strings.Contains(s, "connection reset"):
		return "代理或 HTTPS 目标提前关闭连接，请核对协议及 CONNECT 支持"
	default:
		return "实际 sing-box 出站 HTTPS 检查失败；代理未返回有效响应"
	}
}
