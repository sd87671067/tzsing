# HTTPS 接入

初始化生成的 `secrets/agent.crt` / `agent.key` 只服务本机 Agent 的 TLS 通道，不能当作公网可信证书。浏览器入口需要自己的域名、DNS 和受信任证书。不要提交任何证书、私钥或 `.env`。

在自己管理的 HTTPS 反向代理中，将 `.env` 中完整 `URL_PREFIX` 前缀转发到 `http://127.0.0.1:18880`，保留路径和 WebSocket Upgrade，并正确转发 Host / X-Forwarded-Proto。如果反代在容器里，127.0.0.1 指容器自身，应使用管理员配置的专属网络与服务地址。独立 Caddy 示例：

```caddyfile
monitor.example.com {
    handle /replace_with_your_prefix/* {
        reverse_proxy 127.0.0.1:18880
    }
    respond 404
}
```

替换域名和前缀；仅对你拥有的入口应用，不覆盖其他服务配置。页面/API/WS 都必须使用相同 HTTPS Origin。Cookie 为 Secure、HttpOnly、SameSite，所有写请求要求 Origin 与 CSRF Token。

远端 Agent 报告需要 HTTPS。如果由反代终止 TLS，服务端 `TRUSTED_PROXY` 必须指定准确的反代对等 IP，只有该 IP 的 `X-Forwarded-Proto: https` 被信任，不接受任意地址段或用户提供的转发头。也可将独立 TLS Agent 端口通过受信任证书公开，先完成证书/网络设计。

本机 Agent 可连接 `https://127.0.0.1:19443/PREFIX/api/agent/report`，`ca` 指向生成的证书。浏览器始终走公共可信 HTTPS。证书轮换只更新本项目证书和 Agent CA，保留回滚副本，不清理其他业务证书。
