# Go Agent

在控制台登记服务器后获得一次性 Token。每台服务器一个身份，Agent 通过 HTTPS 主动报告，不监听端口。对目标架构构建并安装：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/tzsingbox-agent ./cmd/tzsingbox
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tzsingbox-agent
sudo install -d -m 0750 -o root -g tzsingbox-agent /etc/tzsingbox
sudo install -d -m 0755 /usr/local/lib/tzsingbox
sudo install -m 0755 bin/tzsingbox-agent /usr/local/lib/tzsingbox/tzsingbox
```

将下列示例以 root:tzsingbox-agent 0640 写入 `/etc/tzsingbox/agent.json`，替换占位符，不提交实际文件。`token` 必须是登记时的完整 Token；Clash API 保持原有本机监听和密钥，Agent 只读访问 `/proxies` 和 `/connections`。

```json
{
  "server_id": "server-1",
  "token": "REPLACE_WITH_REGISTERED_AGENT_TOKEN",
  "url": "https://monitor.example.com/PREFIX/api/agent/report",
  "ca": "",
  "clash_url": "http://127.0.0.1:9090",
  "clash_secret": "REPLACE_WITH_EXISTING_CLASH_SECRET",
  "inventory_file": "/var/lib/tzsingbox-inventory/outbounds.json",
  "sample_seconds": 2,
  "exit_seconds": 1800,
  "proxies": []
}
```

`ca` 留空使用系统信任根；本机回环 TLS 通道应配置自己的 CA 文件。不要使用跳过 TLS 校验。

## 发现清单

有些 sing-box/Clash 版本只暴露一个标准 Direct。推荐由 root 的只读配置导出器持续原子写入最小清单，不给 Agent 读取生产出站凭据的权限：

```json
{
  "routes_verified": false,
  "outbounds": [
    {"tag":"direct-a","type":"direct","bound":true},
    {"tag":"direct-b","type":"direct","bound":true},
    {"tag":"relay-a","type":"socks","bound":true}
  ]
}
```

清单由原配置的 `outbounds` 协议信息及 route/selector 引用图生成，不能按名称、IP 或类型去重。`bound` 表示代理实际被路由引用；所有真实 Direct 始终保留。API 内部合成的 GLOBAL/DIRECT 不会代替原 Tag。示例 `scripts/path-probe.py` 只读默认 `/etc/sing-box/config.json`，每 10 秒核对摘要并导出 Tag/type/bound；Agent 每 30 秒读取清单，实际同步上限约 40 秒加报告/WS 延迟。支持通过 `SINGBOX_CONFIG`、`TZSINGBOX_CONFIG_DIR`、`TZSINGBOX_INVENTORY_FILE` 指定路径；输入为有效 JSON，配置目录合并/JSONC 场景需另行提供经过验证的只读清单导出器。不要把生产配置放入仓库或容器。

导出器仅在存在已审核 `route-attestation.json` 且生产配置摘要一致时启动 tzsingbox 自有 `probe.json` 隔离客户端。无证明时只导出清单，不开展路径探测；配置摘要变化会停止自己的探针、禁用旧路径验证，但继续同步新节点清单。重新验证映射后再重启自有导出器/Agent。绝不自动修改/重启生产 sing-box。

## 出口验证

`proxies` 只接受经管理员确认的专属探针路径。`mode: singbox_route` 通过回环 SOCKS 抵达目标 sing-box 实际出站；`server`/`port` 为这个专属路径。Direct 若有绑定接口、源地址、IPv4/IPv6 策略等，应由隔离 sing-box 客户端复制相应 Direct 拨号选项，每 Tag 一个本机专用 SOCKS 路径。不要为检测修改生产配置。仅当 Direct 等价于宿主机默认拨号时才可使用 `mode: direct`。

```json
{"tag":"direct-a","mode":"singbox_route","server":"127.0.0.1","port":29001,"eligible":true}
```

`routes_verified` 必须与已审查路径一致。新/失效路径不自动继承可信状态。每个真实入站始终展示，出口未知或没有 IP 不影响入站卡片；探针出站本身不生成入站卡片。保留旧成功出口并标记缓存不代表新路径已验证。

## IPinfo 与 systemd

把 Token 单独写入 `/etc/tzsingbox/ipinfo-token`，权限 root:tzsingbox-agent 0640。在 Agent unit 中设置：

```ini
[Service]
Environment=AGENT_CONFIG=/etc/tzsingbox/agent.json
Environment=IPINFO_TOKEN_FILE=/etc/tzsingbox/ipinfo-token
Environment=IPINFO_CACHE_FILE=/var/lib/tzsingbox-agent/ipinfo-cache.json
StateDirectory=tzsingbox-agent
StateDirectoryMode=0700
```

通用 unit 模板见 `scripts/tzsingbox-agent.service`。IPinfo Token 无需出现在中心服务、前端或 Compose 中。缓存包含 IP 元数据和请求预算，应保留，不应上传。日报/月报额度为单 Agent 保护，多个 Agent 共用 Token 需核算账户总额度。

只安装/更新 tzsingbox 自有 unit 和二进制。启动前验证 Token、证书、清单和权限；运行后核对服务器心跳、所有 Direct 数量和验证状态。不得以测试为由重启生产 sing-box。建议为只读导出器使用单独 root unit，以限制生产配置访问，Agent 自身始终无写入生产配置的权限。

导出器的 systemd unit 在 `ProtectSystem=strict` 下应设置 `StateDirectory=tzsingbox-inventory` 与 `StateDirectoryMode=0755`；清单写到 `/var/lib/tzsingbox-inventory/outbounds.json`（root:tzsingbox-agent 0640）。生产配置与 `/etc/tzsingbox` 保持只读，不给导出器整个 `/etc` 的写权限。
