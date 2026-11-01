# 后续更新

当前状态以 [UUID 实时身份归属](UUID-LIVE-MAPPING.md) 为准：已增加标准 Clash 完整 auth_user 规则到 UUID 的真实连接观测映射。以下保留为前轮记录，其中“生产独立流量不可用”已被本轮修正；月额度、到期、限速和并发限制仍未生效；新增/路由/启停/删除当前状态见 [配置管理说明](CONFIGURATION-OWNERSHIP.md)。

# UUID 执行状态与验收边界

本轮是监控可靠性和管理界面修复，不代表生产独立限制已经实现。

## 已核实根因

sing-box v1.13.15 的 VLESS 认证在进程内设置 metadata.User；Clash TrackerMetadata.MarshalJSON 没有导出认证身份。Agent 只收到协议/入站，不能可靠对应共享入站的 UUID。可信清单仍可发现每个 UUID，SHA-256 内部身份经 SQLite 映射为随机 node ID，因此能显示独立卡片，但流量状态必须为 unavailable。SQLite、API 和 WebSocket不会把父入站用量分摊到子身份。

V2Ray StatsService 按认证后的用户计数，需要 with_v2ray_api、显式 stats.users 和全局唯一认证名。被调查的生产构建没有该标签，配置没有开启接口。启用需要替换/重新应用生产 sing-box，可能断开共享监听上的连接，且存在外部配置写入者；本轮没有执行这些变更。进程计数还没有覆盖崩溃尾段、重启和外部 reset 的完整持久计费保证，不能用于强制扣费。

官方版本依据：

- [VLESS 认证身份](https://github.com/SagerNet/sing-box/blob/v1.13.15/protocol/vless/inbound.go)
- [Clash JSON](https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/clashapi/trafficontrol/tracker.go)
- [认证用户计数](https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/v2rayapi/stats.go)
- [VLESS 用户配置](https://github.com/SagerNet/sing-box/blob/v1.13.15/option/vless.go)

## 当前执行能力

| 项目 | 隔离验证 / 生产状态 |
|---|---|
| 独立 UUID 流量 | 带 V2Ray API 的隔离构建真实可用；生产不可用，保持明确标注 |
| 月额度 | 现有 SQLite 配置只作提醒；完整计费与超额封禁执行器未实现 |
| 上传 / 下载限速 | 官方用户选项不提供；认证后数据路径执行器未实现 |
| 到期 | 自动停用执行器未接入，不保存假限制 |
| 并发连接数 | 原生计数接口不提供并发准入；执行器未实现，不能称为设备限制 |
| 启停 / 独立路由应用 | 唯一写入者接管后支持预览、确认和生产事务提交 |
| UUID 实际出口 IP | 没有身份路径证明时未知，不借用共享或默认出口 |

原路由、直连和中转候选继续按 inbound AND auth_user 精确匹配，保留已有拒绝策略和共享 REALITY 配置。当前不能安全无中断提交生产。没有为每个 UUID 新增监听器。

## 前轮隔离验收记录（保留）

正式验证仅使用 sd87671067/go-emby-test main f95149bccb7b9b7a5aa986b56b0ff19008454c21 的全新隔离工作目录，tzsing 源码置于独立隐藏工程；未修改私库业务源码。

- 独立网络命名空间运行同一上游 revision 的 V2Ray API 构建；12 个 UUID 共用隔离 REALITY 443。
- 第 i 个身份（i=0..11）实际传输上传 32768+i×1024、下载 65536+i×2048 字节。逐次核对各 UUID 独立计数和速率；两个实际出站使用不同源地址，关闭连接后仍能读取计数。没有使用前端模拟代替这些真实传输。
- 采集得到的真实计数经认证报告、SQLite、API 和 WebSocket逐项一致，重放报告返回 409 且不重复累计。
- 原生 h2c 缺失/半对计数、恢复、配置切换和移除绑定测试；Clash 故障时 Agent HTTPS 上报测试通过。该故障测试使用协议夹具，仅验证故障处理。
- 定向身份迁移、权限、CSRF、防重放、SQLite 重开持久化、账期和现有隔离配置失败恢复测试通过。没有数据库 schema 变更。
- Chromium/WebKit 移动视口：12 卡、深浅主题、6 种宽度、候选校验、单 UUID 分享、权限、WebSocket、过期曲线清除、禁用状态和自定义 Toast 均通过。UI 状态夹具仅测试展示，不是流量或限制执行证据；不是 iPhone 实机键盘验收。

以上通过项退出码均为 0。新增链路断言最初误将防重放响应期待为 200，按实际安全协议改为期待 409 后通过；测试控制器不接受任意 systemd 单元名导致首轮 UI 服务退出，恢复合法配置并保持 write_enabled=false 后通过。首次测试进程启动时目录尚未创建，未执行；创建后通过。

没有执行或通过 A/B/C 的真实限速吞吐对比、超额封禁、到期拒绝、并发拒绝、逐 UUID 在线启停和限制重启恢复。这些功能缺少执行器，仍为未完成。下一步需要在认证后连接/数据包路径实现按 UUID 的共享令牌桶、准入计数、到期检查和持久用量封禁，并覆盖 TCP、UDP、mux、崩溃、热更新与回滚；仅配置轮询或防火墙按 IP 限制不满足要求。
