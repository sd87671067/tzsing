# UUID 节点、候选校验与能力边界

VLESS 的管理单位是一个 UUID。可信宿主机清单将规范化 UUID（小写带连字符）计算为带域分隔的 SHA-256 内部认证摘要，再与服务器、入站组合；浏览器使用 SQLite 中随机生成的 node ID。清单、监控 API 和 WebSocket 不携带 UUID 或密钥。未具名账号也能建模；无效或重复 UUID 明确报告，不能猜测拆分。其他协议保留现有兼容行为。

首次 UUID 清单进入后端时，在已认证 Agent 报告事务中迁移旧用户名摘要键，保留随机 ID、全局名称、个人别名、授权、账期、额度元数据和历史。旧绑定只消费一次。改名不改变 UUID 身份；UUID 轮换不继承旧授权。冲突拒绝整个报告，不能合并两个节点。共享入站历史保留，VLESS 父入站不重复显示为卡片，也不授予子身份权限。

管理员“添加节点”使用现有受限 Unix socket 控制器读取脱敏目录和校验候选。需要管理员、独立 change 权限和有效会话；POST 必须通过 Origin/CSRF。Go 默认生成 UUID，也接受规范化手工 UUID，拒绝覆盖任何现有 UUID。候选仅在内存中追加 users，不创建监听器、密钥或服务；使用固定 sing-box check 后丢弃，不返回自动生成的认证资料。没有生产创建成功的提示，也不提前登记节点或授予普通用户权限。

选择已有实际出站时添加 inbound AND auth_user 精确规则。用户名由 UUID 派生为唯一内部认证名称，与展示名称无关。保留原拒绝规则和顺序；如果之前的路由可能截获新身份，则拒绝候选而非改变原策略。候选校验不是生产应用；新增 UUID 仍只有候选校验入口；已有 UUID 的独立出站、启停和删除执行器见 [逐 UUID 操作说明](admin-operations.md)，生产受写入协调门槛保护。旧入站控制继续保留哈希 CAS、锁、校验、备份、回滚和健康检查。

客户端 SNI（tls.server_name）与服务端 REALITY handshake.server 是不同配置。两者属于共享监听器，此页面只读。多个 UUID 沿用既有监听与外部 443 映射；本地监听端口不必为 443。不会擅自修改生产握手目标，也不承诺任意独立 SNI 可用。

## 流量

1.13.15 的 VLESS 在认证后设置 metadata.User。Clash JSON 不导出它，因此不能用 /connections 对 UUID 归属，更不能根据 IP、名称相似、端口或出口分摊。可选已认证扩展依旧只能提供连接快照下界。

原生 V2Ray StatsService 直接用认证后的 metadata.User 包装 TCP/UDP 转发计数，关闭连接后计数仍在。可选 Agent 参数 native_stats_url 只接受显式回环 HTTP 端点，通过标准 h2c/gRPC QueryStats（reset=false）读取。清单必须证明用户名全局唯一，并明确列入 experimental.v2ray_api.stats.users；重名、匿名、未启用用户不映射。需要含 with_v2ray_api 的 sing-box；默认构建未必包含该标签。

监控适配器首次读数作为基线，累计随后可见增量；失败为不可用，恢复可补到仍保留的进程计数。计数下降重新取基线，不猜测重启缺口。Agent 重启、sing-box 崩溃尾段、外部重置和配置/进程切换边界没有持久账单保证。因此标记 native_user_observed，仍为保守监控；今日、本月、累计和速率复用现有幂等报告、SQLite 累计和账期机制。**禁止将其当作精确持久计费或自动扣减依据。** 启用前必须核实接口属于正确进程且运行配置与清单一致；未提供运行配置证明时不得把文件配置当作进程证明。生产没有启用接口、没有替换 sing-box 或设置 native_stats_url。

隔离测试用独立网络命名空间、真实 REALITY 443、12 UUID、两条可区分出站路径传输，每 UUID 32768/65536 字节；连接关闭后上游计数和 Agent 归属均精确相符。该结果只证明本测试的业务负载口径，不包含 TLS/链路开销，也不宣称所有 UDP、mux 或崩溃情形已验收。

## 限制与未开放操作

- 现有额度、账期和到期字段保留为监控提醒；无可靠持久计费执行器，不会自动扣费、停认证或踢连接。
- 1.13.15 VLESS 用户选项没有每用户上传/下载限速。未实现新的数据路径限速执行器，配置项禁用，不能声称限速生效。
- VLESS UUID 不能识别物理设备；源 IP、连接数都不是设备数。可验证的后续方案是在认证后的连接/数据包路径设置共享每 UUID 并发会话计数和令牌桶，正确处理 TCP/UDP、mux、关闭、取消及热更新；本版本未接入，配置项禁用。
- UUID 新增保存、额度强制、到期停用仍未实现。已有 UUID 的单身份出站、更换恢复、启停和删除支持预览/确认/事务应用，但本机仍因 sbbot 未协调写锁而关闭生产写入。部署不重启生产 sing-box。
- UUID 出口尚无逐身份路径证明时继续明确未知；不会将共享 SOCKS 探针出口复制给每个 UUID。现有 IPinfo/IPPure、复制 IP 和历史组件保留，但没有可靠身份路径时不能展示虚构 IP。

## 验证

正式验证宿主为 sd87671067/go-emby-test 最新 main 下独立隐藏工程；生产配置、账户和数据库不用于写入测试。定向测试包括身份迁移/幂等/授权、12 空闲卡片、候选和原规则保护、禁用写入、CSRF、单 UUID 分享、Clash/原生计数、候选检查失败恢复，以及 Chromium/WebKit 移动视口。

真正的物理设备限额、带宽限速、配额/到期认证停用没有实现，因此没有将这些条目标为测试通过。原生客户端只验证标准 URI 与剪贴板流程，未冒充 Shadowrocket/v2rayN 实机测试。


版本依据：[VLESS 认证设置 metadata.User](https://github.com/SagerNet/sing-box/blob/v1.13.15/protocol/vless/inbound.go)、[Clash JSON 元数据](https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/clashapi/trafficontrol/tracker.go)、[原生用户计数器](https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/v2rayapi/stats.go)、[auth_user 路由匹配](https://sing-box.sagernet.org/configuration/route/rule/#auth_user)。


## 2026-11-01 链路修复

原生用户计数与 Clash 快照独立采集，Clash 不可用时仍能上报清单绑定的真实用户计数；出口与并发保持未知。上游懒创建计数器，双向均缺失时只建立基线、不宣称已验证零流量；单向缺失时不推进已有基线，不把另一方向补零。配置摘要或用户名绑定变化重新取基线，移除身份不能借用旧基线。

前端将“已配置”和真实连接状态分开，监控断连或计量不可用时清空曲线，长采样间隔重新开始。没有可靠认证连接数时显示“活跃未知”，不能将 Agent 心跳显示成 UUID 在线。额度继续明确标记为提醒；没有将提醒额度宣称为执行额度。

管理员目录新增逐项 capabilities（state、saved、effective、unit、reason）。当前所有限制 effective=false、saved=false，分别为 unsupported 或 disabled；候选预览独立记录尝试和成功/失败审计，不包含凭据。添加页复用原表单、分段选择、Modal、Toast 和主题 tokens，按四组组织；无执行器的项目以状态说明展示，不渲染假装可填写的数值/日期控件。

本次明确未交付生产 UUID 限制执行器，详见 [执行状态与验收边界](UUID-EXECUTION-STATUS.md)。
