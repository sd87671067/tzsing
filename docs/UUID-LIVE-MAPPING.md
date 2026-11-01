# UUID 实时身份归属

节点身份仍由服务器、协议实例和 UUID 摘要确定；共享监听器只用于定位认证配置。显示名称优先使用管理员别名，然后使用配置中的用户 name，最后自动编号。个人别名仍覆盖个人视图。修改显示名称使用 PATCH /api/admin/nodes，只修改 nodes.name，不修改认证配置、权限或任何计数。清空别名恢复配置 name。旧节点 ID、权限、历史和配置保持不变。

## 实际发现与实现

只读研究本机 sbbot：优先读取 metadata.user / auth_user；标准 sing-box 未导出这些字段时，其实现使用完整 auth_user 路由规则，或受管理用户的专属 selector 链识别用户。SQLite 保存连接采样差量、日/月/累计用量；周期检查额度和到期，再生成按 inbound AND auth_user 的拒绝规则并应用配置。这是连接快照观测，不是没有损失的持久账单。

tzsing 独立实现上游公开协议适配，没有复制私有业务代码。可信清单为每个 UUID 导出其 name、UUID 摘要和完整认证规则摘要。只接受单 inbound、单 auth_user、显式 route/outbound 且无附加条件的规则，字符集受限以避免 String() 表示歧义。Agent 必须同时匹配完整 rule、协议监听器及预期出站链，才将连接归属到 UUID。共享出站本身不构成身份。未知或冲突的连接明确保持未归属。连接 ID 去重；已识别连接不能将基线借给另一个 UUID。

标准 Clash 导出的完整 rule 来源于经过认证的 metadata.User 匹配；其 upload/download 是该连接的双向字节计数。状态名为 rule_user_observed。无连接显示 0 B/s；API 故障显示不可用，不能用 0 掩盖故障。Agent 上报、事务去重、SQLite 累计和按权限过滤的 WebSocket 复用原有路径。

## 计量边界与限制

连接快照会遗漏两个采样点间完成的短连接和关闭尾段，Agent 崩溃/断网也可能丢失尚未持久化的增量。因此每日、每月和累计都是已观测下界，不能冒称完整账单或用于严格月额度封禁。可选 V2Ray 用户计数已在隔离实例验证，能覆盖正常关闭连接；生产构建未包含 with_v2ray_api，不能未经授权替换或重启。

生产配置由受限控制器接管前须先停止其他独立写入者。当前新增 UUID、独立路由、启停和删除均经一次性确认、版本检查、配置校验、原子写入、重启、健康检查及失败回滚。共享 sing-box 重启会中断连接。逐 UUID 月额度和到期自动停用尚无可靠执行器，不能宣称生效；旧元数据保留，PUT 拒绝新的非零限制，PATCH 重命名保持旧设置。详见 [当前配置管理说明](CONFIGURATION-OWNERSHIP.md)。

## 本轮定向验证

正式测试位于私库 sd87671067/go-emby-test main f95149bccb7b9b7a5aa986b56b0ff19008454c21 的全新隔离工作目录；tzsing 放在独立隐藏工程，私库业务源码未修改。

- 只读生产验证：14 个 UUID 均有独立规则绑定与 name；实际快照 42 条连接均可归属，双向差量与独立计算一致。这不是对每个生产 UUID 主动造流。
- 独立网络命名空间：14 个合成 UUID 共用 REALITY 443、同一出站，逐个传输不同大小上传/下载；实际 Clash rule 映射逐项一致，V2Ray 用户计数在连接关闭后仍精确匹配有效负载。
- 真实隔离计数经认证上报、SQLite、API 和 WebSocket 一致；重复上报返回 409，不重复累计。
- 独立身份、未知规则、重复连接、认证名复用、无连接归零、别名和配置 name 变化、旧元数据保留、权限及错误限制请求拒绝的定向测试。
- Chromium/WebKit：14 张紧凑管理卡、单行排列、320/390/768/1440 宽度、深浅主题、三点菜单、别名修改、详情 Modal、WebSocket 与无原生提示框。UI 使用隔离夹具，仅作展示/交互证据。

以上为前轮监控验收记录。后续配置接管已验证新增、切换、恢复与删除事务；超额和到期自动拒绝仍未实现。

公开上游协议依据：

- https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/clashapi/trafficontrol/tracker.go
- https://github.com/SagerNet/sing-box/blob/v1.13.15/route/rule/rule_item_auth_user.go
- https://github.com/SagerNet/sing-box/blob/v1.13.15/experimental/v2rayapi/stats.go
