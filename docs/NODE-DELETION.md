# 节点删除

入站和出站使用不同的删除入口。管理员仍需受限控制器、生产写入开关和 `change` 权限；普通用户不能删除生产节点。

- VLESS 按真实 UUID（兼容旧名称摘要）选中用户，只删除该用户，保留共享监听器、443、TLS/REALITY 和其他 UUID。最后一个 VLESS 用户继续受保护，因为当前应用流程要求验证未受影响的 UUID；该情况会明确拒绝。
- Shadowsocks、Trojan、SOCKS、HTTP、mixed、VMess、Hysteria/Hysteria2、TUIC、AnyTLS 按清单中的唯一认证名称/username 摘要选中实际 `users` 项。最后一个用户需要移除独立监听器；无用户模型的独立监听器直接按真实 tag 选择。引用无法安全移除时拒绝，不能把协议当成 VLESS UUID。
- TUN、TProxy、redirect 等系统入站不提供危险删除；重复 tag、重复认证名称、未知协议、未归属的复杂规则都会给出原因。
- 实际出站可在出站列表删除，必须没有显式或隐式引用。无 `route.final` 时首个出站是隐式默认出口。selector/URLTest 等逻辑或系统出站不能在此删除。

删除入站无需先恢复出站。控制器读取真实配置、身份和快照，在内存中一次完成精确快照规则清理、目标身份/监听器删除、目标专属路由和停用规则清理。既有出站永不随入站删除；系统创建的专属出站仅在内容与快照一致且无剩余引用时删除。共享出站、DNS、detour、selector 和其他用户的资源保持原样。复杂规则的目标归属无法证明时拒绝删除并报告路径。

候选校验后绑定配置哈希、快照哈希和两分钟单次计划。沿用跨进程锁、原配置校验、健康基线、写前 CAS、原子文件、事务恢复记录、一次受控应用及健康检查。失败恢复原配置和管理快照；外部并发修改不强制覆盖。成功后重新读取已应用配置确认身份或监听器不存在，再清理该目标的管理和停用快照。Web 端清理现有 UUID 绑定记录，不删除节点数据库行、审计或历史流量。

UI 直接使用现有确认 Modal；展示名称、协议、删除范围和重启影响，提交期间按钮内 Loading 并阻止重复提交。冲突在同一弹窗显示，可以重新获取计划重试；成功刷新列表并显示 Toast。不新增 CSS 覆盖层。

定向覆盖：`TestDelete*`、`TestOutboundDeletion*`、`TestIsolatedDeleteProtocolNodes`、`TestIsolatedRealityCreateShared443AndRollback`、`TestDeleteProtocolIdentityBoundaryAndAdminPermission` 和 `scripts/test_node_deletion.cjs`。真实进程测试只使用合成配置、临时目录和独立网络命名空间；浏览器测试覆盖 Chromium/WebKit、320/390/1280 宽度、取消、Loading、防重复、真实错误、重试和刷新。
