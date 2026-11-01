# 入站监控、IP 来源和受控检测

现有入口 → 决策：`inbound_inventory` 继续从生产配置只读导出，每个真实 Tag 一项，取消协议白名单，补齐 SOCKS/HTTP/TUN。`adapter.inboundTags` 保持按连接元数据计量，用 `type` 保存入站协议、`egress_type` 单独保存出站类型。原 `Store.Present`、权限、节点 ID、WS、Canvas、`UI.bind/modal/notify/icon` 继续复用。原历史 Modal 增加卡片主体入口、来源分段和检查区域；没有第二套弹窗或轮询。旧出站 archive API、管理页档案及其 JS 分支删除；混合报告中的旧出站不进入新面板及汇总。

稳定身份为服务器 ID + `inbound:<原始 Tag>`，不按协议、用户、出站或出口 IP 合并。没有连接、流量、IP 或唯一出口的入站仍存在。序号由当前筛选排序后的可见列表连续生成。普通用户同时需要服务器和入站授权；增加入站不会自动扩大权限。未知快照连接只计“无法归属”，不分配给任何入站；流量继续标为连接快照已观测下界。

## 来源边界

IPinfo 使用原服务端 `IPINFO_TOKEN_FILE`，Authorization Header 认证；复用已有字段解析、预算、磁盘缓存与失效退避。受限主机检测服务需要同样的只读凭据文件和自己可写的缓存路径，不能把凭据传给 Web。多个进程共用同一账户时需合并核算账户额度，不能同时写同一个缓存文件。

IPPure 官方文档：<https://ippure.com/MyIP-Info-API>。公开 `https://my.ippure.com/v1/info` 无需在公开文档中提供 Token，只报告调用方自身的出口。Go 后端通过已核实的该出站专用 SOCKS 路径请求，并确认返回 IP 等于当前经验证的 IP；不能拿默认出口结果冒充其他节点，不抓取任意 IP 页面，也不使用名称相似的其他站点。字段仅采用实际响应的国家、城市、ASN、运营商、`isResidential` 和有效的 `fraudScore`；`isBroadcast` 不被解释为原生、住宅或机房。缺失字段隐藏。评分是来源的观测值，不能当作安全保证。

两个来源按来源与 IP 独立缓存 24 小时，IPPure 再绑定配置摘要和出站路径；失败短缓存一分钟。前端切换有效缓存不重复请求。IPinfo 原持久缓存及预算继续生效；互动来源内存缓存会在检测服务重启后失效。动态路由无法证明唯一出口、返回 IP 不一致、来源不可用或没有凭据时，显示自定义原因，另一个来源仍可使用。

## 检测范围

`POST api/node-inspect` 仅接受节点 ID、固定 action 和固定 source；目标、端口、凭据不由浏览器提供。沿用 session、CSRF、服务器/入站权限，长请求完成后再次校验会话、权限与路由版本；未公开原始 Tag 时检测响应也隐藏出站 Tag。管理员更换/恢复/分享仍走原来的独立权限门禁。

受限服务经原 Unix socket 调用，保持生产写入门禁关闭。配置读取、只读 `sing-box check`、配置本机地址的 TCP 连接和支持协议的测试凭据握手分别报告。当前真实握手支持原有 Shadowsocks 和 VLESS TCP+REALITY；其他协议显示未验证，UDP 入站不拿 TCP 结果冒充成功。握手使用配置中的一个测试凭据，仅代表被测凭据。临时进程是 tzsing 自有隔离客户端，不重启、不改写生产 sing-box。

出站解析复用配置依赖图和运行时 selector；配置摘要必须匹配，且专用回环探针必须有有效路径证明。唯一出站无法证明时返回“当前路径未知”。通过指定路径向固定 ipify HTTPS 端点对每个地址族各请求两次，分别记录成功率、耗时和 IP；与同地址族缓存比较。IPv6 不可用不抹掉 IPv4 成功。最近互动检测得到的 IP 只作为五分钟内、相同配置路径的来源查询依据，不写成新的流量或覆盖 Agent 流量记录。

状态为正常、异常、超时、未验证、无法确定。本机端口或本机协议握手永远不能证明公网可达；没有独立外部探测点时公网状态保持未验证。没有 ICMP 依赖。

每用户每分钟最多 12 次检测或 30 次来源查询；所有用户合计每分钟最多 90 次。受限主机同一时刻一个检测/配置操作，重复入站检测间隔 30 秒，重复来源间隔 5 秒。主机检查总预算 45 秒，单 HTTPS 请求 6 秒，来源请求 8 秒；Web 检测单独设置 50 秒请求预算，不扩大正常 API 时限。固定目标、禁止重定向、回环探针、配置本机地址范围和严格 JSON 字段共同防止任意扫描或 SSRF。

## 旧测量清理

先预览：

```sh
python3 scripts/retire_outbound_stats.py --database /path/to/monitor.db
```

核对后使用一个不存在的备份文件路径：

```sh
python3 scripts/retire_outbound_stats.py --database /path/to/monitor.db --backup /private/backup/before-retirement.db --apply
```

仅当服务器当前报告全部为真实入站身份时，该服务器已有旧出站身份才可成为候选。先 SQLite online backup 和 quick_check，再在事务内删除候选的 history、counters、daily_flow、monthly_flow、monthly、billing_usage、exit_cache 行；对应索引条目由 SQLite 同步删除，保留表和共享索引。用整表指纹保护账户、会话、服务器、权限、名称、别名、额度、审计等资料，并核对全部入站测量指纹及外键。脚本幂等，默认不删除；不清空数据库，不自动迁移或分摊旧流量。

## 定向验证

受影响的 adapter/model/egress/store/server/control/cmd Go 测试、Python 清单与迁移测试、JS 语法、Go build、diff 检查。`scripts/test_monitor_modal.cjs` 必须以 `TZ_SYNTHETIC_STAGE=1` 运行在合成独立数据库和 helper 上；覆盖 Chromium/WebKit、六档宽度、深浅色、Modal 焦点/滚动锁/遮罩/Esc、事件隔离、缓存、检测反馈、动态节点、授权及撤权。浏览器为移动视口与触摸模拟，不冒充 iPhone/Android 真机验收。生产检测仅执行受控只读请求，不用生产数据库做测试夹具。
