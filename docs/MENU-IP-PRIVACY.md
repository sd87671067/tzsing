# 菜单权限与 IP 可选信息

普通用户的“更换节点出站 IP”和“管理个人出站”共用用户管理中的 `change` 操作权限。个人出站 GET、创建/编辑/删除预览、检测、确认应用都在服务端重新读取此权限；预览 nonce 不保留撤销前的授权。管理员不受此普通用户开关限制。权限保存沿用现有 WebSocket 断开、会话权限刷新、菜单关闭和自动重连流程，无需重新登录。未引入逐 UUID 出站授权表，也不修改绑定或流量历史。

IP 信息弹窗保留今日、本月、累计流量及原统计逻辑，移除顶部实时计量技术说明。每个数据源只显示自己的规范化响应，不用节点快照补齐来源缺失字段。

## 可靠字段边界

- IPinfo：保留 IP、国家、城市、ASN、运营商；ISP 只采用显式非空 `isp`，或官方 `asn` / `as` 对象明确 `type=isp` 时的 `name`。`privacy.hosting=true` 或 `is_hosting=true` 规范化为“机房”。ASN、公司分类或运营商名称不推断住宅或机房；`isp` 分类不等于住宅。当前未提供明确住宅证据时不显示住宅。
- IPPure：独立解析 `asOrganization`、`country`、`countryCode`、`city`、`asn`、`fraudScore`；`isResidential=true` 显示“住宅”，明确 `isDatacenter=true` 显示“机房”。只有响应确实有非空显式 `isp` 才提供 ISP；当前官方示例没有该字段，正常隐藏，不把 `asOrganization` 复制成 ISP。`isBroadcast` 不解释为原生/住宅/机房；`isNative` 仅在明确布尔值存在时显示。
- 两种类型同时为真时不显示分类；false 不反推另一种类型。空值、unknown、N/A、null、undefined 等清理为空并通过 omitempty 隐藏。
- 仍使用现有专用出站 PathClient、出口 IP 一致性校验、独立来源缓存及服务端凭据；不增加外部请求、套餐或前端 Key。

官方字段参考：<https://ipinfo.io/developers/ipinfo-api>、<https://ippure.com/MyIP-Info-API>。

定向验证包括 `internal/egress/optional_intel_test.go`、现有出站权限与检测测试，以及 `scripts/test_menu_ip.cjs`（隔离 TestAdminBrowserStage，Chromium/WebKit，320/390/1280，深浅模式）。ISP 四组合中的显式字段为合成夹具，验证可选字段处理，不代表现有套餐承诺返回该字段。
