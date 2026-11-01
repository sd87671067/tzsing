# tzsingbox

轻量、多服务器 sing-box 出口监控。Go + 原生 JavaScript/CSS/Canvas + SQLite WAL + WebSocket；无 Vue、React 或 Node.js 构建/常驻依赖。中心服务以 UID 65532 在只读 distroless 容器内运行，宿主机 Go Agent 使用独立受限身份。

## 独立部署

需要 Linux、Docker Compose v2、OpenSSL、自己的域名和 HTTPS 反向代理。仓库不包含预编译程序、数据库、运行配置、账户或凭据；Dockerfile 从源码构建，无需私有文件。

```bash
git clone https://github.com/sd87671067/tzsing.git
cd tzsing
sudo bash scripts/init.sh https://monitor.example.com
docker compose ps
```

初始化生成随机路径、回环 Agent 通道证书并交互式读取管理员密码，密码通过标准输入交给 Argon2id，不写入文件或日志。公开入口配置详见 [HTTPS](docs/HTTPS.md)。`PUBLIC_ORIGIN` 必须与浏览器 HTTPS Origin 完全一致，不能带路径。`.env` 的 `URL_PREFIX` 是统一页面/API/WS 路径；随机路径不能代替鉴权。

Compose 默认仅绑定 `127.0.0.1:18880` 和 `127.0.0.1:19443`，不依赖其他项目的 Docker 网络。不要把内部 HTTP 端口直接暴露公网。既有代理需另行接入本机 HTTP 或独立 Docker 网络；不要未经核实修改其他业务入口。

## Agent 与节点发现

管理员登记服务器并保存仅出现一次的 Token；部署方法和最小配置见 [Agent](docs/AGENT.md)。同一服务器身份只运行一个 Agent。

- 节点身份是「服务器 ID + 原始 Tag」绑定的不透明持久 ID；同 IP、同类型、同名称均不会合并。
- Direct 不要求 IP 或流量即可展示，实际代理必须有对应出站的出口验证结果才进入监控。验证暂时失败保留上次结果，并明确显示缓存状态。
- 受限的协议清单补齐 Clash API 可能折叠的 Direct，排除未被实际路由绑定的代理和内部 API 辅助节点。清单启动读取，30 秒校验配置变化，WebSocket 同步到浏览器。
- Selector、URLTest、Block、Reject 不进入监控/节点管理；历史记录、身份及独立计数保留。管理员授权列表包含尚未验证 IP 的实际代理。
- 清单只含 Tag、协议和绑定关系，Agent 无需获得生产 sing-box 认证配置。路径映射需人工审核；生产路由变化时隔离探针停止自身路径验证，不能自动信任旧映射。新 Direct 仍展示，新增代理保持待验证。

## 权限与密码

普通账户默认无权限。管理员按服务器分组使用复选框授权，支持搜索、全选、取消、半选、数量和保存状态。授权页随 WS 的节点变化刷新，并以低频校验补充尚未验证的代理清单；未保存的勾选会保留。服务器、节点、主机指标分别授权；节点访问必须同时取得服务器和该节点的授权。全选只保存当时的明确 Tag，新节点不会继承权限。旧通配授权升级时会被展开为当前节点，保留既有主机权限。撤权立即关闭旧 WS，后续 API/历史/导出重新检查权限。

密码允许中文、Unicode、空格和特殊符号，原样保存到 Argon2id（随机盐、32 MiB、2 轮），长度为 14–256 Unicode 字符且不超过 1024 字节；不 trim、不归一化、不要求字符类型。会话和 Agent Token 只保存摘要。用户仅可修改个人别名；管理员可设全局中文名称、到期时间、月额度、账期日和时区，不改变原始 Tag。

全局开关默认：原始 Tag 关闭、到期时间关闭、流量限制开启。普通 API、WS、历史及 CSV 都遵守后端过滤；管理员管理接口可查看 Tag。

## 出口与 IPinfo

出口 IP 由每个实际出站经 HTTPS ipify 验证；Direct 使用其实际直连拨号路径，不能把另一个 Tag 或主机默认出口的 IP 当成证明。代理需经审核的专属 SOCKS 路径接入真实 sing-box 出站；不能用同一共享代理端点冒充多个已验证路径。

仅在 Agent 服务端设置 `IPINFO_TOKEN_FILE`（推荐）或 `IPINFO_TOKEN`，勿放在浏览器、Git、命令行参数或日志中。IPinfo 使用 Authorization Header 查询已经验证的 IP，只补充 API 实际返回的国家、城市、ASN、运营商、IP 类型、托管属性；无字段就隐藏，不生成风险评分。不同套餐字段不同，参考 [IPinfo 文档](https://ipinfo.io/developers/ipinfo-api)。

相同 IP 共享有界 512 条、24 小时缓存，各 Tag 独立计量。请求随探针路径发送，有超时、全局间隔、指数退避、429 冷却；保守预算为每 Agent 每日 400 次、每月 8000 次。设置可写 `IPINFO_CACHE_FILE` 可持久化预算和元数据，必须保留该状态。多个 Agent 共用账户时需按套餐总额规划，当前不是跨服务器的全局额度协调器。Token 不写入缓存。元数据刷新失败保留旧值并标记缓存；出口自身失败也保留上次成功出口。

## 界面与资源

紧凑卡片显示可见列表连续编号、中文名称、直连/中转、在线状态、出口、双向速率和本月已观测流量。按需展开历史、IP 归属、连接数及来源。Canvas 支持折线/面积/柱状图和实时、1h、24h、7d、30d；复用 WS，180 个实时点、720 个历史聚合点、有界缓存、离屏暂停，全部图表和动画在浏览器计算。

统一设计变量、22px SVG、44px 点击区域、深浅主题、左侧弹簧玻璃抽屉、遮罩、键盘和焦点返回、iPhone 安全区、Toast、骨架和减少动画。WS 增量更新已有卡片，不丢失展开状态和滚动位置。

## 流量统计边界

**这是已观测下界，不是精确计费。** Clash `/connections` 按连接 ID 与单调计数差分，`chains[0]` 归属一个实际出站，逻辑选择器不重复计量。轮询间短连接、关闭尾段、API 中断和未上报前重启可能造成漏计。不按 IP 合并，不分摊整机流量，不把快照估算冒充完整计费。

保留实时、今日、本月、历史累计、月额度/剩余和趋势；历史默认保存 30 天（可设 1–90），账期按当地日历处理月底与时区。Agent 暂时断网但继续采样时，内存累计恢复后上报；逐分钟分布不可还原。精确计费的技术路线与限制见 [统计方案](docs/ACCOUNTING.md)，不会擅改生产 sing-box。

## 构建、检查和回滚

```bash
go test ./internal/auth ./internal/adapter ./internal/model ./internal/egress ./internal/store ./internal/server ./internal/agent
CGO_ENABLED=0 go build -trimpath -o bin/tzsingbox ./cmd/tzsingbox
docker compose build web
```

Go 1.24+，Linux amd64/arm64 可交叉构建；交叉构建不代表 ARM64 实机验收。网络/生产测试默认跳过，须显式 opt-in 和指定本地凭据路径。正式测试目标受操作者环境约定约束，不应自动使用任何其他业务仓库或生产数据库。

更新前保留旧健康镜像、二进制、配置及 SQLite 在线一致性备份；只更新本项目容器/Agent，禁止 prune 或覆盖历史库。检查 HTTPS、容器、Agent、数据库完整性、授权及实际节点数后再完成部署。回滚镜像应使用独立 Compose override 指向旧镜像并 `--no-build` 启动，默认保留现有数据库。涉及权限语义变化时，先验证旧版本能执行当前权限；不通过恢复旧授权/旧数据库绕过撤权。备份数据库不是自动回滚步骤。
