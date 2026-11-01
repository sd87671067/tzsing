> 本轮 UUID 实时流量及限制执行状态见 [UUID 实时身份归属](docs/UUID-LIVE-MAPPING.md)。已接入完整认证路由规则映射；统计为已观测下界。独立限制、启停与删除尚未在生产生效。

# tzsingbox

轻量、多服务器 sing-box 入站监控与受限节点管理。Go + 原生 JavaScript/CSS/Canvas + SQLite WAL + WebSocket；无 Vue、React 或 Node.js 构建/常驻依赖。中心服务以 UID 65532 在只读 distroless 容器内运行，宿主机 Go Agent 使用独立受限身份。

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

- 节点身份以服务器和真实入站 TAG 为准；每个客户端入站单独展示，即使共享 direct、WARP 或相同出口 IP。显示名称不改变真实 TAG。数据库使用 `inbound:` 命名空间，防止与旧出站身份碰撞。
- 只读导出器枚举生产配置中每个真实入站 Tag（含 SOCKS/HTTP/TUN 等），生成不含凭据的入站/路由/出站依赖清单；tzsing 自有隔离探针不在生产配置中，不计入生产入站。具名认证用户另生成独立身份卡片；管理 API 和逻辑出站不生成卡片。
- VLESS 按服务器 + 入站 + UUID 摘要建模，一 UUID 一张卡；前端 ID 仍为随机内部 ID。改名保持身份，UUID 轮换成为新身份；旧用户名键通过一次性事务保留 ID、名称、授权及历史。共享入站保留诊断计数但不重复占卡。原生 V2Ray 用户计数适配器经过隔离验证，生产未启用；标准 Clash 无认证字段时 UUID 流量仍不可用。详见 [UUID 管理与能力边界](docs/UUID-MANAGEMENT.md)。
- selector/URLTest 使用运行时选择；按用户、目标、规则集分流或依赖不明时显示未知，不能猜测唯一出口。未知出口不隐藏真实入站卡片。
- sing-box 1.13.15 的 Clash `metadata.type` 为 `协议/入站TAG`，只按与清单精确匹配的值计量；缺失身份的连接不分摊。没有使用该字段的旧 Agent 仍按原出站语义处理。
- 新面板、汇总、图表和历史 API 不展示旧出站测量；节点 ID、名称、别名、权限、额度继续保留，不自动扩大入站授权。已确认废弃的测量可用 `scripts/retire_outbound_stats.py` 先预览、备份再定向清理，见 [入站检测与迁移](docs/INBOUND-MONITOR.md)。
- 清单每 30 秒刷新；路径依赖变化或未知时不复用旧出口证明。受控变更成功可通过绑定准确配置哈希的实际入站路径证明更新出口；其他未重新证明的路径保持待验证。

## 权限与密码

普通账户默认无权限。管理员按服务器分组使用复选框授权，支持搜索、全选、取消、半选、数量和保存状态。授权页随 WS 的节点变化刷新，并以低频校验补充尚未验证的代理清单；未保存的勾选会保留。服务器、节点、主机指标分别授权；节点访问必须同时取得服务器和该节点的授权。全选只保存当时的明确 Tag，新节点不会继承权限。旧通配授权升级时会被展开为当前节点，保留既有主机权限。撤权立即关闭旧 WS，后续 API/历史/导出重新检查权限。

密码允许中文、Unicode、空格和特殊符号，原样保存到 Argon2id（随机盐、32 MiB、2 轮），允许任意非空 Unicode 密码，取消业务最小/最大长度限制（HTTP JSON 请求体仍限制 64 KiB；初始化 stdin 同样限制 64 KiB，并拒绝超限，不截断）；不 trim、不归一化、不要求字符类型。会话和 Agent Token 只保存摘要。用户仅可修改个人别名；管理员可设全局中文名称、到期时间、月额度、账期日和时区，不改变原始 Tag。

全局开关默认：原始 Tag 关闭、到期时间关闭、流量限制开启。普通 API、WS、历史及 CSV 都遵守后端过滤；管理员管理接口可查看 Tag。

## 出口与 IP 信息来源

出口 IP 由每个实际出站经 HTTPS ipify 验证；Direct 使用其实际直连拨号路径，不能把另一个 Tag 或主机默认出口的 IP 当成证明。代理需经审核的专属 SOCKS 路径接入真实 sing-box 出站；不能用同一共享代理端点冒充多个已验证路径。

仅在 Agent 服务端设置 `IPINFO_TOKEN_FILE`（推荐）或 `IPINFO_TOKEN`，勿放在浏览器、Git、命令行参数或日志中。IPinfo 使用 Authorization Header 查询已经验证的 IP，只补充 API 实际返回的国家、城市、ASN、运营商、IP 类型、托管属性；无字段就隐藏，不生成风险评分。不同套餐字段不同，参考 [IPinfo 文档](https://ipinfo.io/developers/ipinfo-api)。Modal 支持独立的 IPinfo / IPPure 缓存；IPPure 仅调用官方自身出口接口，详见 [受控检测与字段边界](docs/INBOUND-MONITOR.md)。

相同 IP 共享有界 512 条、24 小时缓存，各 Tag 独立计量。请求随探针路径发送，有超时、全局间隔、指数退避、429 冷却；保守预算为每 Agent 每日 400 次、每月 8000 次。设置可写 `IPINFO_CACHE_FILE` 可持久化预算和元数据，必须保留该状态。多个 Agent 共用账户时需按套餐总额规划，当前不是跨服务器的全局额度协调器。Token 不写入缓存。元数据刷新失败保留旧值并标记缓存；出口自身失败也保留上次成功出口。

## 界面与资源

紧凑卡片显示可见列表连续编号、中文名称、直连/中转、在线状态、出口、双向速率和本月已观测流量。点击 IP 区域在独立居中玻璃 Modal 查看历史、IP 归属、连接数及来源，无效字段隐藏，IP 一键复制。Canvas 支持折线/面积/柱状图和实时、1h、24h、7d、30d；复用 WS，180 个实时点、720 个历史聚合点、有界缓存、离屏暂停，全部图表和动画在浏览器计算。

统一设计变量、24×24 viewBox / 24px SVG、44px 点击区域、右上角太阳/月亮主题切换、左侧弹簧玻璃抽屉、遮罩、键盘和焦点返回、iPhone 安全区、Toast、骨架和减少动画。WS 增量更新已有卡片，保留 Modal、筛选、排序和滚动位置。

管理员三点菜单的按需分享、客户端剪贴板导入、脱敏预览、出站更换及原始映射恢复见 [控制安全边界](docs/CONTROL.md)。管理员需额外独立权限与受限宿主机控制器；未配置时硬拒绝写入和导出。应用需明确确认 sing-box 重启造成的短暂断连，不把解析成功视为连接成功。所有用户可在导航中修改自己的密码（验证当前密码并退出旧会话）；管理员重置密码使用统一非空规则。初始化脚本交互输入不包含终端回车；直接调用 `init-admin` 时 stdin 字节原样使用，包括换行。

## 流量统计边界

**这是已观测下界，不是精确计费。** Clash `/connections` 按连接 ID 与单调计数差分，在权威入站清单启用时按 `metadata.type=协议/入站TAG` 精确归属；旧模式 `chains[0]` 只代表旧出站统计，不能冒充入站流量。逻辑选择器不重复计量。轮询间短连接、关闭尾段、API 中断和未上报前重启可能造成漏计。不按 IP 合并，不分摊整机流量，不把快照估算冒充完整计费。

保留实时、今日、本月、历史累计、月额度/剩余和趋势；历史默认保存 30 天（可设 1–90），账期按当地日历处理月底与时区。Agent 暂时断网但继续采样时，内存累计恢复后上报；逐分钟分布不可还原。精确计费的技术路线与限制见 [统计方案](docs/ACCOUNTING.md)，不会擅改生产 sing-box。

## 构建、检查和回滚

```bash
go test ./internal/auth ./internal/control ./internal/server ./internal/store ./cmd/tzsingbox
CGO_ENABLED=0 go build -trimpath -o bin/tzsingbox ./cmd/tzsingbox
docker compose build web
```

Go 1.24+，Linux amd64/arm64 可交叉构建；交叉构建不代表 ARM64 实机验收。网络/生产测试默认跳过，须显式 opt-in 和指定本地凭据路径。正式测试目标受操作者环境约定约束，不应自动使用任何其他业务仓库或生产数据库。

更新前保留旧健康镜像、二进制、配置及 SQLite 在线一致性备份；只更新本项目容器/Agent，禁止 prune 或覆盖历史库。检查 HTTPS、容器、Agent、数据库完整性、授权及实际节点数后再完成部署。回滚镜像应使用独立 Compose override 指向旧镜像并 `--no-build` 启动，默认保留现有数据库。涉及权限语义变化时，先验证旧版本能执行当前权限；不通过恢复旧授权/旧数据库绕过撤权。备份数据库不是自动回滚步骤。

## 安全升级与环境配置

`.env.example` 列出非敏感环境变量：`PUBLIC_ORIGIN`、`URL_PREFIX`、`TRUSTED_PROXY`、`CONTROL_SOCKET` 和 `CONTROL_SERVER`。实际 `.env`、`secrets/`、Agent JSON、控制器配置和 SQLite 仅保存在部署主机，不能提交。TLS 私钥按最小读取权限挂载；Agent/IPinfo Token 使用权限受限的文件，不通过浏览器或公开配置传递。

升级前在线备份 SQLite（使用 SQLite backup API，不能只复制运行中的 WAL 主文件），备份本项目配置并记录旧健康镜像。确认迁移兼容性后执行：

```sh
git fetch origin main
git merge --ff-only origin/main
docker compose build web
docker compose up -d --no-deps --no-build web
docker compose ps
```

仅更新 tzsing 自身组件；Agent 二进制更新应保留旧版本和自身服务回滚路径。数据库回滚不应自动覆盖升级后产生的历史和授权记录。

生产配置可能同时由其他工具改写。即使每个工具原子写入，未共享独占锁和版本校验仍会丢失更新；因此不能仅靠隔离测试通过启用写入。存在不协调写入者时，必须保持 `write_enabled=false`，后端拒绝更换/恢复，保留链接解析、脱敏预览、分享和配置校验。推荐此模式下 systemd 只读限制生产配置目录并阻止访问宿主机服务管理 socket。控制器即使发现中断事务，也拒绝在写入关闭时恢复生产配置，保留记录等待操作者处理。校验临时文件存放在控制器私有状态目录。

逐 UUID 限制的实际执行状态与本轮验收边界见 [UUID 执行状态](docs/UUID-EXECUTION-STATUS.md)。

现有 UUID 的独立出站、启停/删除事务和用户操作权限见 [操作与安全边界](docs/admin-operations.md)。本机生产写入者协调、到期自动停用和可靠月额度封禁尚未完成，不代表已开放生产执行。
