# 节点控制与凭据边界

Web/监控 Agent 不挂载生产 sing-box 配置。独立宿主机控制器 `tzsingbox control` 使用固定配置路径、固定 sing-box 二进制与固定 systemd 单元；只监听 Unix socket，校验调用 UID。接口不接受命令、可执行文件、任意配置路径或订阅下载 URL。systemd 沙箱见 `scripts/tzsingbox-control.service`。

## 独立授权与按需分享

管理员角色之外还必须具备 `control_permissions` 中的独立权限：`copy`、`import_shadowrocket`、`import_v2rayn`、`view`、`change`、`restore`。普通用户不会使用该管理员权限表；仅通过独立的 `user_operations` 与具体节点授权访问自己的 UUID。详见 [逐 UUID 操作说明](admin-operations.md)。权限不自动授予新增管理员；由宿主机操作者通过 `grant-control` 命令明确配置：

```sh
CONTROL_ADMIN=your-admin CONTROL_ACTIONS=copy,import_shadowrocket,import_v2rayn,view,change,restore DB_PATH=/your/data/tzsingbox.db /your/tzsingbox grant-control
```

所有操作复核当前会话、角色、节点与独立权限；变更类请求检查 Origin/CSRF。状态接口只接受不透明节点 ID。两分钟、一次性的 nonce 绑定会话、用户、节点；预览后产生新的确认票据，绑定控制器计划与配置哈希。分享、预览和确认票据不能互换。所有响应 `Cache-Control: no-store`；审计不含地址、UUID、密码或链接。

真实入站配置是唯一分享源，出站 TAG/内部 SOCKS/管理端口不能分享。分享支持 VLESS TCP+REALITY 和 Shadowsocks SIP002（包括单密钥 2022）；不支持的传输、入站或无可信对外映射的回环监听返回明确错误。控制器根配置中的 `endpoints` 必须由操作者核实公网映射，不能把监控 IP 当作入口地址。多用户入站由管理员明确选择认证资料。REALITY 公钥用 X25519 从服务端密钥派生，私钥从不返回 Web。

Shadowrocket、v2rayN 通过客户端的“从剪贴板导入”使用标准单节点 URI；不通过 URL 查询参数携带凭据，不伪造不通用的应用深链。浏览器复制后提示“复制成功”，不能证明客户端已经导入。未安装原生客户端时，只能核验 URI 规范和浏览器交互，不能宣称原生客户端实测通过。2022 密码按 SIP002 使用百分号编码的 userinfo。

监控 API/WS 不返回分享资料。只有具备对应操作和节点权限的用户主动操作后，受保护 POST 才按需返回单份连接凭据。查看窗口关闭或撤权后移除内容；敏感复制失败时不自动展开链接。浏览器和剪贴板必然接触用户主动请求的必要凭据，不承诺浏览器绝对保密。

## 出站更换与实际恢复

独立 Go Adapter 接受明确单节点 URI，拒绝未知参数和不支持的语义。可应用子集为 SOCKS5、HTTP(S)、SS AEAD/单密钥 SS2022、VLESS TCP/raw（TLS/REALITY）、Trojan TCP/TLS、Hysteria2（TLS、可选 salamander）。VMess TCP JSON 可离线解析预览，当前不允许应用；WS/gRPC、插件、端口跳跃、跳过证书校验和 pinSHA256 等未实现语义明确拒绝。预览中的目标脱敏，不返回凭据；解析与配置检查不代表连接可用。

只给目标入站新增专用出站及带入站 AND 条件的路由，插入原 route 规则之前；原有认证条件、rule-set、拒绝规则、其他入站及共享出站不变。兜底规则位于原规则之后，不能绕过原拒绝规则。原始映射、依赖哈希和具体新增项保存在 root-only 快照中。恢复撤销实际新增项，保留原路由，绝不强制 direct。恢复前检查原始路由/依赖和目标入站未被外部改写；有冲突时拒绝覆盖。

确认后解析目标 DNS，拒绝回环/私网/管理地址，将实际拨号地址固定为已校验公网 IP，保留 TLS SNI，避免 DNS 重绑定；这意味着受控出站不会自动跟随该域名后续 IP 变动，需要重新预览应用。候选配置不进行订阅下载。

## 事务、生效与回滚

该版本没有经验证的无中断更新入口。上游 1.13.15 Clash PUT `/configs` 是空操作，SIGHUP 会关闭再创建实例。本实现明确使用固定 `systemctl restart sing-box.service`：全部现有连接会短暂断开并重连。界面预览和二次确认必须说明该风险。

1. 单实例锁及跨进程 flock；候选计划绑定配置哈希，写入前再次 CAS；不覆盖外部并发变更。
2. 保留原文件及 SHA-256，候选通过固定二进制 `sing-box check`，验证依赖与范围；在独立临时 sing-box/SOCKS 实例检查新出口。
3. 先持久化恢复事务，再 fsync+原子替换；固定 systemd restart 生效，检查服务、所有 TCP 入站监听及目标真实入站连通性。
4. 失败恢复原文件、重启并验证服务；快照持久化失败同样回滚。写入启用时中断事务由控制器下次启动恢复；写入关闭时保留事务并拒绝启动，不触碰生产配置；若检测到外部配置冲突则停止并保留备份，不能盲目覆盖。
5. 保存最小恢复快照和脱敏审计；审计轮换限制为两份约 4 MiB。原配置备份保留，不自动清理用户回滚资料。成功出口证明绑定准确配置哈希；更换/恢复或依赖变化不能复用旧路径的验证缓存。

仅经过路径验证的 Shadowsocks 或 TCP REALITY VLESS 入站允许写入。`write_enabled` 默认为 false；只有完成隔离验证、明确授权以及全部写入者协调后才能启用。外部工具不参与同一锁时必须保持关闭；哈希 CAS 不能代替跨写入者独占。当前 sbbot 不参与该锁，生产没有启用写入。

根配置示意（只存在宿主机，不能提交真实配置）：

```json
{"config":"/etc/sing-box/config.json","state":"/var/lib/tzsingbox-control","socket":"/run/tzsingbox-control/control.sock","binary":"/usr/local/bin/sing-box","unit":"sing-box.service","peer_uid":65532,"peer_gid":65532,"write_enabled":false,"exit_file":"/var/lib/tzsingbox-inventory/applied-exits.json","endpoints":{"public-inbound":{"host":"node.example.org","port":443,"verified":true}}}
```

Web 配置 `CONTROL_SOCKET` 并只挂载 socket 所在目录，不挂载 root 配置/备份；`CONTROL_SERVER` 必须对应登记的服务器 ID。未配置控制器时保留安全的离线预览，生产写入和凭据导出仍硬拒绝。

## 复用和验证

复用既有 UI dialog、Toast、SVG、卡片 Map、图表、WS、会话、权限、历史与别名入口。成熟玻璃组件仅用于只读设计参考，未复制私有业务源码。URI Adapter 独立实现，不复制 sbbot 源码。

定向 Go 测试覆盖共享 direct 的多入站身份/差分、selector/URLTest/多级依赖、未知规则、历史和缓存兼容、权限/CSRF/重放/凭据边界、真实配置恢复、校验失败和自动回滚。显式设置 `TZSING_TEST_SINGBOX=/usr/local/bin/sing-box` 才运行独立合成实例切换测试，不调用生产 systemd 或读取生产数据库。
