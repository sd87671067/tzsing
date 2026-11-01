# 2026-11-01 执行器与出站授权部署记录

生产 sing-box 已替换为完整协议构建 1.13.15-tzsing-policy-v2，并在明确授权下完成整实例重启。原生产配置 JSON 校验和保持不变，443、REALITY 密钥、14 个 UUID、出站和路由未被此激活动作修改。运行时 UUID/认证名注册集合与生产配置精确匹配。

Control 实际状态为 ready=true，14 个 UUID，quota_enforced=true、expiry_enforced=true。旧配置没有非零额度和到期日，继续保持原值，不擅自添加限制；后续通过管理员策略接口设置后由数据路径执行。带版本心跳和 UUID 注册证明是开放编辑的实际条件，不以普通监控心跳代替。

出站和权限行为见 [出站授权说明](OUTBOUND-PERMISSIONS.md)。正式测试仅使用 sd87671067/go-emby-test main 545b840c953095c506dc63402cec35910e8d3e66 的独立工作区：

| 检查 | 最终退出码 |
| --- | --- |
| 链式解析、逐 UUID 路由、权限隔离、nonce 与个人节点生命周期 | 0 |
| 旧复制权限兼容、撤权恢复、到期/额度/预留与执行器身份证明 | 0 |
| 用户删除后的个人出站所有权隔离 | 0 |
| 三层 detour 实际 HTTP/HTTPS、SOCKS、VLESS、Trojan、Shadowsocks、Selector/URLTest 载荷 | 0 |
| 后台探针动态成员固定及未知状态 | 0 |
| Chromium/WebKit 授权面板、个人节点表单、二次确认、三档宽度与明暗主题 | 0 |
| Go 构建、JavaScript/Python 语法及 diff 检查 | 0 |

隔离测试首次使用空 Direct 作为 detour，被 sing-box 拒绝；修正为三层有效代理后通过。扩展回归发现复制权限对出站清单的额外依赖，已修正。界面测试调整为独立登录上下文后 Chromium/WebKit 均通过。以上失败均未当作成功报告。

首次 Web 发布在健康验证时遇到部署脚本自己的配置锁，状态接口返回 409，自动回滚成功；生产执行器未回滚。修正锁释放顺序后重新部署成功。保留生产旧二进制、配置、一致性数据库备份和最近健康 Web 镜像；SQLite 账本不被旧备份覆盖。

磁盘清理只覆盖可重建 Go 缓存、BuildKit 缓存、本次临时测试二进制和无容器引用的旧候选镜像。没有删除 volumes、未知测试数据、生产运行依赖、证书或密钥。emby_tg_admin、授权服务、tzsingbox 及执行器数据库 quick_check 均为 ok；运行中服务健康。sbbot 源码和数据保留，没有为健康检查擅自启动原本未运行的维护任务。

动态成员没有运行时证明、链路未知、循环或不支持的本地文件依赖时返回明确失败，不伪造出口。未进行持续吞吐压测；崩溃未决预留继续采用文档中的保守占额语义。

最终磁盘统计（十进制 GB）：清理前已用 30.71 GB、可用 8.89 GB；清理后已用 23.68 GB、可用 15.92 GB；净释放 7.03 GB（6.55 GiB）。实际清理 /root/.cache/go-build、/root/go/pkg/mod/cache/download、BuildKit 缓存、本次临时测试二进制和无容器引用的 tzsingbox:recovery-cbe09ad。
