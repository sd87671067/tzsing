# Delete confirmation and policy saving

The deletion entry created a modal containing only a selector and a button labelled
“配置预览”. It did not create cancellation or deletion buttons there; the next
confirmation used the generic “确认应用” label. This was a DOM/action construction
problem. The existing confirmation button was not conditionally hidden by CSS.

The deletion entry and second confirmation now expose “取消” and “删除节点”.
The shared modal awaits the operation, shows its existing inline spinner, rejects
repeat submissions and dismissal while pending, and retains errors on failure.
Retries acquire new one-use plans. Successful deletion refreshes the snapshot and
node management list. Outbound deletion retains all server-side reference checks;
UUID deletion retains its scoped Control transaction, config validation and rollback.
The existing description rule bounds long text so actions fit small safe viewports.

Production policy GET and preview returned HTTP 200 with ready=true, while apply
returned HTTP 503, “策略事务未提交，原策略保留”. The running executor used
uuid-admission-v2 and all fourteen UUID/name registrations matched the configuration.
Inside Control's systemd mount namespace the policy directory was read-only:
SQLite returned SQLITE_READONLY (8), “attempt to write a readonly database”.
ProtectSystem=strict was enabled but ReadWritePaths omitted the policy directory.

The service now explicitly permits that directory and manages it with StateDirectory.
The capability handshake, exact identity checks, CSRF, administrator checks and
session-bound, expiring single-use plans remain required. Failed transactions log
only the node hash and SQLite error locally, without exposing identities to clients.
The live executor already reads the shared durable ledger for payload admission;
no sing-box binary update is needed for this fix.

WebKit additionally retained an invalid internal datetime segment after clearing
the field: the first native submission was rejected despite validity.valid=true.
Normalizing a genuinely empty date on input clears that engine state; incomplete
invalid dates are still rejected. No alternate submit/validation bypass is used.

The shared policy fields accept an empty date as unlimited, round GiB to bytes,
and retain timestamp seconds when only the quota changes. Blank/zero quotas remain
unlimited. Existing account periods, usage and historical monitoring are preserved.

Targeted Go tests cover HTTP policy commits/replay/persistence, exact executor
identity proofs, fourteen-identity isolation and rejection of referenced outbound
deletion. The disposable real sing-box network-namespace tests exercise fourteen
REALITY identities, TCP/UDP accounting, expiration/quota edits and blocking,
shared-listener deletion and activation failure rollback. Browser interaction tests
use explicitly synthetic API responses for error injection; they do not claim to
exercise production configuration writes. Chromium and WebKit cover 320/390/1280
widths, cancellation, safe button hit testing, policy field combinations, errors,
retry, loading and success feedback. Formal validation runs from a disposable tzsing
source copy inside the verified sd87671067/go-emby-test checkout; no go-emby
production code or deployment is changed.
