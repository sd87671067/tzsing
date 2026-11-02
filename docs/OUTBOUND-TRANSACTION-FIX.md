# Outbound transactions and runtime verification

The production configuration at investigation time contained Direct, SOCKS and
selector outbounds, with no Shadowsocks outbound remaining. Its historical SS
failure therefore cannot be attributed to a particular reference or nonce.
The production API did reproduce a referenced deletion returning only a generic
422 and an existing SOCKS probe returning 422 because the safe client field list
omitted `domain_resolver` and `domain_strategy`. A read-only candidate controller
with these fields supported returned a verified public IP through that proxy.

Deletion now checks current server references rather than refusing solely from
an older UI catalog. Errors identify sorted field paths and array positions,
and direct UUID users toward changing/restoring their outbound first. Safety
checks, scoped routes, DNS references, config CAS, locks, nonce consumption,
check/restart/health and rollback remain enforced. Successful deletion no longer
recreates the deleted node's display metadata.

Both UUID creation and outbound save now apply inside their confirmation dialogs.
The manual form now includes Shadowsocks method/password. DNS client fields are
accepted with the same recursive local-file/detour/TLS safety validation and real
sing-box check. Save executes inside the confirmation callback: pending applies
keep the dialog busy, block duplicates/closing, and retain errors for a fresh
single-use plan on retry. A preview never emits a save notification or leaves
the editor. Successful apply refreshes the list and retains the verified exit IP.

Formal validation runs in a clean worktree of sd87671067/go-emby-test, with the
tzsing source staged as a separate module. Only related Go tests and Chromium /
WebKit interactions are used; no full suite or race run. The REALITY integration
runs the production sing-box executable in a private network namespace, creates
outbounds via preview/apply, switches UUID A through SS/SOCKS/HTTP, restores it,
shares an SS outbound between A/B, rejects deletion while referenced, deletes it
after restoration, and tests restart/health rollback. Every switch and restore
is checked by real UUID-authenticated requests to an independent source-address
observer. The addresses 127.0.0.2/.3/.4/.5 are isolated observed source addresses,
not public Internet exit claims. HTTPS and chained selectors/urltest are checked
with real proxy connections in the same isolated namespace.
