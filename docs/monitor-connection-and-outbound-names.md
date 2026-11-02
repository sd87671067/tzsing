# Monitor recovery and outbound display names

The old `connected()` stopped retrying when its single `/api/me` request failed.
The failure was reproduced in both browsers against the old public deployment:
a closed WSS followed by one synthetic HTTP 503 left the page disconnected.

`web/connection.js` owns one effective WebSocket, one reconnect timeout and an
abortable session request. Retries use equal jitter and exponential backoff capped
at 30 seconds; only received monitoring data resets the failure counter. Offline
and hidden pages pause; online and visible pages revalidate the session. Session
401 stops the lifecycle and exposes a persistent login notice. Handshake and
silent-stream deadlines recover half-open connections. Existing server Origin,
CSRF, secure cookies, ping/pong and permission checks remain enabled.

Outbound tags remain controller/config identifiers. Shared display names use the
existing `nodes.name` mapping keyed by `(server, tag)`. Existing
`outbound_registry` IDs/ownership are preserved; its name is updated transactionally
and used as a fallback for personal outbounds. No table or configuration field is
added. Admin catalogs return separate `tag` and `name`; snapshots/WSS add
`egress_name` and path `name`, while retaining raw tag disclosure rules. Viewer
choices still use permission-filtered opaque registry IDs. Equal names never
participate in identity resolution. Empty shared names fall back to the tag when
disclosure is allowed. Native select values remain IDs/tags, while option text and
confirmation descriptions use display names. Live updates patch existing DOM.

## Targeted validation

Run tests only in an isolated fixture under the verified private repository
`sd87671067/go-emby-test`, never in the production service/data directory.
Copy this module into that fixture before running the commands below. Set
`PLAYWRIGHT_MODULE` to the installed Playwright package. No full/race suite is
required.

- `go test ./internal/server -run '^TestOutboundDisplayNameAcrossCatalogsSnapshotsAndPersistence$' -count=1`
- `node scripts/test_connection_recovery.cjs` (Chromium and WebKit, deterministic network/session/handshake/visibility lifecycle cases)
- Start `TestAdminBrowserStage` with `TZSING_BROWSER_STAGE` pointing at a disposable directory, then run `scripts/test_outbound_display_names.cjs` against its fixture. This validates real TLS/WSS and HTTP 503 recovery, naming surfaces, responsive layouts and session expiry. The add UI uses a synthetic controller; no production outbound is created.
- Run `scripts/test_outbound_transactions.cjs` with a fresh stage and `TZ_SYNTHETIC_STAGE=1` to check save/delete/UUID confirmation retries.

Production acceptance must use public DNS and certificate validation for HTTPS
and WSS, preserve the database, compare the actual sing-box configuration hash
before/after rename and deployment, and retain a healthy Web image for rollback.
