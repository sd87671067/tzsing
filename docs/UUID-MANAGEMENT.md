# Authentication identity management

A monitored authentication identity is scoped by server, inbound tag and the
SHA-256 digest of its unique configured user name. Credentials remain on the
restricted host controller. Rotating a UUID with the same unique name retains
its monitor ID, aliases and grants. Renaming a configured user creates a new
identity; old grants are never transferred automatically.

The existing node settings and exact grants apply independently to these
identities. A parent inbound grant does not authorize its children. A shared
inbound remains an unassigned traffic bucket; its traffic is never copied or
divided between identities. Standard Clash connection snapshots without an
attested authentication field cannot supply per-UUID bytes, active connections,
or device counts. Those measurements remain unavailable. Observed inbound
traffic is a lower bound, not exact billing.

The protected node menu can view or copy only the selected identity's share
profile. Import uses the existing clipboard workflow. The server resolves the
opaque node ID against the current report and passes the identity digest to
the controller. The controller resolves it against current configuration,
requires a unique match and rejects another user's profile ID. Dedicated action
permissions, CSRF checks, session-bound single-use nonces and auditing remain
required. Closing the dialog clears the displayed sensitive link.

Identity-specific route changes and restoration are disabled until routing,
rollback and network probes support that exact identity. An identity action
must never silently modify the parent inbound. Shared outbound probes are not
presented as verification of every UUID. The controller's existing production
write gate is preserved.

This change manages existing identities. It does not add, disable or delete
production accounts. Such lifecycle operations require a separate transaction
with configuration conflict detection, route references, rollback and precise
verification. No additional listener is created. Multiple UUIDs use the existing
inbound users array and the existing shared front door.

References: [VLESS users](https://sing-box.sagernet.org/configuration/inbound/vless/)
and [route auth_user](https://sing-box.sagernet.org/configuration/route/rule/).
