# Shared sing-box configuration transactions

The production configuration is the authority. Both tzsingbox and sbbot may edit
it. They submit changes to the host controller, which holds its process mutex and
cross-process `apply.lock` throughout validation, activation and rollback. The Bot
has full configuration read/write functionality through a root-authenticated Unix
socket. It needs no privileged container, host PID namespace or Linux capabilities.
Its configuration bind mount may remain read-only because all writes use this API.
The Web peer cannot use the root-only `/sbbot-*` endpoints (SO_PEERCRED).

Every edit retains its immutable opening snapshot and SHA256. Before saving, the
controller re-reads the production file and three-way merges base, desired and
latest. Independent map fields, tagged inbounds/outbounds, users and unambiguous
route predicates merge. Concurrent scalar edits, ambiguous route identities,
duplicate route predicates during a concurrent edit, and concurrent reordering
are rejected with a refresh message. Existing array order is retained. New entries
are inserted relative to their next surviving anchor. The final byte hash is
checked again under the shared lock immediately before atomic write.

The controller checks the original and candidate using sing-box check, writes an
fsynced backup and transaction journal, atomically replaces the configuration,
restarts sing-box, and checks service/listener health. Verified Bot UUID bindings
also check the actual user path and expected exit IP inside the transaction. Any
failure restores the exact original bytes and snapshots, restarts and checks the
original service. Interrupted transactions recover before accepting requests;
external uncooperative edits cause recovery to fail closed with backups preserved.
Snapshot restoration removes exact recorded additions; it never restores whole
old configuration files over newer work.

REALITY SNI changes coordinate the single standard HAProxy REALITY ACL with the
same transaction, including HAProxy syntax validation, version comparison, reload,
health and exact rollback/recovery. Unrelated ACLs are retained. Creating new
independent listeners opens only their needed TCP/UDP UFW ports if UFW is active;
existing allows are retained and rollback removes only rules added by that
transaction with the dedicated comment. This host uses nftables: UFW status works
without CAP_NET_RAW and fails without CAP_NET_ADMIN. The controller consequently
needs CAP_NET_ADMIN for this feature; sbbot keeps cap_drop ALL.

Configuration generation uses two spaces and a final newline; historic compact
snapshot hashing remains unchanged. A semantic no-op neither rewrites nor
restarts sing-box. Unknown fields and array order are preserved. The Bot no longer
normalizes every direct user's routes during unrelated saves. Its quota enforcer
retains Web-owned reject rules (including their method/extension fields). Manual
pause state is read from the live config rather than replayed from stale SQLite
state. Automatic quotas own only their narrow logical reject rules.

Successful Bot saves re-read the merged production configuration. Inotify refreshes
open read-only Bot user/traffic panels after other manager writes, without changing
unsaved edit snapshots. The existing Agent inventory feed refreshes Web state.
There are no competing background configuration-copy loops. Edit snapshots expire
safely when evicted or after a controller restart.

Keep RuntimeDirectoryPreserve=yes so a controller restart preserves the mounted
socket directory. The controller needs AF_NETLINK for probes/firewall operations.
Only the configuration, state, HAProxy/UFW configuration and named firewall lock
files are writable in its systemd sandbox. Manual editors must participate in the
same locking protocol; writable-descriptor detection and final CAS provide an
additional fail-closed check for uncooperative writers, not a universal OS lock.
