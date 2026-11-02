# sing-box configuration formatting

Generated sing-box configurations use two-space indentation, expanded object and
array layouts, and one final newline. Map keys retain encoding/json's stable
lexicographic order. Arrays are never sorted: routing, DNS, selector and urltest
order stays intact. Unknown JSON fields remain part of generated configuration.

The transaction boundary also formats candidate bytes before validation, the
transaction's after-hash, and the atomic write. This formatter changes whitespace
only, retaining key order and number/string tokens without a decode/re-encode.
Repeated formatting is byte-for-byte idempotent.

The compact `canonical` encoding remains unchanged for historical baseline,
inbound, snapshot and journal hashes. CAS still compares the original file bytes.
Backups, rollback and interrupted-transaction recovery retain the exact original
bytes, including original whitespace. Candidate after-hashes cover the final
formatted bytes. Atomic write/fsync/rename behavior is unchanged.

Only strict JSON is supported. The existing generation parser rejects JSONC
comments and trailing commas; the formatter and apply boundary also reject them.
They do not strip comments or rewrite the original file on rejection. Supporting
JSONC would require a separate comment-preserving parser and mutation strategy.

Installing the controller does not rewrite the current config or restart
sing-box. New formatting takes effect during a subsequent normal configuration
change. Do not apply a production transaction merely to change whitespace.

Targeted validation includes token equivalence (including opaque extension
fields, credentials and large numeric literals), idempotence, historical hash
compatibility, CAS/rollback regression tests, and isolated sing-box check plus
HTTP allow/reject routing under both compact and formatted configurations.
Set TZSING_TEST_SINGBOX explicitly to run the isolated binary integration test.
