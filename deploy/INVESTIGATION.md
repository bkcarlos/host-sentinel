# SSH investigation (0.3)

The read-only MCP provides indexed evidence, backend time-range counts, session classification and coverage metadata. No investigation tool runs arbitrary commands, changes trust, approves an action, or records its own automation attribution.

## Tools

- `investigate_ssh_activity`: full-range statistics, bounded evidence page, source groups, current sessions, trust policy, receipts and coverage in one response.
- `get_auth_attempts`: filters `since`, `until`, `user`, `source_ip`, `kind`; pagination `limit` (1–100) and `offset`. Always use `total_matching_records`/`counts`, not page length, for totals.
- `get_session_details`: cached logind source, start, type, state and leader identity; linked login evidence and exact-session automation receipts when available.
- `get_trust_details`: configured matching conditions and optional event-specific matches. Labels/ownership notes are configuration claims, not proof of who used a key.
- `get_security_evidence`: one evidence ID and at most 100 related SSH process records, with cursor, boot ID, PID, timestamps and a bounded source message.
- `get_collection_health`: upgrade boundary, retention cutoff, reader heartbeat, latest backfill, restarts, parsing rejections and limitations.
- `get_automation_activity`: at most 100 recent root-authored receipts from a bounded 1000-file directory scan. Missing receipts mean unknown attribution.

Use explicit RFC3339 bounds with a timezone:

```json
{"since":"2026-10-25T20:17:00+08:00","until":"2026-10-25T20:26:00+08:00","limit":20}
```

The range is `[since, until)`, at most 31 days. Omitted bounds default to the last hour. Reuse the returned bounds for subsequent pages. UTC and Beijing ISO timestamps are formatted by the backend. Counts use one SQLite read snapshot and cover every indexed matching row, regardless of the page limit. The first/last timestamps refer to matching records; use `kind="success"` when asking specifically about successful logins.

`failure` counts failed authentication log records. `invalid_user` is a separate observation and must not be added to failures: sshd can emit both for one attempt. `session_open`, `session_close` and `disconnect` are lifecycle records, not additional authentications. Different authentication attempts within one connection can each fail; this is not a unique-connection counter.

## Evidence and coverage

Version 0.3 persists individual root-origin `sshd`, `sshd-session` and `sshd-auth` records. Collection follows those journal process names across systemd units because workers can move into session scopes. The legacy `ssh.units` field remains accepted for configuration compatibility but no longer restricts this selector. Root origin and process-name checks remain enforced. This is not a console/sudo/general command audit and does not defend against a compromised root account or falsified logs.

Evidence IDs are hashes of journal cursors. Live evidence, alert and detector/cursor updates commit together. Authentication records do not each trigger notifications; existing alert thresholds still apply. Evidence follows the configured retention period. Unknown auth prefixes are recorded as `unparsed_auth` when possible; rejected malformed records are counted separately by the live collector.

A user manager (`Class=manager`) is not an SSH login. Closing/stale entries are not active SSH connections. Live session-to-login matching requires the same boot, account, IP, leader/journal PID and monotonic start within 10 seconds. Missing matches remain unknown. Historical process correlation uses boot/PID and accepted-login boundaries, capped at 24 hours; it is not proof of human identity. Missing close records never imply the connection remains active.

Before this version, individual failed attempts and lifecycle evidence were not retained in SQLite. An administrator may backfill retained logs **as the monitor account**:

```sh
sudo -u host-sentinel /usr/local/bin/host-sentinel --config /etc/host-sentinel/config.toml \
  backfill-auth --since '2026-10-25T00:00:00+08:00' --until '2026-10-25T21:00:00+08:00'
```

Use an actual past end time. Backfill is bounded to 100,000 input records and 90 seconds; use smaller windows if needed. It is idempotent, never sends notifications, and never changes the live cursor or failure detector. Partial imports remain indexed, but the scan is marked incomplete. Only the latest backfill coverage interval is advertised; older imported rows remain queryable without claiming complete coverage. Backfilled trust matches use policy at import time, not historical policy. A completed scan covers only retained journal records, not logs that were vacuumed or never recorded. A live reader heartbeat is not proof of zero log loss.

## Trust and automation attribution

Optional fields on each existing `ssh.trusted` rule:

```toml
label = "Verified management source; shared by operator and automation"
owner = "Operations team"
verification_note = "Account/IP/key checked during an authorized deployment; individual operator unknown"
```

These fields explain a match and never weaken the account/network/key requirements. Historical evidence retains the rule snapshot captured during indexing.

For new automated sessions, an administrator can create a task receipt before the work:

```sh
sudo install -d -o root -g host-sentinel -m 0750 /etc/host-sentinel/automation.d
sudo /usr/local/bin/host-sentinel --config /etc/host-sentinel/config.toml \
  record-automation --session-id "$XDG_SESSION_ID" \
  --task-id 'deployment-2026-10-25' --label 'Authorized deployment'
```

The CLI requires root and a live SSH session, captures its actual logind identity, and writes a root-owned non-writable-by-group receipt. The monitor only reads these files. A receipt is a local operator claim tied to an observed session, not a cryptographic audit of every command or approval to perform an operation. It cannot retroactively identify old connections. Root can alter this audit; no tamper-proof guarantee is made. Archive older receipts administratively before the bounded directory scan reaches 1000 files.

For stronger future attribution, assign distinct SSH keys to human terminals and each automation identity and label those verified fingerprints. Existing keys are not automatically created, replaced or revoked by this release. Shared IPs/keys cannot reliably distinguish individual operators.

## Reporting contract

1. State the exact query bounds and coverage before interpreting counts.
2. Quote backend counts and formatted times; never derive a period total from the last N records.
3. Separate current active SSH sessions, managers and closing/stale entries from historical authentications.
4. Cite evidence IDs for suspicious observations and use follow-up tools to inspect them.
5. Distinguish a configured trust match, an operator receipt and proven human attribution.
6. Describe missing evidence as unknown. Neither high frequency nor a matching trusted key alone establishes compromise or automation.
7. Response actions still require the existing separate human-approval flow.
