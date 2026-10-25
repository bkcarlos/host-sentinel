# Bounded read-only investigation tools (v0.4)

These five tools extend the monitoring MCP to twenty tools. They do not expose a shell, arbitrary command arguments, paths, SQL, service restarts or configuration changes. The separate response MCP still has seven tools and retains per-action human approval.

| Tool | Input and result |
|---|---|
| `get_session_processes` | `session_id`: current exact logind SSH session cgroup, PID/PPID tree, UID, executable path, RSS and short CPU estimate |
| `get_session_connections` | `session_id`: current TCP/UDP IPv4/IPv6 endpoints, state and owning session PIDs, host network namespace only |
| `get_service_status` | Optional `unit`; omission lists the exact service allowlist; selected status properties, restart count and resource counters |
| `get_service_logs` | `unit`, optional RFC3339 `since`/`until`, `limit`: latest bounded journal page, default 15 minutes/30 rows; maximum 24 hours/100 rows |
| `get_login_timeline` | Same time/user/IP/pagination fields as `get_auth_attempts`, with `kind` omitted or `success`; each accepted login plus correlated open/close/disconnect evidence |

## Enable live session inspection

Service status/log queries run as the unprivileged monitoring account, using fixed `/usr/bin/systemctl` and `/usr/bin/journalctl` commands. The account needs journal read permission for logs. Units default to `ssh.service`, `sshd.service`, `systemd-logind.service`, `host-sentinel.service` and `host-sentinel-response.service`. Configure `[mcp].allowed_services` with exact names, up to 32; an empty list disables service queries. No wildcard or client-supplied command options are accepted. Review a unit's log content before adding it.

Session inspection is disabled by default. It uses two fixed read requests over the existing root broker's UID-checked Unix socket. Enable the broker following [RESPONSE.md](RESPONSE.md), then add these fields **inside the corresponding existing sections**:

```toml
[mcp]
diagnostics_socket = "/run/host-sentinel-response/control.sock"

[response]
allow_read_diagnostics = true
```

For the supplied hardened broker unit, install the optional capability drop-in:

```sh
sudo install -d -m 0755 /etc/systemd/system/host-sentinel-response.service.d
sudo install -m 0644 deploy/read-diagnostics.conf /etc/systemd/system/host-sentinel-response.service.d/read-diagnostics.conf
sudo host-sentinel --config /etc/host-sentinel/config.toml check
sudo systemctl daemon-reload
sudo systemctl restart host-sentinel-response host-sentinel
```

This opt-in adds `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` to the broker: cross-UID `/proc/PID/fd` directories require directory access, and their links/executable symlinks are protected by [ptrace access checks](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html). It increases the broker's OS-level privilege; the application only exposes fixed metadata reads and never invokes ptrace, reads process memory, or offers a root command runner. The network-facing monitor remains unprivileged. Existing `CAP_NET_ADMIN`/`CAP_KILL` are retained for previously enabled response features. The broker has no public listener. This is not a separate isolation boundary from the existing broker; protect its socket/client credentials as described in RESPONSE.md.

Disable session diagnostics by removing `diagnostics_socket`, setting `allow_read_diagnostics = false`, removing this drop-in, reloading systemd and restarting both services. Existing response approvals are independent.

## Bounds and interpretation

- Process queries scan at most 8192 PIDs and return at most 128 processes. The CPU sample spans approximately 200 ms and is normalized to whole-machine capacity. It is not a sustained load measurement. PID/start-time, cgroup and logind session identity are rechecked; live snapshots are still non-atomic.
- Connections inspect at most 256 file descriptors per process and return at most 256 sockets. Other network namespaces, Unix sockets, packets, previous connections and processes moved outside the session cgroup are not covered. Inspect `partial`, `truncated` and unavailable counters. Empty results do not establish no activity.
- Service commands have a 5-second timeout, output caps (32 KiB status, 512 KiB journal), fixed argument arrays and no shell. Logs are tail pages, not counts. SSH workers often log from session scopes; use indexed auth tools for whole-range SSH totals. Querying `ssh.service` alone can miss those worker records.
- Log messages are untrusted data. Common credential assignments, Bearer values, URLs and obvious private-key markers are redacted; this is best effort and cannot identify every secret. Do not add secret-bearing services casually. Status omits ExecStart and environment. Process tools do not collect arguments, environments, file contents or shell history; existing logs can themselves contain application-chosen text.
- Timeline counts are successful login starts in the query window. Failure/invalid-user counts are deliberately omitted, with `failure_statistics.status=not_queried`; query authentication tools without a kind filter to measure them. Lifecycle correlation uses the same boot/PID, before the next success for that PID, bounded to 24 hours/100 records; it may extend beyond the requested end. It is not a kernel-stable process identity. Duration uses monotonic timestamps from acceptance to PAM close, when available. PAM close is distinct from TCP disconnect. Aggregate open/close totals are never paired to infer individual sessions.
- Current active status requires a fresh (45 seconds or less) session snapshot and matching login evidence. No match, stale snapshots or missing closes mean unknown. Each timeline includes evidence IDs and coverage metadata. Concurrent retention/backfill can change lifecycle lookups relative to the initial page.

Suggested agent sequence: explicit time-range SSH counts and coverage → per-login timeline → current session details and automation receipts → current process tree and sockets → relevant allowlisted service status/logs. Do not identify an operator or classify compromise from frequency, shared keys or a quiet snapshot alone. Historical executed commands require an independently deployed audit collector beforehand; this release cannot reconstruct them.
