# Operator-approved host response (optional)

Response is **disabled by default**. The original monitoring endpoint/token remain read-only. A separate action MCP endpoint delegates to a local privileged broker. Configure mandatory human approval before enabling the new client connection.

## Scope

- `disconnect`: terminate one logind SSH session and its processes. Does not prevent reconnection or restore killed work.
- `quarantine`: temporarily block the source IP on the configured **SSH destination ports**, then terminate the selected session. Other SSH connections from that IP are affected. Default: 900 seconds; maximum: one hour. Other ports and the account itself are not disabled.
- `dry_run=true`: record a no-effect validation result, including for protected sessions. No firewall/session changes. Still requires client approval.

This is limited SSH containment, not complete account isolation, malware removal or revocation of stolen keys.

## Authorization boundary

**Human approval is enforced by the MCP client.** In Rakazo, create exact `require_approval` rules for both `mcp__host-sentinel-response__execute_session_action` and `mcp__host-sentinel-response__execute_process_action` and register the new server with slug `host-sentinel-response`. The verified Rakazo version resolves explicit require-approval rules before Auto Review. Recheck this rule after upgrades or renaming the connection. Other clients need equivalent mandatory human gating.

**The broker independently enforces host safeguards.** A proposal records the exact host, action, session ID, username/UID, source IP, leader PID/start time, boot ID, ports, expiry, duration, reason and dry-run flag. Execution must match it unchanged. Live identity and protection rules are checked again. Proposals expire after five minutes by default. Each is consumed durably before effects; replay returns its result rather than executing twice. A crash during execution leaves an indeterminate audit record that must be inspected manually.

The broker cannot prove a human clicked a client button. **Anyone with the action Bearer token or access as its allowed Unix UID has delegated action authority.** Store the token only in trusted client credentials and root-owned service configuration; never expose it to agent prompts or ordinary monitoring clients. Tool annotations are not an authorization boundary. Keep the separate read-only token for routine monitoring.

## Install

```sh
sudo install -m 0644 deploy/host-sentinel-response.service /etc/systemd/system/host-sentinel-response.service
id -u host-sentinel
```

Configure the optional section in `/etc/host-sentinel/config.toml`:

```toml
[response]
enabled = true
socket = "/run/host-sentinel-response/control.sock"
state_dir = "/var/lib/host-sentinel-response"
allowed_uid = 999 # replace with actual host-sentinel UID
listen = "127.0.0.1:8788"
token_env = "SENTINEL_RESPONSE_TOKEN"
allowed_hosts = ["localhost", "127.0.0.1", "::1"]
protected_networks = ["192.0.2.10/32"] # replace with verified management sources
protected_users = ["root", "host-sentinel"]
process_allowed_uids = [1000] # verified ordinary user; empty disables process signals
protected_process_names = []
ssh_ports = [22]
max_quarantine_seconds = 3600
proposal_ttl_seconds = 300
```

Add an independent random token (at least 32 characters) to root-owned `secrets.env`. For Docker use a specific bridge IP and explicit Host allowlist. The privileged broker has no TCP listener, checks the connecting Unix UID, and uses a root-owned socket directory not writable by other users. Its state directory must not be inside the monitor's writable state or another unprivileged directory.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now host-sentinel-response
sudo systemctl restart host-sentinel
```

Register the action MCP connection **after** the human approval rule exists. Keep the broker and monitor on the same binary version. The monitor retains its unprivileged account and `NoNewPrivileges`; it receives no sudo permission.

| Tool | Effect |
|---|---|
| `get_response_targets` | Read live SSH session identity and eligibility |
| `get_session_action_proposal` | Store an expiring proposal; no host effects |
| `execute_session_action` | Execute the exact human-approved proposal |
| `list_response_actions` | Read the latest 50 durable audit entries |

## Verify and operate

Real operations refuse non-SSH/local/system sessions, root/system UIDs, protected usernames, invalid/local source addresses and protected management networks. IPv4-mapped IPv6 addresses are normalized. Changed process identities cannot be substituted after approval. At most 32 unexpired proposals may be outstanding.

First request `dry_run=true`, review its complete approval card, and approve it yourself. Confirm the audit result has `dry_run: true` and no effects. **Never approve a real action solely to test the UI.** A deployment agent must not impersonate the human approval click.

Quarantine lazily creates only `inet host_sentinel_response`. Other firewall tables are never flushed or rewritten. The owner marker, port policy, timeout sets and rule structure are verified before inserting an element. Kernel timeouts expire even if the broker stops. A reboot removes this nonpersistent table; blocks are not reinstalled automatically. Do not persist timed elements as permanent firewall rules.

If insertion succeeds but session termination fails, the audit reports `quarantined: true`, `disconnected: false`; the block still expires. Matching SSH traffic is dropped even if a TCP connection has not timed out. Processes that escaped the session scope may remain running.

Inspect or remove a block early through your trusted administrator shell:

```sh
sudo nft list table inet host_sentinel_response
# Substitute a verified IPv4 address; use ssh6 for IPv6.
sudo nft delete element inet host_sentinel_response ssh4 '{ 203.0.113.99 }'
```

Early unblock is intentionally not an MCP tool in this version. Audit lives in `/var/lib/host-sentinel-response/actions.db`; correlate the proposal ID with Rakazo's approval record. Disabling the action connection, setting `response.enabled=false`, restarting the monitor and disabling the broker leaves the read-only monitor available. Existing kernel timeouts continue to expire.

## Isolated kernel test

The ignored Linux test validates actual nftables JSON and expiry. Run the compiled library test executable only in a disposable network namespace:

```sh
sudo unshare --net env HOST_SENTINEL_ISOLATED_NFT_TEST=yes \
  target/debug/deps/host_sentinel-TEST_BINARY_HASH \
  response::tests::nft_kernel_schema_and_expiry --ignored --exact
```

It refuses PID 1's network namespace, requires explicit opt-in, and never calls `loginctl terminate-session`.

## Emergency process termination

`get_process_target(pid)` reads live PID/UID/name/start ticks/boot ID/cgroup and eligibility. `get_process_action_proposal(pid, signal, reason, dry_run)` prepares an immutable proposal; `execute_process_action(proposal)` requires its own exact human-approval rule. `terminate` sends SIGTERM; `kill` sends SIGKILL and may lose unsaved data. Escalation requires a new proposal and approval. Only one process receives a signal: no process-group kill, child-tree kill, service stop or restart-policy changes. Signal delivery is reported separately from observed process exit. A supervisor may restart the application.

Only explicitly configured ordinary UIDs (>=1000) are eligible. Root/system/setuid processes, the monitor UID, PID 1, management shells, SSH daemons, fixed critical names and configured protected names are refused. Cgroups containing host-sentinel/rakazo are protected. This is a conservative guard, not a complete service dependency analysis; review the target and consequences in the approval card.

Linux pidfds pin the process before identity revalidation and signal delivery. Unsupported kernels fail closed with no numeric-PID fallback. See [pidfd_send_signal](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html). The broker adds only CAP_KILL to its existing CAP_NET_ADMIN capability; it exposes no arbitrary signal or shell command. The same durable one-use audit covers session and process actions.
