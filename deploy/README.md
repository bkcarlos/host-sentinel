# Linux systemd deployment

Build the release binary on Linux for the target CPU architecture. This is an explicit manual installation; nothing in `cargo build` changes system services.

```sh
cargo build --release --locked
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin host-sentinel
sudo usermod -aG systemd-journal host-sentinel
sudo install -m 0755 target/release/host-sentinel /usr/local/bin/host-sentinel
sudo install -d -m 0750 -o root -g host-sentinel /etc/host-sentinel
sudo install -m 0640 -o root -g host-sentinel config.example.toml /etc/host-sentinel/config.toml
sudo install -m 0644 deploy/host-sentinel.service /etc/systemd/system/host-sentinel.service
```

If the user already exists, skip `useradd`. Edit `/etc/host-sentinel/config.toml`:

- Set `state_dir = "/var/lib/host-sentinel"` and an appropriate host label.
- Verify your trust rules; do not copy example fingerprints.
- Configure Rakazo webhook and MCP only when ready.

Create `/etc/host-sentinel/secrets.env` with mode **0600**, owned by root, using a local editor. systemd reads it before switching to the service user:

```text
RAKAZO_WEBHOOK_TOKEN=replace-with-your-bot-webhook-secret
SENTINEL_MCP_TOKEN=replace-with-an-independent-random-secret-at-least-32-characters
```

Do not commit that file or put actual secrets in command history. Tokens must have no whitespace. `check` validates configuration but does not check environment secrets or send anything.

Verify access as the service account before enabling the service:

```sh
sudo -u host-sentinel journalctl --unit=ssh.service --unit=sshd.service --lines=5 --no-pager
sudo -u host-sentinel /usr/local/bin/host-sentinel --config /etc/host-sentinel/config.toml check
sudo systemctl daemon-reload
sudo systemctl enable --now host-sentinel
sudo systemctl status host-sentinel
sudo journalctl -u host-sentinel -f
```

Perform a controlled SSH login and confirm it appears in `list_logins`. Confirm an unknown test source produces an alert and reaches the intended bot; do not manufacture production CPU load just to test an alert. The repository's CPU tests exercise thresholds with synthetic samples.

Inspect local state with:

```sh
sudo -u host-sentinel /usr/local/bin/host-sentinel --config /etc/host-sentinel/config.toml status
```

After changing environment/configuration, restart the service. To stop collection, use `sudo systemctl disable --now host-sentinel`. Preserve `/var/lib/host-sentinel` for history and outstanding notifications. If repeated startup failures hit systemd's start limit, fix the error and run `sudo systemctl reset-failed host-sentinel` before restarting.

## Docker-host MCP access

Keep Rakazo's webhook URL on host loopback. For MCP calls initiated by Rakazo API/worker containers, choose a host bridge address reachable from both containers. Example only:

```toml
[mcp]
enabled = true
listen = "172.19.0.1:8787"
token_env = "SENTINEL_MCP_TOKEN"
allowed_hosts = ["172.19.0.1"]
```

Use your actual bridge address and firewall policy, not a blanket public bind. Configure Rakazo's remote MCP client with that address and the separate Bearer token. If Rakazo blocks private MCP destinations, use its documented setting for your version. This repository does not modify Rakazo or the firewall automatically.
