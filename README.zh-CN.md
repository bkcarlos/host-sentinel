# Host Sentinel

Rust 编写的轻量 Linux 主机监控：SSH 登录检测、CPU 异常告警、Rakazo Webhook 通知和只读 MCP。采用 MIT 许可证，无需云平台账号。

完整配置、部署和故障处理见 [English README](README.md)。

## 功能

- 实时读取 systemd journal 中的 SSH 认证记录，支持新版 Ubuntu 的 `sshd-session`。
- 以用户名、IP 网段、密钥指纹组合匹配信任规则；未知来源成功登录时提醒。未知来源不等于已确认入侵。
- 同一 IP 在时间窗口内出现多条认证失败记录时汇总报警。
- CPU 持续高占用、相对滚动均值的持续突增、恢复通知，附最高占用进程。
- SQLite 保存日志游标、检测状态、历史事件和待发送通知；重启续读，通知失败自动重试。
- 提供 `get_status`、`list_alerts`、`list_logins`、`get_sessions`、`get_top_processes` 五个只读 MCP 工具。
- 不采集进程命令参数、环境变量，不提供执行命令或修改系统的 MCP 工具。

## 启动

```sh
cargo build --release --locked
cp config.example.toml config.toml
# 编辑配置，先保持 webhook.enabled=false
./target/release/host-sentinel --config config.toml check
./target/release/host-sentinel --config config.toml run
```

采集服务需要 Linux `/proc`、systemd 和系统日志读取权限。建议使用 [systemd 部署方式](deploy/README.md)中的独立用户。macOS 可用于开发、测试和查询已有数据库，不能运行 Linux 采集服务。

默认规则：CPU ≥85% 持续 3 分钟报警、≤65% 恢复；CPU ≥70% 且比前 5 分钟均值高 40 个百分点，持续 30 秒时报告突增；同一 IP 在 5 分钟内出现至少 10 条 `Failed …` 记录触发认证失败告警。`Invalid user` 单独记录，不重复计入失败阈值。首次启动从启动时刻开始读取，之后根据保存的游标续读。

## Rakazo

在 Rakazo 为目标机器人配置 Webhook secret，填入 URL，启用 `webhook.enabled`。同机部署可使用：

```text
http://127.0.0.1:3100/api/v1/bots/YOUR_BOT_ID/webhook
```

密钥通过 `RAKAZO_WEBHOOK_TOKEN` 环境变量提供。测试发送命令为 `host-sentinel --config config.toml test-webhook`，会真实唤醒机器人。收到 `ok: true` 仅表示 Rakazo 接收成功，手机/桌面通知需要另外验证。

通知关闭期间告警仍进入持久队列，重新启用时会发送积压告警。重试保留同一事件 ID，供 Rakazo 去重。该程序不会自动修改机器人、轮换密钥或更改提示词。

## MCP

启用 `mcp.enabled`，通过 `SENTINEL_MCP_TOKEN` 设置独立访问密钥，默认地址为 `http://127.0.0.1:8787/mcp`，请求必须带 Bearer token。

Rakazo 在 Docker 内运行时，容器的 `127.0.0.1` 不是宿主机。需要绑定宿主机的指定 Docker 网桥地址、配置 `mcp.allowed_hosts`，并限制为所需 API/worker 容器可访问。不要直接暴露公网或取消鉴权。也可用 `host-sentinel mcp` 提供 stdio，但客户端必须能读取同一个数据库。

登录历史与当前会话分别返回；查询结果附时间戳，避免把过期数据当成实时状态。进程 CPU 百分比按整机容量归一化，四核机器上单核满载约为 25%。

## 边界

当前检测范围是 SSH 认证和 CPU，不包含控制台登录、sudo 审计、文件篡改检测或机器学习。日志可能轮转，采样可能有间隔；请按 README 验证权限和告警链路。同机监控无法在整机宕机时自行发通知，完整宕机监测需外部心跳。待发送告警不会自动因过期删除，长期通知故障时需关注磁盘容量。
