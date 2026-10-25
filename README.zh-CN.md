# Host Sentinel

Rust 编写的轻量 Linux 主机监控：SSH 登录检测、CPU 异常告警、Rakazo Webhook 通知和只读 MCP。采用 MIT 许可证，无需云平台账号。

完整配置、部署和故障处理见 [English README](README.md)。

## 功能

- 实时读取 systemd journal 中的 SSH 认证记录，支持新版 Ubuntu 的 `sshd-session`。
- 以用户名、IP 网段、密钥指纹组合匹配信任规则；未知来源成功登录时提醒。未知来源不等于已确认入侵。
- 同一 IP 在时间窗口内出现多条认证失败记录时汇总报警。
- CPU 持续高占用、相对滚动均值的持续突增、恢复通知，附最高占用进程。
- SQLite 保存日志游标、检测状态、历史事件和待发送通知；重启续读，通知失败自动重试。
- 提供 `get_status`、`list_alerts`、`list_logins`、`get_sessions`、`get_top_processes` 等只读 MCP 工具，并新增 `get_memory_status` 和 `get_top_memory_processes`，查询 RAM、Swap、内存压力、累计 OOM 次数和 RSS 前 20 个进程。
- 不采集进程命令参数、环境变量，默认监控连接只读，不提供通用命令执行。
- 默认监控连接保持只读。可选的独立处置连接支持“断开指定 SSH 会话”和“临时封禁来源 IP 的 SSH 访问并断开会话”，必须在客户端配置逐次人工审批。还支持对指定普通用户进程发送 SIGTERM 或 SIGKILL，必须逐次确认。详见 [处置工具与权限边界](deploy/RESPONSE.md)。

## 磁盘查询

`get_disk_status` 每 30 秒采集本地已挂载文件系统的总容量、已用/可用空间、使用率和 inode 总量/已用/可用/使用率，`get_status` 也包含磁盘快照。查询完全只读，不需要处置审批。可用空间不包含保留块，百分比按 GNU df 向上取整；不支持 inode 的文件系统返回 null。

读取采样时间和 partial/error 字段，不能把失败或过期数据当成正常。默认排除网络挂载、tmpfs/devtmpfs、容器 overlay、squashfs 和 efivarfs；重复挂载由 df 合并，结果受服务挂载命名空间和权限限制。Docker 数据仍计入宿主机所在磁盘的占用。采集有超时，不递归扫描目录、不自动清理文件；本版本仅查询，尚无磁盘阈值告警。

## 可选处置功能（0.2）

机器人先生成包含账号、来源 IP、会话身份、动作、时长和失效时间的处置单，你在 Rakazo 中确认后才执行。默认临时封禁 15 分钟，到期由内核自动解除；封禁会影响同一来源 IP 的其他 SSH 连接，不会锁定整个账号或阻断其他端口。管理 IP、系统账号和会话身份变化都会阻止真实操作。

处置连接使用独立凭据，服务器上的 root 代理仅监听本地 Unix socket。原监控凭据不能执行操作。**人工确认由 Rakazo 的精确 `require_approval` 规则执行，服务端负责处置单一致性、一次性执行与目标保护；直接持有操作凭据的人具有相应操作权限。** 不要把操作凭据交给其他不执行审批的客户端。

提供 `dry_run=true` 演练：仍走审批，但不改变会话或防火墙。终止进程不能撤销，解封也不会恢复被终止的工作。

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

当前告警范围是 SSH 认证和 CPU；内存提供定期采样和查询，暂不主动发送内存阈值告警。不包含控制台登录、sudo 审计、文件篡改检测或机器学习。日志可能轮转，采样可能有间隔；请按 README 验证权限和告警链路。同机监控无法在整机宕机时自行发通知，完整宕机监测需外部心跳。待发送告警不会自动因过期删除，长期通知故障时需关注磁盘容量。

## 登录调查（0.3）

优先调用 `investigate_ssh_activity`，明确起止时间与时区。后端返回整个时间范围的成功/失败记录数、来源统计、北京时间、分页证据、会话分类和数据覆盖范围，不再用“最近 20 条”推测整个时段的登录频率。

另有 `get_auth_attempts`、`get_session_details`、`get_trust_details`、`get_security_evidence`、`get_collection_health` 和 `get_automation_activity`。逐条失败记录与告警阈值独立，用户服务管理器和关闭中的会话不计作活跃 SSH。只读调查不需要处置审批。

旧日志可通过管理员 CLI 回填，不重复发告警；已轮转或未记录的数据无法补回。自动化归属需要 root 登记的任务回执或经过核实的独立密钥，共用 IP/密钥不能识别具体操作者。新版本不会自动轮换现有 SSH 密钥。详见 [调查工具与证据边界](deploy/INVESTIGATION.md)。
