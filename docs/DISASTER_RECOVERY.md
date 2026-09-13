# MailStack 灾难恢复操作手册

> 适用版本：v0.5.2-rc.5。所有命令均与 `mailstack.sh`、`backend/mailstackctl/backup.py`
> 的实际接口核对一致。操作对象为已安装的服务器（`ms` 命令可用）；
> 全部备份/恢复动作经特权 helper 执行，并记入审计日志（`/var/log/mailstack-rpc-audit.log`）。

## 0. 一分钟速查

| 场景 | 命令 |
|---|---|
| 创建配置备份 | `ms backup create` |
| 创建含邮件数据的备份 | `ms backup create --include-mails` |
| 查看历史备份 | `ms backup`（等价 `ms backup list`） |
| 恢复备份 | `ms restore <备份文件名>` |
| 回滚到恢复前状态 | `ms rollback` |
| 全栈体检 | `ms doctor` |
| 解除 fail2ban 误封 | 控制台「安全中心」解封，或 `sudo fail2ban-client set <jail> unbanip <IP>` |

---

## 1. 备份（`ms backup`）

### 1.1 备份内容与存放位置

- 存放目录：`/var/backups/mailstack/`，归档与元数据均为 `0600`（仅 root 可读）。
- 文件名固定格式（`BACKUP_FILENAME_RE`）：
  `mailstack-backup-<YYYYMMDD>-<HHMMSS>[-后缀].tar.gz`，伴随同名 `.json` 元数据（含 `sha256`）。
- 默认备份源：`/etc/mailstack`、`/etc/postfix`、`/etc/dovecot`、`/etc/opendkim`、`/var/lib/mailstack`。
- `--include-mails` 额外纳入：`/var/vmail` 与每个托管邮箱用户的 `~/Maildir`。
- **默认排除敏感文件**：`admin.json`、`ai.json`、`ai-provider.json`、`sasl_passwd(.db)`；
  仅当请求携带 `includeSecrets=true` 时才纳入。命令行入口（`ms backup create`）不传该参数，
  即 CLI 备份**不含**管理员凭据与 AI Key——异地保管备份时不必含口令文件，
  但恢复后需要重新设置管理员密码（或使用控制台/接口带 `includeSecrets` 创建的备份）。

### 1.2 常用操作

```bash
ms backup                    # 列出最近备份（最多 50 条，按时间倒序）
ms backup create             # 仅配置备份
ms backup create --include-mails   # 配置 + 全部邮件数据
```

### 1.3 加密备份

- 备份引擎支持可选的 GPG 对称加密（AES256）：创建请求携带 `passphrase` 时，
  归档整体加密（文件名仍为 `.tar.gz`，元数据带 `encrypted` 标记），口令仅经
  `gpg --passphrase-fd 0`（stdin）传入，不落 argv、不落日志。
- 加密是 fail-closed：系统无 `gpg` 时直接报错，绝不退化成明文备份；加密过程失败时明文归档一并删除。
- **入口（均已实现）**：
  - 命令行：`ms backup create --encrypt` 交互读取口令（`read -s`，两次输入确认）；
    非交互场景可预先设置环境变量 `MAILSTACK_BACKUP_PASSPHRASE`。口令绝不进入任何进程 argv。
  - 控制台：设置页备份卡片提供可选的加密口令输入框，创建成功后展示加密锁标记。
  - 管理 API：`POST /api/backups`，body 携带 `passphrase`。
- **口令保管提醒**：加密口令不随备份存储，系统无任何找回手段；请离线异地妥善保管，
  口令丢失则该备份无法解密。

### 1.4 备份建议

- 重大变更前（升级、DKIM 轮转、批量删用户/域名）先 `ms backup create --include-mails`。
- 将 `/var/backups/mailstack/` 定期异地复制；注意归档内可能含邮件数据，按同等密级保管。
- 升级前另做 VPS 快照（备份不覆盖 `/etc/caddy` 等白名单之外的文件）。

---

## 2. 恢复（`ms restore`）

### 2.1 恢复前置校验（引擎自动执行，失败即中止）

1. 文件名必须是**本地备份目录中的文件**且匹配 `BACKUP_FILENAME_RE`（只传文件名，不要传路径）。
2. 同名元数据存在且与归档名一致；归档 `sha256` 与元数据一致。
3. 部分备份（`partial`）需显式 `allowPartialRestore=true`（CLI 不传，部分备份请走 API）。
4. 加密备份必须提供口令（`passphrase`）；解密在 `0600` 临时文件中进行，结束后立即删除。
5. 归档成员安全校验：路径白名单（`etc/mailstack`、`etc/postfix`、`etc/dovecot`、
   `etc/opendkim`、`var/vmail`、`var/lib/mailstack`、`root/Maildir`、仅托管用户的 `home/`）、
   拒绝符号/硬链接、设备文件、setuid 等权限位；归档 ≤5 GB、成员 ≤100000、解压 ≤50 GB。

### 2.2 操作步骤

```bash
ms backup                    # ① 先确认目标备份文件名
ms restore mailstack-backup-20260101-120000.tar.gz   # ② 确认后执行
```

- 命令行会先给出覆盖警告并要求 `y` 确认。
- **pre-restore 自动快照**：恢复执行前，引擎自动创建
  `mailstack-backup-<时间戳>-pre-restore.tar.gz`（含当前配置、含密钥文件、`0600`，
  带自己的元数据与 `sha256`）。恢复出错或结果不符预期时，用它回滚（见第 3 节）。
- 恢复完成后自动执行：`postfix reload`、`dovecot reload`、`opendkim restart`。
- 加密备份的恢复需要口令：`ms restore` 会读取目标备份元数据，发现 `encrypted`
  标记时自动交互索要解密口令（`read -s`，不进 argv）；非交互场景可预先设置环境变量
  `MAILSTACK_BACKUP_PASSPHRASE`。控制台设置页的还原卡片同样提供口令输入框；
  也可经管理 API（`POST /api/backups/restore`，body：`filename`、`passphrase`、`confirm:true`）恢复。
- 可先以 API `dryRun:true` 预览（返回成员数与前 20 个文件）再实际执行。

---

## 3. 快速回滚（`ms rollback`）

```bash
ms rollback
```

- 自动选取 `/var/backups/mailstack/` 中**最新**的 `mailstack-backup-*-pre-restore.tar.gz`
  快照，并走与 `ms restore` 完全相同的严格恢复路径（校验、确认、再生成新的快照）。
- 若从未执行过 `ms restore`，则不存在快照，命令会明确报错。
- 回滚本身也是“恢复”，因此会再留下一份新的 pre-restore 快照，可反复反悔。

---

## 4. fail2ban 误封自救

症状：自己的客户端/办公出口 IP 因输错 IMAP/SMTP 密码被 ban，无法收发或登录。

**方式一（推荐）：管理控制台**
安全中心可查看当前被封 IP 与所属 jail，并执行解封。对应接口
`POST /api/security/unban`（参数 `ip`、`jail`）；jail 仅允许
`postfix-sasl`、`dovecot`、`sshd` 三个（枚举白名单），非法输入被拒绝。

**方式二：命令行（需 root 或经其他通道登录主机）**

```bash
sudo fail2ban-client status                          # 查看 jail 列表
sudo fail2ban-client status postfix-sasl             # 查看被封 IP
sudo fail2ban-client set postfix-sasl unbanip <IP>   # 解封（dovecot/sshd 同理）
```

预防：`ms doctor` 会断言 `postfix-sasl`/`dovecot` jail 真实可动作（ban/unban 往返）；
若管理员控制台在公网，建议为办公出口 IP 另配防火墙白名单。

---

## 5. 证书续期失败回退

- 控制台续期（`POST /api/certificates/renew`）底层执行
  `acme.sh --renew -d <域名> --force`（home `/root/.acme.sh`）。
- **续期失败不影响在途证书**：旧证书继续生效至到期，续期是幂等重试，不会破坏现有证书文件。
- 处置顺序：
  1. `ms doctor` 查看证书与 DNS 相关检查项（403/验证失败常见于 DNS 未生效或 HTTP-01 路径被改）。
  2. 手动重试：`sudo /root/.acme.sh/acme.sh --renew -d <域名> --force --home /root/.acme.sh`。
  3. 仍失败时重新签发（控制台证书页或引导向导的证书步骤，`--issue` + `--install-cert`），
     安装证书会自动注册重载脚本 `/usr/local/sbin/mailstack-reload-certificates`（reload Postfix/Dovecot）。
  4. 临时回退：将访问模式切回 `local`（SSH 隧道）不依赖该证书即可继续管理。
- 恢复备份不会触碰 `/etc/caddy` 与 acme 目录（不在恢复白名单内），证书状态不随配置回滚改变。

---

## 6. 时钟偏移与管理员 2FA（TOTP）

- TOTP 参数：30 秒步长、±1 步窗口（约 ±30 秒容忍度），并带防重放（同一步长只接受一次）。
- 服务器时钟偏移超过约 30 秒时，管理员验证码将持续校验失败——**这是时钟问题，不是 2FA 故障**。
- 处置：
  ```bash
  timedatectl status                      # 查看 NTP 同步状态
  timedatectl set-ntp true                # 启用 systemd-timesyncd（或安装 chrony）
  ```
  校时后无需重启服务，下一个 30 秒窗口即恢复。
- 应急登录：使用启用 2FA 时一次性发放的 10 个恢复码之一（登录时直接填在验证码框，
  一次性消费）；恢复码耗尽且时钟无法修复时，只能经主机 root 手工处置
  `/etc/mailstack/admin.json` 中的 `totp` 段（先 `ms backup`）。
- 手机端验证器时间不准同样会导致失败，先排除客户端。

---

## 7. 完全丢失后的重建路径

1. 新装同版本（`deploy/install.sh`，保持与原机相同的访问模式/域名参数）。
2. `ms restore <最近备份文件名>` 恢复配置（含邮件数据的备份可一并恢复邮箱）。
3. 若备份不含密钥文件（默认备份），重新设置：管理员密码（控制台初始化界面）、
   SMTP relay 口令、AI Key；DKIM 建议直接轮转（控制台）而非复用旧值。
4. `ms doctor` 全绿、`ms test-mail` 环回投递通过后，再切 DNS 回本机。

## 关联文档

- [`THREAT_MODEL.md`](THREAT_MODEL.md) —— 备份/恢复相关威胁与缓解
- [`DATA_PRIVACY.md`](DATA_PRIVACY.md) —— 备份中数据的停留位置与权限
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) —— 升级/发布流程
