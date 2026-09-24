# Changelog

All notable changes to the MailStack project are documented in this file.

## [v0.8.0-beta.9] - 2026-09-24

> 0.8.0-beta.9 是 beta.8 的「构建与测试可复现性」修复版，两处缺陷都不影响运行产物，
> 但都让「同一份源码必然得到同一份产物 / 同一条结论」这一承诺在本地失守：一处使
> build+package 不可复现（归档哈希随打包时刻漂移），一处让公网 2FA 门禁测试存在约
> 1.3% 的偶发假失败。均已在本地复现、修复并回归。无接口与数据格式变更。

### 🐛 修复 (Fixes)
- **manifest 的 `builtAt` 退回墙上时间，归档不可复现**: `scripts/generate_manifest.mjs`
  此前取 `process.env.SOURCE_DATE_EPOCH`，未设置时回落 `new Date()`。归档内的文件 mtime
  由 `scripts/package.py` 用常量 `1704067200` 固定，但 `dist/build-manifest.json` 的
  `builtAt` 是在「构建」阶段烙进去的——不显式导出该变量时同一份源码重建一次即得到不同的
  manifest，归档哈希随之改变，`RELEASE_CHECKLIST` 的「第二次打包哈希一致」与 README 的
  承诺同时失效。`release.yml` 之所以从未暴露，只是因为它的 `SOURCE_DATE_EPOCH` 写在 job
  级 `env`，构建步骤天然继承。现改为 `process.env.SOURCE_DATE_EPOCH ?? '1704067200'`，
  与 `package.py` 共用一个默认常量，不再依赖调用方是否导出环境变量。
- **T-2FA-1a 启动竞态导致偶发假失败**: 子进程的启动 banner 在 `listen` 回调内打印
  （`backend/server.production.ts` 约 L1568），经 pipe 传给父进程；而 `waitForReady()`
  判定的是 TCP 可连通，仅证明端口已绑定，两条通道之间没有任何同步。父进程在
  `waitForReady()` 返回后立刻读 `srv.stdout` 就是在赌 banner 已经到达——Windows 上并行
  `node --test` 实测约 1.3% 的运行会输掉这个赌局。新增 `waitForLog()` 轮询 helper 等待
  目标行落地（超时同时打印 stdout/stderr 便于定位），并用于 T-2FA-1a 的两条正向断言；
  另在两处**否定**断言（A1 local 不进 enroll window、公网已启用 2FA 不进 enroll window）
  前先等 banner 出现，避免在空 stdout 上「因为什么都没读到」而误判通过。

### ✅ 验证 (Verification)
- 修复后本地 build+package 连续两次，`release/` 四件套（tar.gz / zip / SHA256SUMS /
  SHA256SUMS.sig）哈希稳定，不再随打包时刻变化。
- `npm test` 86/86 通过（含 `public-mode-gate.test.mjs` 全量用例）；
  `verify_release_consistency.py` 100%。

## [v0.8.0-beta.8] - 2026-09-24

> 0.8.0-beta.8 给安装器加了「单文件自举」：`deploy/install.sh` 现在可以脱离源码树被
> 一行式获取并执行（`bash <(curl -fsSL …)` / `sudo bash -c "$(curl -fsSL …)"`）。
> 引导段沿用与 `ms upgrade` 完全相同的信任模型——只取官方 Release 的
> tar.gz + SHA256SUMS + SHA256SUMS.sig 三件套，先验分离签名再比对校验和，全部通过
> 才解压到 /opt/mailstack-source 并转交真正的安装器，自身不含任何安装逻辑。
> 无接口与数据格式变更。

### ✨ 一行式安装（新）
- **install.sh 单文件自举**: 此前 `BASE=$(cd "$(dirname "$0")/.." && pwd)` 强依赖源码树
  （安装器要拷 src/backend/dist 等目录），单文件获取后执行必失败。新增
  `bootstrap_from_signed_release`：源码树缺失时取回签名 Release、`ssh-keygen -Y verify`
  验签、`sha256sum -c` 比对校验和、校验资产为单一顶层目录且含 `deploy/install.sh`，
  之后才解压到 `/opt/mailstack-source` 并 `exec` 安装器（`ms` 正指向该目录，后续
  `ms upgrade` 通道不受影响）。验签或校验和不通过即在解压前中止，不执行任何未验签内容。
- **进程替换形态优先**: README 主推 `bash <(curl -fsSL …)`。进程替换只是把脚本正文挂在
  一个 fd 上，stdin 仍是终端，交互问答与 `--admin-password-stdin` 均正常；而
  `curl … | sudo bash` 的 stdin 就是脚本正文，安装器的 read 只会拿到 EOF（保留
  `</dev/tty` 回接兜底，确实无控制终端时明确失败，而不是在口令重试循环里空转）。
- **明示 `sudo bash <(curl …)` 不可用**: sudo 关闭 3 号以上的文件描述符，bash 取不到
  `/dev/fd/63`（sudo 1.9.15 实测 `No such file or directory`，退出码 127）。非 root
  运行 install.sh 时直接打印 `sudo -i` 与 `sudo bash -c "$(curl …)"` 两条可复制命令，
  不再只回一句「请使用 root 运行」。
- **威胁模型同步**: `docs/THREAT_MODEL.md` 新增「引导安装脚本」信任边界条目，并在残余
  风险里写明引导脚本与信任锚同源、防篡改控制落在 Release 分离签名上。

## [v0.8.0-beta.7] - 2026-09-13

> 0.8.0-beta.7 是 v0.8-beta.6 的 CI / 安装器修复版：自 fb0df337 起 CI 连续全红
> （build、install-matrix、supply-chain 三线独立失败），本版逐一定位并修复五个
> 根因及一个被掩盖的连带问题，全部在本地以与 CI 等价的方式复现验证通过
> （ubuntu:24.04 与 rockylinux:9 容器内完整安装断言 ALL-CHECKS-PASSED；
> Python 单测 106/106 于 3.11 / 3.12 / 3.14 三版本通过，无 cryptography 后端
> 环境按设计跳过 TOTP 用例）。无接口与数据格式变更。

### 🐛 CI 修复（自 fb0df337 起三线全红）
- **build(24) 单测环境敏感缺陷**: `test_actions_unit.py` 的 KeyPermissionScan 对
  `pathlib.Path.stat` 做整表 return_value mock；Python ≤ 3.12 的 `Path.glob/rglob`
  目录遍历内部调用 `Path.stat`，被 mock 后静默返回空 → 扫描器找不到任何 DKIM/
  备份文件 → 4 个用例断言拿到 None（CI 的 3.11 必红，3.14 开发机新 glob 不再调
  `Path.stat` 才侥幸全绿）。改为选择性 mock：仅目标路径返回伪造 `os.stat_result`，
  其余走真实 stat；伪造值同时携带本机 opendkim 组 gid（无 grp / 无组时为 0），
  0640-is-pass 用例不再对宿主环境敏感。
- **build(24) TOTP 用例缺 cryptography 后端时 error 而非 skip**: setup-python 的
  3.11 不含 `python3-cryptography`（依赖政策禁止 pip/发行版包之外来源），CI 自
  首次运行起 TotpActions 的 7 个用例即 error；TotpEnvelope 类早有
  `skipIf(totp.AESGCM is None)` 先例，TotpActions 漏配同款装饰器。补齐 7 处
  （begin/enable/disable/consume_recovery 全链路），无后端环境跳过（fail-closed
  语义下确实无可测内容），allowlist 门禁类用例不受影响继续运行。
- **install-matrix（apt 系三发行版）源码构建必失败**: `deploy/install.sh` 拷贝源码
  到 `/opt/mailstack/ui` 的清单缺 `scripts`、`deploy`、`mailstack.sh`、`VERSION`，
  而源码构建路径 `build:all` → `build:manifest`（`generate_manifest.mjs` 的
  criticalFiles）需要它们做源码树哈希与版本一致性校验 → 干净 checkout（无预构建
  dist/）必现 MODULE_NOT_FOUND。发布归档带 dist/ 走不到该路径，长期掩盖。
- **install-matrix（rockylinux:9）curl-minimal 包冲突**: rockylinux:9 基础镜像自带
  `curl-minimal`，与完整 `curl` 二进制互斥，`dnf install curl` 直接报冲突中止安装
  （`dnf remove curl-minimal` 不可行——它在 dnf 的受保护依赖链上会被连带拒绝）。
  改为检测到 curl-minimal 存在时给 install 传 `--allowerasing` 同事务替换；CI 的
  rocky bootstrap 同步加旗标。
- **supply-chain 审计门禁**: 生产依赖 qs 两条 moderate 通告（GHSA-x5fp-wj9c-mxmx、
  GHSA-4mjr-xmp4-gh2g）经 express 4.22.2 钉死的 `~6.15.1` 传导且无可达修复版
  （registry 无 6.15.4）。`package.json` 加 `overrides: {"qs": "^6.16.0"}`，lockfile
  实际变更仅 qs 6.15.3→6.16.0、body-parser 1.20.6→1.20.8；`--omit=dev` 的
  moderate 门禁与 high 门禁均恢复 exit 0。

### 🔧 安装器连带修复（被上述问题掩盖）
- **非 systemd 精简容器缺 `/etc/init.d`**: rockylinux:9 minimal 镜像未装
  initscripts，init.d 生成路径的 sed 重定向报 No such file or directory 中止安装。
  生成前 `install -d -m 0755 /etc/init.d` 预建目录（真实系统幂等无副作用）。

### ✅ 验证 (Verification)
- ubuntu:24.04 / rockylinux:9 容器内以 CI 完全相同的方式复现 install-matrix
  step 3/4：健康自检、权限模型、sudoers 单条、fail2ban jail、签名信任锚、
  回环投递全部通过。
- Python 单测 106/106 于 3.11 (Windows) / 3.12 (WSL) / 3.14 (Windows) 通过；
  npm test 86/86、vitest 12/12、tsc 零错、shellcheck 零告警、
  verify_release_consistency 100%、npm audit 双门禁 exit 0。

## [v0.8-beta.6] - 2026-09-12

> 0.8-beta.6 是「冲98」安全加固收官与 0.5.3-rc.1 平台成果的合并发布：在九发行版
> 实测 + musl 兑底 + Docker 化的基础上，合入安全加固 PR-A1..A6 与 PR-B1..B6 共
> 十二项，新增 14 条 T-* 行为断言，基线 13 条门禁断言全部保持不回退
> （python 106 / npm 86 / vitest 12 / tsc 零错 / shellcheck 零告警 /
> 版本一致性 100%）。无接口与数据格式变更。

### 🖥️ 平台与容器（承接 0.5.3-rc.1）
- **九发行版支持 + musl**: Ubuntu / Debian / Kali / AlmaLinux 10 / OracleLinux 9.5 /
  openEuler 25.09 / openSUSE Tumbleweed / Arch / Alpine 3.24 两轮本地实测全部跑通
  （8/9 systemd + Alpine OpenRC/init.d 分支）；musl 系统 Node 兑底走官方
  unofficial-builds `linux-x64-musl` 钉 SHA256 渠道。
- **Docker 化**: `Dockerfile` + `docker-compose.yml` + `docker/entrypoint.sh`
  单容器编排入库（无 systemd 的 6 进程前台模型、数据卷种子初始化、首启口令
  `MAILSTACK_ADMIN_PASSWORD` 注入仅日志打印一次），配套 `docs/DOCKER.md`。

### 🔒 安全加固 · 包 A (PR-A1..A6)
- **A1 公网强制 2FA**: 公网模式未启用 2FA 时仅放行 login + 2FA enrollment
  （`ENROLL_ALLOWED_PATHS` 门），窗口过期 `process.exit(1)`；监听地址强制
  `127.0.0.1`（`EFFECTIVE_HOST`）。断言：T-2FA-1a/1b/2。
- **A2 SO_PEERCRED 对端门**: 特权 helper 每连接 `getsockopt(SO_PEERCRED)`，
  ro 通道白名单 uid ∈ {0, mailstack-admin}、rw 通道仅 uid==0，越权即
  `peer_denied` 审计并立即断连（getsockopt 异常同样拒绝）；rw 动作恒走 sudo
  包装器、公网 ro 不回落 sudo。断言：T-PEER-2。
- **A3 TOTP 信封**: TOTP 二因子错误与密码错误共享同一 strike/lockout 台账，
  密码持有者不能借锁定盲区爆破 6 位验证码。
- **A4 禁止降级**: `ms upgrade` 降级门 `assert_no_downgrade`——目标低于已安装
  版本即拒绝，`--allow-downgrade` 显式放行并写 `downgrade_allowed` 审计；
  latest 劫持到旧签名包同样被拦；门位于验签+校验和之后、任何安装动作之前。
  断言：T-UP-1。
- **A5 逃生门硬关**: 公网模式 `MAILSTACK_ALLOW_UNSAFE_GIT=1` /
  `COOKIE_SECURE=0` / `HOST=0.0.0.0` / `MAILSTACK_AUDIT_FAILOPEN=1` 任一即
  doctor FAIL（unit 文件 `Environment=` 与 `/proc/<pid>/environ` 双来源扫描，
  local 模式绝对禁止项仍 WARN）；git clone 通道仅显式开发者旗标可达。
  断言：T-ESC-1。
- **A6 Docker 管理口门**: `docker/entrypoint.sh` 非环回 admin 绑定未同时携带
  双 publish 旗标即拒绝启动（非零退出）。断言：T-DOCK-1。

### 🔐 安全加固 · 包 B (PR-B1..B6)
- **B1 双 socket 通道分离**: `/run/mailstack/helper-ro.sock` 0660
  root:mailstack-admin（只读面）与 `/run/mailstack/helper.sock` 0600 root:root
  （变更面）；通道而非 uid 决定 action 子集，ro 面收到 rw 动作即便 uid=0 也
  拒绝并写 `ro_channel_violation` 审计。断言：T-SOCK-1/2。
- **B2 备份强制加密**: 公网模式 `backup.create` 无口令在打 tar 前拒绝
  （fail-closed 于任何副作用之前，门在函数开头覆盖 CLI/daemon/直调全部路径）；
  gpg 缺失绝不静默降级明文；doctor 明文归档扫描 FAIL、备份文件逐个断言 0600。
  断言：T-BKP-1。
- **B3 审计链外送**: 审计记录 prev_hash 哈希链防篡改，镜像外送 syslog
  AUTHPRIV（容器/无盘日志外送通道）。断言：T-AUD-1。
- **B4 systemd 收窄**: helper unit 全套 systemd 加固集，web unit
  `ProtectSystem=strict` 且不可写 `/etc/mailstack`。断言：T-PERM-1
  （helper/web 两条）。
- **B5 密钥政策**: 密钥权限扫描（KeyPermissionScan——DKIM 私钥
  root:opendkim 0640 等政策断言）；公网模式 AI 出站默认关闭
  （`AI_OUTBOUND_ACTIONS` 全集 fail-closed，须显式开关才放行）。
- **B6 pentest 记录**: `docs/pentest-2026-09.md` 入库——六面评审测试记录，
  每项「已修」附实现位置与测试名，「未修残余」如实记录不冒充已验证。

### ✅ 门禁与断言 (Verification)
- 新增 14 条 T-* 行为断言：T-2FA-1a/1b/2、T-PEER-2、T-SOCK-1/2、T-ESC-1、
  T-PERM-1（helper/web 两条）、T-BKP-1、T-AUD-1、T-UP-1、T-DOCK-1。
- 基线 13 条门禁断言全部保持不回退：python 106 test（skip=9，Windows 侧
  SO_PEERCRED 等环境依赖半区自动跳过）/ npm test 86 pass / vitest 12 pass /
  tsc --noEmit 零错 / shellcheck -S warning 零告警 /
  verify_release_consistency 100%。

## [v0.5.3-rc.1] - 2026-08-31

> rc.1 是一轮平台覆盖与安装器健壮性修订：本地九发行版两轮实测全部跑通（含 Alpine 无
> systemd 场景），补上 rc.5 遗留的 systemd 路径真机验证缺口；安装器新增 16 处针对性修复；
> Docker 化资产（Dockerfile / compose / 入口编排）入库。无接口与数据格式变更。

### 🖥️ 平台覆盖 (Platform)
- **九发行版本地实测全部跑通**: Ubuntu / Debian / Kali / AlmaLinux 10 / OracleLinux 9.5 /
  openEuler 25.09 / openSUSE Tumbleweed / Arch / Alpine 3.24 两轮安装验证（中断重跑、
  卸载重装）全部通过；其中 8/9 平台启用 systemd，补齐 rc.5 遗留的 systemd 路径真机实测缺口，
  Alpine 3.24 无 systemd，走 OpenRC / init.d 分支验证。
- **opendkim 在 openEuler 25.09 按设计降级**: OS/everything 仓库不提供 opendkim 包，安装器按
  预设降级路径跳过 DKIM 配置——收发信不受影响，后续手动安装 opendkim 并执行 `dkim.rotate`
  即可启用签名（与 `docs/SUPPORT_MATRIX.md` 平台能力说明一致）。

### 🔧 安装器加固 (Installer Hardening)
- **musl Node 兜底**: Alpine 等 musl 系统在发行版仓库不满足 Node 20-24 时，回退 Node 官方
  unofficial-builds 渠道 `linux-x64-musl` 构建（v22.20.0，SHA256 钉死；该渠道无 arm64-musl，
  musl+arm64 仅走发行版仓库包）。
- **dnf 系 opendkim 依赖与仓库**: opendkim 依赖的 libmilter 等只在 CRB/PowerTools 仓库，
  安装器按仓库 ID 序列（crb / ol9_codeready_builder / ol8_codeready_builder / powertools /
  codeready-builder）逐个尝试启用；EPEL 前置支持 `epel-release` 与 Oracle Linux 的
  `oracle-epel-release-el<N>` 双包名。
- **EL9 系 Python ≥3.10 保障**: dnf 分支尽力升级后仍不达标即明确失败——后端使用 PEP 604
  语法，3.9 下特权 helper 在 import 阶段即崩（rc.5 OracleLinux 9 默认 3.9 实测）。
- **Arch 旧快照自愈**: 安装前刷新 `archlinux-keyring` 并 `pacman-key --populate`，旧快照镜像
  的过期签名/陈旧 icu 不再阻断安装。
- **zypper 冲突处置**: openSUSE 预装 OpenSMTPD 与 postfix 硬冲突，安装前按冲突包前置卸载；
  Tumbleweed fail2ban 依赖 `ed` 的解析失败改为先补依赖再装，仍失败走 pip 兜底。
- **fail2ban GitHub tarball pip 兜底**: 仓库无包（如 openEuler 25.09）时从 GitHub 钉版本 1.1.0
  tarball 经 pip 安装；pip data_files 铺配置不可靠时手动展开完整 `/etc/fail2ban` 配置树；
  dnf / zypper / pacman / apk 五分支统一接入该兜底。
- **Alpine OpenRC 引导补齐**: 触摸 `/run/openrc/softlevel`（未引导时 rc-service 拒绝启动服务）、
  写 loopback `/etc/network/interfaces`（init 脚本 net 依赖）、服务账号日志文件预创建。
- **init.d 分支 setsid 脱离会话**: 无 systemd 场景用 `setsid` 拉起 admin/webmail（不可用时退回
  裸启动），避免安装会话结束后进程被 SIGHUP 收割。
- **服务启动前孤儿端口清理**: 启动服务前用 `fuser -k` 只杀实际占用 8787/18788 的进程（fuser 缺席时
  退回仅匹配本服务启动命令行的 pkill）——Wave1 实测中断后重跑安装时残留 node 进程占端口，
  新服务 EADDRINUSE 反复重启进 failed。

### 🐳 Docker 化 (Docker)
- 新增 `Dockerfile` + `docker-compose.yml` + `docker/entrypoint.sh` 单容器编排：无 systemd 的
  6 进程前台模型（helper / postfix / dovecot / opendkim 可选 / admin / webmail），任一进程退出即整体退出；
  数据卷空时从镜像种子目录初始化（`/etc/postfix`、`/etc/dovecot`、`/var/spool/postfix`、
  `/etc/opendkim` 等）；首启口令支持 `MAILSTACK_ADMIN_PASSWORD` 注入，未提供则生成随机口令并仅在日志打印一次，口令只写数据卷不进镜像层。
- 新增 `docs/DOCKER.md`：端口模型、卷布局、首启口令、宿主机 25 端口封锁提示。

### 📚 文档 (Documentation)
- `docs/SUPPORT_MATRIX.md` 补平台能力注记：EL9 Python ≥3.10 保障、Arch 旧快照自愈、
  Alpine OpenRC 引导、fail2ban pip 兜底、孤儿端口清理与 init.d setsid。

> 打磨补记：同版本内对全部部署/验证脚本（install.sh、install-mail-stack.sh、mailstack.sh、
> docker/entrypoint.sh、CI 脚本、verify/privacy-audit 脚本）补跑 shellcheck 0.9 `-S warning`
> 全量审计：修复 2 处告警（install.sh 的 ERR trap 改为命名函数、CI 断言脚本去 `ls | grep`
> 改 glob 数组），其余 7 个脚本零告警零豁免；fail2ban/icu 钉版本补来源注释。

> 打磨补记（第二轮，四项差距闭环）：
> - **fail2ban 1.1.0 tarball 钉 SHA256（供应链信任）**：`install_fail2ban_via_pip()` 原从 GitHub
>   tags 直拉 tarball 无完整性校验。核实上游 1.1.0 release 仅托管 GPG 分离签名（`fail2ban-1.1.0.tar.gz.asc`，
>   RSA `8738559E26F671DF9E2C6D9E683BF1BEBD0A882C`）与 `.deb` 资产，被签名的源码 tarball 本体未作为
>   release 资产（`releases/download/1.1.0/fail2ban-1.1.0.tar.gz` 与 fail2ban.org 同路径实测均 404），无法在线验签；
>   退而钉 GitHub 自动归档 tarball 的 SHA256 `474fcc25…570bae`（`archive/refs/tags` 与 `codeload` 双通道实测一致，
>   取值时间 2026-09-12）。改为「单次下载 → SHA256 校验 → 从已校验本地件 pip 安装 + 铺 `/etc/fail2ban` 配置」，
>   校验不通过即 warn 降级跳过（与既有 fail2ban 兜底语义一致，绝不中断安装、绝不装未校验来源）。隔离实测：正例哈希吻合、
>   配置树展开 173 文件（含 fail2ban.conf/jail.conf/filter.d/action.d），负例篡改件触发拒绝。
> - **Arch icu 自愈去硬编码（动态解析）**：`repair_pacman_icu()` 原硬编码 icu 76/77/78 三个 SONAME 的包档 URL 表。
>   改为「已知表快速路径 + `archive.archlinux.org/packages/i/icu/` 列表页动态解析兜底」：SONAME 主号即 icu 大版本
>   （`libicuuc.so.76 ← icu 76.x`），按大版本反查最新补丁版；覆盖扩展到全部 `libicu*.so.*`（旧表仅 `libicuuc`）。
>   数据源三级：本地包缓存 → 已知表直下 → archive 列表页；清华镜像仍只作 libgcc「取最新」动态链。全部失败给清晰手动指引。
>   Ubuntu 内只读实测：`icu-76.1-1`/`icu-78.3-1` 动态解析并 HEAD 200 可下；`icu-77` 上游未入 archive（印证硬编码表脆弱），
>   如实降级为手动指引。
> - **安装结束显式降级摘要**：`install-mail-stack.sh` 引入 `DEGRADED_ITEMS` 登记数组，在 opendkim/fail2ban/EPEL/ACME/Python
>   各权威降级点登记，`main()` 结尾输出「降级组件清单」小节（无降级时明确「无降级，全部组件就位」）。`install.sh` 以子进程
>   调用前者，经 `MAILSTACK_DEGRADED_LOG` 临时文件跨脚本回收降级项（set -e 安全、EXIT trap 清理），并入本层 Caddy 降级，
>   结尾统一汇总；子脚本被编排时抑制自身重复打印。Node 兜底为 fallback 链（成功即无降级、失败即硬门槛）不计入摘要。
> - **init.d heredoc 模板纳入 shellcheck 扫描面**：无 systemd 分支的 `/etc/init.d/mailstack-web` 原以内联 heredoc 生成，
>   shellcheck 扫不到。抽为独立文件 `deploy/init.d-mailstack.in.sh`（安装期变量用 `@占位符@`，运行期 `$0/$1/$network` 保持字面），
>   安装时经 `sed` 变量替换生成（不引入 `envsubst` 等新依赖）；CI 的 `find deploy -name '*.sh'` 自动将其纳入门禁扫描面，
>   `shellcheck -S warning` 零告警。非破坏性实测：模板+sed 产物与现网 `/etc/init.d/mailstack-web` **字节完全一致**（SHA256 相同、零 diff），
>   setsid 可用/缺失两场景均等价，现网文件未被触碰。
> - 复验：`bash -n` + `shellcheck 0.9 -S warning` 全部 12 个脚本（含新模板）零告警零豁免（mailstack.sh 既有 SC1091 sourced-file
>   豁免为基线，本轮未新增）；`verify-release-scripts.sh`、`ci_domain_injection_test.sh`、`verify_release_consistency.py`、`npm test`(62) 全绿。

## [v0.5.2-rc.5] - 2026-08-31

> rc.5 是一轮系统性安全加固：凭据暴露面（webmail 密码离开 argv、登录响应去信息化）、
> 升级供应链（禁止 clone HEAD、强制签名验证、依赖下载钉扎）、管理员 2FA（TOTP + 一次性
> 恢复码）、备份静态加密、权限收敛与注册表位置修复。无破坏性接口变更；旧密码存量不受
> 新密码策略影响，仅新设置的密码需满足 12 位新规。

### 🔒 安全加固 (Security)
- **webmail 登录密码离开进程 argv**: 原 `doveadm auth test user pass` 会把密码直接暴露在
  `/proc/*/cmdline`。新增 `webmail/dovecot-auth.mjs`（Dovecot auth-client socket 协议，
  VERSION/CPID/AUTH PLAIN base64），密码只进 socket 负载；socket 不可用时 fail-closed。
  错误密码与不存在用户返回完全相同的 401，消除用户枚举侧信道。
- **升级通道改为签名验证的 Release 资产，禁止 clone HEAD**: `ms upgrade` 默认只走 GitHub
  Release 三件套（`MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig`），
  `ssh-keygen -Y verify` 验签失败即退出；拒绝非官方 `MAILSTACK_REPO_URL`；`git clone`
  仅在 `MAILSTACK_ALLOW_UNSAFE_GIT=1` 开发者模式保留。新增发布签名 ed25519 公钥与信任锚
  （`deploy/mailstack-release.pub` / `mailstack-release.allowed_signers`），安装时落到
  `/etc/mailstack/release-allowed-signers`。
- **sudoers 收敛为单条**: 删除第二条 sudoers（`mailstack-web-ctl`）并对旧机器清理残留；
  Node 后端 `HELPER_PATH` 恒定 `/usr/local/libexec/mailstack-privileged`，不再回退源目录脚本。
- **管理员 2FA（TOTP + 恢复码）**: 新增 `admin.totp.begin/enable/disable/consume_recovery`
  四个 action；恢复码哈希存储、一次性消费，消费路径带文件锁保证原子性防并发重放；登录流程在
  密码通过后分支——启用 2FA 而未带验证码时返回 `TOTP_REQUIRED`，TOTP 本地校验，恢复码走特权
  helper；配套活跃会话列表与吊销 API（`GET/DELETE /api/auth/sessions`、
  `POST /api/auth/sessions/revoke`）。
- **登录响应去信息化 + 三层限流**: 401 一律只回 `INVALID_CREDENTIALS`（删除
  `remainingAttempts`）；admin 登录叠加全局 500/min + 每 IP 30/15min + 每账号 10/15min 三层
  限流，与原有 5 次失败锁定共同生效。
- **SSRF 映射地址解包**: `is_ip_restricted` 先解包 `ipv4_mapped`/`sixtofour`/`teredo` 内嵌地址
  再应用 v4 规则——此前 `::ffff:100.64.0.1` 等映射地址 `is_private=False`，可绕过全部筛查
  进入内网/CGNAT 服务；单测覆盖 CGNAT 与各映射形态。
- **fail2ban 真拦截**: 安装脚本在 dnf/yum/zypper/pacman/apk 全分支补装 fail2ban，新增
  `configure_fail2ban()` 写 postfix-sasl + dovecot jail；doctor 对每个 jail 做 ban/unban 往返
  探针（TEST-NET-1 192.0.2.1），jail 不存在或不动作判 FAIL 而非黄灯。
- **DKIM 私钥权限收紧**: `dkim_rotate` 与 `setup_identity` 的私钥从 `0600 opendkim:opendkim`
  改为 `root:opendkim 0640`（root 属主防止服务账号改写密钥，组读保证 opendkim 可加载），
  附行为断言。
- **邮箱注册表迁移 /var/lib/mailstack**: `managed-mailboxes.json` 原在 `/etc/mailstack`
  （0750 root:mailstack-admin），webmail 服务账号不可读，导致所有 webmail 登录静默失败；
  现迁移到 `/var/lib/mailstack/`（root:mailstack-webmail 0640），安装器含旧位置迁移，
  备份源与恢复白名单同步纳入。
- **Caddy 注入面收窄**: `DOMAIN_RE`/`EMAIL_RE` 在参数解析后、任何副作用前校验；交互补录的域名/
  邮箱在写 Caddyfile 前再校一次，换行注入在装包前即被拒绝（配套 CI 门禁）。
- **dovecot 新键兼容**: `99-mailstack-webmail.conf` 的 `mail_umask` 在新版 dovecot 是未知键，
  会导致整个 conf 加载失败、auth socket 退化为 0600；改为 `doveconf` 输出探测后逐个追加可选键。

### ✨ 新功能 (Features)
- **备份可选静态加密**: `backup.create` 支持可选口令，使用 gpg 对称加密（AES256）归档；口令只经
  stdin（`--passphrase-fd 0`）传递，不进 argv 与日志；fail-closed——gpg 缺失时拒绝加密请求而非
  降级为明文，加密过程任何失败都会连同明文归档一并清除。恢复时自动识别加密归档并要求口令。
  CLI 与设置页的口令入口已于本轮评审修复中接线（见「三维代码评审修复」）。
- **2FA 管理界面**: LoginView 新增验证码输入；AdminAccountSettings 新增 2FA 卡片（otpauth URI/
  secret 展示、启用/停用、恢复码一次性展示）。
- **活跃会话管理**: 管理员可查看活跃会话并逐个吊销；webmail 侧新增 7 天绝对会话上限与会话 epoch
  失效机制——改密或锁定账号即令该用户全部 webmail 会话失效（helper 在 `user_password`/
  `user_status` 时 bump epoch，webmail 5s 缓存轮询）。
- **长驻特权 helper**: 新增 `backend/mailstackctl/daemon.py`——root 长驻 daemon，暴露
  `/run/mailstack/helper.sock`（0660 root:mailstack-admin），4 字节大端长度前缀 + JSON 协议，
  8 并发上限，与一次性入口共用 `ALLOWED_ACTIONS`；Node 后端 `ctl()` 优先走 socket，仅传输层失败才
  回退一次性 sudo 调用，业务错误绝不重试。安装器新增 `mailstack-helper.service`
  （ProtectSystem=full，ReadWritePaths 与 mailstack-web 收窄为同一集合）。

### 🔧 工程整改 (Engineering)
- **供应链钉扎（停止下载即执行）**: Node.js 删除 NodeSource `fetch_and_run`——发行版包优先，
  不满足 Node 20-24 时下载官方 tarball 并比对 SHA256 常量，不符即拒绝；Caddy 回退 Cloudsmith 时
  先验 GPG 指纹，不符即拒绝加源；acme.sh 从 `git clone` 改为钉版本 3.1.4 tarball + SHA256，
  不符即跳过。
- **发布签名闭环**: `scripts/package.py` 新增门控签名步骤——`MAILSTACK_SIGNING_KEY` 指向私钥时对
  `SHA256SUMS` 执行 `ssh-keygen -Y sign` 并用仓内信任锚即时自验（与升级端验签字节级一致）；私钥已设但私钥文件/`ssh-keygen`/信任锚任一缺失即拒绝产出。新增 `.github/workflows/release.yml`：
  tag 触发，Secret 密钥签名，上传 tar.gz/zip/SHA256SUMS/SHA256SUMS.sig 全套资产。
- **密码策略收紧并对齐**: 最小密码长度 8→12，且要求同时含字母与数字、禁止 3+ 相同/连续字符、
  禁止包含账号身份 token；仅做认证的路径（登录、发信测试）走 `validate_legacy_password_input`，
  旧策略下已设置的存量密码不被锁死；前后端文案全量对齐 12 位新规，安装器 `deploy/install.sh`
  管理员口令文案与校验同步收紧为 12-256 位 + 字母数字（交互与 `--admin-password-stdin` 双路径）。
- **`ms restore` 快照提示修复**: `backup_restore` 返回键为 `preRestoreSnapshot`，而 mailstack.sh
  读旧键 `snapshot`，导致还原前回滚快照路径提示永不显示；已改为读新键并兼容旧键。
- **注册表备份覆盖**: `/var/lib/mailstack` 纳入备份源与恢复白名单，灾难恢复后邮箱注册表不再丢失。

### 🧪 测试与 CI (Testing)
- `scripts/test_actions_unit.py` 扩充至 54 项行为测试（含空 qid 删除、flush 独立 verb、atomic 0640、
  jail 元字符、CGNAT/IPv4-mapped SSRF、rollback 文件名匹配、归档穿越拒绝、2FA 恢复码原子消费等；
  Windows 下 1 项平台相关用例按预期 skip）。
- 新增 `tests/webmail-auth-socket.test.mjs`：假 socket 应答 OK/FAIL、失败关闭、用户名走私拒绝、
  登录零子进程（密码不再出现在任何命令行）。
- 新增 `scripts/ci_install_assertions.sh`（健康、提权探针、sudoers 单条、jail 存在、信任锚、环回发信）
  与 `scripts/ci_domain_injection_test.sh`（域名/邮箱换行注入门禁），均已纳入 CI 装机矩阵，
  环回发信失败即红。
- `scripts/test_backup_e2e.py` 补 `.ssh` 恢复拒绝断言与加密往返用例（目标机无 gpg 时加密用例
  按预期 skip）。
- `tests/security-static.test.mjs` 密码策略断言对齐 12 位新策略与组成规则（新增合规密码正向探针）。

### 📚 文档 (Documentation)
- `SECURITY.md` 重写：威胁模型概要、支持版本表、漏洞报告渠道、非目标声明与加固保证清单。
- 新增四份文档：`docs/THREAT_MODEL.md`（STRIDE）、`docs/DISASTER_RECOVERY.md`、
  `docs/VULNERABILITY_RESPONSE.md`（VEX/SLA）、`docs/DATA_PRIVACY.md`（数据停留、日志红线）。
- README 增补 2FA 与签名升级说明；`docs/RELEASE_CHECKLIST.md` 刷新到 0.5.2-rc.5，sudoers
  「只有一条」与代码一致，签名发布流程写入清单。

### 🛠️ 三维代码评审修复 (Review Fixes)
- **2FA 重绑定需验证码**: `totp_begin` 在 2FA 已启用时不再无条件覆写配置，必须通过
  TOTP 或恢复码验证（否则静默降级为单因子）；`/api/admin/2fa/begin` 重绑定成功后与
  enable/disable 一致清空会话；界面新增「重新绑定」入口。
- **改密码保留 2FA**: `admin_set` 改密路径不再整文件覆写，旧配置中的 `totp` 块合并进
  新记录；整个函数包进 `locked(ADMIN_CONFIG)`。
- **恢复后 admin.json 权限**: `safe_extract_and_copy` 对 admin.json 单独恢复为
  `0640 root:mailstack-admin`（其余密钥文件仍 0600），不再把控制台锁在门外；
  `test_backup_e2e.py` 新增权限断言。
- **备份加密入口接线**: `ms backup create --encrypt`（read -s / `MAILSTACK_BACKUP_PASSPHRASE`，
  口令绝不进 argv）、`ms restore` 对加密备份索要口令；设置页备份卡片新增可选加密口令输入、
  加密备份锁标记与还原口令输入（#16 闭环）。
- **pre-restore 快照校验**: 快照 tar 检查退出码并冒烟校验可解性，损坏快照不再登记为回滚点，
  响应附 `preRestoreSnapshotWarning`。
- **损坏归档误判修复**: 未标记加密但缺失 gzip 魔数的备份报「归档损坏」而非索要口令。
- **fail2ban 自定义 jail 解封恢复**: 解封/封禁的 jail 校验改为运行时白名单（以
  `fail2ban-client status` 实际 jail 列表为准，无法求证时回退安装器枚举），
  `recidive` 等自定义 jail 在 UI 可正常解封。
- **同秒备份同名覆盖**: `backup.create` 目标已存在时追加 4 位随机十六进制后缀。
- **CI 探针口令**: `ci_install_assertions.sh` 的固定探针口令改为满足新密码策略的值，
  装机矩阵环回发信断言恢复可绿。

## [v0.5.2-rc.4] - 2026-08-30

> rc.4 是一轮针对发布脚本本身的全量审计修复：mailstack.sh 与 deploy/ 全部 shell
> 脚本（约 1800 行）逐行审查，交叉验证其与被 sudoers 放行的特权后端之间的协议
> 约束。发现 1 个让非 systemd 环境必然装不上的逻辑缺陷、1 个与 rc.3 门禁同源的
> "定义先于使用"缺陷、1 个自相矛盾导致 CI 红灯的测试引用，以及若干静默吞错点。
> 全部修复；无功能变更，无 Python 特权后端变更。

### 🐛 缺陷修复 (Bug Fixes)
- **非 systemd 分支服务静默启动失败 (P1，rc.1 起存在)**: init 脚本里
  `su -s /bin/sh <服务账号> -c "... >/var/log/mailstack-web.log 2>&1 &"` 的
  重定向以服务账号身份执行，而 `/var/log` 对非 root 不可写——node 进程从未
  启动，`&` 吞掉失败，安装最终以毫无线索的"安装后服务健康自检失败"中止，
  OpenRC/SysV 环境（含支持矩阵中标注 Experimental 的 Alpine）实际不可用。
  rc.4 安装器以 root 预创建两份日志文件并归属对应服务账号。
- **logrotate 轮转后服务写不进自己的日志**: 旧配置用单一通配
  `/var/log/mailstack-*.log` + `create 0640 mailstack-admin`——webmail 日志
  被轮转后重建为 mailstack-admin 属主，mailstack-webmail 无权写入；且未用
  copytruncate，init 脚本持有的重定向 fd 不跟随 rename，轮转后进程继续写
  旧 inode（新文件永远为空）。rc.4 拆为三段策略：root 写入（audit/install
  日志 create root:root）、两个服务账号日志各自 copytruncate。
- **`fail()` 在定义之前被调用 (P2)**: `--admin-password-stdin` 的 stdin EOF
  错误路径位于参数解析循环内，而 say/fail/warn 定义在其后——用户看到的会是
  `fail: command not found`（退出码 127）而非设计好的报错。与当年 warn()
  未定义属同类缺陷：rc.3 的未定义函数门禁只检查"全文件是否定义"，
  查不出"定义晚于使用"。辅助函数已移至参数解析之前。
- **logrotate 配置以 CRLF 行尾发布 (P2，rc.3 引入)**: 发布包中的
  `deploy/mailstack.logrotate` 是 CRLF，被安装器原样 cp 到
  `/etc/logrotate.d/mailstack` 后，logrotate 把 `\r` 当作路径/选项的一部分，
  轮转策略解析失败。CI 行尾门禁只检查 `*.sh`，该文件无后缀逃过检查；
  真机验证使用 git 检出（LF）所以从未暴露。rc.4 全仓文本统一 LF
  （与 .gitattributes `eol=lf` 一致，发布包字节与 git 检出对齐），
  并把 `mailstack-privileged` / `mailstack.logrotate` 纳入 CI 行尾门禁。
- **测试套件与发布门禁互相矛盾 (P2，rc.3 引入)**: rc.3 删除死文件
  `deploy/mailstack-cli` 并让 verify-release-scripts.sh 对其存在报错，但
  tests/security-static.test.mjs 仍按存在读取该文件——"Release hygiene"
  测试在 rc.3 发布包上必然失败（ENOENT），`npm test` 门禁实际处于红灯。
  已移除该引用，本仓库测试恢复全绿。

### 🔧 工程整改 (Chores)
- **移除死参数 `--allow-caddy-degrade`**: 自引入起从未被任何代码读取
  （shellcheck SC2034 唯一 warning），Caddy 降级行为实际是无条件的——传入
  该参数的用户预期改变行为，实际什么都没发生。
- **`ms upgrade` 支持版本钉扎**: 升级此前无条件执行仓库默认分支 HEAD，且
  不留来源痕迹。现支持 `ms upgrade <tag|分支>` 钉扎来源，并把实际执行的
  commit SHA 打印到输出/安装日志——升级以 root 运行，来源必须可追溯。
- **`ms upgrade` 参数透传**: upgrade 此前是唯一不透传 `"$@"` 的命令，用户
  参数被静默丢弃；现持久化参数之后追加的用户参数可覆盖安装行为。
- **CLI 特权调用不再依赖 sudo**: mailstack.sh 六处 heredoc 的
  `sudo /usr/local/libexec/mailstack-privileged` 改为直接调用（need_root 已
  保证 root 身份）——无 sudo 的最小化环境不再无法使用 ms 命令；同时补齐
  helper 缺失（FileNotFoundError）与非零退出码的友好报错，此前这些错误
  路径直接以 Python traceback 收场。
- **特权包装器 python3 解析**: `mailstack-privileged` 硬编码
  `/usr/bin/python3`，而安装器只校验 `command -v python3`——解释器装在
  非标准前缀时 wrapper 直接失效。改为确定路径优先、PATH 解析兜底。
- **预安装备份不再静默吞错**: install-mail-stack.sh 的 backup_path 中
  `tar ... || true` 意味着破坏性改写前可能根本没有回滚副本而无人知晓；
  现备份失败时在安装日志输出明确告警并清理半成品归档。
- **端口"验证"改为真验证**: start_and_verify 的 `ss | grep ... || true`
  永远不会失败，纯属装饰；现监听缺失时输出告警（仍不中断安装，交给安装
  末尾的健康自检兜底，避免 ss 输出格式差异与服务异步启动造成误杀）。
- **端口八进制解析**: 带前导零的端口（如 `0877`）在 bash 算术展开中按
  八进制解析而报错，报错信息与真实原因无关；`10#` 前缀强制十进制
  （install.sh 与 install-v05.sh 同步修复）。
- **bash < 4.4 空数组守卫**: `ms upgrade` 的 `"${extra_args[@]}"` 在
  install-args.conf 缺失时为空数组，老版本 bash 的 set -u 下误报 unbound
  variable；改用 `${extra_args[@]+...}` 幂等守卫写法。

## [v0.5.2-rc.3] - 2026-08-30

> rc.2 全量脚本审计（7 个部署脚本 + mailstack.sh，约 1460 行）发现 1 个 P0 崩溃缺陷、
> 1 个新引入的提权面与若干工程性问题。rc.3 全部修复，并补齐让这类缺陷无法再进入
> 发布包的 CI 门禁（shellcheck / 未定义函数扫描 / 四发行版装机矩阵）。

### 🔒 安全修复 (Security Fixes)
- **`/opt/mailstack` 父目录属主修复 (P0，rc.2 引入)**: rc.2 将 `/opt/mailstack`
  整树 `chown -R mailstack-admin`，仅把 `backend/` 收回 root。父目录对服务账号
  可写意味着：mailstack-admin 可整体替换 `backend/` 并借 `mailstack-web-ctl`
  NOPASSWD 规则以 root 执行伪造的 `mailstackctl.py`（本地提权链）。
  rc.3 改为目录本身 root:root 0755，仅运行所需的 `ui/`、`server.cjs`、
  `webmail.cjs`、`webmail-public/` 归服务账号。
- **管理员密码不再经进程 argv 传递**: `--admin-password-stdin` 与 CLI 改密均改走
  环境变量 + `os.unsetenv`，密码不再短暂暴露于 `/proc/<pid>/cmdline`。
- **第三方安装脚本供应链留痕**: NodeSource setup 不再直接 `curl | bash`，
  先下载到临时文件、将 SHA256 记入安装日志供事后审计，再执行。

### 🐛 缺陷修复 (Bug Fixes)
- **`ms rollback` 协议不匹配导致必失败（rc.3 全量扫描发现，rc.1 起存在）**:
  回滚快照原名 `pre-restore-snapshot-*.tar.gz` 不匹配 helper 的
  `BACKUP_FILENAME_RE`，且 CLI 传绝对路径——`_resolve_archive` 双重拒绝，
  rollback 从未成功过。rc.3 快照改为 `mailstack-backup-*-pre-restore.tar.gz`
  并在创建时写入 metadata（含 sha256），CLI 按 basename 传递，回滚走同一套
  严格 restore 校验链（文件名/SHA256/confirm）。
- **SSRF 拦截补 CGNAT 段**: `100.64.0.0/10` 不在 `ip.is_private` 覆盖内，
  云/运营商内网服务可经 AI 端点探测——补入受限名单（动态攻击向量测试全拦截）。
- **fail2ban jail 名白名单**: `security.ban/unban` 的 jail 参数补
  `^[A-Za-z0-9_.-]{1,64}$` 校验。
- **`warn()` 未定义导致安装崩溃 (P0，rc.1/rc.2 均存在)**: install.sh 三处调用
  `warn` 但从未定义；`set -Eeuo pipefail` 下 caddy 模式任一降级场景
  （caddy 安装失败 / Caddyfile 校验告警 / 80、443 被占用）直接以退出码 127
  中止安装，跳过健康自检。rc.3 补齐定义，并新增发布门禁防重演（见下）。
- **`ms upgrade` 丢失原部署参数**: 升级只传 `--reuse-admin`，非交互下
  ACCESS_MODE 被强制回 local、HTTPS cookie 标志重置——plain/caddy 部署升级后
  监听行为漂移。rc.3 安装时把生效参数持久化到
  `/etc/mailstack/install-args.conf`（0640 root:mailstack-admin），
  升级时原样透传。
- **卸载残留清理**: 补删 `mailstack-web-ctl` sudoers、dovecot
  `99-mailstack*.conf`、logrotate 条目；`/etc/caddy/Caddyfile` 仅当含
  MailStack 管理标记时备份后移除；dry-run 清单同步补全；卸载后重启 dovecot
  回到发行版默认配置。
- **`--admin-password-stdin` EOF 语义**: stdin 关闭/为空时给出明确报错，
  而非晦涩的索引报错。
- **Windows 验证脚本误杀进程**: `verify-source-build.sh` 的 taskkill 从
  `/IM node.exe`（杀全机 node）改为按 PID + `/T` 定向清理测试进程树。
- **失败行号上报**: EXIT trap 的 `$LINENO` 恒指向 trap 行，无定位价值；
  改用 ERR trap + `BASH_LINENO`。

### 🔧 工程整改 (Chores)
- 删除死文件 `deploy/mailstack-cli`（无任何安装器引用，实际 CLI 是
  `mailstack.sh` → `/usr/local/bin/ms`）。
- 删除 `mailstack.sh` 中未使用的 `run_ctl()`（heredoc 无引号拼接 JSON 的
  注入式反样板）。
- logrotate 单一来源：移除 install.sh 内手写的第二份轮转配置
  （rotate 8 copytruncate），统一由 `deploy/mailstack.logrotate` 提供。

### ✅ 新增 CI 门禁 (New CI Gates)
- **shell-gate job**: shellcheck（error 级硬门禁）+ `deploy/verify-release-scripts.sh`
  未定义函数调用扫描——对 rc.2 树运行可正确拦截 warn 缺陷，双向验证通过。
- **install-matrix job**: ubuntu 24.04/22.04、debian 12、rockylinux 9 四个干净
  容器内执行非交互安装，断言双服务健康端点 + 权限模型
  （`/opt/mailstack` 必须 root 属主——直接锁死本次修复的提权面）。

## [v0.5.2-rc.2] - 2026-08-30

> rc.1 在真实 Ubuntu 24.04 VPS 部署中暴露 6 个串联缺陷：部署向导在 Step 1 即中断，
> 依次修复后又在新环节连环引爆。rc.2 对全部链路做了端到端修复并在 WSL Ubuntu 24.04
> (Node 22) 上完成回归测试。

### 🐛 运行时缺陷修复 (Runtime Defect Fixes)
- **`.env` 变量名与实现脱节 (P0)**: `.env.example` 写 `ADMIN_PORT/ADMIN_HOST`，
  而 `server.production.ts` 只读 `PORT/HOST`——用户按模板配置后完全不生效
  （今天现场表现为控制台始终绑定 127.0.0.1）。现按 `ADMIN_* > *` 优先级读取，
  两套变量名均兼容；systemd unit 继续传 `PORT/HOST` 不受影响。
- **特权调用路径与 sudoers 放行不一致 (P0)**: `server.production.ts` spawn 的是
  `sudo /opt/mailstack/backend/mailstackctl.py`，而安装器 sudoers 只放行 wrapper
  `/usr/local/libexec/mailstack-privileged`——**Web 端所有特权操作 100% 失败**
  （`sudo: a password is required`）。rc2 统一走 wrapper（与原安全设计一致），
  源码/dev 环境自动回退 python 入口，安装器同时放行两条路径并各自 visudo 校验。
- **`ProtectSystem=full` 沙箱锁死自身功能 (P0)**: mailstack-web 单元把 `/etc`
  挂成只读，而 `postconf -e` 必须写 `/etc/postfix/main.cf.tmp`——
  `postconf: fatal: Read-only file system`，sudo 提权也无法逃出挂载命名空间。
  rc2 增加 `ReadWritePaths=/etc`（/usr、/boot 仍保持只读防护），沙箱与功能两全。
- **特权调用 30s 硬超时 (P0，潜伏)**: `ctl()` 固定 30 秒，而 ACME 证书首签
  通常需要 30–90 秒——Step 4 签证书必超时。默认提到 120s，并支持
  `MAILSTACK_HELPER_TIMEOUT_MS` 覆盖（下限 5s）。
- **向导 Step 3 直连模式死锁 (P0)**: 前端以 `host=127.0.0.1` 发起中继测试，
  被 helper 的 SSRF 防护（正确地）拒绝；且"下一步"按钮 `disabled={!relayTested}`
  与必失败的测试构成死锁，直连投递用户被永久困在 Step 3。rc2 前端改为发送
  `{direct: true}`，后端新增 `_direct_delivery_probe()`：以固定回环端点对本机
  Postfix 做纯 EHLO 探测（部署常量而非用户输入，不受 SSRF 防护约束，
  且不要求 TLS——此时证书尚未签发）。测试语义与按钮文案终于一致。
- **DKIM 公钥被截断 (P1，潜伏)**: `opendkim-genkey` 输出按 RFC 拆成多行带引号
  片段，旧正则直接在原文匹配 `p=`，密钥跨行即被截断——用截断公钥配置的
  DKIM DNS 记录会导致所有外发邮件签名验证失败。rc2 先剥离引号与空白再匹配。

### 🔧 部署修复 (Deployment Fixes)
- **安装脚本缺目录**: Ubuntu 默认没有 `/usr/local/libexec`，安装器 install 时
  直接 `No such file or directory` 中断。已补 `mkdir -p`。
- **版本引用清理**: 工作树中残留嵌套的 `mailstack-v0.5.2-rc1/` 完整副本
  （上一轮打包未排除的产物），已移除并纳入打包排除清单。

### 📝 已知问题 (Known Issues，留待 rc3)
- 前端每 5 秒轮询 `logs.list`，每次调用都 spawn 一组 sudo+python 进程，
  空载场景产生稳定的进程抖动；计划引入长驻 helper 或 WebSocket 推送。
- `webmail/public/app.js` 多处模板插值未过 `escapeHtml`（多数渲染受控状态，
  但 `${data.subject}/${data.from}/${data.body}` 渲染路径建议逐点加固）。

## [v0.5.2-rc.1] - 2026-08-30

### 🐛 运行时缺陷修复 (Runtime Defect Fixes)
- **`aliases.add` 全量崩溃 (P0)**: `alias_add()` 对 `ADDRESS_RE.fullmatch(src)` 的结果取 `m.group(1)`，
  而该正则**没有捕获组**——每次真实的别名创建都抛 `IndexError: no such group`。
  空参数探针因短路求值（空地址先触发 `not m` 分支）从未暴露此问题；
  行为级单测（见下）以真实地址调用才抓到。别名域名改由显式拆分校验。
- **`mail.test_loopback` 开放中继缺口 (P0)**: 反中继守卫写作 `if managed and ...`，
  全新安装（尚无任何邮箱）时 `managed` 为空列表，**整条检查被跳过**，
  该接口可向互联网任意地址投递测试邮件。现要求收件人域名必须是本服务器管理的域名。
- **队列指标恒为 0**: `server.production.ts` 中 `split("\\n")` 是字面反斜杠+n，`postqueue -j` 输出从未被分割，
  队列总数与延迟数永远返回 0。已修正为真正的换行符。
- **CPU 指标失真**: `getRealtime()` 对状态化差分采样器 `getCpuUsage()` 连续调用两次，
  第二次读数只度量两次调用之间的微秒间隔；`coreUsage` 则是把系统平均值复制 N 份伪造出的每核数据。
  改为单次采样，并从每核计数器真实计算。
- **守护进程内存统计双向失真**: 进程识别用子串匹配（`comm.includes("auth")` 会命中任何名字含 auth 的进程），
  同时漏掉 Postfix 大多数工作进程（cleanup、trivial-rewrite、smtp、local、virtual、pipe、bounce）。
  改为精确名匹配表，并注明刻意排除的歧义名（`config`/`log`/`stats`）。
- **`/proc` 全量扫描每 2 秒一次**: 2 核采样器每次遍历所有 PID。现以 PID 缓存增量扫描，
  邮件守护进程逐周期读取，其余进程每 15 周期（30 秒）全量核对一次。
- **编码损坏**: AI 预设名中的 emoji 在一次有损转码后变成 `??`，并泄漏到用户可见报错
  （如 `AI API key is not configured for ?? GLM (BigModel)`）；域名列表中文文案为 `?? DNS ??`。
  已修复，全库 U+FFFD 扫描结果为 0。

### 🔐 安全加固 (Security Hardening)
- **破坏性操作确认被绕过**: `post()` 中间件与四个 DELETE 路由无条件注入 `confirm: true`，
  使特权助手的 `DESTRUCTIVE_ACTIONS` 门禁完全失效。现在只转发客户端显式提交的确认，缺省即拒绝。
- **SSRF 只校验首个解析地址**: `validate_outbound_ip()` 在解析出第一个地址后即 `return`，
  混合公私 A 记录的主机名可借解析顺序绕过。现在**逐个筛查所有解析地址**，任一受限即拒绝。
- **Postfix 别名表注入**: `alias_del()` 从不校验输入，含换行的 id 会向别名表写入任意条目（邮件重定向）；
  `alias_add()` 的 `destinations` 传字符串会按字符迭代，单字母恰好满足用户名规则。
  两侧均已按 `ADDRESS_RE` / `USER_RE` 显式校验。
- **密钥文件权限形同虚设**: `atomic(path, data, mode=0o640)` 接受 `mode` 参数却从不生效，
  文件落成进程 umask（通常 0644），存放 AI API Key 的 `/etc/mailstack/ai-provider.json` 对全局可读。
  现已 `os.chmod` 落地；同时把 flock 从私有临时文件移到目标文件旁的 sidecar，并发写入才真正串行化。
- **备份恢复可覆写任意用户家目录**: 恢复白名单含裸 `home/` 前缀，覆盖主机上每一个账号。
  现收敛为仅 MailStack 自管邮箱账号，并为 root 单独放行 `root/Maildir/`。
- **默认监听 0.0.0.0**: 管理后台默认暴露在所有网卡。默认值改为 `127.0.0.1`，需要局域网访问请显式设置 `HOST`。
- **API Key 掩码泄漏 8 位**: `masked_key` 同时保留首尾各 4 位，现只保留前缀 4 位。
- **审计日志静默失效**: `audit()` 用 `except Exception: pass` 吞掉自身写入失败，
  磁盘满或权限错会让审计轨迹无声消失。现在向 stderr 报告一次。

### 📡 可观测性 (Observability)
- **指标失败静默归零**: `postqueue` 损坏、`/proc/meminfo` 不可读、`df` 失败、守护进程扫描失败——
  每一处都曾以 `catch {}` 回落为一个**看起来很健康的 0**。现在经 `warnOnce()`（Python 侧为 `warn()`）
  按上下文去重后写一次 stderr：采样器每 2 秒一跑，不去重就是每天 4.3 万行日志。
  两个 helper 均已加固：异常的 `__str__` 抛错时仍保留上下文行，且只在**真正写出后**才标记已报告
  （此前先标记后写出，一次写失败会永久静音该上下文——这本身是单测抓出的真 bug）。
- **webmail 两个通用 500 背后无原因**: `READ_ERROR` 响应保持通用（不给浏览器更多信息），
  但真实原因写入 journal，运维侧 `doveadm 未安装` 与 `密码错误` 终于可区分。
- **AI 诊断页静默缺记录**: 服务器公网 IP 读取失败时，A 记录与 SPF 记录会从生成的 DNS 表中悄悄消失，
  运维复制走的是缺了两条的记录集。现在显式提示缺了什么。

### 🧩 工程质量 (Engineering Quality)
- **建立行为级单测体系（86 分分水岭项）**: 此前 49 个测试大多是"源码里是否出现某字符串"的拼写检查。
  新增 `scripts/test_actions_unit.py`（26 例）：在临时 `/etc` 中重定向模块常量、伪造子进程，
  真实调用 `alias_add` / `user_add` / `mail_test_loopback` / `dispatch` 并断言行为，
  其中 4 例直接抓到或钉住本版修复的缺陷。新增 `tests/frontend/`（12 例，vitest + jsdom +
  @testing-library/react），覆盖错误文案映射与 AI 诊断页渲染。全套进 CI。
- **密码策略单点化**: 8-256 长度校验此前在 `core.py` / `network.py` / `security.py` 中三处各写一遍，
  且只有一处校验控制字符——管理员路径会接受邮箱路径拒绝的含 NUL 字节密码。
  现统一到 `mailstackctl/core.py` 的 `validate_mailbox_password()`，三处改为调用。
- **版本号单点化**: 版本曾硬编码在 8 处，而发布校验脚本只比对其中 4 处，
  完全可以发布出 `/api/health` 报 0.5.1 而 manifest 写 0.5.2 的包。
  现在 Python 模块、`/api/health`、`/api/webmail/health` 与前端默认值全部从 `package.json` 派生，
  校验脚本改为**全量源码扫描**残留版本字面量。
- **测试套件从 18 失败降到 0**: 原 16 条失败中有 14 条是模块化重构后仍在 grep 旧文件路径的失效断言，
  它们的噪音掩盖了 1 个真实崩溃。静态断言改为读取整个 `mailstackctl` 包而非入口 shim。
- **依赖审计与 SBOM 进 CI**: 新增 supply-chain job：`npm audit --audit-level=high` 硬门禁
  （当前 0 漏洞，失败即新引入）+ CycloneDX SBOM 工件。
- **打包防垃圾注入**: 打包脚本现拒绝名字含未展开 `%...%` 的路径
  （一次 `> %SystemDrive%/...` 的笔误曾把 976 KB 的 Windows 缓存数据库打进源树）。
- **包体瘦身**: 2 张 Logo 打了 6 份、每张 1254px，占包体 5.1 MB（约 40%）。
  现按 512px 重编码并删除未被引用的 webmail 副本，图片总量降至 599 KB。

## [v0.5.1-beta.1] - 2026-08-20

### 🚀 核心架构与工程硬化 (Core Engineering & Architecture)
- **预构建零依赖独立运行 (Standalone Inlined Bundling)**:
  - 移除了 esbuild 外部化依赖配置，将 Express、Compression 等运行时依赖全量内联打包至 `dist/server.cjs` 与 `dist/webmail.cjs`。
  - 即使在没有任何 `node_modules` 的纯净 Linux 环境中，预构建产物也能直接独立启动与运行。
  - 新增 `tests/prebuilt-smoke.test.mjs` 自动化冒烟测试，在独立临时沙箱中验证零依赖健康启动。
- **发布溯源与 Manifest 完整性校验**:
  - `build-manifest.json` 记录所有关键二进制与静态资源的 SHA-256 散列值与 Source Tree Hash。
  - 每次安装优先校验 SHA-256 完整性后再进行部署。

### 🛡️ 安全与认证基线统一 (Security & Authentication)
- **密码长度策略统一 (Password Policy Alignment)**:
  - 全链路统一密码最低长度要求为 **>= 8 个字符**（交互式引导、API 参数校验、后台设置、Linux 邮箱账号生成全量对齐）。
  - 各前端视图与终端安装器统一展示“密码至少 8 个字符（推荐 12 位以上包含字母与数字）”引导文案。
- **绝对会话生命周期兜底 (Absolute Session Lifetime Cap)**:
  - 在原有 8 小时滑动刷新机制上，增加了 **7 天绝对生存周期硬顶 (`ABSOLUTE_SESSION_MAX_MS`)**，杜绝无休止会话延续风险。
- **网络访问拓扑与 Caddy 状态诚实性**:
  - 规范四种部署访问模式：`local` (安全默认)、`caddy` (公网自动 HTTPS)、`direct` (自备反代)、`plain` (内网明文测试)。
  - 完善 Caddy 安装与健康状态探测，若 Caddy 未能处于 active 状态，安装器给出诚实告警并输出本地应急隧道访问指引，绝不假报 HTTPS 就绪。

### 🔧 缺陷修复与功能闭环 (Bug Fixes & Feature Completeness)
- **修复 `mail_test_loopback` 运行时 NameError**:
  - 修复 `elapsed_ms` 变量未计算直接引用的崩溃问题，提供精确到毫秒的往返投递时延指标。
- **打通自定义证书导入后端支持 (`method: 'custom'`)**:
  - `setup_cert_issue` 完整支持上传已有 PEM 证书与私钥，自动配置 Postfix / Dovecot（兼容 Dovecot 2.4+ 与 2.3+）并重载服务。
- **修复 `/api/status` 404 与建立端到端 API 契约测试**:
  - 注册 `/api/status` 映射路由，新增 `tests/api-contract.test.mjs` 静态全量扫描 35+ 前端 API 调用，确保前后端 100% 契约吻合。
- **真实出站 25 端口 TCP 连通性探测**:
  - 废除前端假延时模拟，实现 `network.check_port` RPC 动作，向远程 SMTP 服务器真实发起 TCP 握手测量时延与拦截状态。

### 🧪 测试与持续集成 (Tests & Distro Matrix)
- **41 项全量自动化测试套件**:
  - 覆盖 API 契约、预构建独立启动、业务集成、安全静态守卫、遥测指标等 41 项用例，100% 绿色通过。
- **8 大 Linux 发行版实机矩阵**:
  - 实测兼容通过 Ubuntu、Debian、AlmaLinux 10、OracleLinux 9.5、openSUSE Tumbleweed、openEuler 25.09、Alpine、Arch。
  - 强化矩阵测试脚本，任何子项失败严格以非零退出码退出，消除 CI 假绿。

---

## [v0.1.0-beta.1] - 2026-08-10

- 新增统一 `mailstack.sh` 入口与 `ms` 快捷管理工具。
- 引入 Liquid Glass 设计风格 React 管理控制台。
- 支持 Postfix、Dovecot、OpenDKIM、Fail2ban 服务管理与状态监控。
- 引入 AI 邮件诊断助手与多服务商出站集成。
- 支持备份恢复、回环测试与安全事件审计。
