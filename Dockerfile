# syntax=docker/dockerfile:1
# MailStack 单容器镜像（ubuntu:24.04 基线）。
#
# 构建策略与 .github/workflows/ci.yml 的 install-matrix 一致：
# 在干净发行版容器里执行
#   bash deploy/install.sh --non-interactive --access-mode local --admin-password-stdin
# 该路径已被 CI 在 ubuntu:24.04/debian:12/rockylinux:9 上验证可装通并通过健康断言。
#
# 管理员口令安全约定（重要）：
#   - 安装器强制在安装期创建管理员（无"跳过管理员"参数），因此构建期使用
#     一个「当场从 /dev/urandom 生成、构建完立即删除其哈希」的一次性口令，
#     它不出现在任何 ARG/ENV 中（避免留在镜像历史），哈希文件随后被删除；
#   - 真实口令在【首次容器启动】时由 docker/entrypoint.sh 初始化：
#     环境变量 MAILSTACK_ADMIN_PASSWORD 提供，或生成随机口令并只打印一次。
#     口令明文绝不进入任何镜像层。
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# 安装器前置最小依赖（与 CI bootstrap 相同 + tini 作 PID1 + xz 供 Node tarball 解压）。
# Node.js 由安装器自行钉版本安装（哈希校验），不在此预装。
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends ca-certificates curl tini xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# dist 可能为空（本仓库如此）：安装器检测到无效预构建产物会自动执行
#   npm ci && npm run build:all
# 因此镜像构建需要网络访问（npm registry + nodejs.org 钉死哈希下载）。
COPY . .

# 运行安装器。构建期一次性口令：每次构建随机生成，安装完成后删除其哈希，
# 镜像层中不残留任何可用凭证。安装器会顺带完成构建产物门与安装后健康自检。
# 注意：必须以 bash 执行（显式包一层 `bash -c`，BuildKit 与 legacy builder 均适用）：
# legacy builder 默认用 /bin/sh（dash）执行 RUN，而 dash 中 `VAR=赋值 && 命令`
# 的赋值不产生 shell 变量（仅临时环境赋值，且被 && 分隔后不生效），导致
# $BUILD_ADMIN_PASS 展开为空。另：安装器用 `read -r` 读口令，无行尾时
# EOF 会返回非零（即使变量已赋值）——CI 用 `<<<`（自动补 \n）而此处用
# printf，故必须显式带上换行。清理阶段用 `[x]` 字符类写法防止 pkill
# 匹配到包着本命令串的构建 shell 自身而自杀（rc.1 构建实测修复，143）。
RUN bash -c 'set -e; \
    BUILD_ADMIN_PASS="MailStack-Build-$(tr -dc "A-Za-z0-9" </dev/urandom | head -c 20)-7Kx"; \
    printf "%s\n" "$BUILD_ADMIN_PASS" | bash deploy/install.sh \
         --non-interactive --access-mode local --admin-password-stdin; \
    rm -f /etc/mailstack/admin.json; \
    pkill -f "[n]ode /opt/mailstack/server.cjs" || true; \
    pkill -f "[n]ode /opt/mailstack/webmail.cjs" || true; \
    for p in $(pgrep -f "mailstackctl[.]py --daemon"); do \
        kill -TERM "$(ps -o ppid= -p "$p" | tr -d " ")" 2>/dev/null || true; \
    done; \
    postfix stop || true; \
    pkill "[d]ovecot" || true; \
    pkill "[o]pendkim" || true'

# 配置快照（种子）：/etc/* 与 /var/spool/postfix 会被声明为数据卷，空卷首启时
# 由 entrypoint 从这里回填（命名卷 Docker 也会自动从镜像层拷贝，此为绑定挂载兜底）。
# 注意：快照前已删除 admin.json，快照中不含任何凭证。
RUN mkdir -p /opt/mailstack-seed \
    && cp -a /etc/mailstack /opt/mailstack-seed/etc-mailstack \
    && cp -a /etc/postfix /opt/mailstack-seed/etc-postfix \
    && cp -a /etc/dovecot /opt/mailstack-seed/etc-dovecot \
    && cp -a /var/spool/postfix /opt/mailstack-seed/var-spool-postfix \
    && cp -a /var/lib/mailstack /opt/mailstack-seed/var-lib-mailstack \
    && cp -a /etc/opendkim.conf /opt/mailstack-seed/etc-opendkim.conf \
    && { [ -d /etc/opendkim ] && cp -a /etc/opendkim /opt/mailstack-seed/etc-opendkim || true; }

COPY docker/entrypoint.sh /usr/local/bin/mailstack-entrypoint.sh
RUN chmod 0755 /usr/local/bin/mailstack-entrypoint.sh

# 管理面 / Webmail / SMTP / IMAP / POP3
EXPOSE 8787 18788 25 465 587 143 993 110 995

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/mailstack-entrypoint.sh"]
