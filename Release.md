# MailStack v0.1-beta1

<p align="center">
  <img src="https://raw.githubusercontent.com/SectorPace/MailStack/main/assets/mailstack-logo.png" alt="MailStack Logo" width="160">
</p>

MailStack 的首个公开 Beta 测试版本，提供 Liquid Glass Web 管理后台、Linux 邮件服务管理基础能力、可配置 AI 邮件顾问，以及面向 VPS 的统一安装与快捷管理入口。

> 这是公开测试版本。建议只在全新测试 VPS 上部署，不要直接覆盖现有生产邮件服务器。

## 主要功能

- Liquid Glass 风格 React 管理后台
- 简体中文与英文界面
- Light 与 Dark 双主题
- 自定义 Web 管理员用户名和密码
- 自定义管理端口和监听地址
- VPS `mailstack` 快捷管理菜单
- 邮件域名、Linux 邮箱用户与地址别名管理
- Postfix 与 Dovecot 服务状态管理
- SMTP Relay 配置和服务商预设
- TLS、DKIM、DNS、邮件队列与日志页面
- 基础安全检查和服务管理
- HttpOnly Session Cookie 与 CSRF 防护
- 受限 sudo 特权助手
- Gemini、Groq、OpenRouter、Mistral、Cerebras 和自定义兼容 API
- 无外部 AI API 时的本地规则诊断模式

## 安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack
chmod +x mailstack.sh
sudo bash ./mailstack.sh install
```

安装完成后，在 VPS 任意目录运行：

```bash
mailstack
```

## 推荐访问方式

后台默认监听：

```text
127.0.0.1:8787
```

推荐使用 SSH 隧道：

```bash
ssh -L 8787:127.0.0.1:8787 root@服务器IP
```

请勿在未配置 HTTPS、防火墙和 IP 白名单的情况下，将管理端口直接暴露到公网。

## Beta 测试重点

欢迎重点测试并反馈：

- 不同 systemd Linux 发行版的安装流程
- Postfix 和 Dovecot 状态识别
- 域名、用户和别名管理
- 邮件队列和日志读取
- SMTP Relay 配置流程
- TLS、DKIM 和 DNS 引导
- 管理员账户与端口修改
- AI Provider 和自定义 API 连接
- 中英文界面与 Light/Dark 模式

## 已知限制

- 尚未完成所有支持发行版的端到端验证
- 高级 Relay 故障转移和防重复投递仍需验证
- ACME 首次签发、DNS-01 自动化和证书回滚仍需增强
- DKIM、Rspamd、ClamAV、Fail2ban 和防火墙功能仍需发行版适配
- AI 建议不能替代管理员审查，也不能保证邮件进入收件箱
- Mock 或演示状态不应被视为真实服务器结果

## 安全提醒

请勿在 Issue 或日志附件中公开：

- SMTP 密码
- 管理员哈希或密码
- AI API Key
- DKIM 私钥
- TLS 私钥
- ACME DNS API Key
- 邮箱正文
- 未脱敏的生产日志

## 校验与源码

本 Release 对应 Git 标签：

```text
v0.1-beta1
```

安装前可以检查脚本：

```bash
bash -n mailstack.sh
bash mailstack.sh version
```

预期版本输出：

```text
v0.1-beta1
```

感谢参与 MailStack 的首个公开 Beta 测试。
