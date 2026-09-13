# MailStack RPC Request Dispatcher
import json
from .core import ALLOWED_ACTIONS, DESTRUCTIVE_ACTIONS, admin_public, admin_set, ai_outbound_enabled
from .security import security_scan, fail2ban_unban, fail2ban_ban
from .ai import (
    ai_public_config, ai_config_set, ai_models_list, ai_test,
    ai_chat, ai_diagnose, ai_parse, ai_request_custom, ai_request
)
from .certs import certs, cert_renew, setup_cert_issue, dkim_rotate
from .backup import backup_create, backup_list, backup_restore, backup_delete
from .mail import (
    domain_list, domain_add, domain_delete, users, user_add, user_del,
    user_status, user_password, aliases, alias_add, alias_del,
    queue, queue_action, mail_test_loopback
)
from .network import (
    network_check_port, setup_identity, setup_dns_verify,
    setup_relay, setup_relay_apply, setup_send_test, setup_status
)
from .telemetry import (
    status, system_doctor, logs, settings, settings_set, metrics_realtime, services
)
from .totp import totp_begin, totp_enable, totp_disable, totp_consume_recovery, totp_verify

# B5 密码与密钥政策：会发起出站 AI 调用的 action（含 ai.models.list 的
# GET /models 出站探测）。公网模式默认拒绝，需 ai_outbound_enabled() 的
# 显式开关（环境变量或 /etc/mailstack/ai.conf）才放行；ai.config.get/set
# 为本机读写，不在门内。集合必须与 core.ALLOWED_ACTIONS 里的 ai.* 子集
# 保持一致（不得出现未注册 action）。
AI_OUTBOUND_ACTIONS = {
    'ai.test', 'ai.chat', 'ai.diagnose', 'ai.parse', 'ai.models.list',
}

def dispatch(action, data=None):
    data = data or {}
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f'unsupported action: {action}')
    if not isinstance(data, dict):
        raise ValueError('data must be an object')
    if action in DESTRUCTIVE_ACTIONS and data.get('confirm') is not True:
        raise ValueError('explicit confirmation required')
        
    # Snapshot & Doctor
    if action == 'snapshot': return status()
    if action == 'system.doctor': return system_doctor()
    
    # Setup Flow
    if action == 'setup.status': return setup_status()
    if action == 'setup.identity.apply': return setup_identity(data)
    if action == 'setup.dns.verify': return setup_dns_verify(data)
    if action == 'setup.relay.test': return setup_relay(data)
    if action == 'setup.relay.apply': return setup_relay_apply(data)
    if action == 'setup.cert.issue': return setup_cert_issue(data)
    if action == 'setup.mail.test': return setup_send_test(data)
    
    # Mail & Loopback
    if action == 'mail.test_loopback': return mail_test_loopback(data)
    if action == 'network.check_port': return network_check_port(data)
    if action == 'dkim.rotate': return dkim_rotate(data)
    
    # Settings & Telemetry
    if action == 'settings.get': return settings()
    if action == 'settings.set': return settings_set(data)
    if action == 'logs.list': return logs(data.get('limit', 200))
    if action == 'metrics.realtime': return metrics_realtime()
    if action == 'services.action':
        ident = str(data.get('id', '') or data.get('name', '') or data.get('service', '')).strip()
        verb = str(data.get('verb', '') or data.get('action', 'restart')).strip().lower()
        from .core import SERVICES, service_ctl
        if ident not in SERVICES and ident in SERVICES.values():
            unit = ident
        elif ident in SERVICES:
            unit = SERVICES[ident]
        else:
            raise ValueError(f'invalid service: {ident}')
        if verb not in ('start', 'stop', 'restart', 'reload', 'status'):
            raise ValueError(f'invalid service verb: {verb}')
        # 管理后台不能停掉自己承载本次请求的服务：请求经 mailstack-web 的
        # sudo helper 下发，停掉 mailstack-web 后没有任何途径再把它拉起来，
        # 只能上控制台。重启是允许的（systemd 三秒内拉回，不构成自锁）。
        if unit == 'mailstack-web' and verb == 'stop':
            raise ValueError('refusing to stop the admin console from itself; run "systemctl stop mailstack-web" from a shell')
        service_ctl(unit, verb)
        return services()
        
    # Backups
    if action == 'backup.create': return backup_create(data)
    if action == 'backup.list': return backup_list()
    if action == 'backup.restore': return backup_restore(data)
    if action == 'backup.delete': return backup_delete(data)
    
    # Domains
    if action == 'domains.list': return domain_list()
    if action == 'domains.add': return domain_add(data)
    if action == 'domains.delete': return domain_delete(data)
    
    # Users & Aliases & Queue
    if action == 'users.add': return user_add(data)
    if action == 'users.delete': return user_del(data)
    if action == 'users.status': return user_status(data)
    if action == 'users.password': return user_password(data)
    if action == 'aliases.add': return alias_add(data)
    if action == 'aliases.delete': return alias_del(data)
    if action == 'queue.action': return queue_action(data)
    
    # Security
    if action == 'security.scan': return security_scan(certs_fn=certs)
    if action == 'security.unban': return fail2ban_unban(data)
    if action == 'security.ban': return fail2ban_ban(data)
    
    # Certs
    if action == 'certs.list': return certs()
    if action == 'certs.renew': return cert_renew(data)
    
    # Admin
    if action == 'admin.get': return admin_public()
    if action == 'admin.set': return admin_set(data)
    if action == 'admin.totp.begin': return totp_begin(data)
    if action == 'admin.totp.enable': return totp_enable(data)
    if action == 'admin.totp.disable': return totp_disable(data)
    if action == 'admin.totp.consume_recovery': return totp_consume_recovery(data)
    if action == 'admin.totp.verify': return totp_verify(data)
    
    # AI Hub
    # B5: 公网模式默认关 AI 出站（fail-closed）：无显式开关时拒绝，
    # 错误消息直接告诉运维如何开启。local 模式恒放行（历史行为）。
    if action in AI_OUTBOUND_ACTIONS and not ai_outbound_enabled():
        raise ValueError('AI outbound actions are disabled in public mode; set MAILSTACK_AI_OUTBOUND=1 or /etc/mailstack/ai.conf enabled=true to opt in')
    if action == 'ai.config.get': return ai_public_config()
    if action == 'ai.config.set': return ai_config_set(data)
    if action == 'ai.models.list': return ai_models_list(data)
    if action == 'ai.test':
        provider = data.get('provider')
        base_url = data.get('baseUrl')
        api_key = data.get('apiKey')
        model = data.get('model')
        msg = [{'role': 'user', 'content': 'Reply in one short sentence: MailStack AI connection test successful.'}]
        if base_url or api_key or model or provider:
            reply = ai_request_custom(msg, provider or 'custom', base_url, api_key, model, max_tokens=100, temperature=0.1)
        else:
            reply = ai_request(msg, 100, 0.1)
        return {'success': True, 'reply': reply, 'config': ai_public_config()}
    if action == 'ai.chat': return ai_chat(data)
    if action == 'ai.diagnose': return ai_diagnose(data)
    if action == 'ai.parse': return ai_parse(data)
    
    raise ValueError(f'unsupported action: {action}')
