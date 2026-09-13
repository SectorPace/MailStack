# MailStack AI Integration Module with SSRF & DNS Rebinding Protection
import os
import pathlib
import json
import ssl
import ipaddress
import socket
import urllib.parse
import http.client
import datetime
from .core import warn
from .core import ETC, AI_CONFIG, atomic

PRIVATE_NETWORK_ENABLED = os.environ.get('MAILSTACK_ALLOW_PRIVATE_AI') == '1'


def private_network_enabled():
    return PRIVATE_NETWORK_ENABLED


def _effective_private_access(requested=False):
    if requested and not PRIVATE_NETWORK_ENABLED:
        raise ValueError('Private AI network access is disabled by deployment policy')
    return PRIVATE_NETWORK_ENABLED


AI_PRESETS = {
    'bigmodel': {
        'name': 'GLM (BigModel)',
        'baseUrl': 'https://open.bigmodel.cn/api/paas/v4',
        'model': 'glm-4-flash',
        'models': ['glm-4-flash', 'glm-4-plus', 'glm-4-air', 'glm-4-long', 'glm-4-0520'],
        'defaultKey': '',
        'docUrl': 'https://open.bigmodel.cn/usercenter/apikeys',
        'protocol': 'openai'
    },
    'deepseek': {
        'name': 'DeepSeek',
        'baseUrl': 'https://api.deepseek.com/v1',
        'model': 'deepseek-chat',
        'models': ['deepseek-chat', 'deepseek-reasoner'],
        'defaultKey': '',
        'docUrl': 'https://platform.deepseek.com/api_keys',
        'protocol': 'openai'
    },
    'openai': {
        'name': 'OpenAI',
        'baseUrl': 'https://api.openai.com/v1',
        'model': 'gpt-4o-mini',
        'models': ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo', 'o1-mini'],
        'defaultKey': '',
        'docUrl': 'https://platform.openai.com/api-keys',
        'protocol': 'openai'
    },
    'anthropic': {
        'name': 'Anthropic Claude',
        'baseUrl': 'https://api.anthropic.com/v1',
        'model': 'claude-3-5-sonnet-20241022',
        'models': ['claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 'claude-3-opus-20240229'],
        'defaultKey': '',
        'docUrl': 'https://console.anthropic.com/settings/keys',
        'protocol': 'anthropic'
    },
    'custom': {
        'name': 'Custom OpenAI-compatible provider',
        'baseUrl': '',
        'model': '',
        'models': [],
        'defaultKey': '',
        'docUrl': '',
        'protocol': 'openai'
    }
}

def is_ip_restricted(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True
    # IPv4-mapped/6to4/Teredo IPv6 forms embed an IPv4 address that the v6
    # property checks do NOT screen: ::ffff:100.64.0.1 reports is_private=False
    # and would sail past every rule below into an internal CGNAT service.
    # Unwrap to the embedded v4 address first, then apply the v4 rules.
    for attr in ('ipv4_mapped', 'sixtofour', 'teredo'):
        embedded = getattr(ip, attr, None)
        if embedded is not None:
            ip = embedded
            break
    # CGNAT (100.64.0.0/10) is not covered by ip.is_private, but cloud and ISP
    # internal services live there -- treat it as restricted for SSRF purposes.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network('100.64.0.0/10'):
        return True
    return bool(
        ip.is_private or
        ip.is_loopback or
        ip.is_link_local or
        ip.is_multicast or
        ip.is_reserved or
        ip.is_unspecified
    )

def resolve_and_pin_endpoint(url: str, allow_private: bool = False):
    allow_private = _effective_private_access(allow_private)
    raw_url = str(url or '').strip().rstrip('/')
    if not raw_url or len(raw_url) > 2048:
        raise ValueError('Invalid AI endpoint URL')
    u = urllib.parse.urlsplit(raw_url)
    if u.scheme not in ('http', 'https'):
        raise ValueError('AI endpoint must use HTTP or HTTPS')
    host = u.hostname
    if not host:
        raise ValueError('AI endpoint must include a hostname')
    if u.username or u.password or u.fragment:
        raise ValueError('AI endpoint cannot include credentials or a URL fragment')
    if u.scheme == 'http' and not allow_private:
        raise ValueError('Public AI endpoints must use HTTPS')
    port = u.port or (443 if u.scheme == 'https' else 80)
    
    # Resolve all IPs
    try:
        addrinfo = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception as e:
        raise ValueError(f'Unable to resolve AI endpoint {host}: {str(e)}')
        
    resolved_ips = []
    for entry in addrinfo:
        sockaddr = entry[4]
        ip_addr = sockaddr[0]
        if ip_addr not in resolved_ips:
            resolved_ips.append(ip_addr)
            
    if not resolved_ips:
        raise ValueError(f'AI endpoint {host} resolved to no usable IP address')
        
    if not allow_private:
        for ip_addr in resolved_ips:
            if is_ip_restricted(ip_addr):
                raise ValueError(
                    f'AI endpoint {host} resolves to restricted address ({ip_addr}); '
                    f'private-network access must be explicitly enabled to reduce SSRF risk'
                )
                
    pinned_ip = resolved_ips[0]
    return {
        'scheme': u.scheme,
        'host': host,
        'port': port,
        'path': u.path or '/',
        'query': u.query,
        'pinned_ip': pinned_ip,
        'raw_url': raw_url
    }

def validate_outbound_ip(host_or_ip: str, allow_private: bool = False, context_name: str = '') -> str:
    """Resolve an outbound target and return the first usable address.

    Every resolved address is screened, not just the first, so a hostname whose
    A-record set mixes public and private addresses cannot slip a private target
    past the check purely by ordering.
    """
    label = f'{context_name} ' if context_name else ''
    target = str(host_or_ip).strip()
    if not target or len(target) > 255:
        raise ValueError(f'Invalid outbound {label}host')

    def screen(candidate: str) -> None:
        if not allow_private and is_ip_restricted(candidate):
            raise ValueError(
                f'Outbound {label}host {target} resolves to restricted IP {candidate} '
                f'(private/loopback/link-local/metadata).'
            )

    literal = None
    try:
        literal = str(ipaddress.ip_address(target))
    except ValueError:
        literal = None
    if literal is not None:
        screen(literal)
        return literal

    try:
        addrinfo = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except Exception as exc:
        raise ValueError(f'Cannot resolve outbound {label}host {target}: {exc}') from exc

    resolved = []
    for entry in addrinfo:
        candidate = entry[4][0]
        if candidate not in resolved:
            resolved.append(candidate)
    if not resolved:
        raise ValueError(f'Outbound {label}host {target} resolved to no usable IP address')
    for candidate in resolved:
        screen(candidate)
    return resolved[0]

def validate_ai_endpoint(url: str, allow_private: bool = False) -> str:
    ep = resolve_and_pin_endpoint(url, allow_private=allow_private)
    return ep['raw_url']

def get_ai_ssl_context(insecure_tls: bool = False) -> ssl.SSLContext:
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    return ssl.create_default_context()

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, pinned_ip: str, port: int, timeout: int, context: ssl.SSLContext):
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def perform_pinned_http_request(url: str, method: str = 'POST', headers: dict = None, body: bytes = None, timeout: int = 35, allow_private: bool = False, insecure_tls: bool = False, redirects: int = 0):
    if redirects > 3:
        raise RuntimeError('AI endpoint redirected too many times')
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    allow_private = _effective_private_access(allow_private)
    ep = resolve_and_pin_endpoint(url, allow_private=allow_private)
    headers_copy = dict(headers or {})
    if not any(str(key).lower() == 'host' for key in headers_copy):
        default_port = 443 if ep['scheme'] == 'https' else 80
        headers_copy['Host'] = ep['host'] if ep['port'] == default_port else f"{ep['host']}:{ep['port']}"
    path_with_query = ep['path'] + (f"?{ep['query']}" if ep['query'] else '')
    if ep['scheme'] == 'https':
        conn = PinnedHTTPSConnection(ep['host'], ep['pinned_ip'], ep['port'], timeout, get_ai_ssl_context(insecure_tls))
    else:
        conn = http.client.HTTPConnection(ep['pinned_ip'], ep['port'], timeout=timeout)
    try:
        conn.request(method, path_with_query, body=body, headers=headers_copy)
        resp = conn.getresponse()
        resp_body = resp.read(2_000_001)
        if len(resp_body) > 2_000_000:
            raise RuntimeError('AI endpoint response exceeded 2 MB')
        if resp.status in (301, 302, 303, 307, 308):
            location = resp.getheader('Location')
            if not location:
                raise RuntimeError('AI endpoint returned an invalid redirect')
            new_url = urllib.parse.urljoin(url, location)
            old = urllib.parse.urlsplit(url)
            new = urllib.parse.urlsplit(new_url)
            old_port = old.port or (443 if old.scheme == 'https' else 80)
            new_port = new.port or (443 if new.scheme == 'https' else 80)
            if (old.scheme, old.hostname, old_port) != (new.scheme, new.hostname, new_port):
                raise RuntimeError('Cross-origin AI endpoint redirect was rejected')
            next_method = 'GET' if resp.status == 303 else method
            return perform_pinned_http_request(
                new_url,
                method=next_method,
                headers=headers,
                body=None if next_method == 'GET' else body,
                timeout=timeout,
                allow_private=allow_private,
                insecure_tls=insecure_tls,
                redirects=redirects + 1,
            )
        return resp.status, resp.reason, resp_body
    finally:
        try:
            conn.close()
        except Exception:
            pass

def ai_public_config():
    cfg = {}
    try:
        cfg = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except Exception:
        pass
    provider = cfg.get('provider', 'bigmodel')
    preset = AI_PRESETS.get(provider, AI_PRESETS['bigmodel'])
    key = cfg.get('apiKey', '')
    masked_key = (key[:4] + '****') if len(key) >= 8 else ('****' if key else '')
    return {
        'provider': provider,
        'providerName': preset['name'],
        'model': cfg.get('model') or preset['model'],
        'baseUrl': cfg.get('baseUrl') or preset['baseUrl'],
        'hasKey': bool(key),
        'maskedKey': masked_key,
        'docUrl': preset.get('docUrl', ''),
        'availablePresets': {k: {'name': v['name'], 'model': v['model'], 'models': v['models'], 'baseUrl': v['baseUrl'], 'docUrl': v['docUrl']} for k, v in AI_PRESETS.items()},
        'fallbackProvider': cfg.get('fallbackProvider', ''),
        'allowPrivateNetwork': PRIVATE_NETWORK_ENABLED,
        'insecureTls': False,
        'configured': bool(key or preset.get('defaultKey'))
    }

def ai_config_set(data):
    provider = str(data.get('provider', 'bigmodel')).strip()
    if provider not in AI_PRESETS: raise ValueError('Unsupported AI provider')
    preset = AI_PRESETS[provider]
    current = {}
    try:
        current = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        pass
    except Exception as exc:
        warn(f'parse AI config {AI_CONFIG}', exc)
    api_key = str(data.get('apiKey', '')).strip()
    if not api_key:
        api_key = current.get('apiKey', '') or preset.get('defaultKey', '')
    allow_private = _effective_private_access(bool(data.get('allowPrivateNetwork', current.get('allowPrivateNetwork', False))))
    if bool(data.get('insecureTls', current.get('insecureTls', False))):
        raise ValueError('TLS verification cannot be disabled for AI requests')
    base_url = validate_ai_endpoint(str(data.get('baseUrl') or preset['baseUrl']).strip(), allow_private=allow_private)
    cfg = {
        'provider': provider,
        'model': str(data.get('model') or preset['model']).strip(),
        'baseUrl': base_url,
        'apiKey': api_key,
        'fallbackProvider': str(data.get('fallbackProvider', '')).strip(),
        'allowPrivateNetwork': allow_private,
        'insecureTls': False,
        'updatedAt': datetime.datetime.now().isoformat()
    }
    atomic(AI_CONFIG, json.dumps(cfg, indent=2) + '\n', 0o600)
    try:
        atomic(ETC / 'ai.json', json.dumps(cfg, indent=2) + '\n', 0o600)
    except Exception as exc:
        warn(f"mirror AI config to {ETC / 'ai.json'}", exc)
    return ai_public_config()

def ai_models_list(data):
    provider = str(data.get('provider', '')).strip()
    preset = AI_PRESETS.get(provider, {})
    cfg = {}
    try:
        cfg = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        pass
    except Exception as exc:
        warn(f'parse AI config {AI_CONFIG}', exc)
    allow_private = _effective_private_access(bool(data.get('allowPrivateNetwork', cfg.get('allowPrivateNetwork', False))))
    insecure_tls = bool(data.get('insecureTls', cfg.get('insecureTls', False)))
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    base_url = str(data.get('baseUrl', '')).strip().rstrip('/')
    if not base_url:
        base_url = preset.get('baseUrl', '').rstrip('/')
    if not base_url:
        raise ValueError('AI provider API base URL is not configured')
    validate_ai_endpoint(base_url, allow_private=allow_private)
    api_key = str(data.get('apiKey', '')).strip()
    if not api_key:
        api_key = cfg.get('apiKey', '') or preset.get('defaultKey', '')
    url = base_url + '/models'
    headers = {'content-type': 'application/json', 'User-Agent': 'MailStack-AI-Hub/1.0'}
    if api_key:
        headers['authorization'] = f'Bearer {api_key}'
        
    status, reason, resp_body = perform_pinned_http_request(
        url,
        method='GET',
        headers=headers,
        timeout=15,
        allow_private=allow_private,
        insecure_tls=insecure_tls
    )
    if status != 200:
        raise RuntimeError(f'AI model list request failed: HTTP {status} ({reason})')
        
    result = json.loads(resp_body.decode('utf-8', errors='ignore'))
    models = []
    if isinstance(result, dict) and 'data' in result and isinstance(result['data'], list):
        for m in result['data']:
            if isinstance(m, dict) and 'id' in m: models.append(str(m['id']))
            elif isinstance(m, str): models.append(m)
    elif isinstance(result, list):
        for m in result:
            if isinstance(m, dict) and 'id' in m: models.append(str(m['id']))
            elif isinstance(m, str): models.append(m)
    models = sorted(list(set(models)))
    return {'models': models, 'count': len(models), 'baseUrl': base_url}

def ai_request_custom(messages, provider, base_url, api_key, model, max_tokens=1200, temperature=0.2, allow_private=False, insecure_tls=False):
    preset = AI_PRESETS.get(provider, AI_PRESETS['bigmodel'])
    protocol = preset.get('protocol', 'openai')
    validate_ai_endpoint(base_url, allow_private=allow_private)
    
    if protocol == 'anthropic':
        system_prompt = ''
        user_msgs = []
        for m in messages:
            if m.get('role') == 'system':
                system_prompt += (m.get('content', '') + '\n')
            else:
                user_msgs.append({'role': m.get('role', 'user'), 'content': m.get('content', '')})
        payload = {
            'model': model,
            'max_tokens': max_tokens,
            'temperature': temperature,
            'messages': user_msgs
        }
        if system_prompt.strip():
            payload['system'] = system_prompt.strip()
        req_headers = {
            'content-type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'User-Agent': 'MailStack-AI-Hub/1.0'
        }
        req_url = base_url.rstrip('/') + '/messages'
        status, reason, resp_body = perform_pinned_http_request(
            req_url,
            method='POST',
            headers=req_headers,
            body=json.dumps(payload).encode('utf-8'),
            timeout=35,
            allow_private=allow_private,
            insecure_tls=insecure_tls
        )
        if status != 200:
            raise RuntimeError(f'Claude API request failed: HTTP {status}: {resp_body.decode("utf-8", errors="ignore")}')
        result = json.loads(resp_body.decode('utf-8'))
        content = ''
        if 'content' in result and isinstance(result['content'], list):
            for blk in result['content']:
                if blk.get('type') == 'text': content += blk.get('text', '')
        return content.strip(), result.get('usage', {})
    else:
        # Standard OpenAI-compatible format
        payload = {
            'model': model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens
        }
        req_headers = {
            'content-type': 'application/json',
            'authorization': f'Bearer {api_key}',
            'User-Agent': 'MailStack-AI-Hub/1.0'
        }
        req_url = base_url.rstrip('/') + '/chat/completions'
        status, reason, resp_body = perform_pinned_http_request(
            req_url,
            method='POST',
            headers=req_headers,
            body=json.dumps(payload).encode('utf-8'),
            timeout=35,
            allow_private=allow_private,
            insecure_tls=insecure_tls
        )
        if status != 200:
            raise RuntimeError(f'AI completion request failed: HTTP {status}: {resp_body.decode("utf-8", errors="ignore")}')
        result = json.loads(resp_body.decode('utf-8'))
        choices = result.get('choices', [])
        if choices and len(choices) > 0:
            msg = choices[0].get('message', {})
            return (msg.get('content') or '').strip(), result.get('usage', {})
        return '', result.get('usage', {})

def ai_chat(data):
    messages = data.get('messages', [])
    if not isinstance(messages, list) or len(messages) == 0:
        raise ValueError('messages must be a non-empty list')
    cfg = {}
    try:
        cfg = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        pass
    except Exception as exc:
        warn(f'parse AI config {AI_CONFIG}', exc)
    provider = str(data.get('provider') or cfg.get('provider', 'bigmodel')).strip()
    preset = AI_PRESETS.get(provider, AI_PRESETS['bigmodel'])
    api_key = str(data.get('apiKey') or cfg.get('apiKey', '') or preset.get('defaultKey', '')).strip()
    base_url = str(data.get('baseUrl') or cfg.get('baseUrl') or preset.get('baseUrl', '')).strip()
    model = str(data.get('model') or cfg.get('model') or preset.get('model', '')).strip()
    max_tokens = int(data.get('maxTokens', 1500))
    temperature = float(data.get('temperature', 0.2))
    allow_private = _effective_private_access(bool(data.get('allowPrivateNetwork', cfg.get('allowPrivateNetwork', False))))
    insecure_tls = bool(data.get('insecureTls', cfg.get('insecureTls', False)))
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    
    if not api_key:
        raise ValueError(f'AI API key is not configured for {preset["name"]}')
        
    start_t = datetime.datetime.now()
    try:
        content, usage = ai_request_custom(
            messages=messages,
            provider=provider,
            base_url=base_url,
            api_key=api_key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            allow_private=allow_private,
            insecure_tls=insecure_tls
        )
        lat = max(1, round((datetime.datetime.now() - start_t).total_seconds() * 1000))
        return {'status': 'ok', 'provider': provider, 'model': model, 'reply': content, 'latencyMs': lat, 'usage': usage}
    except Exception as e:
        fallback = cfg.get('fallbackProvider')
        if fallback and fallback in AI_PRESETS and fallback != provider and not data.get('provider'):
            fb_preset = AI_PRESETS[fallback]
            fb_key = cfg.get('fallbackApiKey') or fb_preset.get('defaultKey', '')
            if fb_key:
                content, usage = ai_request_custom(
                    messages=messages,
                    provider=fallback,
                    base_url=fb_preset['baseUrl'],
                    api_key=fb_key,
                    model=fb_preset['model'],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    allow_private=allow_private,
                    insecure_tls=insecure_tls
                )
                lat = max(1, round((datetime.datetime.now() - start_t).total_seconds() * 1000))
                return {'status': 'ok', 'provider': fallback, 'model': fb_preset['model'], 'reply': content, 'latencyMs': lat, 'usage': usage, 'fallbackUsed': True}
        raise e

def ai_request(messages, max_tokens=1200, temperature=0.2, specific_provider=None):
    cfg = {}
    try: cfg = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except Exception:
        try: cfg = json.loads(ETC.joinpath('ai.json').read_text(encoding='utf-8'))
        except Exception: cfg = {}
    provider = specific_provider or cfg.get('provider', 'bigmodel')
    preset = AI_PRESETS.get(provider, AI_PRESETS['bigmodel'])
    key = str(cfg.get('apiKey', '') or preset.get('defaultKey', '')).strip()
    model = str(cfg.get('model') or preset['model']).strip()
    allow_private = _effective_private_access(bool(cfg.get('allowPrivateNetwork', False)))
    insecure_tls = bool(cfg.get('insecureTls', False))
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    base_url = cfg.get('baseUrl') or preset['baseUrl']
    if not key: raise RuntimeError(f'{provider} API key is not configured')
    try:
        content, _ = ai_request_custom(
            messages=messages,
            provider=provider,
            base_url=base_url,
            api_key=key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            allow_private=allow_private,
            insecure_tls=insecure_tls
        )
        return content
    except Exception as e:
        fallback = cfg.get('fallbackProvider')
        if fallback and fallback in AI_PRESETS and fallback != provider and not specific_provider:
            try:
                return ai_request(messages, max_tokens, temperature, specific_provider=fallback)
            except Exception as fallback_exc:
                warn(f'AI fallback provider {fallback}', fallback_exc)
        raise e

def ai_test(data):
    messages = [{'role': 'user', 'content': 'Hello, test connection.'}]
    start = datetime.datetime.now()
    cfg = {}
    try:
        cfg = json.loads(AI_CONFIG.read_text(encoding='utf-8'))
    except FileNotFoundError:
        pass
    except Exception as exc:
        warn(f'parse AI config {AI_CONFIG}', exc)
    provider = str(data.get('provider') or cfg.get('provider', 'bigmodel')).strip()
    preset = AI_PRESETS.get(provider, AI_PRESETS['bigmodel'])
    api_key = str(data.get('apiKey') or cfg.get('apiKey', '') or preset.get('defaultKey', '')).strip()
    base_url = str(data.get('baseUrl') or cfg.get('baseUrl') or preset.get('baseUrl', '')).strip()
    model = str(data.get('model') or cfg.get('model') or preset.get('model', '')).strip()
    allow_private = _effective_private_access(bool(data.get('allowPrivateNetwork', cfg.get('allowPrivateNetwork', False))))
    insecure_tls = bool(data.get('insecureTls', cfg.get('insecureTls', False)))
    if insecure_tls:
        raise ValueError('TLS verification cannot be disabled for AI requests')
    
    if not api_key:
        raise ValueError(f"AI API key is not configured for {preset['name']}")
        
    content, usage = ai_request_custom(
        messages=messages,
        provider=provider,
        base_url=base_url,
        api_key=api_key,
        model=model,
        max_tokens=20,
        temperature=0.1,
        allow_private=allow_private,
        insecure_tls=insecure_tls
    )
    elapsed_ms = max(1, round((datetime.datetime.now() - start).total_seconds() * 1000))
    return {
        'status': 'ok',
        'provider': provider,
        'model': model,
        'reply': content[:100],
        'latencyMs': elapsed_ms,
        'usage': usage
    }

def ai_diagnose(data):
    logs = str(data.get('logs', '')).strip()
    prompt = f"Analyze these Linux mail-server logs and return prioritized findings.\n\n{logs}"
    return ai_chat({'messages': [{'role': 'user', 'content': prompt}]})

def ai_parse(data):
    raw_text = str(data.get('text', '')).strip()
    prompt = f"Parse the following mail configuration and return strict JSON diagnostics.\n\n{raw_text}"
    return ai_chat({'messages': [{'role': 'user', 'content': prompt}]})
