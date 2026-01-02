# 🔐 React2Shell - Next.js RSC Pollution RCE Toolkit

This Python toolkit exploits Next.js React Server Components (RSC) prototype pollution + React.lazy(-1) gadget chain for full RCE access, including interactive god shell, file upload (PHP webshell dropper), and exfiltration via `?out=`.

## **Image Preview**
![Pwned](https://github.com/khadafigans/React2Shell/raw/main/pwned.jpg)
![Terminal](https://github.com/khadafigans/React2Shell/raw/main/terminal.jpg)

## 🧾 main.py
### 📌 Purpose
Automated detection & exploitation of vulnerable Next.js apps (e.g., invoices.my.id). Drops uid=33(www-data) shell with:
- RCE via `child_process.execSync` → `/exploit?out=UID`
- God Shell: Interactive cmds, file read (`read /etc/passwd`), uploads
- Bypass: Junk KB padding, Unicode, Vercel/WAF tweaks
- Stealth: Base64 encode, multipart RSC POST

### 🛠 How It Works
1. **Detect**: POST `{\"0\":null}` → 500 `E{\"digest` confirms RSC handler.
2. **Combos**: Test pollution+lazy payloads (junk=0/KB, uni, vercel) → `Location: /exploit?out=id_output`
3. **Exploit**: `execSync(cmd)` → exfil stdout/stderr via redirect.
4. **Shell**: Loop cmds, `upload_txt local.txt remote.php` → write+rename bypass.
5. **WAF**: X-FF=127.0.0.1, Origin/Referer evade BitNinja/nginx.

### 📥 Usage
1. `pip3 install aiohttp`
2. `python3 main.py`
3. Enter target(s): `http://invoices.my.id` or `targets.txt`
4. Mode: `1=Detect 2=PoC(id) 3=Custom 4=God Shell [4]`

**Piped**: `echo \"http://target\n4\" | python3 main.py`

**God Shell Commands**:
```
upload <local.php> <remote/shell.php>    # Direct PHP upload
upload_txt <local> <remote/shell.php>    # TXT→rename bypass
upload_bin <local> <remote>              # Binaries (chmod later)
help / exit
id / cat /etc/passwd / ls -la /var/www/
```

### 📁 Output
- Vulnerable: `React2Shell_Owned/pwned_YYYYMMDD_HHMMSS.txt`
- Screenshots: Banner → `[VULNERABLE]` → `uid=33(www-data)`

### 📦 Dependencies
```
aiohttp
```
`pip install aiohttp`

## ⚠️ Legal Disclaimer
For authorized penetration testing & educational purposes only (user confirmed permission under ToS). Unauthorized use illegal/unethical.

## 👨‍💻 Author
[Bob Marley](https://github.com/khadafigans)

Buy me a Coffee:
```
₿ BTC: 17sbbeTzDMP4aMELVbLW78Rcsj4CDRBiZh
```

©2025 khadafigans
