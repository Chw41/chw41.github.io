---
title: "【關於不是大佬考完OSCE³】"
date: 2026-11-25
author: "CHW"
tags:
  - offsec
description: "OSCE³ 心得：OSWE、OSEP、OSED 與 OSWA 準備時程、考試感想與學習筆記。"
---

【關於不是大佬考完OSCE³】
===

[TOC]

## Takeaways

>[!Important]
>先定義大佬:
>id 或頭貼與水果、動物(特別是貓和水上生物)、銀河系、兩個英文字母、疊字、👁️、咖波、動漫相關的，通常都是大佬 🛐
>> 總之…我不是

[OSCE³](https://www.offsec.com/certificates/osce3/) 是 OffSec 頒發的資安專業認證，想要拿到這張證照必須蒐集三大秘寶：[OSWE](https://www.offsec.com/courses/web-300/)、[OSEP](https://www.offsec.com/courses/pen-300/) 和 [OSED](https://www.offsec.com/courses/exp-301/)！

![image](https://hackmd.io/_uploads/BJS8ZAzy7l.png)

- OffSec 所有證照參考: [Courses & Certifications](https://www.offsec.com/courses/)
- 課程代號原廠文件：[What is your course code system?](https://help.offsec.com/hc/en-us/articles/360050682771-What-is-your-course-code-system#h_01H0DB7E8HV6FNH6XWF3Z3MP3X)
    - OSWE:\
    "Learn advanced web application attacks and exploits, including advanced SSRF, persistent XSS and blind SQLi to .NET deserialization, source code analysis, session hijacking, fuzzing, and authentication bypass"
    - OSEP:\
    "Develop advanced ethical hacking skills, including executing client-side attacks, bypassing application whitelisting, and performing advanced Active Directory attacks. Build advanced cybersecurity skills through hands-on offensive security training and enterprise attack simulations"
    - OSED:\
    "Learn advanced exploit development techniques, including reverse engineering, writing shellcode, and bypassing modern mitigations"

總之就是三張考試時間各自為實作 48 h + 報告撰寫 24 h，共 72 小時的證照，三張通過後可以取得 OSCE3

💡 現在報名：216 小時後你也是 OSCE³

## Schedule

以下是時間排程：
在 2025/09 考完 OSCP+ 想說休息一陣子，年底就看到 Learn Unlimited 即將 retired 的消息 ([Learn Unlimited FAQ](https://help.offsec.com/hc/en-us/articles/4403415547540-Learn-Unlimited-FAQ))\
感謝 [OffSec](https://www.offsec.com/) X [DEVCORE](https://training.devco.re/) 讓我搭上 LU 末班車，索性再刷了 16 萬

課程選定在 1 月底啟用，一開始打算先刷 OSWA 提升信心
### - **2026/02 OSWA (100/70)**
  排定一個月看教材，順利拿到滿分。考試題目對於 Web 仔來說難度不高，都是基本的 OWASP Top 10，相較教材內容，反而覺得 [PortSwigger
 lab](https://portswigger.net/web-security/all-labs) 會更豐富

進到 300 系列打算 3 個月考一張 (放空半個月、兩個月準備、半個月打 lab)，雖然後來不是在工作專案就是在看教材 XD
### -  **2026/05 OSWE (100/85)**
在今年 3-5 月 AI Agent 突然大量普及，正在準備這張慢慢看 code 的我看到懷疑人生。也在想 code reviewer 和 code developer 會不會出現在 10 年後的歷史博物館，🥚 主要還是著重在自己技術能力提升\
當時也試過讓 GPT-5.3 打 oswe challenge lab，平均 15分鐘內解完 …\
總之後來是順利滿分拿下
### -  **2026/08 OSEP (100/100)**
平時有在打紅隊和滲透，這張相對輕鬆一點。主要內容以 OSCP based 延伸如何去規避防禦機制\
不過 Evasion Techniques 在整個考試過程，沒有用到任何 Shellcode Runner、bypass 技巧，順利拿到最後的 secret
### -  **2026/11 OSED (60/60)**
這張是 300 中唯一 60分就能通過的，也是個人目前唯一一張沒有滿分且低空飛過。從 Overflow offset, Bad char, ROP chain, DEP/ASLR 每一個階段對於 Web 仔來說都是很煎熬 😩\
現在看到 Windows Exploiter 都是六體投地 🛐🛐🛐

維持了近 10 個月每天固定行程：
- 上班
- 下班
- 健身房
- 看證照

最多人的疑問肯定是 "不會被 AI 取代嘛？"\
OSCE³ 過程比較像是一場馬拉松在累積自己的實力，目前階段的 AI 除了模型差異外，感覺最大差異還是在於操作的使用者和 Skill ?! 🤔
畢竟 [Orange](https://blog.orange.tw/) 用 AI 和我用 AI 結果肯定不一樣 XD

>For 還是學生：\
如果也想收集 OffSec Badge，在學生時期就勇敢按下去。學校課表可以自己安排。進入職場後，客戶的需求是不可控的🤣 下班後才是自己坐下看證照的時間

最大的遺憾是 Learn Unlimited 沒有包含 [OSAI+](https://www.offsec.com/courses/ai-300/)
雖然技術能力明顯提升，也把觀念重新整理了一遍，但也確實感受到 Lab 環境的漏洞、防毒版本和 x86 架構，放到現代環境的實用性有限

還剩 2 個多月時間，再考個比 OSCE3 還稀有的 KLCP 吧

## OSCE³ Study Resources

準備 OSCE³ 的這段期間，把每張證照的教材重點、lab 實作整理成系列筆記，放在 blog 上，給正在準備或考慮入坑的人參考。筆記是我個人的理解和整理，不能取代官方教材，建議搭配課程一起看。\
P.S 後半段筆記還沒整理完，陸續更新...

![image](https://hackmd.io/_uploads/SyJXF6MyQg.png)

### - BGM playlist
對於長時間學習和考試時間，除了靠自己梳理思緒、逐步拆解問題之外，背景音樂也可以大大幫助。一份順耳的 BGM 可以把周遭的雜音隔開，讓自己更快進入狀態，也能在卡關的時候把情緒穩住。\
推薦這首 [Try Harder](https://youtu.be/t-bgRQfeW64) 聽過無數次、經典不敗的老歌。旋律早就刻在腦子裡，就算連續循環好幾個小時也不容易覺得累。\
~~(甚至半夜聽到會嚇醒，不輸[心靈捕手](https://youtu.be/ybHJNc0Fi3Y) 🥵)~~\
找到適合自己的節奏，長時間作戰更能撐得下去，就是 "Try Harder" 陪我走過這段時間

### - [**OSWE (WEB-300)** Notes](https://chw41.github.io/b1og/oswe-web-300-instructional-notes/)
以 Source Code Review 和 Exploit Chain 分析為主軸。從 .NET / Java 反編譯開始，涵蓋 SQL Injection、Deserialization、XmlSerializer、SSTI、XXE、SOP / CORS / CSRF、SSRF、Prototype Pollution (EJS、Handlebars)，最後是 Eval Filter Bypass 與 WAF Bypass (Coraza)。環境範例包含 ERPNext、openCRX、openITCOCKPIT、Concord、Dolibarr、RudderStack 等 case study，逐步拆解 exploit chain。

### -  [**OSEP (PEN-300)** Notes](https://chw41.github.io/b1og/osep-pen-300-instructional-notes/)
聚焦在 Initial Access 到繞過 Endpoint 防禦。內容包含 Windows 基礎與 Office VBA Macro 釣魚、Client-side Attack (.ics 行事曆釣魚、Responder、DLL Sideloading)、JScript Dropper、DotNetToJscript、C# Shellcode Runner 與 PowerShell Reflection。規避手法包含 Process Injection / Hollowing、AV Evasion (Signature 定位、Sleep Timer、WMI Dechaining 等等)、AMSI Bypass、UAC Bypass，最後是 AppLocker、LOLBAS 與 PowerShell CLM Bypass。

### - [**OSED (EXP-301)** Notes](https://chw41.github.io/b1og/osed-exp-301-instructional-notes/)
從 Web 仔的角度重新入門 Windows User-mode Exploit Development。從 x86 架構、WinDbg 操作開始，實作 Stack Overflow (控制 EIP、Bad Char、JMP ESP)、SEH Overflow (TEB / _NT_TIB、SafeSEH / SEHOP、POP POP RET、NSEH Short Jump) 與 IDA Pro 靜態分析。以 Savant Web Server 實作空間受限時的 Egghunter、透過 PEB 找 kernel32.dll、解析 Export Table，手刻 NULL-free 的 Reverse Shell Shellcode。


>[!Note]
>另外附上一些實用的文章:
>- [Red Team Notes](https://www.ired.team/)
>- [HackTricks](https://hacktricks.wiki/en/index.html#hacktricks)
>- [Shellcode.Blog](https://shellcode.blog/)
>- [Structured Exception Handler](https://memn0ps.github.io/windows-user-mode-exploit-development-seh-part-2/)
>- [0xBEN | Notes](https://notes.benheater.com/)
>- [Reverse Shell Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/)


