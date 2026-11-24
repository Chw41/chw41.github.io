---
title: "[OSED, EXP-301] Instructional notes"
date: 2026-11-24
author: "CHW"
tags:
  - offsec
description: "OSED / EXP-301 instructional notes covering x86 architecture and WinDbg debugging, stack buffer overflow exploitation, SEH overflows and SafeSEH, reverse engineering with IDA Pro, egghunters under space restrictions, and hand-written x86 custom shellcode with PEB walking, export table parsing, API hashing, NULL-free position-independent code, and a reverse shell."
---

This series summarizes my OSED / EXP-301 learning notes, focusing on Windows user-mode exploit development: x86 architecture and WinDbg debugging, stack and SEH overflow exploitation, reverse engineering with IDA Pro, egghunters under space restrictions, and writing custom shellcode from scratch.

以下筆記整理了在 OSED / EXP-301 學習過程中的紀錄，重點涵蓋 Windows User Mode 漏洞利用開發：x86 架構與 WinDbg 除錯、Stack Overflow 與 SEH Overflow 利用、IDA Pro 逆向工程、空間受限環境下的 Egghunter，以及從零手寫 Custom Shellcode。

- [Instructional Notes Part 1](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-1/)\
  **x86 Architecture, WinDbg Fundamentals, and Stack Buffer Overflows**\
  Program Memory (Stack, Calling Conventions, Function Return Mechanics), CPU Registers, WinDbg Interface and Debugging Symbols, Reading / Writing / Searching Memory, Dumping Structures from Memory, Software and Hardware Breakpoints, Stepping Through the Code (p / t / pt / ph), Pseudo Registers, Sync Breeze Stack Overflow, DEP / ASLR / CFG, Controlling EIP, Checking for Bad Characters, Finding a JMP ESP Return Address, Generating Shellcode with msfvenom, etc.

- [Instructional Notes Part 2](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-2/)\
  **SEH Overflows and Introduction to IDA Pro**\
  Structured Exception Handling (SEH), TEB and _NT_TIB, _EXCEPTION_REGISTRATION_RECORD, KiUserExceptionDispatcher and RtlDispatchException, SafeSEH and SEHOP, Inspecting the SEH Chain with !exchain, Locating Modules without SafeSEH (narly), POP POP RET Instruction Sequence, NSEH / SEH Overwrite, Short Jump and Island-Hopping in Assembly, IDA Pro User Interface (Graph / Text / Proximity View), Search and Cross-References, Static-Dynamic Analysis Synchronization (Rebase Program), Tracing Notepad (CreateFileW / ReadFile), etc.

- [Instructional Notes Part 3](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-3/)\
  **Overcoming Space Restrictions: Egghunters**\
  Savant Web Server 3.1 (CVE-2002-1120), Crash Analysis and Bad Characters Detection, Partial EIP Overwrite, POP EAX; RET and Conditional Jumps, Changing the HTTP Method, Windows Heap Memory Manager, Finding Alternative Places to Store Large Buffers, Keystone Engine, System Calls and Egghunters (NtAccessCheckAndAuditAlarm), Fixing the Windows 10 System Call Number and NULL Bytes, Obtaining a Meterpreter Shell, Improving the Egghunter Portability Using SEH, etc.

- [Instructional Notes Part 4](https://chw41.github.io/b1og/osed-exp-301-instructional-notes---part-4/)\
  **Porting the SEH Egghunter to Windows 10 and Creating Custom Shellcode**\
  Identifying the SEH-Based Egghunter Issue, Porting the SEH Egghunter to Windows 10 (TEB StackBase), Calling Conventions on x86, The System Call Problem, Finding kernel32.dll (PEB Method), Export Directory Table, Working with the Export Names Array, Computing Function Name Hashes, Fetching the VMA of a Function, NULL-Free Position-Independent Shellcode (PIC), Reverse Shell (LoadLibraryA, WSAStartup, WSASocketA, WSAConnect, CreateProcessA), etc.
