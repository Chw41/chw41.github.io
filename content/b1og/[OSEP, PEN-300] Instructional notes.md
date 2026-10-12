---
title: "[OSEP, PEN-300] Instructional notes"
date: 2026-10-12
author: "CHW"
tags:
  - offsec
description: "OSEP / PEN-300 instructional notes covering antivirus evasion, application whitelisting and AppLocker bypass, process injection and migration, reflective code execution, client-side and Office macro attacks, JScript/C#/PowerShell shellcode runners, AMSI and UAC bypass, and the defensive mechanisms modern Windows environments rely on."
---

This series summarizes my OSEP / PEN-300 learning notes, focusing on antivirus evasion, application whitelisting bypass, process injection and migration, reflective code execution, client-side code execution, and the defensive mechanisms (AMSI, UAC, AppLocker) that modern Windows environments rely on.

以下筆記整理了在 OSEP / PEN-300 學習過程中的紀錄，重點涵蓋防毒軟體繞過、應用程式白名單繞過、程序注入與遷移、反射式程式碼執行、用戶端程式碼執行，以及 Windows 環境的防禦機制（AMSI、UAC、AppLocker）。

- [Instructional Notes Part 1](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/)
  **Operating System Theory, Office Macro Phishing, and Client-Side Attacks**
  Compiled vs. Interpreted Languages, Windows on Windows (WOW64), Win32 APIs, Windows Registry, Microsoft Office VBA Macros, Executing Shellcode in Word Memory, VBA Shellcode Runner, PowerShell Shellcode Runner, Phishing with Calendars (iCalendar / ICS), Credential Stealing with Responder, DLL Sideloading Using Signed Microsoft Binaries, Proxying the Calls, Weaponizing ZIP Containers for Client-Side Execution, etc.

- [Instructional Notes Part 2](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-2/)
  **JScript Droppers, C# Shellcode Runners, and Reflective PowerShell**
  Basic Dropper in JScript, JScript Meterpreter Dropper, DotNetToJscript, Win32 API Calls from C#, Shellcode Runner in C#, SharpShooter, Classic PowerShell Tradecraft, PowerShell and .NET, Leveraging UnsafeNativeMethods, DelegateType Reflection, Reflection Shellcode Runner in PowerShell, Reflective Code Execution in Client-Side Attacks, etc.

- [Instructional Notes Part 3](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-3/)
  **Process Injection, Migration, and Antivirus Evasion**
  Process Injection Theory (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), DLL Injection, Reflective DLL Injection, Process Hollowing (PEB / PE Header / EntryPoint parsing), Locating Signatures in Files, Metasploit Encoders and Encryptors, Encrypting the C# Shellcode Runner, Sleep Timers and Non-emulated APIs, Bypassing Antivirus in VBA, Module Stomping on Microsoft Word, Hiding PowerShell Inside VBA, Dechaining with WMI, Obfuscating VBA, etc.

- [Instructional Notes Part 4](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-4/)
  **Advanced Antivirus Evasion, AMSI Bypass, and UAC Bypass**
  Intel Architecture (Stack, Heap, CPU Registers, 32-bit vs 64-bit), WinDbg Introduction, Antimalware Scan Interface (AMSI), Hooking with Frida, Bypassing AMSI with Reflection in PowerShell, Wrecking AMSI by Patching the Internals, FodHelper UAC Bypass and Improvements, Bypassing AMSI in JScript (Registry key abuse, self-executable techniques), etc.

- [Instructional Notes Part 5](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-5/)
  **Application Whitelisting and AppLocker Bypass**
  Living off the Land (LOLBIN / LOLBAS), Application Whitelisting Theory, AppLocker Setup and Rules (Path / Hash / Publisher), Basic Bypasses (Trusted Folders, DLLs, Alternate Data Streams, Third-Party Execution), PowerShell Constrained Language Mode, Custom Runspaces, PowerShell CLM Bypass (InstallUtil), Reflective Injection Returns, Bypassing AppLocker with C# (Microsoft.Workflow.Compiler), etc.
  
![image](https://hackmd.io/_uploads/B1PYOpFjfg.png)
