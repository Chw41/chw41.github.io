---
title: "[OSWE, WEB-300] Instructional notes"
date: 2026-05-25
author: "CHW"
tags:
  - offsec
description: "OSWE / WEB-300 instructional notes covering source code review, exploit chain analysis, authentication bypass, deserialization, SSTI, XXE, XSS, CSRF, SSRF, prototype pollution, WAF bypass, and real-world web vulnerability research patterns."
---

This series summarizes my OSWE / WEB-300 learning notes, focusing on source code review, exploit chain analysis, authentication bypass, deserialization, server-side vulnerabilities, client-side security issues, and real-world vulnerability research patterns.\

以下筆記整理了在 OSWE / WEB-300 學習過程中的紀錄，重點涵蓋原始碼審查、漏洞利用鏈分析、身份驗證繞過、反序列化、伺服器端漏洞、客戶端安全問題，以及真實世界漏洞研究中的常見模式。

- [Instructional Notes Part 1](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-1/)  
  **Code Review Foundations and SQL Injection**  
  Managed .NET Code, Decompiling Java Classes, AMUserResourcesSyncServlet SQL Injection Attack, PostgreSQL Extensions, etc.

- [Instructional Notes Part 2](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-2/)  
  **Deserialization and Server-Side Template Injection**  
  XmlSerializer, DotNetNuke Cookie Deserialization RCE, SSTI Attack, ERPNext Authentication Bypass, etc.

- [Instructional Notes Part 3](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-3/)  
  **Authentication Bypass, XXE, and XSS**  
  Password Reset Vulnerability, XML Parsing, XXE Exploit, Web Shells, openCRX Authentication Bypass and RCE, openITCOCKPIT XSS, DOM-based XSS, etc.

- [Instructional Notes Part 4](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-4/)  
  **WebSocket Security, SOP, CORS, and CSRF**  
  WebSocket Client, Concord Authentication Bypass and RCE, Same-Origin Policy (SOP), Cross-Origin Resource Sharing (CORS), SameSite, CORS + CSRF, DatabaseModule API Leak, etc.

- [Instructional Notes Part 5](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-5/)  
  **SSRF and Prototype Pollution Exploitation**  
  Server-Side Request Forgery (SSRF), SSRF Port Scanning, SSRF Subnet Scanning, Render API Authentication Bypass, Prototype Pollution, EJS Prototype Pollution RCE Exploitation, Handlebars Prototype Pollution RCE Exploitation, etc.

- [Instructional Notes Part 6](https://chw41.github.io/b1og/oswe-web-300-instructional-notes---part-6/)  
  **Dangerous Functions, Eval Filter Bypass, and WAF Bypass**  
  Dangerous Functions, Security Filter Bypass to Trigger Eval, Dolibarr Eval Filter Bypass RCE, PostgreSQL Injection, WAF Bypass, Coraza WAF, RudderStack SQL Injection and Coraza WAF Bypass, etc.
 
![image](https://hackmd.io/_uploads/B1cl-C7lMe.png)
