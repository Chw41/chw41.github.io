---
title: "[AI] Penetration Testing Notes: Recon, Web, Privilege Escalation, AD, and Pivoting"
slug: "penetration-testing-notes"
date: 2026-02-28
author: "CHW"
tags:
  - offsec
description: "Penetration testing notes by CHW covering reconnaissance, enumeration, web exploitation, privilege escalation, Active Directory, tunneling, and practical labs."
---

# Penetration Testing Notes

This page groups my **penetration testing** notes into one route: **reconnaissance, enumeration, exploitation, privilege escalation, Active Directory, tunneling, and attack-chain development**.

The goal is not to define penetration testing in abstract terms.  
The goal is to connect the notes and labs that I actually use while studying and practicing offensive security.

## Penetration Testing Workflow

My notes follow a simple sequence:

1. Reconnaissance and service discovery.
2. Enumeration and attack surface validation.
3. Exploitation and foothold.
4. Privilege escalation.
5. Pivoting, tunneling, and post-exploitation.
6. Active Directory and multi-host attack chains.

## Core Study Notes

The main body of my penetration testing notes is the OSCP PEN-200 series:

- [OSCP PEN-200 Part 1]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 1.md" >}}) for recon, enumeration, vulnerability scanning, web attacks, and client-side exploits.
- [OSCP PEN-200 Part 2]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 2.md" >}}) for exploit development, antivirus evasion, password attacks, and NTLM abuse.
- [OSCP PEN-200 Part 3]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 3.md" >}}) for Windows privilege escalation and credential attacks.
- [OSCP PEN-200 Part 4]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 4.md" >}}) for Linux privilege escalation, port redirection, and tunneling.
- [OSCP PEN-200 Part 5]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 5.md" >}}) for SSH tunneling, DNS/HTTP tunneling, and Metasploit usage.
- [OSCP PEN-200 Part 6]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 6.md" >}}) for Active Directory enumeration, PowerView, object permissions, and NTLM/Kerberos attacks.
- [OSCP PEN-200 Part 7]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 7.md" >}}) for lateral movement, PtH/PtT/PtK, AD persistence, and AWS reconnaissance.
- [OSCP PEN-200 Part 8]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 8.md" >}}) for cloud infrastructure attacks, Gitea, Jenkins, and simulated penetration testing flow.

If you want a compact operational reference, use the [OSCP PEN-200 Cheat Sheet]({{< relref "/b1og/[OSCP, PEN-200] Cheat Sheet.md" >}}).

## Lab Writeups That Support the Method

Practical penetration testing requires more than note-taking. These lab writeups show how the workflow looks on real targets:

- [HackTheBox: Sau]({{< relref "/b1og/HackTheBox: Sau.md" >}})
- [HackTheBox: Heal]({{< relref "/b1og/HackTheBox: Heal.md" >}})
- [HackTheBox: Titanic]({{< relref "/b1og/HackTheBox: Titanic.md" >}})
- [HackTheBox: UnderPass]({{< relref "/b1og/HackTheBox: UnderPass.md" >}})
- [HackTheBox: Pilgrimage]({{< relref "/b1og/HackTheBox: Pilgrimage.md" >}})
- [HackTheBox: LinkVortex]({{< relref "/b1og/HackTheBox: LinkVortex.md" >}})
- [HackTheBox: Dog]({{< relref "/b1og/HackTheBox: Dog.md" >}})
- [HackTheBox: Code]({{< relref "/b1og/HackTheBox: Code.md" >}})
- [HackTheBox: Codify]({{< relref "/b1og/HackTheBox: Codify.md" >}})

Each writeup captures a slightly different penetration testing pattern: web entry, service abuse, local privilege escalation, or a longer attack chain.

## Active Directory and Multi-Host Work

For AD-focused penetration testing, these are the most relevant pages:

- [OSCP PEN-200 Part 6]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 6.md" >}})
- [OSCP PEN-200 Part 7]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 7.md" >}})
- [HackTheBox: EscapeTwo [Active Directory]]({{< relref "/b1og/HackTheBox: EscapeTwo [Active Directory].md" >}})
- [HackTheBox: Puppy [Active Directory]]({{< relref "/b1og/HackTheBox: Puppy [Active Directory].md" >}})
- [HackTheBox: TheFrizz [Active Directory]]({{< relref "/b1og/HackTheBox: TheFrizz [Active Directory].md" >}})

This is where the site starts moving away from basic single-host exploitation and into more realistic operator workflow.

## Web Security Inside Penetration Testing

A large part of penetration testing is still web application work.  
For that branch, continue with [Web Security Notes: Web Recon, XSS, SSTI, SSRF, IDOR, and Exploitation Cases]({{< relref "/b1og/Web Security Notes: Web Recon, XSS, SSTI, SSRF, IDOR, and Exploitation Cases.md" >}}).

## Binary and Supporting Notes

Some supporting articles are not pure pentest methodology pages, but they are still useful during study and exploitation work:

- [GDB & Binary Exploitation]({{< relref "/b1og/GDB & Binary Exploitation.md" >}})
- [Git 介紹 & 常用操作]({{< relref "/b1og/Git 介紹 & 常用操作.md" >}})
- [LNMP (Linux + Nginx + MySQL + PHP) 架設伺服器]({{< relref "/b1og/LNMP (Linux + Nginx + MySQL + PHP) 架設伺服器.md" >}})

## Recommended Reading Path

If you want the shortest useful path through these penetration testing notes:

1. [OSCP PEN-200 Part 1]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 1.md" >}})
2. [OSCP PEN-200 Part 3]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 3.md" >}})
3. [OSCP PEN-200 Part 4]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 4.md" >}})
4. [OSCP PEN-200 Part 6]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 6.md" >}})
5. [OSCP PEN-200 Cheat Sheet]({{< relref "/b1og/[OSCP, PEN-200] Cheat Sheet.md" >}})

## Author Context

These penetration testing notes are maintained by CHW, with offensive security study spanning OSWA, OSCP+, lab work, CTFs, and security engineering experience.  
For profile details, see [About]({{< relref "/4b0u7/_index.md" >}}).

If you want the operator-focused subset of this material, continue with [Red Team Notes: OPSEC, Lateral Movement, AD Persistence, and Operator Workflow]({{< relref "/b1og/Red Team Notes: OPSEC, Lateral Movement, AD Persistence, and Operator Workflow.md" >}}).
