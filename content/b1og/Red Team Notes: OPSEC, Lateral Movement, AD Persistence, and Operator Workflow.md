---
title: "[AI] Red Team Notes: OPSEC, Lateral Movement, AD Persistence, and Operator Workflow"
slug: "red-team-notes"
date: 2026-02-30
author: "CHW"
tags:
  - offsec
description: "Red team notes by CHW covering OPSEC, lateral movement, Active Directory persistence, credential attacks, pivoting, and operator-focused offensive workflows."
---

# Red Team Notes

This page collects the parts of my site that are most relevant to **red team** work: **OPSEC, lateral movement, credential attacks, Active Directory abuse, persistence, tunneling, and operator workflow**.

I am not using this page as a vague introduction to red teaming.  
I am using it to connect the posts that best reflect how offensive operations scale from a single foothold into a broader attack path.

## Core Red Team Topics on This Site

The strongest red-team-oriented coverage on this site falls into five areas:

1. OPSEC and detection-aware workflow.
2. Active Directory enumeration and access control abuse.
3. Credential attacks and ticket abuse.
4. Lateral movement and persistence.
5. Infrastructure, pivoting, and simulated operation flow.

## OPSEC and Detection-Aware Thinking

For direct OPSEC-focused material, start with:

- [CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow)]({{< relref "/b1og/CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow).md" >}})

That note is useful because it keeps the focus on operational behavior, not just tools.

## Active Directory, Credential Abuse, and Lateral Movement

The OSCP series contains the densest material for AD and operator tradecraft:

- [OSCP PEN-200 Part 6]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 6.md" >}}) for AD enumeration, PowerView, object permissions, and NTLM/Kerberos attacks.
- [OSCP PEN-200 Part 7]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 7.md" >}}) for lateral movement, PtH, PtT, PtK, AD persistence, and AWS reconnaissance.
- [OSCP PEN-200 Part 8]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 8.md" >}}) for cloud and simulated penetration testing flow.

For a concise operator reference, use the [OSCP PEN-200 Cheat Sheet]({{< relref "/b1og/[OSCP, PEN-200] Cheat Sheet.md" >}}).

## AD-Oriented Lab Writeups

These writeups are the best fit if you want concrete red-team-like attack chains:

- [HackTheBox: EscapeTwo [Active Directory]]({{< relref "/b1og/HackTheBox: EscapeTwo [Active Directory].md" >}})
- [HackTheBox: Puppy [Active Directory]]({{< relref "/b1og/HackTheBox: Puppy [Active Directory].md" >}})
- [HackTheBox: TheFrizz [Active Directory]]({{< relref "/b1og/HackTheBox: TheFrizz [Active Directory].md" >}})

They are useful because they move beyond isolated exploitation and into domain context, privilege relationships, and chaining opportunities.

## Pivoting, Tunneling, and Infrastructure Movement

Operator workflow depends on reliable movement across segmented environments.  
These pages are the most relevant:

- [OSCP PEN-200 Part 4]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 4.md" >}}) for port redirection and tunneling.
- [OSCP PEN-200 Part 5]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 5.md" >}}) for SSH tunneling, DNS/HTTP tunneling, and Metasploit.
- [OSCP PEN-200 Part 8]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 8.md" >}}) for simulated engagement flow.

## Red Teaming and Web Entry

Many operations still begin with web attack surface.  
For the application-security side that can feed an operator workflow, continue with [Web Security Notes: Web Recon, XSS, SSTI, SSRF, IDOR, and Exploitation Cases]({{< relref "/b1og/Web Security Notes: Web Recon, XSS, SSTI, SSRF, IDOR, and Exploitation Cases.md" >}}).

## Recommended Reading Path

If your goal is to use this site specifically for red-team-oriented study, read in this order:

1. [CYBERSEC 2025 OPSEC note]({{< relref "/b1og/CYBERSEC 2025 臺灣資安大會 「Operations Security (OPSEC) — 紅隊不被抓到的秘密！」 (Steven Meow).md" >}})
2. [OSCP PEN-200 Part 6]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 6.md" >}})
3. [OSCP PEN-200 Part 7]({{< relref "/b1og/[OSCP, PEN-200] Instructional notes - Part 7.md" >}})
4. [HackTheBox: EscapeTwo [Active Directory]]({{< relref "/b1og/HackTheBox: EscapeTwo [Active Directory].md" >}})
5. [HackTheBox: Puppy [Active Directory]]({{< relref "/b1og/HackTheBox: Puppy [Active Directory].md" >}})

## Why This Red Team Hub Exists

This site already had the raw material for red-team-oriented content, but it was spread across lab notes, exam notes, conference notes, and individual machine writeups.  
This page exists to connect them as one operator-focused path.

For the broader offensive-security route, continue with [Penetration Testing Notes: Recon, Web, Privilege Escalation, AD, and Pivoting]({{< relref "/b1og/Penetration Testing Notes: Recon, Web, Privilege Escalation, AD, and Pivoting.md" >}}).
