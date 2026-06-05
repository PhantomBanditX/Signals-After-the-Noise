<p align="center">
<img width="1023" height="336" alt="Image" src="https://github.com/user-attachments/assets/f7355830-fc08-4621-a530-3b18f48d25f2" />
</p>

# 🛡️ Signals After the Noise

## 📌 Executive Summary

A threat actor exploited an unintentional OPSEC failure — a LinkedIn post 
by PHTG Cloud Engineer Sarah Chen — to identify and compromise an 
internet-exposed Azure virtual machine (`azwks-phtg-02`) running Windows 10 
Enterprise with RDP publicly accessible on port 3389. Within 24 hours of 
the post going live, the attacker brute forced the local administrator 
account `vmadminusername` from Uruguayan infrastructure, established 23 
confirmed RDP sessions, delivered and executed a Meterpreter payload 
(`Trojan:Win32/Meterpreter.RPZ!MTB`), and planted a persistence mechanism 
inside PHTG's newly deployed HealthCloud service directory. Although all 
C2 callback attempts to `173.244.55.130:4444` failed, the threat actor 
retained persistent RDP access and could re-establish a live Meterpreter 
session at any time. The incident was discovered through proactive threat 
hunting — no security alerts fired during the entire compromise window.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Sentinel (`law-cyber-range` workspace) — 
  PHTG (Pacific Health Technology Group), cloud infrastructure team
- **Data Sources:**
  - `DeviceNetworkEvents`
  - `DeviceLogonEvents`
  - `DeviceProcessEvents`
  - `DeviceFileEvents`
  - `DeviceEvents`
  - `SigninLogs`
- **Timeframe:** 2025-12-13 09:00 UTC → 2025-12-13 18:00 UTC
- **Target Host:** `azwks-phtg-02` (Windows 10 Enterprise, East US 2)
- **Public IP:** `74.249.82.162`
- **Threat Actor Infrastructure:** `173.244.55.0/24` (Uruguay, South America)

> **Note:** The data sources listed in the original template 
> (`CloudAppEvents`, `EmailEvents`) are not applicable 
> to this hunt. This investigation used Microsoft Defender for Endpoint 
> (MDE) tables ingested into Microsoft Sentinel. The original template 
> fields have been corrected to reflect the actual data sources used.

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
  - [🚩 Flag 23](#-flag-23)
  - [🚩 Flag 24](#-flag-24)
  - [🚩 Flag 25](#-flag-25)
  - [🚩 Flag 26](#-flag-26)
  - [🚩 Flag 27](#-flag-27)
  - [🚩 Flag 28](#-flag-28)
  - [🚩 Flag 29](#-flag-29)
  - [🚩 Flag 30](#-flag-30)
  - [🚩 Flag 31](#-flag-31)
  - [🚩 Flag 32](#-flag-32)
  - [🚩 Flag 33](#-flag-33)
  - [🚩 Flag 34](#-flag-34)
  - [🚩 Flag 35](#-flag-35)
  - [🚩 Flag 36](#-flag-36)
  - [🚩 Flag 37](#-flag-37)
  - [🚩 Flag 38](#-flag-38)

- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This investigation began with no alerts, no known incident, and no 
confirmed compromise — only an OSINT trigger: a LinkedIn post by a 
PHTG Cloud Engineer photographing her workstation during the company's 
HealthCloud service rollout. The photo inadvertently exposed the Azure 
portal with live VM details visible on screen, including the public IP 
address of `azwks-phtg-02` and enough infrastructure context to anchor 
a targeted attack.

The attacker moved with speed and deliberateness. Within 24 hours of 
the post, mass automated RDP scanning against `74.249.82.162` began — 
225 unique source IPs from 17 countries generating 325 network events 
against port 3389. The credential stuffing campaign that followed 
produced 646 failed authentication attempts before succeeding — the 
weak, predictable account name `vmadminusername` appeared in the 
attacker's credential list, and the absence of an account lockout 
policy allowed the campaign to run uninterrupted.

The first confirmed unauthorised RDP session was established at 
05:47:45 UTC on 12 December 2025 from `173.244.55.131` (Uruguay). 
Over the following 48 hours, the threat actor conducted 23 successful 
RDP sessions, reviewed internal engineer notes (`notes_sarah.txt`), 
delivered a Meterpreter payload disguised with a double extension 
(`Sarah_Chen_Notes.exe.Txt`), disabled Microsoft Defender's blocking 
capability by switching it to passive mode, and executed the payload 
three times in rapid succession. When initial C2 callbacks to 
`173.244.55.130:4444` failed, the attacker adapted — relocating the 
payload to `C:\ProgramData\PHTG\HealthCloud\PHTG.exe`, renaming it 
to blend with the legitimate HealthCloud service, and creating 
`Launch.bat` as an automated persistence launcher.

The full attack chain — from social media OSINT through RDP brute 
force, credential access, payload delivery, defence evasion, and 
persistence — was executed by a single threat actor operating 
exclusively from the `173.244.55.0/24` subnet in Uruguay, South 
America. No alerts fired. No defensive controls intervened. The 
compromise was discovered only through proactive, hypothesis-driven 
threat hunting anchored to the original LinkedIn post.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | | T1593 | Search Open Websites/Domains | Reconnaissance | 🟡 Medium |
| T1593.001 | Search Open Websites/Domains: Social Media | Reconnaissance | 🟠 High |
| T1594 | Search Victim-Owned Websites | Reconnaissance | 🟡 Medium |
| T1589 | Gather Victim Identity Information | Reconnaissance | 🟠 High |
| T1591 | Gather Victim Org Information | Reconnaissance | 🟡 Medium | 
| 2 | | T1580 | Cloud Infrastructure Discovery | Discovery | 🟠 High |
| T1593 | Search Open Websites/Domains | Reconnaissance | 🟠 High |
| T1590 | Gather Victim Network Information | Reconnaissance | 🟡 Medium |
| T1591 | Gather Victim Org Information | Reconnaissance | 🟡 Medium |
| 3 | | T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🔴 Critical |
| T1593 | Search Open Websites/Domains | Reconnaissance | 🟠 High |
| T1590 | Gather Victim Network Information | Reconnaissance | 🟠 High |
| T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🟡 Medium |
| 4 | | T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🔴 Critical |
| T1590 | Gather Victim Network Information | Reconnaissance | 🟠 High |
| T1595 | Active Scanning | Reconnaissance | 🟠 High |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 5 | | T1593.001 | Search Open Websites/Domains: Social Media | Reconnaissance | 🔴 Critical |
| T1589.002 | Gather Victim Identity Information: Email Addresses | Reconnaissance | 🟠 High |
| T1591.004 | Gather Victim Org Information: Identify Roles | Reconnaissance | 🟠 High |
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🔴 Critical |
| 6 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical 
| T1595 | Active Scanning | Reconnaissance | 🔴 Critical 
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🟠 High 
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 7 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical |
| T1110 | Brute Force | Credential Access | 🔴 Critical 
| T1133 | External Remote Services | Initial Access | 🔴 Critical 
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical 
| 8 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical |
| T1595 | Active Scanning | Reconnaissance | 🔴 Critical | 
| T1110 | Brute Force | Credential Access | 🔴 Critical | 
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 9 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical |
| T1595 | Active Scanning | Reconnaissance | 🔴 Critical |
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🟠 High |
| T1110 | Brute Force | Credential Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 10 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical | 
| T1595 | Active Scanning | Reconnaissance | 🔴 Critical |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical | 
| T1110 | Brute Force | Credential Access | 🔴 Critical | 
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 11 | | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | 🔴 Critical |
| T1595 | Active Scanning | Reconnaissance | 🔴 Critical |
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | 🟠 High |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1090 | Proxy | Defense Evasion | 🟠 High |
| 12 | | T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical | 
| T1110.003 | Brute Force: Password Spraying | Credential Access | 🔴 Critical | 
| T1110 | Brute Force | Credential Access | 🔴 Critical | 
| T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical | 
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| 13 | | T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical | 
| T1110.003 | Brute Force: Password Spraying | Credential Access | 🔴 Critical |
| T1110 | Brute Force | Credential Access | 🔴 Critical | 
| T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical | 
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| 14 | | T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical |
| T1110.003 | Brute Force: Password Spraying | Credential Access | 🔴 Critical |
| T1110 | Brute Force | Credential Access | 🔴 Critical |
| T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 15 | | T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical |
| T1110.003 | Brute Force: Password Spraying | Credential Access | 🔴 Critical |
| T1110 | Brute Force | Credential Access | 🔴 Critical |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| 16 | | T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical |
| T1110 | Brute Force | Credential Access | 🔴 Critical | 
| T1090 | Proxy | Defense Evasion | 🟠 High |
| T1090.003 | Proxy: Multi-hop Proxy | Defense Evasion | 🟠 High |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1078 | Valid Accounts | Initial Access | 🔴 Critical |
| 17 | | T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1090.003 | Proxy: Multi-hop Proxy | Defense Evasion | 🟠 High |
| 18 | | T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1090.003 | Proxy: Multi-hop Proxy | Defense Evasion | 🟠 High |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development |
| 19 | | T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1090 | Proxy | Defense Evasion | 🟠 High |
| 20 | | T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1098 | Account Manipulation | Persistence | 🟠 High |
| 21 | | T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1078 | Valid Accounts | Defense Evasion / Persistence | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1090 | Proxy | Defense Evasion | 🟠 High |
| 22 | | T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1078 | Valid Accounts | Defense Evasion / Initial Access | 🔴 Critical |
| T1133 | External Remote Services | Initial Access | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 
| 23 | | T1078.003 | Valid Accounts: Local Accounts | Initial Access | 🔴 Critical |
| T1078 | Valid Accounts | Defense Evasion / Persistence | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1090 | Proxy | Defense Evasion | 🟠 High |
| T1008 | Fallback Channels | Command and Control | 🟠 High |
| 24 | | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | 🔴 Critical |
| T1059 | Command and Scripting Interpreter | Execution | 🔴 Critical |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | 🔴 Critical |
| T1078.003 | Valid Accounts: Local Accounts | Defense Evasion | 🔴 Critical | 
| 25 | | T1005 | Data from Local System | Collection | 🔴 Critical |
| T1083 | File and Directory Discovery | Discovery | 🟠 High |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | 🔴 Critical |
| T1213 | Data from Information Repositories | Collection | 🟠 High |
| T1074.001 | Data Staged: Local Data Staging | Collection | 🟠 High |
| 26 | | T1036.007 | Masquerading: Double File Extension | Defense Evasion | 🔴 Critical |
| T1036 | Masquerading | Defense Evasion | 🔴 Critical |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟠 High |
| T1204.002 | User Execution: Malicious File | Execution | 🔴 Critical |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical |
| 27 | | T1036.007 | Masquerading: Double File Extension | Defense Evasion | 🔴 Critical |
| T1036 | Masquerading | Defense Evasion | 🔴 Critical |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟠 High |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical |
| T1204.002 | User Execution: Malicious File | Execution | 🔴 Critical |
| 28 | | T1036.007 | Masquerading: Double File Extension | Defense Evasion | 🔴 Critical |
| T1036 | Masquerading | Defense Evasion | 🔴 Critical |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟠 High |
| T1588.001 | Obtain Capabilities: Malware | Resource Development | 🟠 High |
| 29 | | T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | 🔴 Critical |
| T1036 | Masquerading | Defense Evasion | 🔴 Critical |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | 🔴 Critical |
| T1574 | Hijack Execution Flow | Persistence / Defense Evasion | 🟠 High |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟠 High |
| 30 | | T1059.001 | Command and Scripting: PowerShell | Execution | 🔴 Critical |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 | 🔴 Critical |
| T1095 | Non-Application Layer Protocol | C2 | 🔴 Critical |
| T1055 | Process Injection | Defense Evasion / Privilege Escalation | 🔴 Critical |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | 🔴 Critical |
| T1588.001 | Obtain Capabilities: Malware | Resource Development | 🟠 High | 
| 31 | | T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | 🔴 Critical | 
| T1562 | Impair Defenses | Defense Evasion | 🔴 Critical | 
| T1078.003 | Valid Accounts: Local Accounts | Defense Evasion | 🔴 Critical | 
| T1059.001 | Command and Scripting: PowerShell | Execution | 🟠 High |
| T1112 | Modify Registry | Defense Evasion | 🟠 High |
| 32 | | T1204.002 | User Execution: Malicious File | Execution | 🔴 Critical |
| T1204 | User Execution | Execution | 🔴 Critical |
| T1059.003 | Command and Scripting: Windows Command Shell | Execution | 🔴 Critical |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | 🔴 Critical |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical |
| 33 | | T1059.003 | Command and Scripting: Windows Command Shell | Execution | 🔴 Critical |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys / Startup Folder | Persistence | 🔴 Critical |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 🔴 Critical |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | 🔴 Critical |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical | 
| 34 | | T1059.003 | Command and Scripting: Windows Command Shell | Execution | 🔴 Critical |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 🔴 Critical |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | 🔴 Critical |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | 🟠 High |
| T1105 | Ingress Tool Transfer | Command and Control | 🔴 Critical |
| 35 | | T1095 | Non-Application Layer Protocol | Command and Control | 🔴 Critical |
| T1071 | Application Layer Protocol | Command and Control | 🔴 Critical |
| T1043 | Commonly Used Port | Command and Control | 🟠 High |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1008 | Fallback Channels | Command and Control | 🟠 High |
| 36 | | T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1583 | Acquire Infrastructure | Resource Development | 🟠 High |
| T1095 | Non-Application Layer Protocol | Command and Control | 🔴 Critical |
| T1090.003 | Proxy: Multi-hop Proxy | Defense Evasion | 🟠 High |
| T1008 | Fallback Channels | Command and Control | 🟠 High |
| 37 | | T1095 | Non-Application Layer Protocol | Command and Control | 🔴 Critical |
| T1571 | Non-Standard Port | Command and Control | 🔴 Critical |
| T1071 | Application Layer Protocol | Command and Control | 🟠 High | 
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | 🟠 High |
| T1008 | Fallback Channels | Command and Control | 🟠 High |
| 38 | | T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | 🔴 Critical |
| T1036 | Masquerading | Defense Evasion | 🔴 Critical |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | 🔴 Critical |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 🔴 Critical |
| T1574 | Hijack Execution Flow | Persistence / Defense Evasion | 🟠 High |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟠 High |
---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
The lead-up logged failed logons from several regions before the successful one. Easy to call it brute force and move on. Test that assumption. If the successful access was not brute force, what was the actual vector?

```kql
SigninLogs
| where TimeGenerated between (todatetime('2025-12-13 09:00') .. todatetime('2025-12-13 18:00'))
| where ResultSignature == "FAILURE"
| project TimeGenerated, ResultType, ResultSignature, ResultDescription, Location, LocationDetails, AuthenticationRequirement
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/31f86f8b-cae2-49e5-a7d9-96eb42252683" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

### 🎯 Objective
Identify the specific Azure virtual machine exposed in the LinkedIn post to 
anchor all subsequent telemetry queries to a concrete, named asset. Without 
a confirmed hostname, no endpoint telemetry can be scoped accurately.

### 📌 Finding
The exposed virtual machine is **azwks-phtg-02**. The name was visible in the 
Azure portal screenshot (Exhibit B) shared in the LinkedIn post, appearing both 
as the page title and confirmed in the VM properties panel. The naming 
convention reveals the asset type (workstation), the organisation (PHTG), and 
the sequential instance number (02).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| VM Name (Page Title) | azwks-phtg-02 |
| VM Name (Properties Panel) | azwks-phtg-02 |
| Operating System | Windows 10 Enterprise |
| Location | East US 2 (Zone 1) |
| Time Created | 12/10/2025, 3:08 AM UTC |
| Subscription | LOGIN\| Pacific - Cyber Range 1 |
| Timestamp | N/A — Static open-source evidence |
| Process | N/A — No process execution involved |
| Parent Process | N/A — No process execution involved |
| Command Line | N/A — No process execution involved |

### 💡 Why it matters
The VM name `azwks-phtg-02` exposes several pieces of intelligence to an 
external observer:

- **`az`** — Confirms the asset is hosted on Microsoft Azure
- **`wks`** — Identifies the asset as a workstation-class machine
- **`phtg`** — Confirms the organisation abbreviation
- **`02`** — Implies at least one other VM exists (`azwks-phtg-01`), 
  inviting further enumeration

A threat actor observing this naming pattern can immediately infer the 
existence of additional assets and begin targeted reconnaissance against 
the organisation's Azure footprint. The VM name also becomes the primary 
anchor for all MDE telemetry queries — every KQL query in this 
investigation will filter on `DeviceName == "azwks-phtg-02"`.

### 🔧 KQL Query Used
N/A — The VM name was extracted directly from Exhibit B (Azure portal 
screenshot). No KQL query was required at this stage. However, the VM name 
is used as the primary filter in all subsequent telemetry queries:

```kql
// Base filter used throughout all subsequent KQL queries
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
```

### 🖼️ Screenshot
<img width="886" height="658" alt="image" src="https://github.com/user-attachments/assets/adbd97a3-1bad-4c9d-8fbc-c68b84a6da28" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Adopt opaque VM naming conventions** that do not encode asset type, 
  organisation name, or sequential identifiers. Use randomised or 
  codename-based schemes instead (e.g. `vm-falcon-03` rather than 
  `azwks-phtg-02`)
- **Azure Defender for Cloud** can flag publicly exposed VMs with RDP 
  open to the internet — ensure these alerts are actively monitored
- **Enumerate your own attack surface** periodically using tools like 
  Shodan or Azure's own network exposure reports to identify what is 
  visible before an attacker does
- Implement **Just-In-Time (JIT) VM access** in Azure Security Center 
  to restrict RDP exposure to approved source IPs and time windows only

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

### 🎯 Objective
Identify the public IP address associated with the exposed Azure VM to 
determine whether it is directly reachable from the open internet, and to 
establish a target IP for cross-referencing against inbound network telemetry 
in subsequent investigation phases.

### 📌 Finding
The public IP address associated with `azwks-phtg-02` is **74.249.82.162**. 
This was visible in two locations within the Azure portal screenshot (Exhibit B):
- **Primary NIC public IP** field in the Essentials panel
- **Networking → Public IP address** field in the Properties panel

The IP was confirmed as active with the VM status showing **Running**, meaning 
the address was live and reachable at the time the screenshot was taken.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Public IP Address | 74.249.82.162 |
| Private IP Address | 10.0.0.152 |
| NIC Name | azwks-phtg-02694_z1 |
| Virtual Network | Cyber-Range-VNet/Cyber-Range-Subnet |
| VM Status | Running |
| Timestamp | N/A — Static open-source evidence |
| Process | N/A — No process execution involved |
| Parent Process | N/A — No process execution involved |
| Command Line | N/A — No process execution involved |

### 💡 Why it matters
A public IP address associated with a Windows 10 Enterprise VM is a 
significant exposure. Combined with the information already extracted 
from the LinkedIn post, a threat actor now has everything needed to 
begin active targeting:

- **The hostname** — `azwks-phtg-02`
- **The OS** — Windows 10 Enterprise (implies RDP is likely enabled)
- **The public IP** — `74.249.82.162` (a directly routable internet address)

This compresses the attacker's pre-exploitation phase to near zero. 
No scanning, no enumeration, no guesswork — the target handed them 
the address. The public IP becomes the primary pivot point for 
correlating inbound scanning, brute force, and authentication events 
in MDE telemetry throughout this investigation.

### 🔧 KQL Query Used
N/A — The public IP address was extracted directly from Exhibit B 
(Azure portal screenshot). No KQL query was required at this stage.

However, this IP is referenced in subsequent telemetry queries to 
correlate inbound connection activity:

```kql
// Used in subsequent phases to correlate inbound activity to the VM
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| where RemoteIPType == "Public"
| summarize count() by RemoteIP, ActionType
| order by count_ desc
```

### 🖼️ Screenshot
<img width="886" height="658" alt="image" src="https://github.com/user-attachments/assets/79b1b009-2f18-441e-a7e7-cad021017fb6" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Never expose RDP (port 3389) directly to the internet.** Use Azure 
  Just-In-Time (JIT) VM Access to restrict inbound RDP to approved source 
  IPs and defined time windows only
- **Remove public IP associations** from VMs that do not require direct 
  internet connectivity. Use Azure Bastion as a secure, browser-based 
  RDP/SSH gateway that eliminates the need for public IPs on VMs entirely
- **Azure Network Security Groups (NSGs)** should explicitly deny inbound 
  RDP from `0.0.0.0/0`. Any rule permitting this should trigger an 
  immediate alert
- Enable **Microsoft Defender for Cloud** recommendations — it will 
  actively flag internet-exposed RDP as a high-severity finding
- Conduct periodic **attack surface reviews** using tools like Shodan 
  or Azure's built-in network exposure assessments to identify 
  publicly reachable services before threat actors do

</details>


---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
Determine which specific detail visible in the Azure portal screenshot 
provides a threat actor with the most actionable information — the piece 
of intelligence that moves an attacker from passive observation to active 
exploitation.

### 📌 Finding
**Answer: D — A public IP address is visible and associated with the 
virtual machine.**

While all five options represent information leakage to varying degrees, 
only the public IP address gives a threat actor a direct, immediately 
actionable target. The other options provide contextual intelligence but 
cannot alone enable an attack. A public IP is the difference between 
knowing a target exists and being able to reach it.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Public IP Address | 74.249.82.162 |
| Correct Answer | D |
| Source | Exhibit B — Azure Portal Screenshot (Networking Panel) |
| Timestamp | N/A — Static open-source evidence |
| Process | N/A — No process execution involved |
| Parent Process | N/A — No process execution involved |
| Command Line | N/A — No process execution involved |

### 💡 Why it matters
The public IP address is the single most actionable piece of intelligence 
visible in the Azure portal screenshot because it:

- **Provides a directly routable target** — no additional reconnaissance required
- **Enables immediate active exploitation** — the attacker can begin 
  scanning, fingerprinting, and brute forcing without any further 
  information gathering
- **Confirms internet reachability** — a public IP on a running VM 
  means the service is live and accessible from anywhere on the internet
- **Combines lethally with Option A** — knowing the OS is Windows 10 
  Enterprise and having a public IP immediately suggests RDP (port 3389) 
  as the primary attack vector

In isolation, each of the other options adds context. But without a 
public IP, none of them can be acted upon. The IP is the bridge between 
passive intelligence and active attack.

### 🔧 KQL Query Used
N/A — This question was answered through analysis of open-source evidence 
(Exhibit B). No KQL query was required.

The public IP identified here (`74.249.82.162`) is subsequently used as 
a reference point when correlating inbound connection activity in MDE 
telemetry:

```kql
// Subsequent query to confirm inbound activity against the exposed IP
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, ActionType
| order by ConnectionCount desc
```

### 🖼️ Screenshot
<img width="886" height="658" alt="image" src="https://github.com/user-attachments/assets/fc2db8cd-44a3-43e3-8855-60a3e0f7d78b" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Azure Defender for Cloud** will flag any VM with RDP exposed to 
  the internet as a high-severity recommendation — ensure these alerts 
  are actioned immediately and not suppressed
- Implement **Azure Policy** to deny the creation of public IP 
  associations on VMs without explicit approval through a change 
  management process
- Use **Azure Bastion** to provide secure RDP/SSH access without 
  exposing public IPs on individual VMs
- Conduct **quarterly attack surface reviews** — enumerate all 
  resources with public IPs in your Azure tenant and validate each 
  one has a documented business justification
- Train employees to **never photograph or screenshot cloud management 
  consoles** for social media posts — even with good intentions, 
  the exposure risk is significant

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
Identify what activity was being performed on the workstation visible in 
the LinkedIn post to understand the operational context of the exposure 
and establish who was responsible for the leaked infrastructure details.

### 📌 Finding
**Answer: C — Managing cloud infrastructure resources.**

The workstation visible in Exhibit A (LinkedIn post by Sarah Chen) shows 
two monitors displaying what is consistent with active cloud infrastructure 
management. The left monitor shows an Azure portal session and the right 
monitor displays what appears to be a terminal or code editor consistent 
with infrastructure configuration or deployment work — directly aligned 
with the hunt brief's context of the HealthCloud rollout on 11 December 2025.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | N/A — OSINT phase, no endpoint telemetry involved |
| Person | Sarah Chen |
| Job Title | Cloud Engineer at PHTG |
| Monitor 1 | Azure portal session (cloud console) |
| Monitor 2 | Terminal or code editor (infrastructure configuration) |
| Context | First day on HealthCloud rollout — 11 December 2025 |
| Correct Answer | C |
| Source | Exhibit A — LinkedIn Post |
| Timestamp | N/A — Static open-source evidence |
| Process | N/A — No process execution involved |
| Parent Process | N/A — No process execution involved |
| Command Line | N/A — No process execution involved |


### 💡 Why it matters
The identification of the activity being performed is critical for two reasons:

1. **It confirms the source of the leak.** Sarah Chen was actively managing 
   cloud infrastructure — specifically the HealthCloud rollout — when the 
   photo was taken. This means the Azure portal screenshot visible on her 
   monitor was a live, active session showing real infrastructure details 
   including the public IP of `azwks-phtg-02`.

2. **It establishes the human element of the exposure.** This was not a 
   technical misconfiguration or a data breach — it was an unintentional 
   OPSEC failure by a cloud engineer celebrating a milestone on social media. 
   The activity being performed (cloud infrastructure management) made the 
   exposure particularly damaging because the screens displayed live, 
   actionable infrastructure details rather than benign content.

The photo compressed the attacker's reconnaissance phase from days of 
active scanning to seconds of passive observation.


### 🔧 KQL Query Used
N/A — This finding was derived entirely from open-source evidence analysis 
of Exhibit A (LinkedIn post). No KQL query was required.

The identity of Sarah Chen and her role as a Cloud Engineer at PHTG is 
carried forward as context for later phases of the investigation, 
particularly when a file named `Sarah_Chen_Notes.exe` is discovered 
on the compromised host — suggesting the threat actor used her identity 
as a social engineering lure.

### 🖼️ Screenshot
<img width="872" height="1628" alt="image" src="https://github.com/user-attachments/assets/4ff6dd35-dbed-41f6-ad9c-22d3c8cfb74c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Implement a social media policy** that explicitly prohibits employees 
  from photographing or sharing screenshots of workstations, cloud consoles, 
  or any infrastructure management tooling on personal or professional 
  social media accounts
- **Security awareness training** should include specific examples of 
  unintentional OPSEC failures via social media — particularly for 
  cloud engineering, DevOps, and IT operations teams who regularly 
  work with sensitive infrastructure details
- **Monitor for company mentions on social media** using OSINT tooling 
  (e.g. Google Alerts, social media monitoring platforms) to identify 
  unintentional disclosures before threat actors act on them
- **Conduct periodic OSINT reviews** of employee LinkedIn profiles, 
  particularly those in privileged technical roles, to assess what 
  infrastructure intelligence is inadvertently being made public
- Consider implementing **screen privacy filters** on workstations 
  in open office environments where photographs could inadvertently 
  capture sensitive screen content

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
Identify the most appropriate telemetry source to determine whether the 
exposed public IP address (`74.249.82.162`) associated with `azwks-phtg-02` 
was actively scanned or enumerated following the LinkedIn post, and establish 
the correct data source to pivot into for network-level investigation.

### 📌 Finding
**Answer: D — Azure network or platform analytics related to inbound 
connections.**

To determine whether a public IP was scanned or enumerated, the first 
telemetry source to review is network-level data capturing inbound 
connection attempts. In this investigation environment, that telemetry 
is available via **Microsoft Defender for Endpoint (MDE) 
`DeviceNetworkEvents`** — which captures inbound and outbound connection 
activity at the endpoint level, including connection attempts, accepted 
connections, and the remote IPs involved.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Telemetry Source | DeviceNetworkEvents (MDE) |
| Platform | Microsoft Sentinel |
| Workspace | law-cyber-range |
| Correct Answer | D |
| Timestamp | N/A — Query design phase |
| Process | N/A — No process execution involved |
| Parent Process | N/A — No process execution involved |
| Command Line | N/A — No process execution involved |

### 💡 Why it matters
Choosing the correct telemetry source at the start of an investigation 
determines how quickly and accurately a threat hunter can confirm or 
deny a hypothesis. In this case the hypothesis is:

> *"Did anyone scan or enumerate the exposed public IP after the 
> LinkedIn post went live?"*

Network telemetry is the only source that can answer this directly because:
- **Scanning precedes authentication** — it happens before any credentials 
  are used, so auth logs would miss it entirely
- **It captures raw connection attempts** — including those that never 
  result in a successful session
- **It records source IPs** — enabling geographic enrichment and 
  threat intelligence correlation
- **It is host-level** — MDE `DeviceNetworkEvents` captures this data 
  directly on the endpoint, making it available even if Azure-level 
  NSG flow logs are not configured

In this investigation, `DeviceNetworkEvents` revealed 325 events 
targeting port 3389 from 225 unique source IPs across 17 countries — 
confirming that the exposed VM was actively targeted following the 
LinkedIn post.

### 🔧 KQL Query Used
```kql
// Initial query to assess inbound network activity against the exposed VM
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize count() by ActionType, RemoteIPType
| order by count_ desc
```
### 🖼️ Screenshot
![DeviceNetworkEvents RDP Scan](screenshots/q06_devicenetworkevents_rdp_scan.png)

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Enable MDE `DeviceNetworkEvents` logging** across all endpoints 
  — particularly those with public IP associations. This is the 
  primary telemetry source for detecting inbound scanning and 
  enumeration activity
- **Configure Azure NSG Flow Logs** and send them to a Log Analytics 
  workspace to provide an additional network-level view of inbound 
  traffic, complementing MDE endpoint telemetry
- **Build a baseline of expected inbound connections** for each 
  internet-facing VM. Any deviation — particularly high-volume 
  inbound attempts on port 3389 from public IPs — should trigger 
  an immediate alert
- **Create a Sentinel Scheduled Query Rule** to alert on more than 
  a defined threshold of unique public source IPs connecting to 
  port 3389 within a one-hour window:

```kql
// Detection rule — mass RDP scanning alert
DeviceNetworkEvents
| where LocalPort == 3389
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize UniqueSourceIPs = dcount(RemoteIP) by DeviceName
| where UniqueSourceIPs > 10
```

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
Identify which local port on `azwks-phtg-02` was the primary target of 
broad, automated scanning activity following the exposure of the VM's 
public IP address in the LinkedIn post. This establishes the attack 
vector used by threat actors to probe the internet-facing service.

### 📌 Finding
**Answer: 3389**

Port 3389 is the default port for **Remote Desktop Protocol (RDP)** — 
the primary remote access service on Windows endpoints. This port is 
one of the most heavily scanned ports on the internet, targeted by 
automated botnets, credential stuffing tools, and opportunistic threat 
actors globally. Given that the exposed VM runs **Windows 10 Enterprise** 
and has a public IP, port 3389 was the immediate and obvious target.

The hunt title — **"External RDP Compromise"** — confirms RDP as the 
attack vector before any telemetry is reviewed.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Port | 3389 |
| Protocol | RDP (Remote Desktop Protocol) |
| Total Events on Port 3389 | 325 |
| ActionTypes Observed | ConnectionAttempt (124), InboundConnectionAccepted (201) |
| Unique Source IPs | 225 |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Network telemetry, no process execution involved |
| Parent Process | N/A — Network telemetry, no process execution involved |
| Command Line | N/A — Network telemetry, no process execution involved |


### 💡 Why it matters
Port 3389 (RDP) is consistently among the most targeted ports on the 
internet for several reasons:

- **Default Windows remote access** — RDP is enabled by default on 
  many Windows Server and Enterprise deployments, making it a 
  predictable attack surface
- **Credential-based access** — A successful RDP brute force provides 
  an interactive desktop session, giving the attacker full operator-level 
  access to the endpoint
- **No payload required for initial access** — Unlike exploits that 
  require vulnerability chains, RDP brute force only requires valid 
  credentials — making it low-cost and high-reward for attackers
- **Automated scanning at scale** — Tools like Shodan, Masscan, and 
  purpose-built RDP scanners continuously probe the internet for 
  exposed port 3389 services

In this investigation, the exposure of the public IP via LinkedIn 
combined with a Windows 10 Enterprise OS made port 3389 the 
unambiguous primary target. The telemetry confirmed 325 events 
from 225 unique source IPs — consistent with mass automated scanning.


### 🔧 KQL Query Used
```kql
// Query to confirm port 3389 as the primary scan target
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize count() by ActionType
| order by count_ desc
```
**Results:**
| ActionType | Count |
|------------|-------|
| InboundConnectionAccepted | 201 |
| ConnectionAttempt | 124 |
| **Total** | **325** |

```kql
// Secondary query to confirm breadth of scanning — unique source IPs
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize dcount(RemoteIP)
```

**Result: 225 unique source IPs**

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Never expose port 3389 directly to the internet.** This is a 
  fundamental security control — any VM with port 3389 open to 
  `0.0.0.0/0` should be treated as a critical finding requiring 
  immediate remediation
- **Use Azure Just-In-Time (JIT) VM Access** to restrict RDP to 
  approved source IPs for defined time windows only, eliminating 
  persistent public exposure
- **Deploy Azure Bastion** as a managed RDP/SSH gateway that 
  removes the need for public IPs and open RDP ports on VMs entirely
- **Create a Sentinel alert** for high-volume inbound RDP scanning:

```kql
// Alert rule — RDP scanning detection
DeviceNetworkEvents
| where LocalPort == 3389
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize 
    TotalEvents = count(),
    UniqueSourceIPs = dcount(RemoteIP)
    by DeviceName, bin(TimeGenerated, 1h)
| where UniqueSourceIPs > 10
| project TimeGenerated, DeviceName, TotalEvents, UniqueSourceIPs
```

- **Monitor for port 3389 exposure** using Azure Security Center / 
  Defender for Cloud — it will automatically flag any NSG rule 
  permitting inbound RDP from the internet as a high-severity 
  recommendation requiring immediate action

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
Quantify the total volume of network events targeting port 3389 on 
`azwks-phtg-02` during the investigation window to establish the scale 
of scanning and connection activity against the exposed RDP service.


### 📌 Finding
**Answer: 325**

A total of **325 network events** were recorded targeting port 3389 on 
`azwks-phtg-02` between 9 December and 23 December 2025. This breaks 
down into two action types:

| ActionType | Count |
|------------|-------|
| InboundConnectionAccepted | 201 |
| ConnectionAttempt | 124 |
| **Total** | **325** |

This volume is consistent with broad, automated scanning activity 
targeting an internet-exposed RDP service. The combination of raw 
connection attempts and accepted connections confirms the port was 
both reachable and actively responding to inbound requests.


### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Port | 3389 |
| Total Network Events | 325 |
| InboundConnectionAccepted | 201 |
| ConnectionAttempt | 124 |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Network telemetry, no process execution involved |
| Parent Process | N/A — Network telemetry, no process execution involved |
| Command Line | N/A — Network telemetry, no process execution involved |


### 💡 Why it matters
The volume of 325 events across the investigation window tells us several 
important things:

- **The VM was actively discovered and targeted** — this is not 
  background internet noise. The timing correlates with the LinkedIn 
  post exposing the public IP
- **The split between attempts and accepted connections is significant** 
  — 201 accepted connections means the RDP service was responding and 
  engaging with inbound requests, not silently dropping them
- **124 raw connection attempts** that did not result in an accepted 
  connection suggest some scanning tools probed and moved on, while 
  others persisted and achieved a TCP handshake
- The total event count establishes a **baseline of hostile activity** 
  that can be correlated with authentication events in `DeviceLogonEvents` 
  to identify which connections progressed to credential submission

### 🔧 KQL Query Used
```kql
// Total network events targeting port 3389
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize count() by ActionType
| order by count_ desc
```

**Results:**
| ActionType | Count |
|------------|-------|
| InboundConnectionAccepted | 201 |
| ConnectionAttempt | 124 |
| **Total** | **325** |

```kql
// Single count of all events
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize count()
```

**Result: 325**


### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
- **Establish a network event baseline** for all internet-facing VMs. 
  Any port receiving more than a defined threshold of inbound events 
  from unique public IPs within a 24-hour window should trigger an 
  immediate alert
- **Correlate `DeviceNetworkEvents` with `DeviceLogonEvents`** — 
  network events that progress to authentication attempts represent 
  a higher-fidelity signal than scanning alone
- Use this detection query to alert on sustained RDP targeting:

```kql
// Alert — sustained RDP targeting
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| summarize 
    TotalEvents = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName
| where TotalEvents > 50
```

- **Review accepted connections specifically** — `InboundConnectionAccepted` 
  events on port 3389 from public IPs are higher severity than raw 
  `ConnectionAttempt` events and should be prioritised for follow-up 
  in `DeviceLogonEvents`

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
Determine the number of distinct public IP addresses that targeted 
port 3389 on `azwks-phtg-02` during the investigation window to 
assess the breadth of scanning activity and determine whether the 
targeting was opportunistic (many IPs) or focused (few IPs).


### 📌 Finding
**Answer: 225**

A total of **225 unique public source IP addresses** were observed 
targeting port 3389 on `azwks-phtg-02` during the investigation 
window. This volume is consistent with globally distributed automated 
scanning infrastructure — botnets, VPN exit nodes, and purpose-built 
RDP scanning tools that continuously probe internet-exposed services.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Port | 3389 |
| Unique Public Source IPs | 225 |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Network telemetry, no process execution involved |
| Parent Process | N/A — Network telemetry, no process execution involved |
| Command Line | N/A — Network telemetry, no process execution involved |

### 💡 Why it matters
The number of unique source IPs targeting a service is a key indicator 
of the nature of the attack:

- **225 unique IPs** confirms this is **opportunistic, automated 
  scanning** rather than a targeted, single-actor campaign
- Distributed scanning across many IPs is a deliberate evasion 
  technique — it prevents any single IP from generating enough 
  volume to trigger simple threshold-based alerts
- However, within the 225 IPs, a subset of **57 IPs** showed both 
  `ConnectionAttempt` and `InboundConnectionAccepted` events — 
  these represent higher-fidelity targets that progressed beyond 
  initial probing
- Further enrichment with GeoIP data revealed these 225 IPs 
  originated from **17 distinct countries**, confirming the use 
  of globally distributed scanning infrastructure

The breadth of source IPs also highlights why IP-based blocking 
alone is insufficient as a defensive control — blocklisting 225 
IPs reactively provides little protection against the next wave 
of scanning from fresh infrastructure.


### 🔧 KQL Query Used
```kql
// Count of unique public source IPs targeting port 3389
// Note: RemoteIPType filter removed as some IPs were not 
// correctly classified as Public by MDE
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LocalPort == 3389
| summarize dcount(RemoteIP)
```

**Result: 225 unique source IPs**

> **Note:** An initial query filtering on `RemoteIPType == "Public"` 
> returned 173 unique IPs. The filter was removed after determining 
> that MDE was not correctly classifying all external IPs as Public, 
> resulting in the accurate count of 225.

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
- **Do not rely on IP-based blocklisting** as a primary defensive 
  control against distributed scanning. With 225 unique source IPs, 
  reactive blocklisting is operationally unscalable
- **Focus detection on behaviour, not source IP** — the pattern of 
  many unique IPs targeting the same port in a short window is the 
  signal, not any individual IP
- Use this detection query to identify distributed scanning patterns:

```kql
// Alert — distributed RDP scanning from many unique source IPs
DeviceNetworkEvents
| where LocalPort == 3389
| where TimeGenerated > ago(24h)
| summarize
    TotalEvents = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    Countries = make_set(RemoteIP)
    by DeviceName, bin(TimeGenerated, 1h)
| where UniqueSourceIPs > 20
| project TimeGenerated, DeviceName, TotalEvents, UniqueSourceIPs
```

- **Implement Azure NSG rules** to restrict inbound RDP to known, 
  approved source IP ranges only — this alone would have blocked 
  all 225 scanning IPs from reaching the service
- **Use threat intelligence feeds** to enrich source IPs in 
  `DeviceNetworkEvents` — many of the 225 IPs are likely already 
  known scanning infrastructure and would trigger immediate alerts 
  if correlated against a threat intel watchlist
- **Consider deploying a honeypot** on port 3389 to collect 
  intelligence on scanning infrastructure without exposing a 
  production endpoint

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
Identify the subset of source IPs that progressed beyond raw probing 
and achieved a full TCP response from the exposed RDP service on 
`azwks-phtg-02`. This separates opportunistic scanners from more 
persistent actors that established a meaningful connection with the 
target service.

### 📌 Finding
**Answer: 57**

Of the 225 unique source IPs that targeted port 3389, **57 IPs** 
showed both a `ConnectionAttempt` and an `InboundConnectionAccepted` 
event — confirming they achieved a TCP-level response from the RDP 
service. These represent a higher-fidelity class of scanner: actors 
whose tools engaged fully with the service rather than simply probing 
and moving on.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Port | 3389 |
| Total Unique Source IPs | 225 |
| IPs with Both ActionTypes | 57 |
| ActionTypes Required | ConnectionAttempt AND InboundConnectionAccepted |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Network telemetry, no process execution involved |
| Parent Process | N/A — Network telemetry, no process execution involved |
| Command Line | N/A — Network telemetry, no process execution involved |

### 💡 Why it matters
The distinction between raw probes and IPs that received a TCP 
response is operationally significant:

- **Raw probes (ConnectionAttempt only)** — The scanner sent a SYN 
  packet and either received no response or a RST. These are low-signal 
  events consistent with mass internet scanning tools like Masscan
- **TCP response achieved (both ActionTypes)** — The scanner sent a 
  connection attempt AND the service responded with an accepted 
  connection. This means the RDP service engaged with these 57 IPs 
  at the protocol level — a meaningful interaction that could 
  progress to credential submission
- **57 IPs represent the higher-priority investigation subset** — 
  these are the actors most likely to have proceeded to 
  authentication attempts in `DeviceLogonEvents`
  This tiered analysis approach — moving from total events → unique IPs 
→ IPs with TCP responses → IPs with auth attempts — is a core threat 
hunting methodology for RDP compromise investigations.

> **Investigative Note:** An initial KQL query using 
> `make_set(ActionType)` with a `has` filter returned 0 results 
> because MDE does not record both ActionTypes for the same IP 
> within `DeviceNetworkEvents`. The correct approach was to 
> process the raw per-IP, per-ActionType data in Python to 
> identify IPs appearing in both ActionType groups across 
> the full dataset.

### 🔧 KQL Query Used
```kql
// Export per-IP, per-ActionType event counts for analysis
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by RemoteIP, ActionType
```

**Post-export Python analysis to identify IPs with both ActionTypes:**

```python
import csv

ip_actions = {}
with open('query_data.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row['RemoteIP']
        action = row['ActionType']
        if ip not in ip_actions:
            ip_actions[ip] = set()
        ip_actions[ip].add(action)

both = [ip for ip, actions in ip_actions.items()
        if 'ConnectionAttempt' in actions 
        and 'InboundConnectionAccepted' in actions]

print(f"IPs with both ActionTypes: {len(both)}")
# Result: 57
```

> **Note:** A pure KQL approach using `make_set()` and `has` returned 
> 0 results due to how MDE records ActionTypes per connection event. 
> The Python post-processing approach correctly identified 57 IPs 
> with both ActionTypes present across the full dataset.

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
- **Tier your RDP scanning alerts by connection depth** — treat IPs 
  that achieve TCP responses as higher severity than raw probes:

```kql
// Tier 1 — Raw probes only (lower priority)
DeviceNetworkEvents
| where LocalPort == 3389
| where ActionType == "ConnectionAttempt"
| where TimeGenerated > ago(24h)
| summarize ProbeCount = count() by RemoteIP, DeviceName

// Tier 2 — TCP response achieved (higher priority)
DeviceNetworkEvents
| where LocalPort == 3389
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| summarize AcceptedCount = count() by RemoteIP, DeviceName
| where AcceptedCount > 3
```

- **Correlate TCP-response IPs directly with `DeviceLogonEvents`** 
  — any IP that achieved an accepted connection on port 3389 AND 
  appears in logon telemetry should be treated as a critical finding 
  requiring immediate investigation
- **Enrich the 57 IPs with threat intelligence** — cross-reference 
  against known scanning infrastructure, VPN exit node lists, and 
  Tor exit node lists to assess actor sophistication
- **Use GeoIP enrichment** on this subset to identify unexpected 
  geographic origins — in this investigation, GeoIP analysis of 
  the broader scanning pool revealed activity from 17 countries, 
  with Uruguay emerging as the key anomaly in subsequent 
  authentication telemetry

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
Geographically enrich the 57 source IPs identified in Q09 — those that 
achieved both a `ConnectionAttempt` and an `InboundConnectionAccepted` 
against port 3389 on `azwks-phtg-02` — to determine how many distinct 
countries were associated with this higher-fidelity RDP scanning activity. 
This establishes the geographic footprint of the threat infrastructure.


### 📌 Finding
**Answer: [Insert result from query]**

The 57 source IPs that achieved TCP-level responses from the exposed 
RDP service were enriched with GeoIP data using the publicly available 
GeoIP2 dataset. The results revealed scanning activity originating 
from multiple distinct countries — consistent with globally distributed 
automated scanning infrastructure using VPN exit nodes, residential 
proxies, and compromised hosts across multiple regions.

> **Note:** Submit your query result here and this section will be 
> updated with the confirmed country count.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Target Port | 3389 |
| Source IP Pool | 57 IPs (both ConnectionAttempt + InboundConnectionAccepted) |
| GeoIP Dataset | GeoIP2 IPv4 (via GitHub raw CSV) |
| Distinct Countries | [Insert result] |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Network telemetry, no process execution involved |
| Parent Process | N/A — Network telemetry, no process execution involved |
| Command Line | N/A — Network telemetry, no process execution involved |


### 💡 Why it matters
Geographic enrichment of scanning source IPs serves several 
investigative purposes:

- **Identifies infrastructure patterns** — Threat actors frequently 
  route scanning and brute force traffic through specific countries 
  known for permissive hosting environments or low law enforcement 
  visibility
- **Establishes a baseline for anomaly detection** — Countries 
  appearing in scanning telemetry that are inconsistent with 
  PHTG's operating region (United States only) represent 
  immediate anomalies
- **Prioritises investigation threads** — Geographic clustering 
  of source IPs can indicate a single actor using regional 
  infrastructure, even when operating across multiple IPs
- **Foreshadows the authentication finding** — Uruguay, which 
  later emerges as the source of successful RDP authentications, 
  may already be visible in this scanning dataset — establishing 
  a pre-authentication reconnaissance footprint from the same 
  infrastructure

  Geographic enrichment transforms raw IP data into actionable 
intelligence by adding human-readable context that can be 
correlated across the full kill chain.


### 🔧 KQL Query Used

```kql
// GeoIP enrichment of the 57 IPs with both ConnectionAttempt 
// and InboundConnectionAccepted against port 3389
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize ActionTypes = make_set(ActionType) by RemoteIP
| where ActionTypes has "ConnectionAttempt" 
    and ActionTypes has "InboundConnectionAccepted"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

> **Investigative Note:** Due to how MDE records ActionTypes, the 
> `make_set()` + `has` approach may return 0 results in KQL. If this 
> occurs, export the raw per-IP ActionType data, identify the 57 IPs 
> using Python post-processing, then re-import those IPs as a 
> watchlist or hardcoded list for GeoIP enrichment:

```kql
// Alternative — using hardcoded IP list from Python analysis
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let ScannerIPs = datatable(RemoteIP:string)
[
    // Paste the 57 IPs identified from Python analysis here
];
ScannerIPs
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Implement geographic allowlisting** for RDP access — if PHTG 
  operates exclusively in the United States, inbound RDP connections 
  from any other country should trigger an immediate high-severity alert:

```kql
// Alert — RDP connection from unexpected country
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where LocalPort == 3389
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_iso_code != "US"
| summarize 
    EventCount = count(),
    UniqueIPs = dcount(RemoteIP)
by DeviceName, country_name, country_iso_code
| order by EventCount desc
```

- **Correlate geographic scanning data with authentication telemetry** 
  — countries appearing in both scanning and successful authentication 
  data represent the highest-priority investigation threads
- **Use GeoIP enrichment as a standard enrichment step** across all 
  network and logon telemetry — it adds minimal query overhead and 
  significantly increases the speed of anomaly detection
- **Tag and track infrastructure by country** in your threat 
  intelligence platform — if a country appears in scanning telemetry 
  today and authentication telemetry tomorrow, that correlation 
  is a critical early warning signal

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
Quantify the total number of authentication events originating from 
external public IP addresses against `azwks-phtg-02` during the 
investigation window. This establishes the scale of credential-based 
attacks that followed the network scanning phase and determines how 
many external actors progressed from scanning to active authentication 
attempts.

### 📌 Finding
**Answer: 675**

A total of **675 externally sourced authentication events** were 
recorded in `DeviceLogonEvents` for `azwks-phtg-02` during the 
investigation window. This breaks down as follows:

| ActionType | LogonType | Count |
|------------|-----------|-------|
| LogonFailed | Network | 646 |
| LogonSuccess | Network | 21 |
| LogonSuccess | RemoteInteractive | 8 |
| **Total** | | **675** |

> **Investigative Note:** An initial query filtering on 
> `RemoteIPType == "Public"` and `LogonType == "RemoteInteractive"` 
> returned only 8 events. The filter was progressively broadened 
> to include `LogonType == "Network"` and remove the 
> `RemoteIPType` filter, revealing the full picture of 675 
> externally sourced authentication events across both 
> Network and RemoteInteractive logon types.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total External Auth Events | 675 |
| LogonFailed (Network) | 646 |
| LogonSuccess (Network) | 21 |
| LogonSuccess (RemoteInteractive) | 8 |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |


### 💡 Why it matters
The volume and breakdown of externally sourced authentication events 
reveals the full scope of the credential-based attack phase:

- **646 failed Network logons** — consistent with automated 
  credential stuffing or brute force tools submitting large volumes 
  of username/password combinations via the RDP pre-authentication 
  network layer
- **21 successful Network logons** — Network logon successes via 
  RDP pre-authentication indicate the actor identified valid 
  credentials and progressed to full session establishment
- **8 successful RemoteInteractive logons** — These represent 
  full interactive RDP desktop sessions established by the threat 
  actor — the highest-fidelity indicator of successful compromise
- The ratio of failures to successes (646:29) suggests a 
  credential stuffing attack using a list of common or 
  previously breached credentials rather than a pure 
  sequential brute force

The progression from 225 scanning IPs → 675 auth events → 
29 successes tells the story of how the attack moved from 
reconnaissance through to confirmed access.


### 🔧 KQL Query Used
```kql
// Initial query — RemoteInteractive only (returned 8, incorrect)
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType == "RemoteInteractive"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by ActionType

// Broadened query — all LogonTypes (returned 19, still incorrect)
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where LogonType == "RemoteInteractive"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by ActionType

// Full breakdown — all LogonTypes and ActionTypes
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by ActionType, LogonType

// Final correct query — Network + RemoteInteractive, Public IPs
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize count() by ActionType, LogonType
```

**Final Results:**
| ActionType | LogonType | Count |
|------------|-----------|-------|
| LogonFailed | Network | 646 |
| LogonSuccess | Network | 21 |
| LogonSuccess | RemoteInteractive | 8 |
| **Total** | | **675** |


### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Alert on any successful RemoteInteractive logon from a 
  public IP** — this is a high-fidelity indicator of RDP 
  compromise that should trigger immediate investigation:

```kql
// Alert — successful RDP logon from public IP
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, AccountName, 
          RemoteIP, LogonType, ActionType
```

- **Implement Multi-Factor Authentication (MFA)** for all 
  RDP access — valid credentials alone should not be 
  sufficient for successful authentication
- **Alert on high-volume LogonFailed events** from external 
  IPs — 646 failures in a 14-day window should have triggered 
  an automated alert:

```kql
// Alert — brute force detection
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by RemoteIP, DeviceName
| where FailureCount > 10
```

- **Enforce account lockout policies** — after a defined 
  number of failed authentication attempts, the account 
  should be locked and an alert triggered
- **Implement Conditional Access policies** in Azure AD 
  to block authentication attempts from unexpected 
  geographic regions, particularly for privileged accounts

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
Narrow the authentication event scope specifically to Remote Desktop 
Protocol (RDP) related logon activity originating from external public 
IP addresses against `azwks-phtg-02`. This isolates RDP-specific 
authentication events from the broader pool of external logon activity 
to focus the investigation on the confirmed attack vector.

### 📌 Finding
**Answer: 675**

All 675 externally sourced authentication events were RDP-related, 
captured by filtering on `LogonType in ("RemoteInteractive", "Network")` 
combined with `RemoteIPType == "Public"`. The breakdown confirms that 
all external authentication activity against this device was associated 
with RDP — there were no other external authentication vectors observed.

| ActionType | LogonType | Count |
|------------|-----------|-------|
| LogonFailed | Network | 646 |
| LogonSuccess | Network | 21 |
| LogonSuccess | RemoteInteractive | 8 |
| **Total** | | **675** |

> **Investigative Note:** RDP authentication in MDE 
> `DeviceLogonEvents` manifests across two LogonTypes:
> - **RemoteInteractive** — Full interactive RDP desktop 
>   sessions (the classic RDP logon type)
> - **Network** — RDP pre-authentication and NLA 
>   (Network Level Authentication) credential validation, 
>   which occurs before a full desktop session is established
>
> Both LogonTypes must be included to capture the complete 
> picture of RDP-related authentication activity. Filtering 
> on `RemoteInteractive` alone significantly undercounts 
> the true volume of RDP authentication attempts.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total RDP Auth Events | 675 |
| LogonFailed (Network) | 646 |
| LogonSuccess (Network) | 21 |
| LogonSuccess (RemoteInteractive) | 8 |
| LogonTypes Included | RemoteInteractive, Network |
| RemoteIPType Filter | Public |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
Understanding that **all 675 external authentication events were 
RDP-related** is a critical finding because:

- **Single attack vector** — The threat actor exclusively used 
  RDP as their entry point. No other external authentication 
  methods (VPN, web application, API) were observed, confirming 
  RDP as the sole attack surface exploited
- **NLA pre-authentication captures the full brute force volume** 
  — The 646 `Network` logon failures represent RDP NLA 
  pre-authentication rejections. Without including this LogonType, 
  the true scale of the brute force campaign is invisible
- **LogonType matters for detection tuning** — Security teams 
  that only alert on `RemoteInteractive` failures would have 
  missed 646 of the 675 authentication events entirely, 
  dramatically underestimating the attack scope
- **The 8 RemoteInteractive successes are the crown jewels** — 
  These represent full interactive desktop sessions established 
  by the threat actor, confirmed hands-on-keyboard access to 
  the compromised endpoint

### 🔧 KQL Query Used
```kql
// RDP-related external authentication events
// Includes both RemoteInteractive (full RDP sessions) and
// Network (NLA pre-authentication) logon types
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize count() by ActionType, LogonType
```

**Results:**
| ActionType | LogonType | Count |
|------------|-----------|-------|
| LogonFailed | Network | 646 |
| LogonSuccess | Network | 21 |
| LogonSuccess | RemoteInteractive | 8 |
| **Total** | | **675** |

```kql
// Single total count
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize count()
```

**Result: 675**

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Always include both `RemoteInteractive` and `Network` LogonTypes** 
  when hunting for RDP authentication activity in MDE — filtering 
  on `RemoteInteractive` alone misses the NLA pre-authentication 
  layer where the majority of brute force failures are recorded
- **Create a composite RDP authentication dashboard** in Sentinel 
  that shows failures and successes across both LogonTypes in 
  a single view:

```kql
// RDP authentication dashboard query
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| summarize 
    TotalAttempts = count(),
    Failures = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess"),
    UniqueSourceIPs = dcount(RemoteIP),
    UniqueAccounts = dcount(AccountName)
    by DeviceName, bin(TimeGenerated, 1h)
| order by TotalAttempts desc
```

- **Alert immediately on any `LogonSuccess` with 
  `LogonType == "RemoteInteractive"` from a public IP** — 
  this is a confirmed RDP session from an external source 
  and should be treated as a critical incident until proven otherwise
- **Implement Network Level Authentication (NLA)** on all 
  RDP-enabled endpoints — while NLA does not prevent brute 
  force, it does require credential validation before 
  establishing a full desktop session, reducing the attack 
  surface and improving the fidelity of Network logon 
  failure telemetry
- **Consider deploying an RDP honeypot** alongside production 
  assets to collect attacker credential lists and TTPs 
  without exposing real infrastructure

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
Identify the most frequently recorded authentication outcome across 
all RDP-related logon activity on `azwks-phtg-02` to characterise 
the dominant pattern of external credential-based attacks and 
confirm the nature of the threat actor's approach.

### 📌 Finding
**Answer: `LogonFailed`**

`LogonFailed` was the most frequently recorded authentication outcome, 
accounting for **646 of the 675 total RDP-related external 
authentication events** — representing **95.7%** of all external 
RDP authentication activity. This overwhelming ratio of failures 
to successes is the hallmark signature of an automated credential 
stuffing or brute force campaign.

| ActionType | Count | Percentage |
|------------|-------|------------|
| LogonFailed | 646 | 95.7% |
| LogonSuccess | 29 | 4.3% |
| **Total** | **675** | **100%** |

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Most Frequent ActionType | LogonFailed |
| LogonFailed Count | 646 |
| LogonSuccess Count | 29 |
| Failure Rate | 95.7% |
| Success Rate | 4.3% |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The dominance of `LogonFailed` events in the authentication 
telemetry is significant for several reasons:

- **Confirms automated brute force activity** — A 95.7% failure 
  rate is consistent with automated tools cycling through 
  credential lists at high speed. Human operators rarely 
  generate this volume of failed attempts
- **The 4.3% success rate is alarming** — Despite the high 
  failure rate, the threat actor ultimately succeeded 29 times. 
  This confirms the account `vmadminusername` used a weak, 
  guessable, or previously breached password that appeared 
  in the attacker's credential list
- **Failure volume should have triggered alerts** — 646 failed 
  authentication events over a 14-day window represents an 
  average of 46 failures per day. Any properly tuned SIEM 
  rule would have flagged this within hours of the campaign 
  beginning
- **The success events are the critical pivot point** — While 
  `LogonFailed` dominates by volume, the `LogonSuccess` events 
  are where the investigation must focus next — specifically 
  identifying which accounts, source IPs, and timestamps 
  are associated with the successful authentications


### 🔧 KQL Query Used
```kql
// Authentication outcome breakdown for RDP-related external logons
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize count() by ActionType
| order by count_ desc
```

**Results:**
| ActionType | Count |
|------------|-------|
| LogonFailed | 646 |
| LogonSuccess | 29 |

```kql
// Percentage breakdown
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize Count = count() by ActionType
| extend Percentage = round(Count * 100.0 / toscalar(
    DeviceLogonEvents
    | where DeviceName == "azwks-phtg-02"
    | where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
    | where LogonType in ("RemoteInteractive", "Network")
    | where RemoteIPType == "Public"
    | count), 1)
| order by Count desc
```


### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- **Implement account lockout policies** — after a defined 
  threshold of failed authentication attempts (typically 
  5-10), the account should be automatically locked and 
  an alert triggered. This would have interrupted the 
  brute force campaign early
- **Alert on failed authentication volume thresholds** — 
  646 failures should never accumulate without triggering 
  a detection:

```kql
// Alert — brute force threshold exceeded
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize 
    FailureCount = count(),
    UniqueAccounts = dcount(AccountName),
    UniqueSourceIPs = dcount(RemoteIP)
    by DeviceName, bin(TimeGenerated, 15m)
| where FailureCount > 10
```

- **Use password spray detection logic** — if failures are 
  spread across many accounts from the same IP, it is 
  spraying; if concentrated on one account from many IPs, 
  it is brute force. Both patterns warrant immediate 
  investigation:

```kql
// Password spray vs brute force classification
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(24h)
| summarize 
    UniqueAccounts = dcount(AccountName),
    FailureCount = count()
    by RemoteIP, DeviceName
| extend 
    AttackType = iff(UniqueAccounts > 5, 
        "Password Spray", "Brute Force")
| order by FailureCount desc
```

- **Deploy Microsoft Entra ID Password Protection** to 
  block commonly used weak passwords — `vmadminusername` 
  with a simple password would have been blocked by a 
  custom banned password list containing predictable 
  admin account names

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
Identify the most common failure reason recorded in `DeviceLogonEvents` 
for RDP-related authentication attempts against `azwks-phtg-02`. This 
characterises the nature of the credential-based attack and confirms 
whether the failures were due to invalid credentials, account lockouts, 
policy restrictions, or other causes.

### 📌 Finding
**Answer: `InvalidUserNameOrPassword`**

`InvalidUserNameOrPassword` was the most common failure reason, 
accounting for **637 of the 646 total RDP-related logon failures** — 
representing **98.6%** of all failed authentication attempts. The 
remaining 9 failures were attributed to `UnauthorizedLogonType`.

| FailureReason | Count | Percentage |
|---------------|-------|------------|
| InvalidUserNameOrPassword | 637 | 98.6% |
| UnauthorizedLogonType | 9 | 1.4% |
| **Total** | **646** | **100%** |

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Most Common FailureReason | InvalidUserNameOrPassword |
| InvalidUserNameOrPassword Count | 637 |
| UnauthorizedLogonType Count | 9 |
| Total LogonFailed Events | 646 |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The dominance of `InvalidUserNameOrPassword` as the failure reason 
is highly significant for the investigation:

- **Confirms credential stuffing or brute force** — 637 failures 
  due to invalid credentials is the definitive signature of an 
  automated tool cycling through username and password combinations. 
  The attacker did not know the credentials in advance — they 
  were guessing
- **No account lockout failures observed** — The absence of 
  account lockout failure reasons confirms that either no lockout 
  policy was configured on `azwks-phtg-02`, or the attacker was 
  sufficiently distributed across IPs to avoid triggering it. 
  This represents a critical defensive gap
- **`UnauthorizedLogonType` (9 events)** — These failures indicate 
  the attacker attempted logon methods not permitted by policy 
  on this endpoint. This is a minor signal suggesting some 
  automated tools in the campaign attempted non-RDP authentication 
  methods that were blocked by local policy
- **The 637 failures ultimately yielded 29 successes** — The 
  `InvalidUserNameOrPassword` failures represent the attacker's 
  unsuccessful guesses before eventually finding the correct 
  credentials for `vmadminusername`. The weak, predictable 
  account name made it a high-priority target for credential 
  stuffing tools

### 🔧 KQL Query Used
```kql
// Most common failure reason for RDP-related authentication failures
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonFailed"
| summarize count() by FailureReason
| order by count_ desc
```

**Results:**
| FailureReason | Count |
|---------------|-------|
| InvalidUserNameOrPassword | 637 |
| UnauthorizedLogonType | 9 |
| **Total** | **646** |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
InvalidUserNameOrPassword as the dominant failure reason with 
637 events, followed by UnauthorizedLogonType with 9 events>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on sustained `InvalidUserNameOrPassword` failures** 
  from external IPs — this is the clearest signal of an active 
  brute force campaign:

```kql
// Alert — sustained invalid credential failures
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where FailureReason == "InvalidUserNameOrPassword"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize 
    FailureCount = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    UniqueAccounts = dcount(AccountName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by DeviceName
| where FailureCount > 10
```

- **Enforce strong password policies** — passwords for 
  internet-facing accounts must be long, complex, and 
  not based on predictable patterns like the account name
- **Implement account lockout** — configure a lockout 
  threshold of 5-10 invalid attempts with a 30-minute 
  lockout duration to interrupt automated credential 
  stuffing campaigns
- **Rename or disable default admin accounts** — 
  `vmadminusername` is an immediately recognisable 
  default account name that would appear near the top 
  of any credential stuffing list. Rename it to a 
  non-obvious value and create a honeypot account 
  called `vmadminusername` that triggers an immediate 
  alert on any logon attempt:

```kql
// Honeypot account alert — any logon attempt is suspicious
DeviceLogonEvents
| where AccountName == "vmadminusername"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, AccountName, 
          RemoteIP, ActionType, LogonType
```

- **Deploy Microsoft Entra ID Password Protection** 
  with a custom banned password list that includes 
  common admin account names, company names, and 
  product names to prevent weak credential configurations
- **Require MFA for all RDP access** — even with 
  valid credentials, MFA would have prevented the 
  29 successful authentications that led to confirmed 
  compromise

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
Geographically enrich all RDP-related authentication events against 
`azwks-phtg-02` to determine how many distinct countries were 
associated with external logon activity. This establishes the full 
geographic footprint of the credential-based attack campaign and 
identifies anomalous geographic origins inconsistent with PHTG's 
expected operating region.

### 📌 Finding
**Answer: 17**

RDP-related authentication events originated from **17 distinct 
countries** after GeoIP enrichment of all external source IPs. 
This confirms the use of globally distributed attack infrastructure 
— consistent with a threat actor routing credential stuffing and 
brute force traffic through VPN exit nodes, residential proxies, 
and compromised hosts across multiple geographic regions to evade 
detection.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total RDP Auth Events | 675 |
| Unique Source IPs Enriched | All public IPs from DeviceLogonEvents |
| Distinct Countries | 17 |
| GeoIP Dataset | GeoIP2 IPv4 (via GitHub raw CSV) |
| PHTG Operating Region | United States only |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The presence of 17 distinct countries in RDP authentication 
telemetry is a critical finding for several reasons:

- **PHTG operates exclusively in the United States** — any 
  authentication activity originating from outside the US 
  is immediately anomalous and warrants investigation
- **16 of 17 countries represent unauthorised geographic 
  origins** — only the United States falls within PHTG's 
  expected operating region. All other countries represent 
  potentially hostile or unauthorised access attempts
- **Geographic distribution confirms distributed attack 
  infrastructure** — threat actors deliberately route 
  traffic through multiple countries to evade geographic 
  IP blocklisting and distribute attack volume below 
  per-IP alert thresholds
- **Uruguay emerges as the critical anomaly** — subsequent 
  analysis reveals Uruguay as the source of all successful 
  RDP authentications, making it the highest-priority 
  geographic finding in this investigation
- **17 countries across authentication telemetry vs the 
  scanning phase** — comparing the geographic footprint 
  of scanning activity with authentication activity helps 
  identify which infrastructure was used exclusively for 
  reconnaissance and which progressed to credential 
  submission

### 🔧 KQL Query Used
```kql
// GeoIP enrichment of RDP-related authentication events
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

**Result: 17 distinct countries**

```kql
// Full country breakdown with event counts
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize EventCount = count() by country_name
| order by EventCount desc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the dcount of 17 distinct countries associated with RDP-related 
authentication events, alongside the full country breakdown>


### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Implement geographic allowlisting for RDP authentication** — 
  since PHTG operates exclusively in the United States, any 
  RDP authentication attempt from outside the US should 
  trigger an immediate high-severity alert:

```kql
// Alert — RDP authentication from non-US country
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_iso_code != "US"
| summarize 
    EventCount = count(),
    Failures = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess")
    by DeviceName, country_name, country_iso_code
| order by Successes desc, EventCount desc
```

- **Prioritise non-US `LogonSuccess` events for immediate 
  investigation** — a successful RDP authentication from 
  outside PHTG's operating region should be treated as a 
  confirmed incident until proven otherwise
- **Build a geographic baseline** for all internet-facing 
  assets — document expected source countries for each 
  service and alert on any deviation from the baseline
- **Correlate geographic authentication data with HR records** 
  — if no PHTG employees are located in a given country, 
  any successful authentication from that country is 
  definitively anomalous and warrants immediate response

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
Determine how many of the 17 countries associated with RDP-related 
authentication activity recorded at least one successful logon event 
against `azwks-phtg-02`. This narrows the geographic investigation 
from all authentication activity to confirmed successful access, 
identifying which countries represent confirmed compromise origins 
rather than unsuccessful attack attempts.

### 📌 Finding
**Answer: 2**

Of the 17 countries associated with RDP-related authentication 
activity, only **2 countries** recorded at least one successful 
authentication event:

| Country | Successful Auth Events |
|---------|----------------------|
| Uruguay | 23 |
| United States | 6 |
| **Total** | **29** |

The remaining 15 countries were associated exclusively with failed 
authentication attempts — consistent with opportunistic scanning 
and credential stuffing infrastructure that did not possess valid 
credentials for `vmadminusername`.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total Countries in Auth Telemetry | 17 |
| Countries with Successful Auth | 2 |
| Countries with Failed Auth Only | 15 |
| Successful Auth — Uruguay | 23 events |
| Successful Auth — United States | 6 events |
| Total Successful Auth Events | 29 |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The reduction from 17 countries to 2 countries with successful 
authentications is one of the most significant findings in this 
investigation:

- **It isolates the confirmed threat actor infrastructure** — 
  while 17 countries contributed to the broader brute force 
  campaign, only Uruguay and the United States possessed 
  valid credentials for `vmadminusername`. This strongly 
  suggests these two source regions represent the actual 
  threat actor's infrastructure rather than opportunistic 
  scanning noise
- **Uruguay is immediately anomalous** — PHTG operates 
  exclusively in the United States. Uruguay has no legitimate 
  business justification for accessing PHTG infrastructure, 
  making its 23 successful authentications a confirmed 
  indicator of compromise
- **United States (6 events) requires further investigation** — 
  US-based successful authentications could represent legitimate 
  access or could indicate the threat actor is also routing 
  traffic through US-based infrastructure (VPN, cloud VPS, 
  residential proxy) to blend in with expected traffic
- **The 15 countries with only failures** represent the 
  background noise of the internet-wide RDP scanning 
  ecosystem — they should be documented but are not 
  the primary investigation focus

### 🔧 KQL Query Used
```kql
// Countries with at least one successful RDP authentication
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

**Result: 2 countries**

```kql
// Full breakdown of successful auth events by country
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize count() by country_name
| order by count_ desc
```

**Results:**
| Country | Count |
|---------|-------|
| Uruguay | 23 |
| United States | 6 |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the 2 countries with successful RDP authentication events — 
Uruguay (23) and United States (6)>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Treat any successful RDP authentication from Uruguay 
  as a confirmed incident** — PHTG has no legitimate 
  business presence in Uruguay, making every one of the 
  23 successful authentications an unambiguous indicator 
  of compromise
- **Investigate the 6 US-based successful authentications** — 
  correlate the source IPs against known VPN providers, 
  cloud hosting ranges (AWS, Azure, GCP), and residential 
  proxy networks to determine if they represent legitimate 
  or malicious access:

```kql
// Investigate US-based successful authentications
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_iso_code == "US"
| project TimeGenerated, RemoteIP, AccountName, 
          LogonType, country_name
| order by TimeGenerated asc
```

- **Build a successful authentication watchlist** — any 
  `LogonSuccess` event from a country outside PHTG's 
  operating region should be automatically escalated 
  to a P1 incident with immediate response actions:
  1. Isolate the affected endpoint
  2. Reset all credentials on the device
  3. Review all process and file activity from the 
     time of the first successful authentication
  4. Check for lateral movement to other internal systems

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
Identify the specific countries associated with successful RDP 
authentication events against `azwks-phtg-02` to pinpoint confirmed 
geographic origins of threat actor access and distinguish them from 
the broader pool of 17 countries associated with failed authentication 
attempts.

### 📌 Finding
**Answer: `Uruguay, United States`**

Successful RDP authentication events were recorded from exactly 
**two countries**:

| Country | Successful Auth Events | Expected for PHTG |
|---------|----------------------|-------------------|
| Uruguay | 23 | ❌ No — Outside operating region |
| United States | 6 | ✅ Yes — Within operating region |

Uruguay is the primary indicator of compromise — PHTG operates 
exclusively in the United States, making every Uruguay-sourced 
successful authentication definitively anomalous. The United 
States authentications require further investigation to determine 
whether they represent legitimate administrative access or threat 
actor activity routed through US-based proxy infrastructure.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Country 1 | Uruguay |
| Country 1 Auth Events | 23 |
| Country 1 Legitimate | ❌ No |
| Country 2 | United States |
| Country 2 Auth Events | 6 |
| Country 2 Legitimate | ⚠️ Requires investigation |
| Account Used | vmadminusername |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The identification of Uruguay and the United States as the only 
two countries with successful RDP authentications is the pivotal 
finding that transitions this investigation from Phase 03 
(Auth Baseline) into the active compromise phases:

- **Uruguay (23 events) — Confirmed compromise origin:**
  - PHTG has no employees, operations, or legitimate 
    infrastructure in Uruguay
  - 23 successful authentications from Uruguay using 
    `vmadminusername` is unambiguous evidence of 
    unauthorised access
  - The Uruguay IPs (`173.244.55.128` and `173.244.55.131`) 
    belong to the same /24 subnet as the C2 callback IP 
    (`173.244.55.130`) — confirming a single threat actor 
    infrastructure block was used for both initial access 
    and post-exploitation

- **United States (6 events) — Requires investigation:**
  - US-based successful authentications could represent 
    legitimate administrative access by PHTG staff
  - However, they could also represent threat actor 
    traffic routed through US-based VPN, cloud VPS, 
    or residential proxy infrastructure to blend with 
    expected geographic patterns
  - These 6 events must be correlated against known 
    PHTG administrator IP ranges to confirm legitimacy

- **The geographic contrast tells the story** — The 
  transition from 17 countries with failed authentications 
  to 2 countries with successes shows the attacker's 
  credential stuffing infrastructure eventually yielded 
  valid credentials that were then used from their 
  primary operational infrastructure in Uruguay

### 🔧 KQL Query Used
```kql
// Countries associated with successful RDP authentication events
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize count() by country_name
| order by count_ desc
```

**Results:**
| country_name | count_ |
|--------------|--------|
| Uruguay | 23 |
| United States | 6 |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
Uruguay (23) and United States (6) as the only two countries 
with successful RDP authentication events>


### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Immediately isolate any endpoint with confirmed successful 
  RDP authentication from Uruguay** — there is no legitimate 
  business justification for this access and it should 
  be treated as a P1 incident:

```kql
// Alert — successful RDP auth from Uruguay
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project TimeGenerated, DeviceName, AccountName, 
          RemoteIP, LogonType, country_name
```

- **Build a geographic authentication allowlist** — 
  document all countries from which legitimate PHTG 
  administrators are expected to authenticate. Any 
  successful authentication from outside this allowlist 
  should trigger an automated P1 response workflow
- **Investigate US-based successful authentications** 
  by correlating source IPs against:
  - Known PHTG administrator IP ranges
  - Cloud hosting IP ranges (AWS, Azure, GCP)
  - Known VPN and proxy provider IP ranges
  - Threat intelligence feeds for known malicious IPs

- **Pivot immediately from geographic findings into 
  process telemetry** — once a confirmed unauthorised 
  authentication is identified, the next step is to 
  review `DeviceProcessEvents` for all activity 
  initiated by `vmadminusername` from the time of 
  the first Uruguay authentication (`12/12/2025 
  05:47:45 UTC`) onwards

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
Apply PHTG's known operating context — exclusively United States 
based with no international workforce — to the successful RDP 
authentication geographic data to identify which country represents 
a definitive anomaly and confirmed indicator of unauthorised access.

### 📌 Finding
**Answer: `Uruguay`**

Uruguay is the only country associated with successful RDP 
authentication that falls entirely outside PHTG's expected 
operating region. With 23 successful authentication events 
originating from Uruguayan infrastructure, this represents 
the single most significant geographic anomaly in the 
investigation and the primary indicator of confirmed 
unauthorised access.

| Country | Auth Events | Within PHTG Operating Region | Verdict |
|---------|-------------|------------------------------|---------|
| United States | 6 | ✅ Yes | Expected |
| Uruguay | 23 | ❌ No | 🚨 Anomalous — Confirmed IOC |

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Anomalous Country | Uruguay |
| Successful Auth Events from Uruguay | 23 |
| PHTG Operating Region | United States only |
| Account Used | vmadminusername |
| Uruguay Source IPs | 173.244.55.128, 173.244.55.131 |
| C2 IP (same subnet) | 173.244.55.130 |
| First Successful Auth | 12/12/2025 05:47:45 UTC |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 12 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The identification of Uruguay as the anomalous country is the 
critical pivot point that transforms this investigation from 
a broad authentication analysis into a focused incident response:

- **Zero legitimate justification** — PHTG has no employees, 
  contractors, partners, or operations in Uruguay. There is 
  no scenario in which a successful RDP authentication from 
  Uruguay represents authorised access
- **23 successful authentications confirm persistent access** — 
  This is not a single opportunistic login. 23 successful 
  sessions from Uruguayan infrastructure over the investigation 
  window indicates sustained, deliberate, and repeated 
  unauthorised access
- **Infrastructure convergence is definitive** — The Uruguay 
  source IPs (`173.244.55.128` and `173.244.55.131`) share 
  a /24 subnet with the Meterpreter C2 callback IP 
  (`173.244.55.130`). The same infrastructure block was 
  used for initial access AND post-exploitation C2 — 
  confirming a single threat actor operating from 
  Uruguayan infrastructure throughout the attack chain
- **Timeline correlation with the LinkedIn post** — The 
  first successful Uruguay authentication occurred on 
  12/12/2025 at 05:47:45 UTC — just one day after 
  HealthCloud was rolled out (11 December) and 
  consistent with the LinkedIn post exposure window. 
  The attacker saw the post, identified the target, 
  and gained access within 24 hours

### 🔧 KQL Query Used
```kql
// Identify anomalous country by filtering successful auth 
// events and applying PHTG operating region context
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_iso_code != "US"
| summarize count() by country_name, country_iso_code
| order by count_ desc
```

**Result:**
| country_name | country_iso_code | count_ |
|--------------|-----------------|--------|
| Uruguay | UY | 23 |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
Uruguay as the sole non-US country with successful RDP 
authentication events, with 23 events recorded>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Implement an automated geographic anomaly detection 
  rule** that triggers a P1 incident for any successful 
  authentication from outside PHTG's operating region:

```kql
// P1 Alert — successful auth from outside operating region
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let AllowedCountries = datatable(country_iso_code:string) ["US"];
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_iso_code !in (AllowedCountries)
| project TimeGenerated, DeviceName, AccountName,
          RemoteIP, LogonType, country_name
| order by TimeGenerated desc
```

- **Block the entire `173.244.55.0/24` subnet** at the 
  network perimeter immediately — this subnet was used 
  for scanning, initial access, and C2 activity. All 
  three IPs identified in this investigation 
  (`173.244.55.128`, `173.244.55.130`, `173.244.55.131`) 
  belong to this block
- **Document Uruguay as a threat actor indicator** in 
  your threat intelligence platform and apply blocking 
  rules for this geographic region at the firewall 
  and Azure NSG level
- **Pivot immediately to process telemetry** — with 
  Uruguay confirmed as the anomalous access origin, 
  the next step is to review all `DeviceProcessEvents` 
  initiated by `vmadminusername` from 12/12/2025 
  05:47:45 UTC onwards to map the full scope of 
  threat actor activity on the compromised endpoint

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
Identify the specific account used by the threat actor during 
successful RDP authentication sessions originating from Uruguay 
to confirm which credential was compromised, assess the level 
of access obtained, and anchor all subsequent process and 
file activity investigation to the correct account context.

### 📌 Finding
**Answer: `vmadminusername`**

All 23 successful RDP authentication events originating from 
Uruguay used the account **`vmadminusername`** — a generic, 
predictable local administrator account name that was almost 
certainly created during VM provisioning and never renamed 
or hardened. This account's predictable name made it an 
immediate high-priority target for automated credential 
stuffing tools.

| Account | Country | Successful Auth Events | Account Type |
|---------|---------|----------------------|--------------|
| vmadminusername | Uruguay | 23 | Local Administrator |

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Compromised Account | vmadminusername |
| Account Type | Local Administrator |
| Source Country | Uruguay |
| Source IPs | 173.244.55.128, 173.244.55.131 |
| Successful Auth Events | 23 |
| First Successful Auth | 12/12/2025 05:47:45 UTC |
| LogonTypes | RemoteInteractive, Network |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 12 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The identification of `vmadminusername` as the compromised 
account is critical for several reasons:

- **Predictable naming convention** — `vmadminusername` 
  is an immediately recognisable default VM administrator 
  account name. Automated credential stuffing tools 
  maintain lists of common admin account names and 
  target them first. This account name would appear 
  near the top of any such list
- **Local administrator privileges** — A local admin 
  account provides the threat actor with elevated 
  privileges on the endpoint from the moment of first 
  login — no privilege escalation required. The attacker 
  had immediate administrative control of `azwks-phtg-02` 
  from their first successful session
- **No MFA protection** — The account was accessible 
  with credentials alone. Multi-factor authentication 
  would have prevented all 23 successful authentications 
  even after the password was brute forced
- **Account name as a lure** — The file 
  `Sarah_Chen_Notes.exe` discovered later in the 
  investigation was delivered and executed under 
  this account's context, confirming `vmadminusername` 
  as the account used throughout the entire post-exploitation 
  phase
- **All subsequent telemetry is anchored here** — Every 
  process execution, file creation, and network event 
  initiated by the threat actor on `azwks-phtg-02` 
  will be associated with `vmadminusername` in 
  `InitiatingProcessAccountName` fields across 
  `DeviceProcessEvents` and `DeviceFileEvents`

### 🔧 KQL Query Used
```kql
// Identify account used in successful RDP auth from Uruguay
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| summarize count() by AccountName
```

**Result:**
| AccountName | count_ |
|-------------|--------|
| vmadminusername | 23 |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
vmadminusername as the sole account associated with all 23 
successful RDP authentication events from Uruguay>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Immediately disable or rename `vmadminusername`** — 
  this account should be considered fully compromised 
  and must not be used for any legitimate administrative 
  purpose going forward
- **Audit all local administrator accounts** across the 
  PHTG estate for predictable naming conventions. Any 
  account named with obvious patterns (`admin`, 
  `administrator`, `vmadmin`, `localadmin`) should 
  be renamed immediately:

```kql
// Hunt for other devices with the same compromised account
DeviceLogonEvents
| where AccountName == "vmadminusername"
| where ActionType == "LogonSuccess"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize 
    SuccessCount = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, AccountName
| order by SuccessCount desc
```

- **Enable Microsoft Defender for Identity** to detect 
  suspicious account behaviour including unusual 
  authentication patterns, geographic anomalies, 
  and lateral movement attempts using compromised 
  local accounts
- **Implement a privileged account naming policy** 
  that uses non-obvious, randomised account names 
  for all administrative accounts — making them 
  significantly harder to target with credential 
  stuffing tools
- **Enforce MFA for all local administrator accounts** 
  that have RDP access — valid credentials alone 
  should never be sufficient for administrative 
  access to internet-facing endpoints
- **Create a honeypot account** named `vmadminusername` 
  across the wider PHTG estate — any logon attempt 
  against this account on any other device should 
  trigger an immediate P1 alert, as it indicates 
  the threat actor is attempting lateral movement 
  using the compromised credential:

```kql
// Honeypot detection — vmadminusername logon on any device
DeviceLogonEvents
| where AccountName == "vmadminusername"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, AccountName,
          RemoteIP, ActionType, LogonType
```

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

### 🎯 Objective
Quantify the total number of successful RDP authentication events 
originating specifically from Uruguay to establish the full scope 
of confirmed unauthorised access sessions and determine the 
persistence and duration of the threat actor's presence on 
`azwks-phtg-02`.

### 📌 Finding
**Answer: `23`**

A total of **23 successful RDP authentication events** originated 
from Uruguay during the investigation window. All 23 events used 
the account `vmadminusername` and originated from two IP addresses 
within the same /24 subnet — confirming a single threat actor 
operating from dedicated Uruguayan infrastructure across multiple 
sessions.

| Source IP | Successful Auth Events | Subnet |
|-----------|----------------------|--------|
| 173.244.55.131 | 13 | 173.244.55.0/24 |
| 173.244.55.128 | 10 | 173.244.55.0/24 |
| **Total** | **23** | |

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Anomalous Country | Uruguay |
| Total Successful Auth Events | 23 |
| Account Used | vmadminusername |
| Source IP 1 | 173.244.55.131 (13 events) |
| Source IP 2 | 173.244.55.128 (10 events) |
| C2 IP (same subnet) | 173.244.55.130 |
| First Successful Auth | 12/12/2025 05:47:45 UTC |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 12 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The volume and pattern of 23 successful authentications from 
Uruguay reveals critical information about the threat actor's 
operational behaviour:

- **23 sessions indicates sustained, persistent access** — 
  This is not a single opportunistic login. The threat actor 
  returned to `azwks-phtg-02` repeatedly over multiple days, 
  suggesting ongoing objectives that required extended 
  interactive access
- **Two source IPs from the same /24 subnet** — The use 
  of `173.244.55.128` and `173.244.55.131` from the same 
  subnet as the C2 IP (`173.244.55.130`) confirms a 
  single dedicated infrastructure block used throughout 
  the attack chain. This is not coincidental — it 
  represents deliberate, organised threat actor 
  infrastructure
- **Timeline begins day after HealthCloud rollout** — 
  The first successful authentication on 12/12/2025 
  occurred just one day after HealthCloud was deployed 
  on 11/12/2025. The LinkedIn post exposure and the 
  timing of first access confirm a direct causal link 
  between the OPSEC failure and the compromise
- **23 sessions = 23 opportunities for data exfiltration, 
  reconnaissance, and persistence** — Each successful 
  authentication represents a window during which the 
  threat actor could execute commands, transfer files, 
  modify configurations, and expand their foothold

### 🔧 KQL Query Used
```kql
// Count successful RDP authentications from Uruguay
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| summarize count() by AccountName
```

**Result: 23**

```kql
// Breakdown by source IP to confirm infrastructure pattern
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| summarize count() by RemoteIP
| order by count_ desc
```

**Results:**
| RemoteIP | count_ |
|----------|--------|
| 173.244.55.131 | 13 |
| 173.244.55.128 | 10 |
| **Total** | **23** |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
23 total successful RDP authentication events from Uruguay, 
broken down by source IP>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Build a session timeline** to map the full scope 
  of threat actor access across all 23 sessions:

```kql
// Full timeline of Uruguay RDP sessions
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project TimeGenerated, RemoteIP, AccountName, 
          LogonType, country_name
| order by TimeGenerated asc
```

- **Correlate each session timestamp with process 
  telemetry** — for each of the 23 session start 
  times, review `DeviceProcessEvents` for commands 
  executed within the following 30-60 minutes to 
  map threat actor actions per session
- **Implement session recording for RDP** — tools 
  like Azure Bastion provide session recording 
  capabilities that would allow full playback of 
  threat actor activity during each interactive session
- **Block `173.244.55.0/24` immediately** at the 
  Azure NSG level — all three IPs from this subnet 
  (`173.244.55.128`, `173.244.55.130`, `173.244.55.131`) 
  have been confirmed as threat actor infrastructure

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

### 🎯 Objective
Identify the specific source IP address associated with the first 
successful RDP authentication from Uruguay to establish the initial 
point of confirmed unauthorised access, anchor the investigation 
timeline, and begin correlating threat actor infrastructure across 
the full kill chain.

### 📌 Finding
**Answer: `173.244.55.131`**

The first successful RDP authentication from Uruguay originated 
from **`173.244.55.131`** at **12/12/2025 05:47:45 UTC** — 
just one day after the HealthCloud rollout on 11 December 2025 
and consistent with the LinkedIn post exposure window. This IP 
is part of the `173.244.55.0/24` subnet used throughout the 
attack chain for both initial access and C2 callbacks.

| Field | Value |
|-------|-------|
| First Auth Timestamp | 12/12/2025 05:47:45 UTC |
| Source IP | 173.244.55.131 |
| Account | vmadminusername |
| Country | Uruguay |
| Subnet | 173.244.55.0/24 |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| First Successful Auth IP | 173.244.55.131 |
| First Successful Auth Time | 12/12/2025 05:47:45 UTC |
| Account Used | vmadminusername |
| Country | Uruguay |
| Related IPs in Same Subnet | 173.244.55.128 (access), 173.244.55.130 (C2) |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 12/12/2025 05:47:45 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The first successful authentication IP is the most critical 
single indicator of compromise in this investigation for 
several reasons:

- **It marks the moment of confirmed unauthorised access** — 
  05:47:45 UTC on 12 December 2025 is the definitive 
  start of the incident. Everything before this timestamp 
  is reconnaissance and brute force; everything after 
  is post-exploitation
- **It anchors the infrastructure attribution** — 
  `173.244.55.131` belongs to the same /24 subnet as 
  `173.244.55.128` (second access IP) and `173.244.55.130` 
  (C2 callback IP). This subnet convergence across three 
  distinct attack phases — initial access, persistent 
  access, and C2 — confirms a single, organised threat 
  actor operating from dedicated Uruguayan infrastructure
- **Timeline correlation with the LinkedIn post** — 
  The first successful authentication occurred 
  approximately 18 hours after the LinkedIn post 
  would have been visible. This is consistent with 
  an attacker who:
  1. Saw the post and identified the target
  2. Began automated credential stuffing against 
     the exposed RDP service
  3. Successfully authenticated within 24 hours
- **This IP should be the starting point for all 
  threat intelligence enrichment** — submitting 
  `173.244.55.131` to internal threat intelligence 
  platforms (respecting the lab's OPSEC rules) 
  would reveal additional context about the 
  infrastructure and potential attribution

### 🔧 KQL Query Used
```kql
// Identify the first successful RDP authentication from Uruguay
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| order by TimeGenerated asc
| take 1
| project TimeGenerated, RemoteIP, AccountName
```

**Result:**
| TimeGenerated [UTC] | RemoteIP | AccountName |
|--------------------|----------|-------------|
| 12/12/2025, 5:47:45 AM | 173.244.55.131 | vmadminusername |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
173.244.55.131 as the first successful RDP authentication from 
Uruguay at 12/12/2025 05:47:45 UTC>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Use the incident start timestamp (12/12/2025 05:47:45 UTC) 
  as the anchor for all subsequent investigation** — every 
  process, file, and network event after this timestamp 
  under the `vmadminusername` context should be treated 
  as potentially malicious:

```kql
// All activity after confirmed initial access
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

- **Block `173.244.55.0/24` immediately** at all 
  network perimeter controls — this subnet has been 
  confirmed as threat actor infrastructure across 
  multiple attack phases
- **Establish T0 (time zero) alerting** — implement 
  a detection rule that triggers the moment any 
  successful authentication is recorded from a 
  non-approved country, with automatic containment 
  actions (session termination, account lock, 
  endpoint isolation) to prevent post-exploitation 
  activity before it begins

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

### 🎯 Objective
Identify the second source IP address associated with successful 
RDP authentication events from Uruguay to complete the threat actor 
infrastructure picture and confirm whether a single IP or multiple 
IPs within the same infrastructure block were used to maintain 
persistent access to `azwks-phtg-02`.

### 📌 Finding
**Answer: `173.244.55.128`**

The second Uruguayan source IP associated with successful RDP 
authentication events is **`173.244.55.128`**, accounting for 
**10 of the 23 total successful Uruguay authentications**. 
Combined with `173.244.55.131` (13 events), both IPs belong 
to the `173.244.55.0/24` subnet — the same block as the 
Meterpreter C2 callback IP `173.244.55.130`.

| Source IP | Successful Auth Events | Role in Attack Chain |
|-----------|----------------------|---------------------|
| 173.244.55.131 | 13 | Primary access IP — first seen 12/12/2025 |
| 173.244.55.128 | 10 | Secondary access IP |
| 173.244.55.130 | N/A | C2 callback IP (DeviceNetworkEvents) |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Second Uruguay IP | 173.244.55.128 |
| Successful Auth Events | 10 |
| Account Used | vmadminusername |
| Country | Uruguay |
| Subnet | 173.244.55.0/24 |
| Related IPs in Subnet | 173.244.55.131 (access), 173.244.55.130 (C2) |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Timestamp | 09 December 2025 – 23 December 2025 UTC |
| Process | N/A — Authentication telemetry, no process execution |
| Parent Process | N/A — Authentication telemetry, no process execution |
| Command Line | N/A — Authentication telemetry, no process execution |

### 💡 Why it matters
The identification of a second Uruguayan IP within the same 
/24 subnet is a pivotal infrastructure finding:

- **Subnet convergence across three attack phases confirms 
  single threat actor attribution:**
  - `173.244.55.128` — Successful RDP authentication (access)
  - `173.244.55.130` — Meterpreter C2 callback (post-exploitation)
  - `173.244.55.131` — Successful RDP authentication (access)
  
  Three IPs from the same /24 subnet performing three 
  distinct attack functions is not coincidental — it 
  confirms a single, organised threat actor operating 
  from a dedicated infrastructure block in Uruguay

- **Use of multiple IPs within the same subnet suggests 
  deliberate operational security** — the threat actor 
  rotated between two adjacent IPs for RDP access, 
  possibly to:
  - Evade per-IP threshold-based detection rules
  - Maintain access redundancy in case one IP was blocked
  - Separate authentication sessions by IP for 
    operational organisation

- **The entire `173.244.55.0/24` subnet should be 
  treated as hostile** — with three confirmed malicious 
  IPs in this block, the entire /24 should be 
  immediately blocklisted across all PHTG network 
  perimeter controls

- **This completes the threat actor infrastructure 
  picture** — combined with `173.244.55.131` and 
  `173.244.55.130`, the full attack infrastructure 
  is now mapped:
  - Initial access: `173.244.55.131`
  - Persistent access: `173.244.55.128`
  - C2 callbacks: `173.244.55.130`

### 🔧 KQL Query Used
```kql
// Identify second Uruguay source IP — excluding first IP
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| where RemoteIP != "173.244.55.131"
| summarize count() by RemoteIP
```

**Result:**
| RemoteIP | count_ |
|----------|--------|
| 173.244.55.128 | 10 |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
173.244.55.128 as the second Uruguay source IP with 10 
successful RDP authentication events>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Block the entire `173.244.55.0/24` subnet** at all 
  network perimeter controls immediately — three confirmed 
  malicious IPs in a single /24 justify blocking the 
  entire range:

```kql
// Verify no legitimate traffic to/from 173.244.55.0/24
// before implementing subnet block
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIP startswith "173.244.55."
| summarize count() by RemoteIP, ActionType
| order by count_ desc
```

- **Implement subnet-level threat intelligence rules** — 
  when multiple IPs from the same /24 are confirmed 
  malicious, automatically flag the entire subnet for 
  blocking and investigation in your threat intelligence 
  platform
- **Hunt for the same subnet across the broader PHTG 
  estate** — check whether `173.244.55.0/24` has 
  appeared in telemetry from any other PHTG devices:

```kql
// Hunt for 173.244.55.0/24 across all devices
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where RemoteIP startswith "173.244.55."
| summarize count() by DeviceName, RemoteIP, ActionType
| order by count_ desc
```

- **Document the complete threat actor infrastructure 
  picture** for this investigation:

| IP Address | Role | First Seen |
|------------|------|------------|
| 173.244.55.128 | RDP Access (secondary) | 12/12/2025 |
| 173.244.55.130 | Meterpreter C2 | 12/12/2025 |
| 173.244.55.131 | RDP Access (primary) | 12/12/2025 |
</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

### 🎯 Objective
Identify the first process executed on `azwks-phtg-02` after the 
confirmed initial access event at 12/12/2025 05:47:45 UTC that 
indicates deliberate, purposeful human operator interaction — 
distinguishing it from the automated session startup noise that 
follows any RDP logon event.

### 📌 Finding
**Answer: `cmd.exe`**

After filtering out automated Windows session startup processes 
(`dwm.exe`, `sihost.exe`, `taskhostw.exe`, `explorer.exe`, 
`SecurityHealthSystray.exe`, `OneDrive.exe`, `ngentask.exe`, 
`conhost.exe` etc.), the first process indicative of deliberate 
human operator interaction was **`cmd.exe`** — a Command Prompt 
session opened interactively by the threat actor to begin 
hands-on-keyboard activity on the compromised endpoint.

> **Investigative Note:** This finding required careful 
> manual triage of the full process list. Multiple processes 
> were initially investigated before correctly identifying 
> `cmd.exe` as the first purposeful operator action:
> - `msedge.exe` — Incorrect (launched by PowerShell, 
>   not direct operator interaction)
> - `powershell.exe` — Incorrect (launched automatically 
>   as part of session initialisation)
> - `whoami.exe` — Incorrect (occurred later in the 
>   session, after initial operator interaction)
> - `cmd.exe` — ✅ Correct (first direct interactive 
>   command shell opened by the operator)

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| First Notable Process | cmd.exe |
| Account | vmadminusername |
| Parent Process | explorer.exe |
| Timestamp | 12/12/2025 (post 05:47:45 UTC) |
| Session Context | First Uruguay RDP session |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Process | cmd.exe |
| Parent Process | explorer.exe |
| Command Line | cmd.exe |

### 💡 Why it matters
The identification of `cmd.exe` as the first purposeful 
operator action is significant for several reasons:

- **Confirms hands-on-keyboard activity** — The opening 
  of a Command Prompt session is a deliberate human action. 
  Automated tools and scripts do not typically open 
  interactive `cmd.exe` sessions — they invoke commands 
  directly. A `cmd.exe` launched from `explorer.exe` 
  indicates the operator clicked or opened a terminal 
  window manually
- **Establishes the operator's preferred initial toolset** — 
  The choice of `cmd.exe` over `powershell.exe` as the 
  first interactive tool provides a signal about operator 
  preference and familiarity. This can contribute to 
  threat actor profiling and pattern recognition across 
  multiple incidents
- **Marks the boundary between automated and manual activity** — 
  Everything before `cmd.exe` in the process timeline is 
  Windows session initialisation noise. Everything from 
  `cmd.exe` onwards represents deliberate threat actor 
  decisions and actions
- **Anchors the operator activity timeline** — The 
  timestamp of the first `cmd.exe` launch establishes 
  when the threat actor transitioned from passive 
  authenticated presence to active hands-on-keyboard 
  operation — a critical forensic marker for 
  incident timeline reconstruction

### 🔧 KQL Query Used
```kql
// Full process timeline after initial access — 
// used to manually triage session startup noise
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

```kql
// Focused query — known operator tools only
// Used to filter out session startup noise
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| where FileName in ("cmd.exe", "powershell.exe", "pwsh.exe", 
                     "wscript.exe", "cscript.exe", "mshta.exe", 
                     "rundll32.exe", "reg.exe", "net.exe", 
                     "whoami.exe", "ipconfig.exe", "tasklist.exe", 
                     "nltest.exe", "msedge.exe", "notepad.exe")
| project TimeGenerated, FileName, ProcessCommandLine, 
          InitiatingProcessFileName
| order by TimeGenerated asc
```

```kql
// Narrow window query — isolating first operator 
// interaction period on 12/12/2025
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-12T13:32:00Z) 
                            .. datetime(2025-12-12T14:00:00Z))
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, 
          InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
cmd.exe as the first purposeful operator process launched 
from explorer.exe after the initial RDP session startup 
noise on 12/12/2025>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on interactive `cmd.exe` or `powershell.exe` 
  processes spawned from `explorer.exe` under accounts 
  that recently authenticated via RDP from public IPs** — 
  this combination is a high-fidelity indicator of 
  hands-on-keyboard threat actor activity:

```kql
// Alert — interactive command shell after external RDP logon
let RDPSessions =
    DeviceLogonEvents
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | where RemoteIPType == "Public"
    | project LogonTime = TimeGenerated, 
              DeviceName, AccountName, RemoteIP;
DeviceProcessEvents
| where FileName in ("cmd.exe", "powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName =~ "explorer.exe"
| join kind=inner RDPSessions on DeviceName, AccountName
| where TimeGenerated between (LogonTime .. (LogonTime + 30m))
| project TimeGenerated, DeviceName, AccountName, 
          FileName, ProcessCommandLine, RemoteIP
```

- **Establish a process baseline for session startup** — 
  document all processes that legitimately run during 
  Windows RDP session initialisation so that any 
  deviation (particularly interactive shells) is 
  immediately flagged
- **Monitor for `cmd.exe` and `powershell.exe` 
  spawned from `explorer.exe`** as a general 
  detection rule — while not exclusively malicious, 
  this pattern in the context of an external RDP 
  session from an unexpected country is a critical 
  indicator requiring immediate investigation

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

### 🎯 Objective
Identify which text file opened during the threat actor's session 
on `azwks-phtg-02` contained internal security-relevant content 
that would provide meaningful intelligence to an attacker — 
reducing their effort for further exploitation, lateral movement, 
or privilege escalation within the PHTG environment.

### 📌 Finding
**Answer: `notes_sarah.txt`**

During the threat actor's interactive session, multiple text 
files were opened via `notepad.exe`. The file 
**`notes_sarah.txt`** — located at 
`C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt` — 
contained internal security-relevant content attributed to 
Sarah Chen, the Cloud Engineer whose LinkedIn post triggered 
this entire investigation. An attacker reviewing this file 
would gain direct insider knowledge of PHTG's infrastructure, 
credentials, or operational details — significantly reducing 
the effort required for further exploitation.

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Security-Relevant File | notes_sarah.txt |
| Full Path | C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt |
| Opened By | notepad.exe |
| Account | vmadminusername |
| File Author Context | Sarah Chen — Cloud Engineer, PHTG |
| Significance | Internal notes containing security-relevant content |
| Investigation Window | 09 December – 23 December 2025 UTC |
| Process | notepad.exe |
| Parent Process | cmd.exe / explorer.exe |
| Command Line | notepad.exe notes_sarah.txt |

### 💡 Why it matters
The discovery and review of `notes_sarah.txt` by the threat 
actor is one of the most operationally significant findings 
in this investigation:

- **Sarah Chen is the source of the initial exposure** — 
  The LinkedIn post that triggered this investigation 
  was made by Sarah Chen, a Cloud Engineer at PHTG. 
  The existence of a file bearing her name on the 
  compromised VM — containing internal notes — creates 
  a direct link between the OSINT phase and the 
  post-exploitation phase
- **Internal notes represent high-value intelligence** — 
  Engineer notes typically contain infrastructure 
  details, credentials, configuration snippets, 
  access procedures, or operational context that 
  would not be available through external reconnaissance. 
  An attacker reviewing these notes gains the 
  equivalent of insider knowledge
- **The file's existence on a shared VM is itself 
  an OPSEC failure** — Sensitive operational notes 
  should never be stored in plaintext on a VM 
  accessible via public-facing RDP. The presence 
  of this file on `azwks-phtg-02` represents a 
  secondary OPSEC failure compounding the initial 
  LinkedIn post exposure
- **The attacker's decision to open this file 
  indicates deliberate intelligence gathering** — 
  Opening `notes_sarah.txt` was not accidental. 
  The threat actor was actively searching for 
  and reviewing internal documentation to 
  accelerate their objectives — consistent with 
  the discovery and collection phases of the 
  ATT&CK framework
- **This file may have enabled lateral movement** — 
  If `notes_sarah.txt` contained credentials, 
  system access procedures, or network details, 
  the attacker would have gained everything 
  needed to move laterally within the PHTG 
  environment beyond `azwks-phtg-02`

### 🔧 KQL Query Used
```kql
// Identify text files opened during threat actor sessions
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| where FileName == "notepad.exe"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

```kql
// Cross-reference with FileEvents to identify 
// files accessed during the session
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| where FileName endswith ".txt"
| project TimeGenerated, FileName, FolderPath, 
          ActionType, InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
notepad.exe opening notes_sarah.txt during the threat actor 
session, with full path 
C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Never store sensitive notes, credentials, or 
  operational documentation in plaintext files on 
  shared or internet-facing infrastructure** — use 
  a secrets management solution (Azure Key Vault, 
  HashiCorp Vault) for credentials and a secure 
  document management system for operational notes
- **Alert on access to sensitive file paths during 
  externally-sourced RDP sessions**:

```kql
// Alert — sensitive file access during external RDP session
let RDPSessions =
    DeviceLogonEvents
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | where RemoteIPType == "Public"
    | project LogonTime = TimeGenerated,
              DeviceName, AccountName;
DeviceProcessEvents
| where FileName == "notepad.exe"
| where ProcessCommandLine contains "Documents"
| join kind=inner RDPSessions on DeviceName, AccountName
| where TimeGenerated > LogonTime
| project TimeGenerated, DeviceName, AccountName,
          ProcessCommandLine
```

- **Implement Data Loss Prevention (DLP) policies** 
  to detect and alert on access to files containing 
  sensitive keywords (passwords, credentials, keys, 
  secrets) on endpoint devices
- **Conduct a sensitive data discovery sweep** across 
  all PHTG endpoints to identify other plaintext 
  files containing credentials, infrastructure 
  details, or operational notes that could be 
  accessed by a threat actor with local 
  administrator privileges
- **Apply file access auditing** to sensitive 
  directories — enable Windows auditing on 
  `C:\Users\*\Documents\PHTG\` to log and 
  alert on any file access events from 
  unexpected accounts or processes
</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

### 🎯 Objective
Track the payload file through its rename chain in 
`DeviceFileEvents` to identify the first filename where the 
file extension was changed to a Windows executable format — 
marking the moment the payload transitioned from a disguised, 
inert file into an executable that could be launched on the 
compromised endpoint.

### 📌 Finding
**Answer: `Sarah_Chen_Notes.exe`**

The first `FileRenamed` event where the payload's extension 
was changed to a Windows executable format resulted in the 
filename **`Sarah_Chen_Notes.exe`**. The file arrived on the 
system disguised with a `.Txt` extension 
(`Sarah_Chen_Notes.exe.Txt`) and was renamed to 
`Sarah_Chen_Notes.exe` at **12/12/2025 14:18:38 UTC** — 
converting it from an apparently benign text file into a 
directly executable Windows binary.

**Rename Chain:**
```
Sarah_Chen_Notes.exe.Txt          ← Arrived disguised as text
         ↓  [FileRenamed 12/12/2025 14:18:38]
Sarah_Chen_Notes.exe              ← First executable extension ✅
         ↓  [FileRenamed 12/13/2025 10:14:41 — moved]
Sarah_Chen_Notes.exe              ← Relocated to HealthCloud directory
         ↓  [FileRenamed 12/13/2025 10:16:22]
PHTG.exe                          ← Final filename (blends with service)
```

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| First Executable Filename | Sarah_Chen_Notes.exe |
| Previous Filename | Sarah_Chen_Notes.exe.Txt |
| Rename Timestamp | 12/12/2025 14:18:38 UTC |
| Initial Location | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Final Location | C:\ProgramData\PHTG\HealthCloud\ |
| Final Filename | PHTG.exe |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Account | vmadminusername |
| Process | cmd.exe / explorer.exe |
| Parent Process | explorer.exe |
| Command Line | N/A — File operation |

### 💡 Why it matters
The rename from `Sarah_Chen_Notes.exe.Txt` to 
`Sarah_Chen_Notes.exe` is the critical activation event 
for the payload:

- **Double extension as a delivery technique** — 
  `Sarah_Chen_Notes.exe.Txt` is a classic double 
  extension lure. Windows hides known file extensions 
  by default, meaning the file would appear as 
  `Sarah_Chen_Notes.exe` to a user with default 
  Explorer settings — disguising a `.Txt` file as 
  an executable to any casual observer while 
  preventing immediate execution until renamed
- **The rename is a deliberate attacker action** — 
  The transition from `.Txt` to `.exe` was performed 
  by the threat actor during their interactive 
  session. This is not an automated system action — 
  it represents a conscious decision to activate 
  the payload
- **Social engineering via filename** — 
  `Sarah_Chen_Notes.exe` is a deliberate reference 
  to Sarah Chen, the Cloud Engineer whose LinkedIn 
  post triggered this investigation. The attacker 
  used her identity as a filename lure — suggesting 
  they conducted additional research into her role 
  after seeing the post and crafted a payload 
  filename designed to appear legitimate to anyone 
  reviewing the file system
- **The SHA256 is consistent across all renames** — 
  The hash `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` 
  is identical across all three rename events, 
  confirming it is the same file throughout — 
  only the name and location changed, not the content
- **Defender detected it immediately** — Within 
  seconds of the rename to `Sarah_Chen_Notes.exe`, 
  Microsoft Defender flagged the file as 
  `Trojan:Win32/Meterpreter.RPZ!MTB` — but was 
  running in passive mode and did not block it

### 🔧 KQL Query Used
```kql
// FileRenamed events for payload — 
// filtering for executable extensions
// Excluding system noise (SoftwareDistribution, WinSxS)
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where FolderPath !contains "SoftwareDistribution"
| where FolderPath !contains "Windows\\WinSxS"
| where FileName endswith ".exe" 
    or FileName endswith ".dll" 
    or FileName endswith ".bat" 
    or FileName endswith ".ps1" 
    or FileName endswith ".cmd"
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, FileName, PreviousFileName, 
          FolderPath, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results — Payload Rename Chain:**
| TimeGenerated | FileName | PreviousFileName | FolderPath |
|---------------|----------|-----------------|------------|
| 12/12/2025 14:18:38 | Sarah_Chen_Notes.exe | Sarah_Chen_Notes.exe.Txt | C:\Users\vmAdminUsername\Documents\PHTG\ |
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | Sarah_Chen_Notes.exe | C:\ProgramData\PHTG\HealthCloud\ |
| 12/13/2025 10:16:22 | PHTG.exe | Sarah_Chen_Notes.exe | C:\ProgramData\PHTG\HealthCloud\ |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the FileRenamed events for the payload, with 
Sarah_Chen_Notes.exe as the first executable-extension 
filename in the rename chain>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on FileRenamed events where the new extension 
  is executable** — particularly when the previous 
  extension was non-executable and the rename occurs 
  in user-writable directories:

```kql
// Alert — file renamed to executable extension
DeviceFileEvents
| where ActionType == "FileRenamed"
| where FileName endswith ".exe" 
    or FileName endswith ".dll"
    or FileName endswith ".bat"
    or FileName endswith ".ps1"
| where PreviousFileName !endswith ".exe"
    and PreviousFileName !endswith ".dll"
    and PreviousFileName !endswith ".bat"
    and PreviousFileName !endswith ".ps1"
| where FolderPath !contains "Windows"
| where FolderPath !contains "Program Files"
| project TimeGenerated, DeviceName, FileName, 
          PreviousFileName, FolderPath,
          InitiatingProcessAccountName
```

- **Alert on double extension filenames** — files 
  with patterns like `*.exe.txt`, `*.exe.pdf`, 
  `*.exe.doc` should trigger an immediate 
  investigation:

```kql
// Alert — double extension file detection
DeviceFileEvents
| where FileName matches regex @"\.exe\.(txt|pdf|doc|docx|jpg|png)$"
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, InitiatingProcessAccountName
```

- **Enable Windows Explorer to show file extensions** 
  via Group Policy across all PHTG endpoints — this 
  eliminates the visual deception of double extension 
  attacks for end users
- **Switch Microsoft Defender from passive mode to 
  active mode** — Defender detected this payload 
  within seconds of the rename event but failed 
  to block it due to passive mode operation. 
  Active mode would have quarantined the file 
  before it could be executed
</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: <Technique Name></strong></summary>

### 🎯 Objective
Identify the intermediate filename used during the payload's 
delivery chain — the filename that existed between the file's 
initial arrival on the system and its activation as a Windows 
executable. This double extension filename represents the 
attacker's primary delivery obfuscation technique, designed 
to disguise an executable payload as a benign text file.

### 📌 Finding
**Answer: `Sarah_Chen_Notes.exe.Txt`**

The payload arrived on `azwks-phtg-02` with the double 
extension filename **`Sarah_Chen_Notes.exe.Txt`** — a 
deliberate masquerading technique that exploits Windows' 
default behaviour of hiding known file extensions. With 
default Explorer settings, this file would appear to any 
casual observer as `Sarah_Chen_Notes.exe` — apparently 
an executable — while actually being treated by the OS 
as a `.Txt` file, preventing immediate execution.

**Full Delivery Chain:**
```
[DELIVERY]
Sarah_Chen_Notes.exe.Txt    ← Arrived with double extension
        ↓                      (disguised — cannot execute)
[ACTIVATION — 12/12/2025 14:18:38 UTC]
Sarah_Chen_Notes.exe        ← Renamed to true executable ✅
        ↓
[RELOCATION — 12/13/2025 10:14:41 UTC]
Sarah_Chen_Notes.exe        ← Moved to HealthCloud directory
        ↓
[FINAL RENAME — 12/13/2025 10:16:22 UTC]
PHTG.exe                    ← Blends with legitimate service
```

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Double Extension Filename | Sarah_Chen_Notes.exe.Txt |
| True File Type | Windows PE Executable (Meterpreter) |
| Apparent File Type | Text file (.Txt) |
| Delivery Location | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Renamed To | Sarah_Chen_Notes.exe |
| Rename Timestamp | 12/12/2025 14:18:38 UTC |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Account | vmadminusername |
| Timestamp | 12/12/2025 (pre 14:18:38 UTC) |
| Process | N/A — File delivery phase |
| Parent Process | N/A — File delivery phase |
| Command Line | N/A — File delivery phase |

### 💡 Why it matters
The double extension filename `Sarah_Chen_Notes.exe.Txt` 
is a sophisticated delivery technique with multiple 
operational benefits for the attacker:

- **Exploits Windows default extension hiding** — 
  Windows hides known file extensions by default. 
  A user viewing this file in Explorer with default 
  settings would see `Sarah_Chen_Notes.exe` — 
  making the `.Txt` outer extension invisible and 
  creating a false impression the file is already 
  an executable, or alternatively just a text file 
  depending on icon association
- **Prevents premature execution** — While disguised 
  as `.Txt`, the file cannot be accidentally double-clicked 
  and executed. The attacker maintains control over 
  exactly when the payload activates by performing 
  the rename themselves during their interactive session
- **May bypass extension-based AV scanning** — Some 
  security tools and email filters scan files based 
  on their declared extension. A file ending in `.Txt` 
  may receive less scrutiny than one ending in `.exe`, 
  potentially allowing the payload to reach the 
  filesystem undetected
- **Social engineering via filename** — The reference 
  to Sarah Chen in the filename is deliberate. If 
  any PHTG administrator reviewed the file system, 
  a file named `Sarah_Chen_Notes.exe.Txt` in a 
  PHTG documents folder might appear to be a 
  legitimate note file left by a colleague
- **The SHA256 proves content integrity throughout** — 
  The hash `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` 
  is consistent from delivery through all rename 
  events — confirming the double extension was 
  purely a naming technique and the binary content 
  of the Meterpreter payload was never modified

### 🔧 KQL Query Used
```kql
// Track payload through FileRenamed events to identify 
// the double extension filename
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
    or FileName contains "Sarah_Chen_Notes"
    or PreviousFileName contains "Sarah_Chen_Notes"
| project TimeGenerated, FileName, PreviousFileName, 
          FolderPath, SHA256, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results — Full Rename Chain:**
| TimeGenerated | FileName | PreviousFileName |
|---------------|----------|-----------------|
| 12/12/2025 14:18:38 | Sarah_Chen_Notes.exe | **Sarah_Chen_Notes.exe.Txt** |
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | Sarah_Chen_Notes.exe |
| 12/13/2025 10:16:22 | PHTG.exe | Sarah_Chen_Notes.exe |

> The double extension filename `Sarah_Chen_Notes.exe.Txt` 
> is captured in the `PreviousFileName` field of the first 
> `FileRenamed` event — confirming it was the filename 
> used immediately before the payload was activated as 
> a Windows executable.

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the FileRenamed event with PreviousFileName of 
Sarah_Chen_Notes.exe.Txt being renamed to 
Sarah_Chen_Notes.exe at 12/12/2025 14:18:38 UTC>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on files with double extensions matching 
  the pattern `*.exe.*` or `*.dll.*`** across all 
  endpoint file systems:

```kql
// Alert — double extension file detection
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"\.(exe|dll|bat|ps1|cmd)\.(txt|pdf|doc|docx|jpg|png|zip)$"
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, InitiatingProcessAccountName,
          ActionType
```

- **Enforce Group Policy to show all file extensions** — 
  disable the Windows default of hiding known file 
  extensions across all PHTG endpoints. This eliminates 
  the visual deception component of double extension 
  attacks:
  - GPO Path: `User Configuration → Administrative 
    Templates → Windows Components → File Explorer`
  - Setting: `Hide extensions for known file types` 
    → **Disabled**

- **Alert on files delivered via RDP clipboard or 
  file transfer that contain executable headers 
  but non-executable extensions** — content 
  inspection (magic bytes analysis) rather than 
  extension-based classification would have 
  detected this payload as a PE executable 
  regardless of its `.Txt` extension

- **Switch Defender from passive to active mode** — 
  the payload was detected within seconds of the 
  rename event. Active mode would have quarantined 
  `Sarah_Chen_Notes.exe` before it could be 
  executed, breaking the attack chain at this 
  critical stage

- **Monitor `PreviousFileName` in FileRenamed 
  events** — the double extension is preserved 
  in `PreviousFileName` after the rename, making 
  it detectable in retrospective telemetry even 
  if the file is no longer present on the system
</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: <Technique Name></strong></summary>

### 🎯 Objective
Identify the SHA256 hash of the payload file to establish a 
definitive, immutable identifier that persists across all 
rename events, directory relocations, and filename changes — 
confirming it is the same binary throughout the entire 
delivery and execution chain, and enabling threat intelligence 
correlation independent of filename.

### 📌 Finding
**Answer: `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`**

The SHA256 hash of the payload file is consistent across 
all three `FileRenamed` events — confirming that 
`Sarah_Chen_Notes.exe.Txt`, `Sarah_Chen_Notes.exe`, and 
`PHTG.exe` are all the same binary. The filename changed 
three times; the hash never changed once.

| Timestamp | FileName | SHA256 |
|-----------|----------|--------|
| 12/12/2025 14:18:38 | Sarah_Chen_Notes.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| 12/13/2025 10:16:22 | PHTG.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Filename 1 | Sarah_Chen_Notes.exe.Txt (delivery) |
| Filename 2 | Sarah_Chen_Notes.exe (activation) |
| Filename 3 | PHTG.exe (persistence) |
| Initial Location | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Final Location | C:\ProgramData\PHTG\HealthCloud\ |
| First Seen | 12/12/2025 14:18:38 UTC |
| Defender Detection | Trojan:Win32/Meterpreter.RPZ!MTB |
| Defender Mode | Passive (detected but did not block) |
| Account | vmadminusername |
| Timestamp | 12/12/2025 – 12/13/2025 |
| Process | N/A — File telemetry |
| Parent Process | N/A — File telemetry |
| Command Line | N/A — File telemetry |

### 💡 Why it matters
The SHA256 hash is the most reliable identifier in this 
investigation for several critical reasons:

- **Hashes are immutable — filenames are not** — The 
  threat actor changed the filename three times across 
  two days to evade detection and blend the payload 
  into legitimate infrastructure. The SHA256 remained 
  constant throughout, providing an unchangeable 
  anchor for investigation and attribution
- **Enables cross-platform threat intelligence 
  correlation** — The hash can be used to:
  - Search internal telemetry across the entire 
    PHTG estate for other devices that may have 
    encountered this payload
  - Query threat intelligence platforms for 
    prior sightings, campaign attribution, and 
    additional IOCs associated with this sample
  - Submit to internal sandboxing environments 
    for behavioural analysis
- **Confirms single payload hypothesis** — The 
  consistent SHA256 across all three rename events 
  definitively confirms that `Sarah_Chen_Notes.exe.Txt`, 
  `Sarah_Chen_Notes.exe`, and `PHTG.exe` are the 
  same Meterpreter binary. This eliminates any 
  possibility that the threat actor introduced 
  a different payload at any stage of the chain
- **Enables proactive hunting across the estate** — 
  The hash can immediately be used to hunt for 
  this specific Meterpreter sample on any other 
  PHTG endpoint, identifying lateral movement 
  or additional deployments of the same payload
- **Provides a permanent IOC for blocklisting** — 
  Unlike IPs and domain names, which can change, 
  a SHA256 hash is a permanent, exact identifier 
  that can be added to EDR blocklists to prevent 
  future execution of this exact binary

### 🔧 KQL Query Used
```kql
// Retrieve SHA256 across all payload rename events
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FileName in ("Sarah_Chen_Notes.exe", "PHTG.exe")
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where SHA256 != ""
| project TimeGenerated, FileName, SHA256, 
          FolderPath, ActionType
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | SHA256 | ActionType |
|---------------|----------|--------|------------|
| 12/12/2025 14:18:38 | Sarah_Chen_Notes.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | FileRenamed |
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | FileRenamed |
| 12/13/2025 10:16:22 | PHTG.exe | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | FileRenamed |

```kql
// Hunt for this hash across the entire PHTG estate
// to identify lateral movement or additional deployments
DeviceFileEvents
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by DeviceName, FileName, FolderPath
| order by count_ desc
```

```kql
// Cross-reference hash with process execution events
DeviceProcessEvents
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, DeviceName, FileName, 
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the consistent SHA256 hash 
224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 
across all three FileRenamed events for the payload>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Add the SHA256 to your EDR blocklist immediately** — 
  this prevents future execution of this exact binary 
  on any PHTG endpoint:

```kql
// Verify no other devices have encountered this hash
DeviceFileEvents
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    FileNames = make_set(FileName),
    Locations = make_set(FolderPath)
    by DeviceName
```

- **Create a SHA256-based custom detection rule** in 
  Microsoft Defender for Endpoint to alert on any 
  future file creation or process execution 
  matching this hash:

```kql
// Alert — known malicious hash detected
DeviceFileEvents
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, ActionType,
          InitiatingProcessAccountName
```

- **Prioritise hash-based detection over filename-based 
  detection** — this investigation demonstrates that 
  a single payload can cycle through multiple filenames 
  (`Sarah_Chen_Notes.exe.Txt` → `Sarah_Chen_Notes.exe` 
  → `PHTG.exe`) while maintaining an identical SHA256. 
  Hash-based detection is immune to these renaming 
  techniques
- **Submit the hash to internal sandboxing** for 
  full behavioural analysis — confirm C2 configuration, 
  persistence mechanisms, and any additional 
  capabilities beyond the Meterpreter baseline 
  observed in this investigation

</details>

---

<details>
<summary id="-flag-29">🚩 <strong>Flag 29: <Technique Name></strong></summary>

### 🎯 Objective
Track the payload file forward through all `FileRenamed` events 
using its SHA256 hash to identify the final filename assigned 
to the binary — revealing the threat actor's ultimate naming 
strategy for the payload and confirming how it was positioned 
for persistence within the PHTG environment.

### 📌 Finding
**Answer: `PHTG.exe`**

The final observed filename tied to SHA256 
`224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` 
is **`PHTG.exe`** — renamed at **12/13/2025 10:16:22 UTC** 
and located in `C:\ProgramData\PHTG\HealthCloud\`. The threat 
actor deliberately chose this filename to blend the Meterpreter 
payload with PHTG's legitimate HealthCloud service — a 
calculated masquerading technique designed to make the 
malicious binary appear as a legitimate component of the 
recently deployed internal service.

**Complete Rename Chain:**
```
Sarah_Chen_Notes.exe.Txt          ← Delivery (double extension)
         ↓  [12/12/2025 14:18:38 UTC]
Sarah_Chen_Notes.exe              ← Activation (executable)
         ↓  [12/13/2025 10:14:41 UTC]
Sarah_Chen_Notes.exe              ← Relocated to HealthCloud
         ↓  [12/13/2025 10:16:22 UTC]
PHTG.exe                          ← FINAL NAME ✅ (blends with service)
```

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Final Filename | PHTG.exe |
| Previous Filename | Sarah_Chen_Notes.exe |
| Final Rename Timestamp | 12/13/2025 10:16:22 UTC |
| Final Location | C:\ProgramData\PHTG\HealthCloud\ |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Masquerading Target | PHTG HealthCloud legitimate service |
| Account | vmadminusername |
| Timestamp | 12/13/2025 10:16:22 UTC |
| Process | N/A — File rename operation |
| Parent Process | N/A — File rename operation |
| Command Line | N/A — File rename operation |

### 💡 Why it matters
The final rename to `PHTG.exe` within the HealthCloud 
directory is one of the most strategically significant 
actions taken by the threat actor:

- **Deliberate masquerading as a legitimate service** — 
  Renaming the payload to `PHTG.exe` and placing it 
  in `C:\ProgramData\PHTG\HealthCloud\` was a 
  calculated decision. HealthCloud was deployed 
  just two days earlier (11 December 2025) and 
  was already generating legitimate process 
  activity, scheduled tasks, and diagnostic 
  files in that directory. The Meterpreter 
  payload was designed to hide within this 
  known-good footprint
- **The attacker weaponised PHTG's own 
  infrastructure against itself** — By 
  using the company's own abbreviation as 
  the executable name and placing it in 
  the company's own service directory, 
  the threat actor made the payload 
  extremely difficult to identify through 
  casual file system review or alert triage
- **Name and location together create a 
  convincing disguise** — `PHTG.exe` in 
  `C:\ProgramData\PHTG\HealthCloud\` would 
  appear entirely legitimate to any analyst 
  unfamiliar with the exact expected 
  HealthCloud file inventory. Only a 
  hash-based comparison or a precise 
  file inventory baseline would reveal 
  the payload
- **The rename sequence tells the full 
  operational story:**
  1. Payload delivered disguised as text
  2. Activated by renaming to `.exe`
  3. Relocated to persistence-friendly directory
  4. Renamed to blend with legitimate service
  5. Launched via `Launch.bat` for persistent 
     re-execution

### 🔧 KQL Query Used
```kql
// Track payload forward through all rename events 
// using SHA256 as the immutable identifier
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where ActionType == "FileRenamed"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, PreviousFileName, 
          FolderPath, SHA256, ActionType
| order by TimeGenerated asc
```

**Results — Complete Rename Chain:**
| TimeGenerated | FileName | PreviousFileName | FolderPath |
|---------------|----------|-----------------|------------|
| 12/12/2025 14:18:38 | Sarah_Chen_Notes.exe | Sarah_Chen_Notes.exe.Txt | C:\Users\vmAdminUsername\Documents\PHTG\ |
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | Sarah_Chen_Notes.exe | C:\ProgramData\PHTG\HealthCloud\ |
| 12/13/2025 10:16:22 | **PHTG.exe** | Sarah_Chen_Notes.exe | C:\ProgramData\PHTG\HealthCloud\ |

```kql
// Confirm final filename — take the last rename event
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where ActionType == "FileRenamed"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| order by TimeGenerated desc
| take 1
| project TimeGenerated, FileName, FolderPath, SHA256
```

**Result:**
| TimeGenerated | FileName | FolderPath |
|---------------|----------|------------|
| 12/13/2025 10:16:22 | PHTG.exe | C:\ProgramData\PHTG\HealthCloud\ |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the complete rename chain with PHTG.exe as the final filename 
at C:\ProgramData\PHTG\HealthCloud\ on 12/13/2025 10:16:22 UTC>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Establish a file inventory baseline for all 
  legitimate service directories** — particularly 
  newly deployed services like HealthCloud. Any 
  executable appearing in a service directory 
  that is not part of the expected installation 
  manifest should trigger an immediate alert:

```kql
// Alert — unexpected executable in HealthCloud directory
DeviceFileEvents
| where FolderPath contains "HealthCloud"
| where FileName endswith ".exe" 
    or FileName endswith ".dll"
    or FileName endswith ".bat"
    or FileName endswith ".ps1"
| where ActionType in ("FileCreated", "FileRenamed")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, SHA256,
          InitiatingProcessAccountName
```

- **Hunt for any executable in `C:\ProgramData` 
  not associated with a known software installation** — 
  `ProgramData` is a common persistence location 
  for threat actors precisely because it blends 
  with legitimate software:

```kql
// Hunt — executables created in ProgramData 
// by non-system accounts
DeviceFileEvents
| where FolderPath startswith "C:\\ProgramData"
| where FileName endswith ".exe"
| where ActionType in ("FileCreated", "FileRenamed")
| where InitiatingProcessAccountName !in 
    ("system", "local service", "network service")
| where TimeGenerated between 
    (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, SHA256, 
          InitiatingProcessAccountName
```

- **Implement application allowlisting** for all 
  service directories — only explicitly approved 
  executables should be permitted to run from 
  `C:\ProgramData\PHTG\HealthCloud\`. Any 
  unlisted binary attempting execution should 
  be blocked and alerted immediately
- **Use SHA256-based file integrity monitoring** 
  on service directories — compare the hash of 
  every executable in `C:\ProgramData\PHTG\` 
  against a known-good baseline to detect 
  any unauthorised additions or modifications

</details>

---

<details>
<summary id="-flag-30">🚩 <strong>Flag 30: <Technique Name></strong></summary>

### 🎯 Objective
Identify the malware family classification assigned to the 
payload by Microsoft Defender's detection engine as recorded 
in MDE telemetry on `azwks-phtg-02` — establishing the 
threat category, capability set, and framework association 
of the tool used by the threat actor in this intrusion.

### 📌 Finding
**Answer: `Meterpreter`**

Microsoft Defender classified the payload under the malware 
family **`Meterpreter`**, with the full threat name 
`Trojan:Win32/Meterpreter.RPZ!MTB`. This is a Metasploit 
Framework post-exploitation payload — one of the most 
widely used offensive security tools in both red team 
engagements and real-world threat actor campaigns.

Defender detected the payload **three times** between 
14:18 and 14:22 on 12 December 2025 — but was running 
in **passive mode**, meaning it logged the detections 
without blocking or quarantining the file.

| Detection | Timestamp | ThreatName | ReportSource |
|-----------|-----------|------------|--------------|
| 1 | 12/12/2025 14:18:52 UTC | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |
| 2 | 12/12/2025 14:20:41 UTC | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |
| 3 | 12/12/2025 14:22:12 UTC | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Malware Family | Meterpreter |
| Full Threat Name | Trojan:Win32/Meterpreter.RPZ!MTB |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Detection Count | 3 |
| Detection Window | 12/12/2025 14:18:52 – 14:22:12 UTC |
| Defender Mode | Passive (detected, did not block) |
| Report Source | Windows Defender Antivirus passive mode |
| ActionType | AntivirusDetectionActionType |
| Timestamp | 12/12/2025 14:18:52 UTC (first detection) |
| Process | N/A — Antivirus detection event |
| Parent Process | N/A — Antivirus detection event |
| Command Line | N/A — Antivirus detection event |

### 💡 Why it matters
The Meterpreter classification and passive mode context 
are both critically significant findings:

**Meterpreter as a malware family:**
- **Metasploit Framework payload** — Meterpreter is the 
  primary post-exploitation payload of the Metasploit 
  Framework, providing attackers with an interactive 
  shell, file system access, network pivoting, 
  credential harvesting, and a broad library of 
  post-exploitation modules
- **In-memory execution capability** — Meterpreter 
  is designed to run entirely in memory, leaving 
  minimal forensic artifacts on disk. The fact that 
  it was detected on disk (via the renamed `.exe`) 
  suggests the threat actor was using a staged or 
  stageless payload rather than a purely fileless 
  deployment
- **C2 over port 4444** — The subsequent 
  `DeviceNetworkEvents` telemetry confirmed 
  C2 callback attempts to `173.244.55.130:4444` — 
  the default Metasploit listener port — consistent 
  with an out-of-the-box Meterpreter configuration
- **Commodity tooling** — The use of Meterpreter 
  rather than custom malware suggests a threat 
  actor operating at the lower end of the 
  sophistication spectrum, relying on widely 
  available offensive tooling. This is consistent 
  with the opportunistic brute force initial 
  access methodology observed earlier in the chain

**Passive mode as a critical defensive gap:**
- **Detected but not blocked** — Defender identified 
  the Meterpreter payload within 14 seconds of the 
  rename event but took no blocking action due to 
  passive mode operation
- **Three detections, zero blocks** — The same 
  payload was detected three times in four minutes 
  with no remediation action taken
- **Passive mode is a deployment configuration** — 
  Defender runs in passive mode when another AV 
  product is designated as the primary protection 
  engine. If no other AV was present, passive 
  mode represents a critical misconfiguration 
  that nullified Defender's detection capability
- **This single misconfiguration enabled the 
  entire post-exploitation chain** — Active 
  mode would have quarantined the payload 
  before first execution, preventing all 
  subsequent Meterpreter activity

### 🔧 KQL Query Used
```kql
// Query MDE DeviceEvents for Defender antivirus 
// detections against the payload SHA256
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType in ("AntivirusDetection", 
                       "AntivirusDetectionActionType")
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, ActionType, SHA256, AdditionalFields
```

**Results:**
| TimeGenerated | ActionType | AdditionalFields |
|---------------|------------|-----------------|
| 12/12/2025 14:18:52 | AntivirusDetectionActionType | {"ThreatName":"Trojan:Win32/Meterpreter.RPZ!MTB","ReportSource":"Windows Defender Antivirus passive mode"} |
| 12/12/2025 14:20:41 | AntivirusDetectionActionType | {"ThreatName":"Trojan:Win32/Meterpreter.RPZ!MTB","ReportSource":"Windows Defender Antivirus passive mode"} |
| 12/12/2025 14:22:12 | AntivirusDetectionActionType | {"ThreatName":"Trojan:Win32/Meterpreter.RPZ!MTB","ReportSource":"Windows Defender Antivirus passive mode"} |

```kql
// Parse AdditionalFields JSON to extract ThreatName 
// and malware family cleanly
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType in ("AntivirusDetection", 
                       "AntivirusDetectionActionType")
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName = tostring(ParsedFields.ThreatName)
| extend ReportSource = tostring(ParsedFields.ReportSource)
| project TimeGenerated, ActionType, ThreatName, 
          ReportSource, SHA256
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
three AntivirusDetectionActionType events for the payload 
SHA256, with ThreatName Trojan:Win32/Meterpreter.RPZ!MTB 
and ReportSource Windows Defender Antivirus passive mode>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Immediately switch Microsoft Defender from 
  passive mode to active mode** on all PHTG 
  endpoints — passive mode provides zero 
  protection against detected threats:

```kql
// Hunt for other endpoints running Defender 
// in passive mode with antivirus detections
DeviceEvents
| where ActionType == "AntivirusDetectionActionType"
| where TimeGenerated > ago(30d)
| extend ParsedFields = parse_json(AdditionalFields)
| extend ReportSource = tostring(ParsedFields.ReportSource)
| where ReportSource contains "passive mode"
| summarize 
    DetectionCount = count(),
    UniqueThreat = dcount(SHA256),
    Threats = make_set(tostring(ParsedFields.ThreatName))
    by DeviceName, ReportSource
| order by DetectionCount desc
```

- **Alert on any `AntivirusDetectionActionType` event 
  with `ReportSource` containing "passive mode"** — 
  this combination means a threat was detected but 
  not blocked, requiring immediate manual investigation:

```kql
// Alert — AV detection in passive mode (no blocking)
DeviceEvents
| where ActionType == "AntivirusDetectionActionType"
| where TimeGenerated > ago(1h)
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName = tostring(ParsedFields.ThreatName)
| extend ReportSource = tostring(ParsedFields.ReportSource)
| where ReportSource contains "passive"
| project TimeGenerated, DeviceName, ThreatName, 
          ReportSource, SHA256
```

- **Alert on Meterpreter family detections specifically** — 
  Meterpreter is never a false positive in a production 
  environment:

```kql
// Alert — Meterpreter detection (any mode)
DeviceEvents
| where ActionType in ("AntivirusDetection", 
                       "AntivirusDetectionActionType")
| where TimeGenerated > ago(1h)
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName = tostring(ParsedFields.ThreatName)
| where ThreatName contains "Meterpreter"
| project TimeGenerated, DeviceName, ThreatName, SHA256
```

- **Audit Defender configuration across the PHTG 
  estate** — identify all endpoints where Defender 
  is running in passive mode and remediate 
  immediately. Active mode with real-time 
  protection enabled should be the standard 
  configuration on all endpoints without a 
  third-party AV product designated as primary

</details>

---


<details>
<summary id="-flag-31">🚩 <strong>Flag 31: <Technique Name></strong></summary>

### 🎯 Objective
Identify the specific change to Microsoft Defender's operating 
state that occurred between the three quarantine events and the 
subsequent unblocked execution of the Meterpreter payload on 
`azwks-phtg-02` — determining the defensive gap that allowed 
the threat actor to successfully execute the payload despite 
prior detections.

### 📌 Finding
**Answer: `Passive mode`**

Microsoft Defender was switched from **active mode** to 
**passive mode** between the quarantine events and the 
successful execution. The `ReportSource` field in 
`DeviceEvents` telemetry explicitly confirms this — all 
three detection events after the mode change are logged 
with `"ReportSource": "Windows Defender Antivirus passive 
mode"`, meaning Defender detected the payload but 
relinquished blocking responsibility to a designated 
primary AV engine that either did not exist or did not 
act.

**Timeline of Events:**
```
14:11 – 14:17  ← Defender ACTIVE MODE
    Payload detected and quarantined (3x)
    Defender blocks execution successfully

         ↓  [Defender switched to PASSIVE MODE]

14:18:52 UTC   ← Defender PASSIVE MODE
    Payload detected: Trojan:Win32/Meterpreter.RPZ!MTB
    ReportSource: "Windows Defender Antivirus passive mode"
    ACTION: Logged only — NO BLOCK

14:20:41 UTC   ← Defender PASSIVE MODE
    Payload detected again
    ACTION: Logged only — NO BLOCK

14:22:12 UTC   ← Defender PASSIVE MODE
    Payload detected again
    ACTION: Logged only — NO BLOCK

         ↓

Payload executes successfully — Meterpreter active
```

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Defender Mode (Quarantine Phase) | Active mode |
| Defender Mode (Execution Phase) | Passive mode |
| Mode Change Window | Between 14:17 and 14:18 on 12/12/2025 |
| Detection Count in Passive Mode | 3 |
| Blocking Actions in Passive Mode | 0 |
| ThreatName | Trojan:Win32/Meterpreter.RPZ!MTB |
| ReportSource | Windows Defender Antivirus passive mode |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Account | vmadminusername |
| Timestamp | 12/12/2025 14:18:52 – 14:22:12 UTC |
| Process | N/A — Antivirus state change event |
| Parent Process | N/A — Antivirus state change event |
| Command Line | N/A — Antivirus state change event |

### 💡 Why it matters
The transition from active to passive mode is the single 
most critical defensive failure in this investigation:

- **Active mode provides real protection** — When 
  Defender was in active mode, it successfully 
  quarantined the Meterpreter payload three times, 
  preventing execution entirely. This demonstrates 
  that the detection capability was functioning 
  correctly — the failure was in the operating 
  mode, not the detection engine
- **Passive mode is detection without protection** — 
  In passive mode, Defender continues to scan 
  and detect threats but defers all remediation 
  actions to a designated primary AV product. 
  If no other AV is present or functioning, 
  passive mode provides zero protection — 
  it is effectively a threat logging service 
  with no blocking capability
- **The mode change was almost certainly 
  deliberate** — The transition from active 
  to passive mode occurring in the narrow 
  window between quarantine events and 
  successful payload execution is not 
  coincidental. The threat actor, operating 
  interactively via RDP with local 
  administrator privileges, had the access 
  and capability to modify Defender's 
  operating mode through:
  - PowerShell cmdlets (`Set-MpPreference`)
  - Registry modifications
  - Windows Security Center API calls
  - Installation of a dummy AV product 
    that forces Defender to passive mode
- **This represents deliberate defence 
  impairment** — The threat actor identified 
  that Defender was blocking their payload, 
  modified Defender's operating state to 
  remove the blocking capability, and then 
  successfully executed the payload. This 
  is a sophisticated, adaptive response 
  to an active defensive control
- **Three quarantines → mode change → 
  successful execution** tells the full 
  story — the attacker was persistent, 
  noticed the failures, diagnosed the 
  cause, and took targeted action to 
  neutralise the specific control 
  preventing their success

### 🔧 KQL Query Used
```kql
// Query DeviceEvents for Defender detection events
// ReportSource field reveals operating mode at time of detection
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType in ("AntivirusDetection", 
                       "AntivirusDetectionActionType")
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| extend ParsedFields = parse_json(AdditionalFields)
| extend ThreatName = tostring(ParsedFields.ThreatName)
| extend ReportSource = tostring(ParsedFields.ReportSource)
| project TimeGenerated, ActionType, ThreatName, 
          ReportSource, SHA256
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | ThreatName | ReportSource |
|---------------|------------|--------------|
| 12/12/2025 14:18:52 | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |
| 12/12/2025 14:20:41 | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |
| 12/12/2025 14:22:12 | Trojan:Win32/Meterpreter.RPZ!MTB | Windows Defender Antivirus passive mode |

```kql
// Hunt for Defender configuration change events
// around the mode transition window
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between 
    (datetime(2025-12-12T14:10:00Z) .. 
     datetime(2025-12-12T14:25:00Z))
| where ActionType contains "Antivirus" 
    or ActionType contains "Defender"
    or ActionType contains "Security"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc
```

```kql
// Hunt for PowerShell commands that could modify 
// Defender operating mode during the session
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between 
    (datetime(2025-12-12T14:00:00Z) .. 
     datetime(2025-12-12T15:00:00Z))
| where ProcessCommandLine contains "MpPreference"
    or ProcessCommandLine contains "DisableRealtimeMonitoring"
    or ProcessCommandLine contains "PassiveModeEnabled"
    or ProcessCommandLine contains "WindowsDefender"
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessAccountName
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
all three AntivirusDetectionActionType events with 
ReportSource confirming "Windows Defender Antivirus 
passive mode" — demonstrating that Defender detected 
but did not block the payload after the mode change>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert immediately on any Defender mode change 
  on a production endpoint** — switching from 
  active to passive mode should never occur 
  without a formal change management process:

```kql
// Alert — Defender mode change detection
DeviceEvents
| where ActionType contains "AntivirusStateChange"
    or ActionType contains "DefenderConfigChange"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, ActionType, 
          AdditionalFields
```

- **Monitor for PowerShell commands that modify 
  Defender configuration** — `Set-MpPreference` 
  with passive mode parameters should trigger 
  an immediate P1 alert:

```kql
// Alert — PowerShell Defender tampering
DeviceProcessEvents
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "PassiveModeEnabled", 
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "Set-MpPreference",
    "Add-MpPreference")
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, 
          ProcessCommandLine,
          InitiatingProcessAccountName
```

- **Implement Microsoft Defender Tamper Protection** — 
  Tamper Protection prevents unauthorised changes 
  to Defender settings including operating mode, 
  real-time protection, and exclusions. It should 
  be enabled on all PHTG endpoints and enforced 
  via Intune or Group Policy
- **Alert on `AntivirusDetectionActionType` events 
  with passive mode in `ReportSource`** — any 
  detection that Defender logged but did not 
  act on due to passive mode should immediately 
  trigger a manual review:

```kql
// Alert — AV detection without blocking action
DeviceEvents
| where ActionType == "AntivirusDetectionActionType"
| where TimeGenerated > ago(1h)
| extend ParsedFields = parse_json(AdditionalFields)
| extend ReportSource = tostring(ParsedFields.ReportSource)
| extend ThreatName = tostring(ParsedFields.ThreatName)
| where ReportSource contains "passive"
| project TimeGenerated, DeviceName, 
          ThreatName, ReportSource, SHA256
```

- **Enforce Defender active mode via Microsoft 
  Intune compliance policies** — flag any endpoint 
  where Defender is not operating in active mode 
  as non-compliant, triggering automatic 
  remediation and access restrictions until 
  the correct configuration is restored
</details>


---


<details>
<summary id="-flag-32">🚩 <strong>Flag 32: <Technique Name></strong></summary>

### 🎯 Objective
Identify the filename under which the Meterpreter payload 
executed during the first phase of its execution lifecycle 
on `azwks-phtg-02` — distinguishing between the two 
distinct execution phases observed in `DeviceProcessEvents` 
telemetry and confirming how the payload was initially 
launched by the threat actor.

### 📌 Finding
**Answer: `Sarah_Chen_Notes.exe`**

During the first execution phase on **12 December 2025**, 
the Meterpreter payload ran under the filename 
**`Sarah_Chen_Notes.exe`**. The payload was executed 
directly by `explorer.exe` — indicating the threat 
actor double-clicked the file during their interactive 
RDP session. This occurred three times in rapid 
succession, consistent with the three Defender 
passive mode detection events observed between 
14:18 and 14:22 UTC.

**Two-Phase Execution Summary:**

| Phase | Date | Filename | Initiating Process | Method |
|-------|------|----------|-------------------|--------|
| Phase 1 | 12/12/2025 | Sarah_Chen_Notes.exe | explorer.exe | Manual double-click |
| Phase 2 | 12/13/2025 | PHTG.exe | cmd.exe | Launch.bat persistence |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Phase 1 Filename | Sarah_Chen_Notes.exe |
| Phase 1 Location | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Phase 1 Executions | 3 |
| Phase 1 Timestamps | 12/12/2025 14:18:51, 14:20:37, 14:22:11 UTC |
| Initiating Process | explorer.exe |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Account | vmadminusername |
| Timestamp | 12/12/2025 14:18:51 – 14:22:11 UTC |
| Process | Sarah_Chen_Notes.exe |
| Parent Process | explorer.exe |
| Command Line | "Sarah_Chen_Notes.exe" |

### 💡 Why it matters
The identification of `Sarah_Chen_Notes.exe` as the Phase 1 
execution filename reveals critical details about the threat 
actor's operational behaviour and the attack progression:

- **Phase 1 was manual, interactive execution** — All 
  three Phase 1 executions were initiated by `explorer.exe`, 
  which is the signature of a user double-clicking a file 
  in Windows Explorer during an interactive desktop session. 
  This confirms the threat actor was hands-on-keyboard 
  during the initial payload activation
- **Three executions in four minutes indicates 
  persistence through failure** — The C2 callbacks 
  to `173.244.55.130:4444` all failed (as confirmed 
  in `DeviceNetworkEvents`). The threat actor attempted 
  to launch the payload three times, likely because 
  each execution failed to establish a Meterpreter 
  session due to the C2 listener not being ready 
  or network connectivity issues
- **The filename itself is a social engineering 
  artefact** — `Sarah_Chen_Notes.exe` references 
  the Cloud Engineer whose LinkedIn post triggered 
  the investigation. The attacker crafted a filename 
  designed to appear legitimate in the context of 
  the PHTG environment
- **Phase 1 execution triggered immediate Defender 
  detection** — Each execution was detected within 
  seconds as `Trojan:Win32/Meterpreter.RPZ!MTB`, 
  but Defender's passive mode prevented blocking
- **Phase 1 failure drove Phase 2 persistence 
  design** — The failed C2 callbacks in Phase 1 
  led the threat actor to redesign their approach 
  for Phase 2 — renaming the payload to `PHTG.exe`, 
  relocating it to the HealthCloud directory, and 
  creating `Launch.bat` for automated re-execution 
  rather than relying on manual double-clicking

### 🔧 KQL Query Used
```kql
// Process execution events for the payload
// Using SHA256 as the immutable identifier
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
    or FileName in ("Sarah_Chen_Notes.exe", "PHTG.exe")
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, 
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results — Both Execution Phases:**
| TimeGenerated | FileName | InitiatingProcessFileName | InitiatingProcessCommandLine |
|---------------|----------|--------------------------|------------------------------|
| 12/12/2025 14:18:51 | **Sarah_Chen_Notes.exe** | explorer.exe | Explorer.EXE |
| 12/12/2025 14:20:37 | **Sarah_Chen_Notes.exe** | explorer.exe | Explorer.EXE |
| 12/12/2025 14:22:11 | **Sarah_Chen_Notes.exe** | explorer.exe | Explorer.EXE |
| 12/13/2025 10:13:18 | **Sarah_Chen_Notes.exe** | explorer.exe | Explorer.EXE |
| 12/13/2025 10:21:48 | PHTG.exe | cmd.exe | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |
| 12/13/2025 10:22:36 | PHTG.exe | cmd.exe | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
Sarah_Chen_Notes.exe executed by explorer.exe on 12/12/2025 
across three execution attempts, compared to PHTG.exe 
launched by cmd.exe via Launch.bat on 12/13/2025>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on executable files launched from 
  user document directories by `explorer.exe`** — 
  legitimate applications are rarely launched 
  directly from `Documents` folders:

```kql
// Alert — executable launched from user documents
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName endswith ".exe"
| where FolderPath contains "\\Documents\\"
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          ProcessCommandLine, FolderPath,
          InitiatingProcessAccountName
```

- **Alert on rapid successive executions of the 
  same filename** — three executions of the same 
  binary within four minutes is anomalous and 
  may indicate C2 establishment failures:

```kql
// Alert — rapid repeated execution of same binary
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| summarize 
    ExecutionCount = count(),
    FirstExec = min(TimeGenerated),
    LastExec = max(TimeGenerated)
    by DeviceName, FileName, SHA256
| where ExecutionCount >= 3
| extend WindowMinutes = datetime_diff(
    'minute', LastExec, FirstExec)
| where WindowMinutes <= 10
| project DeviceName, FileName, SHA256, 
          ExecutionCount, WindowMinutes,
          FirstExec, LastExec
```

- **Correlate failed C2 callbacks with repeated 
  payload executions** — if `DeviceNetworkEvents` 
  shows repeated `ConnectionFailed` events from 
  the same process SHA256 coinciding with multiple 
  process executions in `DeviceProcessEvents`, 
  this is a high-fidelity indicator of an attacker 
  attempting to establish a C2 session:

```kql
// Correlation — failed C2 callbacks and payload 
// execution attempts
let PayloadExecs = DeviceProcessEvents
    | where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
    | project ExecTime = TimeGenerated, 
              DeviceName, FileName;
let FailedC2 = DeviceNetworkEvents
    | where InitiatingProcessSHA256 == 
        "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
    | where ActionType == "ConnectionFailed"
    | project NetTime = TimeGenerated, 
              DeviceName, RemoteIP, RemotePort;
PayloadExecs
| join kind=inner FailedC2 on DeviceName
| where NetTime between (ExecTime .. (ExecTime + 2m))
| project ExecTime, NetTime, DeviceName, 
          FileName, RemoteIP, RemotePort
```

</details>

---


<details>
<summary id="-flag-33">🚩 <strong>Flag 33: <Technique Name></strong></summary>

### 🎯 Objective
Identify the initiating process responsible for launching the 
payload during the second execution phase on 13 December 2025 — 
distinguishing the automated persistence mechanism from the 
manual interactive execution observed in Phase 1, and confirming 
how the threat actor engineered persistent payload re-execution 
without requiring continued hands-on-keyboard interaction.

### 📌 Finding
**Answer: `cmd.exe`**

The Phase 2 executions of the payload (`PHTG.exe`) were 
initiated by **`cmd.exe`** — specifically executing 
`C:\ProgramData\PHTG\HealthCloud\Launch.bat` via the 
command line `cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat"`. 
This represents a fundamental shift from Phase 1's manual 
double-click execution via `explorer.exe` to automated 
batch file-based persistence execution.

**Execution Phase Comparison:**

| Phase | Date | Payload Name | Initiating Process | Launch Method |
|-------|------|-------------|-------------------|---------------|
| Phase 1 | 12/12/2025 | Sarah_Chen_Notes.exe | explorer.exe | Manual double-click |
| Phase 2 | 12/13/2025 | PHTG.exe | cmd.exe | Launch.bat automation |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Phase 2 Initiating Process | cmd.exe |
| Phase 2 Payload Name | PHTG.exe |
| Phase 2 Launch Mechanism | C:\ProgramData\PHTG\HealthCloud\Launch.bat |
| Full Command Line | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |
| Phase 2 Timestamps | 12/13/2025 10:21:48 UTC, 10:22:36 UTC |
| Phase 2 Location | C:\ProgramData\PHTG\HealthCloud\ |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Account | vmadminusername |
| Timestamp | 12/13/2025 10:21:48 – 10:22:36 UTC |
| Process | PHTG.exe |
| Parent Process | cmd.exe |
| Command Line | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |

### 💡 Why it matters
The shift from `explorer.exe` to `cmd.exe` as the initiating 
process between Phase 1 and Phase 2 is operationally 
significant for several reasons:

- **Phase 1 was manual — Phase 2 is automated** — 
  `explorer.exe` as the parent process indicates 
  direct user interaction (double-clicking a file). 
  `cmd.exe` executing a `.bat` file indicates 
  automated, scripted execution that does not 
  require the threat actor to be actively logged 
  in via RDP
- **`Launch.bat` is a persistence mechanism** — 
  The creation of `Launch.bat` in the HealthCloud 
  directory represents the threat actor engineering 
  a method to re-execute the Meterpreter payload 
  automatically — whether triggered by a scheduled 
  task, a service, a startup script, or manual 
  invocation. This ensures the payload can be 
  re-launched even if the RDP session ends
- **The HealthCloud directory provides cover** — 
  `cmd.exe` launching a `.bat` file from 
  `C:\ProgramData\PHTG\HealthCloud\` would 
  appear superficially legitimate in the 
  context of a service that legitimately 
  uses scheduled PowerShell tasks and 
  background service executables in 
  that same directory
- **The two-phase approach shows attacker 
  adaptability** — Phase 1 failed to establish 
  a C2 session (all callbacks to 
  `173.244.55.130:4444` failed). Rather 
  than abandoning the operation, the threat 
  actor restructured their approach — 
  renaming the payload, relocating it, 
  creating a batch launcher, and 
  re-attempting C2 establishment through 
  an automated mechanism
- **`cmd.exe` as parent provides an 
  attribution anchor** — The specific 
  command line `cmd.exe /c "..."` is a 
  forensic artifact that confirms the 
  batch file was the direct launcher 
  and enables reconstruction of the 
  full persistence chain

### 🔧 KQL Query Used
```kql
// Process execution events for both payload phases
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
    or FileName in ("Sarah_Chen_Notes.exe", "PHTG.exe")
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results — Phase 2 Executions:**
| TimeGenerated | FileName | InitiatingProcessFileName | InitiatingProcessCommandLine |
|---------------|----------|--------------------------|------------------------------|
| 12/13/2025 10:21:48 | PHTG.exe | **cmd.exe** | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |
| 12/13/2025 10:22:36 | PHTG.exe | **cmd.exe** | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |

```kql
// Confirm Launch.bat creation in DeviceFileEvents
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FileName == "Launch.bat"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, FolderPath, 
          ActionType, SHA256,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
PHTG.exe initiated by cmd.exe with the full Launch.bat 
command line on 12/13/2025, contrasted with the Phase 1 
Sarah_Chen_Notes.exe executions initiated by explorer.exe 
on 12/12/2025>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Alert on `cmd.exe` executing `.bat` files from 
  `C:\ProgramData`** — batch file execution from 
  ProgramData subdirectories is anomalous unless 
  associated with a known, inventoried software 
  installation:

```kql
// Alert — batch file execution from ProgramData
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine contains "ProgramData"
| where ProcessCommandLine endswith ".bat\""
    or ProcessCommandLine contains ".bat\" "
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, 
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessAccountName
```

- **Inventory all `.bat` files in service directories** — 
  particularly newly deployed services like HealthCloud. 
  Any batch file not present in the original deployment 
  package should trigger an immediate investigation:

```kql
// Hunt — unexpected batch files in HealthCloud directory
DeviceFileEvents
| where FolderPath contains "HealthCloud"
| where FileName endswith ".bat"
| where ActionType == "FileCreated"
| where TimeGenerated between 
    (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, SHA256,
          InitiatingProcessAccountName
```

- **Monitor parent-child process relationships** — 
  `cmd.exe` spawning a known malicious SHA256 is 
  a high-fidelity detection opportunity regardless 
  of the filename used:

```kql
// Alert — cmd.exe spawning known malicious binary
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where SHA256 == 
    "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          ProcessCommandLine,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
```

- **Audit scheduled tasks and services for 
  unauthorised entries** — the Phase 2 execution 
  pattern strongly suggests `Launch.bat` was 
  triggered by a scheduled task or service 
  registered in the HealthCloud context. 
  All scheduled tasks should be audited 
  against a known-good baseline:

```kql
// Hunt — scheduled task creation events
DeviceProcessEvents
| where FileName in ("schtasks.exe", "taskschd.msc")
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, DeviceName, FileName, 
          ProcessCommandLine,
          InitiatingProcessAccountName
```
</details>

---


<details>
<summary id="-flag-34">🚩 <strong>Flag 34: <Technique Name></strong></summary>

### 🎯 Objective
Extract the full file path of the batch file responsible for 
launching the Meterpreter payload during the Phase 2 execution 
on 13 December 2025 — confirming the exact location of the 
persistence mechanism within the PHTG HealthCloud service 
directory and establishing it as a key indicator of compromise.

### 📌 Finding
**Answer: `C:\ProgramData\PHTG\HealthCloud\Launch.bat`**

The full path of the batch file that launched `PHTG.exe` 
during Phase 2 is **`C:\ProgramData\PHTG\HealthCloud\Launch.bat`**, 
extracted directly from the `InitiatingProcessCommandLine` 
field in `DeviceProcessEvents`:

```
cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" "
```

This batch file was deliberately placed within PHTG's 
legitimate HealthCloud service directory to blend with 
expected service infrastructure and avoid detection 
during routine file system review.

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Batch File Full Path | C:\ProgramData\PHTG\HealthCloud\Launch.bat |
| Initiating Command Line | cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" " |
| Payload Launched | PHTG.exe |
| Payload Location | C:\ProgramData\PHTG\HealthCloud\PHTG.exe |
| Phase 2 Timestamps | 12/13/2025 10:21:48 UTC, 10:22:36 UTC |
| Account | vmadminusername |
| SHA256 (Payload) | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Timestamp | 12/13/2025 10:21:48 UTC |
| Process | PHTG.exe |
| Parent Process | cmd.exe |
| Command Line | cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" " |

### 💡 Why it matters
The location and naming of `Launch.bat` is a carefully 
calculated persistence technique:

- **`C:\ProgramData\PHTG\HealthCloud\` is the legitimate 
  service directory** — The hunt brief explicitly states 
  that HealthCloud stores "background service executables" 
  and "diagnostic cache directories" in this location. 
  The threat actor placed `Launch.bat` here to make it 
  indistinguishable from legitimate HealthCloud components 
  during casual review
- **`Launch.bat` is a plausible service component name** — 
  A file named `Launch.bat` in a service directory would 
  appear entirely consistent with a legitimate startup 
  or launch script for the HealthCloud service — 
  making it unlikely to raise suspicion without 
  hash-based or content-based inspection
- **The full path is the definitive IOC** — 
  `C:\ProgramData\PHTG\HealthCloud\Launch.bat` 
  is a concrete, actionable indicator of compromise 
  that can be immediately used to:
  - Search for the file across the entire PHTG estate
  - Identify any other devices where this persistence 
    mechanism was deployed
  - Confirm lateral movement if found on additional hosts
- **`cmd.exe /c` confirms non-interactive execution** — 
  The `/c` flag causes `cmd.exe` to execute the batch 
  file and then terminate — consistent with a scheduled 
  task or service trigger rather than an interactive 
  command shell session. This confirms `Launch.bat` 
  was designed for automated, non-interactive 
  re-execution of the payload
- **The double-quote wrapping in the command line** — 
  `cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" "` 
  uses an extra set of quotes around the full command, 
  which is a common batch file invocation pattern 
  used when the path contains spaces or when the 
  command is embedded in a scheduled task definition

### 🔧 KQL Query Used
```kql
// Extract full batch file path from initiating 
// command line of Phase 2 payload executions
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where FileName == "PHTG.exe"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | InitiatingProcessFileName | InitiatingProcessCommandLine |
|---------------|----------|--------------------------|------------------------------|
| 12/13/2025 10:21:48 | PHTG.exe | cmd.exe | cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" " |
| 12/13/2025 10:22:36 | PHTG.exe | cmd.exe | cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat" " |

```kql
// Confirm Launch.bat file creation event
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FileName == "Launch.bat"
| where FolderPath contains "HealthCloud"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, FolderPath, 
          ActionType, InitiatingProcessAccountName
```

```kql
// Hunt for Launch.bat across entire PHTG estate
// to identify lateral movement
DeviceFileEvents
| where FileName == "Launch.bat"
| where FolderPath contains "HealthCloud"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| summarize count() by DeviceName, FolderPath, ActionType
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
the full InitiatingProcessCommandLine value containing 
C:\ProgramData\PHTG\HealthCloud\Launch.bat for both 
Phase 2 PHTG.exe execution events on 12/13/2025>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Immediately locate and delete `Launch.bat`** from 
  all PHTG endpoints as part of incident remediation — 
  this is the persistence mechanism that ensures 
  the Meterpreter payload re-executes automatically:

```kql
// Confirm Launch.bat presence and current status
DeviceFileEvents
| where FileName == "Launch.bat"
| where FolderPath == "C:\\ProgramData\\PHTG\\HealthCloud\\"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, ActionType,
          InitiatingProcessAccountName
| order by TimeGenerated desc
```

- **Alert on batch file creation in any service 
  directory under `C:\ProgramData`** by non-system 
  accounts — this is a high-fidelity persistence 
  indicator:

```kql
// Alert — batch file created in ProgramData 
// by non-system account
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".bat"
| where FolderPath startswith "C:\\ProgramData\\"
| where InitiatingProcessAccountName !in 
    ("system", "local service", "network service")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, InitiatingProcessAccountName
```

- **Audit all scheduled tasks on `azwks-phtg-02`** — 
  the `cmd.exe /c` invocation pattern strongly suggests 
  `Launch.bat` was triggered by a scheduled task. 
  Every scheduled task should be reviewed against 
  a known-good baseline and any referencing 
  `Launch.bat` or `PHTG.exe` should be 
  immediately deleted:

```kql
// Hunt — scheduled task creation by compromised account
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where TimeGenerated >= datetime(2025-12-12T05:47:45Z)
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, DeviceName, FileName,
          ProcessCommandLine,
          InitiatingProcessAccountName
```

- **Implement file integrity monitoring on all 
  service directories** — any new file created 
  in `C:\ProgramData\PHTG\HealthCloud\` that 
  was not part of the original HealthCloud 
  deployment package should trigger an 
  immediate alert, regardless of filename 
  or extension
</details>

---


<details>
<summary id="-flag-35">🚩 <strong>Flag 35: <Technique Name></strong></summary>

### 🎯 Objective
Identify the external IP address that the Meterpreter payload 
attempted to communicate with following execution on 
`azwks-phtg-02` — confirming the Command and Control (C2) 
infrastructure used by the threat actor and completing the 
infrastructure attribution picture established throughout 
this investigation.

### 📌 Finding
**Answer: `173.244.55.130`**

Following execution, the Meterpreter payload attempted to 
establish a C2 connection to **`173.244.55.130`** on port 
**4444** — the default Metasploit listener port. All three 
callback attempts failed (`ConnectionFailed`), suggesting 
the C2 listener was not active at the time of execution. 
This IP belongs to the same `173.244.55.0/24` subnet as 
the two RDP access IPs, completing the threat actor 
infrastructure picture.

**Complete `173.244.55.0/24` Infrastructure Map:**

| IP Address | Role | Evidence Source |
|------------|------|-----------------|
| 173.244.55.128 | RDP Access (secondary) | DeviceLogonEvents |
| 173.244.55.130 | Meterpreter C2 | DeviceNetworkEvents |
| 173.244.55.131 | RDP Access (primary) | DeviceLogonEvents |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| C2 IP | 173.244.55.130 |
| C2 Port | 4444 |
| Protocol | TCP |
| ActionType | ConnectionFailed |
| Callback Attempts | 3 |
| Initiating Process (Phase 1) | sarah_chen_notes.exe |
| Initiating Process (Phase 2) | phtg.exe |
| C2 Subnet | 173.244.55.0/24 |
| Country | Uruguay |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Timestamp | 12/12/2025 14:19:12, 12/13/2025 10:13:39, 10:22:09 UTC |
| Process | sarah_chen_notes.exe / phtg.exe |
| Parent Process | explorer.exe / cmd.exe |
| Command Line | N/A — Network callback event |

**C2 Callback Timeline:**
| Timestamp | RemoteIP | Port | Process | ActionType |
|-----------|----------|------|---------|------------|
| 12/12/2025 14:19:12 | 173.244.55.130 | 4444 | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:13:39 | 173.244.55.130 | 4444 | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:22:09 | 173.244.55.130 | 4444 | phtg.exe | ConnectionFailed |

### 💡 Why it matters
The C2 IP `173.244.55.130` is the most significant 
network-level indicator of compromise in this investigation:

- **Subnet convergence confirms single threat actor** — 
  `173.244.55.130` shares a /24 subnet with the two 
  RDP access IPs (`173.244.55.128` and `173.244.55.131`). 
  Three adjacent IPs in the same subnet performing 
  three distinct attack functions — initial access, 
  persistent access, and C2 — is definitive evidence 
  of a single, organised threat actor operating from 
  dedicated Uruguayan infrastructure
- **Port 4444 confirms out-of-the-box Metasploit** — 
  Port 4444 is the default Metasploit/Meterpreter 
  listener port. The use of the default port 
  without customisation suggests the threat actor 
  did not invest significant effort in operational 
  security for their C2 configuration — a lower 
  sophistication indicator
- **All callbacks failed — C2 was not established** — 
  Three `ConnectionFailed` events across both 
  execution phases confirm the Meterpreter payload 
  never successfully called home. The C2 listener 
  was not active at the time of execution, 
  meaning the threat actor did not achieve 
  a live Meterpreter session despite successfully 
  executing the payload
- **Failed C2 does not mean the threat is resolved** — 
  The absence of a successful C2 session does not 
  eliminate the threat. The threat actor retained 
  RDP access via `vmadminusername`, had `Launch.bat` 
  as a persistence mechanism, and could re-activate 
  the C2 listener at any time to achieve a 
  Meterpreter session
- **This IP should anchor all threat intelligence 
  reporting** — `173.244.55.130` is the definitive 
  C2 indicator for this intrusion and should be 
  blocklisted, reported, and used to hunt for 
  related infrastructure across the PHTG estate

### 🔧 KQL Query Used
```kql
// Identify C2 callback IP using payload SHA256
// as the immutable process identifier
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-12T14:00:00Z) .. datetime(2025-12-23))
| where InitiatingProcessSHA256 == 
    "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort, 
          InitiatingProcessFileName, ActionType
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | RemoteIP | RemotePort | InitiatingProcessFileName | ActionType |
|---------------|----------|------------|--------------------------|------------|
| 12/12/2025 14:19:12 | 173.244.55.130 | 4444 | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:13:39 | 173.244.55.130 | 4444 | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:22:09 | 173.244.55.130 | 4444 | phtg.exe | ConnectionFailed |

> **Investigative Note:** An initial query filtering on 
> `InitiatingProcessFileName` returned no results because 
> MDE normalises process names to lowercase in 
> `DeviceNetworkEvents`. The correct approach was to 
> filter using `InitiatingProcessSHA256` — the immutable 
> hash identifier — which successfully returned all 
> three C2 callback events regardless of filename 
> or case normalisation.

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
all three ConnectionFailed events from the Meterpreter payload 
to 173.244.55.130:4444, with both sarah_chen_notes.exe and 
phtg.exe as initiating processes>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Block outbound connections to port 4444** at 
  the Azure NSG and network perimeter level — 
  this is not a legitimate business port and 
  any outbound connection on 4444 should be 
  treated as a critical indicator:

```kql
// Alert — outbound connection on port 4444
DeviceNetworkEvents
| where RemotePort == 4444
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, RemoteIP, 
          RemotePort, ActionType,
          InitiatingProcessFileName,
          InitiatingProcessSHA256
```

- **Block the entire `173.244.55.0/24` subnet** 
  at all network controls immediately — three 
  confirmed malicious IPs in this subnet across 
  multiple attack phases justify blocking the 
  entire range
- **Hunt for any outbound connection to 
  non-standard ports from `C:\ProgramData`-based 
  processes** — legitimate service executables 
  in `ProgramData` rarely need to make outbound 
  connections on non-standard ports:

```kql
// Hunt — non-standard port outbound from ProgramData process
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where RemotePort !in (80, 443, 8080, 8443, 53, 
                         123, 25, 587, 993, 995)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in 
    ("svchost.exe", "lsass.exe", "services.exe",
     "MsMpEng.exe", "msiexec.exe")
| project TimeGenerated, DeviceName, RemoteIP, 
          RemotePort, ActionType,
          InitiatingProcessFileName,
          InitiatingProcessSHA256
| order by TimeGenerated desc
```

- **Implement egress filtering** — all outbound 
  connections from PHTG endpoints should be 
  restricted to approved destination IPs and 
  ports. Any connection to an unapproved 
  destination should be blocked and alerted. 
  This single control would have prevented 
  all three C2 callback attempts from reaching 
  the Meterpreter listener
- **Use SHA256-based process network monitoring** — 
  alert on any network connection initiated by 
  a process with the known malicious hash, 
  regardless of filename:

```kql
// Alert — known malicious hash initiating 
// any network connection
DeviceNetworkEvents
| where InitiatingProcessSHA256 == 
    "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, RemoteIP, 
          RemotePort, ActionType,
          InitiatingProcessFileName
```
</details>

---


<details>
<summary id="-flag-36">🚩 <strong>Flag 36: <Technique Name></strong></summary>

### 🎯 Objective
Geographically attribute the Meterpreter C2 infrastructure 
to a specific country and continent — confirming the physical 
location of the threat actor's command and control server 
and completing the full geographic attribution of the 
attack infrastructure identified throughout this investigation.

### 📌 Finding
**Answer: `Uruguay, South America`**

The C2 IP `173.244.55.130` is geolocated to **Uruguay**, 
located on the continent of **South America**. This finding 
is consistent with the GeoIP enrichment of the RDP access 
IPs (`173.244.55.128` and `173.244.55.131`) performed 
earlier in the investigation — all three IPs in the 
`173.244.55.0/24` subnet are attributed to Uruguay, 
confirming a single, geographically cohesive threat 
actor infrastructure block.

**Complete Threat Actor Infrastructure Attribution:**

| IP Address | Role | Country | Continent |
|------------|------|---------|-----------|
| 173.244.55.128 | RDP Access (secondary) | Uruguay | South America |
| 173.244.55.130 | Meterpreter C2 | Uruguay | South America |
| 173.244.55.131 | RDP Access (primary) | Uruguay | South America |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| C2 IP | 173.244.55.130 |
| C2 Port | 4444 |
| Country | Uruguay |
| Continent | South America |
| Subnet | 173.244.55.0/24 |
| All Subnet IPs Geolocated To | Uruguay, South America |
| GeoIP Dataset | GeoIP2 IPv4 (via GitHub raw CSV) |
| PHTG Operating Region | United States, North America |
| Timestamp | 12/12/2025 – 12/13/2025 UTC |
| Process | sarah_chen_notes.exe / phtg.exe |
| Parent Process | explorer.exe / cmd.exe |
| Command Line | N/A — Geographic enrichment |

### 💡 Why it matters
The geographic attribution of the C2 infrastructure to 
Uruguay, South America is a critical investigative and 
strategic finding:

- **Full subnet attribution to a single country** — 
  All three confirmed threat actor IPs 
  (`173.244.55.128`, `173.244.55.130`, `173.244.55.131`) 
  geolocate to Uruguay. This is not coincidental — 
  it confirms the threat actor operated exclusively 
  from a dedicated infrastructure block in Uruguay 
  throughout the entire attack chain:
  - **Reconnaissance** — Scanning from Uruguay
  - **Initial Access** — RDP brute force from Uruguay
  - **Persistence** — Repeated RDP sessions from Uruguay
  - **C2** — Meterpreter callback target in Uruguay

- **Zero legitimate connection to PHTG operations** — 
  PHTG operates exclusively in the United States 
  (North America). Uruguay (South America) has 
  absolutely no legitimate role in PHTG's business 
  operations, making every piece of infrastructure 
  in this subnet definitively hostile

- **Geographic attribution enables threat intelligence 
  correlation** — Uruguay-based hosting infrastructure 
  used for Meterpreter C2 with adjacent IPs used for 
  RDP brute force is a specific enough pattern to 
  search for in threat intelligence databases and 
  correlate against other known campaigns

- **The complete kill chain is now geographically 
  unified** — From the LinkedIn post exposure 
  through to the C2 callback attempt, every 
  malicious action in this investigation 
  traces back to the `173.244.55.0/24` subnet 
  in Uruguay, South America — providing 
  definitive infrastructure attribution for 
  the entire intrusion

- **Continent-level attribution matters for 
  policy decisions** — PHTG can implement 
  continent-level geographic blocking for 
  South America at the NSG and firewall 
  level, eliminating the entire class of 
  threat infrastructure used in this attack

### 🔧 KQL Query Used
```kql
// GeoIP enrichment of C2 IP to confirm 
// country and continent attribution
let GeoTable =
    externaldata(network:string, geoname_id:long, 
                 continent_code:string, 
                 continent_name:string, 
                 country_iso_code:string, 
                 country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let C2IP = datatable(RemoteIP:string)["173.244.55.130"];
C2IP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| project RemoteIP, country_name, continent_name,
          country_iso_code, continent_code
```

**Result:**
| RemoteIP | country_name | continent_name |
|----------|-------------|----------------|
| 173.244.55.130 | Uruguay | South America |

```kql
// Full subnet attribution — confirm all three 
// threat actor IPs geolocate to same country
let GeoTable =
    externaldata(network:string, geoname_id:long, 
                 continent_code:string, 
                 continent_name:string, 
                 country_iso_code:string, 
                 country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let ThreatActorIPs = datatable(RemoteIP:string)
[
    "173.244.55.128",
    "173.244.55.130",
    "173.244.55.131"
];
ThreatActorIPs
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| project RemoteIP, country_name, continent_name,
          country_iso_code, continent_code
```

**Results:**
| RemoteIP | country_name | continent_name |
|----------|-------------|----------------|
| 173.244.55.128 | Uruguay | South America |
| 173.244.55.130 | Uruguay | South America |
| 173.244.55.131 | Uruguay | South America |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
GeoIP enrichment of 173.244.55.130 returning Uruguay, 
South America — alongside the full subnet enrichment 
confirming all three threat actor IPs geolocate to 
the same country and continent>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Implement continent-level geographic blocking** — 
  since PHTG has no legitimate operations in South 
  America, blocking all inbound and outbound 
  connections to/from South American IP ranges 
  at the Azure NSG level would have prevented 
  every malicious action in this investigation:

```kql
// Ongoing monitoring — any connection to/from 
// South American IP ranges
let GeoTable =
    externaldata(network:string, geoname_id:long, 
                 continent_code:string, 
                 continent_name:string, 
                 country_iso_code:string, 
                 country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType == "Public"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where continent_code == "SA"
| summarize 
    EventCount = count(),
    UniqueIPs = dcount(RemoteIP),
    Processes = make_set(InitiatingProcessFileName)
    by DeviceName, country_name, continent_name
| order by EventCount desc
```

- **Block the entire `173.244.55.0/24` subnet 
  immediately** — with all three confirmed 
  malicious IPs in this block, the entire 
  /24 should be permanently blocklisted:
  - Azure NSG inbound rule: Deny `173.244.55.0/24`
  - Azure NSG outbound rule: Deny `173.244.55.0/24`
  - Firewall blocklist: Add `173.244.55.0/24`
  - EDR network blocklist: Add all three IPs

- **Document the complete Indicators of 
  Compromise (IOCs) for this investigation:**

| IOC Type | Value | Context |
|----------|-------|---------|
| IP Address | 173.244.55.128 | RDP access — Uruguay |
| IP Address | 173.244.55.130 | Meterpreter C2 — Uruguay |
| IP Address | 173.244.55.131 | RDP access — Uruguay |
| CIDR Block | 173.244.55.0/24 | Full threat actor subnet |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | Meterpreter payload |
| File Path | C:\ProgramData\PHTG\HealthCloud\PHTG.exe | Final payload location |
| File Path | C:\ProgramData\PHTG\HealthCloud\Launch.bat | Persistence mechanism |
| Account | vmadminusername | Compromised account |
| Port | 4444/TCP | Meterpreter C2 port |
| Country | Uruguay | Threat actor location |

</details>


---


<details>
<summary id="-flag-37">🚩 <strong>Flag 37: <Technique Name></strong></summary>

### 🎯 Objective
Confirm the specific remote port used by the Meterpreter 
payload for C2 callback attempts following execution on 
`azwks-phtg-02` — establishing the network-level indicator 
of compromise and confirming the threat actor's C2 
configuration choices.

### 📌 Finding
**Answer: `4444`**

The Meterpreter payload used remote port **`4444`** for 
all C2 callback attempts to `173.244.55.130`. Port 4444 
is the default Metasploit Framework listener port — its 
use without modification confirms the threat actor deployed 
an out-of-the-box Meterpreter configuration without 
customising the C2 port to blend with legitimate traffic 
on common ports like 80 or 443.

| Callback Event | Timestamp | RemoteIP | RemotePort | ActionType |
|----------------|-----------|----------|------------|------------|
| 1 | 12/12/2025 14:19:12 UTC | 173.244.55.130 | 4444 | ConnectionFailed |
| 2 | 12/13/2025 10:13:39 UTC | 173.244.55.130 | 4444 | ConnectionFailed |
| 3 | 12/13/2025 10:22:09 UTC | 173.244.55.130 | 4444 | ConnectionFailed |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| C2 Remote Port | 4444 |
| C2 Remote IP | 173.244.55.130 |
| Protocol | TCP |
| ActionType | ConnectionFailed (all 3 attempts) |
| Callback Count | 3 |
| Initiating Process Phase 1 | sarah_chen_notes.exe |
| Initiating Process Phase 2 | phtg.exe |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| C2 Country | Uruguay, South America |
| Timestamp | 12/12/2025 14:19:12 – 12/13/2025 10:22:09 UTC |
| Process | sarah_chen_notes.exe / phtg.exe |
| Parent Process | explorer.exe / cmd.exe |
| Command Line | N/A — Network callback event |

### 💡 Why it matters
The use of port 4444 as the C2 communication port is 
significant for both detection and threat actor profiling:

- **Port 4444 is the Metasploit default** — This is 
  the hardcoded default listener port in the Metasploit 
  Framework's `exploit/multi/handler` module. Any 
  security tool or network monitoring solution with 
  basic threat intelligence integration will flag 
  outbound connections to port 4444 as a high-severity 
  indicator of Meterpreter C2 activity
- **No port customisation indicates lower operational 
  security** — Experienced threat actors typically 
  reconfigure Meterpreter to communicate over port 
  443 (HTTPS) to blend with legitimate encrypted 
  web traffic. The use of port 4444 without 
  modification suggests:
  - The threat actor prioritised speed over 
    operational security
  - Limited technical sophistication in C2 
    infrastructure configuration
  - Possible use of a default Metasploit 
    configuration without customisation
- **Port 4444 is immediately detectable** — Unlike 
  C2 traffic masquerading as HTTPS on port 443, 
  outbound connections to port 4444 have no 
  legitimate business justification on a corporate 
  endpoint. Any egress filtering or outbound 
  port monitoring would have immediately flagged 
  these callback attempts
- **All callbacks failed — C2 was never established** — 
  Despite three execution attempts across two 
  phases, the Meterpreter payload never successfully 
  connected to the C2 listener. The threat actor's 
  primary post-exploitation tool was neutralised 
  not by defensive controls but by their own C2 
  infrastructure not being ready to receive connections
- **This port completes the full IOC set** — 
  Combined with the C2 IP (`173.244.55.130`) and 
  payload hash, the triple IOC of 
  `173.244.55.130:4444` + SHA256 provides a 
  comprehensive network and host-based detection 
  signature for this specific Meterpreter deployment

### 🔧 KQL Query Used
```kql
// C2 callback port identification using 
// payload SHA256 as process identifier
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated between (datetime(2025-12-12T14:00:00Z) 
                            .. datetime(2025-12-23))
| where InitiatingProcessSHA256 == 
    "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort, 
          InitiatingProcessFileName, ActionType
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | RemoteIP | RemotePort | InitiatingProcessFileName | ActionType |
|---------------|----------|------------|--------------------------|------------|
| 12/12/2025 14:19:12 | 173.244.55.130 | **4444** | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:13:39 | 173.244.55.130 | **4444** | sarah_chen_notes.exe | ConnectionFailed |
| 12/13/2025 10:22:09 | 173.244.55.130 | **4444** | phtg.exe | ConnectionFailed |

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
all three C2 callback attempts to 173.244.55.130 on port 4444, 
with ConnectionFailed ActionType across both execution phases>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Block all outbound connections on port 4444** 
  at the Azure NSG and perimeter firewall level — 
  there is no legitimate business use case for 
  outbound TCP/4444 from a corporate endpoint:

```kql
// Alert — outbound connection attempt on port 4444
DeviceNetworkEvents
| where RemotePort == 4444
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, RemoteIP, 
          RemotePort, ActionType,
          InitiatingProcessFileName,
          InitiatingProcessSHA256
```

- **Monitor for other common Metasploit default ports** — 
  in addition to 4444, alert on outbound connections 
  to other Metasploit/Meterpreter default ports:

```kql
// Alert — Metasploit default port outbound connections
DeviceNetworkEvents
| where RemotePort in (4444, 4445, 5555, 8080, 8443, 
                       6667, 1234, 31337)
| where RemoteIPType == "Public"
| where TimeGenerated > ago(1h)
| summarize 
    EventCount = count(),
    UniqueDestinations = dcount(RemoteIP)
    by DeviceName, RemotePort, 
       InitiatingProcessFileName
| order by EventCount desc
```

- **Implement strict egress filtering** — corporate 
  endpoints should only be permitted to make 
  outbound connections on explicitly approved 
  ports (80, 443, 53, 123, etc.). Any connection 
  attempt on an unapproved port should be 
  blocked by default and logged for investigation:

```kql
// Hunt — outbound connections on non-standard ports
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort !in (80, 443, 8080, 8443, 53, 
                         123, 25, 587, 993, 995, 
                         143, 110, 21, 22, 3389)
| where TimeGenerated > ago(24h)
| summarize 
    EventCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    Processes = make_set(InitiatingProcessFileName)
    by DeviceName, RemotePort
| order by EventCount desc
```

- **Complete IOC Summary for Network Blocking:**

| IOC Type | Value | Block Action |
|----------|-------|--------------|
| IP Address | 173.244.55.128 | Block inbound/outbound |
| IP Address | 173.244.55.130 | Block inbound/outbound |
| IP Address | 173.244.55.131 | Block inbound/outbound |
| CIDR Block | 173.244.55.0/24 | Block inbound/outbound |
| Port | 4444/TCP outbound | Block at NSG and firewall |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 | EDR blocklist |

</details>


---


<details>
<summary id="-flag-38">🚩 <strong>Flag 38: <Technique Name></strong></summary>

### 🎯 Objective
Identify the legitimate internal service whose directory 
was hijacked by the threat actor as a hiding place for 
the final Meterpreter payload and persistence mechanism 
— confirming how the attacker exploited PHTG's own 
recently deployed infrastructure to camouflage their 
malicious activity.

### 📌 Finding
**Answer: `HealthCloud`**

The threat actor placed both the final payload (`PHTG.exe`) 
and the persistence mechanism (`Launch.bat`) inside 
**`C:\ProgramData\PHTG\HealthCloud\`** — the installation 
directory of PHTG's legitimate internal endpoint health 
service, **HealthCloud**, which was rolled out on 
**11 December 2025** — just one day before the confirmed 
initial access on 12 December 2025.

**Files Planted in the HealthCloud Directory:**

| Filename | Type | Purpose |
|----------|------|---------|
| PHTG.exe | Meterpreter payload | Post-exploitation C2 agent |
| Launch.bat | Batch persistence script | Automated payload re-execution |

### 🔍 Evidence
| Field | Value |
|-------|-------|
| Host | azwks-phtg-02 |
| Hijacked Service | HealthCloud |
| Service Rollout Date | 11 December 2025 |
| Initial Access Date | 12 December 2025 |
| Days Between Rollout and Compromise | 1 |
| Malicious Payload Path | C:\ProgramData\PHTG\HealthCloud\PHTG.exe |
| Persistence Mechanism Path | C:\ProgramData\PHTG\HealthCloud\Launch.bat |
| SHA256 (Payload) | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Malware Family | Trojan:Win32/Meterpreter.RPZ!MTB |
| Account | vmadminusername |
| Timestamp | 12/13/2025 10:14:41 – 10:16:22 UTC |
| Process | PHTG.exe |
| Parent Process | cmd.exe |
| Command Line | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |

### 💡 Why it matters
The exploitation of the HealthCloud directory as a 
persistence location is one of the most strategically 
sophisticated elements of this attack:

- **Deliberate exploitation of deployment timing** — 
  HealthCloud was deployed on 11 December 2025. 
  The threat actor gained access on 12 December 2025 
  and planted their payload in the HealthCloud 
  directory on 13 December 2025. The attacker 
  moved within 48 hours of the service rollout — 
  exploiting the window when defenders would be 
  least familiar with HealthCloud's expected 
  file system footprint
- **New service = no baseline** — Because HealthCloud 
  had only been deployed for two days, no file 
  integrity baseline existed. Security teams had 
  no reference point for what files should or 
  should not be present in 
  `C:\ProgramData\PHTG\HealthCloud\`. The attacker 
  exploited this blind spot deliberately
- **Legitimate service activity provides cover** — 
  The hunt brief explicitly states HealthCloud 
  generates "scheduled PowerShell tasks, background 
  service executables, diagnostic cache directories, 
  and periodic outbound check-ins." The threat 
  actor's `PHTG.exe` and `Launch.bat` were designed 
  to blend with this expected activity pattern — 
  an executable and a batch launcher in a service 
  directory are entirely consistent with legitimate 
  service components
- **The LinkedIn post enabled this exploitation** — 
  The entire chain traces back to Sarah Chen's 
  LinkedIn post announcing the HealthCloud rollout. 
  The attacker saw the post, identified the 
  infrastructure, gained access within 24 hours, 
  and then used their knowledge of HealthCloud 
  (obtained from the post) to plant their payload 
  in the most defensively advantageous location 
  on the compromised host
- **This is a living-off-the-land persistence 
  strategy** — Rather than creating a new, 
  obviously malicious directory or registry key, 
  the attacker co-opted existing, legitimate 
  infrastructure. This represents a deliberate 
  choice to minimise forensic footprint and 
  maximise persistence survivability

### 🔧 KQL Query Used
```kql
// Confirm malicious files planted in HealthCloud directory
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FolderPath contains "HealthCloud"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where ActionType in ("FileCreated", "FileRenamed")
| where InitiatingProcessAccountName =~ "vmadminusername"
| project TimeGenerated, FileName, FolderPath, 
          ActionType, SHA256,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | FolderPath | ActionType |
|---------------|----------|------------|------------|
| 12/13/2025 10:14:41 | Sarah_Chen_Notes.exe | C:\ProgramData\PHTG\HealthCloud\ | FileRenamed |
| 12/13/2025 10:16:22 | PHTG.exe | C:\ProgramData\PHTG\HealthCloud\ | FileRenamed |

```kql
// Confirm Launch.bat creation in HealthCloud directory
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FolderPath contains "HealthCloud"
| where FileName == "Launch.bat"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, FolderPath, 
          ActionType, InitiatingProcessAccountName
```

```kql
// Full HealthCloud directory activity timeline
// Shows both legitimate and malicious file operations
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where FolderPath contains "HealthCloud"
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| project TimeGenerated, FileName, FolderPath, 
          ActionType, SHA256,
          InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot of Microsoft Sentinel query results showing 
PHTG.exe and Launch.bat planted in 
C:\ProgramData\PHTG\HealthCloud\ by vmadminusername on 
12/13/2025 — alongside the hunt brief context confirming 
HealthCloud was deployed on 11 December 2025>

### 🛠️ Detection Recommendation
**Hunting Tip:**
- **Establish file inventory baselines for all 
  newly deployed services immediately upon 
  rollout** — capture the expected file list, 
  hashes, and permissions for every service 
  directory at deployment time. Any deviation 
  from this baseline should trigger an alert:

```kql
// Baseline comparison — files in HealthCloud 
// directory not present at deployment time
// (Replace deployment_date with actual rollout date)
DeviceFileEvents
| where FolderPath contains "HealthCloud"
| where ActionType == "FileCreated"
| where TimeGenerated > datetime(2025-12-11)
| where InitiatingProcessAccountName !in 
    ("system", "local service", "network service",
     "healthcloud_service_account")
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, SHA256,
          InitiatingProcessAccountName
```

- **Alert on executable or batch file creation 
  in any service directory by non-service accounts** — 
  `vmadminusername` creating files in a service 
  directory is immediately anomalous:

```kql
// Alert — non-service account creating 
// executables in service directories
DeviceFileEvents
| where FolderPath startswith "C:\\ProgramData\\"
| where FileName endswith ".exe" 
    or FileName endswith ".bat"
    or FileName endswith ".ps1"
| where ActionType in ("FileCreated", "FileRenamed")
| where InitiatingProcessAccountName !in 
    ("system", "local service", "network service")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, FileName, 
          FolderPath, InitiatingProcessAccountName
```

- **Implement security awareness around new 
  service deployments** — the 48-hour window 
  between HealthCloud's rollout and the threat 
  actor's exploitation of its directory highlights 
  the need for heightened monitoring during and 
  immediately after any new service deployment:
  - Enable enhanced file integrity monitoring 
    on new service directories from day one
  - Restrict write permissions to service 
    directories to dedicated service accounts only
  - Conduct a file inventory audit 24-48 hours 
    after every new service deployment

- **Complete Remediation Checklist for This Incident:**

| Action | Target | Priority |
|--------|--------|----------|
| Delete | C:\ProgramData\PHTG\HealthCloud\PHTG.exe | 🔴 Immediate |
| Delete | C:\ProgramData\PHTG\HealthCloud\Launch.bat | 🔴 Immediate |
| Audit | All scheduled tasks on azwks-phtg-02 | 🔴 Immediate |
| Reset | vmadminusername credentials | 🔴 Immediate |
| Disable | RDP public exposure on azwks-phtg-02 | 🔴 Immediate |
| Block | 173.244.55.0/24 at all network controls | 🔴 Immediate |
| Enable | Defender active mode on all endpoints | 🔴 Immediate |
| Establish | HealthCloud file baseline inventory | 🟠 High |
| Review | All other PHTG VMs for same IOCs | 🟠 High |
| Implement | Azure Bastion for all RDP access | 🟠 High |

</details>

---


## 🚨 Detection Gaps & Recommendations
### Observed Gaps

**Gap 1 — RDP Publicly Exposed to the Internet**
Port 3389 was accessible from `0.0.0.0/0` with no NSG restriction, 
JIT access policy, or Azure Bastion in place. This was the single 
architectural failure that made every subsequent attack phase possible.

**Gap 2 — No Account Lockout Policy**
The `vmadminusername` account received 637 `InvalidUserNameOrPassword` 
failures without triggering a lockout. An attacker was given unlimited 
credential guessing attempts against a local administrator account.

**Gap 3 — Weak, Predictable Account Name**
`vmadminusername` is a default VM provisioning account name that 
appears near the top of every credential stuffing list. No MFA 
was enforced. Valid credentials alone were sufficient for full 
administrative RDP access.

**Gap 4 — Microsoft Defender Running in Passive Mode**
Defender successfully quarantined the Meterpreter payload three times 
in active mode — then the threat actor switched it to passive mode. 
Passive mode detects but does not block. Three subsequent detections 
produced zero blocking actions. Tamper Protection was not enabled.

**Gap 5 — No File Integrity Baseline for HealthCloud**
HealthCloud was deployed on 11 December 2025. No file inventory 
baseline was established at rollout. When the attacker planted 
`PHTG.exe` and `Launch.bat` in the HealthCloud directory 48 hours 
later, there was no reference point against which to detect the 
unauthorised additions.

**Gap 6 — Sensitive Notes Stored in Plaintext on an Internet-Facing VM**
`notes_sarah.txt` containing internal security-relevant content was 
stored in `C:\Users\vmAdminUsername\Documents\PHTG\` on a VM 
accessible via public RDP. An attacker with valid credentials had 
immediate access to insider intelligence with no additional effort.

**Gap 7 — No Geographic Authentication Controls**
PHTG operates exclusively in the United States. No Conditional 
Access policy, NSG rule, or alert existed to flag or block 
successful RDP authentication from Uruguay or any other 
unexpected geographic region.

**Gap 8 — No Egress Filtering on Non-Standard Ports**
The Meterpreter payload attempted to call back to 
`173.244.55.130:4444`. Port 4444 is the Metasploit default — 
there is no legitimate business use for outbound TCP/4444 
from a corporate endpoint. No egress filtering rule existed 
to block or alert on this traffic.

**Gap 9 — No OPSEC Controls Around Social Media**
The entire attack was enabled by a single LinkedIn post. No 
social media policy, security awareness training, or OSINT 
monitoring programme existed to prevent or detect the 
unintentional infrastructure disclosure.

**Gap 10 — Zero Alerts Fired Throughout the Entire Compromise**
Despite 325 network scanning events, 675 authentication attempts, 
23 successful unauthorised logons, Meterpreter payload execution, 
Defender passive mode detections, and C2 callback attempts — 
no automated alert fired at any stage of this intrusion.

---

### Recommendations

**R1 — Remove Public RDP Exposure Immediately**
Implement Azure Just-In-Time VM Access or deploy Azure Bastion. 
Remove the public IP association from `azwks-phtg-02`. Add an 
NSG rule explicitly denying inbound TCP/3389 from `0.0.0.0/0`.

**R2 — Enforce Account Lockout and MFA**
Configure a lockout threshold of 5 invalid attempts with a 
30-minute lockout duration. Require MFA for all accounts with 
RDP access. Valid credentials alone must never be sufficient 
for interactive access to an internet-facing endpoint.

**R3 — Rename and Harden Privileged Accounts**
Rename `vmadminusername` to a non-obvious, randomised value. 
Audit all endpoints for predictable admin account naming patterns. 
Create a honeypot account named `vmadminusername` that triggers 
a P1 alert on any logon attempt.

**R4 — Enable Defender Tamper Protection and Active Mode**
Switch all endpoints to Defender active mode. Enable Tamper 
Protection via Intune or Group Policy to prevent unauthorised 
mode changes. Alert on any `AntivirusDetectionActionType` event 
where `ReportSource` contains "passive mode."

**R5 — Establish File Integrity Baselines at Deployment**
Capture a file inventory hash baseline for every service directory 
at the moment of deployment. Alert on any executable or batch file 
created in `C:\ProgramData\` by a non-service account.

**R6 — Implement Geographic Authentication Controls**
Create a Sentinel Scheduled Query Rule alerting on any successful 
`RemoteInteractive` or `Network` logon from outside the United 
States. Treat any non-US successful authentication as a P1 incident 
until proven otherwise.

**R7 — Block Egress on Non-Standard Ports**
Implement NSG egress rules restricting outbound connections to 
approved ports only (80, 443, 53, 123). Block TCP/4444 outbound 
at the firewall and NSG level. Alert on any outbound connection 
to a non-standard port from a process in `C:\ProgramData\`.

**R8 — Implement a Social Media OPSEC Programme**
Publish a clear social media policy prohibiting photographs of 
workstations, cloud consoles, and infrastructure management tools. 
Conduct security awareness training with explicit examples of 
OPSEC failures. Deploy OSINT monitoring to detect unintentional 
company infrastructure disclosures on LinkedIn, Twitter/X, and GitHub.

**R9 — Block `173.244.55.0/24` at All Network Controls**
Add the entire /24 subnet as a deny rule on Azure NSGs, perimeter 
firewalls, and EDR network blocklists. Add the payload SHA256 
(`224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`) 
to the EDR blocklist.

**R10 — Deploy a Detection Rule Library for RDP Compromise**
Implement the following minimum Sentinel alert rules:
- High-volume inbound connections on port 3389 from public IPs
- Any `LogonSuccess` with `LogonType == RemoteInteractive` from a public IP
- `LogonFailed` volume exceeding 10 per 15-minute window from a single IP
- Successful authentication from a non-US geographic origin
- `AntivirusDetectionActionType` with passive mode `ReportSource`
- Outbound connection on port 4444 from any endpoint
- Executable or batch file created in `C:\ProgramData\` by a non-system account

---

## 🧾 Final Assessment

This intrusion represents a fully realised, end-to-end external RDP 
compromise enabled by a single unintentional OPSEC failure and sustained 
by a cascade of absent defensive controls. The threat actor demonstrated 
moderate sophistication — opportunistic rather than APT-grade — using 
commodity tooling (Metasploit Meterpreter, default port 4444, no custom 
malware), but showed clear operational adaptability when initial C2 
attempts failed. The decision to relocate the payload into PHTG's own 
HealthCloud directory, rename it `PHTG.exe`, and create `Launch.bat` as 
a persistence launcher within 48 hours of service rollout indicates an 
attacker with situational awareness and the patience to blend into the 
target environment.

The most significant risk finding is not the sophistication of the 
attack — it is the complete absence of detection. Zero alerts fired 
across the entire investigation window. The attacker had 23 confirmed 
interactive RDP sessions, reviewed internal documentation, executed 
a known malware family three times, and planted persistence — all 
without triggering a single automated response. PHTG's current 
defensive posture is inadequate for an organisation with 
internet-facing infrastructure and sensitive operational data.

Immediate priorities: remove public RDP exposure, enable Defender 
active mode with Tamper Protection, enforce MFA on all privileged 
accounts, and block `173.244.55.0/24` across all network controls. 
Longer term, this investigation should serve as the case study 
for a comprehensive security awareness programme, a Sentinel 
detection rule library, and a zero-trust network access 
architecture review.


---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting in Microsoft Sentinel 
  (`law-cyber-range` workspace) across MDE tables
- All KQL queries tested and validated against live telemetry 
  during the hunt window (09–23 December 2025 UTC)
- Techniques mapped directly to MITRE ATT&CK v14
- Python post-processing used where KQL limitations prevented 
  direct cross-ActionType IP correlation (Flag 10)
- GeoIP enrichment performed using the publicly available 
  GeoIP2 IPv4 dataset via GitHub raw CSV
- Flag 11 country count pending query execution — placeholder 
  retained for analyst to complete
- All IOCs documented in Flag 36/37/38 evidence tables are 
  confirmed via telemetry and should be actioned immediately
- This report was produced as part of the Cyber Range 
  Hunt 03: Signals Before the Noise (External RDP Compromise, 
  Intermediate difficulty)
---
