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

- Reconstruct the operator's post-compromise activity across endpoint and network telemetry.
- Identify persistence, command-and-control, and defense evasion techniques used to maintain access.
- Determine whether the intrusion progressed to credential access and credential dumping activity.  

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
  - `DeviceRegistryEvents`
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
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/222db846-4d8c-415c-8e59-bbaad8a8801a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

---

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, ActionType
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ee14285b-934b-4ce6-a747-67eea9018b8a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

---

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where RemoteIP == "10.0.0.105"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, ActionType
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/27f0a4aa-bd32-4592-b38f-854364f9544e" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>


---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where AccountName == "vmadminusername"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-File"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/985869c8-6145-4f68-b8ec-32fcd14ab7c2" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where AccountName == "vmadminusername"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-File"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ae3201d7-1bfb-4a79-8e84-cb6d4abb3997" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where FolderPath startswith "C:\\ProgramData\\PHTG"
| project TimeGenerated, ActionType, FolderPath, FileName
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ee6ed265-53dd-4bbb-8396-04a5caf00b35" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``


</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where FileName =~ "attrib.exe"
| where ProcessCommandLine has_any ("+h", "+s")
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/4baa4832-e8bf-46ec-9609-6730a76e081d" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where FileName != ProcessVersionInfoOriginalFileName
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/f578a330-b7e0-41ab-b48c-0065a895c74a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| summarize Count=count()
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/fee511f7-459d-4357-91b2-8acdf7f70f88" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/7303e337-dd9d-47c8-b01f-589537a84752" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains "CurrentVersion\\Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/4b610653-c153-4174-a9c6-75da14c18f09" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains "CurrentVersion\\Run"
| where RegistryValueName == "PHTGHealthCloudTray"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/d014cfc8-de7b-4d1a-9055-1e176e41853c" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName endswith ".lnk"
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/a9bae179-0302-4bb7-860f-72f3ffefbe63" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains "EventLog\\Application"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/04ba7dae-8d84-4326-a39e-e31ecbda0cdc" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName == "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine contains "/healthcheck"
| summarize Count=count()
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ef7997c1-9c9c-48df-8c71-72993e67f9c5" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-e")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/8a372449-2455-4d5e-a780-fb3fcaed0d2a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
```kql
SigninLogs
| where TimeGenerated between (todatetime('2025-12-13 09:00') .. todatetime('2025-12-13 18:00'))
| where ResultSignature == "FAILURE"
| project TimeGenerated, ResultType, ResultSignature, ResultDescription, Location, LocationDetails, AuthenticationRequirement
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/222db846-4d8c-415c-8e59-bbaad8a8801a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/63610951-09db-4de1-b212-317593e65694" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where InitiatingProcessFileName =~ "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/7512d4c2-5d87-4ac3-aa77-33d3f346359e" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "C:\\ProgramData\\PHTG\\HealthCloud\\Bin"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/8f188fd5-04ef-41ad-8321-2f4d4ff69c8e" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where FileName =~ "cmd.exe" | project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/be0e75f2-bbea-46cc-aa1f-fd46f6c94a0c" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains @"Microsoft\Windows Defender\Exclusions"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/561966fb-048e-4525-b9fa-7e26a4877012" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated  between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType has "AntivirusReport"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, AdditionalFields
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/b327ea57-7781-43f5-8a09-46004980bd0c" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Add-MpPreference", "Remove-MpPreference")
| project TimeGenerated, AdditionalFields
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/6ef94e11-d19d-4f4b-adcd-adc602873226" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

### 🎯 Objective
```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T10:12:59Z)
| where ProcessCommandLine has "HealthCloudTray.ps1"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/371f28b0-6a04-4d90-8cfb-c7c7d8ec82d7" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

### 🎯 Objective
```kql
SigninLogs
| where TimeGenerated between (todatetime('2025-12-13 09:00') .. todatetime('2025-12-13 18:00'))
| where ResultSignature == "FAILURE"
| project TimeGenerated, ResultType, ResultSignature, ResultDescription, Location, LocationDetails, AuthenticationRequirement
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/222db846-4d8c-415c-8e59-bbaad8a8801a" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: <Technique Name></strong></summary>

### 🎯 Objective

### 📌 Findings

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType == "OpenProcessApiCall"
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, AdditionalFields
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/3071711a-cc19-46c7-ae62-bb9bd50a02b8" />

### 💡 Why it matters
- Azure AD already accepted the username/password.
- MFA was the only thing preventing access.
- This is not what you would expect from a password guessing attack.

### Conclusion
The successful authentication was not consistent with a brute-force attack. The telemetry indicates the attacker possessed valid credentials and repeatedly attempted authentication before being challenged for MFA. Based on the evidence, the most likely access vector would be ``Password Reuse.``
</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: <Technique Name></strong></summary>

### 🎯 Objective

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType == "OpenProcessApiCall"
| project TimeGenerated, AdditionalFields
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/32c5451d-fa8b-4a4d-89d5-38d4163ee536" />

### 📌 Findings 
Analysis of LSASS access events identified two sequential DesiredAccess values requested by PowerShell. The first request used ``5136 (0x1410)``, while the second used ``2047999 (0x1F3FFF)``. The latter corresponds to PROCESS_ALL_ACCESS, granting full access to the LSASS process.

### 💡 Why it matters
-	LSASS stores authentication material and credentials.
-	Full process access enables memory inspection and credential theft techniques.
-	Escalating access rights indicates increasing control over the target process.

### Conclusion
The DesiredAccess value ``2047999 (0x1F3FFF)`` grants full access to LSASS. The escalation from limited access to full process access is significant because it enables actions such as reading LSASS memory and accessing stored authentication material.

</details>

---

<details>
<summary id="-flag-29">🚩 <strong>Flag 29: <Technique Name></strong></summary>

### 🎯 Objective
Confirm whether the operator successfully read memory from ``lsass.exe`` after obtaining full process access.

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType == "ReadProcessMemoryApiCall"
| project TimeGenerated, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/73007e2d-fdb1-4301-a486-85b8be06316e" />

### 📌 Findings
Analysis of DeviceEvents identified a ``ReadProcessMemoryApiCall`` event involving ``lsass.exe`` during the investigation window. The event was initiated by ``powershell.exe`` under the ``vmadminusername`` account, confirming activity beyond simple handle access.

### 💡 Why it matters
- ``OpenProcessApiCall`` only proves that a handle to LSASS was opened.
- ``ReadProcessMemoryApiCall`` confirms the operator actually read memory from LSASS.
- Reading LSASS memory is consistent with credential dumping activity.

### Conclusion
The ActionType ``ReadProcessMemoryApiCall`` confirmed that the operator progressed beyond handle access and successfully read memory from ``lsass.exe``. Combined with the earlier ``OpenProcessApiCall`` activity, this provides strong evidence of credential-access behavior consistent with LSASS credential dumping techniques.

</details>

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
