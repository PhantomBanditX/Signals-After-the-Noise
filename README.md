<p align="center">
<img width="1023" height="336" alt="Image" src="https://github.com/user-attachments/assets/f7355830-fc08-4621-a530-3b18f48d25f2" />
</p>

# 🛡️ Signals After the Noise

## 📌 Executive Summary

A threat actor gained access to ``azwks-phtg-01`` using valid credentials obtained through password reuse rather than brute force. After access was established, the operator deployed HealthCloud-themed tooling, implemented multiple persistence mechanisms, created redundant command-and-control channels, and applied Microsoft Defender exclusions to reduce detection. The intrusion ultimately progressed to credential access activity, where ``powershell.exe`` obtained elevated access to ``lsass.exe`` and successfully read LSASS memory. The investigation reconstructed the full attack chain and confirmed persistence, defense evasion, command-and-control, and credential dumping behaviors on the compromised host.

---

## 🎯 Hunt Objectives

- Reconstruct the operator's post-compromise activity across endpoint and network telemetry.
- Identify persistence, command-and-control, and defense evasion techniques used to maintain access.
- Determine whether the intrusion progressed to credential access and credential dumping activity.  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Sentinel (`law-cyber-range` workspace) 
- **Organization:** PHTG (Pacific Health Technology Group)
- **Investigation:** Signals After the Noise 2
- **Timeframe:** 2025-12-13 09:00 UTC → 2025-12-13 18:00 UTC
- **Anchor Time:** 2025-12-13 09:48 UTC
- **Target Host:** `azwks-phtg-01`
- **Primary Account:** `vmadminusername`
- **Data Sources:**
  - `DeviceNetworkEvents`
  - `DeviceLogonEvents`
  - `DeviceProcessEvents`
  - `DeviceFileEvents`
  - `DeviceEvents`
  - `SigninLogs`
  - `DeviceRegistryEvents`

- **Investigation Objectives:**
  - Determine the actual access vector
  - Identify persistence mechanisms
  - Analyze command-and-control activity
  - Review defense evasion techniques
  - Confirm credential access activity (LSASS)
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
  

- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This investigation focused on a suspected compromise of `azwks-phtg-01` within the PHTG environment and aimed to reconstruct the operator's activity after initial access. Through analysis of authentication, process, registry, file, network, and endpoint telemetry, the hunt traced the attack from credential misuse through persistence, command-and-control communications, defense evasion, and credential access activity. The objective was to identify the operator's techniques, validate the scope of compromise, and document the complete attack chain throughout the intrusion lifecycle.

---
## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 01: Password Reuse</strong></summary>

### 🎯 Objective
Determine whether the successful authentication resulted from brute force or the use of previously compromised credentials.

```kql
SigninLogs
| where TimeGenerated between (todatetime('2025-12-13 09:00') .. todatetime('2025-12-13 18:00'))
| where ResultSignature == "FAILURE"
| project TimeGenerated, ResultType, ResultSignature, ResultDescription, Location, LocationDetails, AuthenticationRequirement
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/222db846-4d8c-415c-8e59-bbaad8a8801a" />

### 📌 Findings
Initial review suggested a brute-force attack due to multiple failed authentication attempts originating from different geographic regions. However, comparison of the authentication activity revealed that the successful login was associated with credential material that had already been used elsewhere, indicating that the attacker possessed valid credentials rather than successfully guessing them through repeated login attempts.

### 💡 Why it matters
- Multiple failed logons can create the appearance of a brute-force attack.
- Attribution should be based on authentication evidence rather than assumptions.
- Correctly identifying the access vector improves incident response and remediation decisions.

### Conclusion
The successful authentication was not the result of a brute-force attack. The actual access vector was `Password Reuse`.


---

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 02: Initial Access Account</strong></summary>

### 🎯 Objective
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, ActionType
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ee14285b-934b-4ce6-a747-67eea9018b8a" />

### 📌 Findings
Analysis of DeviceEvents identified a ``ReadProcessMemoryApiCall`` event involving ``lsass.exe`` during the investigation window. The event was initiated by ``powershell.exe`` under the ``vmadminusername`` account, confirming activity beyond simple handle access.

### 💡 Why it matters
- ``OpenProcessApiCall`` only proves that a handle to LSASS was opened.
- ``ReadProcessMemoryApiCall`` confirms the operator actually read memory from LSASS.
- Reading LSASS memory is consistent with credential dumping activity.

### Conclusion
The ActionType ``ReadProcessMemoryApiCall`` confirmed that the operator progressed beyond handle access and successfully read memory from ``lsass.exe``. Combined with the earlier ``OpenProcessApiCall`` activity, this provides strong evidence of credential-access behavior consistent with LSASS credential dumping techniques.

---

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 03: Successful Authentication</summary>

### 🎯 Objective
```kql
DeviceLogonEvents
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where RemoteIP == "10.0.0.105"
| project TimeGenerated, AccountName, RemoteIP, DeviceName, ActionType
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/27f0a4aa-bd32-4592-b38f-854364f9544e" />

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

<details>
<summary id="-flag-4">🚩 <strong>Flag 04: Source Infrastructure</summary>

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

<details>
<summary id="-flag-5">🚩 <strong>Flag 05: Interactive Access</summary>

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

<details>
<summary id="-flag-6">🚩 <strong>Flag 06: Initial Tool Execution</summary>

### 🎯 Objective
Identify the first malicious tooling executed following successful access.

```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where FolderPath startswith "C:\\ProgramData\\PHTG"
| project TimeGenerated, ActionType, FolderPath, FileName
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ee6ed265-53dd-4bbb-8396-04a5caf00b35" />

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

<details>
<summary id="-flag-7">🚩 <strong>Flag 07: HealthCloud Deployment</summary>

### 🎯 Objective
Determine how the operator established the HealthCloud workspace and supporting tooling.

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

<details>
<summary id="-flag-8">🚩 <strong>Flag 08: Masqueraded Binary</summary>

### 🎯 Objective
Identify the disguised executable used to blend malicious activity with legitimate software.

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated >= datetime(2025-12-13T09:48:00Z)
| where FileName != ProcessVersionInfoOriginalFileName
| project TimeGenerated, FileName, ProcessVersionInfoOriginalFileName, FolderPath
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/f578a330-b7e0-41ab-b48c-0065a895c74a" />

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

<details>
<summary id="-flag-9">🚩 <strong>Flag 09: Registry Activity Volume</summary>

### 🎯 Objective
Measure post-compromise registry modification activity performed by the operator.

```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| summarize Count=count()
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/fee511f7-459d-4357-91b2-8acdf7f70f88" />

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

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Persistence Signal Isolation</summary>

### 🎯 Objective
Isolate registry modifications that contributed to persistence from routine system activity.

```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/7303e337-dd9d-47c8-b01f-589537a84752" />

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

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Run Key Value Name</summary>

### 🎯 Objective
Identify the Registry Run Key value used to automatically launch operator tooling.

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

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Run Key Persistence Command</summary>

### 🎯 Objective
Determine the command configured to execute through the persistence mechanism.
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

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Second Persistence Mechanism</summary>

### 🎯 Objective
Identify additional persistence mechanisms deployed beyond the Registry Run Key.

```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName endswith ".lnk"
| project TimeGenerated, ActionType, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/a9bae179-0302-4bb7-860f-72f3ffefbe63" />

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

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Third Persistence Mechanism</summary>

### 🎯 Objective
Identify system-level persistence established through Windows Event Log registration.

```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains "EventLog\\Application"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/04ba7dae-8d84-4326-a39e-e31ecbda0cdc" />

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

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Tooling HealthCheck Loop</summary>

### 🎯 Objective
Measure recurring beacon activity generated by the operator's HealthCloud service.

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where FileName == "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine contains "/healthcheck"
| summarize Count=count()
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/ef7997c1-9c9c-48df-8c71-72993e67f9c5" />

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

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Encoded Beacon Endpoints</summary>

### 🎯 Objective
Identify external endpoints contacted by encoded PowerShell beacon activity.

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

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Two Beacons, Why?</summary>

### 🎯 Objective
Determine the operational advantage gained by maintaining multiple command-and-control channels.

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

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Deployment Pattern Recognition</summary>

### 🎯 Objective
Reconstruct the sequence used to retrieve and execute operator payloads.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| project TimeGenerated, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/63610951-09db-4de1-b212-317593e65694" />

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

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Operator Outbound Domains</summary>

### 🎯 Objective
Identify domains contacted by the operator during post-access activity.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where InitiatingProcessFileName =~ "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/7512d4c2-5d87-4ac3-aa77-33d3f346359e" />

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

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: AMSI Probe Identification</summary>

### 🎯 Objective
Determine whether the operator validated AMSI visibility prior to executing additional tooling.

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

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Lineage Break Pattern</summary>

### 🎯 Objective
Identify process-launch techniques used to obscure execution lineage and parent-child relationships.

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where FileName =~ "cmd.exe" | project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/be0e75f2-bbea-46cc-aa1f-fd46f6c94a0c" />

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

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Defender Tampering</summary>

### 🎯 Objective
Identify Microsoft Defender exclusions configured to reduce detection of operator tooling.

```kql
DeviceRegistryEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where RegistryKey contains @"Microsoft\Windows Defender\Exclusions"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/561966fb-048e-4525-b9fa-7e26a4877012" />

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

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: Defender Detection Outcome</summary>

### 🎯 Objective
Determine whether Defender detections resulted in prevention, remediation, or only alert generation.

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated  between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType has "AntivirusReport"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, AdditionalFields
| order by TimeGenerated desc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/b327ea57-7781-43f5-8a09-46004980bd0c" />

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

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Temporary Defender Exclusion</summary>

### 🎯 Objective
Verify whether temporary Defender exclusions were used to facilitate payload execution.

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

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: Startup Execution Validation</summary>

### 🎯 Objective
Confirm that the deployed persistence mechanism successfully executed after configuration.

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated > datetime(2025-12-13T10:12:59Z)
| where ProcessCommandLine has "HealthCloudTray.ps1"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/371f28b0-6a04-4d90-8cfb-c7c7d8ec82d7" />

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

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: Custom Event Log Source Purpose</summary>

### 🎯 Objective
Determine the purpose and operational benefit of the custom Windows Event Log source registration.

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

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: LSASS Access Anomaly</summary>

### 🎯 Objective
Identify non-standard access to LSASS and determine the responsible process and account context.

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-01"
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T10:48:40Z))
| where ActionType == "OpenProcessApiCall"
| project TimeGenerated, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, AdditionalFields
| sort by TimeGenerated asc
```
<img width="1919" height="821" alt="Image" src="https://github.com/user-attachments/assets/3071711a-cc19-46c7-ae62-bb9bd50a02b8" />

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

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: Access Right Escalation</summary>

### 🎯 Objective
Determine the level of access obtained to LSASS and identify evidence of privilege escalation toward full process access.

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
<summary id="-flag-29">🚩 <strong>Flag 29: Credential Dump Confirmation</summary>

### 🎯 Objective
Confirm whether the operator progressed beyond handle access and successfully read memory from LSASS.

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

### 🧬 MITRE ATT&CK Summary

| Flag | Technique | Category | MITRE ID | Priority |
|------|-----------|----------|----------|----------|
| 01 | Password Reuse | Initial Access | T1078 Valid Accounts | 🟠 High |
| 02 | Valid Account Usage | Initial Access | T1078 | 🟠 High |
| 03 | Valid Account Authentication | Initial Access | T1078 | 🟠 High |
| 04 | External Remote Access | Initial Access | T1133 External Remote Services | 🟡 Medium |
| 05 | Interactive Logon | Execution | T1078 | 🟡 Medium |
| 06 | PowerShell Execution | Execution | T1059.001 PowerShell | 🟠 High |
| 07 | Tool Deployment | Execution | T1105 Ingress Tool Transfer | 🟠 High |
| 08 | Masquerading | Defense Evasion | T1036 Masquerading | 🟠 High |
| 09 | Registry Modification | Defense Evasion | T1112 Modify Registry | 🟡 Medium |
| 10 | Registry Persistence | Persistence | T1547.001 Registry Run Keys | 🟠 High |
| 11 | Registry Run Key | Persistence | T1547.001 | 🟠 High |
| 12 | Run Key Execution | Persistence | T1547.001 | 🟠 High |
| 13 | Startup Folder Persistence | Persistence | T1547.001 Registry Run Keys / Startup Folder | 🟠 High |
| 14 | Event Log Source Registration | Defense Evasion | T1112 Modify Registry | 🟡 Medium |
| 15 | Beaconing Activity | Command and Control | T1071 Application Layer Protocol | 🟠 High |
| 16 | Encoded PowerShell Beacon | Command and Control | T1071.001 Web Protocols | 🟠 High |
| 17 | Redundant C2 Channels | Command and Control | T1071 | 🟡 Medium |
| 18 | Tool Download & Execute | Execution | T1105 Ingress Tool Transfer | 🟠 High |
| 19 | External C2 Domains | Command and Control | T1071.001 Web Protocols | 🟠 High |
| 20 | AMSI Discovery/Testing | Discovery | T1518 Software Discovery | 🟡 Medium |
| 21 | Process Lineage Obfuscation | Defense Evasion | T1036 Masquerading | 🟡 Medium |
| 22 | Defender Exclusions | Defense Evasion | T1562.001 Impair Defenses | 🔴 Critical |
| 23 | AV Detection Validation | Defense Evasion | T1562 Impair Defenses | 🟡 Medium |
| 24 | Temporary Defender Exclusion | Defense Evasion | T1562.001 Impair Defenses | 🔴 Critical |
| 25 | Startup Execution Validation | Persistence | T1547.001 | 🟠 High |
| 26 | Custom Event Log Source | Defense Evasion | T1112 Modify Registry | 🟡 Medium |
| 27 | LSASS Access | Credential Access | T1003.001 LSASS Memory | 🔴 Critical |
| 28 | Full LSASS Access Rights | Credential Access | T1003.001 LSASS Memory | 🔴 Critical |
| 29 | LSASS Memory Read | Credential Access | T1003.001 LSASS Memory | 🔴 Critical |

---

## 🚨 Detection Gaps & Recommendations
### Observed Gaps

- Multiple persistence mechanisms (Registry Run Key, Startup Folder shortcut, and custom Event Log source registration) were successfully established before defensive action occurred.
- The operator implemented both temporary and persistent Microsoft Defender exclusions without generating preventative controls.
- Command-and-control communications persisted through multiple beaconing channels, increasing operational resilience.
- LSASS access progressed from process handle acquisition to memory reads consistent with credential dumping activity.
- Microsoft Defender generated detection events on operator artifacts but did not prevent persistence or credential-access behavior.

---

### Recommendations

- Create detections for Registry Run Key creation, Startup Folder modifications, and Event Log source registration activity.
- Monitor for PowerShell execution using -ExecutionPolicy Bypass, encoded commands, and hidden window execution.
- Generate alerts for Microsoft Defender exclusion additions, removals, and configuration changes.
- Implement detections for abnormal LSASS access, including OpenProcessApiCall and ReadProcessMemoryApiCall events.
- Monitor for recurring beaconing patterns, unusual outbound connections, and repeated health-check style communications.
- Enable credential protection controls and restrict unnecessary access to LSASS memory.

---

## 🧾 Final Assessment

The investigation confirmed a successful compromise of azwks-phtg-01 through the use of valid credentials consistent with Password Reuse. Following initial access, the operator deployed HealthCloud-themed tooling, established multiple persistence mechanisms, implemented defense evasion techniques, and maintained command-and-control communications through redundant beacon channels. Analysis further confirmed credential-access activity through elevated LSASS access and successful LSASS memory reads consistent with credential dumping behavior. The findings demonstrate a multi-stage intrusion involving persistence, defense evasion, command-and-control, and credential-access techniques, providing high confidence that the operator achieved and maintained post-compromise control of the host.

---

## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

