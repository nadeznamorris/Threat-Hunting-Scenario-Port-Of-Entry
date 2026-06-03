# Threat-Huntung-Scenario-Port-Of-Entry

## Executive Summary  

Azuki Import/Export Trading Co. suffered a targeted corporate espionage intrusion resulting in the confirmed exfiltration of sensitive supplier contracts and pricing data. The attack began with unauthorised Remote Desktop Protocol (RDP) access using compromised IT administrator credentials (`kenji.sato`) originating from external IP `88.97.178.12`. The threat actor demonstrated advanced post-exploitation tradecraft — deploying a renamed Mimikatz binary for credential harvesting, abusing native Windows utilities to evade defences, and establishing persistent access via a scheduled task and a hidden backdoor account. Exfiltrated data was staged into a ZIP archive and exfiltrated over Discord, bypassing conventional data loss prevention controls. The attacker subsequently cleared Security event logs to hinder forensic investigation. The scope of compromise extends beyond `AZUKI-SL`, with confirmed lateral movement to internal host `10.1.0.188`. The intrusion is consistent with a financially motivated adversary engaged in competitive intelligence theft.


## 1. Findings

- **Host:** `azuki-sl` (Windows endpoint)
- **Telemetry:** Microsoft Defender For Endpoint:
  - `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`
- **Timeframe:** 2025-11-19 → 2025-11-20 (UTC)

---

***FLAG 1 - INITIAL ACCESS - Remote Access Source***

**Objective :** Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**Flag Value :** `88.97.178.12`

```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, ActionType, RemoteDeviceName, RemoteIP
| order by Timestamp asc
```
<img width="836" height="77" alt="image" src="https://github.com/user-attachments/assets/37dec1d7-de77-40c3-9139-187ea591e999" />

---

***FLAG 2 - INITIAL ACCESS - Compromised User Account***

**Objective :** Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

**Flag Value :** `kenji.sato`

```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, ActionType, RemoteDeviceName, RemoteIP
| order by Timestamp asc
```
<img width="836" height="77" alt="image" src="https://github.com/user-attachments/assets/d6af9485-36ec-4fd6-afaa-c1711acab8d3" />

---

***FLAG 3: DISCOVERY - Network Reconnaissance***

**Objective :** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**Flag Value :** `"ARP.EXE" -a`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("arp", "ipconfig", "nbtstat")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, AccountName
| order by Timestamp asc 
```
<img width="849" height="70" alt="image" src="https://github.com/user-attachments/assets/7ef75c80-c662-44c7-94e7-540f123a316b" />

---

***FLAG 4: DEFENCE EVASION - Malware Staging Directory***

**Objective :** Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**Flag Value :** `C:\ProgramData\WindowsCache`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "attrib"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="872" height="81" alt="image" src="https://github.com/user-attachments/assets/2710c448-aa1e-4583-ad4a-ec08f3f0b91a" />

---

***FLAG 5: DEFENCE EVASION - File Extension Exclusions***

**Objective :** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**Flag Value :** `3`

```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("\\Exclusions\\Extensions")
| project Timestamp, DeviceName, ActionType, RegistryValueName, RegistryKey
| order by Timestamp asc 
```
<img width="1283" height="148" alt="Flag 5" src="https://github.com/user-attachments/assets/d0d40c2c-876c-4d78-8e19-5cfec1335fee" />

---

***FLAG 6: DEFENCE EVASION - Temporary Folder Exclusion***

**Objective :** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**Flag Value :** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("Paths")
| project Timestamp, DeviceName, ActionType, RegistryValueName, RegistryKey, InitiatingProcessFolderPath
| order by Timestamp asc
```
<img width="1366" height="83" alt="image" src="https://github.com/user-attachments/assets/4a98ee39-2742-4757-866f-e70fd9acfcd6" />

---

***FLAG 7: DEFENCE EVASION - Download Utility Abuse***

**Objective :** Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**Flag Value :** `certutil.exe`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("appinstaller.exe", "bitsadmin.exe", "certoc.exe", "certreq.exe", "certutil.exe", "cmd.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="952" height="96" alt="image" src="https://github.com/user-attachments/assets/f66c0e24-887d-4fcc-9e79-85963a1e19cb" />

---

***FLAG 8: PERSISTENCE - Scheduled Task Name***

**Objective :** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Flag Value :** `Windows Update Check`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("schtasks")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc 
```
<img width="947" height="72" alt="image" src="https://github.com/user-attachments/assets/49cba3a9-d00b-408c-b61e-8093cfed8b53" />

---

***FLAG 9: PERSISTENCE - Scheduled Task Target***

**Objective :** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Flag Value :** `C:\ProgramData\WindowsCache\svchost.exe`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("schtasks")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="1158" height="85" alt="image" src="https://github.com/user-attachments/assets/f0593eca-2b9b-43a5-ae52-fe9f3d49d6b2" />

---

***FLAG 10: COMMAND & CONTROL - C2 Server Address***

**Objective :** Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**Flag Value :** `78.141.196.6`

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp asc 
```
<img width="857" height="72" alt="image" src="https://github.com/user-attachments/assets/df623bb2-712a-4bb4-a593-3430b857fe0e" />

---

***FLAG 11: COMMAND & CONTROL - C2 Communication Port***

**Objective :** C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**Flag Value :** `443`

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```
<img width="1170" height="82" alt="image" src="https://github.com/user-attachments/assets/aeda27fd-43ff-4b04-b832-513d2e79a2d2" />

---

***FLAG 12: CREDENTIAL ACCESS - Credential Theft Tool***

**Objective :** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**Flag Value :** `mm.exe`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".exe")
| where ProcessVersionInfoProductName has_any ("Mimikatz", "LaZagne", "lsassy", "nanodump", "ProcDump")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, ProcessCommandLine
| order by Timestamp asc
```
<img width="981" height="75" alt="image" src="https://github.com/user-attachments/assets/fb28222f-6813-4740-a594-3b9271414ef9" />

---

***FLAG 13: CREDENTIAL ACCESS - Memory Extraction Module***

**Objective :** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**Flag Value :** `sekurlsa::logonpasswords`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".exe")
| where ProcessVersionInfoProductName has_any ("Mimikatz", "LaZagne", "lsassy", "nanodump", "ProcDump")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, ProcessCommandLine
| order by Timestamp asc
```
<img width="981" height="75" alt="image" src="https://github.com/user-attachments/assets/fb28222f-6813-4740-a594-3b9271414ef9" />

---

***FLAG 14: COLLECTION - Data Staging Archive***

**Objective :** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**Flag Value :** `export-data.zip`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".zip")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="990" height="71" alt="image" src="https://github.com/user-attachments/assets/cbffe86e-5bbf-4b5c-b406-fbde312920a9" />

---

***FLAG 15: EXFILTRATION - Exfiltration Channel***

**Objective :** Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**Flag Value :** `discord`

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessAccountName == "kenji.sato"
| where RemotePort == "443"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```
<img width="878" height="72" alt="image" src="https://github.com/user-attachments/assets/162e7ca2-acae-458f-8523-8d4d6c8a4670" />

---

***FLAG 16: ANTI-FORENSICS - Log Tampering***

**Objective :** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**Flag Value :** `Security`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine
| order by Timestamp asc 
```
<img width="743" height="73" alt="image" src="https://github.com/user-attachments/assets/48aefb5c-e7ce-4078-a2d1-96bee5ef7042" />

---

***FLAG 17: IMPACT - Persistence Account***

**Objective :** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**Flag Value :** `support`

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("add")
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine
| order by Timestamp asc 
```
<img width="798" height="95" alt="image" src="https://github.com/user-attachments/assets/144a0987-fcc6-4efb-bba4-d139f00e4cd8" />

---

***FLAG 18: EXECUTION - Malicious Script***

**Objective :** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**Flag Value :** `wupdate.ps1`

```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath has_any ("temp", "Temp")
| where FileName !startswith "__PSScriptPolicyTest"
| where FileName has_any (".ps1")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp asc  
```
<img width="1197" height="82" alt="image" src="https://github.com/user-attachments/assets/7584fead-ffa4-4af7-a122-2bc207ae89c6" />

---

***FLAG 19: LATERAL MOVEMENT - Secondary Target***

**Objective :** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**Flag Value :** `10.1.0.188`

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp desc 
```
<img width="667" height="72" alt="image" src="https://github.com/user-attachments/assets/fa97cb33-7f8b-4a6e-a3c4-9592e37a133c" />

---

***FLAG 20: LATERAL MOVEMENT - Remote Access Tool***

**Objective :** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**Flag Value :** `mstsc.exe`

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc 
```
<img width="667" height="72" alt="image" src="https://github.com/user-attachments/assets/fa97cb33-7f8b-4a6e-a3c4-9592e37a133c" />

---
