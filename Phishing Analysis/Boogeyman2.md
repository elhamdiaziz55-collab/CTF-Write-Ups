
# Boogeyman 2

## Overview

In this challenge, we analyze the new tactics, techniques, and procedures (TTPs) of the threat group known as **Boogeyman**.

**Provided artifacts:**
- A copy of the phishing email
- A memory dump of the victim's workstation

---

## Questions & Answers

### 1. What email address was used to send the phishing email?

Open the email file using any mail client (Gmail, Outlook, etc.), then inspect the source code. The sender's address can be retrieved from the `From:` header.

**Answer:** `westaylor23@outlook.com`

---

### 2. What is the email address of the victim employee?

Using the same approach as question 1, look for the `To:` header in the email source.

**Answer:** `maxine.beck@quicklogisticsorg.onmicrosoft.com`

---

### 3. What is the name of the malicious attachment?

Scrolling through the email source code reveals the following headers:

```
Content-Type: application/msword; name="Resume_WesleyTaylor.doc"
Content-Description: Resume_WesleyTaylor.doc
Content-Disposition: attachment; filename="Resume_WesleyTaylor.doc"; size=64000;
    creation-date="Sun, 20 Aug 2023 18:19:13 GMT";
    modification-date="Sun, 20 Aug 2023 18:19:20 GMT"
Content-Transfer-Encoding: base64
```

The attachment is a Word document encoded in Base64. It can be decoded using CyberChef to extract the original `.doc` file.

**Answer:** `Resume_WesleyTaylor.doc`

---

### 4. What is the MD5 hash of the malicious document?
![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-11%20201711.png)  
**Answer:** `52c4384a0b9e248b95804352ebec6c5b`

---

### 5. What URL is used to download the Stage 2 payload based on the document's macro?

To analyze the macro, we use **olevba**, a tool from the `oletools` suite that extracts VBA macros from Office documents, detects suspicious behaviors, and identifies Indicators of Compromise (IOCs).

```bash
olevba ~/Downloads/download.doc
```
![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-11%20210954.png)  
The output reveals two VBA macros: `ThisDocument.cls` (empty) and `NewMacros.bas`. The `NewMacros.bas` module contains the malicious script.

**How the vba script works:**
- The macro runs automatically when the document is opened, because of `Sub AutoOpen()`.
- It sends a GET request to the `files.boogeymanisback.lol` domain to download `update.png` (the attacker disguised the file with a `.png` extension to evade detection).
- The response is saved to `C:\ProgramData\update.js`.
- A Shell object is then created to execute the downloaded JavaScript file.

**Answer:** `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`

---

### 6. What is the name of the process that executed the Stage 2 payload?

**Answer:** `wscript.exe`

---

### 7. What is the full file path of the malicious Stage 2 payload?

Based on the macro code: `.SaveToFile spath & "\update.js", 2` — where `spath` is set to `C:\ProgramData`.

**Answer:** `C:\ProgramData\update.js`

---

### 8. What is the PID of the process that executed the Stage 2 payload?

To find the process ID of `wscript.exe`, we use the `windows.pslist.PsList` Volatility plugin to list all processes present in the memory dump (`WKSTN-2961.raw`):

```bash
vol -f WKSTN-2961.raw windows.pslist.PsList
```
![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-11%20213146.png)  

The output confirms the following process chain:

```
WINWORD.exe (PID: 1124)  →  wscript.exe (PID: 4260)  →  updater.exe (PID: 6216)
```

**Answer:** `4260`

---

### 9. What is the parent PID of the process that executed the Stage 2 payload?

Based on the process tree above, `wscript.exe` (PID 4260) was spawned by `WINWORD.exe`.

**Answer:** `1124`

---

### 10. What URL is used to download the malicious binary executed by the Stage 2 payload?

The `update.js` file was extracted from the memory dump. Its source code shows that it makes a GET request to the same domain as before, saves the response as `updater.exe`, and then executes it.  
To trace the origin of `updater.exe`, we need to extract and read the `update.js` file directly from memory.

**Step 1 — Find the virtual address of the file using `windows.filescan`:**

We scan the memory dump for all file objects and filter by the keyword `update` to locate the file in memory:

```bash
vol -f WKSTN-2961.raw windows.filescan | grep 'update'
```

This returns the virtual address of `update[1].png` (the cached version of `update.js`) along with its memory offset.

**Step 2 — Dump the file using `windows.dumpfiles` with the virtual address:**

```bash
vol -f WKSTN-2961.raw windows.dumpfiles --virtaddr 0xe58f836edc60
```

This extracts the file from memory and saves it locally as a `.dat` file.

![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-11%20220821.png)  
![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-11%20221813.png)  

**Answer:** `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`

---

### 11. What is the PID of the malicious process used to establish the C2 connection?

We scan all network connections and filter for activity related to `updater.exe`:

```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan
```
![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-12%20062344.png)  

**Answer:** `6216`

---

### 12. What is the full file path of the malicious process used to establish the C2 connection?

We use "vol -f WKSTN-2961.raw windows.cmdline.CmdLine"  to get the complete commandLine and arguments for each process .  

![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-12%20071717.png)  
**Answer:** `C:\Windows\Tasks\updater.exe`

---

### 13. What is the IP address and port of the C2 connection initiated by the malicious binary?

From the network scan output, the attacker uses HTTP tunneling over port 8080 to communicate with `updater.exe`.  

![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-12%20062344.png)  
**Answer:** `128.199.95.189:8080`

---

### 14. What is the full file path of the malicious email attachment based on the memory dump?

We use the `windows.cmdline.CmdLine` plugin to retrieve the complete command and arguments for each process:

```bash
vol -f WKSTN-2961.raw windows.cmdline.CmdLine
```

**Answer:** `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`

---

### 15. What is the full command used by the attacker to maintain persistent access?

We use the `strings` command on the memory dump and grep for `schtasks`, since `schtasks.exe` is a legitimate Windows utility used to create and manage scheduled tasks:

```bash
strings WKSTN-2961.raw | grep -i "schtasks"
```

![Using md5sum command to compute the md5 hash](images/Capture%20d’écran%202026-06-12%20073814.png)  

The attacker implanted a scheduled task shortly after establishing the C2 callback.

**Answer:**

```
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
```

This command creates a daily scheduled task named `Updater` that silently runs a PowerShell one-liner. The script reads a Base64-encoded payload from the registry key `HKCU:\Software\Microsoft\Windows\CurrentVersion` (value: `debug`) and executes it in memory using `IEX` (Invoke-Expression) — a classic fileless persistence technique.
