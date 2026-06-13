
# ItsyBitsy — TryHackMe Write-up

## Scenario

During routine SOC monitoring, Analyst John received an alert from the IDS indicating potential C2 (Command and Control) communication originating from a workstation belonging to **Browne**, a user in the HR department. A suspicious file was accessed on that machine, containing a malicious pattern in the format `THM{________}`.

A week's worth of HTTP connection logs was collected for investigation. Due to limited resources, only these connection logs were available, and they were ingested into the **`connection_logs`** index in Kibana.

---

## Questions & Answers

### 1. How many events were returned for the month of March 2022?

**Approach:**
In Kibana, select the `connection_logs` index and set the time range to:

- **From:** `Mar 1, 2022 @ 00:00:00.000`
- **To:** `Mar 31, 2022 @ 23:30:00.000`

Apply the filter.

> **Answer: `1482`**

---

### 2. What is the source IP address of the infected machine?

**Approach:**
To begin the investigation, add the following fields to the Kibana table view to capture all meaningful HTTP connection attributes:

```
source_ip, source_port, destination_ip, destination_port,
host, method, request_body_len, response_body_len,
status_code, status_msg, user_agent, uri
```

Inspecting the `user_agent` field reveals two distinct user agents in the logs. One of them is **BITSAdmin**.

> **What is BITSAdmin?**
> `bitsadmin` is a built-in Windows command-line utility that manages file transfer jobs using **BITS** (Background Intelligent Transfer Service). It is deprecated by Microsoft in favor of PowerShell cmdlets. Security teams closely monitor it because threat actors frequently abuse it to download malware or exfiltrate data stealthily.

Filtering by the `bitsadmin` user agent returns **two log entries**. Examining those entries reveals that the traffic originates from user Browne's machine and is directed toward **pastebin.com**, a well-known site commonly abused as a C2 drop zone by attackers.

![](images/Capture%20d’écran%202026-06-13%20145900.png)  
![](images/Capture%20d’écran%202026-06-13%20150007.png)  
> **Answer: `192.166.65.54`**

---

### 3. What is the name of the legitimate Windows binary used to download the file?

As identified in the previous step, the attacker leveraged a native Windows tool to blend in with normal system activity.

> **Answer: `bitsadmin`**

---

### 4. What is the name of the file-sharing site that also acted as the C2 server?

Looking at the `host` field in the filtered log entries reveals the destination the infected machine was communicating with.

> **Answer: `pastebin.com`**

---

### 5. What is the full URL of the C2 server the infected host connected to?

Inspecting the `uri` field in the BITSAdmin-filtered logs reveals the specific path: `/yTg0Ah6a`. Combined with the host, the full URL is:

> **Answer: `pastebin.com/yTg0Ah6a`**

---

### 6. What is the name of the file accessed on the file-sharing site?

Navigating to `https://pastebin.com/yTg0Ah6a` in a browser displays the content of the paste, which reveals both the file name and the flag.

![](images/Capture%20d’écran%202026-06-13%20153232.png)  

> **Answer: `secret.txt`**

---

### 7. What is the secret code found in the file?

> **Answer: `THM{SECRET__CODE}`**

---

## Room Link

[ItsyBitsy — TryHackMe](https://tryhackme.com/room/itsybitsy)

