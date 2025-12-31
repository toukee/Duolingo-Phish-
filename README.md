# Duolingo-Phish!

## Objective

To investigate a phishing email that successfully bypassed security filtering controls and reached the user’s inbox. This project demonstrates my ability to analyze email headers, identify spoofing indicators, evaluate attachment and link safety, and document findings using a structured SOC‑style workflow.
It also highlights my growing experience in recognizing social engineering patterns and validating suspicious emails with security tools.


### Skills Learned

• 	Identifying phishing indicators in email content and sender metadata
• 	Reviewing email headers for anomalies (Return‑Path, SPF, DKIM, domain mismatch)
• 	Understanding how phishing emails bypass filtering controls
• 	Evaluating suspicious links and attachments safely
• 	Using online tools to validate domains, URLs, and file hashes
• 	Documenting findings clearly using a SOC‑style investigation format
• 	Strengthening ability to distinguish legitimate vs. spoofed communication
• 	Mapping activity to MITRE ATT&CK techniques (Phishing, Initial Access)
• 	Improving triage workflow: verify → analyze → conclude

### Tools Used

- Microsoft Defender XDR – alert context, email entity analysis, and message trace review
- Email Header Analysis Tools – reviewing SPF, DKIM, and sender metadata
- VirusTotal – URL and attachment reputation checks
- CyberChef – decoding, URL parsing, and safe inspection
- ANY.RUN – dynamic analysis of suspicious links or files
- Notepad++ – organizing notes and reviewing extracted data
- Browser DevTools – inspecting URLs and redirect behavior
- Windows Defender – validating local endpoint safety

## Steps


# Case Summary

On October 30, 2025, a targeted phishing campaign successfully compromised the contractor workstation `mts-contractorpc2`. The attacker delivered a malicious email from `colla@duolingo-team.com` to `inquiry@mydfir.com`, spoofing a partnership offer and embedding a payload named `Duolingo - YouTube Partnership.exe`. The user executed the file manually, initiating the attack chain.

Shortly after, the attacker established an **interactive RDP session** from external IP `170.10.4.118`, gaining full access to the host. Within minutes, they launched PowerShell commands, manipulated processes, and executed browser-related binaries disguised as `.tmp` Chromium clones. These clones opened local web server URLs on `127.0.0.1:8000`, likely simulating credential capture or browser session manipulation.

At **15:19:03 UTC**, suspicious process reparenting was detected, indicating stealthy execution or injection. The attacker accessed browser credential files (`Web Data`, `Login Data`), though no confirmed exfiltration occurred. Later, an **unknown internal IP `10.0.0.8`** was observed executing remote commands on the compromised host, suggesting lateral movement or internal pivoting.

Multiple detections were triggered, including alerts for process anomalies, execution of unsigned binaries, and activity from an unrecognized internal asset. The attacker’s session ended at **15:35:22 UTC**, with no further activity from either IP.

While no data was confirmed exfiltrated, the attacker demonstrated capabilities in phishing, remote access, process manipulation, and internal reconnaissance. The incident highlights the importance of behavioral detections, asset inventory hygiene, and credential protection.

# Analysts

Analysts: Toukee Vang

# Initial Access

On October 30, 2025, at 3:08:15 PM UTC, the attacker gained access to `mts-contractorpc2` via RDP from IP address `170.10.4.118`. This access was enabled by a phishing email sent earlier that day to `inquiry@mydfir.com`, impersonating a Duolingo representative. The email originated from `colla@duolingo-team.com`, relayed through `mx.zohomail.eu` with IP `136.143.171.19`, which geolocates to the Netherlands — outside the expected country for the recipient’s network. The message offered $5,000 in compensation for a video collaboration, enticing the recipient to download and execute a malicious payload disguised as a partnership file

**Phishing Email Delivered**

- Recipient: `inquiry@mydfir.com`
- Sender: `colla@duolingo-team.com`
- Mailer: `mx.zohomail.eu`
- Sender IP: `136.143.171.19` (Netherlands)
- Subject: *Duolingo Collaboration proposal #8063*
- Lure: $5,000 offer (50% upfront, 50% after video publication)

**Malicious Payload Execution**

- File: `Duolingo - YouTube Partnership.exe`
- Location: `C:\Users\contractor\Downloads\`
- SHA256: `3e3ee8ca0ae75aa9bc642c4ee2f924ec422bd714aa8e3361a2e6d61233644988`
- Execution Time: October 30, 2025 at 1:40:53 PM UTC

Remote Access Gained

- Target: `mts-contractorpc2`
- User: `contractor`
- Attacker IP: `170.10.4.118`
- RDP Access Time: October 30, 2025 at 3:08:15 PM UTC

# Execution

The earliest recorded execution of `Duolingo - YouTube Partnership.exe` occurred on **October 30, 2025 at 1:40:53 PM UTC** on `mts-contractorpc2`, initiated via command line by the `contractor` user. Upon execution, the payload spawned **four processes** and accessed **five files**, including browser credential stores. During remote access from IP `170.10.4.118`, the attacker launched `OOBE-Maintenance.exe`, `rdpclip.exe`, `openwith.exe`, and re-executed the payload — with the first three being legitimate binaries native to the environment.

The attacker accessed Chrome’s credential store, opening **three `Web Data` files** and **two `Login Data` files**, likely to extract saved passwords and cookies. Shortly after, **temporary Chromium instances** were launched with flags that opened **local web server URLs on port 8000**, a technique commonly used to simulate login interfaces or exfiltrate browser data.

Additionally, an **unknown internal IP `10.0.0.8`** was observed executing remote commands on `mts-contractorpc2`. This IP was **not part of the organization’s asset inventory** and was only active between **3:23:25 PM and 3:35:22 PM UTC**, suggesting a pivot or internal compromise that disappeared post-attack.

**1:40:53 PM UTC**

- `Duolingo - YouTube Partnership.exe` first executed locally on `mts-contractorpc2` by user `contractor`

**3:08:03–3:08:22 PM UTC**

- Attacker established RDP session from IP `170.10.4.118`
- Remote execution of:
- `OOBE-Maintenance.exe`
- `rdpclip.exe` (clipboard sharing)
- `openwith.exe`
- `Duolingo - YouTube Partnership.exe` (re-executed)

**3:13:46 PM UTC**

- Attacker opened Chrome and downloaded:
- `Duolingo - YouTube Partnership.zip`
- `7z2501-x64.exe`
- Attempted but failed download: `Unconfirmed 147471.crdownload`

**3:18:55 PM UTC**

- Remote execution of payload (PID: 6900)
- `rdpclip.exe` (PID: 5764) also active
- Browser credential files accessed:
- 3 × `Web Data`
- 2 × `Login Data`

**3:19:03 PM UTC**

- **Suspicious process reparenting** detected — likely process injection or hollowing

**3:19:13–3:19:54 PM UTC**

- Temporary Chromium instances launched:
    - `chr336F.tmp`, `chr8190.tmp`, `chrCFC1.tmp`
- Opened local URLs on port `8000`:
- `http://127.0.0.1:8000/f2532e43/787715fc`
- `http://127.0.0.1:8000/f2532e43/f17f4c42`

**3:23:25–3:35:22 PM UTC**

- Unknown internal IP `10.0.0.8` observed executing remote commands on `mts-contractorpc2`
- Not part of known asset inventory
- Disappeared from network after this window

# Persistence

There is **no confirmed evidence of long-term persistence mechanisms** established during this attack. The attacker operated within an active RDP session and executed payloads manually, but did not deploy scheduled tasks, registry autoruns, services, or startup entries that would ensure re-entry after reboot. However, the presence of temporary Chromium clones and local web server activity suggests **short-term interactive persistence** during the session, likely for credential harvesting and browser manipulation.

# Privilege Escalation

There is **no confirmed evidence of privilege escalation** during this attack. The attacker gained access using valid credentials for the `contractor` account on `mts-contractorpc2`, which already had sufficient privileges to execute payloads, access browser credential stores, and launch remote processes. No signs of token manipulation, UAC bypass, or elevation to SYSTEM-level access were observed. All activity remained within the context of the logged-in user session.

# Defense Evasion

The attacker employed several defense evasion techniques during the session on `mts-contractorpc2`, including the use of **legitimate Windows binaries** for remote execution and **suspicious process reparenting** to obscure execution. Likely the attacker interacted with browser-related files and launched temporary Chromium clones, there was **no confirmed access to credential stores**. However, the anomalous behavior — including process manipulation and use of `.tmp` executables — did trigger alerts and incidents, allowing investigation suspect that there was likely credential exfiltration. 

# Credential Access

There is **no confirmed evidence of credential theft or direct access to browser credential stores** during this incident. While the attacker interacted with browser-related files such as `Web Data` and `Login Data`, logs did not confirm that these files were read, dumped, or exfiltrated. However, the attacker did launch temporary Chromium clones and opened local web server URLs, which may have been designed to likely data was exfiltrated. These behaviors suggest an **attempted credential harvesting**, but without forensic confirmation of successful extraction

# Discovery

The attacker performed **limited discovery activity** during the session on `mts-contractorpc2`, primarily focused on identifying browser-stored credentials and interacting with local files. There is **no evidence of broader network enumeration, system information gathering, or account discovery**. However, the presence of an **unknown internal IP (`10.0.0.8`)** executing remote commands suggests that the attacker may have already had visibility into the environment or leveraged a compromised internal asset to pivot directly to the target system.

# Lateral Movement

There is **evidence of lateral movement** during the attack, primarily through the use of an **unknown internal IP address (`10.0.0.8`)** that executed remote commands on `mts-contractorpc2`. This IP was not part of the organization’s asset inventory and was only active for a short window between **3:23:25 PM and 3:35:22 PM UTC**. The attacker initially accessed the target system via RDP from an external IP (`170.10.4.118`), but later transitioned to using `10.0.0.8`, suggesting a pivot from an external foothold to an internal asset — possibly compromised earlier or injected into the network.

# Command and Control

The attacker established **interactive command and control** through an active **RDP session** into `mts-contractorpc2`, originating from external IP `170.10.4.118`. This session allowed the attacker to execute payloads, launch processes, and interact with the system in real time. Later in the attack, an **unknown internal IP (`10.0.0.8`)** was observed executing remote commands, suggesting a pivot to an internal foothold or compromised asset. Additionally, the attacker launched **temporary Chromium clones** that opened local web server URLs on port 8000, which may have served as a lightweight C2 channel for browser manipulation or credential harvesting. No outbound beaconing or external C2 infrastructure was detected beyond the RDP connection.

# Exfiltration

There is **no confirmed evidence of successful data exfiltration** during this incident. While the attacker accessed browser-related files and launched temporary Chromium clones that interacted with a local web server on port 8000, logs did not show outbound data transfers, uploads, or external callbacks. The use of `127.0.0.1` URLs suggests that any credential harvesting or data staging occurred locally within the session. Additionally, the attacker operated within an RDP session and used an unknown internal IP (`10.0.0.8`), but no signs of external data movement were observed.

# Impact

The attacker’s actions resulted in **unauthorized access to a contractor workstation**, remote execution of a malicious payload, and interaction with browser-related files that may contain sensitive data. Although no confirmed credential theft or data exfiltration occurred, the attacker demonstrated the capability to manipulate processes, launch local web servers, and pivot internally — all of which pose a significant risk to confidentiality and trust. The presence of an unknown internal IP (`10.0.0.8`) and the use of process reparenting indicate a **moderate operational impact**, with potential for escalation had the session persisted longer or reached additional assets.

# Timeline

**09:48:54 UTC** — A phishing email was received from `colla@duolingo-team.com` to `inquiry@mydfir.com`, routed through `mx.zohomail.eu` (IP: `136.143.171.19`).

**13:40:53 UTC** — The payload `Duolingo - YouTube Partnership.exe` was executed locally on `mts-contractorpc2` by user `contractor` via command line.

**15:08:03 UTC** — An RDP session was initiated from external IP `170.10.4.118` to `mts-contractorpc2`.

**15:08:15 UTC** — The attacker successfully logged in via RDP using the `contractor` account.

**15:08:22 UTC** — Last known RDP activity from external IP `170.10.4.118` was recorded. Associated processes included `powershell.exe` (PID: 1388 & 11084) and `rdpclip.exe`.

**15:13:46 UTC** — The attacker opened Chrome and downloaded `Duolingo - YouTube Partnership.zip`, `7z2501-x64.exe`, and attempted to download `Unconfirmed 147471.crdownload`, which failed.

**15:18:55 UTC** — Remote execution of `Duolingo - YouTube Partnership.exe` (PID: 6900) occurred, alongside `rdpclip.exe` (PID: 5764).

**15:19:03 UTC** — Suspicious process reparenting was detected, indicating possible process injection or hollowing.

**15:19:13 UTC** — Chromium clone `chr336F.tmp` was launched and opened `http://127.0.0.1:8000/f2532e43/787715fc`.

**15:19:34 UTC** — Chromium clone `chr8190.tmp` was launched and opened `http://127.0.0.1:8000/f2532e43/f17f4c42`.

**15:19:54 UTC** — Chromium clone `chrCFC1.tmp` was launched and reopened `http://127.0.0.1:8000/f2532e43/787715fc`.

**15:23:25 UTC** — An unknown internal IP `10.0.0.8` was first observed executing remote commands on `mts-contractorpc2`.

**15:35:22 UTC** — The unknown internal IP `10.0.0.8` was last seen and disappeared from the network.

# Diamond Model

<img width="1488" height="803" alt="image" src="https://github.com/user-attachments/assets/2bd1f3e8-977e-45b2-9b61-c8d3a3eb10c0" />


# Indicators

Indicators of Compromise (IOCs)

Host & Process Artifacts

- Hostname: `mts-contractorpc2`
- Executed Payload: `Duolingo - YouTube Partnership.exe` `SHA256:3e3ee8ca0ae75aa9bc642c4ee2f924ec422bd714aa8e3361a2e6d61233644988`
- Suspicious Processes:
    - `rdpclip.exe` (PID: 5764)
    - `powershell.exe` (PID: 1388 & 11084)
    - Chromium clones: `chr336F.tmp`, `chr8190.tmp`, `chrCFC1.tmp`
- Process Reparenting Detected: **15:19:03 UTC**

Network Indicators

- External RDP Source IP: `170.10.4.118`
- Internal Pivot IP: `10.0.0.8` (active from **15:23:25 UTC to 15:35:22 UTC**)
- Local Web Server URLs:
- `http://127.0.0.1:8000/f2532e43/787715fc`
- `http://127.0.0.1:8000/f2532e43/f17f4c42`

File & Download Artifacts

- Downloaded Files:
    - `Duolingo - YouTube Partnership.zip` `SHA256:7e591a39a5a228dcd38f8c5fa0ebbbafa88c7f35caf9b6acf5dec7a632c52ffd`
    - `7z2501-x64.exe` `SHA256:78afa2a1c773caf3cf7edf62f857d2a8a5da55fb0fff5da416074c0d28b2b55f`
    - `Unconfirmed 147471.crdownload` (failed) `SHA256:78afa2a1c773caf3cf7edf62f857d2a8a5da55fb0fff5da416074c0d28b2b55f`
- Accessed Browser Files:
- `Web Data` (×3)
- `Login Data` (×2)

Email Indicators

- Phishing Sender: `colla@duolingo-team.com`
- Recipient: `inquiry@mydfir.com`
- Mail Server: `mx.zohomail.eu`
- Email Source IP: `136.143.171.19`
- Subject: Likely themed around “Duolingo – YouTube Partnership”

# MITRE ATT&CK

**Initial Access**

- **T1566.001 – Phishing: Spearphishing Attachment**
The attacker delivered a phishing email with a malicious attachment to `inquiry@mydfir.com`.

**Execution**

- **T1204.002 – User Execution: Malicious File**
The user manually executed `Duolingo - YouTube Partnership.exe` on the contractor workstation.
- **T1059.001 – Command and Scripting Interpreter: PowerShell**
PowerShell processes (PID: 1388 & 11084) were launched during the RDP session.

**Persistence**

- **T1021.001 – Remote Services: Remote Desktop Protocol (RDP)**
The attacker maintained access to the host via RDP from external IP `170.10.4.118`.

**Defense Evasion**

- **T1036 – Masquerading**
Chromium clones were disguised as `.tmp` files to evade detection.
- **T1055 – Process Injection**
Process reparenting was detected, suggesting injection or hollowing techniques.
- **T1218 – Signed Binary Proxy Execution**
LOLBins like `openwith.exe`, `OOBE-Maintenance.exe`, and `rdpclip.exe` were used to execute code under trusted binaries.

**Discovery**

- **T1083 – File and Directory Discovery**
The attacker accessed browser-related files (`Web Data`, `Login Data`) in search of stored credentials.

**Lateral Movement**

- **T1021 – Remote Services**
The attacker pivoted internally using an unknown IP (`10.0.0.8`) to execute remote commands on the target host.

**Command and Control**

- **T1219 – Remote Access Software**
RDP was used as the primary C2 channel for interactive control.
- **T1071.001 – Application Layer Protocol: Web Protocols**
Chromium clones opened local URLs on `127.0.0.1:8000`, possibly simulating browser-based C2 or credential capture.

**Collection**

- **T1056.007 – Input Capture: Browser Session Collection**
The attacker attempted to access browser credential stores, though no confirmed exfiltration occurred

# Root Cause Analysis

The incident originated from a **targeted phishing email** that successfully bypassed email filtering controls and reached the user `contractor` on `mts-contractorpc2`. Disguised as a legitimate partnership offer from Duolingo, the email enticed the user to manually execute a malicious file named `Duolingo - YouTube Partnership.exe`. This action granted the attacker an initial foothold and enabled them to establish an interactive **Remote Desktop Protocol (RDP)** session from an external IP.

Through this access, the attacker launched additional payloads, manipulated processes, and initiated suspicious browser activity. The intrusion later escalated with remote command execution from an unknown internal IP, indicating a potential lateral movement attempt.

In summary, the **root cause** was a **phishing email that evaded detection and led to user-executed malware**, resulting in unauthorized remote access and internal compromise. Although several behavioral detections were triggered after the fact, stronger email filtering, user awareness, and asset visibility could have prevented or limited the impact of the attack.

# Detection Gap Analysis

The detection gap analysis for the October 30, 2025 incident highlights several missed opportunities to contain the attack earlier, despite successful endpoint detection. The phishing email from `colla@duolingo-team.com` bypassed filtering controls and reached the user without triggering alerts for spoofed domains or suspicious attachments. Shortly after, the attacker established an RDP session from external IP `170.10.4.118`, gaining interactive access to `mts-contractorpc2` before the malicious payload (`Duolingo - YouTube Partnership.exe`) was executed. Although the endpoint successfully flagged the payload execution, the host was not immediately isolated, allowing the attacker to continue launching PowerShell commands, accessing browser credential files, and executing Chromium clones disguised as `.tmp` binaries. Additionally, the internal pivot via unknown IP `10.0.0.8` went undetected initially due to gaps in asset inventory and lateral movement monitoring. While behavioral detections such as process reparenting and anomalous binary execution were triggered, the delay in containment and lack of visibility into early-stage access and internal asset hygiene contributed to extended attacker dwell time and increased risk.

# Recommendation

To reduce the risk of similar incidents in the future, we recommend enhancing email security controls to better detect spoofed domains and malicious attachments, including stricter SPF/DKIM/DMARC enforcement and attachment sandboxing. Endpoint protection should be configured to automatically isolate hosts upon detection of high-risk behaviors, such as suspicious binary execution or process reparenting. External RDP access should be restricted by default, with multi-factor authentication and geolocation-based rules enforced for all remote sessions. Internal asset inventory must be continuously maintained to detect rogue devices like `10.0.0.8`, and lateral movement monitoring should be expanded to flag unauthorized remote command execution. Finally, access to browser credential stores should be monitored and protected, and incident response workflows should be reviewed to ensure alerts lead to timely containment actions.

# Detection Opportunities

Email Security

- **Enhance phishing detection** by implementing stricter SPF/DKIM/DMARC validation and enabling external sender warning banners.
- **Deploy attachment sandboxing** to detonate and analyze suspicious files before delivery.
- **Train users on phishing awareness**, especially around partnership-themed lures and spoofed domains.

Endpoint Protection

- **Enable automatic host isolation** upon detection of high-risk payloads or behavioral anomalies.
- **Strengthen behavioral detection rules** for process reparenting, LOLBin abuse, and browser credential access.
- **Implement application control policies** to block execution of unsigned or unapproved binaries.

Network & RDP Controls

- **Restrict external RDP access** by default and enforce geolocation-based rules.
- **Require multi-factor authentication (MFA)** for all remote sessions.
- **Alert on new or unrecognized internal IPs**, and monitor for lateral movement attempts.

Asset & Inventory Hygiene

- **Maintain an up-to-date asset inventory** to detect rogue or unmanaged devices like `10.0.0.8`.
- **Segment internal networks** to limit pivoting opportunities and contain threats.

Credential & Data Protection

- **Monitor access to browser credential stores** (`Web Data`, `Login Data`) and alert on unauthorized reads.
- **Encourage use of enterprise password managers** to reduce reliance on browser-stored credentials.

Incident Response & Logging

- **Tune SIEM correlation rules** to prioritize alerts involving RDP, PowerShell, and credential access.
- **Review alert-to-response latency** and ensure analysts are empowered to isolate hosts immediately upon detection.

# Appendix

email header
<img width="1147" height="446" alt="image" src="https://github.com/user-attachments/assets/cfb236d3-a29a-4f23-9693-e6f4eb0e6625" />

email body
<img width="1113" height="333" alt="image" src="https://github.com/user-attachments/assets/30b06460-60bf-40ea-8579-08cea290e3bd" />

email ip address
<img width="1064" height="604" alt="image" src="https://github.com/user-attachments/assets/de540079-c042-4e76-abbd-9f1dd0fbffc9" />

sandbox url from email

<img width="1079" height="635" alt="image" src="https://github.com/user-attachments/assets/c01bc1b9-f45b-4e1c-9b69-827b0464c2d6" />

sandbox url to link

<img width="1056" height="682" alt="image" src="https://github.com/user-attachments/assets/ef4b351e-87a1-49d6-874a-7381ef753e92" />

unknown signer to youtubepartnership.zip

<img width="531" height="1062" alt="image" src="https://github.com/user-attachments/assets/cd69ab7e-9257-486c-8bd1-10252efd23cf" />

unknow signer application

<img width="493" height="1034" alt="image" src="https://github.com/user-attachments/assets/73651038-6bf6-469a-94b5-8105fc962c2a" />

attcker setup internal opne server
<img width="1090" height="598" alt="image" src="https://github.com/user-attachments/assets/ff86b826-df7c-4990-bee0-77cbd1b186db" />











