# Splunk-SOC-Lab

Hands-on SIEM lab using Splunk Enterprise to investigate three real-world attack scenarios end-to-end — SSH brute-force, web-app compromise, and Linux privilege escalation - with MITRE ATT&CK mapping and production-ready detection engineering.

## Overview

A self-built Security Operations Center (SOC) home lab running Splunk Enterprise 10.4.3 on Kali Linux, used to conduct three complete investigations against publicly available attack datasets. Each investigation follows real SOC tiered workflow — Tier 1 triage tickets for fast escalation decisions, Tier 2 incident reports with full kill-chain reconstruction, and detection engineering deliverables (production-ready saved-search rules).

When an alert fires in a real SOC, the analyst has minutes to decide "is this real?" and hours to answer "what actually happened, what's the scope, how do we contain it?" This lab practices exactly that workflow, three times, across three different attack categories.

## Architecture
            ┌────────────────────────────────────────────────────────────────┐
            │                                                                │
            │   Kali Linux (rolling)                                         │
            │                                                                │
            │   Splunk Enterprise 10.4.3                                     │
            │   Installed at /opt/splunk                                     │
            │   Web UI: http://127.0.0.1:8000                                │
            │          │                                                     │
            │          │ Three indexes created                               │
            │          │                                                     │
            │    ──────┼──────────────────────                               │
            │          │            │            │                           │
            │          ▼            ▼            ▼                           │
            │      ssh_lab       botsv1      attack_data                     │
            │      index         index       index                           │
            │          │            │            │                           │
            │          ▼            ▼            ▼                           │
            │      SecRepo       BOTSv1      Splunk                          │
            │      auth.log      dataset     attack_data                     │
            │      86,839        955,807     108 events                      │
            │      events        events                                      │
            │          │            │            │                           │
            │          ▼            ▼            ▼                           │
            │      Invest #1    Invest #2    Invest #3                       │
            │      SSH brute-   Web-app      Linux privilege                 │
            │      force        compromise   escalation                      │
            │          │            │            │                           │
            │          ▼            ▼            ▼                           │
            │      Tier 1 Ticket + Tier 2 Report + Detection Rules           │
            │                                                                │
            └────────────────────────────────────────────────────────────────┘

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | 10.4.3 | SIEM — log storage, search, correlation |
| Splunk Stream | Bundled | Packet capture for HTTP metadata (BOTSv1) |
| Suricata | Bundled with BOTSv1 | IDS alerts as independent detection view |
| auditd | Linux kernel | System-call and process auditing |
| Git LFS | 3.7.1 | Large-file storage for attack_data repo |
| iplocation | Splunk built-in | GeoIP resolution for source IPs |
| rex, stats, timechart | Splunk SPL | Field extraction, aggregation, time-series |

## Infrastructure

| Component | Specification | Role |
|-----------|--------------|------|
| Host OS | Kali Linux (rolling) | Base operating system |
| SIEM | Splunk Enterprise 10.4.3 Free | Log ingestion, search, visualization |
| Storage | ~500MB used | Three indexes across three datasets |
| Auth | Local admin (zoro) | Splunk web + CLI access |

## Datasets Loaded

| Index | Source | Size | Events | Attack Type | Time Period |
|-------|--------|------|--------|-------------|-------------|
| `ssh_lab` | SecRepo public honeypot auth.log | 10 MB | 86,839 | SSH brute-force + scanning | Nov 30 – Dec 31, 2014 |
| `botsv1` | Splunk Boss of the SOC v1 | ~200 MB | 955,807 | Web-app compromise + defacement | Aug 10, 2016 |
| `attack_data` | Splunk attack_data T1548.003 | 15 KB | 108 | Linux privilege escalation | Aug 6, 2024 |

---

## Investigation #1 — SSH Brute-Force Campaign

**Story:** A Linux server exposed SSH to the internet for a month as a honeypot. Investigation reconstructs the attack landscape — who attacked, from where, using what tools, and whether anyone succeeded.

### Tier 1 — Triage (10 minutes)

**Question:** Is this a real threat? Who's involved? Should this go to Tier 2?

Three searches identified the scope and top offenders:

**Top attacker IPs:**
```spl
index=ssh_lab process=sshd
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip | sort -count | head 10
```

Result: `61.197.203.243` (Japan, 11,261 events), `220.99.93.50` (Japan, 10,752), `218.25.17.234` (China, 5,616) topped the list.

📸 ![Top SSH Attackers](screenshots/ssh/01_top_attacker_ips.png)

**Geolocation of top attackers:**
```spl
index=ssh_lab process=sshd
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| iplocation src_ip
| table src_ip, count, Country, City
| sort -count | head 10
```

📸 ![SSH Geolocation](screenshots/ssh/02_geolocation.png)

**Verdict:** True Positive — sustained multi-source SSH abuse. Escalate to Tier 2.

📄 [Full Tier 1 Ticket](tickets/T1-ssh-bruteforce.md)

### Tier 2 — Deep Investigation (45 minutes)

Five searches answered: was there a compromise, was the attacker a bot or human, how sophisticated, how geographically spread, and what shape did the campaign take over time.

**Key finding — coordinated botnet identified via toolkit fingerprinting:**

```spl
index=ssh_lab "Invalid user"
| rex "Invalid user (?<attempted_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(attempted_user) as unique_users_tried count as total_attempts by src_ip
| sort -total_attempts | head 10
```

Result revealed **four IPs from three countries with identical 47-user / 409-attempt fingerprints** — mathematically impossible by coincidence. This is the signature of a distributed botnet running commodity brute-force tooling with a shared wordlist.

📸 ![Coordinated Botnet Discovery](screenshots/ssh/05_dictionary_analysis.png)

**Attack velocity chart** showed each top attacker's activity plotted across the month:

📸 ![Attack Velocity](screenshots/ssh/04_velocity_chart.png)

**Campaign timeline** revealed three attack phases across the month:

📸 ![Campaign Timeline](screenshots/ssh/07_campaign_timeline.png)

**MITRE ATT&CK Techniques:**
- T1595.001 — Active Scanning: Scanning IP Blocks (~78,000 pre-auth SSH port scans)
- T1110.001 — Brute Force: Password Guessing (12,223 Invalid user attempts)

📄 [Full Tier 2 Report](reports/T2-ssh-bruteforce.md)

**Detection Engineering Recommendation:**
```spl
index=ssh_lab process=sshd earliest=-1h
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 50
```
Would have alerted on the top attacker within their first hour of activity.

---

## Investigation #2 — Web-App Compromise & Defacement

**Story:** A Joomla-based marketing site (`imreallynotbatman.com`, IP `192.168.250.70`) was scanned, brute-forced at the admin login, exploited, and defaced. Investigation reconstructs the full kill chain.

### Tier 1 — Triage (15 minutes)

Three searches identified **two coordinated attackers** using different cloud providers:

| IP | Location | Tool | Role |
|----|----------|------|------|
| `40.80.148.42` | Washington (Microsoft Azure) | Acunetix WVS Free Edition | Vulnerability scanning + human login |
| `23.22.63.114` | Ashburn (Amazon EC2) | Python-urllib brute-forcer | Credential attack + webshell operations |

**Scanner identification search:**
```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com
| stats count dc(uri_path) as unique_paths by src_ip
| sort -unique_paths | head 10
```

📸 ![Attacker Identification](screenshots/botsv1/09_scanner_identification.png)

**Verdict:** True Positive — active reconnaissance + coordinated credential attack. Escalate immediately.

📄 [Full Tier 1 Ticket](tickets/T1-webapp-compromise.md)

### Tier 2 — Full Kill Chain Reconstruction (60 minutes)

Six searches reconstructed each stage of the attack.

**Password brute-force analysis:**
```spl
index=botsv1 sourcetype=stream:http http_method=POST dest_ip=192.168.250.70 form_data=*passwd*
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats dc(password) as unique_passwords count as total_attempts by src_ip
```

Attacker B ran 412 unique passwords through a Python script. **All failed** — every attempt returned incorrect. The dictionary attack was defeated by a contextual weakness the wordlist didn't contain.

**Winning password identified via chronological ordering:**
```spl
index=botsv1 sourcetype=stream:http http_method=POST dest_ip=192.168.250.70 form_data=*passwd* src_ip=23.22.63.114
| rex field=form_data "passwd=(?<password>[^&]+)"
| table _time, password
| sort -_time | head 10
```

Last attempt was `rock`. But the actual successful password was **`batman`** — a targeted contextual guess by Attacker A (a human using IE11 on Windows 7), submitted 74 seconds after Attacker B's brute-force failed:

```spl
index=botsv1 sourcetype=stream:http src_ip=40.80.148.42 "passwd=batman"
| table _time, http_user_agent, form_data
```

📸 ![Successful Login](screenshots/botsv1/17_batman_login_confirmed.png)

**Attacker tool fingerprinting via User-Agent injection payloads:**
```spl
index=botsv1 sourcetype=stream:http src_ip=40.80.148.42
| stats count by http_user_agent
| sort -count
```

Revealed `acunetix_wvs_security_test` canary strings — **Acunetix WVS Free Edition** definitively identified. Payloads included SQL injection, command injection, PHP eval, template injection, XSS, and Shellshock (CVE-2014-6271) attempts.

📸 ![Acunetix Fingerprinting](screenshots/botsv1/16_acunetix_useragents.png)

**Webshell activity — post-compromise operations:**
- `/joomla/agent.php` first appeared 2016-08-10 17:55:22 (7 minutes after successful login)
- Accessed 194 times over 26 minutes by Attacker B
- Used exclusively via GET requests with rotating User-Agents

**Suricata IDS independent view:**
```spl
index=botsv1 sourcetype=suricata
| stats count by alert.signature
| sort -count | head 20
```

📸 ![Suricata Alerts](screenshots/botsv1/21_suricata_alerts.png)

Suricata independently identified the attacker: **`ET SCAN Acunetix Version 6 (Free Edition) Scan Detected`** — 45 alerts. Cross-validated our User-Agent analysis. Also caught 200+ injection attempts (XSS, SQLi, XXE, Shellshock, PHP injection).

Critical finding: Suricata caught the reconnaissance phase but MISSED the successful login and webshell activity. Signature-based IDS is blind to successful compromises.

**Complete attack timeline correlation:**
```spl
index=botsv1 (src_ip=23.22.63.114 OR src_ip=40.80.148.42)
| timechart span=1m count by src_ip useother=f
```

📸 ![Attack Timeline](screenshots/botsv1/22_attack_timeline.png)

The chart visually proves the coordinated handoff — Attacker A's Acunetix scan phases finish, Attacker B's brute-force burst begins, quiet period during compromise, then Attacker B's sustained webshell activity resumes.

**MITRE ATT&CK Kill Chain:**
- **T1595** — Active Scanning (Acunetix vulnerability scan)
- **T1110** — Brute Force (412-password dictionary attack)
- **T1078** — Valid Accounts (successful login with `batman`)
- **T1505.003** — Web Shell (agent.php installation)
- **T1059** — Command and Scripting Interpreter (webshell command execution)

📄 [Full Tier 2 Report](reports/T2-webapp-compromise.md)

---

## Investigation #3 — Linux Privilege Escalation & Defense Evasion

**Story:** An attacker with initial sudo access on a Linux host executed a full post-compromise chain — reconnaissance of defenses, attempted log-shipping disruption, and dual persistence establishment. Investigation decodes hex-encoded auditd logs to reconstruct the methodology.

### Tier 1 — Triage (10 minutes)

Two searches inventoried the attack:

**All sudo activity baseline:**
```spl
index=attack_data sourcetype=auditd type=PROCTITLE proctitle=*7375646F*
| stats count by proctitle
```

**Command inventory:**
```spl
index=attack_data sourcetype=auditd type=PROCTITLE
| stats count by proctitle | sort -count
```

📸 ![Command Inventory](screenshots/privesc/24_command_inventory.png)

Five unique commands identified (hex-decoded):

| Command | Count | MITRE Technique |
|---------|-------|-----------------|
| `sudo setcap cap_setuid+ep ./priv_esc` | 36 | T1548.003 (Sudo abuse) |
| `sudo systemctl status SplunkForwarder.service` | 36 | T1518.001 (Security Software Discovery) |
| `sudo /opt/splunkforwarder/bin/splunk restart` | 12 | T1562.001 (Impair Defenses) |
| `sudo chmod u+s vuln` | 12 | T1548.001 (SUID abuse) |
| `sudo systemctl status auditd.service` | 12 | T1518.001 (Security Software Discovery) |

**Verdict:** True Positive — multi-technique privilege escalation chain observed. Escalate immediately.

📄 [Full Tier 1 Ticket](tickets/T1-linux-privesc.md)

### Tier 2 — Attack Methodology Reconstruction (30 minutes)

**Command sequence — attacker checked defenses FIRST:**
```spl
index=attack_data sourcetype=auditd type=PROCTITLE
| table _time, proctitle | sort _time | head 30
```

📸 ![Command Sequence](screenshots/privesc/25_command_sequence.png)

Every one of the first 10 events (executed within 32 milliseconds) was `sudo systemctl status auditd.service`. **Attacker reconned defenses before acting** — professional methodology, and the microsecond intervals confirmed fully automated execution.

**Phase-by-phase timeline reconstruction:**
```spl
index=attack_data sourcetype=auditd type=PROCTITLE
| bin _time span=10s
| stats count by _time, proctitle | sort _time
```

📸 ![Phase Timeline](screenshots/privesc/26_phase_timeline.png)

Revealed the complete 36-minute attack sequence:

| Time | Phase | Action | Purpose |
|------|-------|--------|---------|
| 10:01:00 | Recon | 12× check auditd status | Is audit daemon watching? |
| 10:01:10 | Recon | 12× check SplunkForwarder status | Is central logging active? |
| 10:01:20 | Evasion | 12× restart Splunk | Disrupt log shipping |
| 10:01:40 | Verify | 24× re-check SplunkForwarder | Confirm restart effect |
| 10:02:10 | Persistence #1 | 12× `chmod u+s vuln` | SUID backdoor (T1548.001) |
| 10:02–10:18 | (pause) | — | 16-minute verification window |
| 10:18–10:36 | Persistence #2 | 36× `setcap cap_setuid+ep ./priv_esc` | Capability backdoor (T1548.003) |

**Kill-chain visualization:**
```spl
index=attack_data sourcetype=auditd type=PROCTITLE
| eval technique=case(
    match(proctitle, "61756469746400.*73657276696365"), "T1518 Recon: auditd",
    match(proctitle, "53706C756E6B466F72776172"), "T1518 Recon: Splunk",
    match(proctitle, "2F6F70742F73706C756E6B666F72"), "T1562 Evasion: Splunk restart",
    match(proctitle, "63686D6F6400752B7300"), "T1548.001 Persist: SUID",
    match(proctitle, "73657463617000"), "T1548.003 Persist: setcap"
)
| timechart span=30s count by technique useother=f
```

📸 ![Kill Chain Visualization](screenshots/privesc/28_kill_chain_chart.png)

**Critical finding — dual redundant persistence:** The attacker established TWO independent backdoors (SUID bit on `vuln` AND capability grant on `priv_esc`). If a defender discovers and removes ONE, the OTHER remains active. Incident response that only addresses one leaves the attacker with root access via the other.

**Tooling assessment:** Attack characteristics — phased structure, repeated verification, dual persistence, timed pauses — are consistent with automated ATT&CK simulation frameworks like MITRE Caldera or Atomic Red Team. Not consistent with manual/interactive attacker behavior.

**MITRE ATT&CK Techniques:**
- **T1518.001** — Software Discovery: Security Software Discovery
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1548.001** — Abuse Elevation Control: Setuid and Setgid
- **T1548.003** — Abuse Elevation Control: Sudo and Sudo Caching

📄 [Full Tier 2 Report](reports/T2-linux-privesc.md)

---

## Detection Engineering Deliverables

Every investigation produced production-ready detection rules. Full SPL definitions in [queries/](queries/).

### SSH — High-volume brute-force detection
```spl
index=ssh_lab process=sshd earliest=-1h
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 50
```

### Web-app — Coordinated scanning + login correlation
Alert when successful admin login occurs from an IP whose subnet was previously observed scanning:
```spl
index=botsv1 sourcetype=stream:http src_ip=*
| rex field=src_ip "(?<subnet>\d+\.\d+)"
| stats dc(uri_path) as paths_probed values(src_ip) as attackers by subnet
| where paths_probed > 100
```

### Linux — T1548.003 capability abuse detection
Alert on setcap invocations targeting non-system paths (a system administrator running setcap on user binaries in home directories is highly suspicious):
```spl
index=* sourcetype=auditd type=PROCTITLE proctitle=*7365746361700063*
  NOT proctitle=*2F7573722F62696E2F* NOT proctitle=*2F7573722F7362696E2F*
| stats count by host, proctitle
```

### Linux — Correlation rule for recon + persistence chain
The strongest detection — combines two techniques within a short window:
```spl
index=* sourcetype=auditd type=PROCTITLE
| eval technique=case(
    match(proctitle, "73797374656D63746C.*61756469746400"), "recon",
    match(proctitle, "73657463617000"), "persistence"
)
| where isnotnull(technique)
| stats values(technique) as techniques by host, bin(_time, 5m)
| where mvcount(techniques) > 1
```

---

## Repository Layout

splunk-soc-lab/
├── README.md
├── LICENSE
├── tickets/ Tier 1 triage tickets
│ ├── T1-ssh-bruteforce.md
│ ├── T1-webapp-compromise.md
│ └── T1-linux-privesc.md
├── reports/ Tier 2 incident reports
│ ├── T2-ssh-bruteforce.md
│ ├── T2-webapp-compromise.md
│ └── T2-linux-privesc.md
├── screenshots/ Splunk output proving each finding
│ ├── ssh/ (Investigation 1)
│ ├── botsv1/ (Investigation 2)
│ └── privesc/ (Investigation 3)
└── queries/ Reusable SPL saved-search definitions
├── ssh-detections.spl
├── botsv1-detections.spl
└── privesc-detections.spl

---

## Key Skills Demonstrated

- **SIEM operation** — Splunk Enterprise installation, index management, sourcetype configuration
- **SPL query authoring** — `rex`, `stats`, `eval`, `timechart`, `iplocation`, `case()`, correlation queries
- **Log parsing** — regex-based field extraction from syslog, HTTP metadata, and hex-encoded auditd events
- **Tiered SOC workflow** — Tier 1 triage tickets and Tier 2 incident reports mirroring real analyst work
- **MITRE ATT&CK mapping** — 10+ techniques identified and mapped across three attack types
- **Attribution analysis** — attacker toolkit fingerprinting (Acunetix, Python-urllib, Atomic Red Team patterns)
- **Kill-chain reconstruction** — full end-to-end attack narratives from recon through post-exploitation
- **Detection engineering** — production-ready saved-search rules with correlation logic
- **Multi-source data correlation** — combining stream:http, suricata, and auditd views
- **Pattern recognition** — identified coordinated botnet campaign via toolkit fingerprint matching (47/409 pattern across 4 IPs)
- **Honest interpretation** — revised hypotheses when data contradicted expectations (a real investigation skill)

---

## Attack Categories Covered

| Category | Investigation | Log Source | Attack Vector |
|----------|---------------|-----------|---------------|
| Network | #1 — SSH brute-force | Linux auth.log (syslog) | Remote password attacks |
| Application | #2 — Web-app compromise | HTTP metadata + IDS | Web vulnerability exploitation |
| Endpoint | #3 — Privilege escalation | Kernel audit (auditd) | Post-compromise privesc |

Understanding all three is what makes a generalist SOC analyst.

---

## References

| Resource | Link |
|----------|------|
| Splunk Documentation | https://docs.splunk.com |
| MITRE ATT&CK | https://attack.mitre.org |
| BOTSv1 Dataset | https://github.com/splunk/botsv1 |
| Splunk attack_data | https://github.com/splunk/attack_data |
| SecRepo Datasets | https://www.secrepo.com |
| CVE-2014-6271 (Shellshock) | https://nvd.nist.gov/vuln/detail/CVE-2014-6271 |
| CVE-2014-8681 (OFC Upload) | https://nvd.nist.gov/vuln/detail/CVE-2014-8681 |

---

## About

Built as part of an ongoing cybersecurity portfolio focused on SOC analyst role preparation. All datasets are publicly available research corpora; no proprietary or sensitive data is included. Findings are analytical exercises against known scenarios.

**Contact:** [github.com/kenil-77](https://github.com/kenil-77)
