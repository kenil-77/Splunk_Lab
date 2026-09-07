# Tier 2 Incident Report — Web-App Compromise & Post-Exploitation

**Analyst:** Kenil (T2)
**Date:** 2026-09-05
**Escalated from:** T1-webapp-compromise
**Dataset:** BOTSv1 (Splunk Boss of the SOC v1)
**Incident date:** 2016-08-10

## Executive Summary

The Joomla-based web application `imreallynotbatman.com` (192.168.250.70) was successfully compromised by two coordinated attackers in a 46-minute attack window. Attacker A used the commercial vulnerability scanner **Acunetix WVS Free Edition** for reconnaissance, then successfully authenticated to the Joomla admin panel using the contextual password `batman`. Attacker B ran a parallel 412-password dictionary brute-force (which failed) and later drove post-compromise webshell operations. **Confirmed compromise. Webshell installed. Command execution observed.**

## Target

| Field | Value |
|-------|-------|
| Site | imreallynotbatman.com |
| Host IP | 192.168.250.70 |
| Application | Joomla CMS |
| Attack date | 2016-08-10 |

## Attribution — Two Coordinated Attackers

### Attacker A — 40.80.148.42 (Microsoft Azure, Washington US)

**Two operators on same IP:**

**Operator A1 — automated tool**
- Tool: Acunetix Web Vulnerability Scanner Free Edition (identified via `acunetix_wvs_security_test` canary strings in injected payloads)
- User-Agent: `Mozilla/5.0 ... Chrome/41.0.2228.0` (Acunetix default)
- Requests: 17,420 (99.3% of A's traffic)
- Purpose: Automated vulnerability scanning; injection testing for SQLi, command injection, PHP eval, template injection, XSS, XXE, Shellshock

**Operator A2 — human**
- Browser: Internet Explorer 11 on Windows 7
- User-Agent: `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)`
- Requests: 61 (0.3% of A's traffic)
- **Key action: Successful login as `admin`/`batman` at 17:48:05.858**
- Evidence of legitimate browser: submitted with valid CSRF token (`e5ec827a3f67ce0efc546d81f7356acc`)

### Attacker B — 23.22.63.114 (Amazon EC2, Ashburn US)

**Two toolkits observed:**

**Toolkit 1 — brute-forcer**
- Tool: Custom Python-urllib script
- User-Agent: `Python-urllib/2.7`
- Requests: 412 login POST attempts (100% Python-urllib)
- Purpose: 412-password dictionary attack against Joomla admin login
- **Result: FAILED — all 412 attempts unsuccessful**
- Hypothesis: May have failed due to CSRF token handling in addition to wrong passwords

**Toolkit 2 — webshell operator**
- Tool: UA-rotating tool (unidentified)
- User-Agents: 182 unique rotating UAs, each used ~2× on average
- Requests: 194 GET requests to `/joomla/agent.php`
- Purpose: Webshell command execution (post-compromise)

## Kill Chain Reconstruction

Complete attack sequence proven via HTTP log correlation:

| Phase | Time | Actor | Activity |
|-------|------|-------|----------|
| Recon (Acunetix scan) | ~17:37+ | Attacker A1 | Deep web app scan, 1,871 unique paths probed, injection testing |
| CVE-2014-8681 exploit attempts | 17:37 | Attacker A1 | POST requests to `ofc_upload_image.php` at 12 different path variations |
| Brute-force attack | 17:44-17:46 | Attacker B | 412-password dictionary attack against Joomla admin login |
| Brute-force ends (failed) | 17:46:51 | Attacker B | Last password attempted: `rock` |
| **Successful login** | **17:48:05** | **Attacker A2 (human)** | **Manual login with `admin`/`batman` via IE11** |
| Admin panel activity | 17:48-17:55 | Attacker A2 | Likely webshell upload via file manager (~7 minutes) |
| Webshell active | 17:55:22 | (unknown) | `/joomla/agent.php` first appears |
| Post-exploitation | 17:55:22-18:21:34 | Attacker B | 194 GET requests to webshell; command execution |

**Total attack duration: ~46 minutes**

## The Winning Password Analysis

Attacker B ran 412 unique passwords through the Joomla login form — all failed. Search of Attacker A's activity revealed a single POST containing `passwd=batman` at 17:48:05.858 which **did succeed**.

`batman` is a **contextual password** — derived from the target domain `imreallynotbatman.com`. A generic dictionary would never contain this word ranked high enough to test. Attacker A2's human operator saw the domain name and thought "let me try `batman`" — succeeding in one attempt where 412 dictionary guesses had failed.

**Key lesson:** Attackers who do reconnaissance and think contextually beat attackers who blindly run wordlists.

## Webshell Analysis

| Field | Value |
|-------|-------|
| Filename | `/joomla/agent.php` |
| First appearance | 2016-08-10 17:55:22 |
| Last activity | 2016-08-10 18:21:34 |
| Duration | 26 minutes |
| Accessing IP | 23.22.63.114 (Attacker B, exclusive) |
| Methods used | GET only |
| Total requests | 194 |
| Response sizes | 300-1000 bytes (indicates command execution, not bulk data exfiltration) |

Upload vector: Two candidate paths were both attempted — CVE-2014-8681 exploitation of `ofc_upload_image.php` and admin panel file upload via the successful `batman` login. In real incident response, forensic imaging would determine which succeeded. For this investigation, both attempted vectors are documented; the admin panel upload is the more likely candidate given timing (7 minutes between login and first webshell hit).

## Attack Timeline Correlation

Full attack visualized as time-series analysis of both attacker IPs:

- **Phase 1 (Recon, 17:37-17:44):** Attacker A dominates with 1,000-3,500 requests/minute (Acunetix)
- **Phase 2 (Brute-force, 17:44-17:47):** Attacker B spikes to 2,300-3,545 requests/minute
- **Phase 3 (Compromise, 17:48-17:54):** Both attackers quiet; successful login and webshell upload occur in this window
- **Phase 4 (Post-exploitation, 17:55-18:22):** Attacker B sustains 1,000-1,500 requests/minute driving webshell

**Critical observation:** The successful compromise occurred during the QUIETEST portion of the attack. The single successful login was 1 request out of ~40,000 surrounding events. Detection tuning that only alerted on high-volume events would have missed the actual breach entirely.

## MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|-----------|------|----------|
| T1595 | Active Scanning | Acunetix scanner probing 1,871 unique URL paths |
| T1110 | Brute Force | 412-password dictionary attack (Attacker B) |
| T1078 | Valid Accounts | Successful login as admin/batman (Attacker A2) |
| T1505.003 | Server Software Component: Web Shell | `/joomla/agent.php` installation and 194 uses |
| T1059 | Command and Scripting Interpreter | Webshell used for command execution on server |

## Detection Assessment (Suricata IDS Analysis)

Suricata detected the attack in real time — but only the noisy parts.

### What Suricata Caught

| Signature | Count | Category |
|-----------|-------|----------|
| ET SCAN Acunetix Version 6 (Free Edition) Scan Detected | 45 | Scanner identification |
| ET WEB_SERVER Script tag in URI, Possible XSS Attempt | 103 | XSS injection |
| ET WEB_SERVER Onmouseover= in URI - Likely XSS Attempt | 48 | XSS injection |
| ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY | 41 | XXE injection |
| ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM | 33 | SQL injection |
| ET WEB_SERVER SQL Injection Select Sleep Time Delay | 32 | Blind SQL injection |
| ET WEB_SERVER Possible CVE-2014-6271 Attempt | 18 | Shellshock exploit |
| ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers | 18 | Shellshock exploit |
| ET WEB_SERVER PHP tags in HTTP POST | 13 | PHP injection |

Suricata independently identified Attacker A's tool as **Acunetix Version 6 Free Edition**. This validated the User-Agent-based fingerprinting done via manual analysis. Two independent detection methods converged on the same attribution.

### What Suricata Missed

- **The successful `batman` login** — no signature applicable to legitimate admin authentication
- **The webshell installation** — no signature for `/joomla/agent.php`
- **194 subsequent webshell uses** — no signature match
- **The brute-force from Attacker B** — no rate-based signature fired in top 20
- **CVE-2014-8681 (ofc_upload_image.php) exploitation** — no signature coverage for this specific vulnerability

### Detection Gap

Signature-based IDS excels at catching ATTEMPTED attacks but is fundamentally blind to SUCCESSFUL ones. A SOC relying solely on Suricata would have known within seconds that Acunetix was scanning the server but would have received zero indication that the attacker successfully logged in and installed a webshell.

## Indicators of Compromise (IOCs)

**Attacker IPs:**
- 40.80.148.42 (Microsoft Azure — Attacker A)
- 23.22.63.114 (Amazon EC2 — Attacker B)

**Attacker tools:**
- Acunetix WVS Free Edition (canary string: `acunetix_wvs_security_test`)
- Python-urllib/2.7 (custom brute-force script)

**Successful credentials:**
- Username: `admin`
- Password: `batman`

**Malicious files:**
- `/joomla/agent.php` (webshell)

**Attempted CVE exploitation:**
- CVE-2014-6271 (Shellshock) — 36 attempts
- CVE-2014-8681 (Open Flash Chart image upload) — 12+ attempts across different paths

## Containment / Eradication

### Immediate (within 1 hour)
1. Take web application offline immediately
2. Block both attacker IPs at perimeter firewall
3. Rotate ALL Joomla admin credentials (assume all are compromised)
4. Preserve forensic image of 192.168.250.70 before rebuild

### Short-term (within 24 hours)
1. Identify and remove uploaded webshell(s):
```bash
   find /var/www -name "agent.php" -o -name "*.php" -newer /some/reference/date
```
2. Review web logs for other IPs that used the same webshell
3. Restore Joomla from clean backup predating 2016-08-10 17:37
4. Patch Joomla to latest version
5. Enforce MFA on admin login

### Long-term (policy)
1. Deploy Web Application Firewall (WAF) with Acunetix/scanner signatures
2. Implement rate limiting on login endpoints (5 attempts / 10 min)
3. Add CAPTCHA or MFA after N failed attempts
4. Regular vulnerability scans (defenders should scan before attackers do)

## Detection Engineering Recommendation

**Correlation rule — successful admin login preceded by scanning activity:**
```spl
index=* sourcetype=stream:http src_ip=*
| rex field=src_ip "(?<subnet>\d+\.\d+)"
| stats dc(uri_path) as paths_probed values(src_ip) as attackers by subnet
| where paths_probed > 100
```

Would flag any subnet where combined activity indicates scanning (100+ unique paths). If a successful admin login later comes from that subnet, correlate as high-priority alert.

This rule would have caught the multi-IP attack pattern used here — Attacker A's Azure IP and Attacker B's AWS IP are in different subnets, but the correlation would have flagged Attacker A's subnet immediately when Acunetix scan volume exceeded threshold, providing early warning before the successful login.

## Analyst Signoff

Kenil, Tier 2 SOC — 2026-09-05
