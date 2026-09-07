# Tier 2 Incident Report — SSH Brute-Force Campaign

**Analyst:** Kenil (T2)
**Date:** 2026-09-05
**Escalated from:** T1-ssh-bruteforce
**Dataset:** SecRepo public honeypot auth.log
**Time period:** Nov 30 – Dec 31, 2014

## Executive Summary

A public-facing Linux SSH honeypot was subjected to sustained multi-source scanning and brute-force activity across a full month. Investigation identified 1,556 unique attacker IPs across 77 countries, with the top 3 attackers accounting for 48.9% of attack volume. A coordinated botnet campaign was identified via toolkit fingerprint matching — four IPs from three different countries showed identical attack signatures (47 unique users / 409 attempts each), indicating a distributed botnet running commodity brute-force tooling with a shared wordlist. **No successful compromises were observed.**

## Scope

| Metric | Value |
|--------|-------|
| Total SSH events (excluding cron) | 85,246 |
| Total invalid-user attempts | 12,223 |
| Unique attacker IPs | 1,556 |
| Countries involved | 77 |
| Attack window | Nov 30 – Dec 31, 2014 (32 days) |
| Compromise confirmed? | **No** |

## Compromise Assessment

Searched for successful SSH authentications (`Accepted password`, `Accepted publickey`, `session opened`) filtered to `process=sshd`. **Zero SSH-based successful logins observed.** The 796 events initially matching contained only CRON session events (unrelated to SSH auth). Defensive win — honeypot withstood the campaign.

## Top Attacker Profile

| Metric | Value |
|--------|-------|
| Source IP | 61.197.203.243 |
| Location | Chiyoda, Tokyo, Japan |
| Total attempts | 11,261 (13.2% of all SSH activity) |
| Attack window | 2014-12-06 08:00 to 13:00 EST (~6 hours) |
| Peak velocity | 2,207 attempts/hour |
| Steady rate | ~30 attempts/minute |
| Assessment | Automated dictionary attack, rate-limited to evade fail2ban's default 10-per-10-min threshold |

## Attacker Toolkit Fingerprinting

Cross-referencing unique_users vs. total_attempts per source IP revealed multiple attackers running identical toolkits — evidence of coordinated campaigns rather than independent scanning.

### Toolkit A — "47/409" fingerprint (coordinated botnet)

| IP | Country | Attempts | Unique Users | Attack Date |
|----|---------|----------|--------------|-------------|
| 61.197.203.243 | Japan | 409 | 47 | Dec 6 |
| 220.99.93.50 | Japan | 409 | 47 | Dec 3-5 |
| 218.25.17.234 | China | 409 | 47 | Dec 3-5 |
| 188.87.35.25 | Spain | 409 | 47 | Dec 13 |

**Four IPs across three countries with mathematically identical attack fingerprints.** Assessment: distributed botnet running commodity brute-force tool with shared 47-user wordlist. Same operator or same commodity malware family. Coordination confirmed by non-random pattern.

### Toolkit B — "34/269" fingerprint (paired attackers)

| IP | Country | Attempts | Unique Users |
|----|---------|----------|--------------|
| 67.205.20.23 | US | 269 | 34 |
| 78.129.223.28 | UK | 269 | 34 |

Second coordinated campaign, smaller scale, different toolkit.

### Toolkit C — Single-user hammer (targeted)

| IP | Country | Attempts | Unique Users |
|----|---------|----------|--------------|
| 123.57.51.31 | China | 360 | 1 |

360 attempts against a single username. Targeted attack on a specific known/suspected account rather than a dictionary attack.

## Target Dictionary Analysis

Top 10 targeted usernames across all attackers:

| Rank | Username | Attempts | Category |
|------|----------|----------|----------|
| 1 | admin | 1,912 | Generic admin |
| 2 | test | 933 | Weak default |
| 3 | guest | 515 | Weak default |
| 4 | oracle | 449 | Database service account |
| 5 | ftp | 418 | FTP service account |
| 6 | ftpuser | 392 | FTP service account |
| 7 | nagios | 340 | Monitoring platform |
| 8 | D-Link | 339 | Consumer router admin |
| 9 | debug | 335 | Factory debug account |
| 10 | zxin10 | 20 | Chinese telecom platform |

Assessment: Attackers targeting **infrastructure service accounts** (Oracle DB, Nagios monitoring, D-Link devices) rather than personal user accounts. Indicates hunting for misconfigured/default-credentialed infrastructure, not phishing individual users.

## Geographic Analysis

| Country | Events | Unique IPs | Events per IP |
|---------|--------|------------|---------------|
| Japan | 22,567 | 56 | 403 |
| China | 12,489 | 304 | 41 |
| United States | 6,658 | 262 | 25 |
| Germany | 3,706 | 234 | 16 |
| United Kingdom | 3,152 | 56 | 56 |
| Spain | 2,260 | 28 | 81 |
| South Korea | 1,108 | 48 | 23 |

**Top 3 countries = 48.9% of attack volume. Top 5 = 56.9%.**

Key finding: Attack profile varies significantly by country.
- **Japan/Spain/UK**: small number of highly aggressive attackers. Targeted IP blocking is efficient.
- **China/Germany**: distributed botnet-style activity across hundreds of IPs. Per-IP blocking won't scale; use geo-blocking or aggressive rate-limiting.
- **Russia/Canada**: casual opportunistic scanning; standard rate-limiting sufficient.

## Campaign Timeline

Three-phase pattern observed across the month:

**Phase 1 — Active Assault (Dec 1–6)**
- Two major spikes (Dec 1: 17,500 events; Dec 6: 12,000 events)
- Baseline elevated to 3,000-5,000/day
- ~40% of total monthly traffic in the first 6 days

**Phase 2 — Steady Pressure (Dec 7–25)**
- No major spikes
- Consistent 3,000-5,000/day baseline
- Long-tail scanning at background rate

**Phase 3 — Wind-Down (Dec 26–31)**
- ~80% decline in attack volume over final week
- Likely holiday-related reduction in botnet activity
- Consistent with observed patterns of criminal operators taking time off around Christmas/New Year

## MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|-----------|------|----------|
| T1595.001 | Active Scanning: Scanning IP Blocks | ~78,000 "Did not receive identification string" events — pre-auth SSH port scanning |
| T1110.001 | Brute Force: Password Guessing | 12,223 "Invalid user" events across 1,556 IPs with dictionary-based username attempts |

## Indicators of Compromise (IOCs)

**Top 10 attacker IPs (recommend firewall blocking):**
- 61.197.203.243 (JP)
- 220.99.93.50 (JP)
- 218.25.17.234 (CN)
- 188.87.35.25 (ES)
- 67.205.20.23 (US)
- 78.129.223.28 (UK)
- 222.161.209.92 (CN)
- 173.192.158.3 (US)
- 218.75.153.170 (CN)
- 61.235.147.19 (CN)

**Targeted usernames (attacker dictionary):** admin, test, guest, oracle, ftp, ftpuser, nagios, D-Link, debug

## Detection Assessment

The honeypot appears to have had **no active detection controls** (no fail2ban, no rate-limiting, no geo-blocking). Attackers operated unimpeded for the full month. In a production environment, both major peak days (Dec 1 with 17,500 events, Dec 6 with 12,000 events) would have triggered any anomaly-detection rule configured as "daily SSH event count exceeds 3× 7-day rolling average" within hours of onset.

## Containment Recommendations

### Immediate (within 1 hour)
1. Firewall-block the top 10 attacker IPs at the perimeter
2. Verify the honeypot has no legitimate services on port 22

### Near-term (within 24 hours)
1. Disable SSH password authentication:
/etc/ssh/sshd_config → PasswordAuthentication no
/etc/ssh/sshd_config → PermitRootLogin no
2. Enforce key-based authentication for all users
3. Deploy fail2ban with aggressive threshold (5 failures per 10 min = 1-hour ban)

### Long-term (policy)
1. Move SSH off port 22 (defense in depth — reduces automated scan hits)
2. Enable geo-blocking on the SSH listener if user population is regionally concentrated
3. Implement per-IP rate limiting for all SSH connections

## Detection Engineering Recommendation

**Splunk saved search + email alert:**
```spl
index=ssh_lab process=sshd earliest=-1h
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 50
```

Would fire when any single IP generates more than 50 SSH events in one hour. Would have alerted on the top attacker (`61.197.203.243`) within their first hour of activity, potentially reducing detection time from 6 hours (attack duration) to under 60 minutes.

## Analyst Signoff

Kenil, Tier 2 SOC — 2026-09-05
