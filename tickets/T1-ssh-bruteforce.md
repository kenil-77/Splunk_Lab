# Tier 1 Ticket — SSH Brute-Force / Scanning Campaign

**Analyst:** Kenil (T1)
**Date:** 2026-09-05
**Dataset:** SecRepo public honeypot auth.log (Nov 30 – Dec 31, 2014)
**Index:** ssh_lab
**Total events:** 86,839

## Alert

Sustained SSH brute-force and reconnaissance activity from multiple internet-based sources targeting a public-facing Linux honeypot. High-volume, multi-source, spans full month of dataset.

## Scope Summary

| Metric | Value |
|--------|-------|
| Total SSH events | 85,246 (excluding cron sessions) |
| Total invalid-user attempts | 12,223 |
| Unique attacker IPs | 1,556 |
| Countries involved | 77 |
| Compromise confirmed? | No — no successful logins observed |

## Top Attacker Profile

| Metric | Value |
|--------|-------|
| Source IP | 61.197.203.243 |
| Location | Chiyoda, Tokyo, Japan |
| Events from this IP | 11,261 (13.2% of all SSH activity) |
| Peak velocity | ~2,207 events/hour (2014-12-06 09:00 EST) |
| Attack window | 2014-12-06 08:00 to 13:00 EST (~6 hours) |
| Assessment | Automated dictionary attack — steady ~30 attempts/min suggests rate-limited tool tuned to evade fail2ban's default 10-per-10-min threshold |

## Top 3 Attackers

| Rank | IP | Country | Events |
|------|-----|---------|--------|
| 1 | 61.197.203.243 | Japan (Tokyo) | 11,261 |
| 2 | 220.99.93.50 | Japan (Osaka) | 10,752 |
| 3 | 218.25.17.234 | China (Shenyang) | 5,616 |

## Most-Targeted Accounts

| Rank | Username | Attempts |
|------|----------|----------|
| 1 | admin | 1,912 |
| 2 | test | 933 |
| 3 | guest | 515 |
| 4 | oracle | 449 |
| 5 | ftp | 418 |

Assessment: Attacker dictionary targets infrastructure service accounts (Oracle DB, Nagios monitoring, D-Link devices) rather than personal user accounts. Indicates hunting for misconfigured/default-credentialed infrastructure, not phishing individual users.

## Geographic Origin

Concentrated in Asia-Pacific (Japan + China = 41% of attack volume). Long tail across US, UK, EU, and 70+ other countries.

## Verdict

**True Positive** — sustained multi-source SSH abuse campaign. No successful compromises observed, but attack volume and coordination warrant investigation.

## Action

**ESCALATE to Tier 2** for full campaign analysis, attacker attribution, and containment recommendations.

## Analyst Notes

Data indicates coordinated activity — will investigate whether top attackers share toolkit fingerprints or if independent scanners happened to converge. Tier 2 to correlate.
