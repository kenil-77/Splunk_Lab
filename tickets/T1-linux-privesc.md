# Tier 1 Ticket — Linux Privilege Escalation & Defense Evasion Chain

**Analyst:** Kenil (T1)
**Date:** 2026-09-05
**Dataset:** Splunk attack_data T1548.003 (linux_auditd_sudo_su)
**Index:** attack_data
**Total events:** 108 (auditd PROCTITLE records)

## Alert

Suspicious sudo activity indicating a multi-stage privilege escalation and defense evasion sequence on a Linux host. Attacker with pre-existing sudo access is establishing persistence mechanisms and attempting to disrupt log shipping.

## Host

| Field | Value |
|-------|-------|
| Hostname | kali |
| Attack date | 2024-08-06 |
| Time window | 10:01:00 – 10:36:50 UTC (~36 minutes) |

## Observed Commands (5 unique, 108 total events)

| Count | Command (hex-decoded from auditd PROCTITLE) | MITRE Technique |
|-------|---------------------------------------------|-----------------|
| 36 | `sudo setcap cap_setuid+ep ./priv_esc` | T1548.003 — Sudo and Sudo Caching |
| 36 | `sudo systemctl status SplunkForwarder.service` | T1518.001 — Security Software Discovery |
| 12 | `sudo /opt/splunkforwarder/bin/splunk restart` | T1562.001 — Impair Defenses |
| 12 | `sudo chmod u+s vuln` | T1548.001 — Setuid and Setgid |
| 12 | `sudo systemctl status auditd.service` | T1518.001 — Security Software Discovery |

## MITRE ATT&CK Techniques Detected (4)

- **T1518.001** — Software Discovery: Security Software Discovery
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1548.001** — Abuse Elevation Control: Setuid and Setgid
- **T1548.003** — Abuse Elevation Control: Sudo and Sudo Caching

## Initial Assessment

This is not a single technique — it's a **multi-stage post-compromise scenario**. The attacker:

1. Mapped defensive tooling (checked auditd and Splunk Forwarder status)
2. Attempted to disable log shipping via service restart (defense evasion)
3. Established TWO persistence mechanisms:
   - Capability grant on `./priv_esc` (T1548.003)
   - SUID bit on `vuln` binary (T1548.001)

All 108 events represent an active attacker session with clear intent to maintain root access.

## Verdict

**True Positive** — active privilege escalation and defense evasion chain in progress. Host is compromised.

## Action

**ESCALATE to Tier 2 immediately** — Linux host requires:
- Forensic investigation
- Removal of both persistence mechanisms (SUID + capability)
- Root cause analysis of initial sudo access
- Review of sudo configuration and audit rules

## Analyst Notes

Command repetition patterns (36 identical `setcap` runs, 24 verification checks after Splunk restart) suggest automated tooling rather than manual interactive attacker. Consistent with red-team simulation frameworks (Atomic Red Team, MITRE Caldera). Tier 2 to confirm.
