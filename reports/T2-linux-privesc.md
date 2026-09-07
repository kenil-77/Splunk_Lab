# Tier 2 Incident Report — Linux Privilege Escalation & Defense Evasion

**Analyst:** Kenil (T2)
**Date:** 2026-09-05
**Escalated from:** T1-linux-privesc
**Dataset:** Splunk attack_data T1548.003 (linux_auditd_sudo_su.log)
**Incident date:** 2024-08-06

## Executive Summary

A Linux host with pre-existing attacker sudo access executed a fully automated 36-minute post-compromise chain covering four MITRE ATT&CK techniques: security software discovery, defense evasion (log-shipping disruption), and dual redundant persistence establishment via both SUID abuse and Linux capability grants. Attack characteristics are consistent with automated ATT&CK simulation frameworks (Atomic Red Team or MITRE Caldera). Both persistence mechanisms remain active if not explicitly removed.

## Scope

| Metric | Value |
|--------|-------|
| Total events | 108 auditd PROCTITLE records |
| Unique commands | 5 |
| Attack window | 2024-08-06 10:01:00 – 10:36:50 UTC |
| Duration | ~36 minutes |
| Compromise confirmed? | Yes — attacker had pre-existing sudo access |

## Attacker Profile

| Field | Value |
|-------|-------|
| Access level | User account with sudo privileges (pre-compromise) |
| Attack type | Fully automated / scripted |
| Sophistication | Mid-to-high — reconned defenses before acting; attempted defense evasion; established redundant persistence |
| Tool assessment | Consistent with automated ATT&CK simulation frameworks (Atomic Red Team, MITRE Caldera, or similar) |
| Evidence | 313 events/second peak velocity impossible for manual entry; phased structure with verification loops |

## Complete Attack Kill Chain

Full timeline reconstructed via 10-second time buckets against hex-decoded proctitles:

### Phase 1 — Defense Reconnaissance (T1518.001)

**10:01:00** — 12× `sudo systemctl status auditd.service`
**10:01:10** — 12× `sudo systemctl status SplunkForwarder.service`

Purpose: Attacker checked which security tools were monitoring the host before continuing. Auditd is the local audit daemon (source of these very logs). Splunk Universal Forwarder is the log-shipping agent that sends events to central SIEM.

Assessment: **Textbook attacker methodology.** Attacker wanted to know what would witness their actions before acting. Amateur attackers act first and get caught by unexpected logging; professional attackers recon defenses first.

Duration: 20 seconds.

### Phase 2 — Defense Evasion Attempt (T1562.001)

**10:01:20** — 12× `sudo /opt/splunkforwarder/bin/splunk restart`
**10:01:40** — 24× `sudo systemctl status SplunkForwarder.service` (verification)

Purpose: Restarting the Splunk Forwarder creates a brief log-shipping gap (typically 5-30 seconds). During that window, subsequent events aren't forwarded to central SIEM.

Assessment: **Attacker verified restart effect before continuing.** The 24 verification checks after the restart demonstrate methodology — confirm each action succeeded before proceeding. Weak evasion technique (restart is much less effective than stop; modern Splunk queues events locally during restarts), but the intent is clear.

Duration: 40 seconds.

### Phase 3 — Persistence Method #1: SUID Bit (T1548.001)

**10:02:10** — 12× `sudo chmod u+s vuln`

Purpose: Sets the SUID bit on a binary named `vuln`. When any user (including a non-privileged one) runs `vuln`, it executes with the privileges of `vuln`'s owner (likely root, since sudo was used).

Assessment: Classic Unix privilege escalation trick — mark a binary SUID root, and any user running it gets root. Provides persistent root access surviving user logout.

Duration: 10 seconds.

### Verification Pause

**10:02:10 – 10:18:20** — no activity (~16 minutes)

Assessment: Attacker paused before establishing second persistence method. Possibilities: manual verification of the SUID backdoor, testing whether logging was actually disrupted, setting up something outside the auditd capture, or automated waiting period built into the tool.

### Phase 4 — Persistence Method #2: Capability Abuse (T1548.003)

**10:18:20** — 12× `sudo setcap cap_setuid+ep ./priv_esc`
**10:20:30** — 12× `sudo setcap cap_setuid+ep ./priv_esc`
**10:36:50** — 12× `sudo setcap cap_setuid+ep ./priv_esc`

Purpose: Grants the `CAP_SETUID` Linux capability to a binary named `./priv_esc`. Once granted, running `./priv_esc` gives the ability to change UIDs (become root) **without needing sudo again**. This is a persistent root-access backdoor surviving sudo timeout / logout.

Assessment: Sophisticated persistence method. If the attacker loses their sudo shell, they can regain root by simply running the priv_esc binary. Three separate execution rounds (12 events each, spaced 2-16 minutes apart) suggest either iterative testing or automated retry logic.

Duration: 18 minutes.

## Dual Persistence Assessment

The attacker established **TWO independent persistence mechanisms**:

1. **SUID bit on `vuln`** (T1548.001) — traditional Unix privilege escalation
2. **CAP_SETUID capability on `./priv_esc`** (T1548.003) — modern Linux capability abuse

This is **deliberate redundancy**. If a defender discovers and removes ONE backdoor, the OTHER remains active. Any incident response that only addresses one persistence mechanism leaves the attacker with root access via the other.

## Behavioral Analysis

Key methodological findings:

1. **Recon PRECEDED action** — attacker checked defenses (auditd, Splunk) first, then acted
2. **Evasion attempted BEFORE persistence** — logs disrupted before backdoors set
3. **Verification loops after every action** — 12-36 repetitions per command indicate testing/verification
4. **Dual redundant persistence** — SUID + capability grant, both established
5. **Extended pause between persistence methods** — 16-minute gap between SUID and capability rounds

Timing analysis: First 10 events executed within 32 milliseconds (313 events/second) — impossibly fast for manual entry. Consistent with automated ATT&CK simulation tooling. Not consistent with interactive human attacker.

## MITRE ATT&CK Mapping

| Technique | Name | Evidence |
|-----------|------|----------|
| T1518.001 | Software Discovery: Security Software Discovery | `systemctl status` against auditd and SplunkForwarder (48 events total) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `splunk restart` (12 events) |
| T1548.001 | Abuse Elevation Control: Setuid and Setgid | `chmod u+s vuln` (12 events) |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | `setcap cap_setuid+ep ./priv_esc` (36 events) |

## Indicators of Compromise (IOCs)

**File paths (backdoor binaries):**
- `./priv_esc` — attacker binary with CAP_SETUID capability granted
- `./vuln` — attacker binary with SUID bit set

**Detection commands** (run during forensic investigation):
```bash
# Locate the backdoor binaries
find / -name "priv_esc" -o -name "vuln" 2>/dev/null

# Find any binaries with capabilities set (may reveal others)
getcap -r / 2>/dev/null

# Find all SUID binaries (compare against known baseline)
find / -perm -4000 -type f 2>/dev/null
```

## Containment / Eradication

### Immediate (within 1 hour)

1. Isolate the affected host from the network
2. Identify and remove the attacker's persistence binaries:
```bash
   find / -name "priv_esc" -o -name "vuln" 2>/dev/null
```
3. Remove capabilities from any discovered priv_esc binary:
```bash
   setcap -r /path/to/priv_esc
```
4. Remove SUID bit from any discovered vuln binary:
```bash
   chmod u-s /path/to/vuln
```
5. Verify no other unauthorized SUID binaries exist:
```bash
   find / -perm -4000 -type f 2>/dev/null | diff - /known/suid/baseline
```
6. Verify no other unauthorized capability grants exist:
```bash
   getcap -r / 2>/dev/null
```
7. Revoke sudo access for the compromised user account
8. Force password reset for the compromised user

### Short-term (within 24 hours)

1. Forensic disk image of the host BEFORE any further remediation
2. Timeline analysis to determine initial access vector (how did attacker get sudo access?)
3. Audit `/etc/sudoers` and `/etc/sudoers.d/*` for overly permissive NOPASSWD entries
4. Set `sudo timestamp_timeout=0` in sudoers (no credential caching)
5. Review authentication logs (`/var/log/auth.log`) for the compromised user's login history
6. Check for lateral movement — did the attacker access other hosts?

### Long-term (policy)

1. Enable auditd rules for critical system integrity monitoring:
-w /etc/sudoers -p wa -k sudoers_change
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/setcap -k setcap_use
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chmod -F a0=u+s -k suid_grant
2. Deploy central log forwarding with tamper-resistant configuration (attackers should NOT be able to stop/restart the forwarder without alerting)
3. Implement periodic SUID/capability inventory scans with alerting on any changes from baseline
4. Enforce principle of least privilege — audit which users need sudo, restrict to specific commands rather than full sudo

## Detection Engineering Recommendations

### Rule 1 — T1548.003 Setcap on Non-System Paths

```spl
index=* sourcetype=auditd type=PROCTITLE proctitle=*7365746361700063*
  NOT proctitle=*2F7573722F62696E2F* NOT proctitle=*2F7573722F7362696E2F*
| stats count by host, proctitle
```

Alerts on any setcap invocation that is NOT targeting `/usr/bin/*` or `/usr/sbin/*` (legitimate use of setcap almost always targets system binaries — capability grants on user binaries in unusual locations is the T1548.003 pattern).

### Rule 2 — T1548.001 SUID Bit Setting

```spl
index=* sourcetype=auditd type=PROCTITLE proctitle=*63686D6F6400*
  (proctitle=*752B7300* OR proctitle=*343735* OR proctitle=*343730*)
| stats count by host, proctitle
```

Alerts on chmod invocations setting the SUID bit (`u+s` or numeric modes starting with 4).

### Rule 3 — Correlation: Recon + Persistence Within Short Window

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

Alerts when the same host generates BOTH:
- Security software discovery events (systemctl status against auditd, splunk, wazuh, falco, osquery)
- AND capability/SUID modifications within a 5-minute window

The combination is a strong indicator of the attacker methodology observed in this incident. Would have caught this attack chain in real time.

## Analyst Signoff

Kenil, Tier 2 SOC — 2026-09-05
