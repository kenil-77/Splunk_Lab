# Tier 1 Ticket — Web-App Compromise: Scan + Coordinated Credential Attack

**Analyst:** Kenil (T1)
**Date:** 2026-09-05
**Dataset:** BOTSv1 (Splunk Boss of the SOC v1, 2016-08-10)
**Index:** botsv1
**Total events:** 955,807

## Alert

Active reconnaissance and credential attack against public-facing Joomla CMS. Two distinct attacker IPs observed with role separation (scanner + brute-forcer), suggesting coordinated multi-actor engagement.

## Target

| Field | Value |
|-------|-------|
| Site | imreallynotbatman.com |
| Host IP | 192.168.250.70 |
| Application | Joomla CMS |
| Attack date | 2016-08-10 |

## Attackers Identified (2)

### Attacker A — Broad Scanner + Vulnerability Testing

| Metric | Value |
|--------|-------|
| Source IP | 40.80.148.42 |
| Location | Washington, United States (Microsoft Azure IP space) |
| Total requests | 17,547 |
| Unique paths probed | 1,871 |
| POST requests | 12,844 |
| Assessment | Full-spectrum scanner — mapped entire site and heavily brute-forced form fields with injection payloads |

### Attacker B — Focused Brute-Forcer

| Metric | Value |
|--------|-------|
| Source IP | 23.22.63.114 |
| Location | Ashburn, United States (Amazon EC2 IP space) |
| Total requests | 1,429 |
| Unique paths probed | 1 (targeted a single endpoint only) |
| POST requests | 412 |
| Assessment | Surgical attacker — knew exactly what to target, hammered one endpoint with credential attempts |

## Coordination Assessment

Both attackers used major US cloud provider IPs (Azure + AWS) — modern OPSEC common in attacks where operators use disposable VPS infrastructure. Two IPs in different clouds with complementary roles suggests possible coordinated engagement — either same operator using separate infrastructure to reduce blocking risk, or two coordinated actors sharing target intel.

## Verdict

**True Positive** — active reconnaissance combined with credential attack. Attack volume and coordination indicate serious threat.

## Action

**ESCALATE to Tier 2 immediately** — potential successful breach given attack volume and sophistication. Requires full kill-chain analysis, compromise confirmation, and containment plan.

## Analyst Notes

Two-IP pattern needs deeper analysis in Tier 2:
- Were login attempts successful? Which password worked?
- What tool was Attacker A running (payload signatures suggest a commercial vulnerability scanner)?
- Is there evidence of post-authentication activity (webshell, admin panel access)?
- What did Suricata IDS catch in real time?
