# C2 Beaconing Detection — Runbook

**Owner:** threat-hunting-team (Slack: #threat-hunting)
**Last reviewed:** 2025-03-18
**Applies to:** `malware.sql` Rule 1 (C2_BEACONING)

## Overview

Compromised hosts inside the estate periodically "check in" with their command-and-control (C2) server. Our C2 beaconing detection correlates two signals: the behavioural aggregates produced by the gateway/WAF pipeline, and the nightly IP reputation feed (`ip_reputation`). An IP is raised as a C2 client when *either* source is conclusive, so that low-volume beacons known to a threat feed are not missed.

The detection runs daily over the previous 24-hour window and pushes results to the SOC queue with a severity derived from how many signals agree.

---

## Detection Logic

### Path A — Behavioural (no reputation needed)

An IP is flagged when, within one daily window, all of the following hold:

- Source is a datacenter / hosting range (`is_datacenter = TRUE`)
- Request rate above **50 requests per hour** (tuned down from 100 after the 2024-Q4 incident, where the beacon interval was 90 seconds)
- At most 3 distinct paths
- HTTP method is POST
- Error rate below 5 % (the C2 server answers successfully)
- Non-browser User-Agent

### Path B — Reputation-confirmed

Any IP present in `ip_reputation` with `category = 'malware_c2'` and `confidence >= 0.8` is flagged **regardless of volume**. This is what catches slow beacons (one check-in every few hours) that Path A would never see.

### Path C — Tor-sourced beaconing (added 2025-Q1)

Beacons from Tor exit nodes (`is_tor_exit = TRUE`) are evaluated with the Path A thresholds but *without* the datacenter requirement, since Tor exits are rarely in hosting ranges.

---

## Severity

| Signals agreeing | Severity |
|---|---|
| Behavioural + reputation | Critical |
| Behavioural only | High |
| Reputation only | High |
| Tor-sourced (Path C) | Medium |

---

## Triage

1. Confirm the destination host (`top_host`) is not a known SaaS / telemetry endpoint. The exclusion list lives in the rule.
2. Pull the most-visited URL for the host from `urls_30d`. Beacon URLs typically carry a host identifier (`uuid=`, `id=`) and a command verb (`cmd=`, `task=`).
3. Cross-check the source IP in `ip_reputation`. A `malware_c2` hit with a named framework in `notes` is enough to open an incident without further validation.
4. Known-benign high-rate sources (uptime monitors, CDN health checks) are listed under `category = 'monitoring'` and are auto-suppressed by the rule.

---

## Example

> IP `198.51.100.23` — 200 req/h, 2 paths, POST, `Go-http-client/2.0`, host `cdn-update.analytics-track.ru`.
> Reputation: `malware_c2`, confidence 0.95, "team-server beacon profile".
> **Result:** Critical (behavioural + reputation).

---

## Known Limitations

- HTTPS-only C2 that never touches the gateway is invisible to this pipeline.
- Beacons that rotate paths (jitter on the URI) defeat the `unique_paths <= 3` condition.
- Domain-fronted C2 will show a reputable `top_host` and requires Path B to be caught.
