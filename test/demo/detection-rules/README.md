# detection-rules

Production detection rules run daily by the security data platform against the
`bodyguard_demo` dataset in BigQuery. Each rule file belongs to one team; each
rule is one `SELECT` statement with a header comment describing its signal and
an example hit.

## Rule files

| File | Owner | Slack | Rules |
|---|---|---|---|
| `phishing.sql` | brand-protection-team | #brand-protection | Brand impersonation · Credential harvesting · Token theft |
| `malware.sql` | threat-hunting-team | #threat-hunting | C2 beaconing · Malware distribution · Payload drop on young domains |
| `web_attack.sql` | appsec-team | #appsec | XSS · Layer 7 DDoS · SQL injection |

## Tables (`schema/`)

| Table | Grain | Content |
|---|---|---|
| `urls_30d` | url × day | Gateway/WAF URL aggregates: path, query string, WAF rule and action |
| `domains_30d` | domain × day | Domain aggregates with WHOIS age, brand-similarity score, suspicious keywords |
| `ip_30d` | client_ip × day | Source-IP behaviour: rate, path diversity, block/error rate, method, UA, top host |
| `ip_reputation` | ip | Nightly merge of threat-intelligence feeds: category, source feed, confidence |

All three `*_30d` tables keep a rolling 30 daily windows.

## Running a rule file

```bash
bq query --use_legacy_sql=false --project_id=<project> < phishing.sql
```
