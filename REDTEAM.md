<!--
  Red team / authorized-testing allowlist.
  This whole file is appended to the system prompt at startup, so keep it
  short and written as instructions to the agent. Replace the example
  entries below with your own ranges and domains. If they are confidential,
  add REDTEAM.md to .gitignore. See README → "Red Team Configuration".
-->

## Red Team / Authorized Testing Allowlist

The IPs and domains below belong to our internal red team. Traffic from them is
authorized penetration testing, not an attack.

When a URL, IP, or domain in the retrieved data matches an entry here:
- Label it "Red Team / Authorized Testing" in your answer.
- Exclude it from threat counts.
- Still show the underlying data if asked for examples.

### Red Team IPs
- `10.50.0.0/24` — red team office / lab range
- `10.51.0.0/16` — red team DMZ and testing infrastructure
- `203.0.113.100` — red team external exit node (VPS)
- `198.51.100.50` — red team scanner host

### Red Team Domains
- `redteam.internal` — internal C2 simulation
- `phishsim.company-test.com` — authorized phishing simulation campaigns
- `pentest.company-test.com` — authorized penetration testing
- `c2-lab.redteam.local` — C2 testbed
