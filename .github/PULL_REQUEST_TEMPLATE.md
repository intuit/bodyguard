## Checklist

🚨 Please review this repository's [contribution guidelines](../CONTRIBUTING.md).

- [ ] I've read and agree to the project's [contribution guidelines](../CONTRIBUTING.md).
- [ ] I'm requesting to pull a topic/feature/bugfix branch.
- [ ] I checked that `make test` passes.
- [ ] I updated unit tests (if applicable).
- [ ] My change adds no organization-specific data — IPs are from the RFC 5737
      documentation ranges, ASNs from RFC 5398, and no internal hostnames,
      proprietary schemas, or employer-specific references are included.
- [ ] If I changed retrieval, chunking, or a prompt file, I included before/after
      output for the affected questions (see below).
- [ ] I've read and agree to the [Code of Conduct](../CODE_OF_CONDUCT.md).

## Description

What does this change do and why?

Closes #

## Retrieval / prompt changes

Delete this section if your change does not touch `agent/core.py`,
`kb/builder.py`, `agent/prompts.md`, or `REDTEAM.md`.

A prompt or retrieval tweak that fixes one question routinely breaks another, so
please show the effect on more than the question you were fixing. Model used:

**Before**

```
```

**After**

```
```

Thank you!
