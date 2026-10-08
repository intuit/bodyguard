"""Make Python trust the operating system's certificate store.

Corporate networks often terminate TLS with their own root CA (Zscaler, Netskope,
…). The OS trusts it, so curl and browsers work, but Python ships its own
`certifi` bundle and fails with CERTIFICATE_VERIFY_FAILED — and Google's client
libraries retry that error for minutes, which looks like a hang.

`truststore` (Python 3.10+) swaps the default SSL context for one backed by the
OS store. Call `use_system_trust_store()` once, before any HTTPS request.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def use_system_trust_store() -> bool:
    """Route Python's TLS verification through the OS trust store. Returns True if enabled."""
    try:
        import truststore
    except ImportError:
        log.debug("truststore not installed; using certifi bundle")
        return False
    truststore.inject_into_ssl()
    return True
