# Vendored from agent-call-audit v0.1.0 (MIT, same maintainers).
# The engine is kept verbatim so this firewall is self-contained and
# installable without depending on a not-yet-released package. audit_guard is
# the tamper-evident hash-chain engine; agent_firewall is the MCP adjudication
# layer on top of it.
"""agent-call-audit — dependency-free guardrail layer for agent tool calls.

Public surface::

    from audit_guard import (
        AuditGuard, AuditTrail, AuditRequest, AuditVerdict,
        RuleSet, RedLineRule, FenceLimits,
        hash_payload, sha256_hex, is_sha256,
    )
"""

from .models import AuditRequest, AuditVerdict, ACTION_SEVERITY, DATA_SEVERITY
from .rules import FenceLimits, RedLineRule, RuleSet
from .engine import (
    AuditGuard,
    AuditTrail,
    QuotaBook,
    hash_payload,
    is_sha256,
    sha256_hex,
)

__version__ = "0.1.0"

__all__ = [
    "AuditGuard",
    "AuditTrail",
    "QuotaBook",
    "AuditRequest",
    "AuditVerdict",
    "RuleSet",
    "RedLineRule",
    "FenceLimits",
    "hash_payload",
    "sha256_hex",
    "is_sha256",
    "ACTION_SEVERITY",
    "DATA_SEVERITY",
    "__version__",
]
