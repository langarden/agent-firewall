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
