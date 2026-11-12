"""Core guard engine: evaluate -> decide -> persist.

Invariants (see README): rule priority red lines > fence > permission, fail-closed,
credential-bound identity, replay/idempotency defence, atomic quota reservation,
human review with hard timeout, privacy by default, tamper-evident trail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .models import ACTION_SEVERITY, DATA_SEVERITY, AuditRequest, AuditVerdict
from .rules import RuleSet

MAX_SKEW_SECONDS = 300.0
HUMAN_TIMEOUT_SECONDS = 4 * 3600.0
NEAR_LIMIT_RATIO = 0.95
GENESIS_HASH = "0" * 64


# --------------------------------------------------------------------------- utils
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def hash_payload(payload: Any) -> str:
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return sha256_hex(blob)


def _canonical(record: Dict[str, Any]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


# --------------------------------------------------------------------------- trail
class AuditTrail:
    """Append-only, hash-chained JSONL trail. Tampering breaks ``verify()``."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    @property
    def last_hash(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS_HASH

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            entry = dict(record)
            entry["prev_hash"] = self.last_hash
            entry["entry_hash"] = sha256_hex(_canonical(entry))
            self._entries.append(entry)
            if self.path:
                directory = os.path.dirname(os.path.abspath(self.path))
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            return entry

    def verify(self) -> bool:
        """Offline-verifiable integrity check of the whole chain."""
        prev = GENESIS_HASH
        for entry in self._entries:
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if body.get("prev_hash") != prev:
                return False
            if sha256_hex(_canonical(body)) != entry.get("entry_hash"):
                return False
            prev = entry["entry_hash"]
        return True


# --------------------------------------------------------------------------- quota
class QuotaBook:
    """Atomic spend-quota book (per caller / per day / per month).

    ``reserve`` either grants the whole amount or changes nothing, so concurrent
    callers can never overshoot the caps.
    """

    def __init__(self, limits, clock=time.time) -> None:
        self.limits = limits
        self.clock = clock
        self._lock = threading.Lock()
        self._rows: Dict[str, Dict[str, Any]] = {}

    def _row(self, caller_id: str, now: float) -> Dict[str, Any]:
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        month = time.strftime("%Y-%m", time.gmtime(now))
        row = self._rows.setdefault(
            caller_id, {"day": day, "day_used": 0.0, "month": month, "month_used": 0.0}
        )
        if row["day"] != day:
            row["day"], row["day_used"] = day, 0.0
        if row["month"] != month:
            row["month"], row["month_used"] = month, 0.0
        return row

    def reserve(self, caller_id: str, amount: float, now: float) -> Tuple[Optional[str], Dict[str, float]]:
        with self._lock:
            row = self._row(caller_id, now)
            usage = {"day": row["day_used"], "month": row["month_used"]}
            if amount > self.limits.per_call:
                return "per_call", usage
            if row["day_used"] + amount > self.limits.per_day:
                return "per_day", usage
            if row["month_used"] + amount > self.limits.per_month:
                return "per_month", usage
            row["day_used"] += amount
            row["month_used"] += amount
            return None, {"day": row["day_used"], "month": row["month_used"]}

    def release(self, caller_id: str, amount: float, now: float) -> None:
        with self._lock:
            row = self._row(caller_id, now)
            row["day_used"] = max(0.0, round(row["day_used"] - amount, 6))
            row["month_used"] = max(0.0, round(row["month_used"] - amount, 6))

    def usage(self, caller_id: str, now: float) -> Dict[str, float]:
        with self._lock:
            row = self._row(caller_id, now)
            return {"day": row["day_used"], "month": row["month_used"]}


# --------------------------------------------------------------------------- guard
class AuditGuard:
    def __init__(
        self,
        ruleset: Optional[RuleSet] = None,
        trail: Optional[AuditTrail] = None,
        clock=None,
        human_timeout: float = HUMAN_TIMEOUT_SECONDS,
        max_skew: float = MAX_SKEW_SECONDS,
    ) -> None:
        self.rules = ruleset if ruleset is not None else RuleSet.demo()
        self.trail = trail if trail is not None else AuditTrail()
        self.clock = clock or time.time
        self.human_timeout = human_timeout
        self.max_skew = max_skew
        self.quota = QuotaBook(self.rules.fence, clock=self.clock)
        self._creds: Dict[str, str] = {}
        self._nonces: Dict[str, set] = {}
        self._idem: Dict[str, AuditVerdict] = {}
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- registry
    def register_caller(
        self,
        caller_id: str,
        credential: str,
        capabilities: Optional[List[str]] = None,
        max_action: str = "read",
        max_data_class: str = "public",
    ) -> None:
        if not caller_id or not isinstance(credential, str) or not credential:
            raise ValueError("caller_id and credential are required")
        self.rules.register_caller(caller_id, capabilities, max_action, max_data_class)
        self._creds[caller_id] = sha256_hex(credential.encode("utf-8"))

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    # ------------------------------------------------------------------- entry
    def evaluate(self, req: AuditRequest) -> AuditVerdict:
        """Never raises: any unexpected failure resolves to ``deny`` (fail-closed)."""
        try:
            return self._evaluate(req)
        except Exception as exc:  # noqa: BLE001 - intentional fail-closed
            try:
                if getattr(req, "action_type", None) == "spend" and getattr(req, "amount", None):
                    self.quota.release(
                        getattr(req, "caller_id", "unknown"),
                        round(float(req.amount), 6),
                        self.clock(),
                    )
            except Exception:  # noqa: BLE001 - best effort rollback
                pass
            return self._finalize(
                req, "deny", "ERR_INTERNAL_FAIL_CLOSED", "high", [], note=repr(exc)
            )

    # --------------------------------------------------------------- internals
    def _evaluate(self, req: AuditRequest) -> AuditVerdict:
        now = self.clock()

        # 0. structural validation
        if getattr(req, "action_type", None) not in ACTION_SEVERITY:
            return self._finalize(req, "deny", "ERR_BAD_ACTION_TYPE", "high", [])
        if getattr(req, "data_class", None) not in DATA_SEVERITY:
            return self._finalize(req, "deny", "ERR_BAD_DATA_CLASS", "high", [])

        # 1. identity: credential must match the registered caller
        expected = self._creds.get(getattr(req, "caller_id", None))
        given = sha256_hex(str(getattr(req, "credential", "")).encode("utf-8"))
        if expected is None or not hmac.compare_digest(expected, given):
            return self._finalize(req, "deny", "ERR_AUTH_FAILED", "high", [])

        # 2. capability registration and grant
        if req.target_capability not in self.rules.capabilities:
            return self._finalize(req, "deny", "ERR_UNKNOWN_CAPABILITY", "high", [])
        grant = self.rules.permissions.get(req.caller_id, {})
        if req.target_capability not in grant.get("capabilities", []):
            return self._finalize(req, "deny", "ERR_CAPABILITY_NOT_GRANTED", "high", [])

        # 3. request integrity
        if req.payload is not None:
            if hash_payload(req.payload) != req.request_hash:
                return self._finalize(req, "deny", "ERR_HASH_MISMATCH", "high", [])
        elif not is_sha256(req.request_hash):
            return self._finalize(req, "deny", "ERR_HASH_MISMATCH", "high", [])

        # 4. freshness
        try:
            skew = abs(now - float(req.timestamp))
        except (TypeError, ValueError):
            skew = self.max_skew + 1.0
        if skew > self.max_skew:
            return self._finalize(req, "deny", "ERR_STALE_REQUEST", "high", [])

        # 5. idempotency (safe retries)
        if req.idempotency_key:
            with self._lock:
                cached = self._idem.get(req.idempotency_key)
            if cached is not None:
                payload = cached.as_dict()
                payload["idempotent_replay"] = True
                return AuditVerdict(**payload)

        # 6. replay defence (single-use nonce per caller)
        with self._lock:
            seen = self._nonces.setdefault(req.caller_id, set())
            if req.nonce in seen:
                return self._finalize(req, "deny", "ERR_REPLAY", "high", [])
            seen.add(req.nonce)

        # 7. red lines (highest priority)
        for rule in self.rules.red_lines:
            if rule.matches(req):
                return self._finalize(
                    req, "deny", "ERR_RED_LINE", "high", [rule.id], note=rule.description
                )

        # 8. permission matrix
        if ACTION_SEVERITY[req.action_type] > ACTION_SEVERITY.get(grant.get("max_action", "read"), 0):
            return self._finalize(req, "deny", "ERR_PERMISSION_ACTION", "high", [])
        if DATA_SEVERITY[req.data_class] > DATA_SEVERITY.get(grant.get("max_data_class", "public"), 0):
            return self._finalize(req, "deny", "ERR_PERMISSION_DATA_CLASS", "high", [])

        # 9. fence limits (atomic reservation; released for deny/human-timeout)
        reserved = 0.0
        usage = {"day": 0.0, "month": 0.0}
        if req.action_type == "spend" and req.amount is not None:
            amount = round(float(req.amount), 6)
            if amount <= 0:
                return self._finalize(req, "deny", "ERR_BAD_AMOUNT", "high", [])
            breach, usage = self.quota.reserve(req.caller_id, amount, now)
            if breach:
                return self._finalize(
                    req, "deny", "ERR_LIMIT_EXCEEDED", "high", ["fence:%s" % breach]
                )
            reserved = amount

        # 10. risk grading -> human review
        risk = "low"
        if req.action_type in ("write", "outbound", "spend"):
            risk = "medium"
        if req.action_type in ("outbound", "spend") and DATA_SEVERITY[req.data_class] >= DATA_SEVERITY["sensitive"]:
            risk = "high"
        if risk == "high":
            return self._finalize(req, "human", "HUMAN_REVIEW_REQUIRED", "high", [])
        if reserved:
            near_day = usage["day"] >= NEAR_LIMIT_RATIO * self.rules.fence.per_day
            near_month = usage["month"] >= NEAR_LIMIT_RATIO * self.rules.fence.per_month
            if near_day or near_month:
                return self._finalize(req, "human", "HUMAN_LIMIT_NEAR_THRESHOLD", "medium", [])

        return self._finalize(req, "allow", "ALLOWED", risk, [])

    def _finalize(
        self,
        req: AuditRequest,
        decision: str,
        reason_code: str,
        risk_level: str,
        matched_rules: List[str],
        note: Optional[str] = None,
    ) -> AuditVerdict:
        now = self.clock()
        trace_id = uuid.uuid4().hex
        expires_at: Optional[float] = None
        if decision == "human":
            expires_at = now + self.human_timeout
            with self._lock:
                self._pending[trace_id] = {
                    "caller_id": getattr(req, "caller_id", None),
                    "amount": round(float(getattr(req, "amount", 0.0) or 0.0), 6),
                    "deadline": expires_at,
                    "reason_code": reason_code,
                }

        verdict = AuditVerdict(
            decision=decision,
            reason_code=reason_code,
            risk_level=risk_level,
            matched_rules=list(matched_rules),
            trace_id=trace_id,
            created_at=now,
            expires_at=expires_at,
        )

        # only settled verdicts are cached for idempotent retries
        if getattr(req, "idempotency_key", None) and decision != "human":
            with self._lock:
                self._idem[req.idempotency_key] = verdict

        self.trail.append(
            {
                "trace_id": trace_id,
                "ts": now,
                "caller_id": getattr(req, "caller_id", None),
                "capability": getattr(req, "target_capability", None),
                "action_type": getattr(req, "action_type", None),
                "data_class": getattr(req, "data_class", None),
                "amount": getattr(req, "amount", None),
                "request_hash": getattr(req, "request_hash", None),  # hash only: no payload
                "decision": decision,
                "reason_code": reason_code,
                "risk_level": risk_level,
                "matched_rules": list(matched_rules),
                "note": note,
            }
        )
        return verdict

    # ------------------------------------------------------- human in the loop
    def resolve(self, trace_id: str, approve: bool) -> Optional[AuditVerdict]:
        """Resolve a pending human review. Deny/timeout releases the reserved quota."""
        with self._lock:
            item = self._pending.pop(trace_id, None)
        if item is None:
            return None
        now = self.clock()
        if approve:
            decision, reason, risk = "allow", "HUMAN_APPROVED", "medium"
        else:
            decision, reason, risk = "deny", "HUMAN_DENIED", "high"
            if item["amount"]:
                self.quota.release(item["caller_id"], item["amount"], now)
        verdict = AuditVerdict(
            decision=decision,
            reason_code=reason,
            risk_level=risk,
            matched_rules=[],
            trace_id=trace_id,
            created_at=now,
        )
        self._record_resolution(trace_id, decision, reason, item)
        return verdict

    def expire_pending(self) -> List[AuditVerdict]:
        """Resolve overdue reviews as ``deny`` (hard timeout)."""
        now = self.clock()
        with self._lock:
            overdue = [tid for tid, item in self._pending.items() if item["deadline"] <= now]
        out: List[AuditVerdict] = []
        for trace_id in overdue:
            with self._lock:
                item = self._pending.pop(trace_id, None)
            if item is None:
                continue
            if item["amount"]:
                self.quota.release(item["caller_id"], item["amount"], now)
            verdict = AuditVerdict(
                decision="deny",
                reason_code="ERR_HUMAN_TIMEOUT",
                risk_level="high",
                matched_rules=[],
                trace_id=trace_id,
                created_at=now,
            )
            self._record_resolution(trace_id, "deny", "ERR_HUMAN_TIMEOUT", item)
            out.append(verdict)
        return out

    def _record_resolution(self, trace_id: str, decision: str, reason: str, item: Dict[str, Any]) -> None:
        self.trail.append(
            {
                "trace_id": trace_id,
                "ts": self.clock(),
                "caller_id": item.get("caller_id"),
                "action_type": "human_review",
                "amount": item.get("amount"),
                "decision": decision,
                "reason_code": reason,
                "risk_level": "high" if decision == "deny" else "medium",
                "matched_rules": [],
                "note": "human resolution",
            }
        )
