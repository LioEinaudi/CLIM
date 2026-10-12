"""Codex hook transport for CLIM v0.1.3; pilot only, POSIX file lock.

One admitted in-flight patch per configured state store. All policy and ledger
files must be held outside the agent-writable project and protected by OS ACLs.
This hook is NOT an OS sandbox or a universal Codex tool interceptor.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from clim_agent_guard.core import (
    ActionProposal, ArgumentBinding, Decision, EffectStatus, IntegrityGuard,
    StateCondition, ToolContract,
)

MAX_INPUT = 1_000_000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_hash(obj: Any) -> str:
    return digest(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())


def policy_path() -> Path:
    value = os.environ.get("CLIM_CODEX_POLICY", "")
    if not value or not Path(value).is_absolute():
        raise ValueError("CLIM_CODEX_POLICY must point to an absolute trusted JSON file")
    return Path(value)


def store_dir() -> Path:
    value = os.environ.get("CLIM_CODEX_STATE_DIR", "")
    if not value or not Path(value).is_absolute():
        raise ValueError("CLIM_CODEX_STATE_DIR must be an absolute trusted directory")
    return Path(value)


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, value: Any) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".clim-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, sort_keys=True, ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def locked_state():
    home = store_dir()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(home / "lock", "a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield home
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def append_audit(home: Path, event: dict[str, Any]) -> None:
    with open(home / "audit.jsonl", "a", encoding="utf-8") as out:
        out.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
        out.flush()
        os.fsync(out.fileno())


def record_hook(mode: str, event: Any, output: dict[str, Any]) -> None:
    """Preserve transport evidence separately from CLIM's decision ledger."""
    with locked_state() as home:
        record = {"mode": mode, "input": event, "output": output,
                  "recorded_at": datetime.now(timezone.utc).isoformat()}
        with open(home / "hook_events.jsonl", "a", encoding="utf-8") as out:
            out.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            out.flush()
            os.fsync(out.fileno())


def read_policy(event: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    policy = load_json(policy_path())
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    required = {"_version", "project_root", "authorized_target", "protected_targets", "user_confirmed"}
    if not required.issubset(policy):
        raise ValueError("Missing policy fields: " + str(sorted(required - set(policy))))
    if not isinstance(policy["_version"], int) or isinstance(policy["_version"], bool) or policy["_version"] < 0:
        raise ValueError("Invalid policy state version")
    if not isinstance(policy["user_confirmed"], bool):
        raise ValueError("Invalid host confirmation type")
    root = Path(policy["project_root"])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError("Project root must exist and be absolute, without being a symlink")
    root = root.resolve(strict=True)
    if Path(event.get("cwd", "")).resolve(strict=False) != root:
        raise ValueError("Hook cwd does not match configured project root")
    if not isinstance(policy["authorized_target"], str) or not isinstance(policy["protected_targets"], list):
        raise ValueError("Invalid target configuration")
    if not policy["protected_targets"] or not all(isinstance(x, str) for x in policy["protected_targets"]):
        raise ValueError("At least one protected target is required")
    if root == policy_path().resolve(strict=True) or root in policy_path().resolve(strict=True).parents:
        raise ValueError("Policy must be located outside agent project")
    home = store_dir().resolve(strict=False)
    if root == home or root in home.parents:
        raise ValueError("State directory must be located outside agent project")
    for target in [policy["authorized_target"], *policy["protected_targets"]]:
        resolve_target(root, target)
    return policy, root


def resolve_target(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\x00" in name or name.strip() != name:
        raise ValueError("Invalid file target")
    raw = Path(name)
    item = raw if raw.is_absolute() else root / raw
    resolved = item.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("File escapes workspace root") from None
    if item.is_symlink() or resolved.is_symlink():
        raise ValueError("Symlink target not supported in pilot")
    if not resolved.is_file():
        raise ValueError("Only existing regular files supported in pilot")
    return resolved


def observed_hashes(root: Path, policy: dict[str, Any]) -> dict[str, str | None]:
    result = {}
    for name in dict.fromkeys([policy["authorized_target"], *policy["protected_targets"]]):
        try:
            p = resolve_target(root, name)
            result[name] = digest(p.read_bytes())
        except (OSError, ValueError):
            result[name] = None
    return result


def parse_single_update_patch(command: Any) -> str:
    if not isinstance(command, str) or len(command) > MAX_INPUT or "\x00" in command:
        raise ValueError("Missing or invalid apply_patch command")
    lines = command.strip().splitlines()
    if len(lines) < 4 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("Expected complete native apply_patch envelope")
    headers = []
    for line in lines[1:-1]:
        if line.startswith("*** "):
            m = re.fullmatch(r"\*\*\* (Update|Add|Delete) File: (.+)", line)
            if m is None:
                # Includes Move to: and all unknown patch metacommands.
                raise ValueError("Unsupported patch header")
            headers.append((m.group(1), m.group(2)))
    if len(headers) != 1 or headers[0][0] != "Update":
        raise ValueError("Pilot only authorizes one Update File in a patch")
    return headers[0][1]


def build_guard() -> IntegrityGuard:
    contract = ToolContract(
        tool="codex_apply_patch",
        preconditions=(StateCondition("user_confirmed", "eq", True, "USER_CONFIRMATION_REQUIRED"),),
        argument_bindings=(ArgumentBinding(
            arg_path="path", state_path="authorized_path", value_type="path_canonical",
            base_state_path="sandbox_root", code="TARGET_NOT_AUTHORIZED"),),
        postconditions=(
            StateCondition("observed.allowed_changed", "eq", True, "EXPECTED_EFFECT_NOT_OBSERVED"),
            StateCondition("observed.protected_unchanged", "eq", True, "UNAUTHORIZED_EFFECT_OBSERVED"),
        ),
        require_idempotency_key=True,
        requires_fresh_state=True,
    )
    return IntegrityGuard((contract,))


def guard_state(policy: dict[str, Any], root: Path) -> dict[str, Any]:
    return {
        "_version": policy["_version"],
        "user_confirmed": policy["user_confirmed"],
        "authorized_path": policy["authorized_target"],
        "sandbox_root": str(root),
    }


def decision_deny(message: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "deny", "permissionDecisionReason": "CLIM: " + message[:500]}}


def post_alert(message: str) -> dict[str, Any]:
    return {"decision": "block", "reason": "CLIM: " + message[:500]}


def validate_identity(event: dict[str, Any], expected: str) -> tuple[str, str, str]:
    if event.get("hook_event_name") != expected:
        raise ValueError("Incorrect hook event")
    session, tool_id = event.get("session_id"), event.get("tool_use_id")
    if not isinstance(session, str) or not session or not isinstance(tool_id, str) or not tool_id:
        raise ValueError("Missing session_id/tool_use_id")
    if len(session) > 512 or len(tool_id) > 512:
        raise ValueError("Oversized session or tool identifier")
    return session, tool_id, digest((session + "\x00" + tool_id).encode())


def pre(event: dict[str, Any]) -> dict[str, Any]:
    try:
        session, tool_id, key = validate_identity(event, "PreToolUse")
        with locked_state() as home:
            if not isinstance(event.get("tool_input"), dict):
                raise ValueError("Missing tool_input object")
            if event.get("tool_name") != "apply_patch":
                raise ValueError("Only native apply_patch is supported; Bash and other tools denied")
            policy, root = read_policy(event)
            target = parse_single_update_patch(event["tool_input"].get("command"))
            # Only exact, inspectable local files; CLIM handles identity binding.
            resolve_target(root, target)
            snapshot = guard_state(policy, root)
            pending = load_json(home / "pending.json", {})
            if (home / "incident.json").exists():
                raise ValueError("Prior effect uncertainty; operator reconciliation required")
            if pending:
                raise ValueError("Unverified prior effect; reconcile before next operation")
            guard = build_guard()
            checkpoint = load_json(home / "ledger.json")
            if checkpoint is not None:
                guard.load_state(checkpoint)
            proposal = ActionProposal(
                tool="codex_apply_patch", args={"path": target},
                observed_state_version=policy["_version"], action_id=key,
                idempotency_key=key,
            )
            decision = guard.precheck(proposal, snapshot)
            record = {"phase": "PRE", "session": session, "tool_use_id": tool_id,
                      "action_id": key, "target": target, "policy_sha256": json_hash(policy),
                      "proposal_sha256": json_hash(event["tool_input"]),
                      "decision": decision.decision.value, "code": decision.code}
            append_audit(home, record)
            if decision.decision != Decision.ALLOW:
                return decision_deny(decision.code)
            pending[key] = {"session": session, "tool_use_id": tool_id,
                            "policy_sha256": json_hash(policy), "policy": policy,
                            "before_hashes": observed_hashes(root, policy),
                            "before_state": snapshot, "target": target,
                            "proposal": {"path": target, "action_id": key, "idempotency_key": key,
                                         "observed_state_version": policy["_version"]}}
            atomic_json(home / "ledger.json", guard.dump_state())
            atomic_json(home / "pending.json", pending)
            return {"systemMessage": "CLIM: authorized file target; awaiting effect verification"}
    except Exception as exc:
        # Always return a valid deny JSON, including for unsupported tools.
        # Logging is best effort if the trusted store itself is unavailable.
        try:
            with locked_state() as home:
                append_audit(home, {"phase": "PRE", "decision": "BLOCK",
                    "code": "ADAPTER_DENY", "tool_name": str(event.get("tool_name", ""))[:100],
                    "session": str(event.get("session_id", ""))[:100],
                    "tool_use_id": str(event.get("tool_use_id", ""))[:100],
                    "reason": type(exc).__name__ + ": " + str(exc)[:300]})
        except Exception:
            pass
        return decision_deny(type(exc).__name__ + ": " + str(exc))


def post(event: dict[str, Any]) -> dict[str, Any]:
    try:
        session, tool_id, key = validate_identity(event, "PostToolUse")
        with locked_state() as home:
            pending = load_json(home / "pending.json", {})
            attempt = pending.get(key)
            if not attempt:
                raise ValueError("PostToolUse has no matching authorized precheck")
            policy, root = read_policy(event)
            guard = build_guard()
            guard.load_state(load_json(home / "ledger.json"))
            after = observed_hashes(root, policy)
            before = attempt["before_hashes"]
            allowed = attempt["policy"]["authorized_target"]
            protected = policy["protected_targets"]
            allowed_changed = before.get(allowed) is not None and after.get(allowed) is not None and before[allowed] != after[allowed]
            protected_unchanged = all(before.get(p) is not None and before.get(p) == after.get(p) for p in protected)
            current_version_matches = json_hash(policy) == attempt["policy_sha256"]
            proposal_data = attempt["proposal"]
            proposal = ActionProposal(tool="codex_apply_patch", args={"path": proposal_data["path"]},
                action_id=proposal_data["action_id"], idempotency_key=proposal_data["idempotency_key"],
                observed_state_version=proposal_data["observed_state_version"])
            # Treat missing evidence / changed authority as uncertain. Tool response
            # is not enough to declare a verified effect.
            if not current_version_matches or not protected_unchanged or not allowed_changed:
                status = EffectStatus.UNKNOWN
            else:
                status = EffectStatus.SUCCESS
            after_state = dict(attempt["before_state"])
            after_state["observed"] = {"allowed_changed": allowed_changed,
                "protected_unchanged": protected_unchanged}
            verdict = guard.verify_effect(proposal, attempt["before_state"], after_state, status)
            append_audit(home, {"phase": "POST", "session": session, "tool_use_id": tool_id,
                "action_id": key, "decision": verdict.decision.value, "code": verdict.code,
                "effect_status": status.value, "allowed_changed": allowed_changed,
                "protected_unchanged": protected_unchanged,
                "policy_unchanged": current_version_matches,
                "file_hashes_before": before, "file_hashes_after": after})
            atomic_json(home / "ledger.json", guard.dump_state())
            del pending[key]
            atomic_json(home / "pending.json", pending)
            if verdict.decision != Decision.ALLOW:
                atomic_json(home / "incident.json", {
                    "action_id": key, "reason": verdict.code,
                    "note": "Manual reconciliation required; do not delete this file without review"})
            if verdict.decision == Decision.ALLOW:
                return {"systemMessage": "CLIM: EFFECT_VERIFIED for authorized file"}
            return post_alert("POST_EFFECT_UNVERIFIED: " + verdict.code)
    except Exception as exc:
        return post_alert(type(exc).__name__ + ": " + str(exc))
