#!/usr/bin/env python3
"""Independent, read-only fixture snapshot / effect-set oracle for CLIM Shadow.

This does NOT prove which process caused a change or whether Codex hooks fired.
Only inspect dedicated disposable test fixtures, not private production repos.
Requires Python >=3.10. No third-party dependencies.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

MAX_HASH_BYTES = 8 * 1024 * 1024
MAX_INVENTORY = 10000


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump(path: str | Path | None, obj):
    output = json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


def safe_rel(path: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        raise ValueError(f"Invalid inventory path: {path!r}")
    p = PurePosixPath(path)
    if p.is_absolute() or any(part in ("..", "") for part in p.parts) or path != p.as_posix():
        raise ValueError(f"Unsafe inventory path: {path!r}")
    return path


def one(root: Path, name: str):
    """Never follow symlinks for file content. Record target *metadata* only."""
    file = root / name
    cur = root
    hops = []
    try:
        for part in PurePosixPath(name).parts:
            cur = cur / part
            if cur.is_symlink():
                raw = os.readlink(cur)
                resolved = cur.resolve(strict=False)
                hops.append({"at": cur.relative_to(root).as_posix(),
                             "target_string_sha256": digest(raw.encode()),
                             "resolved_inside_root": resolved.is_relative_to(root)})
        if hops:
            return {"kind": "symlink_path", "symlink_hops": hops,
                    "coverage": "not_followed"}
        if not file.exists():
            return {"kind": "missing", "coverage": "complete"}
        if file.is_dir():
            return {"kind": "directory", "coverage": "metadata_only"}
        if not file.is_file():
            return {"kind": "special", "coverage": "unreadable"}
        size = file.stat().st_size
        if size > MAX_HASH_BYTES:
            return {"kind": "file", "bytes": size, "coverage": "oversize"}
        h = hashlib.sha256()
        with file.open("rb") as handle:
            while chunk := handle.read(128 * 1024):
                h.update(chunk)
        return {"kind": "file", "bytes": size, "sha256": h.hexdigest(), "coverage": "complete"}
    except (PermissionError, OSError) as exc:
        return {"kind": "unknown", "coverage": "unreadable",
                "error_type": type(exc).__name__}


def capture(root: str, inventory: str):
    project = Path(root).resolve(strict=True)
    listed = load(inventory)
    if isinstance(listed, dict):
        listed = listed.get("paths")
    if not isinstance(listed, list) or not listed or len(listed) > MAX_INVENTORY:
        raise ValueError("Inventory must be a list of 1..10000 paths")
    paths = sorted(set(safe_rel(path) for path in listed))
    return {"schema": "clim-fixture-snapshot/v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "root": str(project), "inventory_count": len(paths),
            "limits": {"hash_bytes_max": MAX_HASH_BYTES,
                       "inventory_max": MAX_INVENTORY},
            "files": {name: one(project, name) for name in paths}}


def tracked(snap):
    if snap.get("schema") != "clim-fixture-snapshot/v1":
        raise ValueError("Snapshot schema missing or unsupported")
    return snap["files"]


def fingerprint(meta):
    kind = meta.get("kind")
    if kind == "file" and meta.get("coverage") == "complete":
        return (kind, meta.get("sha256"), meta.get("bytes"))
    if kind == "missing":
        return (kind,)
    if kind == "symlink_path":
        return (kind, json.dumps(meta.get("symlink_hops", []), sort_keys=True))
    return None


def effect_compare(before, after, proposed, authorized=None, required=None):
    if before.get("root") != after.get("root"):
        raise ValueError("Independent snapshots must refer to the same fixture root")
    first, last = tracked(before), tracked(after)
    keys = set(first) & set(last)
    gap = sorted((set(first) ^ set(last)) |
                 {k for k in keys if fingerprint(first[k]) is None or fingerprint(last[k]) is None
                  or first[k].get("kind") == "symlink_path" or last[k].get("kind") == "symlink_path"})
    changed = sorted(k for k in keys if k not in gap and fingerprint(first[k]) != fingerprint(last[k]))
    link_metadata_changed = sorted(k for k in keys
                                   if first[k].get("kind") == "symlink_path"
                                   and last[k].get("kind") == "symlink_path"
                                   and first[k].get("symlink_hops") != last[k].get("symlink_hops"))
    prop = {safe_rel(x) for x in proposed}
    auth = {safe_rel(x) for x in authorized} if authorized is not None else None
    req = {safe_rel(x) for x in required} if required is not None else None
    verifiable = keys - set(gap)
    required_unknown = sorted(req - verifiable) if req is not None else None
    # A missing required effect is only measurable where both snapshots are adequate.
    missing = sorted((req & verifiable) - set(changed)) if req is not None else None
    return {"schema": "clim-independent-effect-oracle/v1",
            "source": "independent fixture file snapshots (not Codex/CLIM telemetry)",
            "captured_before_at": before.get("captured_at"),
            "captured_after_at": after.get("captured_at"),
            "observation_inventory_count": len(keys),
            "observed_changed_paths": changed,
            "symlink_metadata_changed_paths_not_content_proof": link_metadata_changed,
            "R_proposal": sorted(set(changed) - prop),
            "R_authority": sorted(set(changed) - auth) if auth is not None else None,
            "R_missing": missing,
            "required_effect_unknown_paths": required_unknown,
            "coverage_gap_paths": gap,
            "unobserved_proposal_paths": sorted(prop - verifiable),
            "unobserved_authorized_paths": sorted(auth - verifiable) if auth is not None else None,
            "authority_trust": "HOST_DECLARED_INPUT_ONLY" if auth is not None else "AUTHORITY_UNKNOWN",
            "attribution": "UNKNOWN_UNLESS_EXCLUSIVE_WRITER_INDEPENDENTLY_VERIFIED",
            "caveat": "Snapshot deltas cannot establish Agent attribution, detect unlisted paths, or prove a missing effect beyond observed coverage."}


def audit_check(path: str):
    events = []
    malformed = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            malformed += 1
    pres = {}
    posts = set()
    shadow_denials = []
    for e in events:
        use = e.get("tool_use_id")
        session = e.get("session_id")
        if e.get("phase") == "PRE" and use:
            pres[(session, use)] = e
            if e.get("mode") == "shadow" and (e.get("decision") == "BLOCK" or e.get("enforced") is True):
                shadow_denials.append(use)
        if e.get("phase") == "POST" and use:
            # Some v0.2 POST events omit session_id. Pair by tool ID when unique.
            posts.add(use)
    missing = sorted(use for (session, use), e in pres.items()
                     if e.get("tool") == "apply_patch" and use not in posts
                     and e.get("decision") not in ("BLOCK",))
    return {"schema": "clim-audit-consistency/v1", "events": len(events),
            "malformed_lines": malformed, "pre_count": len(pres),
            "post_count": sum(e.get("phase") == "POST" for e in events),
            "missing_post_candidates": missing,
            "shadow_active_denial_ids": shadow_denials,
            "note": "This checks event consistency only. Missing post is a coverage gap; tool IDs need uniqueness. Hook-invocation denominator needs an independent Codex trace."}


def privacy_scan(paths, sentinel_file):
    canary = Path(sentinel_file).read_bytes().strip()
    if len(canary) < 12:
        raise ValueError("Test canary must be at least 12 bytes")
    matches = []
    inspected = 0
    for spec in paths:
        p = Path(spec)
        files = [f for f in p.rglob("*") if f.is_file() and not f.is_symlink()] if p.is_dir() else [p]
        for f in files:
            inspected += 1
            if canary in f.read_bytes():
                matches.append(str(f))
    return {"schema": "clim-canary-scan/v1", "scanned_files": inspected,
            "plaintext_leak_count": len(matches), "leak_file_paths": matches,
            "pass_default_storage_privacy": not matches,
            "note": "Scan ONLY CLIM-owned state/report outputs, not the input fixture or native Codex transcript. Canary bytes are never printed."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture"); cap.add_argument("--root", required=True); cap.add_argument("--inventory", required=True); cap.add_argument("--out", required=True)
    com = sub.add_parser("compare"); com.add_argument("--before", required=True); com.add_argument("--after", required=True); com.add_argument("--proposed", required=True); com.add_argument("--authorized"); com.add_argument("--required"); com.add_argument("--out")
    aud = sub.add_parser("audit"); aud.add_argument("--events", required=True); aud.add_argument("--out")
    pri = sub.add_parser("privacy"); pri.add_argument("--sentinel-file", required=True); pri.add_argument("--path", action="append", required=True); pri.add_argument("--out")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "capture":
            obj = capture(args.root, args.inventory)
        elif args.cmd == "compare":
            def names(file):
                value = load(file)
                return value["paths"] if isinstance(value, dict) else value
            obj = effect_compare(load(args.before), load(args.after), names(args.proposed),
                                 names(args.authorized) if args.authorized else None,
                                 names(args.required) if args.required else None)
        elif args.cmd == "audit":
            obj = audit_check(args.events)
        else:
            obj = privacy_scan(args.path, args.sentinel_file)
        dump(args.out, obj)
        if args.cmd == "privacy" and obj["plaintext_leak_count"]:
            return 2
        if args.cmd == "audit" and (obj["malformed_lines"] or obj["shadow_active_denial_ids"]):
            return 2
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"ORACLE ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
