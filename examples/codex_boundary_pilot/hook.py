#!/usr/bin/env python3
"""Codex JSON stdin/stdout bridge; use 'pre' or 'post' command."""
import json
import sys
from engine import MAX_INPUT, pre, post, decision_deny, post_alert, record_hook


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    data = None
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("Hook input exceeds supported size")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Hook event must be a JSON object")
        if mode == "pre":
            reply = pre(data)
        elif mode == "post":
            reply = post(data)
        else:
            raise ValueError("Expected pre or post")
    except Exception as e:
        reply = post_alert(str(e)) if mode == "post" else decision_deny(str(e))
    try:
        record_hook(mode, data, reply)
    except Exception as e:
        reply = (post_alert if mode == "post" else decision_deny)(
            "Cannot persist hook evidence: " + str(e))
    # A valid JSON denial is used even on errors; no accidental approval by exit 0/no JSON.
    print(json.dumps(reply, ensure_ascii=False))


if __name__ == "__main__":
    main()
