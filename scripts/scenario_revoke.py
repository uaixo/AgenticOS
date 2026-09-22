#!/usr/bin/env python3
"""Scenario 3: revoke a subagent while its tool call is in flight."""
import sys
sys.path.insert(0, "scripts")
import drive

t = drive.run([
    (r"agenticos> ", ":spawn", 1.0),
    (r"slow read starting", ":revoke", 0.2),
    (r"DENY_REVOKED", ":audit", 1.5),
])

expect = [
    "slow read starting",
    "REVOKE task 1: authority emptied, thread stopped",
    "DENY_REVOKED",
]
missing = [e for e in expect if e not in t]

print("\n==== scenario: revoke mid-call ====")
for e in expect:
    print(("  ok   " if e not in missing else "  MISS ") + e)
sys.exit(1 if missing else 0)
