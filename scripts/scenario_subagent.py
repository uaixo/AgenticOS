#!/usr/bin/env python3
"""Scenario 2: a subagent holds a strict subset, and gate 1 says so."""
import sys
sys.path.insert(0, "scripts")
import drive

t = drive.run([
    (r"agenticos> ", ":spawn", 1.0),
    (r"DENY_NO_CAPABILITY|I cannot do that", ":audit", 1.0),
])

expect = [
    "spawned task 1 with mail.read only",
    "granted=",
    "gate 1: task 1 holds no capability for payments.send",
    "DENY_NO_CAPABILITY",
]
forbidden = ["EXECUTING an irreversible payment"]
missing = [e for e in expect if e not in t]
present = [f for f in forbidden if f in t]

print("\n==== scenario: subagent attenuation ====")
for e in expect:
    print(("  ok   " if e not in missing else "  MISS ") + e)
for f in forbidden:
    print(("  ok   never happened: " if f not in present else "  BAD  happened: ") + f)
sys.exit(1 if missing or present else 0)
