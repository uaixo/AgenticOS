#!/usr/bin/env python3
"""Scenario 1: the injected email cannot authorise the payment."""
import sys
sys.path.insert(0, "scripts")
import drive

t = drive.run([
    (r"agenticos> ", ":demo", 1.0),
    (r"confirm> ", "n", 0.5),
    (r"DENY_ATTESTATION_REFUSED", ":audit", 1.0),
])

expect = [
    "gate 2",
    "DENY_TAINTED_IRREVERSIBLE",
    "confirmation required",
    "DENY_ATTESTATION_REFUSED",
]
missing = [e for e in expect if e not in t]
forbidden = ["EXECUTING an irreversible payment"]
present = [f for f in forbidden if f in t]

print("\n==== scenario: injection ====")
for e in expect:
    print(("  ok   " if e not in missing else "  MISS ") + e)
for f in forbidden:
    print(("  ok   never happened: " if f not in present else "  BAD  happened: ") + f)
sys.exit(1 if missing or present else 0)
