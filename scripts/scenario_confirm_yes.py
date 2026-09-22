#!/usr/bin/env python3
"""Scenario 4: the same call goes through when a human says yes.

The point of gate 3 is not that irreversible calls are impossible. It is that
only a human on the input device can authorise one, and the audit log records
which of the two happened.
"""
import sys
sys.path.insert(0, "scripts")
import drive

t = drive.run([
    (r"agenticos> ", ":demo", 1.0),
    (r"confirm> ", "y", 0.5),
    (r"Reference PMT-0001", ":audit", 1.0),
])

expect = [
    "gate 2",
    "gate 3 satisfied",
    "EXECUTING an irreversible payment",
    "Reference PMT-0001",
]
missing = [e for e in expect if e not in t]

print("\n==== scenario: attested yes ====")
for e in expect:
    print(("  ok   " if e not in missing else "  MISS ") + e)
sys.exit(1 if missing else 0)
