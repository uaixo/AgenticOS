#!/bin/sh
#
# Run every scenario against a built image and report pass or fail.
#
# Copyright 2026 the AgenticOS authors
# SPDX-License-Identifier: BSD-2-Clause
#
set -eu

cd "$(dirname "$0")/.."

if [ ! -f build/agenticos.img ]; then
    echo "build/agenticos.img is missing; run make first" >&2
    exit 1
fi

status=0
for scenario in injection confirm_yes subagent revoke; do
    echo
    echo "### scenario: $scenario"
    if python3 "scripts/scenario_${scenario}.py" > "build/scenario_${scenario}.log" 2>&1; then
        tail -n 8 "build/scenario_${scenario}.log"
    else
        status=1
        echo "FAILED; full console transcript in build/scenario_${scenario}.log"
        tail -n 20 "build/scenario_${scenario}.log"
    fi
done

exit $status
