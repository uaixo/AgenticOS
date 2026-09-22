#!/usr/bin/env python3
"""Drive the prototype's console non-interactively and print the transcript.

Used by scripts/run-scenarios.sh so the demo can be checked in CI as well as
watched by a human. Each step waits for a cue on the console before typing.
"""
import os
import pty
import re
import select
import subprocess
import sys
import time

QEMU = [
    "qemu-system-aarch64",
    "-machine", "virt,virtualization=on",
    "-cpu", "cortex-a53",
    "-serial", "mon:stdio",
    "-device", "loader,file=build/agenticos.img,addr=0x70000000,cpu-num=0",
    "-m", "size=2G",
    "-nographic",
]


def run(steps, image="build/agenticos.img", timeout=180.0):
    qemu = list(QEMU)
    qemu[qemu.index("-device") + 1] = f"loader,file={image},addr=0x70000000,cpu-num=0"

    primary, secondary = pty.openpty()
    proc = subprocess.Popen(qemu, stdin=secondary, stdout=secondary,
                            stderr=subprocess.STDOUT, close_fds=True)
    os.close(secondary)

    transcript = ""
    pending = list(steps)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            ready, _, _ = select.select([primary], [], [], 0.5)
            if ready:
                try:
                    chunk = os.read(primary, 4096).decode("utf-8", "replace")
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
                sys.stdout.write(chunk)
                sys.stdout.flush()
            if pending:
                cue, text, delay = pending[0]
                if cue is None or re.search(cue, transcript):
                    time.sleep(delay)
                    os.write(primary, (text + "\r").encode())
                    transcript += f"\n<<< typed: {text}\n"
                    pending.pop(1 - 1)
            elif not ready:
                # everything sent and the console has gone quiet
                time.sleep(1.0)
                ready, _, _ = select.select([primary], [], [], 2.0)
                if not ready:
                    break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(primary)
    return transcript
