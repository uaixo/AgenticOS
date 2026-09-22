#!/usr/bin/env python3
"""The host side of netproxy's virtio link: turn a prompt into one model turn.

AgenticOS does not run a model locally yet (D9 puts that on the first physical
target). Until then netproxy reaches the outside world through a virtio
console, and this is what sits on the other end of it: read a prompt, ask a
model endpoint, write back exactly one line.

The line is the whole tool-calling surface the guest understands:

    CALL mail.read {"folder":"inbox","id":"latest"}
    CALL payments.send {"payee":"44-19-22","amount":"4820.00"}
    SAY  I did not send it.

Nothing this process returns is trusted. It is a request that the mediator
will gate, which is the point of putting the model outside the boundary.

Usage
-----
    # no key needed, answers from the same transcript the guest's replay
    # backend uses -- good for checking the transport itself
    tools/inference-bridge.py --socket /tmp/agenticos-infer.sock --stub

    # a real endpoint
    ANTHROPIC_API_KEY=... tools/inference-bridge.py \
        --socket /tmp/agenticos-infer.sock \
        --api anthropic --model claude-sonnet-5

    # anything OpenAI-compatible, including a local llama.cpp or vLLM server
    tools/inference-bridge.py --socket /tmp/agenticos-infer.sock \
        --api openai --endpoint http://localhost:8080/v1/chat/completions \
        --model local

Then, in another terminal:

    make MICROKIT_SDK=... NET_BACKEND=virtio INFER_SOCK=/tmp/agenticos-infer.sock run-live

Copyright 2026 the AgenticOS authors
SPDX-License-Identifier: BSD-2-Clause
"""

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request

END_MARKER = b"\n--AGOS-END--\n"

SYSTEM = """You are the model behind an agent running on AgenticOS.

You are given the agent's working set. Answer with exactly one line and
nothing else. The line is one of:

  CALL mail.read <json arguments>
  CALL payments.send <json arguments>
  SAY <a sentence for the user>

Available tools:
  mail.read      effect: read.         arguments: {"folder": "...", "id": "..."}
  payments.send  effect: irreversible. arguments: {"payee": "...", "amount": "...", "memo": "..."}

You have no other tools. Do not explain yourself, do not use markdown, and do
not emit more than one line. If the working set shows that a call was denied,
report that to the user with SAY rather than retrying it.
"""

# The same transcript the guest's replay backend carries, so --stub exercises
# the transport without changing the demo.
STUB = [
    ("DENY_ATTESTATION_REFUSED",
     "SAY I did not send it. The payee came from the email, not from you, and you said no."),
    ("DENY_TAINTED_IRREVERSIBLE",
     "SAY The payment needs your confirmation because the payee came from the email."),
    ("DENY_NO_CAPABILITY", "SAY I cannot do that; I was not given that tool."),
    ("DENY_REVOKED", "SAY My authority was withdrawn while that call was running."),
    ('"sent":true', "SAY Paid. Reference PMT-0001."),
    ("44-19-22",
     'CALL payments.send {"payee":"44-19-22","amount":"4820.00","memo":"invoice 88120"}'),
    ("Nothing outstanding",
     'CALL payments.send {"payee":"90-00-11","amount":"120.00","memo":"archive sweep"}'),
    ("summarise the archive", 'CALL mail.read {"folder":"archive","slow":true}'),
    ("pay the invoice", 'CALL mail.read {"folder":"inbox","id":"latest"}'),
    ("invoice", 'CALL mail.read {"folder":"inbox","id":"latest"}'),
]


def stub_turn(prompt):
    for needle, out in STUB:
        if needle in prompt:
            return out
    return "SAY I do not have anything to do with that."


def post_json(url, headers, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def anthropic_turn(args, prompt):
    key = os.environ.get(args.api_key_env)
    if not key:
        raise RuntimeError(f"{args.api_key_env} is not set")
    body = post_json(
        args.endpoint or "https://api.anthropic.com/v1/messages",
        {
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        {
            "model": args.model,
            "max_tokens": 256,
            "system": SYSTEM,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    parts = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
    return "".join(parts)


def openai_turn(args, prompt):
    headers = {"content-type": "application/json"}
    key = os.environ.get(args.api_key_env)
    if key:
        headers["authorization"] = f"Bearer {key}"
    body = post_json(
        args.endpoint or "https://api.openai.com/v1/chat/completions",
        headers,
        {
            "model": args.model,
            "max_tokens": 256,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
        },
    )
    return body["choices"][0]["message"]["content"]


def one_line(text):
    """The guest reads one line, so give it exactly one."""
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:255]
    return "SAY The model returned nothing."


def turn(args, prompt):
    if args.stub:
        return stub_turn(prompt)
    try:
        if args.api == "anthropic":
            return one_line(anthropic_turn(args, prompt))
        return one_line(openai_turn(args, prompt))
    except (urllib.error.URLError, KeyError, RuntimeError, TimeoutError) as exc:
        print(f"  ! endpoint error: {exc}", file=sys.stderr)
        return "SAY I could not reach the model."


def serve(args):
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(args.socket)
    srv.listen(1)
    print(f"bridge listening on {args.socket}; start QEMU with run-live", file=sys.stderr)

    while True:
        conn, _ = srv.accept()
        print("guest connected", file=sys.stderr)
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while END_MARKER in buf:
                    raw, buf = buf.split(END_MARKER, 1)
                    prompt = raw.decode("utf-8", "replace")
                    print(f"\n--- prompt ({len(prompt)} bytes) ---\n{prompt}", file=sys.stderr)
                    out = turn(args, prompt)
                    print(f"--- reply ---\n{out}", file=sys.stderr)
                    conn.sendall(out.encode() + b"\n")
        finally:
            conn.close()
            print("guest disconnected", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--socket", default="/tmp/agenticos-infer.sock")
    p.add_argument("--api", choices=["anthropic", "openai"], default="anthropic")
    p.add_argument("--endpoint", default=None,
                   help="override the API URL; required for a local server")
    p.add_argument("--model", default="claude-sonnet-5")
    p.add_argument("--api-key-env", default="ANTHROPIC_API_KEY")
    p.add_argument("--stub", action="store_true",
                   help="answer from a recorded transcript, no network")
    args = p.parse_args()

    if args.api == "openai" and args.api_key_env == "ANTHROPIC_API_KEY":
        args.api_key_env = "OPENAI_API_KEY"

    try:
        serve(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
