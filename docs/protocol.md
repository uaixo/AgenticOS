# The mediated call

Everything that crosses a protection-domain boundary in this system carries a
provenance label in its header, and every tool declares an effect class. Those
two fields are the whole of the trust model; the rest is bookkeeping.

## Labels

Four bits, defined in `include/agenticos/abi.h`.

| Bit | Name | Set by |
| --- | --- | --- |
| `0x1` | `ATTESTED` | `inputd`, at the point of capture, before any model sees the bytes |
| `0x2` | `TAINTED` | the mediator, on anything a tool returns, whatever the tool claims |

Labels join with OR on every hop, including into an agent's arena. A task that
has read one email is tainted from then on, and everything it subsequently
asks for inherits that.

The coarseness is deliberate and is the known problem: see the
declassification note in `deviations.md`.

## Effects

Declared per tool. The prototype's manifest lives in `src/mediator/mediator.c`;
a shipping system reads it from the signed component.

| Effect | Example | Gate 2 applies |
| --- | --- | --- |
| `read` | `mail.read` | no |
| `write` | — | no |
| `irreversible` | `payments.send` | yes |
| `spend` | — | yes |

## The call

`struct ag_call` lives in a memory region shared by exactly two domains, so no
task can see another task's calls. The mediator overwrites `task_id` and
`effect` on arrival: the caller's identity comes from the channel it arrived
on, and the effect comes from the manifest, so neither is something a caller
can assert about itself.

```
agent ──ppcall──▶ mediator ──ppcall──▶ taskd        gate 1: may this task?
                          ──ppcall──▶ keyring      a single-use grant
                          ──ppcall──▶ toolhost     the call itself
                          ──ppcall──▶ taskd        gate 1 again: still may it?
                  mediator ──notify──▶ inputd      gate 3, when gate 2 says so
                  inputd   ──notify──▶ mediator    the human's answer
```

## Gate 3 in detail

When gate 2 refuses, the mediator does not return a denial. It mints a nonce
from the call id and a digest of the argument bytes, writes a confirmation
request into the region it shares with `inputd`, and returns
`AG_PENDING_CONFIRMATION`.

`inputd` reads back the arguments verbatim on the device it exclusively owns,
and waits for a keystroke on that same device. The answer carries the nonce.

The agent then re-drives the call with `AG_OP_RESUME`. The mediator checks
that the nonce matches, **and that a fresh digest of the argument bytes still
matches the one the nonce was minted from**. A yes is therefore a yes to
specific arguments, not to a tool.

## What each architecture decision looks like in code

| Decision | Where |
| --- | --- |
| D1 stock seL4 with Microkit | `scripts/setup-sdk.sh` pins the kernel and tool revisions; no kernel source here |
| D2 agent kernel in privileged userspace | `src/taskd`, `src/mediator` — ordinary protection domains |
| D3 an agent is a task; spawn attenuates; stop is revoke | `src/taskd/taskd.c`, `spawn()` and `revoke()` |
| D4 tool ABI, credentials never held by agents | `src/tools/`, `src/keyring/keyring.c` |
| D5 provenance in the header from day one | `include/agenticos/abi.h`, gate 2 and gate 3 |
| D6 context as a per-task arena | `src/agent/agent.c`, `arena[]` — private, mapped nowhere else |
| D7 one attested input path, no screen-driving | `src/inputd/inputd.c` |
| D8 confine a driver rather than write one | not exercised; the accelerator work is thread 4 and later |
| D9 x86-64 workstation, QEMU for development | `board/qemu_virt_aarch64/` |
| D10 scope | there is no display server, no filesystem, and no POSIX here |

## Priorities

Microkit's protected procedure calls require the callee to outrank the caller,
which fixes most of the ordering:

```
inputd   254   the one deliberate exception, see below
taskd    250
keyring  249
tools    245
mediator 240
netproxy 230
inferd   220
agent0   210
agent1   205
```

`inputd` sits above everything, including the components it never calls,
because a human must be able to reach the input path while a tool is spinning.
That is why operator commands go to `taskd` over shared memory and a
notification rather than a procedure call: a call would require `taskd` to
outrank `inputd`, and then a spinning tool could lock a human out of the
revoke. The `:revoke` scenario is exactly that case.
