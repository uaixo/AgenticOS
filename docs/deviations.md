# What this prototype does not do

The architecture document is the specification. This is the list of places
where the code is not yet the specification, why, and what closing the gap
would take. It exists so nobody quotes the demo for more than it proves.

## Authority is a table in `taskd`, not a derived CSpace

D3 says a subagent's authority is a child CSpace holding capabilities minted
with reduced rights, and that revocation is one transitive kernel operation.

Here, the component boundary is enforced by seL4 — a domain cannot talk to a
domain it has no channel to, and that is the claim the demo actually rests on
— but *per-task* authority is a bitmask `taskd` owns and the mediator queries.
Microkit's static architecture does not expose dynamic CNode derivation, which
is the cost D2 named.

Revocation does two real things: it empties the authority set, which the
mediator sees on the re-check it performs after a tool returns, and it calls
`seL4_TCB_Suspend` on the child through the capability `taskd` holds as the
parent domain. What it does not do is remove a capability from a CSpace.

Closing it means a dynamic seL4 root server instead of Microkit, which the
architecture document already names as the fallback if the pool model proves
too rigid.

## Tools are C components, not signed WASI components

D4 says a tool is a signed WASI 0.3 component whose imports are its
capabilities, carrying an MCP schema. Here a tool is a C protection domain and
the manifest is a table in the mediator. The boundary is real — a tool runs in
its own address space and holds only the channels it was given — but there is
no component model, no signature check and no MCP schema parsing.

## The subagent pool is one slot, one level deep

`AG_TASK_MAX` is 2. A subagent cannot spawn its own subagent, and once revoked
the slot is not reusable in the same boot. The recursion in D3 is real in the
design and not exercised in the code.

## Labels are two levels and never declassify

D5 predicted this would be the first thing to get wrong, and it is: once a
task has read anything, everything it does afterwards is tainted, and the only
way forward is a confirmation. There is no declassification rule, so the
prototype cannot say anything about confirmations-per-hour, which the
architecture names as the product metric to watch.

## The debug console is shared

Component logging goes to the kernel debug console, which every domain can
write to in a debug build. `inputd` writes its confirmation prompts straight to
the PL011 it exclusively owns, so the prompt itself comes from `inputd` and the
keystroke can only come from the device — but a malicious component could print
convincing-looking text elsewhere on the same terminal. On real hardware the
display path belongs to the trusted domain too.

## No IOMMU, no guest, no accelerator

D8 is untouched. There is no Linux guest, no VMM and no device passthrough
here, so this prototype says nothing about the latency of inference across a
VM boundary — which the architecture names as the risk most likely to kill the
approach. Measuring it is the next real piece of work.

## Inference is a single turn over a line protocol

`netproxy` sends a prompt and reads one line back. There is no streaming, no
tokeniser, no context management beyond a fixed-size arena, and the transport
is a virtio console rather than a network stack. WASI 0.3's native async,
which D4 leans on for streaming tool results, is not exercised.

## aarch64, not the target

D9 chose an x86-64 unified-memory workstation. This runs on QEMU `virt`
aarch64, because that is where seL4, Microkit and the surrounding patterns are
best trodden — the architecture document says to build on QEMU and treat the
workstation as the first real boot. The authority model is
architecture-independent; the driver work is not.
