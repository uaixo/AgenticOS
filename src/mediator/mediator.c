/*
 * mediator -- the one gate.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Every tool call in the system arrives here, because no other protection
 * domain holds a channel to a tool. Three gates, in order:
 *
 *   Gate 1  capability   does this task's authority set contain this tool?
 *   Gate 2  provenance   do tainted arguments want an irreversible effect?
 *   Gate 3  attestation  did a human on the input device say yes to these
 *                        exact arguments, under this call's nonce?
 *
 * Gate 1 is re-run after the tool returns, so a task revoked while its call
 * was in flight never receives the result.
 *
 * This component is in the trusted computing base. It is meant to stay small
 * and boring enough to audit by reading.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

/* Shared regions, one per peer, so no task can see another task's calls. */
uintptr_t call_agent0;
uintptr_t call_agent1;
uintptr_t call_tool_mail;
uintptr_t call_tool_pay;
uintptr_t confirm_region;

/*
 * The tool manifest. A shipping system reads this from the signed component;
 * here it is a table, and the effect class is the only field the gates need.
 */
struct tool_manifest {
    uint32_t          tool_id;
    uint32_t          effect;
    microkit_channel  ch;
    uintptr_t        *region;
};

static struct tool_manifest manifests[] = {
    { AG_TOOL_MAIL_READ,     AG_EFFECT_READ,         CH_MED_TOOL_MAIL, &call_tool_mail },
    { AG_TOOL_PAYMENTS_SEND, AG_EFFECT_IRREVERSIBLE, CH_MED_TOOL_PAY,  &call_tool_pay  },
};
#define MANIFEST_COUNT (sizeof(manifests) / sizeof(manifests[0]))

static struct tool_manifest *manifest_for(uint32_t tool_id)
{
    for (unsigned i = 0; i < MANIFEST_COUNT; i++) {
        if (manifests[i].tool_id == tool_id) {
            return &manifests[i];
        }
    }
    return 0;
}

/* One confirmation may be outstanding at a time in this prototype. */
struct pending {
    int      active;
    uint64_t nonce;
    uint64_t arg_digest;
    uint64_t call_id;
    uint32_t task_id;
    uint32_t tool_id;
    uint32_t state;
    microkit_channel notify_ch;
};

static struct pending pending;
static uint64_t next_call_id = 1;
static uint64_t nonce_counter = 0x9e3779b97f4a7c15ULL;

/* Audit log. Non-repudiation is a property of the boundary, not a feature. */
#define AUDIT_MAX 64

struct audit_entry {
    uint64_t call_id;
    uint64_t nonce;
    uint32_t task_id;
    uint32_t tool_id;
    uint32_t effect;
    uint32_t arg_label;
    uint32_t res_label;
    uint32_t status;
    uint32_t gate;      /* which gate produced this outcome; 0 = dispatched */
};

static struct audit_entry audit[AUDIT_MAX];
static uint32_t audit_head;
static uint32_t audit_count;

static void audit_record(uint64_t call_id, uint64_t nonce, uint32_t task_id,
                         uint32_t tool_id, uint32_t effect, uint32_t arg_label,
                         uint32_t res_label, uint32_t status, uint32_t gate)
{
    struct audit_entry *e = &audit[audit_head];
    e->call_id = call_id;
    e->nonce = nonce;
    e->task_id = task_id;
    e->tool_id = tool_id;
    e->effect = effect;
    e->arg_label = arg_label;
    e->res_label = res_label;
    e->status = status;
    e->gate = gate;
    audit_head = (audit_head + 1) % AUDIT_MAX;
    if (audit_count < AUDIT_MAX) {
        audit_count++;
    }

    ag_log_start("audit");
    ag_puts("call=");
    ag_putu(call_id);
    ag_puts(" task=");
    ag_putu(task_id);
    ag_puts(" tool=");
    ag_puts(ag_tool_name(tool_id));
    ag_puts(" effect=");
    ag_puts(ag_effect_name(effect));
    ag_puts(" args=");
    ag_label_puts(arg_label);
    ag_puts(" result=");
    ag_label_puts(res_label);
    ag_puts(" -> ");
    ag_puts(ag_status_name(status));
    if (gate != 0) {
        ag_puts(" (gate ");
        ag_putu(gate);
        ag_puts(")");
    }
    ag_log_end();
}

static void audit_dump(void)
{
    ag_log_start("audit");
    ag_puts("---- audit log, ");
    ag_putu(audit_count);
    ag_puts(" entries, oldest first ----");
    ag_log_end();

    uint32_t start = (audit_count == AUDIT_MAX) ? audit_head : 0;
    for (uint32_t i = 0; i < audit_count; i++) {
        struct audit_entry *e = &audit[(start + i) % AUDIT_MAX];
        ag_log_start("audit");
        ag_puts("  call=");
        ag_putu(e->call_id);
        ag_puts(" task=");
        ag_putu(e->task_id);
        ag_puts(" ");
        ag_puts(ag_tool_name(e->tool_id));
        ag_puts("/");
        ag_puts(ag_effect_name(e->effect));
        ag_puts(" args=");
        ag_label_puts(e->arg_label);
        ag_puts(" res=");
        ag_label_puts(e->res_label);
        ag_puts(" ");
        ag_puts(ag_status_name(e->status));
        if (e->nonce != 0) {
            ag_puts(" nonce=");
            ag_puthex(e->nonce);
        }
        ag_log_end();
    }
    ag_log_start("audit");
    ag_puts("---- end ----");
    ag_log_end();
}

/* Gate 1: taskd owns the authority table; the mediator only asks. */
static int gate_capability(uint32_t task_id, uint32_t tool_id)
{
    microkit_mr_set(0, task_id);
    microkit_mr_set(1, tool_id);
    microkit_msginfo reply =
        microkit_ppcall(CH_MED_TASKD, microkit_msginfo_new(AG_TASKD_CAN_INVOKE, 2));
    (void)reply;
    return microkit_mr_get(0) != 0;
}

/*
 * The credential never reaches the agent or the tool. The mediator obtains a
 * single-use grant bound to this call, and the tool presents that grant to
 * keyring on the far side of this boundary.
 */
static uint64_t keyring_grant(uint32_t task_id, uint32_t tool_id, uint64_t call_id)
{
    microkit_mr_set(0, task_id);
    microkit_mr_set(1, tool_id);
    microkit_mr_set(2, call_id);
    microkit_ppcall(CH_MED_KEYRING, microkit_msginfo_new(1, 3));
    return microkit_mr_get(0);
}

static uint64_t make_nonce(uint64_t call_id, uint64_t arg_digest)
{
    nonce_counter += 0x9e3779b97f4a7c15ULL;
    return nonce_counter ^ (call_id * 0x100000001b3ULL) ^ arg_digest;
}

static void raise_confirmation(struct ag_call *c, uint64_t arg_digest,
                               microkit_channel notify_ch)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;

    pending.active = 1;
    pending.nonce = make_nonce(c->call_id, arg_digest);
    pending.arg_digest = arg_digest;
    pending.call_id = c->call_id;
    pending.task_id = c->task_id;
    pending.tool_id = c->tool_id;
    pending.state = AG_CONFIRM_REQUESTED;
    pending.notify_ch = notify_ch;

    cf->magic = AG_MAGIC;
    cf->state = AG_CONFIRM_REQUESTED;
    cf->nonce = pending.nonce;
    cf->task_id = c->task_id;
    cf->tool_id = c->tool_id;
    cf->effect = c->effect;
    cf->text_len = (uint32_t)ag_memcpy_str(cf->text, c->arg, c->arg_len,
                                           AG_CONFIRM_TEXT_MAX);

    c->nonce = pending.nonce;
    c->status = AG_PENDING_CONFIRMATION;

    microkit_notify(CH_MED_INPUTD);
}

/* Steps 5 to 8: dispatch, re-check, label, log. */
static void dispatch(struct ag_call *c, struct tool_manifest *m)
{
    struct ag_call *tc = (struct ag_call *)*m->region;

    uint64_t grant = keyring_grant(c->task_id, c->tool_id, c->call_id);

    tc->magic = AG_MAGIC;
    tc->version = AG_ABI_VERSION;
    tc->op = AG_OP_INVOKE;
    tc->status = AG_OK;
    tc->call_id = c->call_id;
    tc->nonce = grant;          /* the tool's single-use keyring grant */
    tc->label = c->label;
    tc->res_label = AG_LABEL_NONE;
    tc->task_id = c->task_id;
    tc->tool_id = c->tool_id;
    tc->effect = m->effect;
    tc->arg_len = (uint32_t)ag_memcpy_str(tc->arg, c->arg, c->arg_len, AG_ARG_MAX);
    tc->res_len = 0;

    microkit_ppcall(m->ch, microkit_msginfo_new(AG_OP_INVOKE, 0));

    /*
     * Gate 1 again. A task revoked while this call was in flight does not get
     * the result, and the drop is logged.
     */
    if (!gate_capability(c->task_id, c->tool_id)) {
        c->status = AG_DENY_REVOKED;
        c->res_len = 0;
        c->res_label = AG_LABEL_NONE;
        audit_record(c->call_id, 0, c->task_id, c->tool_id, m->effect,
                     c->label, AG_LABEL_NONE, AG_DENY_REVOKED, 1);
        return;
    }

    c->res_len = (uint32_t)ag_memcpy_str(c->res, tc->res, tc->res_len, AG_RES_MAX);
    /*
     * Anything a tool returns is tainted at the boundary, whatever the tool
     * says about itself. The label joins into the caller's working set.
     */
    c->res_label = ag_label_join(tc->res_label, AG_LABEL_TAINTED);
    c->status = tc->status;

    audit_record(c->call_id, 0, c->task_id, c->tool_id, m->effect,
                 c->label, c->res_label, c->status, 0);
}

static void handle_call(struct ag_call *c, uint32_t task_id, microkit_channel notify_ch)
{
    if (c->magic != AG_MAGIC || c->version != AG_ABI_VERSION ||
        c->arg_len > AG_ARG_MAX) {
        c->status = AG_ERR_MALFORMED;
        return;
    }

    /* The task's identity comes from the channel, not from the message. */
    c->task_id = task_id;
    c->label &= AG_LABEL_MASK;

    struct tool_manifest *m = manifest_for(c->tool_id);
    if (m == 0) {
        c->status = AG_DENY_NO_SUCH_TOOL;
        c->effect = AG_EFFECT_READ;
        audit_record(c->call_id, 0, task_id, c->tool_id, AG_EFFECT_READ,
                     c->label, AG_LABEL_NONE, AG_DENY_NO_SUCH_TOOL, 0);
        return;
    }
    c->effect = m->effect;

    uint64_t arg_digest = ag_digest(c->arg, c->arg_len);

    if (c->op == AG_OP_RESUME) {
        /*
         * Gate 3, second half. The confirmation is bound to this nonce and to
         * these exact argument bytes: changing the payee after the human heard
         * it read back invalidates the yes.
         */
        if (!pending.active || pending.nonce != c->nonce ||
            pending.task_id != task_id || pending.tool_id != c->tool_id) {
            c->status = AG_DENY_BAD_NONCE;
            audit_record(c->call_id, c->nonce, task_id, c->tool_id, m->effect,
                         c->label, AG_LABEL_NONE, AG_DENY_BAD_NONCE, 3);
            return;
        }
        if (pending.arg_digest != arg_digest) {
            pending.active = 0;
            c->status = AG_DENY_BAD_NONCE;
            audit_record(c->call_id, c->nonce, task_id, c->tool_id, m->effect,
                         c->label, AG_LABEL_NONE, AG_DENY_BAD_NONCE, 3);
            return;
        }
        if (pending.state == AG_CONFIRM_REQUESTED) {
            c->status = AG_PENDING_CONFIRMATION;
            return;
        }
        if (pending.state == AG_CONFIRM_REFUSED) {
            pending.active = 0;
            c->status = AG_DENY_ATTESTATION_REFUSED;
            audit_record(c->call_id, c->nonce, task_id, c->tool_id, m->effect,
                         c->label, AG_LABEL_NONE, AG_DENY_ATTESTATION_REFUSED, 3);
            return;
        }
        /* Granted. Gate 1 still has to hold. */
        pending.active = 0;
        if (!gate_capability(task_id, c->tool_id)) {
            c->status = AG_DENY_NO_CAPABILITY;
            audit_record(c->call_id, c->nonce, task_id, c->tool_id, m->effect,
                         c->label, AG_LABEL_NONE, AG_DENY_NO_CAPABILITY, 1);
            return;
        }
        ag_log_start("mediator");
        ag_puts("gate 3 satisfied for call ");
        ag_putu(c->call_id);
        ag_puts(": attested yes over the input path, nonce ");
        ag_puthex(c->nonce);
        ag_log_end();
        dispatch(c, m);
        return;
    }

    c->call_id = next_call_id++;
    c->nonce = 0;

    /* Gate 1. */
    if (!gate_capability(task_id, c->tool_id)) {
        c->status = AG_DENY_NO_CAPABILITY;
        c->res_len = 0;
        audit_record(c->call_id, 0, task_id, c->tool_id, m->effect,
                     c->label, AG_LABEL_NONE, AG_DENY_NO_CAPABILITY, 1);
        ag_log_start("mediator");
        ag_puts("gate 1: task ");
        ag_putu(task_id);
        ag_puts(" holds no capability for ");
        ag_puts(ag_tool_name(c->tool_id));
        ag_puts(" -- the tool does not exist for it");
        ag_log_end();
        return;
    }

    /* Gate 2. */
    if (ag_effect_needs_attestation(m->effect) && (c->label & AG_LABEL_TAINTED)) {
        ag_log_start("mediator");
        ag_puts("gate 2: ");
        ag_puts(ag_tool_name(c->tool_id));
        ag_puts(" declares effect ");
        ag_puts(ag_effect_name(m->effect));
        ag_puts(" and its arguments carry TAINTED -- refused, raising a confirmation");
        ag_log_end();

        raise_confirmation(c, arg_digest, notify_ch);
        audit_record(c->call_id, c->nonce, task_id, c->tool_id, m->effect,
                     c->label, AG_LABEL_NONE, AG_DENY_TAINTED_IRREVERSIBLE, 2);
        return;
    }

    dispatch(c, m);
}

void init(void)
{
    pending.active = 0;
    audit_head = 0;
    audit_count = 0;

    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;
    cf->magic = AG_MAGIC;
    cf->state = AG_CONFIRM_IDLE;

    ag_log_start("mediator");
    ag_puts("up. gates: 1 capability, 2 provenance, 3 attestation. ");
    ag_putu((uint64_t)MANIFEST_COUNT);
    ag_puts(" tools in the manifest");
    ag_log_end();
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)msginfo;

    switch (ch) {
    case CH_MED_AGENT0:
        handle_call((struct ag_call *)call_agent0, AG_TASK_MAIN, CH_MED_AGENT0);
        break;
    case CH_MED_AGENT1:
        handle_call((struct ag_call *)call_agent1, AG_TASK_SUB, CH_MED_AGENT1);
        break;
    default:
        break;
    }

    return microkit_msginfo_new(0, 0);
}

void notified(microkit_channel ch)
{
    if (ch != CH_MED_INPUTD) {
        return;
    }

    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;

    if (cf->state == AG_CONFIRM_GRANTED || cf->state == AG_CONFIRM_REFUSED) {
        if (pending.active && cf->nonce == pending.nonce) {
            pending.state = cf->state;
            ag_log_start("mediator");
            ag_puts("gate 3: attestation ");
            ag_puts(cf->state == AG_CONFIRM_GRANTED ? "granted" : "refused");
            ag_puts(" for nonce ");
            ag_puthex(cf->nonce);
            ag_log_end();
            microkit_notify(pending.notify_ch);
        } else {
            ag_log_start("mediator");
            ag_puts("gate 3: dropping an attestation that matches no pending call");
            ag_log_end();
        }
        cf->state = AG_CONFIRM_IDLE;
        return;
    }

    if (cf->state == AG_CONFIRM_AUDIT) {
        cf->state = AG_CONFIRM_IDLE;
        audit_dump();
    }
}
