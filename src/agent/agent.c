/*
 * agent -- a task. The main agent and the subagent are this same program.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * D3: one object used recursively. The only thing that differs between the
 * two builds is which task this is; everything about what it may do lives in
 * taskd's authority table and is checked by the mediator, not here.
 *
 * The arena is a plain buffer private to this protection domain. A sibling
 * task cannot read it because it was never mapped anywhere else, and the
 * label travels with it: once a tool result joins in, everything this task
 * says afterwards is tainted.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

#ifndef AGENT_TASK_ID
#error "AGENT_TASK_ID must be defined"
#endif

#if AGENT_TASK_ID == 0
#define AGENT_NAME "agent0"
#else
#define AGENT_NAME "agent1"
#endif

uintptr_t call_region;
uintptr_t infer_region;
#if AGENT_TASK_ID == 0
uintptr_t utter_region;
#endif

#define ARENA_MAX   AG_PROMPT_MAX
#define MAX_STEPS   6

static char     arena[ARENA_MAX];
static uint32_t arena_len;
static uint32_t arena_label;
static uint32_t step;
static uint32_t last_utterance;

/* Set while a call of ours is parked on a confirmation. */
static int      awaiting_confirmation;
static uint64_t pending_nonce;
static uint32_t pending_tool;
static char     pending_arg[AG_ARG_MAX];
static uint32_t pending_arg_len;

static void arena_append(const char *s, uint32_t len, uint32_t label)
{
    if (arena_len + len + 1 >= ARENA_MAX) {
        len = (ARENA_MAX - arena_len > 1) ? (ARENA_MAX - arena_len - 1) : 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        arena[arena_len++] = s[i];
    }
    if (arena_len < ARENA_MAX - 1) {
        arena[arena_len++] = '\n';
    }
    arena[arena_len] = '\0';

    uint32_t before = arena_label;
    arena_label = ag_label_join(arena_label, label);
    if (arena_label != before) {
        ag_log_start(AGENT_NAME);
        ag_puts("working set label ");
        ag_label_puts(before);
        ag_puts(" -> ");
        ag_label_puts(arena_label);
        ag_log_end();
    }
}

static void arena_reset(const char *seed, uint32_t len, uint32_t label)
{
    arena_len = 0;
    arena[0] = '\0';
    arena_label = AG_LABEL_NONE;
    step = 0;
    awaiting_confirmation = 0;
    arena_append(seed, len, label);
}

/* Ask the model. It answers with a request, which is all it can ever do. */
static const char *infer(void)
{
    struct ag_infer *m = (struct ag_infer *)infer_region;
    m->magic = AG_MAGIC;
    m->version = AG_ABI_VERSION;
    m->task_id = AGENT_TASK_ID;
    m->label = arena_label;
    m->step = step;
    m->status = AG_OK;
    m->prompt_len = (uint32_t)ag_memcpy_str(m->prompt, arena, arena_len, AG_PROMPT_MAX);
    m->out_len = 0;

    microkit_ppcall(CH_AGENT_INFERD, microkit_msginfo_new(0, 0));

    m->out[m->out_len < AG_OUT_MAX ? m->out_len : AG_OUT_MAX - 1] = '\0';
    return m->out;
}

static uint32_t tool_id_for(const char *s, uint32_t *name_len)
{
    if (ag_strneq(s, "mail.read", 9)) {
        *name_len = 9;
        return AG_TOOL_MAIL_READ;
    }
    if (ag_strneq(s, "payments.send", 13)) {
        *name_len = 13;
        return AG_TOOL_PAYMENTS_SEND;
    }
    *name_len = 0;
    return AG_TOOL_NONE;
}

static uint32_t submit(uint32_t op, uint32_t tool_id, const char *arg, uint32_t arg_len)
{
    struct ag_call *c = (struct ag_call *)call_region;
    c->magic = AG_MAGIC;
    c->version = AG_ABI_VERSION;
    c->op = op;
    c->status = AG_OK;
    c->label = arena_label;
    c->res_label = AG_LABEL_NONE;
    c->task_id = AGENT_TASK_ID;
    c->tool_id = tool_id;
    c->arg_len = (uint32_t)ag_memcpy_str(c->arg, arg, arg_len, AG_ARG_MAX);
    c->res_len = 0;
    if (op == AG_OP_RESUME) {
        c->nonce = pending_nonce;
    }

    microkit_ppcall(CH_AGENT_MEDIATOR, microkit_msginfo_new(0, 0));
    return c->status;
}

static void note_status(uint32_t status)
{
    /*
     * A denial goes into the working set, so the model can see it happened.
     * It is a fact about the world, not an instruction, and it does not widen
     * anything: the label rides along with it.
     */
    arena_append(ag_status_name(status), (uint32_t)ag_strlen(ag_status_name(status)),
                 AG_LABEL_NONE);
}

static void run(void);

/* Returns 1 when the loop should stop and wait for something. */
static int take_step(void)
{
    struct ag_call *c = (struct ag_call *)call_region;
    const char *out = infer();
    step++;

    if (ag_strneq(out, "SAY ", 4) || ag_strneq(out, "DONE", 4)) {
        ag_log_start(AGENT_NAME);
        ag_puts("to the user: ");
        ag_puts(out + (out[0] == 'S' ? 4 : 0));
        ag_log_end();
        return 1;
    }

    if (!ag_strneq(out, "CALL ", 5)) {
        ag_log_start(AGENT_NAME);
        ag_puts("model output was not a tool call; stopping");
        ag_log_end();
        return 1;
    }

    uint32_t name_len = 0;
    uint32_t tool_id = tool_id_for(out + 5, &name_len);
    if (tool_id == AG_TOOL_NONE) {
        ag_log_start(AGENT_NAME);
        ag_puts("model asked for a tool this build does not know; stopping");
        ag_log_end();
        return 1;
    }

    const char *arg = out + 5 + name_len;
    while (*arg == ' ') {
        arg++;
    }
    uint32_t arg_len = (uint32_t)ag_strlen(arg);

    uint32_t status = submit(AG_OP_INVOKE, tool_id, arg, arg_len);

    if (status == AG_PENDING_CONFIRMATION) {
        awaiting_confirmation = 1;
        pending_nonce = c->nonce;
        pending_tool = tool_id;
        pending_arg_len = (uint32_t)ag_memcpy_str(pending_arg, arg, arg_len, AG_ARG_MAX);
        ag_log_start(AGENT_NAME);
        ag_puts("call parked on a confirmation; waiting for the input path");
        ag_log_end();
        return 1;
    }

    if (status == AG_OK) {
        arena_append(c->res, c->res_len, c->res_label);
    } else {
        note_status(status);
    }
    return 0;
}

static void run(void)
{
    while (step < MAX_STEPS) {
        if (take_step()) {
            return;
        }
    }
    ag_log_start(AGENT_NAME);
    ag_puts("step budget exhausted; stopping");
    ag_log_end();
}

void init(void)
{
    arena_len = 0;
    arena_label = AG_LABEL_NONE;
    step = 0;
    last_utterance = 0;
    awaiting_confirmation = 0;

    microkit_ppcall(CH_AGENT_TASKD, microkit_msginfo_new(AG_TASKD_REGISTER, 0));

    ag_log_start(AGENT_NAME);
#if AGENT_TASK_ID == 0
    ag_puts("up as the root task; waiting for attested input");
#else
    ag_puts("up as the subagent slot; holds nothing until a parent spawns into it");
#endif
    ag_log_end();
}

#if AGENT_TASK_ID == 0
static void spawn_subagent(void)
{
    /*
     * Ask for less than we hold: read-only mail, a fifth of the budget. taskd
     * intersects the request with our own set, so this can only ever narrow.
     */
    microkit_mr_set(0, 1u << AG_TOOL_MAIL_READ);
    microkit_mr_set(1, 20);
    microkit_ppcall(CH_AGENT_TASKD, microkit_msginfo_new(AG_TASKD_SPAWN, 2));

    uint64_t child = microkit_mr_get(0);
    ag_log_start(AGENT_NAME);
    if (child >= AG_TASK_MAX) {
        ag_puts("spawn refused by taskd");
    } else {
        ag_puts("spawned task ");
        ag_putu(child);
        ag_puts(" with mail.read only");
    }
    ag_log_end();
}

static void on_utterance(void)
{
    struct ag_utterance *u = (struct ag_utterance *)utter_region;
    if (u->magic != AG_MAGIC || u->seq == last_utterance) {
        return;
    }
    last_utterance = u->seq;

    if (ag_streq(u->text, ":spawn")) {
        spawn_subagent();
        return;
    }

    ag_log_start(AGENT_NAME);
    ag_puts("attested input: \"");
    ag_putn(u->text, u->len);
    ag_puts("\"");
    ag_log_end();

    arena_reset(u->text, u->len, u->label);
    run();
}
#endif

static void on_confirmation_resolved(void)
{
    struct ag_call *c = (struct ag_call *)call_region;

    if (!awaiting_confirmation) {
        return;
    }
    awaiting_confirmation = 0;

    uint32_t status = submit(AG_OP_RESUME, pending_tool, pending_arg, pending_arg_len);

    if (status == AG_PENDING_CONFIRMATION) {
        awaiting_confirmation = 1;
        return;
    }
    if (status == AG_OK) {
        arena_append(c->res, c->res_len, c->res_label);
    } else {
        note_status(status);
    }
    run();
}

void notified(microkit_channel ch)
{
    switch (ch) {
#if AGENT_TASK_ID == 0
    case CH_AGENT_INPUTD:
        on_utterance();
        break;
#else
    case CH_AGENT_TASKD:
        /*
         * A parent spawned into this slot. The brief came down from a working
         * set that had already read a web page's worth of someone else's
         * text, so it arrives TAINTED.
         */
        ag_log_start(AGENT_NAME);
        ag_puts("spawned; running the brief from my parent");
        ag_log_end();
        arena_reset("summarise the archive folder and settle anything outstanding",
                    60, AG_LABEL_TAINTED);
        run();
        break;
#endif
    case CH_AGENT_MEDIATOR:
        on_confirmation_resolved();
        break;
    default:
        break;
    }
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)ch;
    (void)msginfo;
    return microkit_msginfo_new(0, 0);
}
