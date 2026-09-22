/*
 * taskd -- task lifecycle, authority derivation, revocation.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * D3: an agent is a task holding an authority set, a budget and a label.
 * A subagent is the same object holding a strict subset. Spawning is
 * attenuation; stopping is revocation, and revocation is transitive down the
 * task tree.
 *
 * taskd is the parent protection domain of both agent tasks, so it holds
 * their TCB capabilities and can stop them for real. In this prototype the
 * authority set itself is a table taskd owns rather than a derived seL4
 * CSpace -- see docs/deviations.md, which says why and what it would take to
 * close the gap.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

/* Microkit child ids, matching agenticos.system. */
#define CHILD_AGENT0 0u
#define CHILD_AGENT1 1u

struct task {
    int      live;
    uint32_t parent;      /* AG_TASK_MAX means "no parent, this is the root" */
    uint32_t authority;   /* bitmask over tool ids */
    uint32_t may_spawn;
    uint32_t budget_pct;
    uint32_t revoked;
};

static struct task tasks[AG_TASK_MAX];

/* Written by inputd, which runs at a higher priority so a spinning tool
 * cannot stop a human from reaching this path. */
uintptr_t opcmd_region;
static uint32_t opcmd_seen;

static uint32_t tool_bit(uint32_t tool_id)
{
    return 1u << tool_id;
}

static void log_task(uint32_t id)
{
    struct task *t = &tasks[id];
    ag_log_start("taskd");
    ag_puts("task ");
    ag_putu(id);
    ag_puts(t->live ? " live" : " dead");
    ag_puts(" authority={");
    int first = 1;
    for (uint32_t tool = 1; tool < AG_TOOL_COUNT; tool++) {
        if (t->authority & tool_bit(tool)) {
            if (!first) {
                ag_puts(",");
            }
            ag_puts(ag_tool_name(tool));
            first = 0;
        }
    }
    if (first) {
        ag_puts("(empty)");
    }
    ag_puts("} spawn=");
    ag_puts(t->may_spawn ? "yes" : "no");
    ag_puts(" budget=");
    ag_putu(t->budget_pct);
    ag_puts("%");
    if (t->revoked) {
        ag_puts(" REVOKED");
    }
    ag_log_end();
}

void init(void)
{
    opcmd_seen = 0;
    struct ag_opcmd *cmd = (struct ag_opcmd *)opcmd_region;
    cmd->magic = AG_MAGIC;
    cmd->cmd = AG_OPCMD_NONE;
    cmd->seq = 0;

    for (uint32_t i = 0; i < AG_TASK_MAX; i++) {
        tasks[i].live = 0;
        tasks[i].parent = AG_TASK_MAX;
        tasks[i].authority = 0;
        tasks[i].may_spawn = 0;
        tasks[i].budget_pct = 0;
        tasks[i].revoked = 0;
    }

    /* The root task: the main agent, holding everything this machine grants. */
    tasks[AG_TASK_MAIN].live = 1;
    tasks[AG_TASK_MAIN].authority =
        tool_bit(AG_TOOL_MAIL_READ) | tool_bit(AG_TOOL_PAYMENTS_SEND);
    tasks[AG_TASK_MAIN].may_spawn = 1;
    tasks[AG_TASK_MAIN].budget_pct = 100;

    /*
     * The subagent slot is a pre-declared task domain (D2: Microkit fixes the
     * component graph at build time). The domain exists from boot and holds
     * nothing at all, so there is nothing it can do. Spawning is the grant of
     * authority, not the creation of the thread.
     */

    ag_log_start("taskd");
    ag_puts("up. task pool = 2 domains, 1 root task live");
    ag_log_end();
    log_task(AG_TASK_MAIN);
}

/* Gate 1's oracle. The mediator asks; taskd answers; nobody else decides. */
static uint32_t can_invoke(uint32_t task_id, uint32_t tool_id)
{
    if (task_id >= AG_TASK_MAX) {
        return 0;
    }
    struct task *t = &tasks[task_id];
    if (!t->live || t->revoked) {
        return 0;
    }
    return (t->authority & tool_bit(tool_id)) != 0;
}

/*
 * Spawn is attenuation: the child gets the intersection of what the parent
 * asked for and what the parent itself holds, never more. A parent that does
 * not hold mail.read cannot hand mail.read to anyone.
 */
static uint32_t spawn(uint32_t parent_id, uint32_t requested, uint32_t budget_pct)
{
    if (parent_id >= AG_TASK_MAX || !tasks[parent_id].live) {
        return AG_TASK_MAX;
    }
    if (!tasks[parent_id].may_spawn) {
        ag_log_start("taskd");
        ag_puts("spawn refused: task ");
        ag_putu(parent_id);
        ag_puts(" does not hold spawn");
        ag_log_end();
        return AG_TASK_MAX;
    }
    if (tasks[AG_TASK_SUB].live) {
        ag_log_start("taskd");
        ag_puts("spawn refused: the task pool is exhausted");
        ag_log_end();
        return AG_TASK_MAX;
    }

    uint32_t granted = requested & tasks[parent_id].authority;
    if (budget_pct > tasks[parent_id].budget_pct) {
        budget_pct = tasks[parent_id].budget_pct;
    }

    tasks[AG_TASK_SUB].live = 1;
    tasks[AG_TASK_SUB].parent = parent_id;
    tasks[AG_TASK_SUB].authority = granted;
    tasks[AG_TASK_SUB].may_spawn = 0;   /* one level deep in this prototype */
    tasks[AG_TASK_SUB].budget_pct = budget_pct;
    tasks[AG_TASK_SUB].revoked = 0;

    ag_log_start("taskd");
    ag_puts("spawn: task ");
    ag_putu(parent_id);
    ag_puts(" -> task ");
    ag_putu((uint64_t)AG_TASK_SUB);
    ag_puts(", requested=");
    ag_puthex(requested);
    ag_puts(" granted=");
    ag_puthex(granted);
    ag_puts(" (intersected with the parent's own set)");
    ag_log_end();
    log_task(AG_TASK_SUB);

    microkit_notify(CH_TASKD_AGENT1);
    return AG_TASK_SUB;
}

/*
 * Revoke. Two things happen and both are observable: the authority set is
 * emptied, which the mediator sees on its next gate-1 check -- including the
 * re-check it performs after a tool returns, so a call already in flight is
 * caught -- and the task's thread is stopped through the TCB capability taskd
 * holds as the parent protection domain.
 */
static uint32_t revoke(uint32_t task_id)
{
    if (task_id == AG_TASK_MAIN) {
        ag_log_start("taskd");
        ag_puts("refusing to revoke the root task");
        ag_log_end();
        return 0;
    }
    if (task_id >= AG_TASK_MAX || !tasks[task_id].live) {
        return 0;
    }

    tasks[task_id].authority = 0;
    tasks[task_id].may_spawn = 0;
    tasks[task_id].revoked = 1;

    /* Transitive: anything this task spawned goes with it. */
    for (uint32_t i = 0; i < AG_TASK_MAX; i++) {
        if (tasks[i].live && tasks[i].parent == task_id) {
            tasks[i].authority = 0;
            tasks[i].may_spawn = 0;
            tasks[i].revoked = 1;
        }
    }

    ag_log_start("taskd");
    ag_puts("REVOKE task ");
    ag_putu(task_id);
    ag_puts(": authority emptied, thread stopped");
    ag_log_end();

    microkit_pd_stop(CHILD_AGENT1);
    tasks[task_id].live = 0;
    return 1;
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    uint64_t op = microkit_msginfo_get_label(msginfo);
    uint64_t a0 = microkit_mr_get(0);
    uint64_t a1 = microkit_mr_get(1);
    uint64_t a2 = microkit_mr_get(2);
    uint64_t result = 0;

    /*
     * The calling task's identity comes from the channel the call arrived on,
     * which the kernel will not let a caller forge. Only the mediator may ask
     * about an arbitrary task; an agent may only ever act as itself.
     */
    uint32_t caller_task = AG_TASK_MAX;
    switch (ch) {
    case CH_TASKD_AGENT0: caller_task = AG_TASK_MAIN; break;
    case CH_TASKD_AGENT1: caller_task = AG_TASK_SUB;  break;
    default: break;
    }

    switch (op) {
    case AG_TASKD_CAN_INVOKE:
        if (ch != CH_TASKD_MEDIATOR) {
            result = 0;   /* only the mediator asks this question */
            break;
        }
        result = can_invoke((uint32_t)a0, (uint32_t)a1);
        break;

    case AG_TASKD_SPAWN:
        if (caller_task == AG_TASK_MAX) {
            result = AG_TASK_MAX;
            break;
        }
        result = spawn(caller_task, (uint32_t)a0, (uint32_t)a1);
        break;

    case AG_TASKD_REVOKE:
        /* An agent may revoke only a task it parented. */
        if (caller_task != AG_TASK_MAX &&
            (uint32_t)a0 < AG_TASK_MAX &&
            tasks[(uint32_t)a0].parent == caller_task) {
            result = revoke((uint32_t)a0);
        } else {
            result = 0;
        }
        break;

    case AG_TASKD_DUMP:
        for (uint32_t i = 0; i < AG_TASK_MAX; i++) {
            log_task(i);
        }
        result = 1;
        break;

    case AG_TASKD_REGISTER:
        result = (caller_task != AG_TASK_MAX && tasks[caller_task].live);
        break;

    default:
        result = 0;
        break;
    }

    (void)a2;
    microkit_mr_set(0, result);
    return microkit_msginfo_new(0, 1);
}

void notified(microkit_channel ch)
{
    if (ch != CH_TASKD_INPUTD) {
        return;
    }

    struct ag_opcmd *cmd = (struct ag_opcmd *)opcmd_region;
    if (cmd->magic != AG_MAGIC || cmd->seq == opcmd_seen) {
        return;
    }
    opcmd_seen = cmd->seq;

    switch (cmd->cmd) {
    case AG_OPCMD_REVOKE:
        revoke(cmd->arg);
        break;
    case AG_OPCMD_DUMP:
        for (uint32_t i = 0; i < AG_TASK_MAX; i++) {
            log_task(i);
        }
        break;
    default:
        break;
    }
}
