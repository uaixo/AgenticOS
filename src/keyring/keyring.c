/*
 * keyring -- credentials agents never touch.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * D4: an agent holds a capability meaning "invoke tool X as identity Y". The
 * token itself lives here and crosses no boundary. The mediator asks for a
 * single-use grant bound to one call; the tool presents that grant on the far
 * side and gets back an identity it can act under, never the secret.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

#define GRANT_MAX 8

struct grant {
    int      live;
    uint64_t id;
    uint32_t task_id;
    uint32_t tool_id;
    uint64_t call_id;
};

static struct grant grants[GRANT_MAX];
static uint64_t next_grant = 0x5150;

/*
 * Stand-ins for the OAuth material a real keyring would hold. They are
 * deliberately never copied into any message that leaves this component.
 */
static const char *identity_for(uint32_t tool_id)
{
    switch (tool_id) {
    case AG_TOOL_MAIL_READ:     return "mail:freeman@example.invalid";
    case AG_TOOL_PAYMENTS_SEND: return "pay:freeman@example.invalid";
    default:                    return "";
    }
}

static uint64_t mint(uint32_t task_id, uint32_t tool_id, uint64_t call_id)
{
    for (int i = 0; i < GRANT_MAX; i++) {
        if (!grants[i].live) {
            grants[i].live = 1;
            grants[i].id = ++next_grant;
            grants[i].task_id = task_id;
            grants[i].tool_id = tool_id;
            grants[i].call_id = call_id;
            return grants[i].id;
        }
    }
    return 0;
}

/* Redeem is single use: a grant that has been spent is gone. */
static struct grant *redeem(uint64_t id, uint32_t tool_id)
{
    for (int i = 0; i < GRANT_MAX; i++) {
        if (grants[i].live && grants[i].id == id && grants[i].tool_id == tool_id) {
            grants[i].live = 0;
            return &grants[i];
        }
    }
    return 0;
}

void init(void)
{
    for (int i = 0; i < GRANT_MAX; i++) {
        grants[i].live = 0;
    }
    ag_log_start("keyring");
    ag_puts("up. tokens are held here and handed to nobody");
    ag_log_end();
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)msginfo;

    if (ch == CH_KEYRING_MEDIATOR) {
        uint32_t task_id = (uint32_t)microkit_mr_get(0);
        uint32_t tool_id = (uint32_t)microkit_mr_get(1);
        uint64_t call_id = microkit_mr_get(2);
        microkit_mr_set(0, mint(task_id, tool_id, call_id));
        return microkit_msginfo_new(0, 1);
    }

    /* A tool redeeming its grant. */
    uint32_t tool_id = (ch == CH_KEYRING_TOOL_MAIL) ? AG_TOOL_MAIL_READ
                                                    : AG_TOOL_PAYMENTS_SEND;
    uint64_t id = microkit_mr_get(0);
    struct grant *g = redeem(id, tool_id);

    if (g == 0) {
        ag_log_start("keyring");
        ag_puts("refused: ");
        ag_puts(ag_tool_name(tool_id));
        ag_puts(" presented a grant that is not live");
        ag_log_end();
        microkit_mr_set(0, 0);
        return microkit_msginfo_new(0, 1);
    }

    ag_log_start("keyring");
    ag_puts("grant ");
    ag_puthex(g->id);
    ag_puts(" redeemed by ");
    ag_puts(ag_tool_name(tool_id));
    ag_puts(" for task ");
    ag_putu(g->task_id);
    ag_puts(": acting as ");
    ag_puts(identity_for(tool_id));
    ag_puts(" (token withheld)");
    ag_log_end();

    microkit_mr_set(0, 1);
    return microkit_msginfo_new(0, 1);
}

void notified(microkit_channel ch)
{
    (void)ch;
}
