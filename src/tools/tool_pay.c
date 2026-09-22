/*
 * payments.send -- a tool with an irreversible effect.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Nothing in this component decides whether the payment should happen. By the
 * time a call reaches here the mediator has already run all three gates, so
 * the interesting property of this file is how little it contains: the
 * defence is not in the tool.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

uintptr_t call_region;

void init(void)
{
    ag_log_start("tool:payments.send");
    ag_puts("up. effect=irreversible");
    ag_log_end();
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)ch;
    (void)msginfo;

    struct ag_call *c = (struct ag_call *)call_region;

    microkit_mr_set(0, c->nonce);
    microkit_ppcall(CH_TOOL_KEYRING, microkit_msginfo_new(1, 1));
    if (microkit_mr_get(0) == 0) {
        c->status = AG_ERR_MALFORMED;
        c->res_len = 0;
        return microkit_msginfo_new(0, 0);
    }

    ag_log_start("tool:payments.send");
    ag_puts("EXECUTING an irreversible payment for task ");
    ag_putu(c->task_id);
    ag_puts(": ");
    ag_putn(c->arg, c->arg_len);
    ag_log_end();

    c->res_len = (uint32_t)ag_strlcpy(c->res, "{\"sent\":true,\"reference\":\"PMT-0001\"}",
                                      AG_RES_MAX);
    c->res_label = AG_LABEL_TAINTED;
    c->status = AG_OK;

    return microkit_msginfo_new(0, 0);
}

void notified(microkit_channel ch)
{
    (void)ch;
}
