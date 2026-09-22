/*
 * inferd -- the model runtime, and the least trusted thing in the system.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The whole argument of this architecture is visible in the channel map: this
 * component has a channel to the two agent tasks and a channel to netproxy,
 * and no channel to any tool. Model output is a request. If inferd were
 * replaced wholesale by an attacker the authority boundary would not move,
 * because there is no name inferd can utter that reaches a tool.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

uintptr_t infer_agent0;
uintptr_t infer_agent1;
uintptr_t infer_net;

static void forward(struct ag_infer *from)
{
    struct ag_infer *net = (struct ag_infer *)infer_net;

    if (from->magic != AG_MAGIC || from->prompt_len > AG_PROMPT_MAX) {
        from->status = AG_ERR_MALFORMED;
        from->out_len = 0;
        return;
    }

    net->magic = AG_MAGIC;
    net->version = AG_ABI_VERSION;
    net->task_id = from->task_id;
    net->label = from->label;
    net->step = from->step;
    net->status = AG_OK;
    net->prompt_len = (uint32_t)ag_memcpy_str(net->prompt, from->prompt,
                                              from->prompt_len, AG_PROMPT_MAX);
    net->out_len = 0;

    ag_log_start("inferd");
    ag_puts("task ");
    ag_putu(from->task_id);
    ag_puts(" step ");
    ag_putu(from->step);
    ag_puts(": context is ");
    ag_label_puts(from->label);
    ag_puts(", asking the model over netproxy");
    ag_log_end();

    microkit_ppcall(CH_INFERD_NETPROXY, microkit_msginfo_new(0, 0));

    from->out_len = (uint32_t)ag_memcpy_str(from->out, net->out, net->out_len,
                                            AG_OUT_MAX);
    from->status = net->status;

    ag_log_start("inferd");
    ag_puts("model proposes: ");
    ag_putn(from->out, from->out_len);
    ag_log_end();
}

void init(void)
{
    ag_log_start("inferd");
    ag_puts("up. holds no capability to any tool; it can only ask");
    ag_log_end();
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)msginfo;

    switch (ch) {
    case CH_INFERD_AGENT0:
        forward((struct ag_infer *)infer_agent0);
        break;
    case CH_INFERD_AGENT1:
        forward((struct ag_infer *)infer_agent1);
        break;
    default:
        break;
    }

    return microkit_msginfo_new(0, 0);
}

void notified(microkit_channel ch)
{
    (void)ch;
}
