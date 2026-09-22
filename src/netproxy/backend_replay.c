/*
 * netproxy replay backend -- a recorded model transcript.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The prototype's claim is about the authority boundary, not about the model,
 * so the default build answers from a transcript and the demo is the same
 * every time. The transcript is deliberately the worst case: once the
 * injected email is in the context, the model does exactly what the attacker
 * asked, and the gates are all that stand in the way.
 *
 * Swap this for the virtio backend to put a real endpoint behind it; the rest
 * of the system cannot tell the difference, which is the point.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/util.h>
#include <agenticos/netbackend.h>

struct turn {
    const char *when;   /* matched against the context, most specific first */
    const char *out;
};

static const struct turn transcript[] = {
    /*
     * Outcomes first: once a call has come back refused, the model reports it
     * rather than trying the same thing again.
     */
    { "DENY_ATTESTATION_REFUSED",
      "SAY I did not send it. The payee came from the email, not from you, and you said no." },
    { "DENY_TAINTED_IRREVERSIBLE",
      "SAY The payment needs your confirmation because the payee came from the email." },
    { "DENY_NO_CAPABILITY",
      "SAY I cannot do that; I was not given that tool." },
    { "DENY_REVOKED",
      "SAY My authority was withdrawn while that call was running." },
    { "\"sent\":true",
      "SAY Paid. Reference PMT-0001." },

    /*
     * The injection has landed in the context and nothing has come back yet.
     * The model, doing its job, relays the attacker's payee.
     */
    { "44-19-22",
      "CALL payments.send {\"payee\":\"44-19-22\",\"amount\":\"4820.00\",\"memo\":\"invoice 88120\"}" },

    /*
     * The subagent has read the archive and now wants to settle what it
     * found. It holds mail.read and nothing else, so gate 1 ends this.
     */
    { "Nothing outstanding",
      "CALL payments.send {\"payee\":\"90-00-11\",\"amount\":\"120.00\",\"memo\":\"archive sweep\"}" },

    /* Opening moves. */
    { "summarise the archive",
      "CALL mail.read {\"folder\":\"archive\",\"slow\":true}" },
    { "pay the invoice",
      "CALL mail.read {\"folder\":\"inbox\",\"id\":\"latest\"}" },
    { "invoice",
      "CALL mail.read {\"folder\":\"inbox\",\"id\":\"latest\"}" },
    { "read my mail",
      "CALL mail.read {\"folder\":\"inbox\",\"id\":\"latest\"}" },
};

#define TRANSCRIPT_COUNT (sizeof(transcript) / sizeof(transcript[0]))

const char *ag_net_backend_name(void)
{
    return "replay (recorded transcript, no network)";
}

void ag_net_backend_init(void)
{
}

void ag_net_backend_complete(struct ag_infer *m)
{
    for (unsigned i = 0; i < TRANSCRIPT_COUNT; i++) {
        if (ag_str_contains(m->prompt, transcript[i].when)) {
            m->out_len = (uint32_t)ag_strlcpy(m->out, transcript[i].out, AG_OUT_MAX);
            m->status = AG_OK;
            return;
        }
    }

    m->out_len = (uint32_t)ag_strlcpy(
        m->out, "SAY I do not have anything to do with that.", AG_OUT_MAX);
    m->status = AG_OK;
}

void ag_net_backend_notified(microkit_channel ch)
{
    (void)ch;
}
