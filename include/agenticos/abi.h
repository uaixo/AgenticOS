/*
 * AgenticOS -- the wire ABI every mediated message uses.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Architecture decisions D3, D4 and D5 land here. Everything that crosses a
 * protection-domain boundary carries a provenance label in its header, and
 * every tool declares an effect class that the mediator reads before it
 * dispatches anything.
 */

#pragma once

#include <stdint.h>

#define AG_MAGIC        0x41474f53u  /* 'AGOS' */
#define AG_ABI_VERSION  1u

/*
 * Provenance labels (D5). Four bits, joined with OR on every hop: once a
 * working set has touched tainted bytes it stays tainted. ATTESTED means the
 * bytes entered the system through inputd, which is the only protection
 * domain holding a capability to the input device.
 */
#define AG_LABEL_NONE      0x0u
#define AG_LABEL_ATTESTED  0x1u
#define AG_LABEL_TAINTED   0x2u
#define AG_LABEL_MASK      0xfu

static inline uint32_t ag_label_join(uint32_t a, uint32_t b)
{
    return (a | b) & AG_LABEL_MASK;
}

/* Effect classes a tool manifest may declare (D5). */
#define AG_EFFECT_READ          0u
#define AG_EFFECT_WRITE         1u
#define AG_EFFECT_IRREVERSIBLE  2u
#define AG_EFFECT_SPEND         3u

/*
 * An effect the mediator will not let tainted arguments reach without a fresh
 * attestation over the input path.
 */
static inline int ag_effect_needs_attestation(uint32_t effect)
{
    return effect == AG_EFFECT_IRREVERSIBLE || effect == AG_EFFECT_SPEND;
}

/* Tools in this prototype. A real system reads these from signed manifests. */
#define AG_TOOL_NONE            0u
#define AG_TOOL_MAIL_READ       1u
#define AG_TOOL_PAYMENTS_SEND   2u
#define AG_TOOL_COUNT           3u

/* Operations carried in ag_call.op. */
#define AG_OP_INVOKE        1u
#define AG_OP_RESUME        2u  /* re-drive a call whose confirmation resolved */

/* Status codes returned by the mediator. */
#define AG_OK                          0u
#define AG_PENDING_CONFIRMATION        1u
#define AG_DENY_NO_CAPABILITY          2u
#define AG_DENY_TAINTED_IRREVERSIBLE   3u
#define AG_DENY_ATTESTATION_REFUSED    4u
#define AG_DENY_REVOKED                5u
#define AG_DENY_NO_SUCH_TOOL           6u
#define AG_DENY_BAD_NONCE              7u
#define AG_ERR_MALFORMED               8u

#define AG_ARG_MAX   512
#define AG_RES_MAX   1024

/*
 * The mediated call. Lives in a memory region shared by exactly two
 * protection domains, so a task cannot see another task's calls.
 */
struct ag_call {
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t status;
    uint64_t call_id;
    uint64_t nonce;      /* binds a confirmation to this call and these args */
    uint32_t label;      /* provenance of arg[] */
    uint32_t res_label;  /* provenance of res[], set by the mediator */
    uint32_t task_id;    /* filled in by the mediator from the channel */
    uint32_t tool_id;
    uint32_t effect;     /* filled in by the mediator from the manifest */
    uint32_t arg_len;
    uint32_t res_len;
    uint32_t _pad;
    char     arg[AG_ARG_MAX];
    char     res[AG_RES_MAX];
};

/* Confirmation request/response, mediator <-> inputd (gate 3). */
#define AG_CONFIRM_IDLE      0u
#define AG_CONFIRM_REQUESTED 1u
#define AG_CONFIRM_GRANTED   2u
#define AG_CONFIRM_REFUSED   3u
#define AG_CONFIRM_AUDIT     4u  /* operator asked for the audit log */

#define AG_CONFIRM_TEXT_MAX 512

struct ag_confirm {
    uint32_t magic;
    uint32_t state;
    uint64_t nonce;
    uint32_t task_id;
    uint32_t tool_id;
    uint32_t effect;
    uint32_t text_len;
    char     text[AG_CONFIRM_TEXT_MAX]; /* read back to the human verbatim */
};

/* Attested utterance, inputd -> an agent task. */
#define AG_UTTER_MAX 256

struct ag_utterance {
    uint32_t magic;
    uint32_t label;   /* always AG_LABEL_ATTESTED: inputd owns the device */
    uint32_t seq;
    uint32_t len;
    char     text[AG_UTTER_MAX];
};

/* Inference request/response, an agent task -> inferd -> netproxy. */
#define AG_PROMPT_MAX 2048
#define AG_OUT_MAX    256

struct ag_infer {
    uint32_t magic;
    uint32_t version;
    uint32_t task_id;
    uint32_t label;      /* provenance of the context; advisory only */
    uint32_t step;
    uint32_t status;
    uint32_t prompt_len;
    uint32_t out_len;
    char     prompt[AG_PROMPT_MAX];
    char     out[AG_OUT_MAX];
};

/* Operator commands, inputd -> taskd. A human at the trusted device. */
#define AG_OPCMD_NONE    0u
#define AG_OPCMD_REVOKE  1u
#define AG_OPCMD_DUMP    2u

struct ag_opcmd {
    uint32_t magic;
    uint32_t cmd;
    uint32_t arg;
    uint32_t seq;
};

/* taskd's authority table, queried by the mediator over a PPC (gate 1). */
#define AG_TASKD_CAN_INVOKE  1u
#define AG_TASKD_SPAWN       2u
#define AG_TASKD_REVOKE      3u
#define AG_TASKD_DUMP        4u
#define AG_TASKD_REGISTER    5u

#define AG_TASK_MAIN  0u
#define AG_TASK_SUB   1u
#define AG_TASK_MAX   2u

/* Human-readable names, shared so the audit log and the console agree. */
static inline const char *ag_tool_name(uint32_t tool_id)
{
    switch (tool_id) {
    case AG_TOOL_MAIL_READ:     return "mail.read";
    case AG_TOOL_PAYMENTS_SEND: return "payments.send";
    default:                    return "<unknown>";
    }
}

static inline const char *ag_effect_name(uint32_t effect)
{
    switch (effect) {
    case AG_EFFECT_READ:         return "read";
    case AG_EFFECT_WRITE:        return "write";
    case AG_EFFECT_IRREVERSIBLE: return "irreversible";
    case AG_EFFECT_SPEND:        return "spend";
    default:                     return "?";
    }
}

static inline const char *ag_status_name(uint32_t status)
{
    switch (status) {
    case AG_OK:                        return "OK";
    case AG_PENDING_CONFIRMATION:      return "PENDING_CONFIRMATION";
    case AG_DENY_NO_CAPABILITY:        return "DENY_NO_CAPABILITY";
    case AG_DENY_TAINTED_IRREVERSIBLE: return "DENY_TAINTED_IRREVERSIBLE";
    case AG_DENY_ATTESTATION_REFUSED:  return "DENY_ATTESTATION_REFUSED";
    case AG_DENY_REVOKED:              return "DENY_REVOKED";
    case AG_DENY_NO_SUCH_TOOL:         return "DENY_NO_SUCH_TOOL";
    case AG_DENY_BAD_NONCE:            return "DENY_BAD_NONCE";
    case AG_ERR_MALFORMED:             return "ERR_MALFORMED";
    default:                           return "?";
    }
}
