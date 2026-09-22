/*
 * AgenticOS -- the channel map.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Microkit channel ids are per protection domain, so every id below is named
 * from the point of view of the domain that holds it. The map is the
 * enforcement: inferd has no channel to any tool, so there is no name inferd
 * can utter that reaches one. Keep this file and agenticos.system in step.
 */

#pragma once

/* inputd */
#define CH_INPUTD_IRQ        0   /* PL011 receive interrupt */
#define CH_INPUTD_MEDIATOR   1   /* gate 3: confirmation request/response */
#define CH_INPUTD_AGENT0     2   /* attested utterance delivery */
#define CH_INPUTD_TASKD      3   /* operator commands: spawn, revoke, dump */

/* mediator */
#define CH_MED_AGENT0        0   /* PPC target for the main agent */
#define CH_MED_AGENT1        1   /* PPC target for the subagent */
#define CH_MED_TASKD         2   /* PPC to taskd: gate 1 */
#define CH_MED_TOOL_MAIL     3   /* PPC to the read-effect tool */
#define CH_MED_TOOL_PAY      4   /* PPC to the irreversible-effect tool */
#define CH_MED_INPUTD        5   /* gate 3 */
#define CH_MED_KEYRING       6   /* PPC to keyring: identity, never the token */

/* taskd */
#define CH_TASKD_MEDIATOR    0
#define CH_TASKD_AGENT0      1
#define CH_TASKD_AGENT1      2
#define CH_TASKD_INPUTD      3

/* inferd */
#define CH_INFERD_AGENT0     0
#define CH_INFERD_AGENT1     1
#define CH_INFERD_NETPROXY   2

/* netproxy */
#define CH_NETPROXY_INFERD   0
#define CH_NETPROXY_IRQ      1   /* virtio-mmio interrupt */

/* agent tasks */
#define CH_AGENT_MEDIATOR    0
#define CH_AGENT_TASKD       1
#define CH_AGENT_INFERD      2
#define CH_AGENT_INPUTD      3   /* agent0 only */

/* tool components */
#define CH_TOOL_MEDIATOR     0
#define CH_TOOL_KEYRING      1

/* keyring */
#define CH_KEYRING_MEDIATOR  0
#define CH_KEYRING_TOOL_MAIL 1
#define CH_KEYRING_TOOL_PAY  2
