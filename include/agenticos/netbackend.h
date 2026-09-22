/*
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <microkit.h>
#include <agenticos/abi.h>

const char *ag_net_backend_name(void);
void        ag_net_backend_init(void);
void        ag_net_backend_complete(struct ag_infer *m);
void        ag_net_backend_notified(microkit_channel ch);
