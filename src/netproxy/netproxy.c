/*
 * netproxy -- the only way out of the machine.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * D9 puts local inference on the first physical target; until then the model
 * lives off the box and is reached through this component, which owns the
 * transport and nothing else. inferd cannot reach the network except by
 * asking netproxy, and netproxy cannot reach a tool at all.
 *
 * Two backends, chosen at build time:
 *   replay  a recorded transcript compiled into the image. Deterministic,
 *           needs nothing outside QEMU, and is what `make run` uses.
 *   virtio  a virtio-mmio console to a bridge on the host, which makes the
 *           real call to a model endpoint. See tools/inference-bridge.py.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>
#include <agenticos/netbackend.h>

uintptr_t infer_net;

/*
 * The virtio-mmio transport. These are set by the Microkit tool for every
 * build so one system description serves both backends; the replay backend
 * simply never touches them.
 */
uintptr_t virtio_base;
uintptr_t virtio_queue_vaddr;
uintptr_t virtio_queue_paddr;
uintptr_t virtio_buf_vaddr;
uintptr_t virtio_buf_paddr;

void init(void)
{
    ag_log_start("netproxy");
    ag_puts("up. backend=");
    ag_puts(ag_net_backend_name());
    ag_log_end();
    ag_net_backend_init();
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    (void)msginfo;

    if (ch == CH_NETPROXY_INFERD) {
        struct ag_infer *m = (struct ag_infer *)infer_net;
        if (m->magic != AG_MAGIC) {
            m->status = AG_ERR_MALFORMED;
            m->out_len = 0;
        } else {
            ag_net_backend_complete(m);
        }
    }

    return microkit_msginfo_new(0, 0);
}

void notified(microkit_channel ch)
{
    ag_net_backend_notified(ch);
}
