/*
 * netproxy virtio backend -- inference over a link to the outside.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * netproxy owns one virtio-mmio console and speaks a two-line protocol to a
 * bridge on the host, which makes the real call to a model endpoint. This
 * component is outside the trusted computing base and holds no capability to
 * anything but this transport: a hostile bridge can lie about what the model
 * said, and the gates still hold, because what comes back is a request.
 *
 * The queue is polled rather than driven by an interrupt. That keeps the
 * component small, and inputd runs at a higher priority, so a human can still
 * type while netproxy is waiting on the far end.
 *
 * See tools/inference-bridge.py for the other side.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/util.h>
#include <agenticos/netbackend.h>

extern uintptr_t virtio_base;
extern uintptr_t virtio_queue_vaddr;
extern uintptr_t virtio_queue_paddr;
extern uintptr_t virtio_buf_vaddr;
extern uintptr_t virtio_buf_paddr;

#define VIRTIO_MAGIC        0x74726976u
#define VIRTIO_DEV_CONSOLE  3u
#define MMIO_SLOT_STRIDE    0x200u
#define MMIO_SLOT_COUNT     32u

#define R_MAGIC            0x000
#define R_VERSION          0x004
#define R_DEVICE_ID        0x008
#define R_DEVICE_FEATURES  0x010
#define R_DEVICE_FEAT_SEL  0x014
#define R_DRIVER_FEATURES  0x020
#define R_DRIVER_FEAT_SEL  0x024
#define R_QUEUE_SEL        0x030
#define R_QUEUE_NUM_MAX    0x034
#define R_QUEUE_NUM        0x038
#define R_QUEUE_READY      0x044
#define R_QUEUE_NOTIFY     0x050
#define R_INTERRUPT_STATUS 0x060
#define R_INTERRUPT_ACK    0x064
#define R_STATUS           0x070
#define R_QUEUE_DESC_LO    0x080
#define R_QUEUE_DESC_HI    0x084
#define R_QUEUE_DRIVER_LO  0x090
#define R_QUEUE_DRIVER_HI  0x094
#define R_QUEUE_DEVICE_LO  0x0a0
#define R_QUEUE_DEVICE_HI  0x0a4

#define ST_ACKNOWLEDGE  1u
#define ST_DRIVER       2u
#define ST_DRIVER_OK    4u
#define ST_FEATURES_OK  8u
#define ST_FAILED      128u

#define VIRTIO_F_VERSION_1 32u   /* feature bit 32, i.e. word 1 bit 0 */

#define Q_RX 0u
#define Q_TX 1u
#define Q_SIZE 8u

#define DESC_F_NEXT  1u
#define DESC_F_WRITE 2u

/* Per-queue offsets inside the shared queue page. */
#define Q_STRIDE      0x400u
#define OFF_DESC      0x000u
#define OFF_AVAIL     0x100u
#define OFF_USED      0x180u

/* Buffers: eight receive slots then one transmit slot. */
#define RX_SLOT_SIZE  512u
#define TX_OFFSET     (RX_SLOT_SIZE * Q_SIZE)
#define TX_SIZE       2048u

#define END_MARKER "\n--AGOS-END--\n"

struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[Q_SIZE];
    uint16_t used_event;
};

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
};

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[Q_SIZE];
    uint16_t avail_event;
};

static uintptr_t dev;          /* the slot we found, 0 if none */
static uint16_t  rx_used_seen;
static uint16_t  tx_used_seen;

static volatile uint32_t *r(uintptr_t off)
{
    return (volatile uint32_t *)(dev + off);
}

static void barrier(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

static struct virtq_desc *desc_of(uint32_t q)
{
    return (struct virtq_desc *)(virtio_queue_vaddr + q * Q_STRIDE + OFF_DESC);
}

static struct virtq_avail *avail_of(uint32_t q)
{
    return (struct virtq_avail *)(virtio_queue_vaddr + q * Q_STRIDE + OFF_AVAIL);
}

static struct virtq_used *used_of(uint32_t q)
{
    return (struct virtq_used *)(virtio_queue_vaddr + q * Q_STRIDE + OFF_USED);
}

static uint64_t queue_paddr(uint32_t q, uint32_t off)
{
    return (uint64_t)virtio_queue_paddr + q * Q_STRIDE + off;
}

static char *rx_slot(uint32_t i)
{
    return (char *)(virtio_buf_vaddr + i * RX_SLOT_SIZE);
}

static char *tx_slot(void)
{
    return (char *)(virtio_buf_vaddr + TX_OFFSET);
}

static void setup_queue(uint32_t q)
{
    *r(R_QUEUE_SEL) = q;
    if (*r(R_QUEUE_NUM_MAX) < Q_SIZE) {
        return;
    }
    *r(R_QUEUE_NUM) = Q_SIZE;

    uint64_t d = queue_paddr(q, OFF_DESC);
    uint64_t a = queue_paddr(q, OFF_AVAIL);
    uint64_t u = queue_paddr(q, OFF_USED);

    *r(R_QUEUE_DESC_LO)   = (uint32_t)d;
    *r(R_QUEUE_DESC_HI)   = (uint32_t)(d >> 32);
    *r(R_QUEUE_DRIVER_LO) = (uint32_t)a;
    *r(R_QUEUE_DRIVER_HI) = (uint32_t)(a >> 32);
    *r(R_QUEUE_DEVICE_LO) = (uint32_t)u;
    *r(R_QUEUE_DEVICE_HI) = (uint32_t)(u >> 32);

    avail_of(q)->flags = 0;
    avail_of(q)->idx = 0;
    used_of(q)->flags = 0;
    used_of(q)->idx = 0;

    barrier();
    *r(R_QUEUE_READY) = 1;
}

/* Hand every receive slot to the device so it has somewhere to put bytes. */
static void post_rx_all(void)
{
    struct virtq_desc *d = desc_of(Q_RX);
    struct virtq_avail *a = avail_of(Q_RX);

    for (uint32_t i = 0; i < Q_SIZE; i++) {
        d[i].addr = (uint64_t)virtio_buf_paddr + i * RX_SLOT_SIZE;
        d[i].len = RX_SLOT_SIZE;
        d[i].flags = DESC_F_WRITE;
        d[i].next = 0;
        a->ring[i % Q_SIZE] = (uint16_t)i;
    }
    barrier();
    a->idx = (uint16_t)Q_SIZE;
    barrier();
    *r(R_QUEUE_NOTIFY) = Q_RX;
}

static void post_rx_one(uint16_t id)
{
    struct virtq_avail *a = avail_of(Q_RX);
    a->ring[a->idx % Q_SIZE] = id;
    barrier();
    a->idx++;
    barrier();
    *r(R_QUEUE_NOTIFY) = Q_RX;
}

const char *ag_net_backend_name(void)
{
    return "virtio (a bridge on the host calls the model endpoint)";
}

void ag_net_backend_init(void)
{
    dev = 0;
    rx_used_seen = 0;
    tx_used_seen = 0;

    for (uint32_t i = 0; i < MMIO_SLOT_COUNT; i++) {
        uintptr_t slot = virtio_base + i * MMIO_SLOT_STRIDE;
        volatile uint32_t *m = (volatile uint32_t *)slot;
        if (m[R_MAGIC / 4] != VIRTIO_MAGIC) {
            continue;
        }
        if (m[R_DEVICE_ID / 4] != VIRTIO_DEV_CONSOLE) {
            continue;
        }
        ag_log_start("netproxy");
        ag_puts("virtio console at mmio slot ");
        ag_putu(i);
        ag_puts(", version ");
        ag_putu(m[R_VERSION / 4]);
        ag_log_end();

        if (m[R_VERSION / 4] != 2) {
            /*
             * QEMU still defaults virtio-mmio to the legacy interface on the
             * arm virt board. This driver only speaks the modern one, which
             * is a deliberate trade: it is half the code and it is what any
             * real target would offer. Pass the flag below and it appears.
             */
            ag_log_start("netproxy");
            ag_puts("that is the legacy interface; start QEMU with "
                    "-global virtio-mmio.force-legacy=false");
            ag_log_end();
            break;
        }

        dev = slot;
        break;
    }

    if (dev == 0) {
        ag_log_start("netproxy");
        ag_puts("no virtio console found; every inference request will fail. "
                "Start QEMU with a virtconsole, or build NET_BACKEND=replay");
        ag_log_end();
        return;
    }

    *r(R_STATUS) = 0;
    barrier();
    *r(R_STATUS) = ST_ACKNOWLEDGE;
    *r(R_STATUS) = ST_ACKNOWLEDGE | ST_DRIVER;

    /*
     * Negotiate nothing but VERSION_1. In particular we do not take MULTIPORT,
     * so this is plain port 0 and there is no control queue to service.
     */
    *r(R_DRIVER_FEAT_SEL) = 0;
    *r(R_DRIVER_FEATURES) = 0;
    *r(R_DRIVER_FEAT_SEL) = 1;
    *r(R_DRIVER_FEATURES) = 1u << (VIRTIO_F_VERSION_1 - 32);

    *r(R_STATUS) = ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK;
    barrier();
    if (!(*r(R_STATUS) & ST_FEATURES_OK)) {
        ag_log_start("netproxy");
        ag_puts("the device refused our feature set");
        ag_log_end();
        *r(R_STATUS) = ST_FAILED;
        dev = 0;
        return;
    }

    setup_queue(Q_RX);
    setup_queue(Q_TX);

    *r(R_STATUS) = ST_ACKNOWLEDGE | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK;
    barrier();

    post_rx_all();

    ag_log_start("netproxy");
    ag_puts("virtio console ready");
    ag_log_end();
}

static void tx(const char *data, uint32_t len)
{
    if (len > TX_SIZE) {
        len = TX_SIZE;
    }
    char *buf = tx_slot();
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = data[i];
    }

    struct virtq_desc *d = desc_of(Q_TX);
    struct virtq_avail *a = avail_of(Q_TX);

    d[0].addr = (uint64_t)virtio_buf_paddr + TX_OFFSET;
    d[0].len = len;
    d[0].flags = 0;
    d[0].next = 0;

    a->ring[a->idx % Q_SIZE] = 0;
    barrier();
    a->idx++;
    barrier();
    *r(R_QUEUE_NOTIFY) = Q_TX;

    /* Wait for the device to take it, with a bound so a dead bridge is not fatal. */
    for (uint64_t spin = 0; spin < 200000000ULL; spin++) {
        barrier();
        if (used_of(Q_TX)->idx != tx_used_seen) {
            tx_used_seen = used_of(Q_TX)->idx;
            return;
        }
    }
}

/*
 * Read until a newline. Returns the length, or 0 if the far end never
 * answered. The bridge's reply is one line, so this is the whole protocol.
 */
static uint32_t rx_line(char *out, uint32_t out_max)
{
    uint32_t len = 0;

    for (uint64_t spin = 0; spin < 600000000ULL; spin++) {
        barrier();
        struct virtq_used *u = used_of(Q_RX);
        if (u->idx == rx_used_seen) {
            continue;
        }

        while (rx_used_seen != u->idx) {
            struct virtq_used_elem *e = &u->ring[rx_used_seen % Q_SIZE];
            uint16_t id = (uint16_t)e->id;
            uint32_t n = e->len;
            const char *src = rx_slot(id);

            for (uint32_t i = 0; i < n; i++) {
                if (src[i] == '\n') {
                    out[len] = '\0';
                    rx_used_seen++;
                    post_rx_one(id);
                    return len;
                }
                if (len < out_max - 1) {
                    out[len++] = src[i];
                }
            }

            rx_used_seen++;
            post_rx_one(id);
        }
    }

    out[len] = '\0';
    return 0;
}

void ag_net_backend_complete(struct ag_infer *m)
{
    if (dev == 0) {
        m->out_len = (uint32_t)ag_strlcpy(
            m->out, "SAY The inference link is down.", AG_OUT_MAX);
        m->status = AG_OK;
        return;
    }

    tx(m->prompt, m->prompt_len);
    tx(END_MARKER, (uint32_t)ag_strlen(END_MARKER));

    uint32_t n = rx_line(m->out, AG_OUT_MAX);
    if (n == 0) {
        ag_log_start("netproxy");
        ag_puts("the bridge did not answer");
        ag_log_end();
        m->out_len = (uint32_t)ag_strlcpy(
            m->out, "SAY The model did not answer.", AG_OUT_MAX);
        m->status = AG_OK;
        return;
    }

    m->out_len = n;
    m->status = AG_OK;
}

void ag_net_backend_notified(microkit_channel ch)
{
    (void)ch;
}
