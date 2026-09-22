/*
 * inputd -- the attested input path.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * D7: inputd owns the input device and is the root of trust for
 * confirmation. It is the only protection domain with the PL011 mapped and
 * the only holder of its receive interrupt, so a keystroke is something no
 * model and no tool component can manufacture. Bytes that arrive here are
 * stamped ATTESTED at the point of capture, before anything else sees them.
 *
 * On the real target this is the microphone, the keyboard and the camera. On
 * QEMU it is the serial line you are typing into.
 */

#include <stdint.h>
#include <microkit.h>

#include <agenticos/abi.h>
#include <agenticos/chan.h>
#include <agenticos/util.h>

/* PL011 registers, relative to the mapped device page. */
#define UARTDR    0x000
#define UARTFR    0x018
#define UARTIMSC  0x038
#define UARTMIS   0x040
#define UARTICR   0x044

#define FR_RXFE   (1u << 4)   /* receive FIFO empty */
#define FR_TXFF   (1u << 5)   /* transmit FIFO full */
#define INT_RX    (1u << 4)
#define INT_RT    (1u << 6)   /* receive timeout: a partial FIFO still counts */

uintptr_t uart_base;
uintptr_t confirm_region;
uintptr_t utter_region;
uintptr_t opcmd_region;

static uint32_t opcmd_seq;

static volatile uint32_t *reg(uintptr_t off)
{
    return (volatile uint32_t *)(uart_base + off);
}

/*
 * Written straight to the device this protection domain exclusively holds.
 * Component logging goes to the kernel debug console instead, so a prompt
 * that appears here came from inputd and from nothing else.
 */
static void dev_putc(char c)
{
    if (c == '\n') {
        while (*reg(UARTFR) & FR_TXFF) { }
        *reg(UARTDR) = '\r';
    }
    while (*reg(UARTFR) & FR_TXFF) { }
    *reg(UARTDR) = (uint32_t)(unsigned char)c;
}

static void dev_puts(const char *s)
{
    for (size_t i = 0; s[i] != '\0'; i++) {
        dev_putc(s[i]);
    }
}

static void dev_putn(const char *s, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        dev_putc(s[i]);
    }
}

#define LINE_MAX 256
static char line[LINE_MAX];
static uint32_t line_len;
static uint32_t utter_seq;

static void prompt(void)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;
    if (cf->state == AG_CONFIRM_REQUESTED) {
        dev_puts("confirm> ");
    } else {
        dev_puts("agenticos> ");
    }
}

static void banner(void)
{
    dev_puts("\n");
    dev_puts("AgenticOS prototype -- seL4 + Microkit, QEMU virt aarch64\n");
    dev_puts("inputd owns this serial line. What you type is stamped ATTESTED.\n");
    dev_puts("\n");
    dev_puts("  :help     the commands\n");
    dev_puts("  :demo     run the prompt-injection scenario end to end\n");
    dev_puts("  :spawn    spawn a subagent holding a strict subset\n");
    dev_puts("  :revoke   revoke the subagent, including mid-call\n");
    dev_puts("  :tasks    print the task tree and its authority sets\n");
    dev_puts("  :audit    print the mediator's audit log\n");
    dev_puts("  anything else is spoken to the main agent as attested input\n");
    dev_puts("\n");
}

static void help(void)
{
    banner();
}

/*
 * inputd runs at the top priority in this system, because a human must be
 * able to reach it while a tool component is spinning. That rules out a
 * protected procedure call into taskd, which would require taskd to be higher
 * still, so operator commands go over shared memory and a notification.
 */
static void taskd_command(uint32_t cmd, uint32_t arg)
{
    struct ag_opcmd *c = (struct ag_opcmd *)opcmd_region;
    c->magic = AG_MAGIC;
    c->cmd = cmd;
    c->arg = arg;
    c->seq = ++opcmd_seq;
    microkit_notify(CH_INPUTD_TASKD);
}

static void deliver_utterance(const char *text, uint32_t len)
{
    struct ag_utterance *u = (struct ag_utterance *)utter_region;
    u->magic = AG_MAGIC;
    u->label = AG_LABEL_ATTESTED;   /* stamped here, at the point of capture */
    u->seq = ++utter_seq;
    u->len = (uint32_t)ag_memcpy_str(u->text, text, len, AG_UTTER_MAX);
    microkit_notify(CH_INPUTD_AGENT0);
}

static void answer_confirmation(int granted)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;
    cf->state = granted ? AG_CONFIRM_GRANTED : AG_CONFIRM_REFUSED;
    dev_puts(granted ? "  attested: yes\n" : "  attested: no\n");
    microkit_notify(CH_INPUTD_MEDIATOR);
}

static void show_confirmation(void)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;

    dev_puts("\n");
    dev_puts("  ---- confirmation required ----------------------------------\n");
    dev_puts("  task ");
    dev_putc((char)('0' + (cf->task_id % 10)));
    dev_puts(" wants ");
    dev_puts(ag_tool_name(cf->tool_id));
    dev_puts(", effect ");
    dev_puts(ag_effect_name(cf->effect));
    dev_puts("\n");
    dev_puts("  arguments, read back verbatim:\n    ");
    dev_putn(cf->text, cf->text_len);
    dev_puts("\n");
    dev_puts("  These arguments carry TAINTED: they came from something the\n");
    dev_puts("  agent read, not from you. Answer y or n.\n");
    dev_puts("  -------------------------------------------------------------\n");
}

static void handle_line(void)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;

    line[line_len] = '\0';

    if (cf->state == AG_CONFIRM_REQUESTED) {
        if (line_len == 1 && (line[0] == 'y' || line[0] == 'Y')) {
            answer_confirmation(1);
            line_len = 0;
            prompt();
            return;
        }
        if (line_len == 1 && (line[0] == 'n' || line[0] == 'N')) {
            answer_confirmation(0);
            line_len = 0;
            prompt();
            return;
        }
        dev_puts("  answer y or n.\n");
        line_len = 0;
        prompt();
        return;
    }

    if (line_len == 0) {
        prompt();
        return;
    }

    if (ag_streq(line, ":help")) {
        help();
    } else if (ag_streq(line, ":tasks")) {
        taskd_command(AG_OPCMD_DUMP, 0);
    } else if (ag_streq(line, ":audit")) {
        cf->state = AG_CONFIRM_AUDIT;
        microkit_notify(CH_INPUTD_MEDIATOR);
    } else if (ag_streq(line, ":revoke")) {
        /*
         * A revoke from the trusted input device: a human, not a model. The
         * subagent may well be inside a tool call when this lands, which is
         * the point.
         */
        dev_puts("  revoking task 1\n");
        taskd_command(AG_OPCMD_REVOKE, AG_TASK_SUB);
    } else if (ag_streq(line, ":spawn")) {
        deliver_utterance(":spawn", 6);
    } else if (ag_streq(line, ":demo")) {
        deliver_utterance("pay the invoice in that email", 29);
    } else if (line[0] == ':') {
        dev_puts("  unknown command. :help for the list.\n");
    } else {
        deliver_utterance(line, line_len);
    }

    line_len = 0;
    prompt();
}

void init(void)
{
    struct ag_confirm *cf = (struct ag_confirm *)confirm_region;
    cf->magic = AG_MAGIC;
    cf->state = AG_CONFIRM_IDLE;

    struct ag_utterance *u = (struct ag_utterance *)utter_region;
    u->magic = AG_MAGIC;
    u->seq = 0;
    u->len = 0;

    line_len = 0;
    utter_seq = 0;
    opcmd_seq = 0;

    /* Drain anything the firmware left behind, then take receive interrupts. */
    while (!(*reg(UARTFR) & FR_RXFE)) {
        (void)*reg(UARTDR);
    }
    *reg(UARTICR) = 0x7ff;
    *reg(UARTIMSC) = INT_RX | INT_RT;

    ag_log_start("inputd");
    ag_puts("up. PL011 is mapped here and nowhere else; receive IRQ is ours");
    ag_log_end();

    banner();
    prompt();
}

void notified(microkit_channel ch)
{
    if (ch == CH_INPUTD_MEDIATOR) {
        struct ag_confirm *cf = (struct ag_confirm *)confirm_region;
        if (cf->state == AG_CONFIRM_REQUESTED) {
            show_confirmation();
            prompt();
        }
        return;
    }

    if (ch != CH_INPUTD_IRQ) {
        return;
    }

    uint32_t status = *reg(UARTMIS);
    *reg(UARTICR) = status;

    while (!(*reg(UARTFR) & FR_RXFE)) {
        char c = (char)(*reg(UARTDR) & 0xff);

        if (c == '\r' || c == '\n') {
            dev_puts("\n");
            handle_line();
            continue;
        }
        if (c == 0x7f || c == 0x08) {
            if (line_len > 0) {
                line_len--;
                dev_puts("\b \b");
            }
            continue;
        }
        if (c < 0x20) {
            continue;
        }
        if (line_len < LINE_MAX - 1) {
            line[line_len++] = c;
            dev_putc(c);
        }
    }

    microkit_irq_ack(CH_INPUTD_IRQ);
}
