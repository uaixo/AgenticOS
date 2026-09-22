/*
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <microkit.h>
#include <agenticos/util.h>
#include <agenticos/abi.h>

size_t ag_strlen(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

int ag_streq(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

int ag_strneq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
        if (a[i] == '\0') {
            return 1;
        }
    }
    return 1;
}

size_t ag_strlcpy(char *dst, const char *src, size_t dst_size)
{
    size_t i = 0;
    if (dst_size == 0) {
        return 0;
    }
    while (src[i] != '\0' && i < dst_size - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

size_t ag_memcpy_str(char *dst, const char *src, size_t len, size_t dst_size)
{
    size_t n = len;
    if (dst_size == 0) {
        return 0;
    }
    if (n > dst_size - 1) {
        n = dst_size - 1;
    }
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
    dst[n] = '\0';
    return n;
}

void ag_memzero(void *p, size_t n)
{
    volatile unsigned char *q = p;
    for (size_t i = 0; i < n; i++) {
        q[i] = 0;
    }
}

int ag_str_contains(const char *hay, const char *needle)
{
    size_t nl = ag_strlen(needle);
    if (nl == 0) {
        return 1;
    }
    for (size_t i = 0; hay[i] != '\0'; i++) {
        if (ag_strneq(&hay[i], needle, nl)) {
            return 1;
        }
    }
    return 0;
}

uint64_t ag_digest(const void *data, size_t len)
{
    const unsigned char *p = data;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

void ag_puts(const char *s)
{
    microkit_dbg_puts(s);
}

void ag_putn(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        microkit_dbg_putc(s[i]);
    }
}

void ag_putu(uint64_t v)
{
    char buf[21];
    int i = 20;
    buf[i] = '\0';
    if (v == 0) {
        microkit_dbg_putc('0');
        return;
    }
    while (v > 0 && i > 0) {
        buf[--i] = (char)('0' + (v % 10));
        v /= 10;
    }
    microkit_dbg_puts(&buf[i]);
}

void ag_puthex(uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    char buf[17];
    buf[16] = '\0';
    for (int i = 15; i >= 0; i--) {
        buf[i] = digits[v & 0xf];
        v >>= 4;
    }
    microkit_dbg_puts("0x");
    microkit_dbg_puts(buf);
}

void ag_log_start(const char *component)
{
    microkit_dbg_puts("[");
    microkit_dbg_puts(component);
    microkit_dbg_puts("] ");
}

void ag_log_end(void)
{
    microkit_dbg_puts("\n");
}

void ag_label_puts(uint32_t label)
{
    if (label == AG_LABEL_NONE) {
        microkit_dbg_puts("NONE");
        return;
    }
    int first = 1;
    if (label & AG_LABEL_ATTESTED) {
        microkit_dbg_puts("ATTESTED");
        first = 0;
    }
    if (label & AG_LABEL_TAINTED) {
        if (!first) {
            microkit_dbg_puts("|");
        }
        microkit_dbg_puts("TAINTED");
    }
}
