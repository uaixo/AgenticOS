/*
 * AgenticOS -- freestanding helpers.
 *
 * Copyright 2026 the AgenticOS authors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * There is no libc here. These are the few string and formatting pieces the
 * components need, kept small enough to read in one sitting -- the mediator
 * is in the trusted computing base and so is everything it links against.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

size_t ag_strlen(const char *s);
int    ag_streq(const char *a, const char *b);
int    ag_strneq(const char *a, const char *b, size_t n);
size_t ag_strlcpy(char *dst, const char *src, size_t dst_size);
size_t ag_memcpy_str(char *dst, const char *src, size_t len, size_t dst_size);
void   ag_memzero(void *p, size_t n);
int    ag_str_contains(const char *hay, const char *needle);

/* A 64-bit FNV-1a digest. Used to bind a confirmation to exact arguments. */
uint64_t ag_digest(const void *data, size_t len);

/*
 * Logging. Every component writes to the kernel debug console; the mediator's
 * audit lines are prefixed so they can be grepped out of a boot log.
 */
void ag_puts(const char *s);
void ag_putu(uint64_t v);
void ag_puthex(uint64_t v);
void ag_putn(const char *s, size_t n);

/* ag_log("prefix", "part", ...) with a NULL sentinel; keeps call sites short. */
void ag_log_start(const char *component);
void ag_log_end(void);
void ag_label_puts(uint32_t label);
