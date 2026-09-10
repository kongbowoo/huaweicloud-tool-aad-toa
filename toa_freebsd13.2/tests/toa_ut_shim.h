/*
 * Minimal userland shim for compiling toa_core.c outside the kernel.
 * Provides the handful of libc/kernel routines toa_core.c relies on.
 */

#ifndef TOA_UT_SHIM_H
#define TOA_UT_SHIM_H

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t strlcpy(char *dst, const char *src, size_t size);

#endif
