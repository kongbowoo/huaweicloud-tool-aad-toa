/*
 * TOA pure logic layer, shared by the kernel module (toa.c) and the
 * userland unit tests (tests/).  Keep this file free of kernel-only
 * APIs: everything here compiles both with _KERNEL and in userland
 * via tests/toa_ut_shim.h.
 */

#ifndef TOA_CORE_H
#define TOA_CORE_H

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>
#endif

/* TOA protocol constants (must match the proxy side / Linux toa.h) */
#ifndef TCPOPT_EOL
#define TCPOPT_EOL	0
#endif
#ifndef TCPOPT_NOP
#define TCPOPT_NOP	1
#endif
#define TCPOPT_TOA	254
#define TCPOLEN_TOA	8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

#define TOA_MAX_SCOPE		5
#define TOA_SCOPE_STR_MAX	256
#define TOA_HASH_SIZE		1024	/* power of two */

struct toa_data {
	uint8_t		opcode;
	uint8_t		opsize;
	uint16_t	port;		/* network byte order, as on wire */
	uint32_t	ip;		/* network byte order, as on wire */
};

_Static_assert(sizeof(struct toa_data) == 8, "toa_data must be 8 bytes");

/* source address scope entry, addresses in host-order numeric form */
struct toa_scope {
	uint32_t	begin;
	uint32_t	end;
};

extern struct toa_scope	toa_scopes[TOA_MAX_SCOPE];
extern int		toa_nscope;
extern char		toa_scope_str[TOA_SCOPE_STR_MAX];

/* "a.b.c.d" -> numeric value (e.g. "1.2.3.4" -> 0x01020304), *ok = 0 on error */
uint32_t toa_in_aton(const char *str, int *ok);

/* parse "a.b.c.d/nn,..." into toa_scopes[]; empty string resets to
 * "accept all"; returns 0 on success, -1 on error (toa_nscope unchanged) */
int toa_scope_parse(const char *s);

/* host-order numeric address against the configured scopes;
 * 1 = in scope (always 1 when no scope is configured) */
int toa_in_scope(uint32_t saddr);

/* scan a TCP options byte stream for TOA; returns 0 and fills *out on
 * hit, -1 when absent or malformed; EOL terminates the scan but keeps
 * an already-seen TOA value */
int toa_find_toa(const uint8_t *ptr, int length, struct toa_data *out);

/* five-tuple hash (values are network-order as stored on wire);
 * result is always < TOA_HASH_SIZE */
uint32_t toa_hash(uint32_t faddr, uint16_t fport, uint32_t laddr,
    uint16_t lport);

#endif
