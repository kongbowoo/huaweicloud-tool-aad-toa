/*
 * TOA pure logic layer.  See toa_core.h for the contracts.
 * Compiled into the kernel module (with _KERNEL) and into the
 * userland unit tests (via tests/toa_ut_shim.h).
 */

#ifdef _KERNEL
#include "toa_core.h"
#include <sys/param.h>
#include <sys/systm.h>
#else
/* the shim must come before any system header so _DEFAULT_SOURCE takes effect */
#include "toa_ut_shim.h"
#include "toa_core.h"
#endif

struct toa_scope	toa_scopes[TOA_MAX_SCOPE];
int			toa_nscope;
char			toa_scope_str[TOA_SCOPE_STR_MAX];

uint32_t
toa_in_aton(const char *str, int *ok)
{
	uint32_t addr = 0;
	int octet = 0, ndots = 0, digits = 0;

	*ok = 0;
	while (*str != '\0') {
		if (*str == '.') {
			if (digits == 0 || octet > 255 || ndots >= 3)
				return (0);
			addr = (addr << 8) | octet;
			octet = 0;
			digits = 0;
			ndots++;
		} else if (*str >= '0' && *str <= '9') {
			octet = octet * 10 + (*str - '0');
			digits++;
			if (octet > 255)
				return (0);
		} else {
			return (0);
		}
		str++;
	}
	if (ndots != 3 || digits == 0 || octet > 255)
		return (0);
	addr = (addr << 8) | octet;
	*ok = 1;
	return (addr);
}

static int
toa_scope_fill(const char *s, struct toa_scope *out, int max, int *err)
{
	char buf[TOA_SCOPE_STR_MAX];
	char *cur, *tok, *slash;
	uint32_t ip, mask;
	int n, bits, ok;

	n = 0;
	*err = 0;
	strlcpy(buf, s, sizeof(buf));
	cur = buf;
	while ((tok = strsep(&cur, ",;")) != NULL) {
		if (*tok == '\0')
			continue;
		if (n >= max) {
			printf("TOA: too many scopes, max %d\n", max);
			*err = 1;
			return (n);
		}
		slash = strchr(tok, '/');
		if (slash == NULL) {
			printf("TOA: invalid scope entry \"%s\"\n", tok);
			*err = 1;
			return (n);
		}
		*slash = '\0';
		bits = strtol(slash + 1, NULL, 10);
		if (bits <= 0 || bits > 32) {
			printf("TOA: invalid mask \"%s\"\n", slash + 1);
			*err = 1;
			return (n);
		}
		ip = toa_in_aton(tok, &ok);
		if (ok == 0) {
			printf("TOA: invalid ip \"%s\"\n", tok);
			*err = 1;
			return (n);
		}
		mask = bits == 32 ? 0xffffffffu : ~((1u << (32 - bits)) - 1);
		out[n].begin = ip & mask;
		out[n].end = ip | ~mask;
		n++;
	}
	return (n);
}

int
toa_scope_parse(const char *s)
{
	struct toa_scope tmp[TOA_MAX_SCOPE];
	int n, err;

	n = toa_scope_fill(s, tmp, TOA_MAX_SCOPE, &err);
	if (err != 0)
		return (-1);		/* toa_nscope / toa_scopes unchanged */
	memcpy(toa_scopes, tmp, sizeof(toa_scopes));
	toa_nscope = n;
	strlcpy(toa_scope_str, s, sizeof(toa_scope_str));
	return (0);
}

int
toa_in_scope(uint32_t saddr)
{
	int i;

	if (toa_nscope == 0)
		return (1);
	for (i = 0; i < toa_nscope; i++) {
		if (saddr >= toa_scopes[i].begin && saddr <= toa_scopes[i].end)
			return (1);
	}
	return (0);
}

uint32_t
toa_hash(uint32_t faddr, uint16_t fport, uint32_t laddr, uint16_t lport)
{
	uint32_t h;

	h = faddr ^ laddr ^ ((uint32_t)fport << 16) ^ (uint32_t)lport;
	h ^= h >> 16;
	h *= 0x85ebca6bU;
	h ^= h >> 13;
	h *= 0xc2b2ae35U;
	h ^= h >> 16;
	return (h & (TOA_HASH_SIZE - 1));
}

int
toa_find_toa(const uint8_t *ptr, int length, struct toa_data *out)
{
	struct toa_data tdata;
	int opcode, opsize, toa_lay = -1;

	while (length > 0) {
		opcode = *ptr++;
		switch (opcode) {
		case TCPOPT_EOL:
			length = 0;	/* end of options; keep seen TOA */
			continue;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return (-1);
			if (opcode == TCPOPT_TOA && opsize == TCPOLEN_TOA) {
				toa_lay++;
				if (toa_lay >= 3)
					return (-1);
				memcpy(&tdata, ptr - 2, sizeof(tdata));
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
	if (toa_lay != -1) {
		memcpy(out, &tdata, sizeof(*out));
		return (0);
	}
	return (-1);
}
