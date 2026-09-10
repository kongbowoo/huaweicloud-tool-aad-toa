/*
 * Userland unit tests for toa_core.c (pure logic layer of the TOA
 * FreeBSD kernel module).  Build and run with: make -C tests test
 */

#include "toa_ut_shim.h"

#include "../toa_core.h"

static int t_pass, t_fail;

static int mk_toa(uint8_t *b, uint32_t ip, uint16_t port);

#define CHECK(cond) do {						\
	if (cond) {							\
		t_pass++;						\
	} else {							\
		t_fail++;						\
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);	\
	}								\
} while (0)

/* value of a 4-byte on-wire IPv4 address copied into a uint32_t,
 * matching how toa_find_toa() copies option bytes into toa_data.ip */
static uint32_t
wire_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	uint8_t t[4] = { a, b, c, d };
	uint32_t v;

	memcpy(&v, t, 4);
	return (v);
}

static uint16_t
wire_port(uint8_t hi, uint8_t lo)
{
	uint8_t t[2] = { hi, lo };
	uint16_t v;

	memcpy(&v, t, 2);
	return (v);
}

static void
test_in_aton(void)
{
	int ok;

	CHECK(toa_in_aton("1.2.3.4", &ok) == 0x01020304u && ok == 1);
	CHECK(toa_in_aton("0.0.0.0", &ok) == 0u && ok == 1);
	CHECK(toa_in_aton("255.255.255.255", &ok) == 0xffffffffu && ok == 1);
	CHECK(toa_in_aton("10.0.0.1", &ok) == 0x0a000001u && ok == 1);

	CHECK(toa_in_aton("256.0.0.1", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("1.2.3", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("1.2.3.4.5", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("1..2.3", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("a.b.c.d", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("1.2.3.", &ok) == 0 && ok == 0);
	CHECK(toa_in_aton("", &ok) == 0 && ok == 0);
}

static void
test_scope(void)
{
	int ok;

	/* empty string = accept all */
	CHECK(toa_scope_parse("") == 0);
	CHECK(toa_nscope == 0);
	CHECK(toa_in_scope(0x0a010203u) == 1);
	CHECK(toa_in_scope(0xffffffffu) == 1);

	/* /8 */
	CHECK(toa_scope_parse("10.0.0.0/8") == 0);
	CHECK(toa_nscope == 1);
	CHECK(toa_scopes[0].begin == 0x0a000000u);
	CHECK(toa_scopes[0].end == 0x0affffffu);
	CHECK(toa_in_scope(0x0a010203u) == 1);
	CHECK(toa_in_scope(0x0affffffu) == 1);
	CHECK(toa_in_scope(0x0b000001u) == 0);

	/* /24 boundaries */
	CHECK(toa_scope_parse("192.168.1.0/24") == 0);
	CHECK(toa_in_scope(0xc0a80100u) == 1);
	CHECK(toa_in_scope(0xc0a801ffu) == 1);
	CHECK(toa_in_scope(0xc0a80200u) == 0);

	/* /32 */
	CHECK(toa_scope_parse("1.2.3.4/32") == 0);
	CHECK(toa_in_scope(0x01020304u) == 1);
	CHECK(toa_in_scope(0x01020305u) == 0);

	/* multiple entries */
	CHECK(toa_scope_parse("10.0.0.0/8,192.168.1.0/24") == 0);
	CHECK(toa_nscope == 2);
	CHECK(toa_in_scope(0x0a000001u) == 1);
	CHECK(toa_in_scope(0xc0a80101u) == 1);
	CHECK(toa_in_scope(0x0b000000u) == 0);

	/* echo keeps the full string */
	CHECK(strcmp(toa_scope_str, "10.0.0.0/8,192.168.1.0/24") == 0);

	/* errors leave the previous configuration intact */
	CHECK(toa_scope_parse("1.2.3.4/0") == -1);
	CHECK(toa_scope_parse("1.2.3.4/33") == -1);
	CHECK(toa_scope_parse("1.2.3.4") == -1);
	CHECK(toa_scope_parse("300.1.1.1/8") == -1);
	CHECK(toa_scope_parse("1.2.3.4/8,junk") == -1);
	CHECK(toa_nscope == 2);
	CHECK(toa_in_scope(0x0a000001u) == 1);

	/* more than TOA_MAX_SCOPE entries */
	CHECK(toa_scope_parse("10.0.0.0/8") == 0);
	CHECK(toa_scope_parse("1.1.1.0/24,2.2.2.0/24,3.3.3.0/24,"
	    "4.4.4.0/24,5.5.5.0/24,6.6.6.0/24") == -1);
	CHECK(toa_nscope == 1);

	(void)ok;
}

static void
test_find_toa(void)
{
	uint8_t b[64];
	struct toa_data out;
	uint32_t ip = wire_ip(1, 2, 3, 4);
	uint16_t port = wire_port(0x1f, 0x90);	/* 8080 */

	/* plain TOA option */
	memset(b, 0, sizeof(b));
	CHECK(mk_toa(b, ip, port) == 8);
	CHECK(toa_find_toa(b, 8, &out) == 0);
	CHECK(out.opcode == TCPOPT_TOA && out.opsize == TCPOLEN_TOA);
	CHECK(out.ip == ip && out.port == port);

	/* MSS + NOP + TOA */
	memset(b, 0, sizeof(b));
	b[0] = 2; b[1] = 4; b[2] = 0x05; b[3] = 0xb4;
	b[4] = 1; /* NOP */
	mk_toa(b + 5, ip, port);
	CHECK(toa_find_toa(b, 13, &out) == 0);
	CHECK(out.ip == ip && out.port == port);

	/* TOA followed by EOL and zero padding: EOL ends the scan but
	 * keeps the already-seen value */
	memset(b, 0, sizeof(b));
	mk_toa(b, ip, port);
	CHECK(toa_find_toa(b, 13, &out) == 0);
	CHECK(out.ip == ip && out.port == port);

	/* no options at all */
	CHECK(toa_find_toa(b, 0, &out) == -1);
	memset(b, 0, sizeof(b));
	b[0] = 1; b[1] = 1; b[2] = 1; b[3] = 1;
	CHECK(toa_find_toa(b, 4, &out) == -1);

	/* EOL before any option */
	memset(b, 0, sizeof(b));
	b[0] = 0; b[1] = 0;
	CHECK(toa_find_toa(b, 4, &out) == -1);

	/* silly option: opsize < 2 */
	memset(b, 0, sizeof(b));
	b[0] = TCPOPT_TOA; b[1] = 1;
	CHECK(toa_find_toa(b, 2, &out) == -1);

	/* opsize beyond the buffer */
	memset(b, 0, sizeof(b));
	b[0] = TCPOPT_TOA; b[1] = 9;
	CHECK(toa_find_toa(b, 2, &out) == -1);

	/* TOA opcode with wrong length is skipped, not matched */
	memset(b, 0, sizeof(b));
	b[0] = TCPOPT_TOA; b[1] = 7;
	b[7] = 0; b[8] = 0; b[9] = 0;
	CHECK(toa_find_toa(b, 7, &out) == -1);

	/* truncated TOA: opsize claims 8, only 6 bytes present */
	memset(b, 0, sizeof(b));
	b[0] = TCPOPT_TOA; b[1] = 8;
	CHECK(toa_find_toa(b, 6, &out) == -1);

	/* three stacked TOA options: last one wins */
	memset(b, 0, sizeof(b));
	mk_toa(b, wire_ip(9, 9, 9, 9), wire_port(0, 1));
	mk_toa(b + 8, wire_ip(9, 9, 9, 9), wire_port(0, 2));
	mk_toa(b + 16, ip, port);
	CHECK(toa_find_toa(b, 24, &out) == 0);
	CHECK(out.ip == ip && out.port == port);

	/* four stacked TOA options are rejected */
	memset(b, 0, sizeof(b));
	mk_toa(b, ip, port);
	mk_toa(b + 8, ip, port);
	mk_toa(b + 16, ip, port);
	mk_toa(b + 24, ip, port);
	CHECK(toa_find_toa(b, 32, &out) == -1);
}

static int
mk_toa(uint8_t *b, uint32_t ip, uint16_t port)
{
	uint8_t i[4], p[2];

	memcpy(i, &ip, 4);
	memcpy(p, &port, 2);
	b[0] = TCPOPT_TOA;
	b[1] = TCPOLEN_TOA;
	b[2] = p[0];
	b[3] = p[1];
	b[4] = i[0];
	b[5] = i[1];
	b[6] = i[2];
	b[7] = i[3];
	return (8);
}

static void
test_hash(void)
{
	uint32_t h1, h2, i, seen[TOA_HASH_SIZE];
	int distinct;

	h1 = toa_hash(0x0a000001u, 0x1f90, 0xc0a80101u, 0x0050);
	h2 = toa_hash(0x0a000001u, 0x1f90, 0xc0a80101u, 0x0050);
	CHECK(h1 == h2);
	CHECK(h1 < TOA_HASH_SIZE);

	/* distribution smoke test: 1000 sequential source addresses
	 * should spread over most of the 1024 buckets */
	memset(seen, 0, sizeof(seen));
	distinct = 0;
	for (i = 0; i < 1000; i++) {
		uint32_t h = toa_hash(0x0a000000u + i, 0x1f90,
		    0xc0a80101u, 0x0050);

		CHECK(h < TOA_HASH_SIZE);
		if (seen[h] == 0)
			distinct++;
		seen[h] = 1;
	}
	CHECK(distinct >= 550);
}

int
main(void)
{
	test_in_aton();
	test_scope();
	test_find_toa();
	test_hash();

	printf("UT: %d passed, %d failed\n", t_pass, t_fail);
	return (t_fail > 0 ? 1 : 0);
}
