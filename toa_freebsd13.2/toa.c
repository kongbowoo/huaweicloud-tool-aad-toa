/*-
 * TOA (TCP Option Address) support for FreeBSD 13.2
 *
 * FreeBSD port of the huaweicloud-tool-aad-toa Linux kernel module.
 * Parses the real client {IP, Port} carried in TCP option (opcode 254)
 * inserted by the AAD/LVS FULLNAT proxy on SYN packets, and serves it
 * back through getpeername().
 *
 * Implementation map (Linux -> FreeBSD):
 *   get_toa_data()/skb parse   -> pfil(9) inbound IPv4 hook, mbuf parse
 *   tcp_v4_syn_recv_sock hook  -> five-tuple hash table filled from the hook
 *   inet_getname hook          -> replace tcp_usrreqs.pru_peeraddr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/counter.h>
#include <sys/rmlock.h>
#include <sys/callout.h>
#include <sys/atomic.h>

#include <net/if.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet6/in6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in_pcb.h>
#include <netinet/in_pcb_var.h>
#include <netinet/tcp_var.h>

VNET_DECLARE(struct pfil_head, inet_pfil_head);
#define	V_inet_pfil_head	VNET(inet_pfil_head)

/* ---- TOA protocol constants (must match the proxy side / Linux toa.h) ---- */

#define TCPOPT_TOA	254
#define TCPOLEN_TOA	8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

struct toa_data {
	uint8_t		opcode;
	uint8_t		opsize;
	uint16_t	port;		/* network byte order */
	uint32_t	ip;		/* network byte order */
};

_Static_assert(sizeof(struct toa_data) == 8, "toa_data must be 8 bytes");

/* ---- tunables ---- */

#define TOA_HASH_SIZE		1024	/* power of two */
#define TOA_MAX_ENTRIES		65536
#define TOA_ENTRY_TTL		300	/* seconds */
#define TOA_GC_INTERVAL		60	/* seconds */
#define TOA_MAX_SCOPE		5
#define TOA_SCOPE_STR_MAX	256

static char	toa_scope_boot[TOA_SCOPE_STR_MAX];
TUNABLE_STR_FETCH("toa.scope", toa_scope_boot, sizeof(toa_scope_boot));

static char	toa_scope_str[TOA_SCOPE_STR_MAX];

/* ---- real-address cache ---- */

struct toa_entry {
	uint32_t		faddr;		/* proxy src ip (net order) */
	uint32_t		laddr;		/* local dst ip (net order) */
	uint16_t		fport;		/* net order */
	uint16_t		lport;		/* net order */
	struct toa_data		data;		/* real client ip/port */
	time_t			ts;
	LIST_ENTRY(toa_entry)	chain;
};

LIST_HEAD(toa_bucket, toa_entry);

static struct toa_bucket	*toa_buckets;
static struct rmlock		toa_rm;
static struct callout		toa_gc_callout;
static volatile int		toa_nentries;

/* source address scope, protected by toa_rm */
struct toa_scope {
	uint32_t		begin;		/* host order */
	uint32_t		end;		/* host order */
};

static struct toa_scope	toa_scopes[TOA_MAX_SCOPE];
static int		toa_nscope;

/* ---- statistics ---- */

static counter_u64_t	toa_stat_syn_toa;
static counter_u64_t	toa_stat_syn_no_toa;
static counter_u64_t	toa_stat_syn_out_of_scope;
static counter_u64_t	toa_stat_getname_ok;
static counter_u64_t	toa_stat_getname_miss;
static counter_u64_t	toa_stat_table_full;

/* ---- original pru_peeraddr saved at load time ---- */

extern struct pr_usrreqs	tcp_usrreqs;	/* netinet/tcp_usrreq.c */

static int (*toa_orig_peeraddr)(struct socket *so, struct sockaddr **nam);

static MALLOC_DEFINE(M_TOA, "toa", "TOA real client address cache");

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static uint32_t
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

/* parse "a.b.c.d/nn,a.b.c.d/nn..." into toa_scopes[], caller holds rm_wlock */
static int
toa_scope_parse(const char *s)
{
	char buf[TOA_SCOPE_STR_MAX];
	char echo[TOA_SCOPE_STR_MAX];
	char *cur, *tok, *slash;
	uint32_t ip, mask;
	int n, bits, ok;

	n = 0;
	strlcpy(buf, s, sizeof(buf));
	strlcpy(echo, s, sizeof(echo));
	cur = buf;
	while ((tok = strsep(&cur, ",;")) != NULL) {
		if (*tok == '\0')
			continue;
		if (n >= TOA_MAX_SCOPE) {
			printf("TOA: too many scopes, max %d\n", TOA_MAX_SCOPE);
			return (-1);
		}
		slash = strchr(tok, '/');
		if (slash == NULL) {
			printf("TOA: invalid scope entry \"%s\"\n", tok);
			return (-1);
		}
		*slash = '\0';
		bits = strtol(slash + 1, NULL, 10);
		if (bits <= 0 || bits > 32) {
			printf("TOA: invalid mask \"%s\"\n", slash + 1);
			return (-1);
		}
		ip = ntohl(toa_in_aton(tok, &ok));
		if (ok == 0) {
			printf("TOA: invalid ip \"%s\"\n", tok);
			return (-1);
		}
		mask = bits == 32 ? 0xffffffffu : ~((1u << (32 - bits)) - 1);
		toa_scopes[n].begin = ip & mask;
		toa_scopes[n].end = ip | ~mask;
		n++;
	}
	toa_nscope = n;
	strlcpy(toa_scope_str, echo, sizeof(toa_scope_str));
	return (0);
}

/* ------------------------------------------------------------------ */
/* real-address hash table                                             */
/* ------------------------------------------------------------------ */

static uint32_t
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

static struct toa_entry *
toa_lookup(uint32_t faddr, uint16_t fport, uint32_t laddr, uint16_t lport)
{
	struct toa_bucket *b;
	struct toa_entry *e;

	b = &toa_buckets[toa_hash(faddr, fport, laddr, lport)];
	LIST_FOREACH(e, b, chain) {
		if (e->faddr == faddr && e->fport == fport &&
		    e->laddr == laddr && e->lport == lport)
			return (e);
	}
	return (NULL);
}

static void
toa_insert(uint32_t faddr, uint16_t fport, uint32_t laddr, uint16_t lport,
    const struct toa_data *data)
{
	struct toa_bucket *b;
	struct toa_entry *e;

	b = &toa_buckets[toa_hash(faddr, fport, laddr, lport)];
	e = toa_lookup(faddr, fport, laddr, lport);
	if (e != NULL) {
		e->data = *data;
		e->ts = time_uptime;
		return;
	}
	if (atomic_fetchadd_int(&toa_nentries, 1) >= TOA_MAX_ENTRIES) {
		atomic_subtract_int(&toa_nentries, 1);
		counter_u64_add(toa_stat_table_full, 1);
		return;
	}
	e = malloc(sizeof(*e), M_TOA, M_NOWAIT | M_ZERO);
	if (e == NULL) {
		atomic_subtract_int(&toa_nentries, 1);
		return;
	}
	e->faddr = faddr;
	e->fport = fport;
	e->laddr = laddr;
	e->lport = lport;
	e->data = *data;
	e->ts = time_uptime;
	LIST_INSERT_HEAD(b, e, chain);
}

static void
toa_table_drain(void)
{
	struct toa_entry *e, *tmp;
	int i;

	for (i = 0; i < TOA_HASH_SIZE; i++) {
		LIST_FOREACH_SAFE(e, &toa_buckets[i], chain, tmp) {
			LIST_REMOVE(e, chain);
			atomic_subtract_int(&toa_nentries, 1);
			free(e, M_TOA);
		}
	}
}

static void
toa_gc(void *arg __unused)
{
	struct toa_entry *e, *tmp;
	int i;

	rm_wlock(&toa_rm);
	for (i = 0; i < TOA_HASH_SIZE; i++) {
		LIST_FOREACH_SAFE(e, &toa_buckets[i], chain, tmp) {
			if (time_uptime - e->ts > TOA_ENTRY_TTL) {
				LIST_REMOVE(e, chain);
				atomic_subtract_int(&toa_nentries, 1);
				free(e, M_TOA);
			}
		}
	}
	rm_wunlock(&toa_rm);
	callout_reset(&toa_gc_callout, TOA_GC_INTERVAL * hz, toa_gc, NULL);
}

/* ------------------------------------------------------------------ */
/* pfil hook: parse TOA option from inbound SYN                        */
/* ------------------------------------------------------------------ */

static int
toa_find_toa(const uint8_t *ptr, int length, struct toa_data *out)
{
	struct toa_data tdata;
	int opcode, opsize, toa_lay = -1;

	while (length > 0) {
		opcode = *ptr++;
		switch (opcode) {
		case TCPOPT_EOL:
			return (-1);
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

static int
toa_pfil(void *arg __unused, struct mbuf **mp, struct ifnet *ifp __unused,
    int dir, void *inp __unused)
{
	struct mbuf *m = *mp;
	struct ip *ip;
	struct tcphdr *th;
	struct toa_data tdata;
	int hlen, thlen;

	if (dir != PFIL_IN)
		return (PFIL_PASS);
	if (m->m_pkthdr.len < sizeof(struct ip) + sizeof(struct tcphdr))
		return (PFIL_PASS);
	ip = mtod(m, struct ip *);
	if (ip->ip_v != IPVERSION || ip->ip_p != IPPROTO_TCP)
		return (PFIL_PASS);
	if ((ntohs(ip->ip_off) & IP_OFFMASK) != 0)
		return (PFIL_PASS);	/* non-first fragment */
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip))
		return (PFIL_PASS);
	if (m->m_len < hlen + sizeof(struct tcphdr))
		return (PFIL_PASS);
	th = (struct tcphdr *)((char *)ip + hlen);
	if ((th->th_flags & (TH_SYN | TH_ACK)) != TH_SYN)
		return (PFIL_PASS);
	thlen = th->th_off << 2;
	if (thlen < sizeof(struct tcphdr))
		return (PFIL_PASS);
	if (m->m_len < hlen + thlen)
		return (PFIL_PASS);	/* tcp options not linear, give up */
	if (toa_in_scope(ntohl(ip->ip_src.s_addr)) == 0) {
		counter_u64_add(toa_stat_syn_out_of_scope, 1);
		return (PFIL_PASS);
	}
	if (toa_find_toa((const uint8_t *)th + sizeof(struct tcphdr),
	    thlen - sizeof(struct tcphdr), &tdata) != 0) {
		counter_u64_add(toa_stat_syn_no_toa, 1);
		return (PFIL_PASS);
	}
	rm_wlock(&toa_rm);
	toa_insert(ip->ip_src.s_addr, th->th_sport,
	    ip->ip_dst.s_addr, th->th_dport, &tdata);
	rm_wunlock(&toa_rm);
	counter_u64_add(toa_stat_syn_toa, 1);
	return (PFIL_PASS);
}

/* ------------------------------------------------------------------ */
/* pru_peeraddr replacement                                            */
/* ------------------------------------------------------------------ */

static int
toa_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct rm_priotracker pt;
	struct toa_entry *e;
	struct inpcb *inp;
	int err;

	err = toa_orig_peeraddr(so, nam);
	if (err != 0 || *nam == NULL)
		return (err);
	inp = sotoinpcb(so);
	if (inp == NULL)
		return (err);

	rm_rlock(&toa_rm, &pt);
	e = toa_lookup(inp->inp_faddr.s_addr, inp->inp_fport,
	    inp->inp_laddr.s_addr, inp->inp_lport);
	if (e != NULL && (*nam)->sa_family == AF_INET) {
		sin = (struct sockaddr_in *)*nam;
		sin->sin_addr.s_addr = e->data.ip;
		sin->sin_port = e->data.port;
		counter_u64_add(toa_stat_getname_ok, 1);
	} else if (e != NULL && (*nam)->sa_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)*nam;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			sin6->sin6_addr.s6_addr32[3] = e->data.ip;
			sin6->sin6_port = e->data.port;
			counter_u64_add(toa_stat_getname_ok, 1);
		} else {
			counter_u64_add(toa_stat_getname_miss, 1);
		}
	} else {
		counter_u64_add(toa_stat_getname_miss, 1);
	}
	rm_runlock(&toa_rm, &pt);
	return (err);
}

/* ------------------------------------------------------------------ */
/* sysctl                                                              */
/* ------------------------------------------------------------------ */

static SYSCTL_NODE(_net_inet, OID_AUTO, toa,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "TOA subsystem");

SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, syn_recv_sock_toa,
    CTLFLAG_RD, &toa_stat_syn_toa, "SYN packets carrying TOA data");
SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, syn_recv_sock_no_toa,
    CTLFLAG_RD, &toa_stat_syn_no_toa, "in-scope SYN packets without TOA data");
SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, syn_recv_not_in_scope,
    CTLFLAG_RD, &toa_stat_syn_out_of_scope, "SYN packets out of scope");
SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, getname_toa_ok,
    CTLFLAG_RD, &toa_stat_getname_ok, "getpeername served real address");
SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, getname_toa_miss,
    CTLFLAG_RD, &toa_stat_getname_miss, "getpeername with no cached entry");
SYSCTL_COUNTER_U64(_net_inet_toa, OID_AUTO, table_full,
    CTLFLAG_RD, &toa_stat_table_full, "inserts dropped due to full table");
SYSCTL_INT(_net_inet_toa, OID_AUTO, table_entries,
    CTLFLAG_RD, &toa_nentries, 0, "current number of cached entries");

static int
toa_sysctl_scope(SYSCTL_HANDLER_ARGS)
{
	char buf[TOA_SCOPE_STR_MAX];
	int error;

	rm_wlock(&toa_rm);
	strlcpy(buf, toa_scope_str, sizeof(buf));
	rm_wunlock(&toa_rm);
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	rm_wlock(&toa_rm);
	error = toa_scope_parse(buf) == 0 ? 0 : EINVAL;
	rm_wunlock(&toa_rm);
	return (error);
}

SYSCTL_PROC(_net_inet_toa, OID_AUTO, scope,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0, toa_sysctl_scope,
    "A", "source address scopes \"a.b.c.d/nn,...\" (empty = accept all)");

/* ------------------------------------------------------------------ */
/* module                                                              */
/* ------------------------------------------------------------------ */

static int
toa_modevent(module_t mod, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		toa_stat_syn_toa = counter_u64_alloc(M_WAITOK);
		toa_stat_syn_no_toa = counter_u64_alloc(M_WAITOK);
		toa_stat_syn_out_of_scope = counter_u64_alloc(M_WAITOK);
		toa_stat_getname_ok = counter_u64_alloc(M_WAITOK);
		toa_stat_getname_miss = counter_u64_alloc(M_WAITOK);
		toa_stat_table_full = counter_u64_alloc(M_WAITOK);
		toa_buckets = malloc(sizeof(struct toa_bucket) * TOA_HASH_SIZE,
		    M_TOA, M_WAITOK | M_ZERO);
		rm_init(&toa_rm, "toa");
		callout_init(&toa_gc_callout, 1);

		rm_wlock(&toa_rm);
		toa_scope_parse(toa_scope_boot);
		rm_wunlock(&toa_rm);

		toa_orig_peeraddr = tcp_usrreqs.pru_peeraddr;
		tcp_usrreqs.pru_peeraddr = toa_peeraddr;

		pfil_add_hook(toa_pfil, NULL, PFIL_IN | PFIL_WAITOK,
		    V_inet_pfil_head);

		callout_reset(&toa_gc_callout, TOA_GC_INTERVAL * hz, toa_gc, NULL);
		printf("TOA: loaded, version 1.0.0.1 (FreeBSD 13.2 port)\n");
		break;

	case MOD_UNLOAD:
		callout_drain(&toa_gc_callout);
		pfil_remove_hook(toa_pfil, NULL, PFIL_IN | PFIL_WAITOK,
		    V_inet_pfil_head);
		tcp_usrreqs.pru_peeraddr = toa_orig_peeraddr;

		rm_wlock(&toa_rm);
		toa_table_drain();
		rm_wunlock(&toa_rm);

		rm_destroy(&toa_rm);
		free(toa_buckets, M_TOA);
		counter_u64_free(toa_stat_syn_toa);
		counter_u64_free(toa_stat_syn_no_toa);
		counter_u64_free(toa_stat_syn_out_of_scope);
		counter_u64_free(toa_stat_getname_ok);
		counter_u64_free(toa_stat_getname_miss);
		counter_u64_free(toa_stat_table_full);
		printf("TOA: unloaded\n");
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static moduledata_t toa_moddata = {
	"toa",
	toa_modevent,
	NULL
};

DECLARE_MODULE(toa, toa_moddata, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_MIDDLE);
MODULE_VERSION(toa, 1);
MODULE_DEPEND(toa, inet, 1, 1, 1);
