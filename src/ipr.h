/* ipr.h */

#include "postgres.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "fmgr.h"
#include "funcapi.h"

#include "access/gist.h"
#include "access/hash.h"
#include "access/skey.h"
#include "libpq/pqformat.h"
#include "utils/builtins.h"
#include "utils/elog.h"
#include "utils/inet.h"
#include "utils/numeric.h"
#include "utils/varbit.h"
#include "utils/palloc.h"

#if !defined(PG_VERSION_NUM)
#error "Unknown or unsupported postgresql version"
#endif
#if PG_VERSION_NUM < 80400
#error "Unknown or unsupported postgresql version"
#endif

bool ip4_raw_input(const char *src, uint32 *dst);
bool ip6_raw_input(const char *src, uint64 *dst);
int ip4_raw_output(uint32 ip, char *str, int len);
int ip6_raw_output(uint64 *ip, char *str, int len);

/* IP4 = uint32, stored in host-order. fixed-length and pass by value. */
typedef uint32 IP4;

#define IP4_INITIALIZER 0

/* IP4R = range of IP4, stored in host-order. fixed-length by reference */
typedef struct IP4R {
    IP4 lower;
    IP4 upper;
} IP4R;

#define IP4R_INITIALIZER {0,0}

/*
 * IP6 = 2 x uint64, stored hi to lo, each stored in host-order.
 * fixed-length and pass by reference.
 */

typedef struct IP6 {
    uint64 bits[2];
} IP6;

#define IP6_INITIALIZER {{0,0}}

/* IP6R = range of IP6. fixed-length by reference */
typedef struct IP6R {
    IP6 lower;
    IP6 upper;
} IP6R;

#define IP6R_INITIALIZER {IP6_INITIALIZER,IP6_INITIALIZER}

#define IP6_STRING_MAX (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+2)
#define IP6R_STRING_MAX (2*IP6_STRING_MAX)

#define IP4_STRING_MAX (sizeof("255.255.255.255"))
#define IP4R_STRING_MAX (2*IP4_STRING_MAX)

typedef union IP {
	IP6 ip6;
	IP4 ip4;
} IP;

#define IP_INITIALIZER {IP6_INITIALIZER}

#define ipr_af_maxbits(af_) ((af_) == PGSQL_AF_INET ? 32 : 128)
#define ip_sizeof(af_) ((af_) == PGSQL_AF_INET ? sizeof(IP4) : sizeof(IP6))
#define ipr_sizeof(af_) ((af_) == PGSQL_AF_INET ? sizeof(IP4R) : sizeof(IP6R))

typedef void *IP_P;  /* unaligned! */

void ipaddr_internal_error(void) __attribute__((noreturn));

static inline
int ip_unpack(IP_P in, IP *out)
{
    switch (VARSIZE_ANY_EXHDR(in))
    {
        case sizeof(IP4):
            memcpy(&out->ip4, VARDATA_ANY(in), sizeof(IP4));
            return PGSQL_AF_INET;
        case sizeof(IP6):
            memcpy(&out->ip6, VARDATA_ANY(in), sizeof(IP6));
            return PGSQL_AF_INET6;
        default:
			ipaddr_internal_error();
    }
}

static inline
IP_P ip_pack(int af, IP *val)
{
	int sz = ip_sizeof(af);
    IP_P out = palloc(VARHDRSZ + sz);

	SET_VARSIZE(out, VARHDRSZ + sz);
	memcpy(VARDATA(out), val, sz);
	return out;
}

typedef union IPR {
	IP6R ip6r;
	IP4R ip4r;
} IPR;

#define IPR_INITIALIZER {IP6R_INITIALIZER}

typedef void *IPR_P;  /* unaligned! */

#define DatumGetIP4RP(X)	((IP4R *) DatumGetPointer(X))
#define IP4RPGetDatum(X)	PointerGetDatum(X)
#define PG_GETARG_IP4R_P(n) DatumGetIP4RP(PG_GETARG_DATUM(n))
#define PG_RETURN_IP4R_P(x) return IP4RPGetDatum(x)

#define DatumGetIP4(X) DatumGetUInt32(X)
#define IP4GetDatum(X) UInt32GetDatum(X)
#define PG_GETARG_IP4(n) PG_GETARG_UINT32(n)
#define PG_RETURN_IP4(x) PG_RETURN_UINT32(x)

#define DatumGetIP6RP(X)	((IP6R *) DatumGetPointer(X))
#define IP6RPGetDatum(X)	PointerGetDatum(X)
#define PG_GETARG_IP6R_P(n) DatumGetIP6RP(PG_GETARG_DATUM(n))
#define PG_RETURN_IP6R_P(x) return IP6RPGetDatum(x)

#define DatumGetIP6P(X)	((IP6 *) DatumGetPointer(X))
#define IP6PGetDatum(X)	PointerGetDatum(X)
#define PG_GETARG_IP6_P(n) DatumGetIP6P(PG_GETARG_DATUM(n))
#define PG_RETURN_IP6_P(x) return IP6PGetDatum(x)

#define DatumGetIP_P(X) ((IP_P) PG_DETOAST_DATUM_PACKED(X))
#define IP_PGetDatum(X) PointerGetDatum(X)
#define PG_GETARG_IP_P(n) DatumGetIP_P(PG_GETARG_DATUM(n))
#define PG_RETURN_IP_P(x) return IP_PGetDatum(x)

#define DatumGetIPR_P(X) ((IP_P) PG_DETOAST_DATUM_PACKED(X))
#define IPR_PGetDatum(X) PointerGetDatum(X)
#define PG_GETARG_IPR_P(n) DatumGetIPR_P(PG_GETARG_DATUM(n))
#define PG_RETURN_IPR_P(x) return IPR_PGetDatum(x)

/* PG version dependencies */

#define INET_STRUCT_DATA(is_) ((inet_struct *)VARDATA_ANY(is_))

#define GISTENTRYCOUNT(v) ((v)->n)
#define GISTENTRYVEC(v) ((v)->vector)

/* hash_any_extended is new in pg11. On older pg, we don't care about what the
 * extended hash functions return, so just fake it.
 */

#if PG_VERSION_NUM < 110000

#ifndef ERRCODE_INVALID_PRECEDING_OR_FOLLOWING_SIZE
#define ERRCODE_INVALID_PRECEDING_OR_FOLLOWING_SIZE MAKE_SQLSTATE('2','2','0','1','3')
#endif

#ifndef DatumGetUInt64
#define DatumGetUInt64(d_) ((uint64) DatumGetInt64(d_))
#endif

static inline
Datum hash_any_extended(register const unsigned char *k,
						register int keylen, uint64 seed)
{
	Datum d = hash_any(k, keylen);
	PG_RETURN_INT64((int64)(uint32) DatumGetInt32(d));
}

#endif

/* funcs */

Datum ip4_in(PG_FUNCTION_ARGS);
Datum ip4_out(PG_FUNCTION_ARGS);
Datum ip4_recv(PG_FUNCTION_ARGS);
Datum ip4_send(PG_FUNCTION_ARGS);
Datum ip4hash(PG_FUNCTION_ARGS);
Datum ip4_hash_extended(PG_FUNCTION_ARGS);
Datum ip4_cast_to_text(PG_FUNCTION_ARGS);
Datum ip4_cast_from_text(PG_FUNCTION_ARGS);
Datum ip4_cast_from_bit(PG_FUNCTION_ARGS);
Datum ip4_cast_to_bit(PG_FUNCTION_ARGS);
Datum ip4_cast_from_bytea(PG_FUNCTION_ARGS);
Datum ip4_cast_to_bytea(PG_FUNCTION_ARGS);
Datum ip4_cast_from_inet(PG_FUNCTION_ARGS);
Datum ip4_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ip4_cast_to_bigint(PG_FUNCTION_ARGS);
Datum ip4_cast_to_numeric(PG_FUNCTION_ARGS);
Datum ip4_cast_from_bigint(PG_FUNCTION_ARGS);
Datum ip4_cast_from_numeric(PG_FUNCTION_ARGS);
Datum ip4_cast_to_double(PG_FUNCTION_ARGS);
Datum ip4_cast_from_double(PG_FUNCTION_ARGS);
Datum ip4r_in(PG_FUNCTION_ARGS);
Datum ip4r_out(PG_FUNCTION_ARGS);
Datum ip4r_recv(PG_FUNCTION_ARGS);
Datum ip4r_send(PG_FUNCTION_ARGS);
Datum ip4rhash(PG_FUNCTION_ARGS);
Datum ip4r_hash_extended(PG_FUNCTION_ARGS);
Datum ip4r_cast_to_text(PG_FUNCTION_ARGS);
Datum ip4r_cast_from_text(PG_FUNCTION_ARGS);
Datum ip4r_cast_from_bit(PG_FUNCTION_ARGS);
Datum ip4r_cast_to_bit(PG_FUNCTION_ARGS);
Datum ip4r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum ip4r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ip4r_cast_from_ip4(PG_FUNCTION_ARGS);
Datum ip4r_from_ip4s(PG_FUNCTION_ARGS);
Datum ip4r_net_prefix(PG_FUNCTION_ARGS);
Datum ip4r_net_mask(PG_FUNCTION_ARGS);
Datum ip4r_lower(PG_FUNCTION_ARGS);
Datum ip4r_upper(PG_FUNCTION_ARGS);
Datum ip4r_is_cidr(PG_FUNCTION_ARGS);
Datum ip4r_cidr_split(PG_FUNCTION_ARGS);
Datum ip4_netmask(PG_FUNCTION_ARGS);
Datum ip4_net_lower(PG_FUNCTION_ARGS);
Datum ip4_net_upper(PG_FUNCTION_ARGS);
Datum ip4_plus_int(PG_FUNCTION_ARGS);
Datum ip4_plus_bigint(PG_FUNCTION_ARGS);
Datum ip4_plus_numeric(PG_FUNCTION_ARGS);
Datum ip4_minus_int(PG_FUNCTION_ARGS);
Datum ip4_minus_bigint(PG_FUNCTION_ARGS);
Datum ip4_minus_numeric(PG_FUNCTION_ARGS);
Datum ip4_minus_ip4(PG_FUNCTION_ARGS);
Datum ip4_and(PG_FUNCTION_ARGS);
Datum ip4_or(PG_FUNCTION_ARGS);
Datum ip4_xor(PG_FUNCTION_ARGS);
Datum ip4_not(PG_FUNCTION_ARGS);
Datum ip4_lt(PG_FUNCTION_ARGS);
Datum ip4_le(PG_FUNCTION_ARGS);
Datum ip4_gt(PG_FUNCTION_ARGS);
Datum ip4_ge(PG_FUNCTION_ARGS);
Datum ip4_eq(PG_FUNCTION_ARGS);
Datum ip4_neq(PG_FUNCTION_ARGS);
Datum ip4r_lt(PG_FUNCTION_ARGS);
Datum ip4r_le(PG_FUNCTION_ARGS);
Datum ip4r_gt(PG_FUNCTION_ARGS);
Datum ip4r_ge(PG_FUNCTION_ARGS);
Datum ip4r_eq(PG_FUNCTION_ARGS);
Datum ip4r_neq(PG_FUNCTION_ARGS);
Datum ip4r_overlaps(PG_FUNCTION_ARGS);
Datum ip4r_contains(PG_FUNCTION_ARGS);
Datum ip4r_contains_strict(PG_FUNCTION_ARGS);
Datum ip4r_contained_by(PG_FUNCTION_ARGS);
Datum ip4r_contained_by_strict(PG_FUNCTION_ARGS);
Datum ip4_contains(PG_FUNCTION_ARGS);
Datum ip4_contained_by(PG_FUNCTION_ARGS);
Datum ip4r_union(PG_FUNCTION_ARGS);
Datum ip4r_inter(PG_FUNCTION_ARGS);
Datum ip4r_size(PG_FUNCTION_ARGS);
Datum ip4r_size_exact(PG_FUNCTION_ARGS);
Datum ip4r_prefixlen(PG_FUNCTION_ARGS);
Datum ip4r_cmp(PG_FUNCTION_ARGS);
Datum ip4_cmp(PG_FUNCTION_ARGS);
Datum ip4_in_range_bigint(PG_FUNCTION_ARGS);
Datum ip4_in_range_ip4(PG_FUNCTION_ARGS);
Datum ip4r_left_of(PG_FUNCTION_ARGS);
Datum ip4r_right_of(PG_FUNCTION_ARGS);

Datum ip6_in(PG_FUNCTION_ARGS);
Datum ip6_out(PG_FUNCTION_ARGS);
Datum ip6_recv(PG_FUNCTION_ARGS);
Datum ip6_send(PG_FUNCTION_ARGS);
Datum ip6hash(PG_FUNCTION_ARGS);
Datum ip6_hash_extended(PG_FUNCTION_ARGS);
Datum ip6_cast_to_text(PG_FUNCTION_ARGS);
Datum ip6_cast_from_text(PG_FUNCTION_ARGS);
Datum ip6_cast_from_bit(PG_FUNCTION_ARGS);
Datum ip6_cast_to_bit(PG_FUNCTION_ARGS);
Datum ip6_cast_from_bytea(PG_FUNCTION_ARGS);
Datum ip6_cast_to_bytea(PG_FUNCTION_ARGS);
Datum ip6_cast_from_inet(PG_FUNCTION_ARGS);
Datum ip6_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ip6_cast_to_numeric(PG_FUNCTION_ARGS);
Datum ip6_cast_from_numeric(PG_FUNCTION_ARGS);
Datum ip6r_in(PG_FUNCTION_ARGS);
Datum ip6r_out(PG_FUNCTION_ARGS);
Datum ip6r_recv(PG_FUNCTION_ARGS);
Datum ip6r_send(PG_FUNCTION_ARGS);
Datum ip6rhash(PG_FUNCTION_ARGS);
Datum ip6r_hash_extended(PG_FUNCTION_ARGS);
Datum ip6r_cast_to_text(PG_FUNCTION_ARGS);
Datum ip6r_cast_from_text(PG_FUNCTION_ARGS);
Datum ip6r_cast_from_bit(PG_FUNCTION_ARGS);
Datum ip6r_cast_to_bit(PG_FUNCTION_ARGS);
Datum ip6r_cast_from_cidr(PG_FUNCTION_ARGS);
Datum ip6r_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ip6r_cast_from_ip6(PG_FUNCTION_ARGS);
Datum ip6r_from_ip6s(PG_FUNCTION_ARGS);
Datum ip6r_net_prefix(PG_FUNCTION_ARGS);
Datum ip6r_net_mask(PG_FUNCTION_ARGS);
Datum ip6r_lower(PG_FUNCTION_ARGS);
Datum ip6r_upper(PG_FUNCTION_ARGS);
Datum ip6r_is_cidr(PG_FUNCTION_ARGS);
Datum ip6r_cidr_split(PG_FUNCTION_ARGS);
Datum ip6_netmask(PG_FUNCTION_ARGS);
Datum ip6_net_lower(PG_FUNCTION_ARGS);
Datum ip6_net_upper(PG_FUNCTION_ARGS);
Datum ip6_plus_int(PG_FUNCTION_ARGS);
Datum ip6_plus_bigint(PG_FUNCTION_ARGS);
Datum ip6_plus_numeric(PG_FUNCTION_ARGS);
Datum ip6_minus_int(PG_FUNCTION_ARGS);
Datum ip6_minus_bigint(PG_FUNCTION_ARGS);
Datum ip6_minus_numeric(PG_FUNCTION_ARGS);
Datum ip6_minus_ip6(PG_FUNCTION_ARGS);
Datum ip6_and(PG_FUNCTION_ARGS);
Datum ip6_or(PG_FUNCTION_ARGS);
Datum ip6_xor(PG_FUNCTION_ARGS);
Datum ip6_not(PG_FUNCTION_ARGS);
Datum ip6_lt(PG_FUNCTION_ARGS);
Datum ip6_le(PG_FUNCTION_ARGS);
Datum ip6_gt(PG_FUNCTION_ARGS);
Datum ip6_ge(PG_FUNCTION_ARGS);
Datum ip6_eq(PG_FUNCTION_ARGS);
Datum ip6_neq(PG_FUNCTION_ARGS);
Datum ip6r_lt(PG_FUNCTION_ARGS);
Datum ip6r_le(PG_FUNCTION_ARGS);
Datum ip6r_gt(PG_FUNCTION_ARGS);
Datum ip6r_ge(PG_FUNCTION_ARGS);
Datum ip6r_eq(PG_FUNCTION_ARGS);
Datum ip6r_neq(PG_FUNCTION_ARGS);
Datum ip6r_overlaps(PG_FUNCTION_ARGS);
Datum ip6r_contains(PG_FUNCTION_ARGS);
Datum ip6r_contains_strict(PG_FUNCTION_ARGS);
Datum ip6r_contained_by(PG_FUNCTION_ARGS);
Datum ip6r_contained_by_strict(PG_FUNCTION_ARGS);
Datum ip6_contains(PG_FUNCTION_ARGS);
Datum ip6_contained_by(PG_FUNCTION_ARGS);
Datum ip6r_union(PG_FUNCTION_ARGS);
Datum ip6r_inter(PG_FUNCTION_ARGS);
Datum ip6r_size(PG_FUNCTION_ARGS);
Datum ip6r_size_exact(PG_FUNCTION_ARGS);
Datum ip6r_prefixlen(PG_FUNCTION_ARGS);
Datum ip6r_cmp(PG_FUNCTION_ARGS);
Datum ip6_cmp(PG_FUNCTION_ARGS);
Datum ip6_in_range_bigint(PG_FUNCTION_ARGS);
Datum ip6_in_range_ip6(PG_FUNCTION_ARGS);
#if 0
Datum ip6_in_range_numeric(PG_FUNCTION_ARGS);
#endif
Datum ip6r_left_of(PG_FUNCTION_ARGS);
Datum ip6r_right_of(PG_FUNCTION_ARGS);

Datum ipaddr_in(PG_FUNCTION_ARGS);
Datum ipaddr_out(PG_FUNCTION_ARGS);
Datum ipaddr_recv(PG_FUNCTION_ARGS);
Datum ipaddr_send(PG_FUNCTION_ARGS);
Datum ipaddr_hash(PG_FUNCTION_ARGS);
Datum ipaddr_hash_extended(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_text(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_text(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_bit(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_bit(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_bytea(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_bytea(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_inet(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_cidr(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_numeric(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_ip4(PG_FUNCTION_ARGS);
Datum ipaddr_cast_from_ip6(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_ip4(PG_FUNCTION_ARGS);
Datum ipaddr_cast_to_ip6(PG_FUNCTION_ARGS);
Datum ipaddr_net_lower(PG_FUNCTION_ARGS);
Datum ipaddr_net_upper(PG_FUNCTION_ARGS);
Datum ipaddr_family(PG_FUNCTION_ARGS);
Datum ipaddr_plus_int(PG_FUNCTION_ARGS);
Datum ipaddr_plus_bigint(PG_FUNCTION_ARGS);
Datum ipaddr_plus_numeric(PG_FUNCTION_ARGS);
Datum ipaddr_minus_int(PG_FUNCTION_ARGS);
Datum ipaddr_minus_bigint(PG_FUNCTION_ARGS);
Datum ipaddr_minus_numeric(PG_FUNCTION_ARGS);
Datum ipaddr_minus_ipaddr(PG_FUNCTION_ARGS);
Datum ipaddr_and(PG_FUNCTION_ARGS);
Datum ipaddr_or(PG_FUNCTION_ARGS);
Datum ipaddr_xor(PG_FUNCTION_ARGS);
Datum ipaddr_not(PG_FUNCTION_ARGS);
Datum ipaddr_lt(PG_FUNCTION_ARGS);
Datum ipaddr_le(PG_FUNCTION_ARGS);
Datum ipaddr_gt(PG_FUNCTION_ARGS);
Datum ipaddr_ge(PG_FUNCTION_ARGS);
Datum ipaddr_eq(PG_FUNCTION_ARGS);
Datum ipaddr_neq(PG_FUNCTION_ARGS);
Datum ipaddr_cmp(PG_FUNCTION_ARGS);

Datum iprange_in(PG_FUNCTION_ARGS);
Datum iprange_out(PG_FUNCTION_ARGS);
Datum iprange_recv(PG_FUNCTION_ARGS);
Datum iprange_send(PG_FUNCTION_ARGS);
Datum iprange_hash(PG_FUNCTION_ARGS);
Datum iprange_hash_new(PG_FUNCTION_ARGS);
Datum iprange_hash_extended(PG_FUNCTION_ARGS);
Datum iprange_cast_to_text(PG_FUNCTION_ARGS);
Datum iprange_cast_from_text(PG_FUNCTION_ARGS);
Datum iprange_cast_from_cidr(PG_FUNCTION_ARGS);
Datum iprange_cast_to_cidr(PG_FUNCTION_ARGS);
Datum iprange_cast_to_bit(PG_FUNCTION_ARGS);
Datum iprange_cast_from_ip4(PG_FUNCTION_ARGS);
Datum iprange_cast_from_ip6(PG_FUNCTION_ARGS);
Datum iprange_cast_from_ipaddr(PG_FUNCTION_ARGS);
Datum iprange_cast_from_ip4r(PG_FUNCTION_ARGS);
Datum iprange_cast_from_ip6r(PG_FUNCTION_ARGS);
Datum iprange_cast_to_ip4r(PG_FUNCTION_ARGS);
Datum iprange_cast_to_ip6r(PG_FUNCTION_ARGS);
Datum iprange_from_ip4s(PG_FUNCTION_ARGS);
Datum iprange_from_ip6s(PG_FUNCTION_ARGS);
Datum iprange_from_ipaddrs(PG_FUNCTION_ARGS);
Datum iprange_net_prefix_ip4(PG_FUNCTION_ARGS);
Datum iprange_net_prefix_ip6(PG_FUNCTION_ARGS);
Datum iprange_net_prefix(PG_FUNCTION_ARGS);
Datum iprange_net_mask_ip4(PG_FUNCTION_ARGS);
Datum iprange_net_mask_ip6(PG_FUNCTION_ARGS);
Datum iprange_net_mask(PG_FUNCTION_ARGS);
Datum iprange_lower(PG_FUNCTION_ARGS);
Datum iprange_upper(PG_FUNCTION_ARGS);
Datum iprange_is_cidr(PG_FUNCTION_ARGS);
Datum iprange_family(PG_FUNCTION_ARGS);
Datum iprange_cidr_split(PG_FUNCTION_ARGS);
Datum iprange_lt(PG_FUNCTION_ARGS);
Datum iprange_le(PG_FUNCTION_ARGS);
Datum iprange_gt(PG_FUNCTION_ARGS);
Datum iprange_ge(PG_FUNCTION_ARGS);
Datum iprange_eq(PG_FUNCTION_ARGS);
Datum iprange_neq(PG_FUNCTION_ARGS);
Datum iprange_overlaps(PG_FUNCTION_ARGS);
Datum iprange_contains(PG_FUNCTION_ARGS);
Datum iprange_contains_strict(PG_FUNCTION_ARGS);
Datum iprange_contained_by(PG_FUNCTION_ARGS);
Datum iprange_contained_by_strict(PG_FUNCTION_ARGS);
Datum iprange_contains_ip(PG_FUNCTION_ARGS);
Datum iprange_contains_ip4(PG_FUNCTION_ARGS);
Datum iprange_contains_ip6(PG_FUNCTION_ARGS);
Datum iprange_ip_contained_by(PG_FUNCTION_ARGS);
Datum iprange_ip4_contained_by(PG_FUNCTION_ARGS);
Datum iprange_ip6_contained_by(PG_FUNCTION_ARGS);
Datum iprange_union(PG_FUNCTION_ARGS);
Datum iprange_inter(PG_FUNCTION_ARGS);
Datum iprange_size(PG_FUNCTION_ARGS);
Datum iprange_size_exact(PG_FUNCTION_ARGS);
Datum iprange_prefixlen(PG_FUNCTION_ARGS);
Datum iprange_cmp(PG_FUNCTION_ARGS);

/* end */
