/* $Id: ip6r_funcs.h,v 1.1 2011/08/03 20:16:03 andrewsn Exp $ */

/**************************************************************************/
/* This part is the internal implementation of all functionality, with no
 * reference to the interface with postgres. That part comes later and is
 * implemented in terms of these functions.
 */

static inline
uint64 hostmask6_hi(unsigned masklen)
{
    if (masklen >= 64)
        return 0;
    if (masklen == 0)
        return ~((uint64)0);
    return (((uint64)(1U)) << (64-masklen)) - 1U;
}

static inline
uint64 hostmask6_lo(unsigned masklen)
{
    if (masklen <= 64)
        return ~((uint64)0);
    return (((uint64)(1U)) << (128-masklen)) - 1U;
}

static inline
uint64 netmask6_hi(unsigned masklen)
{
    return ~hostmask6_hi(masklen);
}

static inline
uint64 netmask6_lo(unsigned masklen)
{
    return ~hostmask6_lo(masklen);
}

/* if LO and HI are ends of a CIDR prefix, return the mask length.
 * If not, returns ~0.
 */

static inline
unsigned masklen64(uint64 lo, uint64 hi, int offset)
{
    uint64 d = (lo ^ hi) + 1;
    int t = 0;
    int b;

    /* at this point, d can be:
     *  0 if A and B have all bits different
     *  1 if A and B are equal
     *  1 << (64-masklen)
     *  some other value if A and B are not ends of a CIDR range
     * but in any case, after extracting the masklen, we have to
     * recheck because some non-CIDR ranges will produce the same
     * results.
     */
    if (d == 0)
        return (lo == 0 && hi == ~((uint64)0)) ? offset : ~0;
    if (d == 1)
        return (lo == hi) ? 64+offset : ~0;

    if (!(d & 0xFFFFFFFFUL))
    {
        t = 32;
        d >>= 32;
    }

    b = ffs((uint32) d);
    if ((((uint32)1U) << (b-1)) != d)
        return ~0;

    {
        uint64 mask = ((uint64)(1U) << (t+b-1)) - 1U;
        if ((lo & mask) == 0 && (hi & mask) == mask)
            return 65-t-b + offset;
    }

    return ~0;
}

static inline
unsigned masklen6(IP6 *lo, IP6 *hi)
{
    if (lo->bits[0] == hi->bits[0])     /* masklen >= 64 */
    {
        return masklen64(lo->bits[1], hi->bits[1], 64);
    }
    else                                /* masklen < 64 */
    {
        if (lo->bits[1] != 0 || hi->bits[1] != ~((uint64)0))
            return ~0U;
        return masklen64(lo->bits[0], hi->bits[0], 0);
    }
}

static inline
bool ip6_valid_netmask(uint64 maskhi, uint64 masklo)
{
    uint64 d;
    int fbit;

    if (maskhi == ~((uint64)0))
        d = ~masklo + 1;
    else if (masklo == 0)
        d = ~maskhi + 1;
    else
        return FALSE;

    /* at this point, d can be:
     *  0 if mask was 0x00000000 (valid)
     *  1 << (32-masklen)   (valid)
     *  some other value  (invalid)
     */

    if (!(d & 0xFFFFFFFFUL))
        d >>= 32;
    if (!d)
        return TRUE;

    fbit = ffs((uint32)d);
    return ((uint32)(1U) << (fbit-1)) == d;
}


static inline
bool ip6_equal(IP6 *a, IP6 *b)
{
    return (a->bits[0] == b->bits[0]) && (a->bits[1] == b->bits[1]);
}

static inline
int ip6_compare(IP6 *a, IP6 *b)
{
    if (a->bits[0] != b->bits[0])
        return (a->bits[0] > b->bits[0]) ? 1 : -1;
    if (a->bits[1] != b->bits[1])
        return (a->bits[1] > b->bits[1]) ? 1 : -1;
    return 0;
}

static inline
bool ip6_lessthan(IP6 *a, IP6 *b)
{
    return ( (a->bits[0] < b->bits[0])
             || ((a->bits[0] == b->bits[0]) && (a->bits[1] < b->bits[1])) );
}

static inline
void ip6_sub(IP6 *minuend, IP6 *subtrahend, IP6 *result)
{
    result->bits[1] = minuend->bits[1] - subtrahend->bits[1];
    result->bits[0] = minuend->bits[0] - subtrahend->bits[0] - (minuend->bits[1] < subtrahend->bits[1]);
}

static inline
void ip6_sub_int(IP6 *minuend, int subtrahend, IP6 *result)
{
	uint64 res_lo;

    if (subtrahend >= 0)
    {
        res_lo = minuend->bits[1] - (uint64)(subtrahend);
        result->bits[0] = minuend->bits[0] - (res_lo > minuend->bits[1]);
    }
    else
    {
        res_lo = minuend->bits[1] + (uint64)(-subtrahend);
        result->bits[0] = minuend->bits[0] + (res_lo < minuend->bits[1]);
    }

	result->bits[1] = res_lo;
}


static inline
bool ip6r_from_cidr(IP6 *prefix, unsigned masklen, IP6R *ipr)
{
    uint64 mask_lo = hostmask6_lo(masklen);
    uint64 mask_hi = hostmask6_hi(masklen);
    if (masklen > 128)
        return FALSE;
    if ((prefix->bits[0] & mask_hi) || (prefix->bits[1] & mask_lo))
        return FALSE;
    ipr->upper.bits[0] = (prefix->bits[0] | mask_hi);
    ipr->upper.bits[1] = (prefix->bits[1] | mask_lo);
    ipr->lower = *prefix;
    return TRUE;
}

static inline
bool ip6r_from_inet(IP6 *addr, unsigned masklen, IP6R *ipr)
{
    uint64 mask_lo = hostmask6_lo(masklen);
    uint64 mask_hi = hostmask6_hi(masklen);
    if (masklen > 128)
        return FALSE;
    ipr->lower.bits[0] = (addr->bits[0] & ~mask_hi);
    ipr->lower.bits[1] = (addr->bits[1] & ~mask_lo);
    ipr->upper.bits[0] = (addr->bits[0] | mask_hi);
    ipr->upper.bits[1] = (addr->bits[1] | mask_lo);
    return TRUE;
}

/* helpers for union/intersection for indexing */

/* note that this function has to handle the case where RESULT aliases
 * either of A or B
 */

static inline
IP6R *ip6r_union_internal(IP6R *a, IP6R *b, IP6R *result)
{
    if (ip6_lessthan(&a->lower,&b->lower))
        result->lower = a->lower;
    else
        result->lower = b->lower;

    if (ip6_lessthan(&b->upper,&a->upper))
        result->upper = a->upper;
    else
        result->upper = b->upper;

    return result;
}

static inline
IP6R *ip6r_inter_internal(IP6R *a, IP6R *b, IP6R *result)
{
    if (ip6_lessthan(&a->upper,&b->lower) || ip6_lessthan(&b->upper,&a->lower))
    {
        /* disjoint */
        result->lower.bits[0] = 0;
        result->lower.bits[1] = 1;
        result->upper.bits[0] = 0;  /* INVALID VALUE */
        result->upper.bits[1] = 0;  /* INVALID VALUE */
        return NULL;
    }

    if (ip6_lessthan(&a->upper,&b->upper))
        result->upper = a->upper;
    else
        result->upper = b->upper;

    if (ip6_lessthan(&b->lower,&a->lower))
        result->lower = a->lower;
    else
        result->lower = b->lower;

    return result;
}

static inline
double ip6r_metric(IP6R *v)
{
    IP6 diff;
    double res = 0.0;
    if (!v)
        return res;

    ip6_sub(&v->upper, &v->lower, &diff);

    return ( (ldexp((double)diff.bits[0],64))
             + (diff.bits[1] + 1.0) );
}

/* comparisons */

static inline
bool ip6_less_eq(IP6 *a, IP6 *b)
{
    return !ip6_lessthan(b,a);
}

static inline
bool ip6r_equal(IP6R *a, IP6R *b)
{
    return ip6_equal(&a->lower,&b->lower) && ip6_equal(&a->upper,&b->upper);
}

static inline
bool ip6r_lessthan(IP6R *a, IP6R *b)
{
    switch (ip6_compare(&a->lower,&b->lower))
    {
        default: return ip6_lessthan(&a->upper,&b->upper);
        case -1: return true;
        case 1: return false;
    }
}

static inline
bool ip6r_less_eq(IP6R *a, IP6R *b)
{
    return !ip6r_lessthan(b,a);
}

static inline
bool ip6r_contains_internal(IP6R *left, IP6R *right, bool eqval)
{
    if (ip6r_equal(left,right))
        return eqval;
    return !ip6_lessthan(&right->lower,&left->lower) && !ip6_lessthan(&left->upper,&right->upper);
}

static inline
bool ip6r_overlaps_internal(IP6R *left, IP6R *right)
{
    return !ip6_lessthan(&left->upper,&right->lower) && !ip6_lessthan(&right->upper,&left->lower);
}

static inline
bool ip6_contains_internal(IP6R *left, IP6 *right)
{
    return !ip6_lessthan(right,&left->lower) && !ip6_lessthan(&left->upper,right);
}

/* end */
