/* $Id: ip6r.c,v 1.2 2011/08/22 14:05:19 andrewsn Exp $ */

#include "ipr.h"

#include "ip6r_funcs.h"


/* extract an IP range from text.
 */
static
bool ip6r_from_str(char *str, IP6R *ipr)
{
    char buf[IP6_STRING_MAX];
    int pos = strcspn(str, "-/");
    IP6 ip;

    switch (str[pos])
    {
        case 0:     /* no separator, must be single ip6 addr */
        {
            if (!ip6_raw_input(str, ip.bits))
                return FALSE;
            ipr->lower = ip;
            ipr->upper = ip;
            return TRUE;
        }

        case '-':   /* lower-upper */
        {
            char *rest = str + pos + 1;

            if (pos > sizeof(buf)-2)
                return FALSE;
            memcpy(buf, str, pos);
            buf[pos] = 0;
            if (!ip6_raw_input(buf, ip.bits))
                return FALSE;
            ipr->lower = ip;
            if (!ip6_raw_input(rest, ip.bits))
                return FALSE;
            if (!ip6_lessthan(&ip, &ipr->lower))
                ipr->upper = ip;
            else
            {
                ipr->upper = ipr->lower;
                ipr->lower = ip;
            }
            return TRUE;
        }

        case '/':  /* prefix/len */
        {
            char *rest = str + pos + 1;
            unsigned pfxlen;
            char dummy;

            if (pos > sizeof(buf)-2)
                return FALSE;
            memcpy(buf, str, pos);
            buf[pos] = 0;
            if (!ip6_raw_input(buf, ip.bits))
                return FALSE;
            if (rest[strspn(rest,"0123456789")])
                return FALSE;
            if (sscanf(rest, "%u%c", &pfxlen, &dummy) != 1)
                return FALSE;
            return ip6r_from_cidr(&ip, pfxlen, ipr);
        }

        default:
            return FALSE;      /* can't happen */
    }
}


/* Output an ip range in text form
 */
static
int ip6r_to_str(IP6R *ipr, char *str, int slen)
{
    char buf1[IP6_STRING_MAX];
    char buf2[IP6_STRING_MAX];
    unsigned msk;

    if (ip6_equal(&ipr->lower, &ipr->upper))
        return ip6_raw_output(ipr->lower.bits, str, slen);

    if ((msk = masklen6(&ipr->lower,&ipr->upper)) <= 128)
    {
        ip6_raw_output(ipr->lower.bits, buf1, sizeof(buf1));
        return snprintf(str, slen, "%s/%u", buf1, msk);
    }

    ip6_raw_output(ipr->lower.bits, buf1, sizeof(buf1));
    ip6_raw_output(ipr->upper.bits, buf2, sizeof(buf2));

    return snprintf(str, slen, "%s-%s", buf1, buf2);
}


/**************************************************************************/
/* This part handles all aspects of postgres interfacing.
 */


/* end of version dependencies */


/*
#define GIST_DEBUG
#define GIST_QUERY_DEBUG
*/

static
text *
make_text(char *str, int len)
{
    text *ret = (text *) palloc(len + VARHDRSZ);
    SET_VARSIZE(ret, len + VARHDRSZ);
    if (str)
        memcpy(VARDATA(ret), str, len);
    else
        memset(VARDATA(ret), 0, len);
    return ret;
}

static inline
void
set_text_len(text *txt, int len)
{
    if ((len + VARHDRSZ) < VARSIZE(txt))
      SET_VARSIZE(txt, len + VARHDRSZ);
}

static inline
int
get_text_len(text *txt)
{
    return VARSIZE(txt) - VARHDRSZ;
}

/*
** Input/Output routines
*/

PG_FUNCTION_INFO_V1(ip6_in);
Datum
ip6_in(PG_FUNCTION_ARGS)
{
    char *str = PG_GETARG_CSTRING(0);
    IP6 *ip = palloc(sizeof(IP6));
    if (ip6_raw_input(str, ip->bits))
        PG_RETURN_IP6_P(ip);

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid IP6 value: '%s'", str)));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6_out);
Datum
ip6_out(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    char *out = palloc(IP6_STRING_MAX);
    ip6_raw_output(ip->bits, out, IP6_STRING_MAX);
    PG_RETURN_CSTRING(out);
}

PG_FUNCTION_INFO_V1(ip6_recv);
Datum
ip6_recv(PG_FUNCTION_ARGS)
{
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
    IP6 *ip = palloc(sizeof(IP6));

    ip->bits[0] = pq_getmsgint64(buf);
    ip->bits[1] = pq_getmsgint64(buf);

    PG_RETURN_IP6_P(ip);
}

PG_FUNCTION_INFO_V1(ip6_send);
Datum
ip6_send(PG_FUNCTION_ARGS)
{
    IP6 *arg1 = PG_GETARG_IP6_P(0);
    StringInfoData buf;

    pq_begintypsend(&buf);
    pq_sendint64(&buf, arg1->bits[0]);
    pq_sendint64(&buf, arg1->bits[1]);
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

PG_FUNCTION_INFO_V1(ip6hash);
Datum
ip6hash(PG_FUNCTION_ARGS)
{
    IP6 *arg1 = PG_GETARG_IP6_P(0);

    return hash_any((unsigned char *)arg1, sizeof(IP6));
}

PG_FUNCTION_INFO_V1(ip6_cast_to_text);
Datum
ip6_cast_to_text(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    text *out = make_text(NULL,IP6_STRING_MAX);
    set_text_len(out, ip6_raw_output(ip->bits, VARDATA(out), IP6_STRING_MAX));
    PG_RETURN_TEXT_P(out);
}

PG_FUNCTION_INFO_V1(ip6_cast_from_text);
Datum
ip6_cast_from_text(PG_FUNCTION_ARGS)
{
    text *txt = PG_GETARG_TEXT_P(0);
    int tlen = get_text_len(txt);
    char buf[IP6_STRING_MAX];

    if (tlen < sizeof(buf))
    {
        IP6 *ip = palloc(sizeof(IP6));

        memcpy(buf, VARDATA(txt), tlen);
        buf[tlen] = 0;
        if (ip6_raw_input(buf, ip->bits))
            PG_RETURN_IP6_P(ip);
    }

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid IP6 value in text")));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6_cast_from_inet);
Datum
ip6_cast_from_inet(PG_FUNCTION_ARGS)
{
    inet *inetptr = PG_GETARG_INET_P(0);
    inet_struct *in = INET_STRUCT_DATA(inetptr);

    if (in->family == PGSQL_AF_INET6)
    {
        unsigned char *p = in->ipaddr;
        IP6 *ip = palloc(sizeof(IP6));
        ip->bits[0] = (((uint64)p[0] << 56)
                       | ((uint64)p[1] << 48)
                       | ((uint64)p[2] << 40)
                       | ((uint64)p[3] << 32)
                       | ((uint64)p[4] << 24)
                       | ((uint64)p[5] << 16)
                       | ((uint64)p[6] << 8)
                       | p[7]);
        ip->bits[1] = (((uint64)p[8] << 56)
                       | ((uint64)p[9] << 48)
                       | ((uint64)p[10] << 40)
                       | ((uint64)p[11] << 32)
                       | ((uint64)p[12] << 24)
                       | ((uint64)p[13] << 16)
                       | ((uint64)p[14] << 8)
                       | p[15]);
        PG_RETURN_IP6_P(ip);
    }

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid INET value for conversion to IP6")));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6_cast_to_cidr);
Datum
ip6_cast_to_cidr(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    inet *res = palloc0(VARHDRSZ + sizeof(inet_struct));
    inet_struct *in;

    SET_VARSIZE(res, VARHDRSZ + offsetof(inet_struct, ipaddr) + 16);

    in = ((inet_struct *)VARDATA(res));
    INET_INIT_CIDR(in);
    in->bits = 128;
    in->family = PGSQL_AF_INET6;
    {
        unsigned char *p = in->ipaddr;
        p[0] = (ip->bits[0] >> 56);
        p[1] = (ip->bits[0] >> 48);
        p[2] = (ip->bits[0] >> 40);
        p[3] = (ip->bits[0] >> 32);
        p[4] = (ip->bits[0] >> 24);
        p[5] = (ip->bits[0] >> 16);
        p[6] = (ip->bits[0] >> 8);
        p[7] = (ip->bits[0]);
        p[8] = (ip->bits[1] >> 56);
        p[9] = (ip->bits[1] >> 48);
        p[10] = (ip->bits[1] >> 40);
        p[11] = (ip->bits[1] >> 32);
        p[12] = (ip->bits[1] >> 24);
        p[13] = (ip->bits[1] >> 16);
        p[14] = (ip->bits[1] >> 8);
        p[15] = (ip->bits[1]);
    }

    PG_RETURN_INET_P(res);
}


PG_FUNCTION_INFO_V1(ip6_cast_to_numeric);
Datum
ip6_cast_to_numeric(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    Datum res,tmp,mul;
    static int64 mul_val = ((int64)1 << 56);
    int64 tmp_val;

    mul = DirectFunctionCall1(int8_numeric,Int64GetDatumFast(mul_val));
    tmp_val = (ip->bits[0] >> 48);
    res = DirectFunctionCall1(int8_numeric,Int64GetDatumFast(tmp_val));
    tmp_val = ((ip->bits[0] & (uint64)(0xFFFFFFFFFFFFULL)) << 8) | (ip->bits[1] >> 56);
    tmp = DirectFunctionCall1(int8_numeric,Int64GetDatumFast(tmp_val));
    res = DirectFunctionCall2(numeric_mul,res,mul);
    res = DirectFunctionCall2(numeric_add,res,tmp);
    tmp_val = (ip->bits[1] & (uint64)(0xFFFFFFFFFFFFFFULL));
    tmp = DirectFunctionCall1(int8_numeric,Int64GetDatumFast(tmp_val));
    res = DirectFunctionCall2(numeric_mul,res,mul);
    res = DirectFunctionCall2(numeric_add,res,tmp);

    PG_RETURN_DATUM(res);
}

PG_FUNCTION_INFO_V1(ip6_cast_from_numeric);
Datum
ip6_cast_from_numeric(PG_FUNCTION_ARGS)
{
    Datum val = NumericGetDatum(PG_GETARG_NUMERIC(0));
    Datum rem,tmp,div,mul;
    static int64 mul_val = ((int64)1 << 56);
    uint64 tmp_val;
    IP6 *res;

    tmp = DirectFunctionCall1(numeric_floor,DirectFunctionCall1(numeric_abs,val));

    if (!DatumGetBool(DirectFunctionCall2(numeric_eq,tmp,val)))
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid numeric value for conversion to IP6")));
    }

    res = palloc(sizeof(IP6));

    /* we use div/mul here rather than mod because numeric_mod is implemented as
     * a div/mul/subtract in any case, so we save a division step by doing the
     * mul/subtract ourselves
     */

    mul = DirectFunctionCall1(int8_numeric,Int64GetDatumFast(mul_val));
    div = DirectFunctionCall2(numeric_div_trunc,val,mul);
    tmp = DirectFunctionCall2(numeric_mul,div,mul);
    rem = DirectFunctionCall2(numeric_sub,val,tmp);
    res->bits[1] = (uint64)DatumGetInt64(DirectFunctionCall1(numeric_int8,rem));
    val = div;
    div = DirectFunctionCall2(numeric_div_trunc,val,mul);
    tmp = DirectFunctionCall2(numeric_mul,div,mul);
    rem = DirectFunctionCall2(numeric_sub,val,tmp);
    tmp_val = (uint64)DatumGetInt64(DirectFunctionCall1(numeric_int8,rem));
    res->bits[1] |= ((tmp_val & 0xFF) << 56);
    res->bits[0] = (tmp_val >> 8);
    if (!DatumGetBool(DirectFunctionCall2(numeric_gt,div,mul)))
    {
        tmp_val = (uint64)DatumGetInt64(DirectFunctionCall1(numeric_int8,div));
        if (tmp_val <= (uint64)0xFFFFU)
        {
            res->bits[0] |= (tmp_val << 48);
            PG_RETURN_IP6_P(res);
        }
    }

    ereport(ERROR,
            (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
             errmsg("numeric value too large for conversion to IP6")));
    PG_RETURN_NULL();
}


PG_FUNCTION_INFO_V1(ip6_netmask);
Datum
ip6_netmask(PG_FUNCTION_ARGS)
{
    int pfxlen = PG_GETARG_INT32(0);
    IP6 *mask;

    if (pfxlen < 0 || pfxlen > 128)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("prefix length out of range")));
    }

    mask = palloc(sizeof(IP6));
    mask->bits[0] = netmask6_hi(pfxlen);
    mask->bits[1] = netmask6_lo(pfxlen);
    PG_RETURN_IP6_P(mask);
}

PG_FUNCTION_INFO_V1(ip6_net_lower);
Datum
ip6_net_lower(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int pfxlen = PG_GETARG_INT32(1);
    IP6 *res;

    if (pfxlen < 0 || pfxlen > 128)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("prefix length out of range")));
    }

    res = palloc(sizeof(IP6));
    res->bits[0] = ip->bits[0] & netmask6_hi(pfxlen);
    res->bits[1] = ip->bits[1] & netmask6_lo(pfxlen);

    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6_net_upper);
Datum
ip6_net_upper(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int pfxlen = PG_GETARG_INT32(1);
    IP6 *res;

    if (pfxlen < 0 || pfxlen > 128)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("prefix length out of range")));
    }

    res = palloc(sizeof(IP6));
    res->bits[0] = ip->bits[0] | hostmask6_hi(pfxlen);
    res->bits[1] = ip->bits[1] | hostmask6_lo(pfxlen);

    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6_plus_int);
Datum
ip6_plus_int(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int addend = PG_GETARG_INT32(1);
    IP6 *result = palloc(sizeof(IP6));

    if (addend >= 0)
    {
        result->bits[1] = ip->bits[1] + addend;
        result->bits[0] = ip->bits[0] + (result->bits[1] < ip->bits[1]);
    }
    else
    {
        result->bits[1] = ip->bits[1] - (uint64)(-addend);
        result->bits[0] = ip->bits[0] - (result->bits[1] > ip->bits[1]);
    }

    if ((addend < 0) != ip6_lessthan(result,ip))
    {
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("ip address out of range")));
    }

    PG_RETURN_IP6_P(result);
}

PG_FUNCTION_INFO_V1(ip6_plus_bigint);
Datum
ip6_plus_bigint(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int64 addend = PG_GETARG_INT64(1);
    IP6 *result = palloc(sizeof(IP6));

    if (addend >= 0)
    {
        result->bits[1] = ip->bits[1] + addend;
        result->bits[0] = ip->bits[0] + (result->bits[1] < ip->bits[1]);
    }
    else
    {
        result->bits[1] = ip->bits[1] - (uint64)(-addend);
        result->bits[0] = ip->bits[0] - (result->bits[1] > ip->bits[1]);
    }

    if ((addend < 0) != ip6_lessthan(result,ip))
    {
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("ip address out of range")));
    }

    PG_RETURN_IP6_P(result);
}

PG_FUNCTION_INFO_V1(ip6_plus_numeric);
Datum
ip6_plus_numeric(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    Datum addend_num = NumericGetDatum(PG_GETARG_NUMERIC(1));
    Datum addend_abs;
    IP6 *addend;
    IP6 *result = palloc(sizeof(IP6));
    bool is_negative;

    addend_abs = DirectFunctionCall1(numeric_abs,addend_num);
    addend = DatumGetIP6P(DirectFunctionCall1(ip6_cast_from_numeric,addend_abs));

    if (DatumGetBool(DirectFunctionCall2(numeric_eq,addend_num,addend_abs)))
    {
        is_negative = false;
        result->bits[1] = ip->bits[1] + addend->bits[1];
        result->bits[0] = ip->bits[0] + addend->bits[0] + (result->bits[1] < ip->bits[1]);
    }
    else
    {
        is_negative = true;
        result->bits[1] = ip->bits[1] - addend->bits[1];
        result->bits[0] = ip->bits[0] - addend->bits[0] - (result->bits[1] > ip->bits[1]);
    }

    if (is_negative != ip6_lessthan(result,ip))
    {
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("ip address out of range")));
    }

    PG_RETURN_IP6_P(result);
}

PG_FUNCTION_INFO_V1(ip6_minus_int);
Datum
ip6_minus_int(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int subtrahend = PG_GETARG_INT32(1);
    IP6 *result = palloc(sizeof(IP6));

	ip6_sub_int(ip, subtrahend, result);

    if ((subtrahend > 0) != ip6_lessthan(result,ip))
    {
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("ip address out of range")));
    }

    PG_RETURN_IP6_P(result);
}

PG_FUNCTION_INFO_V1(ip6_minus_bigint);
Datum
ip6_minus_bigint(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int64 subtrahend = PG_GETARG_INT64(1);
    IP6 *result = palloc(sizeof(IP6));

    if (subtrahend >= 0)
    {
        result->bits[1] = ip->bits[1] - (uint64)subtrahend;
        result->bits[0] = ip->bits[0] - (result->bits[1] > ip->bits[1]);
    }
    else
    {
        result->bits[1] = ip->bits[1] + (uint64)(-subtrahend);
        result->bits[0] = ip->bits[0] + (result->bits[1] < ip->bits[1]);
    }

    if ((subtrahend > 0) != ip6_lessthan(result,ip))
    {
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("ip address out of range")));
    }

    PG_RETURN_IP6_P(result);
}

PG_FUNCTION_INFO_V1(ip6_minus_numeric);
Datum
ip6_minus_numeric(PG_FUNCTION_ARGS)
{
    Datum ip = PG_GETARG_DATUM(0);
    Datum subtrahend = PG_GETARG_DATUM(1);

    subtrahend = DirectFunctionCall1(numeric_uminus,subtrahend);
    return DirectFunctionCall2(ip6_plus_numeric,ip,subtrahend);
}

PG_FUNCTION_INFO_V1(ip6_minus_ip6);
Datum
ip6_minus_ip6(PG_FUNCTION_ARGS)
{
    Datum minuend = PG_GETARG_DATUM(0);
    Datum subtrahend = PG_GETARG_DATUM(1);
    Datum res;

    res = DirectFunctionCall2(numeric_sub,
                              DirectFunctionCall1(ip6_cast_to_numeric,minuend),
                              DirectFunctionCall1(ip6_cast_to_numeric,subtrahend));

    PG_RETURN_DATUM(res);
}

PG_FUNCTION_INFO_V1(ip6_and);
Datum
ip6_and(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *b = PG_GETARG_IP6_P(1);
    IP6 *res = palloc(sizeof(IP6));

    res->bits[0] = a->bits[0] & b->bits[0];
    res->bits[1] = a->bits[1] & b->bits[1];

    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6_or);
Datum
ip6_or(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *b = PG_GETARG_IP6_P(1);
    IP6 *res = palloc(sizeof(IP6));

    res->bits[0] = a->bits[0] | b->bits[0];
    res->bits[1] = a->bits[1] | b->bits[1];

    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6_xor);
Datum
ip6_xor(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *b = PG_GETARG_IP6_P(1);
    IP6 *res = palloc(sizeof(IP6));

    res->bits[0] = a->bits[0] ^ b->bits[0];
    res->bits[1] = a->bits[1] ^ b->bits[1];

    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6_not);
Datum
ip6_not(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *res = palloc(sizeof(IP6));

    res->bits[0] = ~a->bits[0];
    res->bits[1] = ~a->bits[1];

    PG_RETURN_IP6_P(res);
}


/*---- ip6r ----*/

PG_FUNCTION_INFO_V1(ip6r_in);
Datum
ip6r_in(PG_FUNCTION_ARGS)
{
    char *str = PG_GETARG_CSTRING(0);
    IP6R ipr;

    if (ip6r_from_str(str, &ipr))
    {
        IP6R *res = palloc(sizeof(IP6R));
        *res = ipr;
        PG_RETURN_IP6R_P(res);
    }

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid IP6R value: \"%s\"", str)));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6r_out);
Datum
ip6r_out(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    char *out = palloc(IP6R_STRING_MAX);
    ip6r_to_str(ipr, out, IP6R_STRING_MAX);
    PG_RETURN_CSTRING(out);
}

PG_FUNCTION_INFO_V1(ip6r_recv);
Datum
ip6r_recv(PG_FUNCTION_ARGS)
{
    StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
    IP6R *ipr = palloc(sizeof(IP6R));

    ipr->lower.bits[0] = pq_getmsgint64(buf);
    ipr->lower.bits[1] = pq_getmsgint64(buf);
    ipr->upper.bits[0] = pq_getmsgint64(buf);
    ipr->upper.bits[1] = pq_getmsgint64(buf);

    PG_RETURN_IP6R_P(ipr);
}

PG_FUNCTION_INFO_V1(ip6r_send);
Datum
ip6r_send(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    StringInfoData buf;

    pq_begintypsend(&buf);
    pq_sendint64(&buf, ipr->lower.bits[0]);
    pq_sendint64(&buf, ipr->lower.bits[1]);
    pq_sendint64(&buf, ipr->upper.bits[0]);
    pq_sendint64(&buf, ipr->upper.bits[1]);
    PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

PG_FUNCTION_INFO_V1(ip6rhash);
Datum
ip6rhash(PG_FUNCTION_ARGS)
{
    IP6R *arg1 = PG_GETARG_IP6R_P(0);

    return hash_any((unsigned char *)arg1, sizeof(IP6R));
}

PG_FUNCTION_INFO_V1(ip6r_cast_to_text);
Datum
ip6r_cast_to_text(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    text *out = make_text(NULL,IP6R_STRING_MAX);
    set_text_len(out, ip6r_to_str(ipr, VARDATA(out), IP6R_STRING_MAX));
    PG_RETURN_TEXT_P(out);
}

PG_FUNCTION_INFO_V1(ip6r_cast_from_text);
Datum
ip6r_cast_from_text(PG_FUNCTION_ARGS)
{
    text *txt = PG_GETARG_TEXT_P(0);
    int tlen = get_text_len(txt);
    char buf[IP6R_STRING_MAX];

    if (tlen < sizeof(buf))
    {
        IP6R ipr;

        memcpy(buf, VARDATA(txt), tlen);
        buf[tlen] = 0;
        if (ip6r_from_str(buf, &ipr))
        {
            IP6R *res = palloc(sizeof(IP6R));
            *res = ipr;
            PG_RETURN_IP6R_P(res);
        }
    }

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid IP6R value in text")));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6r_cast_from_cidr);
Datum
ip6r_cast_from_cidr(PG_FUNCTION_ARGS)
{
    inet *inetptr = PG_GETARG_INET_P(0);
    inet_struct *in = INET_STRUCT_DATA(inetptr);

    if (INET_IS_CIDR(in) && in->family == PGSQL_AF_INET6)
    {
        unsigned char *p = in->ipaddr;
        IP6 ip;
        IP6R ipr;
        ip.bits[0] = (((uint64)p[0] << 56)
                      | ((uint64)p[1] << 48)
                      | ((uint64)p[2] << 40)
                      | ((uint64)p[3] << 32)
                      | ((uint64)p[4] << 24)
                      | ((uint64)p[5] << 16)
                      | ((uint64)p[6] << 8)
                      | p[7]);
        ip.bits[1] = (((uint64)p[8] << 56)
                      | ((uint64)p[9] << 48)
                      | ((uint64)p[10] << 40)
                      | ((uint64)p[11] << 32)
                      | ((uint64)p[12] << 24)
                      | ((uint64)p[13] << 16)
                      | ((uint64)p[14] << 8)
                      | p[15]);
        if (ip6r_from_cidr(&ip, in->bits, &ipr))
        {
            IP6R *res = palloc(sizeof(IP6R));
            *res = ipr;
            PG_RETURN_IP6R_P(res);
        }
    }

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid CIDR value for conversion to IP6R")));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6r_cast_to_cidr);
Datum
ip6r_cast_to_cidr(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    IP6 *ip = &ipr->lower;
    inet *res;
    inet_struct *in;
    unsigned bits = masklen6(ip, &ipr->upper);

    if (bits > 128)
        PG_RETURN_NULL();

    res = palloc0(VARHDRSZ + sizeof(inet_struct));
    SET_VARSIZE(res, VARHDRSZ + offsetof(inet_struct, ipaddr) + 16);

    in = ((inet_struct *)VARDATA(res));
    INET_INIT_CIDR(in);
    in->bits = bits;
    in->family = PGSQL_AF_INET6;
    {
        unsigned char *p = in->ipaddr;
        p[0] = (ip->bits[0] >> 56);
        p[1] = (ip->bits[0] >> 48);
        p[2] = (ip->bits[0] >> 40);
        p[3] = (ip->bits[0] >> 32);
        p[4] = (ip->bits[0] >> 24);
        p[5] = (ip->bits[0] >> 16);
        p[6] = (ip->bits[0] >> 8);
        p[7] = (ip->bits[0]);
        p[8] = (ip->bits[1] >> 56);
        p[9] = (ip->bits[1] >> 48);
        p[10] = (ip->bits[1] >> 40);
        p[11] = (ip->bits[1] >> 32);
        p[12] = (ip->bits[1] >> 24);
        p[13] = (ip->bits[1] >> 16);
        p[14] = (ip->bits[1] >> 8);
        p[15] = (ip->bits[1]);
    }

    PG_RETURN_INET_P(res);
}

PG_FUNCTION_INFO_V1(ip6r_cast_from_ip6);
Datum
ip6r_cast_from_ip6(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    IP6R *res = palloc(sizeof(IP6R));
    if (ip6r_from_inet(ip, 128, res))
    {
        PG_RETURN_IP6R_P(res);
    }

    pfree(res);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("invalid IP6 value for conversion to IP6R (shouldn't be possible)")));
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6r_from_ip6s);
Datum
ip6r_from_ip6s(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *b = PG_GETARG_IP6_P(1);
    IP6R *res = palloc(sizeof(IP6R));
    if (ip6_lessthan(a,b))
        res->lower = *a, res->upper = *b;
    else
        res->lower = *b, res->upper = *a;
    PG_RETURN_IP6R_P(res);
}

PG_FUNCTION_INFO_V1(ip6r_net_prefix);
Datum
ip6r_net_prefix(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    int pfxlen = PG_GETARG_INT32(1);

    if (pfxlen < 0 || pfxlen > 128)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("prefix length out of range")));
    }

    {
        IP6R *res = palloc(sizeof(IP6R));
        ip6r_from_inet(ip, (unsigned)pfxlen, res);
        PG_RETURN_IP6R_P(res);
    }
}

PG_FUNCTION_INFO_V1(ip6r_net_mask);
Datum
ip6r_net_mask(PG_FUNCTION_ARGS)
{
    IP6 *ip = PG_GETARG_IP6_P(0);
    IP6 *mask = PG_GETARG_IP6_P(1);

    if (!ip6_valid_netmask(mask->bits[0], mask->bits[1]))
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid netmask")));
    }

    {
        IP6R *res = palloc(sizeof(IP6R));
    
        res->lower.bits[0] = ip->bits[0] & mask->bits[0];
        res->lower.bits[1] = ip->bits[1] & mask->bits[1];
        res->upper.bits[0] = ip->bits[0] | ~(mask->bits[0]);
        res->upper.bits[1] = ip->bits[1] | ~(mask->bits[1]);

        PG_RETURN_IP6R_P(res);
    }
}


PG_FUNCTION_INFO_V1(ip6r_lower);
Datum
ip6r_lower(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    IP6 *res = palloc(sizeof(IP6));
    *res = ipr->lower;
    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6r_upper);
Datum
ip6r_upper(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    IP6 *res = palloc(sizeof(IP6));
    *res = ipr->upper;
    PG_RETURN_IP6_P(res);
}

PG_FUNCTION_INFO_V1(ip6r_is_cidr);
Datum
ip6r_is_cidr(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
    PG_RETURN_BOOL( (masklen6(&ipr->lower,&ipr->upper) <= 128U) );
}

PG_FUNCTION_INFO_V1(ip6_lt);
Datum
ip6_lt(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_lessthan(PG_GETARG_IP6_P(0), PG_GETARG_IP6_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6_le);
Datum
ip6_le(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_less_eq(PG_GETARG_IP6_P(0), PG_GETARG_IP6_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6_gt);
Datum
ip6_gt(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_lessthan(PG_GETARG_IP6_P(1), PG_GETARG_IP6_P(0)) );
}

PG_FUNCTION_INFO_V1(ip6_ge);
Datum
ip6_ge(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_less_eq(PG_GETARG_IP6_P(1), PG_GETARG_IP6_P(0)) );
}

PG_FUNCTION_INFO_V1(ip6_eq);
Datum
ip6_eq(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_equal(PG_GETARG_IP6_P(0), PG_GETARG_IP6_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6_neq);
Datum
ip6_neq(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( !ip6_equal(PG_GETARG_IP6_P(0), PG_GETARG_IP6_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_lt);
Datum
ip6r_lt(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_lessthan(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_le);
Datum
ip6r_le(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_less_eq(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_gt);
Datum
ip6r_gt(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_lessthan(PG_GETARG_IP6R_P(1), PG_GETARG_IP6R_P(0)) );
}

PG_FUNCTION_INFO_V1(ip6r_ge);
Datum
ip6r_ge(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_less_eq(PG_GETARG_IP6R_P(1), PG_GETARG_IP6R_P(0)) );
}

PG_FUNCTION_INFO_V1(ip6r_eq);
Datum
ip6r_eq(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_equal(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_neq);
Datum
ip6r_neq(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( !ip6r_equal(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_overlaps);
Datum
ip6r_overlaps(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_overlaps_internal(PG_GETARG_IP6R_P(0), 
                                           PG_GETARG_IP6R_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6r_contains);
Datum
ip6r_contains(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_contains_internal(PG_GETARG_IP6R_P(0),
                                           PG_GETARG_IP6R_P(1),
                                           TRUE) );
}

PG_FUNCTION_INFO_V1(ip6r_contains_strict);
Datum
ip6r_contains_strict(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_contains_internal(PG_GETARG_IP6R_P(0),
                                           PG_GETARG_IP6R_P(1),
                                           FALSE) );
}

PG_FUNCTION_INFO_V1(ip6r_contained_by);
Datum
ip6r_contained_by(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_contains_internal(PG_GETARG_IP6R_P(1),
                                           PG_GETARG_IP6R_P(0),
                                           TRUE) );
}

PG_FUNCTION_INFO_V1(ip6r_contained_by_strict);
Datum
ip6r_contained_by_strict(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6r_contains_internal(PG_GETARG_IP6R_P(1),
                                           PG_GETARG_IP6R_P(0),
                                           FALSE) );
}

PG_FUNCTION_INFO_V1(ip6_contains);
Datum
ip6_contains(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_contains_internal(PG_GETARG_IP6R_P(0), PG_GETARG_IP6_P(1)) );
}

PG_FUNCTION_INFO_V1(ip6_contained_by);
Datum
ip6_contained_by(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL( ip6_contains_internal(PG_GETARG_IP6R_P(1), PG_GETARG_IP6_P(0)) );
}

PG_FUNCTION_INFO_V1(ip6r_union);
Datum
ip6r_union(PG_FUNCTION_ARGS)
{
    IP6R *res = palloc(sizeof(IP6R));
    ip6r_union_internal(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1), res);
    PG_RETURN_IP6R_P(res);
}

PG_FUNCTION_INFO_V1(ip6r_inter);
Datum
ip6r_inter(PG_FUNCTION_ARGS)
{
    IP6R *res = palloc(sizeof(IP6R));
    if (ip6r_inter_internal(PG_GETARG_IP6R_P(0), PG_GETARG_IP6R_P(1), res))
    {
        PG_RETURN_IP6R_P(res);
    }
    pfree(res);
    PG_RETURN_NULL();
}

PG_FUNCTION_INFO_V1(ip6r_size);
Datum
ip6r_size(PG_FUNCTION_ARGS)
{
    double size = ip6r_metric(PG_GETARG_IP6R_P(0));
    PG_RETURN_FLOAT8(size);
}

PG_FUNCTION_INFO_V1(ip6r_size_exact);
Datum
ip6r_size_exact(PG_FUNCTION_ARGS)
{
	IP6R *ipr = PG_GETARG_IP6R_P(0);
	Datum l = DirectFunctionCall1(ip6_cast_to_numeric, IP6PGetDatum(&ipr->lower));
	Datum u = DirectFunctionCall1(ip6_cast_to_numeric, IP6PGetDatum(&ipr->upper));
	Datum d = DirectFunctionCall2(numeric_sub, u, l);
	Datum s = DirectFunctionCall1(numeric_inc, d);
	PG_RETURN_DATUM(s);
}

PG_FUNCTION_INFO_V1(ip6r_prefixlen);
Datum
ip6r_prefixlen(PG_FUNCTION_ARGS)
{
    IP6R *ipr = PG_GETARG_IP6R_P(0);
	unsigned len = masklen6(&ipr->lower, &ipr->upper);
	if (len <= 128)
		PG_RETURN_INT32((int32) len);
	PG_RETURN_NULL();
}


/*****************************************************************************
 *                                                 Btree functions
 *****************************************************************************/

PG_FUNCTION_INFO_V1(ip6r_cmp);
Datum
ip6r_cmp(PG_FUNCTION_ARGS)
{
    IP6R *a = PG_GETARG_IP6R_P(0);
    IP6R *b = PG_GETARG_IP6R_P(1);
    if (ip6r_lessthan(a,b))
        PG_RETURN_INT32(-1);
    if (ip6r_equal(a,b))
        PG_RETURN_INT32(0);
    PG_RETURN_INT32(1);
}

PG_FUNCTION_INFO_V1(ip6_cmp);
Datum
ip6_cmp(PG_FUNCTION_ARGS)
{
    IP6 *a = PG_GETARG_IP6_P(0);
    IP6 *b = PG_GETARG_IP6_P(1);
    PG_RETURN_INT32(ip6_compare(a,b));
}


/*****************************************************************************
 *                                                 GiST functions
 *****************************************************************************/

/*
** GiST support methods
*/

Datum gip6r_consistent(PG_FUNCTION_ARGS);
Datum gip6r_compress(PG_FUNCTION_ARGS);
Datum gip6r_decompress(PG_FUNCTION_ARGS);
Datum gip6r_penalty(PG_FUNCTION_ARGS);
Datum gip6r_picksplit(PG_FUNCTION_ARGS);
Datum gip6r_union(PG_FUNCTION_ARGS);
Datum gip6r_same(PG_FUNCTION_ARGS);

static bool gip6r_leaf_consistent(IP6R * key, IP6R * query, StrategyNumber strategy);
static bool gip6r_internal_consistent(IP6R * key, IP6R * query, StrategyNumber strategy);

/*
** The GiST Consistent method for IP ranges
** Should return false if for all data items x below entry,
** the predicate x op query == FALSE, where op is the oper
** corresponding to strategy in the pg_amop table.
*/
PG_FUNCTION_INFO_V1(gip6r_consistent);
Datum
gip6r_consistent(PG_FUNCTION_ARGS)
{
    GISTENTRY *entry = (GISTENTRY *) PG_GETARG_POINTER(0);
    IP6R *query = (IP6R *) PG_GETARG_POINTER(1);
    StrategyNumber strategy = (StrategyNumber) PG_GETARG_UINT16(2);
    bool *recheck = GIST_RECHECK_ARG;
    IP6R *key = (IP6R *) DatumGetPointer(entry->key);
    bool retval;

    /* recheck is never needed with this type */
    if (recheck)
        *recheck = false;

    /*
     * * if entry is not leaf, use gip6r_internal_consistent, * else use
     * gip6r_leaf_consistent
     */
    if (GIST_LEAF(entry))
        retval = gip6r_leaf_consistent(key, query, strategy);
    else
        retval = gip6r_internal_consistent(key, query, strategy);

    PG_RETURN_BOOL(retval);
}

/*
** The GiST Union method for IP ranges
** returns the minimal bounding IP4R that encloses all the entries in entryvec
*/
PG_FUNCTION_INFO_V1(gip6r_union);
Datum
gip6r_union(PG_FUNCTION_ARGS)
{
    GistEntryVector *entryvec = (GistEntryVector *) PG_GETARG_POINTER(0);
    int *sizep = (int *) PG_GETARG_POINTER(1);
    GISTENTRY *ent = GISTENTRYVEC(entryvec);

    int numranges, i;
    IP6R *out = palloc(sizeof(IP6R));
    IP6R *tmp;
  
#ifdef GIST_DEBUG
    fprintf(stderr, "union\n");
#endif
  
    numranges = GISTENTRYCOUNT(entryvec);
    tmp = (IP6R *) DatumGetPointer(ent[0].key);
    *sizep = sizeof(IP6R);
    *out = *tmp;
  
    for (i = 1; i < numranges; i++)
    {
        tmp = (IP6R *) DatumGetPointer(ent[i].key);
        if (ip6_lessthan(&tmp->lower,&out->lower))
            out->lower = tmp->lower;
        if (ip6_lessthan(&out->upper,&tmp->upper))
            out->upper = tmp->upper;
    }
    
    PG_RETURN_IP6R_P(out);
}

/*
** GiST Compress and Decompress methods for IP ranges
** do not do anything.
*/
PG_FUNCTION_INFO_V1(gip6r_compress);
Datum
gip6r_compress(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(PG_GETARG_POINTER(0));
}

PG_FUNCTION_INFO_V1(gip6r_decompress);
Datum
gip6r_decompress(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(PG_GETARG_POINTER(0));
}

/*
** The GiST Penalty method for IP ranges
** As in the R-tree paper, we use change in area as our penalty metric
*/
PG_FUNCTION_INFO_V1(gip6r_penalty);
Datum
gip6r_penalty(PG_FUNCTION_ARGS)
{
    GISTENTRY *origentry = (GISTENTRY *) PG_GETARG_POINTER(0);
    GISTENTRY *newentry = (GISTENTRY *) PG_GETARG_POINTER(1);
    float *result = (float *) PG_GETARG_POINTER(2);
    IP6R *key = (IP6R *) DatumGetPointer(origentry->key);
    IP6R *newkey = (IP6R *) DatumGetPointer(newentry->key);
    IP6R ud;
	double tmp = 0.0;

	/* rather than subtract the sizes, which might lose due to rounding errors,
	 * we calculate the actual number of addresses added to the range.
	 */

    if (ip6_lessthan(&newkey->lower,&key->lower))
	{
        ud.lower = newkey->lower;
		ud.upper = key->lower;
		ip6_sub_int(&ud.upper,1,&ud.upper);
		tmp = ip6r_metric(&ud);
	}
    if (ip6_lessthan(&key->upper,&newkey->upper))
	{
		ud.lower = key->upper;
        ud.upper = newkey->upper;
		ip6_sub_int(&ud.upper,1,&ud.upper);
		tmp += ip6r_metric(&ud);
	}

	/*
	 * we want to scale the result a bit. For one thing, the gist code implicitly
	 * assigns a penalty of 1e10 for a union of null and non-null values, and we
	 * want to keep our values less than that. For another, the penalty is sometimes
	 * summed across columns of a multi-column index, and we don't want our huge
	 * metrics (>2^80) to completely swamp anything else.
	 *
	 * So, we scale as the fourth power of the log2 of the computed penalty, which
	 * gives us a range 0 - 268435456.
	 */

    *result = (float) pow(log(tmp+1) / log(2), 4);
  
#ifdef GIST_DEBUG
    fprintf(stderr, "penalty\n");
    fprintf(stderr, "\t%g\n", *result);
#endif
  
    PG_RETURN_POINTER(result);
}


/* Helper functions for picksplit. We might need to sort a list of
 * ranges by size; these are for that.
 */

struct gip6r_sort
{
    IP6R *key;
    OffsetNumber pos;
};

static int
gip6r_sort_compare(const void *a, const void *b)
{
    double sa = ip6r_metric(((struct gip6r_sort *)a)->key);
    double sb = ip6r_metric(((struct gip6r_sort *)b)->key);
    return (sa > sb) ? 1 : ((sa == sb) ? 0 : -1);
}

/*
** The GiST PickSplit method for IP ranges
** This is a linear-time algorithm based on a left/right split,
** based on the box functions in rtree_gist simplified to one
** dimension
*/
PG_FUNCTION_INFO_V1(gip6r_picksplit);
Datum
gip6r_picksplit(PG_FUNCTION_ARGS)
{
    GistEntryVector *entryvec = (GistEntryVector *) PG_GETARG_POINTER(0);
    GIST_SPLITVEC *v = (GIST_SPLITVEC *) PG_GETARG_POINTER(1);
    GISTENTRY *ent = GISTENTRYVEC(entryvec);
    OffsetNumber i;
    int nbytes;
    OffsetNumber maxoff;
    OffsetNumber *listL;
    OffsetNumber *listR;
    bool allisequal = true;
    IP6R pageunion;
    IP6R *cur;
    IP6R *unionL;
    IP6R *unionR;
    int posL = 0;
    int posR = 0;

    posL = posR = 0;
    maxoff = GISTENTRYCOUNT(entryvec) - 1;

    cur = (IP6R *) DatumGetPointer(ent[FirstOffsetNumber].key);
    pageunion = *cur;

    /* find MBR */
    for (i = OffsetNumberNext(FirstOffsetNumber); i <= maxoff; i = OffsetNumberNext(i))
    {
        cur = (IP6R *) DatumGetPointer(ent[i].key);
        if (allisequal == true && !ip6r_equal(&pageunion,cur))
            allisequal = false;

        if (ip6_lessthan(&cur->lower,&pageunion.lower))
            pageunion.lower = cur->lower;
        if (ip6_lessthan(&pageunion.upper,&cur->upper))
            pageunion.upper = cur->upper;
    }

    nbytes = (maxoff + 2) * sizeof(OffsetNumber);
    listL = (OffsetNumber *) palloc(nbytes);
    listR = (OffsetNumber *) palloc(nbytes);
    unionL = palloc(sizeof(IP6R));
    unionR = palloc(sizeof(IP6R));
    v->spl_ldatum = PointerGetDatum(unionL);
    v->spl_rdatum = PointerGetDatum(unionR);
    v->spl_left = listL;
    v->spl_right = listR;

    if (allisequal)
    {
        cur = (IP6R *) DatumGetPointer(ent[OffsetNumberNext(FirstOffsetNumber)].key);
        if (ip6r_equal(cur, &pageunion))
        {
            OffsetNumber split_at = FirstOffsetNumber + (maxoff - FirstOffsetNumber + 1)/2;
            v->spl_nleft = v->spl_nright = 0;
            *unionL = pageunion;
            *unionR = pageunion;

            for (i = FirstOffsetNumber; i < split_at; i = OffsetNumberNext(i))
                v->spl_left[v->spl_nleft++] = i;
            for (; i <= maxoff; i = OffsetNumberNext(i))
                v->spl_right[v->spl_nright++] = i;

            PG_RETURN_POINTER(v);
        }
    }

#define ADDLIST( list_, u_, pos_, num_ ) do { \
        if ( pos_ ) { \
            if ( ip6_lessthan(&(u_)->upper, &(cur)->upper) ) (u_)->upper = (cur)->upper; \
            if ( ip6_lessthan(&(cur)->lower, &(u_)->lower) ) (u_)->lower = (cur)->lower; \
        } else { \
                *(u_) = *(cur); \
        } \
        (list_)[(pos_)++] = (num_); \
} while(0)

    for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
    {
        IP6 diff1;
        IP6 diff2;

        cur = (IP6R *) DatumGetPointer(ent[i].key);
        ip6_sub(&cur->lower, &pageunion.lower, &diff1);
        ip6_sub(&pageunion.upper, &cur->upper, &diff2);
        if (ip6_lessthan(&diff1,&diff2))
            ADDLIST(listL, unionL, posL, i);
        else
            ADDLIST(listR, unionR, posR, i);
    }

    /* bad disposition, sort by ascending size and resplit */
    if (posR == 0 || posL == 0)
    {
        struct gip6r_sort *arr = (struct gip6r_sort *)
            palloc(sizeof(struct gip6r_sort) * (maxoff + FirstOffsetNumber));

        for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
        {
            arr[i].key = (IP6R *) DatumGetPointer(ent[i].key);
            arr[i].pos = i;
        }

        qsort(arr + FirstOffsetNumber,
              maxoff - FirstOffsetNumber + 1,
              sizeof(struct gip6r_sort),
              gip6r_sort_compare);

        posL = posR = 0;
        for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
        {
            IP6 diff1;
            IP6 diff2;

            cur = arr[i].key;
            ip6_sub(&cur->lower, &pageunion.lower, &diff1);
            ip6_sub(&pageunion.upper, &cur->upper, &diff2);

            if (ip6_lessthan(&diff1,&diff2))
                ADDLIST(listL, unionL, posL, arr[i].pos);
            else if (ip6_equal(&diff1,&diff2))
            {
                if (posL > posR)
                    ADDLIST(listR, unionR, posR, arr[i].pos);
                else
                    ADDLIST(listL, unionL, posL, arr[i].pos);
            }
            else
                ADDLIST(listR, unionR, posR, arr[i].pos);
        }
        pfree(arr);
    }

    v->spl_nleft = posL;
    v->spl_nright = posR;

    PG_RETURN_POINTER(v);
}

#undef ADDLIST

/*
** Equality methods
*/
PG_FUNCTION_INFO_V1(gip6r_same);
Datum
gip6r_same(PG_FUNCTION_ARGS)
{
    IP6R *v1 = (IP6R *) PG_GETARG_POINTER(0);
    IP6R *v2 = (IP6R *) PG_GETARG_POINTER(1);
    bool *result = (bool *) PG_GETARG_POINTER(2);

    if (v1 && v2)
        *result = ip6r_equal(v1,v2);
    else
        *result = (v1 == NULL && v2 == NULL);

#ifdef GIST_DEBUG
    fprintf(stderr, "same: %s\n", (*result ? "TRUE" : "FALSE"));
#endif

    PG_RETURN_POINTER(result);
}


/*
 * Strategy numbers:
 *      OPERATOR        1       >>= ,
 *      OPERATOR        2       <<= ,
 *      OPERATOR        3       >> ,
 *      OPERATOR        4       << ,
 *      OPERATOR        5       && ,
 *      OPERATOR        6       = ,
 */

/*
** SUPPORT ROUTINES
*/
static bool
gip6r_leaf_consistent(IP6R * key,
                      IP6R * query,
                      StrategyNumber strategy)
{
#ifdef GIST_QUERY_DEBUG
    fprintf(stderr, "leaf_consistent, %d\n", strategy);
#endif
  
    switch (strategy)
    {
        case 1:   /* left contains right nonstrict */
            return ip6r_contains_internal(key, query, TRUE);
        case 2:   /* left contained in right nonstrict */
            return ip6r_contains_internal(query, key, TRUE);
        case 3:   /* left contains right strict */
            return ip6r_contains_internal(key, query, FALSE);
        case 4:   /* left contained in right strict */
            return ip6r_contains_internal(query, key, FALSE);
        case 5:   /* left overlaps right */
            return ip6r_overlaps_internal(key, query);
        case 6:   /* left equal right */
            return ip6r_equal(key, query);
        default:
            return FALSE;
    }
}

/* logic notes:
 * If the union value we're looking at overlaps with our query value
 * at all, then any of the values underneath it might overlap with us
 * or be contained by us, so all the "contained by" and "overlaps"
 * cases degenerate to "overlap".
 * If the union value is equal to the query value, then none of the
 * values under it can strictly contain the query value, so for
 * "contained" queries the strictness is preserved.
 * If we're looking for an "equal" value, then we have to enter any
 * subtree whose union contains (not strictly) our query value.
 */

bool
gip6r_internal_consistent(IP6R * key,
                          IP6R * query,
                          StrategyNumber strategy)
{
#ifdef GIST_QUERY_DEBUG
    fprintf(stderr, "internal_consistent, %d\n", strategy);
#endif
  
    switch (strategy)
    {
        case 2:   /* left contained in right nonstrict */
        case 4:   /* left contained in right strict */
        case 5:   /* left overlaps right */
            return ip6r_overlaps_internal(key, query);
        case 3:   /* left contains right strict */
            return ip6r_contains_internal(key, query, FALSE);
        case 1:   /* left contains right nonstrict */
        case 6:   /* left equal right */
            return ip6r_contains_internal(key, query, TRUE);
        default:
            return FALSE;
    }
}

/* end */
