/* ip4r_module.c */

#include "postgres.h"
#include "fmgr.h"

#include "ipr_internal.h"

#if PG_VERSION_NUM >= 180000
PG_MODULE_MAGIC_EXT(.name = "ip4r", .version = IP4R_VERSION_STR);
#else
PG_MODULE_MAGIC;
#endif

/* end */
