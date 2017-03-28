
MODULE_big = ip4r

ifndef NO_EXTENSION
EXTENSION = ip4r
DATA = ip4r--2.2.sql \
       ip4r--2.1--2.2.sql \
       ip4r--2.0--2.1.sql \
       ip4r--unpackaged2.1--2.1.sql \
       ip4r--unpackaged2.0--2.0.sql \
       ip4r--unpackaged1--2.0.sql
REGRESS = ip4r
else
DATA_built = ip4r.sql
EXTRA_CLEAN += ip4r.sql.in sql/ip4r-legacy.sql expected/ip4r-legacy.out
REGRESS = ip4r-legacy
endif

DOCS = README.ip4r
OBJS = ip4r_module.o ip4r.o ip6r.o ipaddr.o iprange.o raw_io.o

ifndef NO_PGXS
PG_CONFIG = pg_config
PGXS = $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/ip4r
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

ifeq ($(filter-out 7.% 8.0 8.1 8.2 8.3, $(MAJORVERSION)),)
$(error unsupported PostgreSQL version)
endif

ifndef EXTENSION

ifeq ($(filter-out 8.4, $(MAJORVERSION)),)

ip4r.sql.in: ip4r--2.2.sql legacy.sed
	sed -f legacy.sed $< | sed -e '/^DO /,/^[$$]/d' >$@

else

ip4r.sql.in: ip4r--2.2.sql legacy.sed
	sed -f legacy.sed $< >$@

endif

sql/ip4r-legacy.sql: sql/ip4r.sql legacy-r.sed
	sed -f legacy-r.sed $< >$@

expected/ip4r-legacy.out: expected/ip4r.out
	sed -f legacy-r.sed $< | sed -e '/^\\i /,+1d' >$@

installcheck: sql/ip4r-legacy.sql expected/ip4r-legacy.out

else
ifeq ($(filter-out 8.% 9.0, $(MAJORVERSION)),)
$(error extension build not supported in versions before 9.1, use NO_EXTENSION=1)
endif
endif

