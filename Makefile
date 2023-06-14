
EXTENSION= ip4r

MODULE_big = ip4r

SRC_SQL	= ip4r--2.4.sql \
	  ip4r--2.2--2.4.sql \
	  ip4r--2.1--2.2.sql \
	  ip4r--2.0--2.1.sql \
	  $(if $(call version_ge,$(MAJORVERSION),13),,$(SRC_OLD))
# "FROM unpackaged" was removed in pg13
SRC_OLD = ip4r--unpackaged2.1--2.1.sql \
	  ip4r--unpackaged2.0--2.0.sql \
	  ip4r--unpackaged1--2.0.sql
DATA	= $(addprefix scripts/, $(SRC_SQL))

objdir	= src

DOCS	= README.ip4r
OBJS_C	= ip4r_module.o ip4r.o ip6r.o ipaddr.o iprange.o raw_io.o
OBJS	= $(addprefix src/, $(OBJS_C))
INCS	= ipr.h ipr_internal.h

HEADERS = src/ipr.h

REGRESS = ip4r \
	  $(REGRESS_BY_VERSION)
REGRESS_V11 := ip4r-v11
REGRESS_V16 := ip4r-softerr

define REGRESS_BY_VERSION
$(strip
   $(foreach v,$(filter REGRESS_V%,$(.VARIABLES)),
      $(if $(call version_ge,$(MAJORVERSION),$(subst REGRESS_V,,$(v))),
           $($(v)))))
endef

# if VPATH is not already set, but the makefile is not in the current
# dir, then assume a vpath build using the makefile's directory as
# source. PGXS will set $(srcdir) accordingly.
ifndef VPATH
ifneq ($(realpath $(CURDIR)),$(realpath $(dir $(firstword $(MAKEFILE_LIST)))))
VPATH := $(dir $(firstword $(MAKEFILE_LIST)))
endif
endif

mklibdir := $(if $(VPATH),$(VPATH)/tools,tools)
include $(mklibdir)/numeric.mk

PG_CONFIG ?= pg_config
PGXS = $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

ifeq ($(call version_ge,$(MAJORVERSION),9.1),)
$(error unsupported PostgreSQL version)
endif

$(OBJS): $(addprefix $(srcdir)/src/, $(INCS))

# for a vpath build, we need src/ to exist in the build dir before
# building any objects.
ifdef VPATH
all: vpath-mkdirs
.PHONY: vpath-mkdirs
$(OBJS): | vpath-mkdirs

vpath-mkdirs:
	$(MKDIR_P) $(objdir)
endif # VPATH


# end
