##

include tools/numeric.mk

define assert
$(if $1,,$(error assert failed: $2))
endef

define assert_n
$(if $1,$(error assert_n failed: $2),)
endef

.PHONY: tools_test_numeric

tools_test_numeric:
    $(call assert_n,$(call version_ge,9.0,9.1))
    $(call assert,$(call version_ge,9.2,9.1))
    $(call assert,$(call version_ge,9.0,9.0))
    $(call assert_n,$(call version_ge,9.4,13))
