##--
## Hacks for numeric comparisons.

# $(call version_ge,a,b)
#  true iff a >= b when treated as vectors of integers separated by . or space
version_ge = $(strip $(call vge_2,$(subst ., ,$(1)),$(subst ., ,$(2))))

# if a is empty, result is true if b is empty otherwise false.
# if b is empty, result is true.
# if neither is empty, compare first words; if equal, strip one word and recurse.
define vge_2
$(if $(strip $(1)),
     $(if $(strip $(2)),
          $(if $(call numeric_lt,$(firstword $(2)),$(firstword $(1))),
               t,
               $(if $(call numeric_lt,$(firstword $(1)),$(firstword $(2))),
                    ,
                    $(call vge_2,
                           $(wordlist 2,$(words $(1)),$(1)),
                           $(wordlist 2,$(words $(2)),$(2))))),
          t),
     $(if $(strip $(2)),,t))
endef

# $(call numeric_le,a,b)  - true if a <= b, i.e. either a is 0 or a can index a [1..b] list
numeric_le = $(if $(filter 0,$(1)),t,$(word $(1),$(call nwords,$(2),)))

# $(call numeric_lt,a,b)  - true if a < b, i.e. !(b <= a)
numeric_lt = $(if $(call numeric_le,$(2),$(1)),,t)

# list of N words
nwords = $(if $(filter-out 0,$(1)),$(if $(word $(1),$(2)),$(2),$(call nwords,$(1),$(2) t)))

## end of hacks.
##--
