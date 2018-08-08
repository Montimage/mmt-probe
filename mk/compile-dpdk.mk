###################################################
# COMPILE MMT-Probe USING DPDK TO CAPTURE PACKETS #
###################################################

#DPDK variables
ifndef RTE_SDK
  $(error Need RTE_SDK variable)
endif
#RTE_SDK    ?= /home/mmt/huunghia/dpdk-stable-17.11.3
RTE_TARGET ?= build

#avoid being overried by DPDK
_OLD_CFLAGS := $(CFLAGS)

include $(RTE_SDK)/mk/rte.vars.mk

#DPDK variables
CFLAGS += $(_OLD_CFLAGS)
LDLIBS += $(LIBS)
SRCS-y := $(ALL_SRCS)

ifdef VERBOSE
  V = @
  Q = @
endif

compile: --check-dpi-folder all
	@#copy probe from the build folder to the current folder
	$(QUIET)$(CP) $(TOP_DIR)/build/$(APP) $(TOP_DIR)

include $(RTE_SDK)/mk/rte.extapp.mk