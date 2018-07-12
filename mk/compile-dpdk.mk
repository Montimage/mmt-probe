###################################################
# COMPILE MMT-Probe USING DPDK TO CAPTURE PACKETS #
###################################################

#DPDK variables
RTE_SDK    ?= /home/mmt/huunghia/dpdk-stable-17.11.3
RTE_TARGET ?= build

#avoid being overried by DPDK
_OLD_CFLAGS := $(CFLAGS)

#build is not a file target, 
.PHONY: compile

#default target
.DEFAULT_GOAL := compile

include $(RTE_SDK)/mk/rte.vars.mk

#DPDK variables
CFLAGS += $(_OLD_CFLAGS)
LDLIBS += $(LIBS)
SRCS-y := $(ALL_SRCS)

ifdef VERBOSE
  V = @
  Q = @
endif

#This variable will tell DPDK the targets to be executed after building
POSTBUILD += --private-copy-probe

#copy probe from the build folder to the current folder
--private-copy-probe:
	$(QUIET)$(CP) $(TOP_DIR)/build/$(APP) $(TOP_DIR)

compile: --check-security-folder --check-dpi-folder all

include $(RTE_SDK)/mk/rte.extapp.mk