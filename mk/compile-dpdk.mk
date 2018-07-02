#dpdk makefile
RTE_SDK    ?= /home/mmt/dpdk-stable-17.11.1
RTE_TARGET ?= build

#avoid being overried by DPDK
_OLD_CFLAGS := $(CFLAGS)

include $(RTE_SDK)/mk/rte.vars.mk

#build is not a file target, 
.PHONY : build
#default target
.DEFAULT_GOAL := build

#DPDK variable
CFLAGS += $(_OLD_CFLAGS)
LDLIBS += $(LIBS)
SRCS-y := $(ALL_SRCS)
V       = $(VERBOSE)

#copy probe from the build folder to the current folder
POSTBUILD += --private-copy-probe
--private-copy-probe:
	$(QUIET) $(CP) $(TOP_DIR)/build/$(APP) $(TOP_DIR)

include $(RTE_SDK)/mk/rte.extapp.mk