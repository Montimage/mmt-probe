###################################################
# COMPILE MMT-Probe USING DPDK TO CAPTURE PACKETS #
###################################################

# DPDK supports building using Makefile until version 20.08 (using meson+ninja after that)
# So this compilation works only for DPDK <= 20.08
# To build DPDK: http://doc.dpdk.org/guides-20.08/linux_gsg/build_dpdk.html#installation-of-dpdk-target-environment-using-make
#
# For example (DPDK 20.08):
#
# make config T=x86_64-native-linux-gcc O=build
# vi build/.config
#   change "CONFIG_RTE_EAL_IGB_UIO=n" to "CONFIG_RTE_EAL_IGB_UIO=y"
# make -j2
# make install O=build DESTDIR=myinstall prefix=

#this avoids DPDK pausing to print deprecation message (as it prefers menson+ninja)
MAKE_PAUSE=n

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