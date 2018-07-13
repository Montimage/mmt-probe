MKDIR  = mkdir -p
CC     = gcc
CXX    = g++ -std=c++11
CP     = cp
RM     = rm -rf

ifndef TOP_DIR
  #current directory
  TOP_DIR := $(shell pwd)
  #we need to export this variable for the second call by DPDK, eventually
  export TOP_DIR
endif
SRC_DIR := $(TOP_DIR)/src

#installation directory
ifndef MMT_BASE
  MMT_BASE             := /opt/mmt
  NEED_ROOT_PERMISSION := 1
else
  $(info INFO: Set default folder of MMT to $(MMT_BASE))
endif

INSTALL_DIR       := $(MMT_BASE)/probe
# Directory where MMT-Security was installed
MMT_SECURITY_DIR  := $(MMT_BASE)/security
# Directory where MMT-DPI was installed
MMT_DPI_DIR       := $(MMT_BASE)/dpi

	
#Name of executable file to generate
APP = probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.4.0

$(info INFO: MMT-Probe version $(VERSION) $(GIT_VERSION) ($(MAKECMDGOALS)))


#set of library
LIBS     := -L$(MMT_DPI_DIR)/lib     -lconfuse -lpthread 
CFLAGS   := -I$(MMT_DPI_DIR)/include -Wall -Wno-unused-variable\
			   -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"

#intermediate targets
#This function will create a dummy target naming by its first parameter, e.g., VERBOSE
# when user call the target, it will set an environment variable having the same name
# Example: 
#     $(eval $(call EXPORT_TARGET,VERBOSE))
# => when user do: make VERBOSE
# =>  env variable VERBOSE will be defined to 1
define EXPORT_TARGET
$(1): ;@:

ifneq (,$(findstring $(1),$(MAKECMDGOALS)))
  export $(1)=1
endif

endef


# embedded MMT libraries into probe
$(eval $(call EXPORT_TARGET,STATIC_LINK))
ifdef STATIC_LINK
  CFLAGS += -DSTATIC_LINK
  LIBS   += -l:libmmt_tcpip.a -l:libmmt_core.a
else
  LIBS   += -l:libmmt_core.so
endif


# to print more details of compiling process
$(eval $(call EXPORT_TARGET,VERBOSE))
ifndef VERBOSE
  QUIET := @
endif

# to enable debug information, e.g., to be able to used by gdb
$(eval $(call EXPORT_TARGET,DEBUG))
ifdef DEBUG
$(info - Enable DEBUG)
  CFLAGS   += -g -O0 -DDEBUG_MODE
else
  CFLAGS   += -O3
endif

#for valgrind check
ifdef VALGRIND
	CFLAGS += -DVALGRIND_MODE
endif

# For showing message from debug(...)
ifndef NDEBUG
  CFLAGS += -DNDEBUG
endif


-include mk/gperf.mk

-include mk/modules.mk


# Check if there exists the folder of MMT-Security.
#   We check only if SECURITY_MODULE is active
--check-security-folder:
ifdef SECURITY_MODULE
	@test -d $(MMT_SECURITY_DIR)                                                        \
		||( echo "ERROR: Not found MMT-Security at folder $(MMT_SECURITY_DIR)."          \
		&& exit 1                                                                        \
		)
endif

# check if there exists the folder of MMT-DPI 
--check-dpi-folder:
	@test -d $(MMT_DPI_DIR)                                                             \
		||( echo "ERROR: Not found MMT-DPI at folder $(MMT_DPI_DIR)."                    \
		&& exit 1                                                                        \
		)

CFLAGS += $(MODULE_FLAGS)
LIBS   += $(MODULE_LIBS)

# main source file
MAIN_SRCS := $(SRC_DIR)/main.c

#source files in lib/
LIB_SRCS = $(wildcard $(SRC_DIR)/lib/*.c) \
			  $(SRC_DIR)/configure.c $(SRC_DIR)/configure_override.c $(SRC_DIR)/worker.c

#all source code
ALL_SRCS  := $(LIB_SRCS) $(MODULE_SRCS) $(MAIN_SRCS)


ifdef DPDK_CAPTURE #use makefiles of dpdk
#we need explicitly TOP_DIR as this line will be called second times from ./build folder by dpdk
-include $(TOP_DIR)/mk/compile-dpdk.mk
else
-include mk/compile-pcap.mk
endif


#other makefiles
-include mk/serial-key.mk
-include mk/install-package.mk