MKDIR  = mkdir -p
CC     = gcc
CP     = cp
RM     = rm -rf

#current directory
TOP_DIR := $(dir $(firstword $(MAKEFILE_LIST)))
SRC_DIR := $(TOP_DIR)src

#installation directory
INSTALL_DIR = /opt/mmt/probe

#install directory is given from cmd parameter
ifdef PREFIX
	INSTALL_DIR $= $(PREFIX)
endif

#Name of executable file to generate
APP = probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.2.2

$(info MMT-Probe version $(VERSION) $(GIT_VERSION) ($(MAKECMDGOALS)))

#set of library
LIBS     := -L/opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -lconfuse -lpthread 
CFLAGS   := -I /opt/mmt/dpi/include -Wall -Wno-unused-variable\
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

CFLAGS += $(MODULE_FLAGS)
LIBS   += $(MODULE_LIBS)

# main source file
MAIN_SRCS := $(SRC_DIR)/main.c

#source files in lib/
LIB_SRCS = $(wildcard $(SRC_DIR)/lib/*.c) \
			  $(SRC_DIR)/configure.c $(SRC_DIR)/configure_override.c $(SRC_DIR)/worker.c

#all source code
ALL_SRCS  := $(LIB_SRCS) $(MODULE_SRCS) $(MAIN_SRCS)

ifdef DPDK_CAPTURE #use makefiles of dpd
-include mk/compile-dpdk.mk
else
-include mk/compile-pcap.mk
endif

-include mk/serial-key.mk

-include mk/install-package.mk