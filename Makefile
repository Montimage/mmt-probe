ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

#Name of executable file to generate
APP = dpdk_probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.0

SRCS-y := src/smp_main.c  src/processing.c src/web_session_report.c src/thredis.c \
src/send_msg_to_file.c src/send_msg_to_redis.c src/ip_statics.c src/rtp_session_report.c src/ftp_session_report.c \
src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c src/default_app_session_report.c \
src/microflows_session_report.c src/radius_reporting.c src/security_analysis.c src/parseoptions.c src/license.c src/dpdk_capture.c \
src/lib/data_spsc_ring.c src/lib/lock_free_spsc_ring.c src/lib/packet_hash.c src/lib/system_info.c

#set of library
LDLIBS    += -L /opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -lpcap -lconfuse -lhiredis -lpthread -lm 

CFLAGS += $(WERROR_CFLAGS) -g -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -Wall -Wno-unused-variable 
#CFLAGS   = -Wall -Wno-unused-variable -DNDEBUG -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"
CLDFLAGS += -I /opt/mmt/dpi/include -DNDEBUG
 

ifndef VERBOSE
	QUIET := @
endif

include $(RTE_SDK)/mk/rte.extapp.mk


