#Save files to
INSTALL_DIR = /opt/mmt/probe
MKDIR  = mkdir -p
TOP ?= $(shell pwd)
OUTPUT_DIR =$(TOP)/build
CC     = gcc-4.9
CP     = cp
RM     = rm -rf

#Name of executable file to generate
APP = probe


ifndef VERBOSE
        QUIET := @
endif

ifdef DPDK
RTE_SDK=/home/server10g/dpdk
RTE_TARGET=build
ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

#Name of executable file to generate
#APP = probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.0

SRCS-y := src/smp_main.c  src/processing.c src/web_session_report.c src/thredis.c \
src/send_msg_to_file.c src/send_msg_to_redis.c src/ip_statics.c src/init_socket.c src/rtp_session_report.c src/ftp_session_report.c \
src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c src/default_app_session_report.c \
src/microflows_session_report.c src/radius_reporting.c src/security_analysis.c src/parseoptions.c src/license.c src/dpdk_capture.c \
src/lib/security.c src/lib/data_spsc_ring.c src/lib/lock_free_spsc_ring.c src/lib/packet_hash.c src/lib/system_info.c src/attributes_extraction.c \
src/multisession_reporting.c src/security_msg_reporting.c src/condition_based_reporting.c  src/pcap_capture.c

#set of library
LDLIBS   += -L/opt/mmt/dpi/lib -L/opt/mmt/security/lib -lmmt_core -lmmt_tcpip -lmmt_security -lmmt_security2 -lxml2 -lpcap -lconfuse -lhiredis -lpthread
CFLAGS   += $(WERROR_CFLAGS) -O3 -I /opt/mmt/dpi/include -I /opt/mmt/security/include -Wall -Wno-unused-variable -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DDPDK
#CFLAGS   = -Wall -Wno-unused-variable -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"
CLDFLAGS += -I /opt/mmt/dpi/include
 
include $(RTE_SDK)/mk/rte.extapp.mk

#copy probe to current folder
#	$(CP) $(OUTPUT_DIR)/probe $(TOP)

endif
# End of DPDK

ifdef PCAP
#name of executable file to generate
#APP = probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.0


#set of library
LIBS     = -L /opt/mmt/dpi/lib -L/opt/mmt/security/lib -lmmt_core -lmmt_tcpip -lmmt_security -lmmt_security2 -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread

CFLAGS   = -Wall -Wno-unused-variable -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DPCAP
CLDFLAGS = -I /opt/mmt/dpi/include -I /opt/mmt/security/include

#for debuging
ifdef DEBUG
	CFLAGS   += -g -O0
	CLDFLAGS += -g -O0
else
	CFLAGS   += -O3
	CLDFLAGS += -O3
endif

# For HTTP reconstruction option
ifdef HTTP_RECONSTRUCT
LIBS     += -lhtmlstreamparser -lz
CFLAGS   += -DHTTP_RECONSTRUCT
endif

#folders containing source files
SRCDIR = src

#objects to generate
LIB_OBJS :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/lib/*.c)) \

#filter out 2 files: src/main.c and src/test_probe.c
MAIN_SRCS := $(wildcard   $(SRCDIR)/*.c)
MAIN_SRCS := $(filter-out $(SRCDIR)/main.c,       $(MAIN_SRCS))
MAIN_SRCS := $(filter-out $(SRCDIR)/test_probe.c, $(MAIN_SRCS))

MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS)) \

all: $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT)
		
endif

ifndef NDEBUG
CLDFLAGS   += -DNDEBUG
CFLAGS 	   += -DNDEBUG
endif

#
# Install probe
#
create: 
	@echo "Installing probe on" $(INSTALL_DIR)
#create dir
	$(QUIET) $(MKDIR) $(INSTALL_DIR)/bin $(INSTALL_DIR)/conf \
		$(INSTALL_DIR)/log/online \
		$(INSTALL_DIR)/log/offline \
		$(INSTALL_DIR)/result/report/offline \
		$(INSTALL_DIR)/result/report/online \
		$(INSTALL_DIR)/result/behaviour/online \
		$(INSTALL_DIR)/result/behaviour/offline \
		$(INSTALL_DIR)/result/security/online \
		$(INSTALL_DIR)/result/security/offline

#copy probe to existing dir from buit in DPDK
ifdef DPDK
	$(QUIET) $(CP) $(OUTPUT_DIR)/probe $(TOP)
endif

#copy to bin
	$(QUIET) $(CP) $(APP) $(INSTALL_DIR)/bin/probe


#create link
#	$(QUIET) $(CP) $(INSTALL_DIR)/bin/probe $(INSTALL_DIR)/bin/probe_online
#	$(QUIET) $(CP) $(INSTALL_DIR)/bin/probe $(INSTALL_DIR)/bin/probe_offline
#copy config files
	$(QUIET) $(CP) mmt_offline.conf $(INSTALL_DIR)/conf/offline.conf
	$(QUIET) $(CP) mmt_online.conf  $(INSTALL_DIR)/conf/online.conf
#install deamon -e: regex expression
	$(QUIET) sed "s|/opt/mmt/probe|$(INSTALL_DIR)|g" daemon.sh  > /tmp/probe_daemon
	$(QUIET) sed "s|runing_mode|online|g" /tmp/probe_daemon     > /etc/init.d/probe_online_d
	$(QUIET) sed "s|runing_mode|offline|g" /tmp/probe_daemon    > /etc/init.d/probe_offline_d
	$(QUIET) chmod +x /etc/init.d/probe_*_d
#
	@echo
	@echo "To run probe online: sudo service probe_online_d start"
	@echo "online's config file is located at " $(INSTALL_DIR)/conf/online.conf
	@echo

keygen:
	$(QUIET) $(CC) -o keygen $(CLDFLAGS)  key_generator.c
		
dist-clean:
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	$(QUIET) $(RM) -rf /etc/init.d/probe_*_d
