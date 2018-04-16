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

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.2.2

$(info Building MMT-Probe version $(VERSION) $(GIT_VERSION))

#set of library
LIBS     := -L/opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -lconfuse -lpthread 
CFLAGS   := -I /opt/mmt/dpi/include -Wall -Wno-unused-variable\
			   -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"

ifdef ALL_OPTIONS
	DEBUG := 1
	VALGRIND := 1
	HTTP_RECONSTRUCT := 1
	KAFKA := 1
	REDIS := 1
	SECURITY := 1
endif


LIB_SRCS    := $(wildcard src/lib/*.c)
LIB_SRCS    += src/configure.c src/worker.c

#################################################
############ OTHER SETTING ######################
#################################################
#for debuging
ifdef DEBUG
$(warning - Enable DEBUG)
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
	CFLAGS 	  += -DNDEBUG
endif

ifdef SIMPLE_REPORT
$(info - Enable SIMPLE_REPORT (output simple reports for MMT-Box) )
	CFLAGS      += -DSIMPLE_REPORT
else
$(info -> Disable SIMPLE_REPORT (output normal reports))
endif

# check license
ifdef LICENSE
$(info - Enable LICENSE checking)
	CFLAGS      += -DLICENSE_CHECK
else
$(info -> Disable LICENSE checking)
#exclude license.c
	LIB_SRCS := $(filter-out src/lib/license.c, $(LIB_SRCS))
endif

MODULE_SRCS := $(wildcard src/modules/output/*.c)
MODULE_SRCS += $(wildcard src/modules/output/file/*.c)
MODULE_SRCS += $(wildcard src/modules/dpi/*.c)
MODULE_SRCS += $(wildcard src/modules/dpi/report/*.c)
MODULE_SRCS += $(wildcard src/modules/routine/*.c)
#################################################
########### MODULES #############################
#################################################

# For HTTP reconstruction option
ifdef HTTP_RECONSTRUCT
$(info - Enable HTTP_RECONSTRUCT)
	LIBS        += -lhtmlstreamparser -lz
	CFLAGS      += -DHTTP_RECONSTRUCT_MODULE
	MODULE_SRCS += $(wildcard src/modules/construct_http/*.c)
else
$(info -> Disable HTTP_RECONSTRUCT)
endif

ifdef KAFKA
$(info - Enable KAFKA)
	LIBS        += -lrdkafka
	CFLAGS      += -I /usr/local/include/librdkafka -DKAFKA_MODULE
	MODULE_SRCS += $(wildcard src/modules/output/kafka/*.c)
else
$(info -> Disable KAFKA)
endif

ifdef MONGODB
$(info - Enable MONGODB)
	LIBS        += -L/usr/lib/x86_64-linux-gnu/ -lmongoc-1.0 -lbson-1.0
	CFLAGS      += -DMONGODB_MODULE -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0
	MODULE_SRCS += $(wildcard src/modules/output/mongodb/*.c)
else
$(info -> Disable MONGODB)
endif

ifdef REDIS
$(info - Enable REDIS)
	LIBS        += -lhiredis
	CFLAGS      += -DREDIS_MODULE
	MODULE_SRCS += $(wildcard src/modules/output/redis/*.c)
else
$(info -> Disable REDIS)
endif

ifdef NETCONF
$(info - Enable NETCONF)
	LIBS        += -lrt -lsysrepo -lxml2
	CFLAGS      += -DNETCONF_MODULE
	MODULE_SRCS += $(wildcard src/modules/netconf/*.c)
else
$(info -> Disable NETCONF)
endif

ifdef DYNAMIC_CONFIG
$(info - Enable DYNAMIC_CONFIG)
	CFLAGS      += -DDYNAMIC_CONFIG_MODULE
	MODULE_SRCS += $(wildcard src/modules/dynamic_conf/*.c)
else
$(info -> Disable DYNAMIC_CONFIG)
endif

ifdef SECURITY
$(info - Enable SECURITY)
	LIBS        += -L/opt/mmt/security/lib -lmmt_security2 -lxml2
	CFLAGS      += -I /opt/mmt/security/include -DSECURITY_MODULE
	MODULE_SRCS += $(wildcard src/modules/security/*.c)
else
$(info -> Disable SECURITY)
endif


MAIN_SRCS := src/main.c

#################################################
############ CAPTURE PACKETS ####################
#################################################
ifdef DPDK
$(info - Use DPDK to capture packet $(RTE_SDK))
	#dpdk makefile
	ifndef RTE_SDK
#$(error RTE_SDK is not set)
	endif
   RTE_SDK    ?= /home/mmt/mmt/dpdk-stable-17.11.1
   RTE_TARGET ?= build

	#avoid being overried by DPDK
	_OLD_CFLAGS := $(CFLAGS) -DDPDK_MODULE

	include $(RTE_SDK)/mk/rte.vars.mk

   CFLAGS += $(WERROR_CFLAGS) $(_OLD_CFLAGS)
   LDLIBS += $(LIBS) 
   
	#DPDK variable
	#SRCS-y := $(wildcard src/lib/*.c) $(MODULE_SRCS) $(wildcard src/modules/packet_capture/dpdk/*.c) $(MAIN_SRCS)
   SRCS-y := src/lib/pcap_dump.c src/lib/system_info.c src/lib/configure.c src/lib/base64.c src/lib/valgrind.c src/lib/version.c src/lib/timer.c src/lib/worker.c src/modules/output/output.c src/modules/output/file/file_output.c src/modules/dpi/session_report.c src/modules/dpi/no_session_report.c src/modules/dpi/session_report_web.c src/modules/dpi/dump_data.c src/modules/dpi/dpi.c src/modules/dpi/event_based_report.c src/modules/dpi/session_report_ssl.c src/modules/packet_capture/dpdk/dpdk_capture.c src/modules/packet_capture/dpdk/distributor.c src/main.c
   
   V      := $(VERBOSE)
   
$(info $(SRCS-y))
   
include $(RTE_SDK)/mk/rte.extapp.mk
   
   
else #for PCAP

$(info - Use PCAP to capture packet)
	CFLAGS      += -DPCAP_MODULE
	LIBS        += -lpcap -ldl
	MODULE_SRCS += $(wildcard src/modules/packet_capture/pcap/*.c)

# PCAP COMPILE

MODULE_OBJS := $(patsubst %.c,%.o, $(MODULE_SRCS))
LIB_OBJS    := $(patsubst %.c,%.o, $(LIB_SRCS))
MAIN_OBJS   := $(patsubst %.c,%.o, $(MAIN_SRCS))

all: $(LIB_OBJS) $(MODULE_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(MODULE_OBJS) $(OUTPUT)
	
endif


#################################################
############ PACKAGE & INSTALL ##################
#################################################
#temp folder to contain installed files
FACE_ROOT_DIR=/tmp/probe/$(INSTALL_DIR)
#
# Install probe
#
copy_files: all
#create dir
	$(QUIET) $(RM) $(FACE_ROOT_DIR)
	$(QUIET) $(MKDIR) $(FACE_ROOT_DIR)/bin \
		$(FACE_ROOT_DIR)/log/online \
		$(FACE_ROOT_DIR)/log/offline \
		$(FACE_ROOT_DIR)/result/report/offline \
		$(FACE_ROOT_DIR)/result/report/online \
		$(FACE_ROOT_DIR)/result/behaviour/online \
		$(FACE_ROOT_DIR)/result/behaviour/offline \
		$(FACE_ROOT_DIR)/result/security/online \
		$(FACE_ROOT_DIR)/result/security/offline

#copy probe to existing dir from buit in DPDK
	ifdef DPDK
		$(QUIET) $(CP) $(OUTPUT_DIR)/probe $(TOP)
	endif

#copy to bin
	$(QUIET) $(CP) $(APP)           $(FACE_ROOT_DIR)/bin/probe

	$(QUIET) $(CP) mmt_online.conf  $(FACE_ROOT_DIR)/mmt-probe.conf

	@echo


create: copy_files
	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(CP) -r $(FACE_ROOT_DIR)/* $(INSTALL_DIR)

SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)

ifdef DPDK
	PACKAGE_NAME = mmt-probe_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)_dpdk
else
	PACKAGE_NAME = mmt-probe_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)_pcap
endif

copy_libs: copy_files
	$(QUIET) $(RM) $(PACKAGE_NAME)
	
	$(QUIET) $(MKDIR) $(PACKAGE_NAME)/usr/bin/
	$(QUIET) ln -s /opt/mmt/probe/bin/probe $(PACKAGE_NAME)/usr/bin/mmt-probe
	
	$(QUIET) $(MKDIR) $(PACKAGE_NAME)/etc/ld.so.conf.d/
	@echo "/opt/mmt/probe/lib" >> $(PACKAGE_NAME)/etc/ld.so.conf.d/mmt-probe.conf
	
	$(QUIET) $(MKDIR) $(PACKAGE_NAME)$(INSTALL_DIR)
	$(QUIET) $(CP) -r $(FACE_ROOT_DIR)/* $(PACKAGE_NAME)$(INSTALL_DIR)
	
	$(QUIET) $(MKDIR) $(PACKAGE_NAME)$(INSTALL_DIR)/lib
	
	ifdef REDIS_MODULE
		$(QUIET) $(CP) /usr/local/lib/libhiredis.so.*  $(PACKAGE_NAME)$(INSTALL_DIR)/lib
	endif
	
	ifdef KAFKA_MODULE
		$(QUIET) $(CP) /usr/local/lib/librdkafka.so.*  $(PACKAGE_NAME)$(INSTALL_DIR)/lib
	endif
	$(QUIET) $(CP) /lib64/libconfuse.so.*  $(PACKAGE_NAME)$(INSTALL_DIR)/lib/

#package for Debian-based
deb: copy_libs
	echo $(PACKAGE_NAME)
	$(QUIET) $(MKDIR) $(PACKAGE_NAME)/DEBIAN
	$(QUIET) echo "Package: mmt-probe \
        \nVersion: $(VERSION) \
        \nSection: base \
        \nPriority: standard \
        \nDepends: mmt-dpi, mmt-security \
        \nArchitecture: all \
        \nMaintainer: Montimage <contact@montimage.com> \
        \nDescription: MMT-Probe:  \
        \n  Version id: $(GIT_VERSION). Build time: `date +"%Y-%m-%d %H:%M:%S"` \
        \nHomepage: http://www.montimage.com" \
		> $(PACKAGE_NAME)/DEBIAN/control

	$(QUIET) dpkg-deb -b $(PACKAGE_NAME)
	$(QUIET) $(RM) $(PACKAGE_NAME)
	$(QUIET) $(RM) $(FACE_ROOT_DIR)
	
#package for CentOS
rpm: copy_libs
	$(QUIET) $(MKDIR) ./rpmbuild/{RPMS,BUILD}
	
	$(QUIET) echo -e\
      "Summary:  MMT-Probe\
      \nName: mmt-probe\
      \nVersion: $(VERSION)\
      \nRelease: $(GIT_VERSION)\
      \nLicense: proprietary\
      \nGroup: Development/Tools\
      \nURL: http://montimage.com/\
      \n\
      \nRequires:  mmt-dpi >= 1.6.9, mmt-security >= 1.1.5\
      \nBuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}\
      \n\
      \n%description\
      \nMMT-Probe is a tool to analyze network traffic.\
      \nBuild date: `date +"%Y-%m-%d %H:%M:%S"`\
      \n\
      \n%prep\
      \nrm -rf %{buildroot}\
      \nmkdir -p %{buildroot}\
      \ncp -r %{_topdir}/../$(PACKAGE_NAME)/* %{buildroot}/\
      \n\
      \n%clean\
      \nrm -rf %{buildroot}\
      \n\
      \n%files\
      \n%defattr(-,root,root,-)\
      \n/opt/mmt/probe/*\
      \n/usr/bin/mmt-probe\
      \n/etc/ld.so.conf.d/mmt-probe.conf\
      \n%post\
      \nldconfig\
   " > ./mmt-probe.spec
	
	$(QUIET) rpmbuild --quiet --rmspec --define "_topdir $(shell pwd)/rpmbuild" --define "_rpmfilename ../../$(PACKAGE_NAME).rpm" -bb ./mmt-probe.spec
	$(QUIET) $(RM) rpmbuild
	@echo "[PACKAGE] $(PACKAGE_NAME).rpm"
	
	$(QUIET) $(RM) $(PACKAGE_NAME)
	$(QUIET) $(RM) $(FACE_ROOT_DIR)

keygen:
	$(QUIET) $(CC) -o keygen $(CLDFLAGS)  key_generator.c
		
dist-clean:
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	$(QUIET) $(RM) -rf /etc/init.d/probe_*_d
