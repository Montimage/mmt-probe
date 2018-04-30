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

#opt_debug: 
#	$(eval DEBUG := 1 )

LIB_SRCS    := $(wildcard src/lib/*.c)
#LIB_SRCS    := $(wildcard src/*.c)
#LIB_SRCS    := $(filter-out src/main.c, $(LIB_SRCS)) #exclude main.c
LIB_SRCS    += src/configure.c src/configure_override.c src/worker.c

#################################################
############ OTHER SETTING ######################
#################################################
#for debuging
ifdef DEBUG
$(info - Enable DEBUG)
	CFLAGS   += -g -O0 -DDEBUG_MODE
else
$(info - Disable DEBUG)
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

ifdef PCAP_DUMP
$(info - Enable PCAP_DUMP)
	CFLAGS      += -DPCAP_DUMP_MODULE
	MODULE_SRCS += $(wildcard src/modules/dpi/pcap_dump/*.c)
else
$(info -> Disable PCAP_DUMP)
endif

ifdef SIMPLE_REPORT
undefine DISABLE_REPORT
endif

ifndef DISABLE_REPORT
$(info - Enable REPORT)
	CFLAGS      += -DSTAT_REPORT
	MODULE_SRCS += $(wildcard src/modules/dpi/report/*.c)
else
$(info -> Disable REPORT)
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
   RTE_SDK    ?= /home/mmt/dpdk-stable-17.11.1
   RTE_TARGET ?= build

	#avoid being overried by DPDK
	_OLD_CFLAGS = $(CFLAGS) -DDPDK_MODULE

	include $(RTE_SDK)/mk/rte.vars.mk

   CFLAGS += $(WERROR_CFLAGS) $(_OLD_CFLAGS)
   LDLIBS += $(LIBS) 
   
	#DPDK variable
	SRCS-y = $(MODULE_SRCS) $(wildcard src/modules/packet_capture/dpdk/*.c) $(MAIN_SRCS)
   #SRCS-y = src/lib/pcap_dump.c src/lib/system_info.c src/lib/configure.c src/lib/base64.c src/lib/valgrind.c src/lib/version.c src/lib/timer.c src/lib/worker.c src/modules/output/output.c src/modules/output/file/file_output.c src/modules/dpi/session_report.c src/modules/dpi/no_session_report.c src/modules/dpi/session_report_web.c src/modules/dpi/dump_data.c src/modules/dpi/dpi.c src/modules/dpi/event_based_report.c src/modules/dpi/session_report_ssl.c src/modules/packet_capture/dpdk/dpdk_capture.c src/modules/packet_capture/dpdk/distributor.c src/main.c
   
   V      := $(VERBOSE)
   
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

#internal target to be used by others
--private-copy-files: all
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
		$(FACE_ROOT_DIR)/result/security/offline \
		$(FACE_ROOT_DIR)/files \
      $(FACE_ROOT_DIR)/pcaps
#copy probe to existing dir from buit in DPDK
ifdef DPDK
	$(QUIET) $(CP) $(OUTPUT_DIR)/probe $(TOP)
endif
#copy to bin
	$(QUIET) $(CP) $(APP)           $(FACE_ROOT_DIR)/bin/probe
#configuration file
	$(QUIET) $(CP) mmt_online.conf  $(FACE_ROOT_DIR)/mmt-probe.conf


--private-check-root:
	$(QUIET) [ "$$(id -u)" != "0" ] && echo "ERROR: Need root privilege" && exit 1 || true

#copy binary file to $PATH
USR_BIN_FILE_PATH     = /usr/bin/mmt-probe
#copy binary file to service list
ETC_SERVICE_FILE_PATH = /etc/init.d/mmt-probe

install: --private-check-root --private-copy-files
#check if old version of MMT-Probe is existing
	$(QUIET) test -d $(INSTALL_DIR)                           \
		&& echo "ERROR: Old version of MMT-Probe is existing." \
		&& exit 1                                              \
		|| true

	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(CP) -r $(FACE_ROOT_DIR)/* $(INSTALL_DIR)
#create an alias
	$(QUIET) ln -s $(INSTALL_DIR)/bin/probe $(USR_BIN_FILE_PATH)
#create service
	$(QUIET) $(CP) daemon-service.sh  $(ETC_SERVICE_FILE_PATH)
	$(QUIET) chmod 0755               $(ETC_SERVICE_FILE_PATH)
	$(QUIET) systemctl daemon-reload
	@echo ""
	@echo "Successfully installed MMT-Probe on $(INSTALL_DIR)"
	@echo "You can start MMT-Probe by:"
	@echo " - either: sudo mmt-probe"
	@echo " - or    : sudo service mmt-probe start"

#internal target to be used to create distribution file: .deb or .rpm
--private-prepare-build: --private-copy-files
	$(QUIET) $(RM) $(DEB_NAME)

	$(QUIET) $(MKDIR) $(DEB_NAME)/usr/bin/
	$(QUIET) ln -s /opt/mmt/probe/bin/probe $(DEB_NAME)$(USR_BIN_FILE_PATH)

	$(QUIET) $(MKDIR) $(DEB_NAME)/etc/ld.so.conf.d/
	@echo "/opt/mmt/probe/lib" >> $(DEB_NAME)/etc/ld.so.conf.d/mmt-probe.conf

	$(QUIET) $(MKDIR) $(DEB_NAME)/etc/init.d/
	$(QUIET) $(CP) daemon-service.sh  $(DEB_NAME)$(ETC_SERVICE_FILE_PATH)
	$(QUIET) chmod 0755               $(DEB_NAME)$(ETC_SERVICE_FILE_PATH)

	$(QUIET) $(MKDIR) $(DEB_NAME)$(INSTALL_DIR)
	$(QUIET) $(CP) -r $(FACE_ROOT_DIR)/* $(DEB_NAME)$(INSTALL_DIR)

	$(QUIET) $(MKDIR) $(DEB_NAME)$(INSTALL_DIR)/lib
ifdef REDIS
	$(QUIET) $(CP) /usr/local/lib/libhiredis.so.*  $(DEB_NAME)$(INSTALL_DIR)/lib
endif
ifdef KAFKA
	$(QUIET) $(CP) /usr/local/lib/librdkafka.so.*  $(DEB_NAME)$(INSTALL_DIR)/lib
endif
	$(QUIET) $(CP) /usr/lib/x86_64-linux-gnu/libconfuse.so.*  $(DEB_NAME)$(INSTALL_DIR)/lib/

#List of packages mmt-probe depends on
RPM_DEPENDING_PACKAGES := mmt-dpi >= 1.6.13
DEB_DEPENDING_PACKAGES := mmt-dpi (>= 1.6.13)
ifdef SECURITY
	RPM_DEPENDING_PACKAGES += mmt-security >= 1.2.0
	DEB_DEPENDING_PACKAGES += mmt-security (>= 1.2.0)
endif

#build .deb file for Debian
deb: --private-prepare-build
	$(QUIET) $(MKDIR) $(DEB_NAME)/DEBIAN
	$(QUIET) echo "Package: mmt-probe\
        \nVersion: $(VERSION)\
        \nSection: base\
        \nPriority: standard\
        \nDepends: $(DEB_DEPENDING_PACKAGES)\
        \nArchitecture: all \
        \nMaintainer: Montimage <contact@montimage.com> \
        \nDescription: MMT-Probe:\
        \n  Version id: $(GIT_VERSION). Build time: `date +"%Y-%m-%d %H:%M:%S"`\
        \n  Modules: $(MODULES_LIST)\
        \nHomepage: http://www.montimage.com"\
		> $(DEB_NAME)/DEBIAN/control

	$(QUIET) dpkg-deb -b $(DEB_NAME)
	$(QUIET) $(RM) $(DEB_NAME)
	$(QUIET) $(RM) $(FACE_ROOT_DIR)

#build .rpm file for RedHat
rpm: --private-prepare-build
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
      \nRequires:  $(RPM_DEPENDING_PACKAGES)\
      \nBuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}\
      \n\
      \n%description\
      \nMMT-Probe is a tool to analyze network traffic.\
      \nModules: $(MODULES_LIST) \
      \nBuild date: `date +"%Y-%m-%d %H:%M:%S"`\
      \n\
      \n%prep\
      \nrm -rf %{buildroot}\
      \nmkdir -p %{buildroot}\
      \ncp -r %{_topdir}/../$(DEB_NAME)/* %{buildroot}/\
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

	$(QUIET) rpmbuild --quiet --rmspec --define "_topdir $(shell pwd)/rpmbuild"\
				 --define "_rpmfilename ../../$(DEB_NAME).rpm" -bb ./mmt-probe.spec
	$(QUIET) $(RM) rpmbuild
	@echo "[PACKAGE] $(DEB_NAME).rpm"

	$(QUIET) $(RM) $(DEB_NAME)
	$(QUIET) $(RM) $(FACE_ROOT_DIR)

keygen:
	$(QUIET) $(CC) -o keygen $(CLDFLAGS)  key_generator.c

#stop mmt-probe service and remove it if exists
--private-stop-and-remove-service: --private-check-root
#check if file exists and not empty
	$(QUIET) [ -s $(ETC_SERVICE_FILE_PATH) ]                                   \
		&& update-rc.d -f mmt-probe remove                             \
		&& $(RM) -rf $(ETC_SERVICE_FILE_PATH)                          \
		&& systemctl daemon-reload                                     \
		&& echo "Removed MMT-Probe from service list $(ETC_SERVICE_FILE_PATH)" \
		|| true

dist-clean: --private-stop-and-remove-service
	$(QUIET) $(RM) -rf $(USR_BIN_FILE_PATH)
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	@echo "Removed MMT-Probe from $(INSTALL_DIR)"
	@echo "Done"