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


LIB_SRCS     = $(wildcard $(SRC_DIR)/lib/*.c)
LIB_SRCS    += $(SRC_DIR)/configure.c $(SRC_DIR)/configure_override.c $(SRC_DIR)/worker.c

MODULE_SRCS  = $(wildcard $(SRC_DIR)/modules/output/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/file/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/routine/*.c)

#intermediate targets
#This function will create a target naming by its first parameter, e.g., MONGODB_MODULE
# when user call the target, it will set an environment variable naming by the second parameter
# Example: 
#     $(eval $(call EXPORT_TARGET,DPDK_CAPTURE,DPDK))
# => when user do: make DPDK_CAPTURE
# =>  env variable DPDK will be defined to 1
define EXPORT_TARGET
$(1): ;@:
ifneq (,$(findstring $(1),$(MAKECMDGOALS))) 
 export $(2)=1 
endif
endef

$(eval $(call EXPORT_TARGET,VERBOSE,VERBOSE))
$(eval $(call EXPORT_TARGET,DEBUG,DEBUG))
$(eval $(call EXPORT_TARGET,QOS,QOS))

$(eval $(call EXPORT_TARGET,MONGODB_MODULE,MONGODB))
$(eval $(call EXPORT_TARGET,REDIS_MODULE,REDIS))
$(eval $(call EXPORT_TARGET,KAFKA_MODULE,KAFKA))
$(eval $(call EXPORT_TARGET,SOCKET_MODULE,SOCKET))


$(eval $(call EXPORT_TARGET,LICENSE_MODULE,LICENSE))
$(eval $(call EXPORT_TARGET,SECURITY_MODULE,SECURITY))

$(eval $(call EXPORT_TARGET,DYNAMIC_CONFIG_MODULE,DYNAMIC_CONFIG))

$(eval $(call EXPORT_TARGET,PCAP_DUMP_MODULE,PCAP_DUMP))
$(eval $(call EXPORT_TARGET,HTTP_RECONSTRUCT_MODULE,HTTP_RECONSTRUCT))
$(eval $(call EXPORT_TARGET,FTP_RECONSTRUCT_MODULE,FTP_RECONSTRUCT))

$(eval $(call EXPORT_TARGET,SIMPLE_REPORT,SIMPLE_REPORT))
$(eval $(call EXPORT_TARGET,DISABLE_REPORT,DISABLE_REPORT))

$(eval $(call EXPORT_TARGET,DPDK_CAPTURE,DPDK))


	

ifndef VERBOSE
  QUIET := @
endif
#################################################
############ OTHER SETTING ######################
#################################################
#for debuging
ifdef DEBUG
$(info - Enable DEBUG)
	CFLAGS   += -g -O0 -DDEBUG_MODE
else
$(info -> Disable DEBUG)
	CFLAGS   += -O3
endif

#for valgrind check
ifdef VALGRIND
	CFLAGS += -DVALGRIND_MODE
endif

#to calculate response time, transfer time, ...
ifdef QOS
	CFLAGS += -DQOS_MODULE
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

MODULE_SRCS := $(wildcard $(SRC_DIR)/modules/output/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/file/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/routine/*.c)
#################################################
########### MODULES #############################
#################################################

# For HTTP reconstruction option
ifdef HTTP_RECONSTRUCT
$(info - Enable HTTP_RECONSTRUCT)
	LIBS        += -lz
	CFLAGS      += -DHTTP_RECONSTRUCT_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/reconstruct/http/*.c)
else
$(info -> Disable HTTP_RECONSTRUCT)
endif

ifdef FTP_RECONSTRUCT
$(info - Enable FTP_RECONSTRUCT)
	CFLAGS      += -DFTP_RECONSTRUCT_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/reconstruct/ftp/*.c)
else
$(info -> Disable FTP_RECONSTRUCT)
endif

ifdef KAFKA
$(info - Enable KAFKA)
	LIBS        += -L/usr/local/lib/ -lrdkafka
	CFLAGS      += -I /usr/local/include/librdkafka -DKAFKA_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/kafka/*.c)
else
$(info -> Disable KAFKA)
endif

ifdef MONGODB
$(info - Enable MONGODB)
	LIBS        += -L/usr/lib/x86_64-linux-gnu/ -lmongoc-1.0 -lbson-1.0
	CFLAGS      += -DMONGODB_MODULE -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/mongodb/*.c)
else
$(info -> Disable MONGODB)
endif

ifdef REDIS
$(info - Enable REDIS)
	LIBS        += -lhiredis
	CFLAGS      += -DREDIS_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/redis/*.c)
else
$(info -> Disable REDIS)
endif

ifdef SOCKET
$(info - Enable SOCKET output)
	CFLAGS      += -DSOCKET_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/socket/*.c)
else
$(info -> Disable SOCKET output)
endif

ifdef NETCONF
$(info - Enable NETCONF)
	LIBS        += -lrt -lsysrepo -lxml2
	CFLAGS      += -DNETCONF_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/netconf/*.c)
else
$(info -> Disable NETCONF)
endif

ifdef DYNAMIC_CONFIG
$(info - Enable DYNAMIC_CONFIG)
	CFLAGS      += -DDYNAMIC_CONFIG_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dynamic_conf/*.c)
else
$(info -> Disable DYNAMIC_CONFIG)
endif

ifdef SECURITY
$(info - Enable SECURITY)
	LIBS        += -L/opt/mmt/security/lib -lmmt_security2 -lxml2
	CFLAGS      += -I /opt/mmt/security/include -DSECURITY_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/security/*.c)
else
$(info -> Disable SECURITY)
endif

ifdef PCAP_DUMP
$(info - Enable PCAP_DUMP)
	CFLAGS      += -DPCAP_DUMP_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/pcap_dump/*.c)
else
$(info -> Disable PCAP_DUMP)
endif

ifdef SIMPLE_REPORT
undefine DISABLE_REPORT
endif

ifndef DISABLE_REPORT
$(info - Enable REPORT)
	CFLAGS      += -DSTAT_REPORT
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/report/*.c)
else
$(info -> Disable REPORT)
endif

ifdef DPDK
$(info - Use DPDK to capture packet)
	CFLAGS      += -DDPDK_MODULE
	MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/packet_capture/dpdk/*.c) 
else
$(info - Use PCAP to capture packet)
   CFLAGS      += -DPCAP_MODULE
   LIBS        += -lpcap -ldl
   MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/packet_capture/pcap/*.c)
endif

MAIN_SRCS := $(SRC_DIR)/main.c

#all source code
ALL_SRCS  := $(LIB_SRCS) $(MODULE_SRCS) $(MAIN_SRCS)

#################################################
############ BUILD & CLEAN  #####################
#################################################

ifdef DPDK #use makefiles of dpdk
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

#copy probe from folder build to the current folder
POSTBUILD += --private-copy-probe
--private-copy-probe:
	$(QUIET) $(CP) $(TOP_DIR)/build/$(APP) $(TOP_DIR)

include $(RTE_SDK)/mk/rte.extapp.mk
   
else #for PCAP

ALL_OBJS    := $(patsubst %.c,%.o, $(ALL_SRCS))

all: $(ALL_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(APP)
#remove all object files
	$(QUIET) find $(SRC_DIR)/ -name \*.o -type f -delete
endif


#################################################
############ PACKAGE & INSTALL ##################
#################################################
#temp folder to contain installed files
FACE_ROOT_DIR=/tmp/probe/$(INSTALL_DIR)

#internal target to be used by others
--private-copy-files:
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