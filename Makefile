MKDIR       = mkdir -p
TOP        ?= $(shell pwd)
OUTPUT_DIR  = $(TOP)
CC          = gcc
CXX         = g++ -std=c++11
CP          = cp
RM          = rm -rf


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

#executable file name to generate
APP = probe

#environment variables
SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)

ifdef DPDK
	DEB_NAME = mmt-probe_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)_dpdk
else
	DEB_NAME = mmt-probe_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)_pcap
endif

#list of module names
MODULES_LIST := "DPI"

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.3.3


$(info Building MMT-Probe version $(VERSION) $(GIT_VERSION))

#set of library
LIBS    := -L$(MMT_DPI_DIR)/lib -L/usr/local/lib  -lpthread -lrt
CFLAGS += -I /opt/mmt/dpi/include -Wall -Wno-unused-variable           \
            -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"  \
            -DMMT_BASE=\"$(MMT_BASE)\"

ifdef STATIC_LINK
  $(info - Use STATIC_LINK)
  CFLAGS += -DSTATIC_LINK
  LIBS   += -l:libconfuse.a -l:libmmt_tcpip.a -l:libmmt_core.a
else
  $(info - Use dynamic link)
  LIBS   += -l:libconfuse.so  -l:libmmt_core.so
endif

#more information of building process?
ifndef VERBOSE
  QUIET := @
endif

#for debuging
ifdef DEBUG
  $(warning Debug option is enable. This cannot be used in production)
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -O3
endif

#################################################
########### MODULES #############################
#################################################
ifdef KAFKA
  $(info - Enable KAFKA module)
  LIBS    += -lrdkafka
  CFLAGS  += -I /usr/local/include/librdkafka -DKAFKA
  MODULES_LIST +=  KAFKA
else
  $(info -> Disable KAFKA module)
endif

ifdef REDIS
  $(info - Enable REDIS module)
  LIBS    += -lhiredis
  CFLAGS  +=  -DREDIS
  MODULES_LIST +=  REDIS
else
  $(info -> Disable REDIS module)
endif

ifdef HTTP_RECONSTRUCT
$(info - Enable HTTP_RECONSTRUCT module)
  LIBS   += -lhtmlstreamparser -lz
  CFLAGS += -DHTTP_RECONSTRUCT
  MODULES_LIST +=  HTTP_RECONSTRUCT
else
$(info -> Disable HTTP_RECONSTRUCT module)
endif

ifdef TCP_PAYLOAD_DUMP
$(info - Enable TCP_PAYLOAD_DUMP module)
  LIBS   += -L /opt/mmt/reassembly/lib -lmmt_reassembly -lntoh
  CFLAGS += -I /opt/mmt/reassembly/include -DTCP_PAYLOAD_DUMP
  MODULES_LIST +=  TCP_PAYLOAD_DUMP

else
  $(info -> Disable TCP_PAYLOAD_DUMP module)
endif

#old security that is inside mmt-dpi
ifdef SECURITY_V1
  $(info - Enable SECURITY_V1 module)
  LIBS   += -lmmt_security -lxml2
  CFLAGS += -DSECURITY_V1
  MODULES_LIST += SECURITY_V1
else
  $(info -> Disable SECURITY_V1 module)
endif

#new security that is mmt-security
ifdef SECURITY
  $(info - Enable SECURITY module)
  #depending on link type, we use either static or dynamic library
  ifdef STATIC_LINK
    LIB_SECURITY := -l:libmmt_security2.a
  else
    LIB_SECURITY := -l:libmmt_security2.so
  endif
  
  LIBS   += -L$(MMT_SECURITY_DIR)/lib $(LIB_SECURITY) -lxml2
  CFLAGS += -I$(MMT_SECURITY_DIR)/include -DSECURITY
  MODULES_LIST +=  SECURITY
  
else
  $(info -> Disable SECURITY module)
endif

ifndef NDEBUG
  CFLAGS += -DNDEBUG
endif


#################################################
############ CAPTURE PACKETS ####################
#################################################

ifdef DPDK
  $(info - Use DPDK to capture packet)
  RTE_SDK    =/home/mmt/dpdk-stable-17.11.1
  RTE_TARGET = build

  include $(RTE_SDK)/mk/rte.vars.mk

  #source files to compile
  SRCS-y := src/smp_main.c src/processing.c src/web_session_report.c src/thredis.c \
    src/send_msg_to_file.c src/send_msg_to_redis.c src/ip_statics.c src/init_socket.c \
    src/rtp_session_report.c src/ftp_session_report.c \
    src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c \
    src/default_app_session_report.c src/microflows_session_report.c \
    src/radius_reporting.c src/security_analysis.c src/parseoptions.c \
    src/license.c src/dpdk_capture.c src/lib/security.c src/lib/data_spsc_ring.c \
    src/lib/lock_free_spsc_ring.c src/lib/packet_hash.c src/lib/system_info.c \
    src/lib/pcap_dump.c src/attributes_extraction.c src/multisession_reporting.c \
    src/security_msg_reporting.c src/condition_based_reporting.c  \
    src/pcap_capture.c src/html_integration.c src/http_reconstruct.c \
    src/send_msg_to_kafka.c

  #set of library
  LDLIBS   += $(LIBS)
  CFLAGS   += $(WERROR_CFLAGS) -DDPDK

  include $(RTE_SDK)/mk/rte.extapp.mk

else #for PCAP
$(info - Use PCAP to capture packet)

  #set of library
  LIBS     += -lpcap -ldl
  CFLAGS   += -DPCAP

  #folders containing source files
  SRCDIR = src

  #objects to generate
  LIB_OBJS :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/lib/*.c))

  #filter out 2 files: src/main.c and src/test_probe.c
  MAIN_SRCS := $(wildcard   $(SRCDIR)/*.c)
  MAIN_SRCS := $(filter-out $(SRCDIR)/main.c,       $(MAIN_SRCS))
  MAIN_SRCS := $(filter-out $(SRCDIR)/test_probe.c, $(MAIN_SRCS))

  MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS)) \

all: $(APP)

$(APP): $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] probe"
	@# When compiling using static link, we need to use g++ as DPI uses stdc++
ifdef STATIC_LINK
	$(QUIET) $(CXX) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
else
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
endif

%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT)
endif

#################################################
############ PACKAGE & INSTALL ##################
#################################################

#temp folder to contain installed files
FACE_ROOT_DIR := build_mmt_probe_$(shell bash -c 'echo $$RANDOM')

#internal target to be used by others
--private-copy-files: all
	@#create dir
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
	@#copy probe to existing dir from buit in DPDK
ifdef DPDK
	$(QUIET) $(CP) $(OUTPUT_DIR)/probe $(TOP)
endif
	@#copy to bin
	$(QUIET) $(CP) $(APP)           $(FACE_ROOT_DIR)/bin/probe
	@#configuration file
	$(QUIET) $(CP) mmt_online.conf  $(FACE_ROOT_DIR)/mmt-probe.conf
	@#replace /opt/mmt by $MMT_BASE
	$(QUIET) sed -i -- "s:/opt/mmt:$(MMT_BASE):g" $(FACE_ROOT_DIR)/mmt-probe.conf


--private-check-root:
ifdef NEED_ROOT_PERMISSION
	$(QUIET) [ "$$(id -u)" != "0" ] && echo "ERROR: Need root privilege" && exit 1 || true
endif

#remove these files to trigger a recompile of these files to take into account the last value of MMT_BASE
--refresh-mmt-base:
	$(QUIET) $(RM) $(APP) $(SRCDIR)/parseoptions.o

#copy binary file to $PATH
USR_BIN_FILE_PATH     = /usr/bin/mmt-probe
#copy binary file to service list
ETC_SERVICE_FILE_PATH = /etc/init.d/mmt-probe

install: --private-check-root --refresh-mmt-base --private-copy-files
#check if old version of MMT-Probe is existing
	$(QUIET) test -d $(INSTALL_DIR)                           \
		&& echo "ERROR: Old version of MMT-Probe is existing." \
		&& exit 1                                              \
		|| true

	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(CP) -r $(FACE_ROOT_DIR)/* $(INSTALL_DIR)
	$(QUIET) $(RM) $(FACE_ROOT_DIR)
	
ifdef NEED_ROOT_PERMISSION
	@#create an alias
	$(QUIET) ln -s $(INSTALL_DIR)/bin/probe $(USR_BIN_FILE_PATH)
	@#create service
	$(QUIET) $(CP) daemon-service.sh  $(ETC_SERVICE_FILE_PATH)
	$(QUIET) chmod 0755               $(ETC_SERVICE_FILE_PATH)
	$(QUIET) systemctl daemon-reload
endif

	@echo ""
	@echo "Successfully installed MMT-Probe on $(INSTALL_DIR)"
	
ifdef NEED_ROOT_PERMISSION
	@echo "You can start MMT-Probe by:"
	@echo " - either: sudo mmt-probe"
	@echo " - or    : sudo service mmt-probe start"
endif

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
ifdef NEED_ROOT_PERMISSION
#check if file exists and not empty
	$(QUIET) [ -s $(ETC_SERVICE_FILE_PATH) ]                                   \
		&& update-rc.d -f mmt-probe remove                                      \
		&& $(RM) -rf $(ETC_SERVICE_FILE_PATH)                                   \
		&& systemctl daemon-reload                                              \
		&& echo "Removed MMT-Probe from service list $(ETC_SERVICE_FILE_PATH)"  \
		|| true
endif

dist-clean: --private-stop-and-remove-service
ifdef NEED_ROOT_PERMISSION
	$(QUIET) $(RM) -rf $(USR_BIN_FILE_PATH)
endif
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	@echo "Removed MMT-Probe from $(INSTALL_DIR)"
	@echo "Done"
