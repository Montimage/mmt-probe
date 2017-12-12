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
LIBS     := -L/opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -lmmt_security -lconfuse -lpthread 
CFLAGS   := -I /opt/mmt/dpi/include -Wall -Wno-unused-variable\
			   -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"

#################################################
############ OTHER SETTING ######################
#################################################
#for debuging
ifdef DEBUG
	CFLAGS   := -g -O0
else
	CFLAGS   := -O3
endif

# For showing message from debug(...)
ifndef NDEBUG
	CLDFLAGS   += -DNDEBUG
	CFLAGS 	  += -DNDEBUG
endif

#################################################
############ CAPTURE PACKETS ####################
#################################################
ifdef DPDK
	#dpdk makefile
	ifndef RTE_SDK
$(error RTE_SDK is not set)
	endif
   #RTE_SDK    ?= /home/mmt/dpdk/
   RTE_TARGET ?= x86_64-native-linuxapp-gcc
   
   include $(RTE_SDK)/mk/rte.vars.mk
   include $(RTE_SDK)/mk/rte.extapp.mk
   
   
$(info - Use DPDK to capture packet)
   CFLAGS += $(WERROR_CFLAGS) -DDPDK
else
	#for PCAP
$(info - Use PCAP to capture packet)
	CFLAGS += -DPCAP
	LIBS   += -lpcap -ldl
endif

#################################################
########### MODULES #############################
#################################################
# For HTTP reconstruction option
ifdef HTTP_RECONSTRUCT_MODULE
$(info - Enable HTTP reconstruction)
	LIBS     += -lhtmlstreamparser -lz
	CFLAGS   += -DHTTP_RECONSTRUCT_MODULE
endif

ifdef KAFKA_MODULE
$(info - Enable Kafka output)
	LIBS   += -lrdkafka
	CFLAGS += -I /usr/local/include/librdkafka -DKAFKA_MODULE
endif

ifdef REDIS_MODULE
$(info - Enable Redis output)
	LIBS   += -lhiredis
	CFLAGS += -DREDIS_MODULE
endif

ifdef NETCONF_MODULE
$(info - Enable dynamic configuration using Netconf)
	LIBS   += -lrt -lsysrepo -lxml2
	CFLAGS += -DNETCONF_MODULE
endif

ifdef SECURITY_MODULE
$(info - Enable Security analysis)
	LIBS   += -L/opt/mmt/security/lib -lmmt_security2 
	CFLAGS += -I /opt/mmt/security/include -DSECURITY_MODULE
endif


#################################################
############## COMPILE ##########################
#################################################
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
