#############################################
# Create dummy targets for building modules #
#############################################

# - Input variables: 
#     SRC_DIR: path of /src
#     MMT_SECURITY_DIR: directory where MMT-Security is installed
#     MMT_DPI_DIR     : directory where MMT-DPI is installed
#     
# - Output variables:
#     MODULE_SRCS   : all .c files of modules to be compiled
#     MODULE_LIBS   : libraries must be linked to in order to compiles the selected modules
#     MODULE_CFLAGS : compile flags
#     and list of module names:
#     TCP_REASSEMBLY_MODULE = 1 if TCP reassemply module is active when compiling
#     ....
#
#     ALL_MODULES = 1 if user actives all modules when compiling

# dummy target to enable all modules
ALL_MODULES: ;@:

# compile all modules
ifneq (,$(findstring ALL_MODULES,$(MAKECMDGOALS)))
  ALL_MODULES := 1
endif


#decide when we need to print out the message if a module is disable
#ex: no need when we do: make clean
#by default, we do not print out the message
undefine PRINT_MODULE_MSG
#by default, when no target is given to `make` commandline => do `make compile`
ifndef MAKECMDGOALS
  PRINT_MODULE_MSG := 1
endif
#when do `make compile` or `make deb` or `make rpm`, we need to print out the modules
ifneq (,$(findstring compile,$(MAKECMDGOALS)))
  PRINT_MODULE_MSG := 1
endif
ifneq (,$(findstring rpm,$(MAKECMDGOALS)))
  PRINT_MODULE_MSG := 1
endif
ifneq (,$(findstring deb,$(MAKECMDGOALS)))
  PRINT_MODULE_MSG := 1
endif

#a function to print out a message if need
#usage: $(eval $(call _info, message xyz))
define _info
  ifdef PRINT_MODULE_MSG
    $$(info $(1))
  endif
endef

#intermediate targets
#This function will create a dummy target naming by its first parameter, e.g., MONGODB_MODULE
# when user call the target, it will set an environment variable having the same name
# Example: 
#     $(eval $(call check_module,DPDK_CAPTURE))
# => when user do: make DPDK_CAPTURE
# =>  env variable DPDK_CAPTURE will be defined to 1

define check_module
# dummy target
$(1): ;@:

MODULES_LIST += $(1)
#enable this module if 
# - ALL_MODULES is given on parameters of make command
# - or its name is called on the parameters 
ifdef ALL_MODULES
  export $(1)=1
endif

ifneq (,$(findstring $(1),$(MAKECMDGOALS)))
  export $(1)=1
endif

ifdef $(1)
  $$(info - Enable $(1))
else
  ifdef PRINT_MODULE_MSG
    $$(info -> Disable $(1))
  endif
endif

endef

#list of modules' sources
MODULE_SRCS := $(wildcard $(SRC_DIR)/modules/output/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/output/file/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/lpi/*.c)
MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/routine/*.c)
#list of modules' libraries
MODULE_LIBS  += -L/usr/local/lib/ -ldl
#list of modules' compiling flags
MODULE_FLAGS :=


#to calculate response time, transfer time, ...
$(eval $(call check_module,QOS_MODULE))
ifdef QOS_MODULE
  MODULE_FLAGS += -DQOS_MODULE
endif

$(eval $(call check_module,HTTP_RECONSTRUCT_MODULE))
ifdef HTTP_RECONSTRUCT_MODULE
  export TCP_REASSEMBLY_MODULE=1 #HTTP_RECONSTRUCT requires TCP_REASSEMBLY
  MODULE_LIBS  += -lz
  MODULE_FLAGS += -DHTTP_RECONSTRUCT_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/dpi/reconstruct/http/*.c)
endif

$(eval $(call check_module,FTP_RECONSTRUCT_MODULE))
ifdef FTP_RECONSTRUCT_MODULE
  export TCP_REASSEMBLY_MODULE=1 #FTP_RECONSTRUCT requires TCP_REASSEMBLY
  MODULE_FLAGS += -DFTP_RECONSTRUCT_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/dpi/reconstruct/ftp/*.c)
endif

$(eval $(call check_module,TCP_REASSEMBLY_MODULE))
ifdef TCP_REASSEMBLY_MODULE
  MODULE_FLAGS += -DTCP_REASSEMBLY_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/dpi/reassembly/*.c)
endif

# OUTPUTS >>>>>>>>>>>>
$(eval $(call check_module,KAFKA_MODULE))
ifdef KAFKA_MODULE
  ifdef STATIC_LINK
    MODULE_LIBS  += -lrdkafka
  else
    MODULE_LIBS  += -lrdkafka
  endif
  MODULE_FLAGS += -I /usr/local/include/librdkafka -DKAFKA_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/output/kafka/*.c)
endif

$(eval $(call check_module,MONGODB_MODULE))
ifdef MONGODB_MODULE
  ifdef STATIC_LINK
    MODULE_LIBS  += -lmongoc-1.0 -lbson-1.0
  else
    MODULE_LIBS  += -lmongoc-1.0 -lbson-1.0
  endif
  MODULE_FLAGS += -DMONGODB_MODULE -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/output/mongodb/*.c)
endif

$(eval $(call check_module,REDIS_MODULE))
ifdef REDIS_MODULE
  ifdef STATIC_LINK
    MODULE_LIBS  += -l:libhiredis.a
  else
    MODULE_LIBS  += -lhiredis
  endif
  MODULE_FLAGS += -DREDIS_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/output/redis/*.c)
endif

$(eval $(call check_module,SOCKET_MODULE))
ifdef SOCKET_MODULE
  MODULE_FLAGS += -DSOCKET_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/output/socket/*.c)
endif

$(eval $(call check_module,SECURITY_MODULE))
ifdef SECURITY_MODULE
  #folder where MMT-Security is installed
  MMT_SECURITY_DIR := $(realpath $(MMT_BASE)/security)
  #check if MMT_SECURITY_DIR exists
  ifndef MMT_SECURITY_DIR
    $(error Not found MMT-Security at $(MMT_BASE)/security)
  endif

  #depending on link type, we use either static or dynamic library
  ifdef STATIC_LINK
    LIB_SECURITY := -l:libmmt_security2.a
  else
    LIB_SECURITY := -l:libmmt_security2.so
  endif
  
  MODULE_LIBS  += -L$(MMT_SECURITY_DIR)/lib $(LIB_SECURITY) -lxml2
  MODULE_FLAGS += -I$(MMT_SECURITY_DIR)/include -DSECURITY_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/security/*.c)
endif

$(eval $(call check_module,PCAP_DUMP_MODULE))
ifdef PCAP_DUMP_MODULE
  MODULE_FLAGS += -DPCAP_DUMP_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/dpi/pcap_dump/*.c)
endif

# check license
$(eval $(call check_module,LICENSE_MODULE))
ifdef LICENSE_MODULE
  MODULE_FLAGS += -DLICENSE_CHECK
  MODULE_SRCS  +=  $(wildcard $(SRC_DIR)/modules/license/*.c)
endif

# Report for enodeb lte
$(eval $(call check_module,LTE_MODULE))
ifdef LTE_MODULE
  MODULE_FLAGS += -DLTE_REPORT
  MODULE_SRCS  +=  $(wildcard $(SRC_DIR)/modules/dpi/lte/*.c)
endif

$(eval $(call check_module,NETCONF_MODULE))
ifdef NETCONF_MODULE
  export DYNAMIC_CONFIG_MODULE=1 #NETCONF requires DYNAMIC_CONFIG
  MODULE_LIBS  += -lrt -lsysrepo -lxml2
  MODULE_FLAGS += -DNETCONF_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/netconf/*.c)
endif

$(eval $(call check_module,DYNAMIC_CONFIG_MODULE))
ifdef DYNAMIC_CONFIG_MODULE
  MODULE_FLAGS += -DDYNAMIC_CONFIG_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/dynamic_conf/*.c)
endif

#################### Other optional parameters for compiling ######################
$(eval $(call EXPORT_TARGET,DISABLE_REPORT))
$(eval $(call EXPORT_TARGET,SIMPLE_REPORT))

ifdef SIMPLE_REPORT
  ifdef DISABLE_REPORT
    $(error Either SIMPLE_REPORT or DISABLE_REPORT can be used, but not both of them)
  endif

  $(info - Use simple reports for MMT-Box)
  MODULE_FLAGS += -DSIMPLE_REPORT
endif

ifndef DISABLE_REPORT
  MODULE_FLAGS += -DSTAT_REPORT
  #simple report uses only session_report.c. It does not take into account FTP, HTTP, RTP, micro session, radius
  ifdef SIMPLE_REPORT
    MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/report/session_report.c)
  else
    MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/report/*.c)
    MODULE_SRCS += $(wildcard $(SRC_DIR)/modules/dpi/report/query/*.c)
  endif
else
  $(info -> Disable reports)
endif

# to use DPDK to capture packet
$(eval $(call EXPORT_TARGET,DPDK_CAPTURE))

ifdef DPDK_CAPTURE
  $(info - Use DPDK to capture packet)
  MODULE_FLAGS += -DDPDK_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/packet_capture/dpdk/*.c)
  
  #we need to export these variables as we need them in the second call of compile-dpdk.mk by the makefile of DPDK
  export MODULE_FLAGS
  export MODULE_SRCS
  export MODULE_LIBS
  
  ifdef STATIC_LINK
    $(error DPDK_CAPTURE and STATIC_LINK cannot be together)
  endif
else
  $(eval $(call _info,- Use PCAP to capture packet))
  ifdef STATIC_LINK
    MODULE_LIBS  += -l:libpcap.a
  else
    MODULE_LIBS  += -lpcap
  endif
  MODULE_FLAGS += -DPCAP_MODULE
  MODULE_SRCS  += $(wildcard $(SRC_DIR)/modules/packet_capture/pcap/*.c)
endif
