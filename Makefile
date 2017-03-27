CC     = gcc-4.9
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp

#name of executable file to generate
OUTPUT   = probe
#directory where probe will be installed on
INSTALL_DIR = /opt/mmt/probe

#get git version abbrev
GIT_VERSION := $(shell git log --format="%h" -n 1)
VERSION     := 1.0


#set of library
LIBS     = -L /opt/mmt/dpi/lib -lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread -lhtmlstreamparser -lz

CFLAGS   = -Wall -Wno-unused-variable -DNDEBUG -DVERSION=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\"
CLDFLAGS = -I /opt/mmt/dpi/include -DNDEBUG

#for debuging
ifdef DEBUG
	CFLAGS   += -g -DNDEBUG -O0
	CLDFLAGS += -g -DNDEBUG -O0
else
	CFLAGS   += -O3
	CLDFLAGS += -O3
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

ifndef VERBOSE
	QUIET := @
endif

all: $(LIB_OBJS) $(MAIN_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(OUTPUT) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT)
	
keygen:
	$(QUIET) $(CC) -o keygen $(CLDFLAGS)  key_generator.c
	
#
# Install probe
#
install: all
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
#copy probe to bin
	$(QUIET) $(CP) $(OUTPUT) $(INSTALL_DIR)/bin/probe
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
	
dist-clean:
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	$(QUIET) $(RM) -rf /etc/init.d/probe_*_d