#################################################
############ PACKAGE & INSTALL ##################
#################################################

# Input variables:
#   - APP         : app name, e.g., probe
#   - INSTALL_DIR : directory to install MMT-Probe
#   - NEED_ROOT_PERMISSION : is defined if user install in the default folder /opt/mmt/
#   - DPDK_CAPTURE: indicate wheter MMT-Probe uses DPDK
#   - REDIS_MODULE: indicate wheter MMT-Probe uses Redis
#   - KAFKA_MODULE: indicate wheter MMT-Probe uses Kafka
#   - MODULES_LIST: contains a list of modules that have been enable when compiling
#
#   - VERSION     :
#   - GIT_VERSION :
#   - QUIET       :
#   - RM          : remove file or folder
#   - MKDIR       : create a folder
 
#environment variables
SYS_NAME    = $(shell uname -s)
SYS_VERSION = $(shell uname -p)

#name of package files
PACKAGE_FILE_NAME = mmt-probe_$(VERSION)_$(GIT_VERSION)_$(SYS_NAME)_$(SYS_VERSION)
ifdef DPDK_CAPTURE
  PACKAGE_FILE_NAME := $(PACKAGE_FILE_NAME)_dpdk
else
  PACKAGE_FILE_NAME := $(PACKAGE_FILE_NAME)_pcap
endif


#List of packages mmt-probe depends on:

#1. When use build using STATIC_LINK, we do not need mmt-dpi, mmt-security package
ifndef STATIC_LINK
  RPM_DEPENDING_PACKAGES += mmt-dpi >= 1.7.1  #for .rpm file
  DEB_DEPENDING_PACKAGES += mmt-dpi (>= 1.7.1)#for .def file

#2. When security enable => we need mmt-security package
ifdef SECURITY_MODULE
  RPM_DEPENDING_PACKAGES += , mmt-security >= 1.2.0
  DEB_DEPENDING_PACKAGES += , mmt-security (>= 1.2.0)
endif
endif

#temp folder to contain installed files
TEMP_DIR := build_mmt_probe
#_$(shell bash -c 'echo $$RANDOM')

$(APP):
	$(error ERROR: Not found probe. Please compile first!)

#internal target to be used by others
# copy all necessary files to TEMP_DIR
--private-copy-files: $(APP)
#create dir
	$(QUIET) $(RM) $(TEMP_DIR)
	$(QUIET) $(MKDIR) $(TEMP_DIR)/bin       \
		$(TEMP_DIR)/result/report/offline    \
		$(TEMP_DIR)/result/report/online     \
		$(TEMP_DIR)/result/behaviour/online  \
		$(TEMP_DIR)/result/behaviour/offline \
		$(TEMP_DIR)/result/security/online   \
		$(TEMP_DIR)/result/security/offline  \
		$(TEMP_DIR)/files                    \
      $(TEMP_DIR)/pcaps
#copy to bin
	$(QUIET) $(CP) $(APP)           $(TEMP_DIR)/bin/probe
#configuration file
	$(QUIET) $(CP) mmt-probe.conf   $(TEMP_DIR)/mmt-probe.conf

#Check if having root permission to install MMT-Probe
--private-check-root:
ifdef NEED_ROOT_PERMISSION
	$(QUIET) [ "$$(id -u)" != "0" ] && echo "ERROR: Need root privilege" && exit 1 || true
endif

#check if old version of MMT-Probe is existing
--private-check-old-version:
	$(QUIET) test -d $(INSTALL_DIR)                           \
		&& echo "ERROR: Old version of MMT-Probe is existing." \
		&& echo "($(INSTALL_DIR))"                             \
		&& exit 1                                              \
		|| true


#copy binary file to $PATH
USR_BIN_FILE_PATH     = /usr/bin/mmt-probe
#copy binary file to service list
ETC_SERVICE_FILE_PATH = /etc/systemd/system/mmt-probe.service

--private-info:
	$(info MMT-Probe will be installed on folder: $(INSTALL_DIR))

install: $(APP) --private-info --private-check-old-version --private-check-root --private-copy-files
	$(QUIET) echo "INFO: Install MMT-Probe on $(INSTALL_DIR)"

	$(QUIET) $(MKDIR)  $(INSTALL_DIR)
	$(QUIET) $(CP) -r  $(TEMP_DIR)/* $(INSTALL_DIR)
	$(QUIET) $(RM) -rf $(TEMP_DIR) #remove temp_file
	
ifdef NEED_ROOT_PERMISSION
	@#create an alias
	$(QUIET) ln -s $(INSTALL_DIR)/bin/probe $(USR_BIN_FILE_PATH)
	@#create service
	$(QUIET) $(CP) mmt-probe.service  $(ETC_SERVICE_FILE_PATH)
	$(QUIET) chmod +x                 $(ETC_SERVICE_FILE_PATH)
	$(QUIET) ( command -v systemctl && systemctl daemon-reload ) || true
endif

	@echo ""
	@echo "Successfully installed MMT-Probe on $(INSTALL_DIR)"
	
	@echo "You can start MMT-Probe by:"
	
ifdef NEED_ROOT_PERMISSION
	@echo " - either: sudo mmt-probe"
	@echo " - or    : sudo systemctl start mmt-probe"
else
	@echo "$(INSTALL_DIR)/bin/probe"
endif

	@echo
	@echo "The default configuration file of MMT-Probe is located at $(INSTALL_DIR)/mmt-probe.conf"

#internal target to be used to create distribution file: .deb or .rpm
--private-prepare-build: --private-copy-files
	$(QUIET) $(RM) $(PACKAGE_FILE_NAME) #remove old files

	$(QUIET) $(MKDIR) $(PACKAGE_FILE_NAME)/usr/bin/
	$(QUIET) ln -s $(INSTALL_DIR)/bin/probe $(PACKAGE_FILE_NAME)$(USR_BIN_FILE_PATH)

	$(QUIET) $(MKDIR) $(PACKAGE_FILE_NAME)/etc/ld.so.conf.d/
	@echo "$(INSTALL_DIR)/lib" >> $(PACKAGE_FILE_NAME)/etc/ld.so.conf.d/mmt-probe.conf

	$(QUIET) $(MKDIR) $(PACKAGE_FILE_NAME)/etc/systemd/system/
	$(QUIET) $(CP) mmt-probe.service  $(PACKAGE_FILE_NAME)$(ETC_SERVICE_FILE_PATH)
	$(QUIET) chmod +x                 $(PACKAGE_FILE_NAME)$(ETC_SERVICE_FILE_PATH)

	$(QUIET) $(MKDIR)  $(PACKAGE_FILE_NAME)$(INSTALL_DIR)
	$(QUIET) $(CP) -r  $(TEMP_DIR)/* $(PACKAGE_FILE_NAME)$(INSTALL_DIR)
	$(QUIET) $(RM) -rf $(TEMP_DIR) #remove temp_file
	
	$(QUIET) $(MKDIR) $(PACKAGE_FILE_NAME)$(INSTALL_DIR)/lib
	
ifdef REDIS_MODULE
	@#when using STATIC_LINK, libhiredis is embedded into probe, 
	@#thus we do not need to copy it together with package (.deb, or .rpm) file
ifndef STATIC_LINK
	$(QUIET) $(CP) /usr/local/lib/libhiredis.so.*  $(PACKAGE_FILE_NAME)$(INSTALL_DIR)/lib
endif
endif

ifdef KAFKA_MODULE
	$(QUIET) $(CP) /usr/local/lib/librdkafka.so.*  $(PACKAGE_FILE_NAME)$(INSTALL_DIR)/lib
endif


.PHONY: deb
#build .deb file for Debian
deb: --private-prepare-build
	$(QUIET) $(MKDIR) $(PACKAGE_FILE_NAME)/DEBIAN
	$(QUIET) echo "Package: mmt-probe\
        \nVersion: $(VERSION)\
        \nSection: base\
        \nPriority: standard\
        \nDepends: $(DEB_DEPENDING_PACKAGES)\
        \nArchitecture: all \
        \nMaintainer: Montimage <contact@montimage.com> \
        \nDescription: MMT-Probe:\
        \n  Version id: $(GIT_VERSION).\
        \n  Build time: `date +"%Y-%m-%d %H:%M:%S"`\
        \n  Modules: $(MODULES_LIST)\
        \nHomepage: http://www.montimage.com"\
		> $(PACKAGE_FILE_NAME)/DEBIAN/control

	@#the script will be executed after installing the deb file
	$(QUIET) echo "ldconfig && systemctl daemon-reload" \
	   > $(PACKAGE_FILE_NAME)/DEBIAN/postinst 
	
	$(QUIET) chmod 755 $(PACKAGE_FILE_NAME)/DEBIAN/postinst
	
	$(QUIET) dpkg-deb -b $(PACKAGE_FILE_NAME)
	$(QUIET) $(RM) $(PACKAGE_FILE_NAME)
	$(QUIET) $(RM) $(TEMP_DIR)

.PHONY: rpm
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
      \ncp -r %{_topdir}/../$(PACKAGE_FILE_NAME)/* %{buildroot}/\
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
				 --define "_rpmfilename ../../$(PACKAGE_FILE_NAME).rpm" -bb ./mmt-probe.spec
	$(QUIET) $(RM) rpmbuild
	@echo "[PACKAGE] $(PACKAGE_FILE_NAME).rpm"

	$(QUIET) $(RM) $(PACKAGE_FILE_NAME)
	$(QUIET) $(RM) $(TEMP_DIR)


#stop mmt-probe service and remove it if exists
--private-stop-and-remove-service: --private-check-root
#check if file exists and not empty
ifdef NEED_ROOT_PERMISSION
	$(QUIET) [ -s $(ETC_SERVICE_FILE_PATH) ]                                  \
		&& update-rc.d -f mmt-probe remove                                     \
		&& $(RM) -rf $(ETC_SERVICE_FILE_PATH)                                  \
		&& systemctl daemon-reload                                             \
		&& echo "INFO: Removed successfully MMT-Probe from service list $(ETC_SERVICE_FILE_PATH)" \
		|| true
endif

.PHONY: dist-clean
#delete files generated by "install"
dist-clean: --private-stop-and-remove-service
ifdef NEED_ROOT_PERMISSION
	$(QUIET) $(RM) -rf $(USR_BIN_FILE_PATH)
endif
	$(QUIET) $(RM) -rf $(INSTALL_DIR)
	@echo "INFO: Removed successfully MMT-Probe from $(INSTALL_DIR)"
	@echo "Done"
	