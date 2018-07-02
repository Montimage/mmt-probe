#################################################
############ PACKAGE & INSTALL ##################
#################################################

# Input variables:
#   - INSTALL_DIR: directory to install MMT-Probe
#   - 

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

#Check if having root permission to install MMT-Probe
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


#stop mmt-probe service and remove it if exists
--private-stop-and-remove-service: --private-check-root
#check if file exists and not empty
	$(QUIET) [ -s $(ETC_SERVICE_FILE_PATH) ]                          \
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
	