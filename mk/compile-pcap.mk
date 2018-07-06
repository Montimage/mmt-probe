###################################################
# COMPILE MMT-Probe USING PCAP TO CAPTURE PACKETS #
###################################################

ALL_OBJS    := $(patsubst %.c,%.o, $(ALL_SRCS))

build: $(ALL_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)


%.o: %.c --check-security-folder --check-dpi-folder
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<


clean:
	$(QUIET) $(RM) $(APP)
#remove all .o files
	$(QUIET) find $(SRC_DIR)/ -name \*.o -type f -delete
