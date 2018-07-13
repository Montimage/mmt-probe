###################################################
# COMPILE MMT-Probe USING PCAP TO CAPTURE PACKETS #
###################################################

#
# When compiling using static variables, we need to use g++ as DPI uses stdc++
#

ALL_OBJS    := $(patsubst %.c,%.o, $(ALL_SRCS))

compile: $(ALL_OBJS)
	@echo "[COMPILE] probe"
ifdef STATIC_LINK
	$(QUIET) $(CXX) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
else
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
endif

%.o: %.c --check-security-folder --check-dpi-folder
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<

clean:
	$(QUIET) $(RM) $(APP)
#remove all .o files
	$(QUIET) find $(SRC_DIR)/ -name \*.o -type f -delete
