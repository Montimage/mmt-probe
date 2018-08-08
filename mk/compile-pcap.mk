###################################################
# COMPILE MMT-Probe USING PCAP TO CAPTURE PACKETS #
###################################################

ALL_OBJS    := $(patsubst %.c,%.o, $(ALL_SRCS))

compile: $(ALL_OBJS)
	@echo "[COMPILE] probe"
# When compiling using static link, we need to use g++ as DPI uses stdc++
ifdef STATIC_LINK
	$(QUIET) $(CXX) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
else
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
endif

%.o: %.c --check-dpi-folder
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	$(QUIET) $(RM) $(APP)
#remove all .o files
	$(QUIET) find $(SRC_DIR)/ -name \*.o -type f -delete
