ALL_OBJS    := $(patsubst %.c,%.o, $(ALL_SRCS))

build: $(ALL_OBJS)
	@echo "[COMPILE] probe"
	$(QUIET) $(CC) -o $(APP) $(CLDFLAGS)  $^ $(LIBS)
%.o: %.c
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(APP)
#remove all .o files
	$(QUIET) find $(SRC_DIR)/ -name \*.o -type f -delete
