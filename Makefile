CC     = gcc-4.9
RM     = rm -rf

#name of executable file to generate
OUTPUT   = probe

#set of library
LIBS     = -lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread

CFLAGS   = -O3 -Wall -Wno-unused-variable
CLDFLAGS =

#for debuging
ifdef DEBUG
	CFLAGS   += -g
	CLDFLAGS += -g
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
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<
clean:
	$(QUIET) $(RM) $(MAIN_OBJS) $(LIB_OBJS) probe