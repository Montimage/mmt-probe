################################################
# Generate C-code for perfect hash using gperf #
################################################

# - Input variables: 
#     SRC_DIR : directory of source code "src/"
#     QUIET   : verbose or not
#     RM      : command to remove files/directories


# Must define SRC directory
ifndef SRC_DIR
$(error Must define SRC_DR)
endif

# Must have gperf program
EXIST_GPERF := $(shell command -v gperf 2> /dev/null)


#Create a recusive wildcard
rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
#List of all *.gperf files in ./src
GPERF_FILES := $(call rwildcard,$(SRC_DIR)/,*.gperf)
GPERF_H     := $(patsubst %.gperf,%.h, $(GPERF_FILES))

--private-inform-gperf:
	@echo "Generate perfect hash functions using gperf"

gperf: --private-inform-gperf $(GPERF_H)
	@echo "Done"

#generate .h files from .gperf files
%.h: %.gperf
ifndef EXIST_GPERF
	$(error "Please install gperf: https://www.gnu.org/software/gperf/")
endif
	@echo "[GENERATE] $@"
	@echo "/* Generated on $(shell date) */" > $@
	$(QUIET) gperf $< >> $@
	
#remove generated files
gperf-clean:
	$(QUIET) $(RM) $(GPERF_H)