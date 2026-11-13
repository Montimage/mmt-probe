#####################################################
# UNIT TESTS                                        #
#####################################################

# Unit check of the STIX 2.1 alert builder (src/modules/output_format/stix_format.c).
# Needs only gcc and libuuid (package uuid-dev), not MMT-DPI.
#   make test-stix
STIX_TEST_DIR := $(TOP_DIR)/test/stix_format
STIX_TEST_BIN := $(STIX_TEST_DIR)/test_stix_format

.PHONY: test-stix
test-stix:
	@echo "[COMPILE] $(notdir $(STIX_TEST_BIN))"
	$(QUIET) $(CC) -Wall -Wextra -O1 -o $(STIX_TEST_BIN) \
		$(STIX_TEST_DIR)/test_stix_format.c $(SRC_DIR)/modules/output_format/stix_format.c -luuid
	@echo "[TEST] $(notdir $(STIX_TEST_BIN))"
	$(QUIET) $(STIX_TEST_BIN)
