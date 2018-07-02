###############################
# Create serial key generator #
###############################

# - Input variables: QUIET, CC, CLDFLAGS

keygen:
	$(QUIET) $(CC) -o keygen $(CLDFLAGS)  key_generator.c
