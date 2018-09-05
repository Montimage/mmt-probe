/*
 * combinator.c
 *
 *  Created on: Jun 27, 2018
 *          by: Huu Nghia Nguyen
 *
 * Program to generate all permutation of a set with distinct strings.
 * The set of strings is given via input parameter of the program.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

static unsigned int comb_mask = 0x00000001;
static unsigned int max_mask_length = 0;

bool generate_combination(char * const *source_string, char **combination_string) {
	unsigned int mask = 0x00000001;
	int s_pos = 0, c_pos = 0;

	/* Main logic */
	while ((mask & max_mask_length)) {
		if ((comb_mask & mask)) {
			combination_string[c_pos] = source_string[s_pos];
			c_pos++;
		}
		s_pos++;
		mask <<= 1;
	}

	/*update permutation mask */
	comb_mask++;

	/* Terminate the combination_string with NULL character */
	combination_string[c_pos] = 0;

	/* If combination_string is empty, ie. c_pos == 0 , return FALSE else return TRUE */
	return (c_pos != 0 );
}

void print(char * const * args) {
	while (*args != NULL) {
		printf("%s ", *args);
		args++;
	}
	printf("\n");
}



/* Main Function, driving generate_combination() */
int main(int argc, char **args) {
	char *combination_string[argc];

	if (argc <= 1) {
		printf("usage: %s param1 param2 ... paramN", args[0]);
		return EXIT_FAILURE;
	}

	//jump over the first string representing the file name
	args++;
	argc--;

	max_mask_length = ~(0x00000001 << argc);

	while (generate_combination(args, combination_string))
		print(combination_string);

	return EXIT_SUCCESS;
}

