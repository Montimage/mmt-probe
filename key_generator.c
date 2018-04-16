/**
 * gcc -o key_generator key_generator.c
 *
 * Information that needs to be changed in the code for generating new license
 * Provide expiry date of the license in year (4-digits),month(2-digits) and date(2-digits)
 * Provide number of mac address (3 digits) and 12 digit MAC addresses (12 digits) separated by "-" of the machine for the license
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Provide all these parameters:\n");
	fprintf(stderr,
			"\t-m <MACs> : Provide MAC addresses separated by - if more than 1.\nFor example: \"2a:3z:45:6c:12:34-45:67:34:t5:78:fG\"\n");
	fprintf(stderr,
			"\t-d <Date> : Provide expiry date in format YYYY/MM/DD\n");
	fprintf(stderr,
			"\t-h        : Print this help then exit.\n");
	exit(0);
}

int nb_of_mac_address = 1;
char *mac_addresses = NULL;
char *expiry_date = NULL;

void parseOptions(int argc, char ** argv) {
	int opt, optcount = 0;
	int num_mac = 0;

	while ((opt = getopt(argc, argv, "m:d:h")) != EOF) {
		switch (opt) {
		case 'm':
			optcount++;
			mac_addresses = strdup( optarg );
			break;
		case 'd':
			optcount++;
			expiry_date = strdup( optarg );
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (optcount > 2 || optcount < 2) {
		usage(argv[0]);
		exit(0);
	}

	int count = 0;
	int length = strlen( mac_addresses );
	if (length == 0) {
		usage(argv[0]);
		exit(0);
	}

	for (count = 0; count < length; count++) {
		if (mac_addresses[count] == '-')
			nb_of_mac_address++;
	}

	int mac_address_length = (nb_of_mac_address * 17 + nb_of_mac_address - 1);
	if (!mac_addresses || length < mac_address_length
			|| length > mac_address_length) {
		fprintf( stderr, "ERROR: Specify 12 characters MAC addresses separated by - . For example: 2A:3Z:45:6T:12:34-45:67:34:T5:78:FG\n");
		exit( 1 );
	}

	if (strlen(expiry_date) < 10 || strlen(expiry_date) > 10) {
		fprintf( stderr, "ERROR: Specify expiry date in format YYYY/MM/DD \n");
		exit( 2 );
	}

	return;
}

/**
 * This blocks contains no information but are used to make the license key difficult to read
 */
static inline void _encrypt( char *string ) {
	char *ch = string;
	while(  *ch != '\0' ) {
		*ch = *ch - (8 * 4 - 3);
		ch ++;
	}
}

int main(int argc, char **argv) {
	parseOptions(argc, argv);
	char year[5];  //4-digits
	char month[3]; //2-digits
	char day[3];   //2-digits

	unsigned int offset = 0;
	char license_data[3000] = { 0 };

	FILE *file = fopen("license.key", "w");
	if( file == NULL ){
		fprintf(stderr, "Error: Cannot create file. %s", strerror(errno) );
		return EXIT_FAILURE;
	}

	strncpy(year, expiry_date, 4);
	year[4] = '\0';

	//1. 4 characters for year
	offset += snprintf( license_data + offset, sizeof( license_data ) - offset, "%s", year );

	strncpy(month, &expiry_date[5], 2);
	month[2] = '\0';

	//2. 2 characters for month
	offset += snprintf( license_data + offset, sizeof( license_data ) - offset, "%s", month );

	strncpy(day, &expiry_date[8], 2);
	day[2] = '\0';

	//3. 2 characters for day
	offset += snprintf( license_data + offset, sizeof( license_data ) - offset, "%s", day );

	//4. 3 characters for number of mac addresses
	offset += snprintf( license_data + offset, sizeof( license_data ) - offset, "%03d", nb_of_mac_address );

	unsigned long check_sum = atoi(year) * atoi(month) * atoi(day) + nb_of_mac_address;

	//5. List of MAC addresses by removing separator - and :
	char *ch  = mac_addresses;
	while( *ch != '\0' ){
		if( *ch == ':' || *ch == '-' ){
			ch ++;
			continue;
		}

		check_sum += *ch;
		//copy to license_data
		license_data[offset] = *ch;
		offset ++;
		ch ++;

		if( offset >= sizeof( license_data )){
			fprintf(stderr, "ERROR: MAC addresses are too long");
			return EXIT_FAILURE;
		}
	}

	//6. Check sum
	offset += snprintf( license_data + offset, sizeof( license_data ) - offset, "%lu", check_sum );

	//obfuscate data
	_encrypt( license_data );

	//write to file
	fprintf(file, "%s", license_data );
	fclose( file );

	return EXIT_SUCCESS;
}

