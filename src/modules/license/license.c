#include <stdio.h>
#include <time.h>
#include <string.h>
//#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <mmt_core.h>

#include "../../lib/limit.h"
#include "../../lib/version.h"
#include "../../lib/log.h"


#include "license.h"

typedef struct license_content_struct{
	int year; //time to expire
	int month;//time to expire
	int day;  //time to expire
	int mac_count; //number of MAC address to verify
	// a pointer points to a buffer containing MAC addresses.
	// This buffer must be larger enough to contain the addresses.
	// Each MAC address has 16 characters, thus if #mac_count = 5 then
	// this buffer must have a size of 60
	char *mac_addresses;
}license_content_t;


enum license_messages {
	BUY_MMT_LICENSE_FOR_THIS_DEVICE=1,
	MMT_LICENSE_EXPIRED,
	MMT_LICENSE_WILL_EXPIRE_SOON,
	MMT_LICENSE_MODIFIED,
	MMT_LICENSE_KEY_DOES_NOT_EXIST,
	MMT_LICENSE_INFO
};

/**
 * Get mac addresses of available NIC
 * @param mac_addresses
 * @return number of mac addresses
 * @note size of #mac_addresses must be larger enough to contain addresses.
 * For example, if 4 NIC are found then #mac_addresses will contain 4*6 characters
 * representing 4 MAC addresses.
 */
static inline int _get_host_mac_address( unsigned char *mac_addresses ){
	unsigned char *str = mac_addresses;
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa;
	int mac_count = 0;

	if( getifaddrs(&ifaddr) == -1 )
		return 0;
	for ( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
		if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) ){
			struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
			memcpy( str, &s->sll_addr, 6);
			str += 6;
			mac_count ++;
		}
	}
	freeifaddrs(ifaddr);

	return mac_count;
}


/**
 * Decode content of license file
 * @param license_file_name
 * @param content is a pointer points to a memory buffer to contain decripted content of license
 * @return
 * 	- NULL if file does not exist
 * 	- length of the content
 */
static inline int _decode_license_file( const char* license_file_name, license_content_t *li  ){
	int len = 0, i;
	int ch;
	char license_decrypt_key[1000];
	char string[10];
	int mac_len;
	FILE *file = fopen( license_file_name, "r" );
	long int sum_license;
	long int val;

	if(file == NULL)
		return MMT_LICENSE_KEY_DOES_NOT_EXIST;

	while( (ch=fgetc( file )) != EOF ){
		//decode file content
		ch = ch + (8*4-3);

		license_decrypt_key[ len++ ] = ch;
	}

	license_decrypt_key [len] = '\0';

	//license file is not conform
	if( len < 11 ){
		fclose( file );
		return 2;
	}

	//decode content structure
	strncpy(string, &license_decrypt_key[0], 4);
	string[4] = '\0';
	li->year = atoi( string );

	strncpy(string, &license_decrypt_key[4], 2);
	string[2] = '\0';
	li->month = atoi( string );

	strncpy( string, &license_decrypt_key[6], 2);
	string[2] = '\0';
	li->day = atoi( string );

	strncpy( string, &license_decrypt_key[8], 3);
	string[3] = '\0';
	li->mac_count = atoi( string );

	mac_len = li->mac_count * 12;
	if( len-11 < mac_len ){
		fclose( file );
		return MMT_LICENSE_MODIFIED;
	}

	//copy mac addresses and calculate its total value
	sum_license = 0;
	for( i=0; i<mac_len; i++ ){
		li->mac_addresses[ i ] = license_decrypt_key[i+11];
		sum_license           += license_decrypt_key[i+11];
	}

	sum_license += (li->year * li->month * li->day) + li->mac_count;

	//last check the integrity of license file
	val = atol( &license_decrypt_key[ 11 + mac_len ] );
	if( val != sum_license ){
		fclose( file );
		return MMT_LICENSE_MODIFIED;
	}
	fclose( file );
	return 0;
}

/**
 * Verify license agaist a list of mac addresses
 * @param license
 * @param mac_count is number of mac addresses
 * @param mac_addresses is a tuple of 6-char MAC. Its size is (#mac_count * 6)
 *
 * @param time_remaining is number of seconds remaining in the case of the license is conform
 * @return
 * 	- true if license is conform, i.e., it contains a mac in the given mac addresses
 * 	- false, otherwise
 */
static inline bool _check_license( const license_content_t *license, size_t mac_count, const unsigned char *mac_addresses, double *time_remaining ){
	struct tm expiry_time;
	time_t now = time(0);
	int i,j, val;
	char mac[13];
	const unsigned char *ptr;
	int is_ok = false;

	//check conform mac addresses;
	for( i=0; i<mac_count; i++ ){
		ptr = & mac_addresses[ i*6 ];
		//convert mac to readable format
		snprintf( mac, 13, "%.2x%.2x%.2x%.2x%.2x%.2x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5] );

		//find if this mac exists on license
		for( j=0; j<license->mac_count; j++ ){
			val = strncmp( &license->mac_addresses[j*12], mac, 12 );
			//found one in license
			if( val == 0 ){
				is_ok = true;
				break;
			}
		}
		if( is_ok ) break;
	}

	//check expired time
	expiry_time = *localtime( &now );
	expiry_time.tm_hour = expiry_time.tm_min = expiry_time.tm_sec = 0;
	expiry_time.tm_mday = license->day;
	expiry_time.tm_mon  = license->month - 1;
	expiry_time.tm_year = license->year  - 1900; //since 1900

	//calculate difference in seconds between two dates
	*time_remaining = difftime( mktime(&expiry_time), now );

	return is_ok;
}

/**
 *  This function checks MAC address, license expiry dates to validate the MMT license.
 * @return
 * - true if license is valid,
 * - false otherwise.
 */
bool license_check_expiry( const char *license_file, output_t *output ){
	const char *version_probe = get_version();
	const char *version_sdk   = mmt_version();

	license_content_t license;
	char mac_stored_in_license[1000];

	unsigned char mac_to_verify[1000];
	size_t nb_of_mac_to_verify;

	char *mac_address, *char_ptr;
	double time_remaining;

	int ret, i;

	struct timeval current_time, expired_date;
	gettimeofday (&current_time, NULL);

	memset( &license, 0, sizeof( license ) );
	license.mac_addresses = mac_stored_in_license;
	ret = _decode_license_file( license_file, &license );

	if( ret == MMT_LICENSE_KEY_DOES_NOT_EXIST ) {
		output_write_report_with_format(output, CONF_OUTPUT_CHANNEL_ALL, LICENSE_REPORT_TYPE, &current_time,
				"%d",
				MMT_LICENSE_KEY_DOES_NOT_EXIST);

		log_write( LOG_WARNING, "MMT license key does not exist" );

		return false;
	}

	if( ret == MMT_LICENSE_MODIFIED ){
		output_write_report_with_format(output, CONF_OUTPUT_CHANNEL_ALL, LICENSE_REPORT_TYPE, &current_time,
						"%d",
						MMT_LICENSE_MODIFIED);

		log_write( LOG_WARNING,"MMT license was modified");

		return false;
	}

	//separate mac addresses by comma
	mac_address = malloc( license.mac_count * 13 );
	for( i=0; i<license.mac_count; i++ ){
		if( i == 0 ){
			memcpy( mac_address, &license.mac_addresses[i*12], 12 );
			mac_address[12] = '\0';
		}else{
			mac_address[ i*12 ] = ',';
			memcpy( &mac_address[i*13], &license.mac_addresses[i*12], 12 );
			mac_address[i*13 + 12] = '\0';
		}
	}

	nb_of_mac_to_verify = _get_host_mac_address( mac_to_verify );
	//cannot get any mac address of the current machine
	if( nb_of_mac_to_verify == 0 ){
		log_write( LOG_WARNING, "Cannot read MAC of the machine");
		free( mac_address );
		return false;
	}

	ret = _check_license( &license, nb_of_mac_to_verify, mac_to_verify, &time_remaining );

	expired_date.tv_usec = 0;
	expired_date.tv_sec  = current_time.tv_sec + time_remaining;

	//license does not conform
	if ( ret == false ){
		output_write_report_with_format(output, CONF_OUTPUT_CHANNEL_ALL, LICENSE_REPORT_TYPE, &current_time,
				"%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"",
				BUY_MMT_LICENSE_FOR_THIS_DEVICE,
				license.mac_count, mac_address,
				expired_date.tv_sec, expired_date.tv_usec,
				version_probe, version_sdk );

		log_write( LOG_WARNING, "Buy MMT license" );
		free( mac_address );
		return false;
	}

	//license ok but expired
	if( time_remaining <= 0 ){
		output_write_report_with_format(output, CONF_OUTPUT_CHANNEL_ALL, LICENSE_REPORT_TYPE, &current_time,
				"%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"",
				MMT_LICENSE_EXPIRED,
				license.mac_count, mac_address,
				expired_date.tv_sec, expired_date.tv_usec,
				version_probe, version_sdk );

		log_write( LOG_WARNING,"MMT license expired on %04d-%02d-%02d",
				license.year, license.month, license.day );

		free( mac_address );
		return false;
	}

	output_write_report_with_format(output, CONF_OUTPUT_CHANNEL_ALL, LICENSE_REPORT_TYPE, &current_time,
			"%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"",
			//License will expired in seven days???
			( time_remaining <= 7*24*60*60 ) ? MMT_LICENSE_WILL_EXPIRE_SOON : MMT_LICENSE_INFO,
			license.mac_count, mac_address,
			expired_date.tv_sec, expired_date.tv_usec,
			version_probe, version_sdk);

	log_write( LOG_WARNING, "MMT license will expire on %04d-%02d-%02d",
					license.year, license.month, license.day );

	free( mac_address );
	return true;
}
