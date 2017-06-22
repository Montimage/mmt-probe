#include <stdio.h>
#include <time.h>
#include <string.h>
//#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include "mmt_core.h"
#include "processing.h"

enum license_messages {
	BUY_MMT_LICENSE_FOR_THIS_DEVICE=1,
	MMT_LICENSE_EXPIRED,
	MMT_LICENSE_WILL_EXPIRE_SOON,
	MMT_LICENSE_MODIFIED,
	MMT_LICENSE_KEY_DOES_NOT_EXIST,
	MMT_LICENSE_INFO

};
/* This function gets MAC addresses from the machine and compares with license MAC field in the license key.
 * If machine MAC address matches license MAC returns 1, 0 otherwise
 * */
int gethostMACaddress(char *read_mac_address, int no_of_mac)
{
	unsigned char mac_address [7];
	char message [13];
	memset(mac_address, '0', 7);
	memset(message, '0', 13);
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	char licensed_MAC[13];
	int offset = 0;
	int j = 0;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
	}
	else
	{
		for ( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) )
			{
				struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
				memcpy(mac_address, &s->sll_addr, 6);
				mac_address[6] ='\0';
				snprintf(message, 13, "%.2x%.2x%.2x%.2x%.2x%.2x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
				message[12] = '\0';
				for (j = 0; j < no_of_mac; j++){
					memcpy(licensed_MAC, &read_mac_address[offset], 12);
					licensed_MAC[12] = '\0';
					if(strncmp(message, licensed_MAC, 12) == 0){
						freeifaddrs(ifaddr);
						return 1;
					}
					offset += 12;
				}
				offset = 0;
			}
		}
		freeifaddrs(ifaddr);
	}
	return 0;
}

/* This function checks MAC address, license expiry dates to validate the MMT license.
 * If license is valid returns 0, 1 otherwise.
 *  */
int license_expiry_check(int status){
	//struct tm *tm;
	struct tm expiry_time;
	time_t now;
	now = time(0);
	FILE * license_key;
	int MAX = 50;
	char message [MAX];
	char year[5];
	char month[3];
	char day[3];
	char no_of_mac_address[4];
	char *read_mac_address;
	int no_of_mac;
	char read_sum_license[20];
	char license_message[MAX_MESS + 1];
	char lg_msg[512];
	char version_probe[15] = "v0.95-003fc92";
	char version_sdk[15] = "v1.4-6e9fae9";
	char ch;
	char license_decrypt_key[300];
	int i = 0;

	int return_ok = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	//convert timeval time into epoch time
	struct timeval current_time;
	gettimeofday (&current_time, NULL);

	license_key = fopen(probe_context->license_location, "r");
	//license_key= fopen("license.key", "r");

	if(license_key == NULL) {
		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_KEY_DOES_NOT_EXIST);
		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable == 1 && status == 0) send_message_to_file (license_message);
		if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
		if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


		sprintf(lg_msg, "\n\t*************************************\n"
				"\t*  MMT LICENSE KEY DOES-NOT EXIST   *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);

		return 1;
	}

	while(1)
	{
		ch=fgetc(license_key);
		if(ch == EOF)
		{
			//printf("\nEnd Of File\n");
			break;
		}
		else
		{
			ch = ch + (8*4-3);
			license_decrypt_key[i] = ch;
			i++;
		}
	}
	license_decrypt_key [i] = '\0';

	int length = strlen (license_decrypt_key);

	if (length < 11){
		//printf("modified \n");
		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec,MMT_LICENSE_MODIFIED);

		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
		if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
		if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


		sprintf(lg_msg,"\n\t*************************************\n"
				"\t*        MMT LICENSE MODIFIED       *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
		return_ok = 1;
		return return_ok;
	}

	strncpy(year, &license_decrypt_key[0], 4);
	strncpy(month, &license_decrypt_key[4], 2);
	strncpy(day, &license_decrypt_key[6], 2);
	strncpy(no_of_mac_address, &license_decrypt_key[8], 3);
	year[4] = '\0';
	month[2] = '\0';
	day[2] = '\0';
	no_of_mac_address[3] = '\0';
	no_of_mac = atoi(no_of_mac_address);
	int mac_length = 0;
	mac_length = no_of_mac * 12;

	if (length - 11 <= mac_length){
		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_MODIFIED);

		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
		if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
		if (probe_context->kafka_enable == 1 && status == 0 )send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


		sprintf(lg_msg,"\n\t*************************************\n"
				"\t*        MMT LICENSE MODIFIED       *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
		return_ok = 1;
		return return_ok;

	}
	read_mac_address=malloc(sizeof(char)* (mac_length+1));
	strncpy(read_mac_address, &license_decrypt_key[11], mac_length);
	read_mac_address[mac_length]='\0';

	if (length - 11 - mac_length <= 0){
		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_MODIFIED);

		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
		if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
		if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


		sprintf(lg_msg,"\n\t*************************************\n"
				"\t*        MMT LICENSE MODIFIED       *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
		return_ok = 1;
		return return_ok;

	}
	strncpy(read_sum_license, &license_decrypt_key[11+mac_length], length-(mac_length+11));
	read_sum_license[length - (mac_length+11)] = '\0';

	int yr = atoi(year);
	int mn = atoi(month);
	int dy = atoi(day);

	long int date_sum = yr*mn*dy;
    long int  sum_mac = 0;
    int m;

	for (m = 0; m < (no_of_mac*12); m++){

		sum_mac += read_mac_address[m];

	}
	long int sum_license_calc = date_sum + sum_mac + no_of_mac;

	char * mac_address;
	mac_address = malloc(sizeof(char) * no_of_mac * 13);

	int j = 0;
	int offset_mac_read = 0;
	int offset_mac_write = 0;
	for (j = 1; j <= no_of_mac; j++){
		strncpy(&mac_address[offset_mac_write], &read_mac_address[offset_mac_read], 12);
		if (j != no_of_mac){
			mac_address[12 + offset_mac_write] = ',';
			offset_mac_write += 13;
			offset_mac_read += 12;
		}else{
			offset_mac_write += 12;
			offset_mac_read += 12;
		}
	}
	mac_address[offset_mac_write] = '\0';

	if(license_key != NULL) fclose (license_key);

	//calculate difference in seconds between two dates
	expiry_time = * localtime(&now);
	double seconds;
	//expiry date
	expiry_time.tm_hour = 0; expiry_time.tm_min = 0; expiry_time.tm_sec = 0;
	expiry_time.tm_mday = dy;expiry_time.tm_mon = mn-1; expiry_time.tm_year = yr-1900;
	time_t expiry_date = mktime(&expiry_time);
	seconds = difftime(mktime(&expiry_time), now);

	//convert time_t into epoch time
	struct timeval expired_date;
	expired_date.tv_sec = expiry_date;
	expired_date.tv_usec = 0;


	//if (strncmp(key,message,valid)==0 && yr==atoi(year) && mn==atoi(month) && dy==atoi(day) && strncmp(read_sum_mac,sum_mac_str,valid1)==0 && strncmp(read_sum_block,sum_block_str,valid2)==0){
	if (sum_license_calc == atoi(read_sum_license)){

		int valid_mac = gethostMACaddress(read_mac_address,no_of_mac);

		if (valid_mac == 0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, BUY_MMT_LICENSE_FOR_THIS_DEVICE, no_of_mac, mac_address, expired_date.tv_sec, expired_date.tv_usec, version_probe, version_sdk);

			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
			if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
			if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


			sprintf(lg_msg, "\n\t*************************************\n"
					"\t*          BUY MMT LICENSE          *\n"
					"\t*   Website: http://montimage.com   *\n"
					"\t*   Contact: contact@montimage.com  *\n"
					"\t**************************************\n\n");
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
			return_ok = 1;
		}

		if (seconds <= 0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec,MMT_LICENSE_EXPIRED, no_of_mac,mac_address, expired_date.tv_sec, expired_date.tv_usec, version_probe, version_sdk);

			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
			if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
			if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


			sprintf(lg_msg, "\n\t*************************************\n"
					"\t* MMT LICENSE EXPIRED ON %04d-%02d-%02d *\n"
					"\t*          BUY MMT LICENSE          *\n"
					"\t*   Website: http://montimage.com   *\n"
					"\t*   Contact: contact@montimage.com  *\n"
					"\t**************************************\n\n", yr, mn, dy);
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);

			return_ok = 1;
		}

		//Seven days =7*24*60*60
		if ( seconds <= 604800 && seconds > 0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_WILL_EXPIRE_SOON, no_of_mac,mac_address, expired_date.tv_sec, expired_date.tv_usec, version_probe, version_sdk);
			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
			if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
			if (probe_context->kafka_enable == 1 && status ==0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);


			sprintf(lg_msg,"\n\t***********************************************\n"
					"\t*  MMT LICENSE WILL EXPIRE ON %04d-%02d-%02d  *\n"
					"\t*              BUY MMT LICENSE                *\n"
					"\t*        Website: http://montimage.com        *\n"
					"\t*        Contact: contact@montimage.com       *\n"
					"\t************************************************\n\n", yr, mn, dy);
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
			return_ok = 0;
		}else if (seconds > 604800 && valid_mac == 1){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_INFO, no_of_mac, mac_address, expired_date.tv_sec, expired_date.tv_usec, version_probe, version_sdk);
			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
			if (probe_context->redis_enable== 1 && status == 0)send_message_to_redis ("license.stat", license_message);
			if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);

		}
	}else{

		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%d,%d,\"%s\",%lu.%06lu,\"%s\",\"%s\"", MMT_LICENSE_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, current_time.tv_sec, current_time.tv_usec, MMT_LICENSE_MODIFIED, no_of_mac, mac_address, expired_date.tv_sec, expired_date.tv_usec, version_probe, version_sdk);

		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable == 1 && status == 0)send_message_to_file (license_message);
		if (probe_context->redis_enable == 1 && status == 0)send_message_to_redis ("license.stat", license_message);
		if (probe_context->kafka_enable == 1 && status == 0)send_msg_to_kafka(probe_context->topic_object->rkt_license, license_message);

		sprintf(lg_msg,"\n\t*************************************\n"
				"\t*        MMT LICENSE MODIFIED       *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
		return_ok = 1;
	}

	if(mac_address) free(mac_address);
	mac_address = NULL;
	if(read_mac_address) free(read_mac_address);
	read_mac_address = NULL;
	return return_ok;
}

