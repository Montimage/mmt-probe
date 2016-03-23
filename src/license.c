#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
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
int gethostMACaddress(char *read_mac_address,int no_of_mac)
{
	unsigned char mac_address [7];
	char message [13];
	memset(mac_address,'0', 7);
	memset(message, '0', 13);
	struct ifaddrs *ifaddr=NULL;
	struct ifaddrs *ifa = NULL;
	char licensed_MAC[13];
	int offset=0;
	int j=0;

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
				mac_address[6]='\0';
				snprintf(message,13,"%.2x%.2x%.2x%.2x%.2x%.2x", mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
				message[12]='\0';
				for (j=0;j<no_of_mac;j++){
					memcpy(licensed_MAC,&read_mac_address[offset],12);
					licensed_MAC[12]='\0';
					if(strncmp(message,licensed_MAC,12)==0){
						freeifaddrs(ifaddr);
						return 1;
					}
					offset+=12;
				}
				offset =0;
			}
		}
		freeifaddrs(ifaddr);
	}
	return 0;
}

int license_expiry_check(int status){
	//struct tm *tm;
	struct tm expiry_time;
	time_t now;
	now=time(0);
	FILE * license_key;
	int MAX=50;
	char message[MAX];
	int valid=0;
	char year[5];
	char month[3];
	char day[3];
	char no_of_mac_address[4];
	char *read_mac_address;
	int no_of_mac;
	int offset=0;
	char block1[11];
	char block2[11];
	char block3[11];
	char block4[11];
	char license_message[MAX_MESS + 1];
	char lg_msg[256];
	char version_probe[15] = "v0.95-003fc92";
	char version_sdk[15] = "v1.4-6e9fae9";

	mmt_probe_context_t * probe_context = get_probe_context_config();
	//convert timeval time into epoch time
	struct timeval current_time;
	gettimeofday (&current_time, NULL);

	//license_key= fopen("/opt/mmt/mmt_bin/License_key.key", "r");
	license_key= fopen(probe_context->license_location, "r");
	//license_key= fopen("License_key.key", "r");

	if(license_key == NULL) {
		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,MMT_LICENSE_KEY_DOES_NOT_EXIST);
		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
		if (probe_context->redis_enable==1 && status ==0)send_message_to_redis ("license.stat", license_message);

		sprintf(lg_msg, "\n\t*************************************\n"
				"\t*  MMT LICENSE KEY DOES-NOT EXIST   *\n"
				"\t*          BUY MMT LICENSE          *\n"
				"\t*   Website: http://montimage.com   *\n"
				"\t*   Contact: contact@montimage.com  *\n"
				"\t**************************************\n\n");
		mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);

		return 1;
	}

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(block1,1,10,license_key);
	block1[10]='\0';

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(year,1,4,license_key);
	year[4]='\0';

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(month,1,2,license_key);
	month[2]='\0';

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(day,1,2,license_key);
	day[2]='\0';

	long int date = atoi(year)*atoi(month)*atoi(day);

	valid=snprintf(message,MAX,"%li",date);
	message[valid]='\0';

	char * key;
	key=malloc((valid+1)*sizeof(char));

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(block2,1,10,license_key);
	block2[10]='\0';

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(key,1,valid,license_key);
	key[valid]='\0';

	int mn_dy=atoi(month)* atoi (day);
	int yr_dy=atoi(year) * atoi(day);
	int mn_yr=atoi (month) * atoi (year);

	int yr =  atoi(key)/mn_dy;
	int mn= atoi(key)/yr_dy;
	int dy= atoi(key)/mn_yr;

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(block3,1,10,license_key);
	block3[10]='\0';

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(no_of_mac_address,1,3,license_key);
	no_of_mac_address[3]='\0';
	no_of_mac=atoi(no_of_mac_address);
	//printf("no_of_mac=%d\n",no_of_mac);


	int mac_length=0;
	mac_length=no_of_mac*12;

	read_mac_address=malloc(sizeof(char)* (mac_length+1));
	memset(read_mac_address,0,mac_length);
	fseek(license_key,offset,SEEK_SET);
	offset+=fread(read_mac_address,1,mac_length,license_key);
	read_mac_address[mac_length]='\0';


	char * mac_address;
	mac_address=malloc(sizeof(char)*no_of_mac*13);

	int j=0;
	int offset_mac_read=0;
	int offset_mac_write=0;
	for (j=1;j<=no_of_mac;j++){
		strncpy(&mac_address[offset_mac_write],&read_mac_address[offset_mac_read],12);
		if (j!=no_of_mac){
			mac_address[12+offset_mac_write]=',';
			offset_mac_write+=13;
			offset_mac_read+=12;
		}else{
			offset_mac_write+=12;
			offset_mac_read+=12;
		}

	}
	mac_address[offset_mac_write]='\0';
	//printf("MAC address=%s",mac_address);

	fseek(license_key,offset,SEEK_SET);
	offset+=fread(block4,1,10,license_key);
	block4[10]='\0';

	long int  sum_mac=0;
	int i;
	int valid1=0;

	for (i=0;i<(no_of_mac*12);i++){

		sum_mac+=read_mac_address[i];

	}

	char * sum_mac_str;

	sum_mac_str= malloc(sizeof(char)*20);

	memset(sum_mac_str,'0',20);
	valid1=snprintf(sum_mac_str,20,"%li",sum_mac);

	sum_mac_str[valid1]='\0';

	char * read_sum_mac;
	read_sum_mac=malloc(sizeof(char)* (valid1 + 1));
	fseek(license_key,offset,SEEK_SET);
	offset+=fread(read_sum_mac,1,valid1,license_key);
	read_sum_mac[valid1]='\0';

	int valid2=0;
	int k=0;
	unsigned long int  sum_of_blocks=0;

	for (k=0;k<10;k++){

		sum_of_blocks+=block1[k]+block2[k]+block3[k]+block4[k];

	}

	char * sum_block_str;

	sum_block_str= malloc(sizeof(char)*20);

	memset(sum_block_str,'0',20);
	valid2=snprintf(sum_block_str,20,"%lu",sum_of_blocks);
	sum_block_str[valid2]='\0';

	char * read_sum_block;
	read_sum_block=malloc(sizeof(char)* (valid2+1));
	fseek(license_key,offset,SEEK_SET);
	fread(read_sum_block,1,valid2,license_key);
	read_sum_block[valid2]='\0';

	//printf("sum_of_blocks_read=%s\n",read_sum_block);
	if(license_key != NULL) fclose (license_key);

	//calculate difference in seconds between two dates
	expiry_time = * localtime(&now);
	double seconds;
	//expiry date
	expiry_time.tm_hour = 0; expiry_time.tm_min = 0; expiry_time.tm_sec = 0;
	expiry_time.tm_mday = dy;expiry_time.tm_mon = mn-1; expiry_time.tm_year = yr-1900;
	time_t expiry_date =mktime(&expiry_time);
	seconds=difftime(mktime(&expiry_time),now);
	// printf("seconds=%f\n",seconds);


	//convert time_t into epoch time
	struct timeval expired_date;
	expired_date.tv_sec=expiry_date;
	expired_date.tv_usec=0;
	int return_ok = 0;

	if (strncmp(key,message,valid)==0 && yr==atoi(year) && mn==atoi(month) && dy==atoi(day) && strncmp(read_sum_mac,sum_mac_str,valid1)==0 && strncmp(read_sum_block,sum_block_str,valid2)==0){

		int valid_mac = gethostMACaddress(read_mac_address,no_of_mac);

		if (valid_mac == 0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d,%d,\"%s\",%lu.%lu,\"%s\",\"%s\"",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,BUY_MMT_LICENSE_FOR_THIS_DEVICE,no_of_mac,mac_address,expired_date.tv_sec,expired_date.tv_usec,version_probe,version_sdk);

			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
			if (probe_context->redis_enable==1&& status ==0)send_message_to_redis ("license.stat", license_message);

			sprintf(lg_msg, "\n\t*************************************\n"
					"\t*          BUY MMT LICENSE          *\n"
					"\t*   Website: http://montimage.com   *\n"
					"\t*   Contact: contact@montimage.com  *\n"
					"\t**************************************\n\n");
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
			return_ok = 1;
		}

		if (seconds <= 0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d,%d,\"%s\",%lu.%lu,\"%s\",\"%s\"",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,MMT_LICENSE_EXPIRED,no_of_mac,mac_address,expired_date.tv_sec,expired_date.tv_usec,version_probe,version_sdk);

			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
			if (probe_context->redis_enable==1 && status ==0)send_message_to_redis ("license.stat", license_message);

			sprintf(lg_msg,"\n\t*************************************\n"
					"\t* MMT LICENSE EXPIRED ON %04d-%02d-%02d *\n"
					"\t*          BUY MMT LICENSE          *\n"
					"\t*   Website: http://montimage.com   *\n"
					"\t*   Contact: contact@montimage.com  *\n"
					"\t**************************************\n\n",yr,mn,dy);
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);

			return_ok = 1;
		}

		//Seven days =7*24*60*60
		if ( seconds<=604800 && seconds>0){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d,%d,\"%s\",%lu.%lu,\"%s\",\"%s\"",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,MMT_LICENSE_WILL_EXPIRE_SOON,no_of_mac,mac_address,expired_date.tv_sec,expired_date.tv_usec,version_probe,version_sdk);
			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
			if (probe_context->redis_enable==1 && status ==0)send_message_to_redis ("license.stat", license_message);

			sprintf(lg_msg,"\n\t***********************************************\n"
					"\t*  MMT LICENSE WILL EXPIRE ON %04d-%02d-%02d  *\n"
					"\t*              BUY MMT LICENSE                *\n"
					"\t*        Website: http://montimage.com        *\n"
					"\t*        Contact: contact@montimage.com       *\n"
					"\t************************************************\n\n",yr,mn,dy);
			mmt_log(probe_context, MMT_L_INFO, MMT_LICENSE, lg_msg);
			return_ok = 0;
		}else if (seconds > 604800 && valid_mac == 1){
			snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d,%d,\"%s\",%lu.%lu,\"%s\",\"%s\"",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,MMT_LICENSE_INFO,no_of_mac,mac_address,expired_date.tv_sec,expired_date.tv_usec,version_probe,version_sdk);
			license_message[ MAX_MESS ] = '\0';
			if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
			if (probe_context->redis_enable==1 && status ==0)send_message_to_redis ("license.stat", license_message);

		}
	}else{

		snprintf(license_message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%d,%d,\"%s\",%lu.%lu,\"%s\",\"%s\"",30,probe_context->probe_id_number,probe_context->input_source,current_time.tv_sec,current_time.tv_usec,MMT_LICENSE_MODIFIED,no_of_mac,mac_address,expired_date.tv_sec,expired_date.tv_usec,version_probe,version_sdk);

		license_message[ MAX_MESS ] = '\0';
		if (probe_context->output_to_file_enable==1 && status ==0)send_message_to_file (license_message);
		if (probe_context->redis_enable==1 && status ==0)send_message_to_redis ("license.stat", license_message);

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
	if(key) free(key);
	key = NULL;
	if(read_sum_mac) free(read_sum_mac);
	read_sum_mac = NULL;
	if(sum_mac_str) free(sum_mac_str);
	sum_mac_str = NULL;
	if(sum_block_str) free(sum_block_str);
	sum_block_str = NULL;
	if(read_sum_block) free(read_sum_block);
	read_sum_block = NULL;
	if(read_mac_address) free(read_mac_address);
	read_mac_address = NULL;

	return return_ok;
}

