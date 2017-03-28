/*
 * attributes_extraction.c
 *
 *  Created on: Dec 28, 2016
 *      Author: montimage
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

/**
 * FTP command structure: CMD PARAMETER
 */
typedef struct ftp_command_struct{
	uint16_t cmd;
	char *str_cmd;
	char *param;
}ftp_command_t;

/**
 * FTP response structure
 */
typedef struct ftp_response_struct{
	uint16_t code;
	char *str_code;
	char *value;
}ftp_response_t;

/* This function extracts the protocol payload from a packet for reporting  */
void payload_extraction(const ipacket_t * ipacket,struct smp_thread *th,attribute_t * attr_extract, int report_num){
	int  j = 0;
	uint16_t length = 0;
	uint16_t offset = 0;
	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset += ipacket->proto_headers_offset->proto_path[j];
		if (ipacket->proto_hierarchy->proto_path[j] == attr_extract->proto_id){
			if ((j+1) < ipacket->proto_hierarchy->len){
				offset += ipacket->proto_headers_offset->proto_path[j+1];
				//printf ("offset = %u\n",offset);
				length = ipacket->p_hdr->caplen - offset;
				//printf ("proto_id = %u, packet_len =%u, offset = %u\n",ipacket->proto_hierarchy->proto_path[j],ipacket->p_hdr->caplen,length);
			}
		}

	}
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], &length, 2);
	th->report[report_num].length += 2;
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], attr_extract->data,length);
	th->report[report_num].length +=  length;
	//printf ("attribute_data ...=%s \n", (char *)attr_extract->data);
}

/* This function extracts the protocol data from a packet for reporting  */
void data_extraction(const ipacket_t * ipacket,struct smp_thread *th,attribute_t * attr_extract, int report_num){
	int  j = 0;

	uint16_t length = 0;
	uint16_t offset = 0;
	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset +=ipacket->proto_headers_offset->proto_path[j];
		if (ipacket->proto_hierarchy->proto_path[j] == attr_extract->proto_id){
			if (j < ipacket->proto_hierarchy->len){
				//printf ("offset = %u\n",offset);
				length = ipacket->p_hdr->caplen - offset;
				//printf ("proto_id = %u, packet_len =%u, offset = %u\n",ipacket->proto_hierarchy->proto_path[j],ipacket->p_hdr->caplen,length);
			}
		}
	}
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], &length, 2);
	th->report[report_num].length += 2;
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], attr_extract->data,length);
	th->report[report_num].length +=  length;
	//printf ("attribute_data ...=%s \n",(char *)attr_extract->data);

}

/* This function extracts the ftp_last_command from a packet for reporting  */
void ftp_last_command(const ipacket_t * ipacket,struct smp_thread *th,attribute_t * attr_extract, int report_num){

	uint16_t length = 0;
	ftp_command_t * last_command = (ftp_command_t *)attr_extract->data;
	length = strlen(last_command->str_cmd);
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], &length, 2);
	th->report[report_num].length += 2;
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], last_command->str_cmd,length);
	th->report[report_num].length +=  length;
	//printf ("len= %u, attribute_data ...=%s \n",length,last_command->str_cmd);
}

/* This function extracts the ftp_last_response_code from a packet for reporting  */
void ftp_last_response_code(const ipacket_t * ipacket,struct smp_thread *th,attribute_t * attr_extract, int report_num){

	uint16_t length = 0;
	ftp_response_t * last_command = (ftp_response_t *)attr_extract->data;
	length = strlen(last_command->str_code);
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], &length, 2);
	th->report[report_num].length += 2;
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], last_command->str_code,length);
	th->report[report_num].length +=  length;
	//printf ("len= %u, attribute_data ...=%s \n",length,last_command->str_code);
}

/* This function extracts the ip_opts from a packet for reporting  */
void ip_opts(const ipacket_t * ipacket,struct smp_thread *th,attribute_t * attr_extract, int report_num){
	int  j = 0;
	uint16_t length = 0;
	uint16_t offset = 0;
	uint16_t offset_ip = 0;
	for (j = 1; j < ipacket->proto_hierarchy->len; j++){
		offset +=ipacket->proto_headers_offset->proto_path[j];
		if (ipacket->proto_hierarchy->proto_path[j] == attr_extract->proto_id){
			if (j < ipacket->proto_hierarchy->len){
				offset_ip = offset;
				offset += ipacket->proto_headers_offset->proto_path[j+1];
				length = ipacket->p_hdr->caplen - offset - offset_ip - 20;
				//printf ("proto_id = %u, packet_len =%u, offset = %u\n",ipacket->proto_hierarchy->proto_path[j],ipacket->p_hdr->caplen,length);
			}
		}
	}
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], &length, 2);
	th->report[report_num].length += 2;
	memcpy(&th->report[report_num].data[th->report[report_num].security_report_counter][th->report[report_num].length], attr_extract->data,length);
	th->report[report_num].length +=  length;
	//printf ("attribute_data ...=%s \n",(char *)attr_extract->data);

}
