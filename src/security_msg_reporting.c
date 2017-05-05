/*
 * security_msg_reporting.c
 *
 *  Created on: Mar 29, 2017
 *      Author: montimage
 */

#include "processing.h"

/* This function extracts the required information from the #ipacket, which is required to create
 * a security report and then sends the message/report to mmt-security through socket.
 * */
void get_security_report(const ipacket_t * ipacket,void * args){

	mmt_probe_context_t * probe_context = get_probe_context_config();
	attribute_t * attr_extract;
	struct smp_thread *th = (struct smp_thread *) args;
	int MAX_LEN = 1024;
	int i = 0, j = 0, k = 0;
	//condition1 = 0, condition2 = 0, condition3 = 0;
	int retval =0;


	for(i = 0; i < probe_context->security_reports_nb; i++) {
		//p = 0;
		if (probe_context->security_reports[i].enable == 0)
			continue;
		int initial_buffer_size =10000;
		security_report_buffer_t *report_ptr = &( th->report[i] );

		report_ptr->length = 0;
		//memset(report_ptr->data[report_ptr->security_report_counter], '\0', 10000);
		memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length + 5], &ipacket->p_hdr->ts,sizeof(struct timeval));
		report_ptr->length += sizeof(struct timeval) + 5; //4 bytes are reserved to assign the total length of the report and 1 byte for the number of attributes
		k = 0;
		//condition1 = 0, condition2 = 0, condition3 = 0;

		for(j = 0; j < probe_context->security_reports[i].attributes_nb; j++) {
			mmt_security_attribute_t * security_attribute = &probe_context->security_reports[i].attributes[j];
			attr_extract   = get_extracted_attribute( ipacket,security_attribute->proto_id, security_attribute->attribute_id );

			int rem_buffer = initial_buffer_size - (report_ptr->length+10);

			if(attr_extract != NULL) {
				if( unlikely( attr_extract->data_len > rem_buffer )){
					printf("Buffer_overflow\n");
					break;
				}

				memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length], &attr_extract->proto_id, 4);
				report_ptr->length += 4;
				memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length], &attr_extract->field_id, 4);
				report_ptr->length += 4;

				if (attr_extract->data_type == MMT_HEADER_LINE
						|| attr_extract->data_type == MMT_DATA_PATH
						|| attr_extract->data_type == MMT_BINARY_DATA
						|| attr_extract->data_type == MMT_BINARY_VAR_DATA
						|| attr_extract->data_type == MMT_STRING_DATA
						|| attr_extract->data_type == MMT_STRING_LONG_DATA
						|| attr_extract->data_type == MMT_STRING_DATA_POINTER){

					report_ptr->length += 2;
					int valid = mmt_attr_sprintf((char *)&report_ptr->data[report_ptr->security_report_counter][report_ptr->length], MAX_LEN, attr_extract);
					memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length - 2], &valid, 2);
					report_ptr->length +=  valid;

				} else if (attr_extract->data_type == MMT_DATA_POINTER){
					if (attr_extract->field_id == PROTO_PAYLOAD)payload_extraction(ipacket,th,attr_extract, i);
					if (attr_extract->field_id == PROTO_DATA)data_extraction(ipacket,th,attr_extract, i);
					if (attr_extract->proto_id == PROTO_FTP && attr_extract->field_id == FTP_LAST_COMMAND)ftp_last_command(ipacket,th,attr_extract, i);
					if (attr_extract->proto_id == PROTO_FTP && attr_extract->field_id == FTP_LAST_RESPONSE_CODE)ftp_last_response_code(ipacket,th,attr_extract, i);
					if (attr_extract->proto_id == PROTO_IP && attr_extract->field_id == IP_OPTS)ip_opts(ipacket,th,attr_extract, i);

				} else {
					memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length], &attr_extract->data_len, 2);
					report_ptr->length += 2;
					memcpy(&report_ptr->data[report_ptr->security_report_counter][report_ptr->length], attr_extract->data, attr_extract->data_len);
					report_ptr->length +=  attr_extract->data_len;
				}
				k++;

			}
		}

		//all attribute data are NULL

		if (unlikely( k == 0 )) continue;

		//First 4 bytes contains the total length of the report
		memcpy(&report_ptr->data[report_ptr->security_report_counter][0], &report_ptr->length, 4);
		//number of attributes
		report_ptr->data[report_ptr->security_report_counter][4] = k;
		//safe string
		report_ptr->data[report_ptr->security_report_counter][report_ptr->length] = '\0';

		if (probe_context->socket_enable == 1){
			th->packet_send ++;

			report_ptr->msg[report_ptr->security_report_counter].iov_base = report_ptr->data[report_ptr->security_report_counter];
			report_ptr->msg[report_ptr->security_report_counter].iov_len  = report_ptr->length;
			report_ptr->security_report_counter ++;

			if (report_ptr->security_report_counter == probe_context->nb_of_report_per_msg){
				report_ptr->grouped_msg.msg_hdr.msg_iov    = report_ptr->msg;
				report_ptr->grouped_msg.msg_hdr.msg_iovlen = probe_context->nb_of_report_per_msg;
				if (probe_context->socket_domain == 1 || probe_context->socket_domain == 2)
					retval = sendmmsg(th->sockfd_internet[i], &report_ptr->grouped_msg, 1, 0);
				if (probe_context->socket_domain == 0 || probe_context->socket_domain == 2)
					retval = sendmmsg(th->sockfd_unix, &report_ptr->grouped_msg, 1, 0);

				if ( unlikely( retval == -1))
					perror("sendmmsg()");

				report_ptr->security_report_counter = 0;
				memset(report_ptr->msg, 0, sizeof(struct iovec) *probe_context->nb_of_report_per_msg);
			}
		}
	}
}

/* This function registers extraction attribute for security report.
 * Returns 0 if unsuccessful
 * */
int register_security_report_handle(void * args) {
	int i = 0, j = 0, l = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;

    if (!register_extraction_attribute(th->mmt_handler,PROTO_IP,IP_HEADER_LEN)){ //ip_header_len is used for extraction of ip_opts
		fprintf(stderr,"[Error] Cannot register_extraction_attribute (security-report): IP_HEADER_LEN)");
    	return 0;
    }

	for(i = 0; i < probe_context->security_reports_nb; i++) {
		if (probe_context->security_reports[i].enable == 1){
			th->report[i].data = malloc (sizeof (unsigned char *) * probe_context->nb_of_report_per_msg +1);

			if (th->report[i].data == NULL){
				printf ("Error: Memory allocation of data in register_security_report_handle \n");
				exit(1);
			}
			th->report[i].msg = malloc (sizeof (struct iovec) * probe_context->nb_of_report_per_msg +1);

			if (th->report[i].msg == NULL){
				printf ("Error: Memory allocation of msg in register_security_report_handle \n");
				exit(1);
			}
			for (l=0; l < probe_context->nb_of_report_per_msg; l++)th->report[i].data[l]= malloc(10000);

			for(j = 0; j < probe_context->security_reports[i].attributes_nb; j++) {
				mmt_security_attribute_t * security_attribute = &probe_context->security_reports[i].attributes[j];

				security_attribute->proto_id = get_protocol_id_by_name (security_attribute->proto);
				if (security_attribute->proto_id == 0) return 0;

				security_attribute->attribute_id = get_attribute_id_by_protocol_and_attribute_names(security_attribute->proto, security_attribute->attribute);
				if (security_attribute->attribute_id == 0) return 0;

				if (is_registered_attribute(th->mmt_handler, security_attribute->proto_id, security_attribute->attribute_id) == 0){
					if (!register_extraction_attribute(th->mmt_handler, security_attribute->proto_id, security_attribute->attribute_id)) {
						fprintf(stderr,"[Error] Cannot register_extraction_attribute (security-report): proto: %s ,attribute: %s \n",security_attribute->proto,security_attribute->attribute);
						return 0;
					}
				}else{
					fprintf(stderr,"[WARNING] Already registered register_extraction_attribute (security-report): proto: %s ,attribute: %s \n",security_attribute->proto,security_attribute->attribute);

				}
			}
		}
	}
	return 1;
}

/* This function initialize security report.
 * */
void security_reports_init(void * args) {

	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th = (struct smp_thread *) args;
	th->report = calloc(sizeof(security_report_buffer_t), probe_context->security_reports_nb);
	if (th->report == NULL){
		printf ("Error: Memory allocation of report in security_reports_init \n");
		exit(1);
	}

	if(register_security_report_handle((void *) th) == 0) {
		fprintf(stderr, "Error while initializing security report !\n");
		exit(1);
	}
	if (probe_context->socket_enable == 1 && th->socket_active == 0){
		create_socket(probe_context, args);
		th->socket_active = 1;
	}
	if (is_registered_packet_handler(th->mmt_handler,6) == 1)unregister_packet_handler(th->mmt_handler, 6);
	register_packet_handler(th->mmt_handler, 6, packet_handler, (void *) th);
}


