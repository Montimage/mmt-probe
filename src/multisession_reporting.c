/*
 * multisession_reporting.c
 *
 *  Created on: Mar 29, 2017
 *      Author: montimage
 */

#include "processing.h"

/* This function extracts the required information from the #ipacket, which is required to create
 * a multi_session report and then sends the message/report through redis in a particular channel.
 * */
void get_security_multisession_report(const ipacket_t * ipacket,void * args){
	int i = 0, j = 0, offset = 0, valid = 0, k = 0;
	int LEN = 10000;
	char message[LEN + 1];
	//char attribute_value [MAX_MESS +1];
	attribute_t * attr_extract;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	int attr_len =0;

	struct smp_thread *th = (struct smp_thread *) args;
	struct timeval current_time;
	gettimeofday (&current_time, NULL);

	for(i = 0; i < probe_context->security_reports_multisession_nb; i++) {
		j=0, offset = 0, valid = 0;

		if (probe_context->security_reports_multisession[i].enable == 0)
			continue;
		valid= snprintf(message, LEN,
				"%u,%u,%lu.%06lu",
				MMT_MULTI_SESSION_REPORT_FORMAT,probe_context->probe_id_number, current_time.tv_sec,current_time.tv_usec);
		if(valid > 0) {
			offset += valid;
		}else {
			printf ("ERROR: In function get_security_multisession_report, valid1 < 0 \n ");
		}

		for(j = 0; j < probe_context->security_reports_multisession[i].attributes_nb; j++) {
			mmt_security_attribute_t * security_attribute_multisession   = &probe_context->security_reports_multisession[i].attributes[j];
			attr_extract = get_extracted_attribute(ipacket,security_attribute_multisession->proto_id, security_attribute_multisession->attribute_id);
			message[offset] = ',';
			if(attr_extract != NULL) {
				valid = mmt_attr_sprintf(&message[offset + 1], LEN - offset + 1, attr_extract);
				if(valid > 0) {
					offset += valid + 1;
					k++;
				}else {
					printf ("ERROR: In function get_security_multisession_report, valid2 < 0 \n ");
				}
			}else {
				message[offset + 1] = ' ';
				offset += 2;
			}
		}
		message[ offset ] = '\0';
		if (k == 0)return;
	}

		if (probe_context->output_to_file_enable && probe_context->multisession_output_channel[0]) send_message_to_file_thread (message, th);
		if (probe_context->redis_enable && probe_context->multisession_output_channel[1]) send_message_to_redis ("multisession.report", message);
		if (probe_context->kafka_enable && probe_context->multisession_output_channel[2])send_msg_to_kafka(probe_context->topic_object->rkt_multisession, message);
}

/* This function registers extraction attribute for multisession reports.
 * Returns 0 if unsuccessful
 * */
int register_security_report_multisession_handle(void * args) {
	int i = 0, j = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;

	for(i = 0; i < probe_context->security_reports_multisession_nb; i++) {
		if (probe_context->security_reports_multisession[i].enable == 1){

			for(j = 0; j < probe_context->security_reports_multisession[i].attributes_nb; j++) {
				mmt_security_attribute_t * security_attribute_multisession = &probe_context->security_reports_multisession[i].attributes[j];

				security_attribute_multisession->proto_id = get_protocol_id_by_name (security_attribute_multisession->proto);
				if (security_attribute_multisession->proto_id == 0) return 0;

				security_attribute_multisession->attribute_id = get_attribute_id_by_protocol_and_attribute_names(security_attribute_multisession->proto, security_attribute_multisession->attribute);
				if (security_attribute_multisession->attribute_id == 0) return 0;

				if (is_registered_attribute(th->mmt_handler, security_attribute_multisession->proto_id, security_attribute_multisession->attribute_id) == 0){
					if (!register_extraction_attribute(th->mmt_handler, security_attribute_multisession->proto_id, security_attribute_multisession->attribute_id)){
						fprintf(stderr,"[Error] Cannot register_extraction_attribute (multisession_report): proto: %s ,attribute: %s \n",security_attribute_multisession->proto,security_attribute_multisession->attribute);
						return 0;
					}
				}else {
					fprintf(stderr,"[WARNING] Already registered register_extraction_attribute (multisession_report): proto: %s ,attribute: %s \n",security_attribute_multisession->proto,security_attribute_multisession->attribute);
				}

			}
		}
	}
	return 1;
}

/* This function initialize multisession reports.  * */
void security_reports_multisession_init(void * args) {

	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th = (struct smp_thread *) args;


	if(register_security_report_multisession_handle((void *) th) == 0) {
		fprintf(stderr, "Error while initializing security_reports_multisession !\n");
	}
/*
	if (probe_context->socket_enable == 1 && th->socket_active == 0){
		create_socket(probe_context, args);
		th->socket_active = 1;
	}
*/
	if (is_registered_packet_handler(th->mmt_handler,6) == 1)unregister_packet_handler(th->mmt_handler, 6);
	register_packet_handler(th->mmt_handler, 6, packet_handler, (void *) th);
}
