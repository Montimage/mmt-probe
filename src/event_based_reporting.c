#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdatomic.h>
#include "mmt_core.h"
#include "processing.h"
#include <pthread.h>
#include "tcpip/mmt_tcpip.h"

/* This function is for reporting event report * */
void event_report_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	int j;
	attribute_t * attr_extract;
	int offset = 0, valid;
	char message[MAX_MESS + 1];
	struct user_data *p   = (struct user_data *) user_args;
	struct smp_thread *th = (struct smp_thread *) p->smp_thread;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	mmt_event_report_t * event_report   = p->event_reports; //(mmt_event_report_t *) user_args;
	if (atomic_load(&th->event_report_flag)==1 ) {
		return;
	}

	valid= snprintf(message, MAX_MESS,
			"%u,%u,\"%s\",%lu.%06lu,%u",
			MMT_EVENT_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ipacket->p_hdr->ts.tv_sec,ipacket->p_hdr->ts.tv_usec, event_report->id);
	if(valid > 0) {
		offset += valid;
	}else {
		return;
	}
	message[offset] = ',';

	valid = mmt_attr_sprintf(&message[offset+1], MAX_MESS - offset+1, attribute);

	if(valid > 0) {
		offset += valid+1;
	}else {
		return;
	}
	for(j = 0; j < event_report->attributes_nb; j++) {
		mmt_event_attribute_t * event_attribute = &event_report->attributes[j];
		attr_extract = get_extracted_attribute_by_name(ipacket,event_attribute->proto, event_attribute->attribute);
		message[offset] = ',';
		if(attr_extract != NULL) {
			valid = mmt_attr_sprintf(&message[offset + 1], MAX_MESS - offset+1, attr_extract);
			if(valid > 0) {
				offset += valid + 1;
			}else {

				return;
			}
		}else {

			offset += 1;
		}
	}
	message[ offset ] = '\0';
	//send_message_to_file ("event.report", message);
	printf ("message = %s\n", message);
	if (probe_context->output_to_file_enable && event_report->event_output_channel[0] ) send_message_to_file_thread (message, th);
	if (probe_context->redis_enable && event_report->event_output_channel[1] ) send_message_to_redis ("event.report", message);
	if (probe_context->kafka_enable && event_report->event_output_channel[2] ) send_msg_to_kafka(probe_context->topic_object->rkt_event, message);

}
/* This function registers attributes and handlers for event report.
 * Returns 0 if unsuccessful
 * */
int register_event_report_handle(void * args) {
	int j;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th ;
	struct user_data *p = ( struct user_data *) args;
	th = p->smp_thread;
	mmt_event_report_t * event_report = p->event_reports;

	event_report->event.proto_id = get_protocol_id_by_name (event_report->event.proto);
	if (event_report->event.proto_id == 0) return 0;

	event_report->event.attribute_id = get_attribute_id_by_protocol_and_attribute_names(event_report->event.proto, event_report->event.attribute);
	if (event_report->event.attribute_id == 0) return 0;

	if (is_registered_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle) == 0){
		if (!register_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle, NULL, (void *) p)){
			fprintf(stderr,"[Error] Cannot registered register_attribute_handler (event_report): proto: %s ,attribute: %s (report: %i)\n",event_report->event.proto,event_report->event.attribute, event_report->id);
			return 0;
		}

	}else{
		fprintf(stderr,"[WARNING] Already registered register_attribute_handler (event_report): proto: %s ,attribute: %s (report: %i)\n",event_report->event.proto,event_report->event.attribute, event_report->id);
		if (unregister_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle)== 0){
			return 0;
		}
		if (!register_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle, NULL, (void *) p)){
			fprintf(stderr,"[Error] Cannot registered register_attribute_handler (event_report): proto: %s ,attribute: %s (report: %i)\n",event_report->event.proto,event_report->event.attribute, event_report->id);
			return 0;
		}
		printf ("Unregistered the registered attribute handler and register the new handler \n");
	}
	for(j = 0; j < event_report->attributes_nb; j++) {
		mmt_event_attribute_t * event_attribute = &event_report->attributes[j];

		event_attribute->proto_id = get_protocol_id_by_name (event_attribute->proto);
		if (event_attribute->proto_id == 0) return 0;


		event_attribute->attribute_id = get_attribute_id_by_protocol_and_attribute_names(event_attribute->proto, event_attribute->attribute);
		if (event_attribute->attribute_id == 0) return 0;

		if (is_registered_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id) == 0){
			if (!register_extraction_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id)){
				fprintf(stderr,"[Error] Cannot register_extraction_attribute (event_report): proto: %s ,attribute: %s (report: %i)\n",event_attribute->proto,event_attribute->attribute, event_report->id);
				return 0;
			}
		}else{
			fprintf(stderr,"[WARNING] Already registered register_extraction_attribute (event_report): proto: %s ,attribute: %s (report: %i)\n",event_attribute->proto,event_attribute->attribute, event_report->id);
			if (unregister_extraction_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id) == 0){
				return 0;
			}
			if (!register_extraction_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id)){
				fprintf(stderr,"[Error] Cannot register_extraction_attribute (event_report): proto: %s ,attribute: %s (report: %i)\n",event_attribute->proto,event_attribute->attribute, event_report->id);
				return 0;
			}
			printf ("Unregistered the registered attribute and register the new attribute \n");

		}
	}
	return 1;
}

int unregister_event_report_handle(void * args) {
	int j;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th ;
	struct user_data *p = ( struct user_data *) args;
	th = p->smp_thread;
	mmt_event_report_t * event_report = p->event_reports;

	event_report->event.proto_id = get_protocol_id_by_name (event_report->event.proto);
	if (event_report->event.proto_id == 0) return 0;

	event_report->event.attribute_id = get_attribute_id_by_protocol_and_attribute_names(event_report->event.proto, event_report->event.attribute);
	if (event_report->event.attribute_id == 0) return 0;
	if (is_registered_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle) != 0){
		if (unregister_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle)== 0) return 0;

	}
	for(j = 0; j < event_report->attributes_nb; j++) {
		mmt_event_attribute_t * event_attribute = &event_report->attributes[j];

		event_attribute->proto_id = get_protocol_id_by_name (event_attribute->proto);
		if (event_attribute->proto_id == 0) return 0;


		event_attribute->attribute_id = get_attribute_id_by_protocol_and_attribute_names(event_attribute->proto, event_attribute->attribute);
		if (event_attribute->attribute_id == 0) return 0;

		if (is_registered_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id) != 0){
			if (unregister_extraction_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id) == 0) return 0;
		}
	}
	return 1;
}


/* This function initialize event report.
 * */
void event_reports_init(void * args) {
	int i;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread * th = (struct smp_thread *) args;
	struct user_data * p;
	mmt_event_report_t * current = probe_context->event_reports;
	if (current == NULL) printf ("ERROR Memory allocation : event_reports_init\n");

	while(current != NULL) {
		th->event_reports = current;
		if(th->event_reports->enable == 1){
			p = malloc( sizeof( struct user_data ));
			if (p == NULL){
				printf ("Error: Memory allocation of user_data in event_reports_init \n");
				exit(1);
			}
			p->smp_thread    = th;
			p->event_reports = th->event_reports;
			if(register_event_report_handle((void *) p) == 0) {
				fprintf(stderr, "Error while initializing event report number!\n");
				exit(1);
			}

		} else {

			p = malloc( sizeof( struct user_data ));
			if (p == NULL){
				printf ("Error: Memory allocation of user_data in event_reports_init \n");
				exit(1);
			}
			p->smp_thread    = th;
			p->event_reports = th->event_reports;
			if(unregister_event_report_handle((void *) p) == 0) {
				fprintf(stderr, "Error while uninitializing event report number \n");
				exit(1);
			}


		} 
		current = current->next;
	}
	if (probe_context->event_reports_nb > 0){
		atomic_store (&th->event_report_flag, 0);
	}

}

/* This function uninitialize event report.
 * */
/*void event_reports_uninit(void * args) {
        int i;
        mmt_probe_context_t * probe_context = get_probe_context_config();
        struct smp_thread * th = (struct smp_thread *) args;
        struct user_data * p;
        mmt_event_report_t * current = probe_context->event_reports;
        if (current == NULL) printf ("ERROR Memory allocation : event_reports_init\n");

        while(current != NULL) {
                printf ("HERE_event_init\n");
                th->event_reports = current;
                if(th->event_reports->enable == 1){
                       printf("here_inside\n");
                        p = malloc( sizeof( struct user_data ));
                        if (p == NULL){
                                printf ("Error: Memory allocation of user_data in event_reports_init \n");
                                exit(1);
                        }
                        p->smp_thread    = th;
                        p->event_reports = th->event_reports;
                        if(unregister_event_report_handle((void *) p) == 0) {
                                fprintf(stderr, "Error while initializing event report number %i!\n", th->event_reports->id);
                                exit(1);
                        }

                }
            current = current->next;
        }
}
 */
