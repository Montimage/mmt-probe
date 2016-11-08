#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "processing.h"
#include <pthread.h>

void event_report_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    int j;
    attribute_t * attr_extract;
    int offset = 0, valid;
    char message[MAX_MESS + 1];
    struct user_data *p   = (struct user_data *) user_args;
	struct smp_thread *th = (struct smp_thread *) p->smp_thread;
    mmt_probe_context_t * probe_context = get_probe_context_config();
    mmt_event_report_t * event_report   = p->event_reports; //(mmt_event_report_t *) user_args;

    valid= snprintf(message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%lu",
            event_report->id, probe_context->probe_id_number, probe_context->input_source, ipacket->p_hdr->ts.tv_sec,ipacket->p_hdr->ts.tv_usec);
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
                offset += valid+1;
            }else {

                return;
            }
        }else {

            offset += 1;
        }
    }
    message[ offset ] = '\0';
    //send_message_to_file ("event.report", message);
    if (probe_context->output_to_file_enable==1)send_message_to_file_thread (message,th);
    if (probe_context->redis_enable==1)send_message_to_redis ("event.report", message);

}

int register_event_report_handle(void * args) {
	int i = 1, j;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th ;
	struct user_data *p = ( struct user_data *) args;
	th = p->smp_thread;
	mmt_event_report_t * event_report   = p->event_reports;

	if (is_registered_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle) == 0){
		i &= register_attribute_handler(th->mmt_handler, event_report->event.proto_id, event_report->event.attribute_id, event_report_handle, NULL, (void *) p);
	}

	for(j = 0; j < event_report->attributes_nb; j++) {
		mmt_event_attribute_t * event_attribute = &event_report->attributes[j];
		event_attribute->proto_id = get_protocol_id_by_name (event_attribute->proto);
		event_attribute->attribute_id = get_attribute_id_by_protocol_and_attribute_names(event_attribute->proto,event_attribute->attribute);
		if (is_registered_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id) == 0){
			i &= register_extraction_attribute(th->mmt_handler, event_attribute->proto_id, event_attribute->attribute_id);
		}
		//printf ("proto=%s \tAttribute=%s\n\n",event_attribute->proto,event_attribute->attribute);
	}
	return i;
}
int register_security_report_handle(void * args) {
	int i=1,j =0, k=0, l=0;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th = (struct smp_thread *) args;

	for(i = 0; i < probe_context->security_reports_nb; i++) {
		if (probe_context->security_reports[i].enable == 1){
			   th->report[i].data = malloc (sizeof (unsigned char *) * probe_context->nb_of_report_per_msg +1);
			   th->report[i].msg = malloc (sizeof (struct iovec)*probe_context->nb_of_report_per_msg +1);
			   for (l=0; l < probe_context->nb_of_report_per_msg; l++)th->report[i].data[l]= malloc(2000);
			/*			if (strcmp(probe_context->security_reports[i].event.proto,"null") != 0 && strcmp(probe_context->security_reports[i].event.attribute,"null") !=0){

				probe_context->security_reports[i].event.proto_id = get_protocol_id_by_name (probe_context->security_reports[i].event.proto);
				probe_context->security_reports[i].event.attribute_id = get_attribute_id_by_protocol_and_attribute_names(probe_context->security_reports[i].event.proto,probe_context->security_reports[i].event.attribute);

				if (is_registered_attribute(th->mmt_handler, probe_context->security_reports[i].event.proto_id, probe_context->security_reports[i].event.attribute_id ) == 0){
					i &= register_extraction_attribute(th->mmt_handler, probe_context->security_reports[i].event.proto_id, probe_context->security_reports[i].event.attribute_id );
				}
			}else {
				probe_context->security_reports[i].event.proto_id = 0;
				probe_context->security_reports[i].event.attribute_id = 0;
			}*/

			for(j = 0; j < probe_context->security_reports[i].attributes_nb; j++) {
				mmt_security_attribute_t * security_attribute = &probe_context->security_reports[i].attributes[j];

				security_attribute->proto_id = get_protocol_id_by_name (security_attribute->proto);
				security_attribute->attribute_id = get_attribute_id_by_protocol_and_attribute_names(security_attribute->proto,security_attribute->attribute);
				//method1
				//th->security_attributes[k].proto_id = security_attribute->proto_id;
				//th->security_attributes[k].attribute_id = security_attribute->attribute_id ;
				if (is_registered_attribute(th->mmt_handler, security_attribute->proto_id, security_attribute->attribute_id) == 0){
					i &= register_extraction_attribute(th->mmt_handler, security_attribute->proto_id, security_attribute->attribute_id);
				}
				//printf("th_nb=%u, n= %u,k=%u, proto_id = %u, attribute_id =%u \n",th->thread_number,i,k,security_attribute->proto_id,security_attribute->attribute_id);

				k++;
			}
		}
	}
	return i;
}
void security_reports_init(void * args) {
	int i,j,k=0;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th = (struct smp_thread *) args;
	th->report = calloc(sizeof(security_report_buffer_t), probe_context->security_reports_nb);

	//method1
	//th->security_attributes =calloc(sizeof(mmt_security_attributes_t), probe_context->total_security_attribute_nb);
	if(register_security_report_handle((void *) th) == 0) {
		fprintf(stderr, "Error while initializing security report !\n");
	}

	if (probe_context->socket_enable == 1){
		create_socket(probe_context, args);
		probe_context->socket_active = 1;
	}
	if (is_registered_packet_handler(th->mmt_handler,6)==1)unregister_packet_handler(th->mmt_handler,6);
	register_packet_handler(th->mmt_handler, 6, packet_handler, (void *) th);
}

void event_reports_init(void * args) {
	int i,j;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;
	struct user_data *p;
	for(i = 0; i < probe_context->event_reports_nb; i++) {
		th->event_reports = &probe_context->event_reports[i];
		if(th->event_reports->enable == 1){
				p = malloc( sizeof( struct user_data ));
				p->smp_thread    = th;
				p->event_reports = th->event_reports;
			if(register_event_report_handle((void *) p) == 0) {
				fprintf(stderr, "Error while initializing event report number %i!\n", th->event_reports->id);
			}

		}
	}
}

