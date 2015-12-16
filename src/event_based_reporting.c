#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "processing.h"

#define MAX_MESS 2000

void event_report_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    int j;
    attribute_t * attr_extract;
    int offset = 0, valid;
    char message[MAX_MESS + 1];
    mmt_probe_context_t * probe_context = get_probe_context_config();
    mmt_event_report_t * event_report = (mmt_event_report_t *) user_args;

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
    if (probe_context->output_to_file_enable==1)send_message_to_file (message);
    if (probe_context->redis_enable==1)send_message_to_redis ("event.report", message);
}

int register_event_report_handle(void * handler, mmt_event_report_t * event_report) {
    int i = 1, j;
    i &= register_attribute_handler_by_name(handler, event_report->event.proto, event_report->event.attribute, event_report_handle, NULL, (void *) event_report);
    for(j = 0; j < event_report->attributes_nb; j++) {
        mmt_event_attribute_t * event_attribute = &event_report->attributes[j];
        i &= register_extraction_attribute_by_name(handler, event_attribute->proto, event_attribute->attribute);
        // printf ("%s \tAttribute=%s, i=%d\n\n",event_attribute->proto,event_attribute->attribute,i);
    }
    return i;
}
void event_reports_init(void * handler) {
    int i;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    for(i = 0; i < probe_context->event_reports_nb; i++) {
        mmt_event_report_t * event_report = &probe_context->event_reports[i];
        if(register_event_report_handle(handler, event_report) == 0) {
            fprintf(stderr, "Error while initializing event report number %i!\n", event_report->id);
        }
    }
}
