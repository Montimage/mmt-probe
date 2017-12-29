/*
 * condition_based_reporting.c
 *
 *  Created on: Mar 29, 2017
 *      Author: montimage
 */
#include "processing.h"
/* This function returns the function handler corresponding to a particular func_name.
 * If a func_name does not exist it returns 0.
 * */
void * get_handler_by_name(char * func_name){
	if (strcmp(func_name,"ftp_session_connection_type_handle") == 0){
		return ftp_session_connection_type_handle;
	}
	if (strcmp(func_name,"ftp_response_value_handle") == 0){
		return ftp_response_value_handle;
	}
	if (strcmp(func_name,"http_method_handle") == 0){
		return http_method_handle;
	}
	if (strcmp(func_name,"http_response_handle") == 0){
		return http_response_handle;
	}
	if (strcmp(func_name,"mime_handle") == 0){
		return mime_handle;
	}
	if (strcmp(func_name,"host_handle") == 0){
		return host_handle;
	}
	if (strcmp(func_name,"uri_handle") == 0){
		return uri_handle;
	}
	if (strcmp(func_name,"useragent_handle") == 0){
		return useragent_handle;
	}
	if (strcmp(func_name,"referer_handle") == 0){
		return referer_handle;
	}
	if (strcmp(func_name,"xcdn_seen_handle") == 0){
		return xcdn_seen_handle;
	}
	if (strcmp(func_name,"content_len_handle") == 0){
		return content_len_handle;
	}
	if (strcmp(func_name,"rtp_version_handle") == 0){
		return rtp_version_handle;
	}
	if (strcmp(func_name,"rtp_jitter_handle") == 0){
		return rtp_jitter_handle;
	}
	if (strcmp(func_name,"rtp_loss_handle") == 0){
		return rtp_loss_handle;
	}
	if (strcmp(func_name,"rtp_order_error_handle") == 0){
		return rtp_order_error_handle;
	}
	if (strcmp(func_name,"rtp_burst_loss_handle") == 0){
		return rtp_burst_loss_handle;
	}
	if (strcmp(func_name,"ssl_server_name_handle") == 0){
		return ssl_server_name_handle;
	}
//#ifdef HTTP_RECONSTRUCT_MODULE
	//LN: HTTP reconstruct
	// if (strcmp(func_name,"ip_new_session_handle") == 0){
	// 	return ip_new_session_handle;
	// }

	if (strcmp(func_name,"http_message_start_handle") == 0){
		return http_message_start_handle;
	}

	if (strcmp(func_name,"http_generic_header_handle") == 0){
		return http_generic_header_handle;
	}
	if (strcmp(func_name,"http_headers_end_handle") == 0){
		return http_headers_end_handle;
	}

	if (strcmp(func_name,"http_data_handle") == 0){
		return http_data_handle;
	}

	if (strcmp(func_name,"http_message_end_handle") == 0){
		return http_message_end_handle;
	}
	// END of HTTP reconstruct
//#endif // end of HTTP_RECONSTRUCT_MODULE
	return 0;
}

/* uninitilisation condition report  * */
int unregister_conditional_report_handle(void * args, mmt_condition_report_t * condition_report) {
        int j;
        struct smp_thread *th = (struct smp_thread *) args;

        for(j = 0; j < condition_report->attributes_nb; j++) {
                uint32_t protocol_id;
                uint32_t attribute_id;
                mmt_condition_attribute_t * condition_attribute = &condition_report->attributes[j];
                mmt_condition_attribute_t * handler_attribute = &condition_report->handlers[j];

                if (strcmp(condition_attribute->proto, "NULL") == 0) continue;
                if (strcmp(handler_attribute->attribute,"NULL") == 0) continue;

                protocol_id = get_protocol_id_by_name (condition_attribute->proto);
                if (protocol_id == 0) return 0;

                attribute_id = get_attribute_id_by_protocol_and_attribute_names(condition_attribute->proto,condition_attribute->attribute);
                if (attribute_id == 0) return 0;

                if (strcmp(handler_attribute->handler,"NULL") == 0){
                        if (is_registered_attribute(th->mmt_handler, protocol_id, attribute_id) != 0){
                                if(unregister_extraction_attribute(th->mmt_handler, protocol_id, attribute_id) == 0)return 0;
                        }
                }else{
                        if (is_registered_attribute_handler(th->mmt_handler, protocol_id, attribute_id, get_handler_by_name (handler_attribute->handler)) != 0){
                                if(unregister_attribute_handler(th->mmt_handler, protocol_id, attribute_id, get_handler_by_name (handler_attribute->handler)) == 0) return 0;
                        }
                }
        }
        return 1;
}


/* This function registers attributes and attribute handlers for different condition_reports (if enabled in a configuration file).
 * */
int register_conditional_report_handle(void * args, mmt_condition_report_t * condition_report) {
	int j;
	struct smp_thread *th = (struct smp_thread *) args;

	for(j = 0; j < condition_report->attributes_nb; j++) {
		uint32_t protocol_id;
		uint32_t attribute_id;
		mmt_condition_attribute_t * condition_attribute = &condition_report->attributes[j];
		mmt_condition_attribute_t * handler_attribute = &condition_report->handlers[j];
               
                if (strcmp(condition_attribute->proto, "NULL") == 0) continue;
                if (strcmp(handler_attribute->attribute,"NULL") == 0) continue;
		protocol_id = get_protocol_id_by_name (condition_attribute->proto);
		if (protocol_id == 0) return 0;

		attribute_id = get_attribute_id_by_protocol_and_attribute_names(condition_attribute->proto,condition_attribute->attribute);
		if (attribute_id == 0) return 0;

		if (strcmp(handler_attribute->handler,"NULL") == 0){
			if (is_registered_attribute(th->mmt_handler, protocol_id, attribute_id) == 0){
				if(!register_extraction_attribute(th->mmt_handler, protocol_id, attribute_id)){
					fprintf(stderr,"[error] Cannot register_extraction_attribute (condition_report): proto: %s ,attribute: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,condition_report->id);
					// fprintf(stderr, "[error] cannot register_extraction_attribute for report: %i\n",condition_report->id);
					return 0;
				}else{
					// printf("[debug] register_extraction_attribute: proto: %s ,attribute: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,condition_report->id);
				}
			}else{
				fprintf(stderr,"[WARNING] Already registered register_extraction_attribute (condition_report): proto: %s ,attribute: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,condition_report->id);
			}
		}else{
			if (is_registered_attribute_handler(th->mmt_handler, protocol_id, attribute_id, get_handler_by_name (handler_attribute->handler)) == 0){
				if(!register_attribute_handler(th->mmt_handler, protocol_id, attribute_id, get_handler_by_name (handler_attribute->handler), NULL, args)){
					fprintf(stderr,"[error] Cannot register_attribute_handler (condition_report): proto: %s ,attribute: %s, handler: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,handler_attribute->handler,condition_report->id);
					// fprintf(stderr, "[error] cannot register_attribute_handler for report: %i\n",condition_report->id);
					return 0;
				}else{
					// printf("[debug] register_attribute_handler: proto: %s ,attribute: %s, handler: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,handler_attribute->handler,condition_report->id);
				}
			}else{
				fprintf(stderr,"[WARNING] Already registered register_attribute_handler (condition_report): proto: %s ,attribute: %s, handler: %s (report: %i)\n",condition_attribute->proto,condition_attribute->attribute,handler_attribute->handler,condition_report->id);
			}
		}
	}
	return 1;
}

/* This function initializes condition_reports (if enabled in a configuration file).
 * */
void conditional_reports_init(void * args) {
	int i;
	mmt_probe_context_t * probe_context = get_probe_context_config();
        struct smp_thread *th = (struct smp_thread *) args;
        mmt_condition_report_t * current = probe_context->condition_reports;
	while (current != NULL) {
           if (current->enable == 1){
		//mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
		if(register_conditional_report_handle(args, current) == 0) {
			fprintf(stderr, "Error while initializing condition report number %i!\n", current->id);
			exit(1);
		}
           } else {
                if(unregister_conditional_report_handle(args, current) == 0) {
                        fprintf(stderr, "Error while uninitializing condition report number %i!\n", current->id);
                        exit(1);
                }
        
           }
            current = current->next;
	}
    if (probe_context->condition_reports_nb > 0){
       atomic_store(&th->condition_report_flag, 0);
    }

}
