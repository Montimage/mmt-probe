#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
//#include "mmt/tcpip/mmt_tcpip_attributes.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

/* This function resets http stats */
void http_reset_report(session_struct_t *temp_session){

	((web_session_attr_t *) temp_session->app_data)->mimetype[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->hostname[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->referer[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->useragent[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->method[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->uri[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->response[0] = '\0';
	((web_session_attr_t *) temp_session->app_data)->content_len[0] = '\0';

	((web_session_attr_t *) temp_session->app_data)->response_time.tv_sec = 0;
	((web_session_attr_t *) temp_session->app_data)->response_time.tv_usec = 0;
	((web_session_attr_t *) temp_session->app_data)->method_time.tv_sec = 0;
	((web_session_attr_t *) temp_session->app_data)->method_time.tv_usec = 0;
	((web_session_attr_t *) temp_session->app_data)->seen_response = 0;
	((web_session_attr_t *) temp_session->app_data)->has_referer = 0;
	((web_session_attr_t *) temp_session->app_data)->xcdn_seen = 0;
	((web_session_attr_t *) temp_session->app_data)->has_useragent = 0;
    ((web_session_attr_t *) temp_session->app_data)->has_uri = 0;
}

/* This function is called by mmt-dpi for reporting http mime type, if an extraction handler is registered */
void mime_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * mime = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if (mime != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
		int max = (mime->len > 63) ? 63 : mime->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->mimetype, (char *) mime->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->mimetype[max] = '\0';
		char * semi_column = strchr(((web_session_attr_t *) temp_session->app_data)->mimetype, ';');
		if (semi_column) {
			//Semi column found, replace it by an en of string '\0'
			*semi_column = '\0';
		}
		temp_session->contentclass = get_content_class_by_content_type(((web_session_attr_t *) temp_session->app_data)->mimetype);
	}
}

/* This function is called by mmt-dpi for reporting http host, if an extraction handler is registered */
void host_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * host = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if (host != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
		int max = (host->len > 95) ? 95 : host->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->hostname, (char *) host->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->hostname[max] = '\0';
		char * coma = strchr(((web_session_attr_t *) temp_session->app_data)->hostname, ',');
		if (coma) {
			//Semi column found, replace it by an en of string '\0'
			*coma = '\0';
		}
		//((web_session_attr_t *) temp_session->app_data)->trans_nb += 1;
		//if (((web_session_attr_t *) temp_session->app_data)->trans_nb == 1) {
		//	((web_session_attr_t *) temp_session->app_data)->response_time = ipacket->p_hdr->ts;
		//	((web_session_attr_t *) temp_session->app_data)->first_request_time = ipacket->p_hdr->ts;
		//}
	}
}

/* This function is called by mmt-dpi for reporting http method, if an extraction handler is registered
 * Initializes temp_session in the probe
 * Reporting between two http requests */
void http_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_args;
	if (temp_session != NULL) {
		if (temp_session->app_data == NULL) {
			web_session_attr_t * http_data = (web_session_attr_t *) malloc(sizeof (web_session_attr_t));
			if (http_data != NULL) {
				memset(http_data, '\0', sizeof (web_session_attr_t));
				temp_session->app_format_id = MMT_WEB_REPORT_FORMAT;
				temp_session->app_data = (void *) http_data;
				((web_session_attr_t *) temp_session->app_data)->touched = 0;
			} else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP reporting context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}
		}
		if (temp_session->session_attr == NULL) {
			temp_session->session_attr = (session_stat_t *) malloc(sizeof (session_stat_t));
			memset(temp_session->session_attr, 0, sizeof (session_stat_t));
		}
		if (probe_context->web_enable == 1){
			if (((web_session_attr_t *) temp_session->app_data)->touched == 0){
				((web_session_attr_t *) temp_session->app_data)->touched = 1;
				((web_session_attr_t *) temp_session->app_data)->state_http_request_response++;//response is not finished
				//((web_session_attr_t *) temp_session->app_data)->request_counter = 1;
				((web_session_attr_t *) temp_session->app_data)->trans_nb = 1;
			}else{
				((web_session_attr_t *) temp_session->app_data)->state_http_request_response = 0;// response is finished
				temp_session->report_counter = th->report_counter;
				print_ip_session_report (ipacket->session, user_args);
				http_reset_report(temp_session);
				//((web_session_attr_t *) temp_session->app_data)->request_counter++;
				((web_session_attr_t *) temp_session->app_data)->trans_nb++;
			}
		}
		http_line_struct_t * method = (http_line_struct_t *) attribute->data;
		if (method != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
			int max = (method->len > 20) ? 20 : method->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->method, (char *) method->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->method[max] = '\0';

		}
		//((web_session_attr_t *) temp_session->app_data)->trans_nb += 1;
		if (((web_session_attr_t *) temp_session->app_data)->trans_nb >= 1) {
			((web_session_attr_t *) temp_session->app_data)->method_time = ipacket->p_hdr->ts;

		}
		if (((web_session_attr_t *) temp_session->app_data)->trans_nb == 1){
			((web_session_attr_t *) temp_session->app_data)->first_request_time = ipacket->p_hdr->ts;
		}
	}
}

/* This function is called by mmt-dpi for reporting http referer, if an extraction handler is registered */
void referer_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * referer = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if ((referer != NULL) && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT && (((web_session_attr_t *) temp_session->app_data)->has_referer == 0)) {
		int max = (referer->len > 63) ? 63 : referer->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->referer, (char *) referer->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->referer[max] = '\0';
		char * coma = strchr(((web_session_attr_t *) temp_session->app_data)->referer, ',');
		if (coma) {
			//Semi column found, replace it by an en of string '\0'
			*coma = '\0';
		}
		((web_session_attr_t *) temp_session->app_data)->has_referer = 1;
	}
}

/* This function is called by mmt-dpi for reporting http useragent, if an extraction handler is registered */
void useragent_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * user_agent = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if ((user_agent != NULL) && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT && (((web_session_attr_t *) temp_session->app_data)->has_useragent == 0)) {
		int max = (user_agent->len > 63) ? 63 : user_agent->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->useragent, (char *) user_agent->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->useragent[max] = '\0';
		((web_session_attr_t *) temp_session->app_data)->has_useragent = 1;
	}
}

/* This function is called by mmt-dpi for reporting http xcdn_seen, if an extraction handler is registered */
void xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	uint8_t * xcdn_seen = (uint8_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (xcdn_seen != NULL && temp_session != NULL && temp_session->app_data != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
		((web_session_attr_t *) temp_session->app_data)->xcdn_seen = 1;
	}
}

/* This function is called by mmt-dpi for reporting http content len, if an extraction handler is registered */
void content_len_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t* content_len = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (content_len != NULL && temp_session != NULL && temp_session->app_data != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
		int max = (content_len->len > 20) ? 20 : content_len->len;
		strncpy(((web_session_attr_t *) temp_session->app_data)->content_len, (char *) content_len->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->content_len[max] = '\0';
	}

}

/* This function is called by mmt-dpi for reporting http response, if an extraction handler is registered
 * Response time calculation*/
void http_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	if (temp_session != NULL) {
		if (temp_session->app_data == NULL) {
			web_session_attr_t * http_data = (web_session_attr_t *) malloc(sizeof (web_session_attr_t));
			if (http_data != NULL) {
				memset(http_data, '\0', sizeof (web_session_attr_t));
				temp_session->app_format_id = MMT_WEB_REPORT_FORMAT;
				temp_session->app_data = (void *) http_data;
			} else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP reporting context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}
		}

		if(temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
			if (((web_session_attr_t *) temp_session->app_data)->trans_nb >= 1) { //Needed for response_time calculation
				((web_session_attr_t *) temp_session->app_data)->response_time = mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->method_time, ipacket->p_hdr->ts);
				((web_session_attr_t *) temp_session->app_data)->seen_response = 1;
			}
			((web_session_attr_t *) temp_session->app_data)->interaction_time = ipacket->p_hdr->ts;
		}


		http_line_struct_t * response = (http_line_struct_t *) attribute->data;

		if (response != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
			int max = (response->len > 1024) ? 1024 : response->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->response, (char *) response->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->response[max] = '\0';
		}
	}
}

/* This function is called by mmt-dpi for reporting http uri, if an extraction handler is registered */
void uri_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * uri = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}

	if (uri != NULL && temp_session->app_format_id == MMT_WEB_REPORT_FORMAT) {
		int max = (uri->len > 1024) ? 1024 : uri->len;
		strncpy(((web_session_attr_t *) temp_session->app_data)->uri, (char *) uri->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->uri[max] = '\0';
		((web_session_attr_t *) temp_session->app_data)->has_uri = 1;
		//printf ("uri = %s\n", ((web_session_attr_t *) temp_session->app_data)->uri);

	}
}

/* This function is called by mmt-dpi for reporting tcp session close, if an extraction handler is registered
 * Reporting at tcp close */
void tcp_closed_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	struct smp_thread *th = (struct smp_thread *) user_args;
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	uint16_t * tcp_close = (uint16_t *) attribute->data;

	if (tcp_close != NULL ) {
		if(temp_session->app_format_id == MMT_WEB_REPORT_FORMAT){
			//printf ("HEERRER1, session_id = %lu\n", temp_session->session_id);
			if (((web_session_attr_t *) temp_session->app_data)->state_http_request_response != 0)((web_session_attr_t *) temp_session->app_data)->state_http_request_response = 0;
			if (temp_session->session_attr == NULL) {
				temp_session->session_attr = (session_stat_t *) malloc(sizeof (session_stat_t));
				memset(temp_session->session_attr, 0, sizeof (session_stat_t));
			}
			temp_session->session_attr->last_activity_time.tv_sec =0;
			temp_session->session_attr->last_activity_time.tv_usec =0;
			temp_session->report_counter = th->report_counter;
			print_ip_session_report (ipacket->session, th);
		}
	}

}
/* This function is for reporting http session statistics*/
void print_initial_web_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){
	mmt_probe_context_t * probe_context = get_probe_context_config();
	uint32_t cdn_flag = 0;
	if (((web_session_attr_t *) temp_session->app_data)->xcdn_seen) cdn_flag = ((web_session_attr_t *) temp_session->app_data)->xcdn_seen;
	else if (get_session_content_flags(session) & MMT_CONTENT_CDN) cdn_flag = 2;
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	snprintf(&message[valid], MAX_MESS-valid,
			",%u,%u,%u,%"PRIu64",%u,%"PRIu64",\"%s\",\"%s\",\"%s\",%u,\"%s\",\"%s\",\"%s\",%s,%u", // app specific
			temp_session->app_format_id, get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
			temp_session->contentclass,
			(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint64_t) TIMEVAL_2_USEC(((web_session_attr_t *) temp_session->app_data)->response_time) : 0,
					(((web_session_attr_t *) temp_session->app_data)->seen_response) ? ((web_session_attr_t *) temp_session->app_data)->trans_nb : 0,
							(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint64_t) TIMEVAL_2_USEC(mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->first_request_time, ((web_session_attr_t *) temp_session->app_data)->interaction_time)) : 0,
									((web_session_attr_t *) temp_session->app_data)->hostname,
									((web_session_attr_t *) temp_session->app_data)->mimetype,
									(((web_session_attr_t *) temp_session->app_data)->referer[0] == '\0') ? "null":((web_session_attr_t *) temp_session->app_data)->referer,
									cdn_flag,
									(((web_session_attr_t *) temp_session->app_data)->uri[0] == '\0') ? "null":((web_session_attr_t *) temp_session->app_data)->uri,
									(((web_session_attr_t *) temp_session->app_data)->method[0] == '\0') ? "null":((web_session_attr_t *) temp_session->app_data)->method,
									(((web_session_attr_t *) temp_session->app_data)->response[0] == '\0') ? "null" :((web_session_attr_t *) temp_session->app_data)->response,
									(((web_session_attr_t *) temp_session->app_data)->content_len[0] == '\0')? "0":((web_session_attr_t *) temp_session->app_data)->content_len,
									((web_session_attr_t *) temp_session->app_data)->state_http_request_response
	);

	if(temp_session->app_format_id == MMT_WEB_REPORT_FORMAT ){
		if (temp_session->app_data == NULL) return;
		if (((web_session_attr_t *) temp_session->app_data)->state_http_request_response != 0)((web_session_attr_t *) temp_session->app_data)->state_http_request_response ++;
	}
	((web_session_attr_t *) temp_session->app_data)->response_time.tv_sec = 0;
	((web_session_attr_t *) temp_session->app_data)->response_time.tv_usec = 0;
	temp_session->session_attr->touched = 1;

}
