#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
//#include "mmt/tcpip/mmt_tcpip_attributes.h"
#include "mmt/tcpip/mmt_tcpip.h"
#include "processing.h"

typedef struct http_line_struct {
	const uint8_t *ptr;
	uint16_t len;
} http_line_struct_t;


void mime_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * mime = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if (mime != NULL && temp_session->app_format_id == probe_context->web_id) {
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

void host_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * host = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if (host != NULL && temp_session->app_format_id == probe_context->web_id) {
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
void print_http_request_response_report (const mmt_session_t * session, void *user_args){
	char message[MAX_MESS + 1];
	uint32_t cdn_flag = 0;
	uint8_t *ea = 0;
	char src_mac_pretty [18], dst_mac_pretty [18];
	int keep_direction = 1;
	int valid = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_args;
	session_struct_t * temp_session = (session_struct_t *) get_user_session_context(session);
	if (temp_session == NULL){
		return;
	}
	if (((web_session_attr_t *) temp_session->app_data)->http_session_attr == NULL){
		return;
	}
	// To  check whether the session activity occurs between the reporting time interval
	//if (TIMEVAL_2_MSEC(mmt_time_diff(temp_session->session_attr->last_activity_time,get_session_last_activity_time(session))) == 0)return; // check the condition if in the last interval there was a protocol activity or not

	ea = temp_session->src_mac;
	snprintf(src_mac_pretty , 18, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
	ea = temp_session->dst_mac;
	snprintf(dst_mac_pretty , 18, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
	char ip_src_str[46];
	char ip_dst_str[46];
	if (temp_session->ipversion == 4) {
		inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
		keep_direction = is_local_net(temp_session->ipclient.ipv4);
	} else if(temp_session->ipversion == 6) {
		inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
		keep_direction = is_localv6_net(ip_src_str);//add more condition if any in is_localv6_net function
	}

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];
	proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(session), temp_session->path);

	if (((web_session_attr_t *) temp_session->app_data)->xcdn_seen) cdn_flag = ((web_session_attr_t *) temp_session->app_data)->xcdn_seen;
	else if (get_session_content_flags(session) & MMT_CONTENT_CDN) cdn_flag = 2;

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->last_activity_time = get_session_last_activity_time(session);

	uint64_t active_session_count = get_active_session_count(th->mmt_handler);

	snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%u,\"%s\",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%lu.%lu,\"%s\",\"%s\",\"%s\",\"%s\",%"PRIu64",%hu,%hu,%"PRIu32",\"%s\",\"%s\",\"%s\",%u,\"%s\",\"%s\",\"%s\",%u",
			400, probe_context->probe_id_number, probe_context->input_source,((web_session_attr_t *)temp_session->app_data)->http_session_attr->last_activity_time.tv_sec, ((web_session_attr_t *)temp_session->app_data)->http_session_attr->last_activity_time.tv_usec,
			proto_id,
			temp_session->path,active_session_count,
			get_session_byte_count(session) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_byte_count,
			get_session_data_byte_count(session) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_data_byte_count,
			get_session_packet_count(session) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_packet_count,
			((keep_direction)?get_session_ul_byte_count(session):get_session_dl_byte_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[0],
			((keep_direction)?get_session_ul_data_byte_count(session):get_session_dl_data_byte_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[0],
			((keep_direction)?get_session_ul_packet_count(session):get_session_dl_packet_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[0],

			((keep_direction)?get_session_dl_byte_count(session):get_session_ul_byte_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[1],
			((keep_direction)?get_session_dl_data_byte_count(session):get_session_ul_data_byte_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[1],
			((keep_direction)?get_session_dl_packet_count(session):get_session_ul_packet_count(session)) - ((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[1],
			((web_session_attr_t *)temp_session->app_data)->http_session_attr->start_time.tv_sec, ((web_session_attr_t *)temp_session->app_data)->http_session_attr->start_time.tv_usec,
			ip_src_str, ip_dst_str, src_mac_pretty, dst_mac_pretty,temp_session ->session_id,
			temp_session->serverport, temp_session->clientport,temp_session->thread_number,
			((web_session_attr_t *) temp_session->app_data)->hostname,
			((web_session_attr_t *) temp_session->app_data)->mimetype, ((web_session_attr_t *) temp_session->app_data)->referer,cdn_flag,
			((web_session_attr_t *) temp_session->app_data)->uri,((web_session_attr_t *) temp_session->app_data)->method,((web_session_attr_t *) temp_session->app_data)->response,
			(((web_session_attr_t *) temp_session->app_data)->http_session_attr->seen_response) ?(uint32_t) TIMEVAL_2_MSEC(((web_session_attr_t *) temp_session->app_data)->http_session_attr->response_time):0
	);
	message[ MAX_MESS] = '\0';

	if (probe_context->output_to_file_enable == 1)send_message_to_file_thread (message, (void *)user_args);
	if (probe_context->redis_enable == 1)send_message_to_redis ("http_request_response.flow.report", message);

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_byte_count = get_session_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_data_byte_count = get_session_data_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_packet_count = get_session_packet_count(session);

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[0] = (keep_direction)?get_session_ul_byte_count(session):get_session_dl_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[1] = (keep_direction)?get_session_dl_byte_count(session):get_session_ul_byte_count(session);

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[0] = (keep_direction)?get_session_ul_data_byte_count(session):get_session_dl_data_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[1] = (keep_direction)?get_session_dl_data_byte_count(session):get_session_ul_data_byte_count(session);


	((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[0] = (keep_direction)?get_session_ul_packet_count(session):get_session_dl_packet_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[1] = (keep_direction)?get_session_dl_packet_count(session):get_session_ul_packet_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->start_time = get_session_last_activity_time(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->seen_response = 0;
}

void init_http_request_response_report (const mmt_session_t * session, void *user_args){
	char message[MAX_MESS + 1];
	int keep_direction = 1;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_args;
	session_struct_t * temp_session = (session_struct_t *) get_user_session_context(session);
	if (temp_session == NULL){
		return;
	}

	char ip_src_str[46];
	char ip_dst_str[46];
	if (temp_session->ipversion == 4) {
		inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
		keep_direction = is_local_net(temp_session->ipclient.ipv4);
	} else if(temp_session->ipversion == 6) {
		inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
		keep_direction = is_localv6_net(ip_src_str);//add more condition if any in is_localv6_net function
	}


	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_byte_count = get_session_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_data_byte_count = get_session_data_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->total_packet_count = get_session_packet_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[0] = (keep_direction)?get_session_ul_byte_count(session):get_session_dl_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->byte_count[1] = (keep_direction)?get_session_dl_byte_count(session):get_session_ul_byte_count(session);

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[0] = (keep_direction)?get_session_ul_data_byte_count(session):get_session_dl_data_byte_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->data_byte_count[1] = (keep_direction)?get_session_dl_data_byte_count(session):get_session_ul_data_byte_count(session);

	((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[0] = (keep_direction)?get_session_ul_packet_count(session):get_session_dl_packet_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->packet_count[1] = (keep_direction)?get_session_dl_packet_count(session):get_session_ul_packet_count(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->start_time = get_session_last_activity_time(session);
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->seen_response = 0;
	((web_session_attr_t *)temp_session->app_data)->http_session_attr->touched = 1;

}

void http_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	if (temp_session != NULL) {
		if (temp_session->app_data == NULL) {
			web_session_attr_t * http_data = (web_session_attr_t *) malloc(sizeof (web_session_attr_t));
			if (http_data != NULL) {
				memset(http_data, '\0', sizeof (web_session_attr_t));
				temp_session->app_format_id = probe_context->web_id;
				temp_session->app_data = (void *) http_data;
			} else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP reporting context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}
		}

		if (((web_session_attr_t *) temp_session->app_data)->http_session_attr == NULL) {
			temp_session_statistics_t * http_session_data = (temp_session_statistics_t *) malloc(sizeof (temp_session_statistics_t));

			if (http_session_data != NULL) {
				memset(http_session_data, '\0', sizeof (temp_session_statistics_t));
				((web_session_attr_t *)temp_session->app_data)->http_session_attr =http_session_data;
			}else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP session_data context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}

		}

		if (((web_session_attr_t *)temp_session->app_data)->http_session_attr->touched == 0)init_http_request_response_report (ipacket->session, user_args);
		else print_http_request_response_report(ipacket->session, user_args);
		((web_session_attr_t *)temp_session->app_data)->http_session_attr->response_time = ipacket->p_hdr->ts;

		http_line_struct_t * method = (http_line_struct_t *) attribute->data;
		if (method != NULL && temp_session->app_format_id == probe_context->web_id) {
			int max = (method->len > 20) ? 20 : method->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->method, (char *) method->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->method[max] = '\0';

		}
		((web_session_attr_t *) temp_session->app_data)->trans_nb += 1;
		if (((web_session_attr_t *) temp_session->app_data)->trans_nb == 1) {
			((web_session_attr_t *) temp_session->app_data)->response_time = ipacket->p_hdr->ts;
			((web_session_attr_t *) temp_session->app_data)->first_request_time = ipacket->p_hdr->ts;
		}

	}
}

void referer_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * referer = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if ((referer != NULL) && temp_session->app_format_id == probe_context->web_id && (((web_session_attr_t *) temp_session->app_data)->has_referer == 0)) {
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

void useragent_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * user_agent = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	if ((user_agent != NULL) && temp_session->app_format_id == probe_context->web_id && (((web_session_attr_t *) temp_session->app_data)->has_useragent == 0)) {
		int max = (user_agent->len > 63) ? 63 : user_agent->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->useragent, (char *) user_agent->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->useragent[max] = '\0';
		((web_session_attr_t *) temp_session->app_data)->has_useragent = 1;
	}
}

void xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	uint8_t * xcdn_seen = (uint8_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if (xcdn_seen != NULL && temp_session != NULL && temp_session->app_data != NULL && temp_session->app_format_id == probe_context->web_id) {
		((web_session_attr_t *) temp_session->app_data)->xcdn_seen = 1;
	}
}


void http_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	if (temp_session != NULL) {
		if (temp_session->app_data == NULL) {
			web_session_attr_t * http_data = (web_session_attr_t *) malloc(sizeof (web_session_attr_t));
			if (http_data != NULL) {
				memset(http_data, '\0', sizeof (web_session_attr_t));
				temp_session->app_format_id = probe_context->web_id;
				temp_session->app_data = (void *) http_data;
			} else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP reporting context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}
		}
		if(temp_session->app_format_id == probe_context->web_id) {
			if (((web_session_attr_t *) temp_session->app_data)->trans_nb == 1) {
				((web_session_attr_t *) temp_session->app_data)->response_time = mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->response_time, ipacket->p_hdr->ts);
				((web_session_attr_t *) temp_session->app_data)->seen_response = 1;
			}
			((web_session_attr_t *) temp_session->app_data)->interaction_time = ipacket->p_hdr->ts;
		}

		if (((web_session_attr_t *) temp_session->app_data)->http_session_attr != NULL && temp_session->app_format_id == probe_context->web_id) {
			((web_session_attr_t *)temp_session->app_data)->http_session_attr->response_time = mmt_time_diff(((web_session_attr_t *)temp_session->app_data)->http_session_attr->response_time, ipacket->p_hdr->ts);
			((web_session_attr_t *)temp_session->app_data)->http_session_attr->seen_response = 1;
		}


		http_line_struct_t * response = (http_line_struct_t *) attribute->data;

		if (response != NULL && temp_session->app_format_id == probe_context->web_id) {
			int max = (response->len > 1024) ? 1024 : response->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->response, (char *) response->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->response[max] = '\0';

		}
	}
}
void tcp_fin_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}
	uint16_t * fin = (uint16_t *) attribute->data;
	if (fin != NULL && temp_session->app_format_id == probe_context->web_id) {
		if (((web_session_attr_t *)temp_session->app_data)->http_session_attr->touched == 1)print_http_request_response_report(ipacket->session, user_args);
		((web_session_attr_t *)temp_session->app_data)->http_session_attr->touched = 0;
	}

}
void ip_proto_id_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL ) {
		return;
	}
	temp_session->previous_packet_time = temp_session->latest_packet_time;
	uint8_t * proto_id= (uint8_t *) attribute->data;

	if (proto_id != NULL && * proto_id == 6 ) {
		temp_session->latest_packet_time = ipacket->p_hdr->ts;
	}

}

void tcp_data_off_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL ) {
		return;
	}
	uint32_t * data_off= (uint32_t *) attribute->data;
	printf("data_off = %u\n",* data_off);
	if (data_off != NULL && * data_off == 0 ) {
		uint32_t rtt_ms = TIMEVAL_2_MSEC(mmt_time_diff(temp_session->previous_packet_time,temp_session->latest_packet_time));
		printf("data_off= %u, rtt=%u \n",* data_off,rtt_ms);

	}

}

void uri_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t * uri = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL || temp_session->app_data == NULL) {
		return;
	}

	if (uri != NULL && temp_session->app_format_id == probe_context->web_id) {
		int max = (uri->len > 1024) ? 1024 : uri->len;

		strncpy(((web_session_attr_t *) temp_session->app_data)->uri, (char *) uri->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->uri[max] = '\0';
		((web_session_attr_t *) temp_session->app_data)->has_uri=1;

	}
}

void print_web_app_format(const mmt_session_t * expired_session, void *args) {
	int keep_direction = 1;
	session_struct_t * temp_session = get_user_session_context(expired_session);
	char path[128];
	char message[MAX_MESS + 1];
	struct smp_thread *th = (struct smp_thread *) args;
	//common fields
	//format id, timestamp
	//Flow_id, Start timestamp, IP version, Server_Address, Client_Address, Server_Port, Client_Port, Transport Protocol ID,
	//Uplink Packet Count, Downlink Packet Count, Uplink Byte Count, Downlink Byte Count, TCP RTT, Retransmissions,
	//Application_Family, Content Class, Protocol_Path, Application_Name

	//proto_hierarchy_to_str(&expired_session->proto_path, path);

	mmt_probe_context_t * probe_context = get_probe_context_config();
	proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(expired_session), path);
	if (((web_session_attr_t *) temp_session->app_data)->http_session_attr != NULL){
		if (((web_session_attr_t *)temp_session->app_data)->http_session_attr->touched == 1)print_http_request_response_report(expired_session, args);
	}

	//printf("print_web_app_format_th_nb=%d \n",th->thread_number);

	char dev_prop[12];

	if ((probe_context->user_agent_parsing_threshold) && (get_session_byte_count(expired_session) > probe_context->user_agent_parsing_threshold)) {
		mmt_dev_properties_t dev_p = get_dev_properties_from_user_agent(((web_session_attr_t *) temp_session->app_data)->useragent, 128);
		sprintf(dev_prop, "%hu:%hu", dev_p.dev_id, dev_p.os_id);
	} else {
		dev_prop[0] = '\0';
	}
	//IP strings
	char ip_src_str[46];
	char ip_dst_str[46];
	if (temp_session->ipversion == 4) {
		inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
		keep_direction = is_local_net(temp_session->ipclient.ipv4);
	} else {
		inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
		keep_direction = is_localv6_net(ip_src_str);
	}

	uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(expired_session));
	uint32_t cdn_flag = 0;

	if (((web_session_attr_t *) temp_session->app_data)->xcdn_seen) cdn_flag = ((web_session_attr_t *) temp_session->app_data)->xcdn_seen;
	else if (get_session_content_flags(expired_session) & MMT_CONTENT_CDN) cdn_flag = 2;

	struct timeval init_time = get_session_init_time(expired_session);
	struct timeval end_time = get_session_last_activity_time(expired_session);
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(expired_session);

	snprintf(message, MAX_MESS,
			"%u,%u,\"%s\",%lu.%lu,%"PRIu64",%"PRIu32",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,\"%s\",%u,%u,%u,%u,\"%s\",\"%s\",\"%s\",\"%s\",%u", // app specific
			temp_session->app_format_id, probe_context->probe_id_number, probe_context->input_source, end_time.tv_sec, end_time.tv_usec,
			temp_session->session_id,temp_session->thread_number,
			init_time.tv_sec, init_time.tv_usec,
			(int) temp_session->ipversion,
			ip_dst_str, ip_src_str,
			temp_session->serverport, temp_session->clientport, (unsigned short) temp_session->proto,
			(keep_direction)?get_session_ul_packet_count(expired_session):get_session_dl_packet_count(expired_session),
					(keep_direction)?get_session_dl_packet_count(expired_session):get_session_ul_packet_count(expired_session),
							(keep_direction)?get_session_ul_byte_count(expired_session):get_session_dl_byte_count(expired_session),
									(keep_direction)?get_session_dl_byte_count(expired_session):get_session_ul_byte_count(expired_session),
											rtt_ms, get_session_retransmission_count(expired_session),
											get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
											temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
											(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_MSEC(((web_session_attr_t *) temp_session->app_data)->response_time) : 0,
													(((web_session_attr_t *) temp_session->app_data)->seen_response) ? ((web_session_attr_t *) temp_session->app_data)->trans_nb : 0,
															(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_MSEC(mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->first_request_time, ((web_session_attr_t *) temp_session->app_data)->interaction_time)) : 0,
																	((web_session_attr_t *) temp_session->app_data)->hostname,
																	((web_session_attr_t *) temp_session->app_data)->mimetype, ((web_session_attr_t *) temp_session->app_data)->referer,
																	dev_prop, cdn_flag
	);

	message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
	if (probe_context->output_to_file_enable==1)send_message_to_file_thread (message,(void*)args);
	if (probe_context->redis_enable==1)send_message_to_redis ("web.flow.report", message);

}

void print_initial_web_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){
	snprintf(&message[valid], MAX_MESS-valid,
				",%u",temp_session->app_format_id);

/*	snprintf(&message[valid], MAX_MESS-valid,
			",%u,%u,%u,%u,%u,%u,\"%s\",\"%s\",\"%s\",%u,\"%s\",\"%s\",\"%s\"", // app specific
			temp_session->app_format_id,get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
			temp_session->contentclass,
			(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_MSEC(((web_session_attr_t *) temp_session->app_data)->response_time) : 0,
					(((web_session_attr_t *) temp_session->app_data)->seen_response) ? ((web_session_attr_t *) temp_session->app_data)->trans_nb : 0,
							(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_MSEC(mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->first_request_time, ((web_session_attr_t *) temp_session->app_data)->interaction_time)) : 0,
									((web_session_attr_t *) temp_session->app_data)->hostname,
									((web_session_attr_t *) temp_session->app_data)->mimetype, ((web_session_attr_t *) temp_session->app_data)->referer,cdn_flag,
									((web_session_attr_t *) temp_session->app_data)->uri,((web_session_attr_t *) temp_session->app_data)->method,((web_session_attr_t *) temp_session->app_data)->response
	);*/
	temp_session->session_attr->touched=1;
}

/*
void register_web_attributes(void * handler){
    int i = 1;
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_METHOD, http_method_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_RESPONSE, http_response_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_CONTENT_TYPE, mime_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_HOST, host_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_REFERER, referer_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_USER_AGENT, useragent_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_HTTP, RFC2822_XCDN_SEEN, xcdn_seen_handle, NULL, NULL);

    if(!i) {
        //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
        fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
    }

}*/


