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
				((web_session_attr_t *) temp_session->app_data)->touched = 0;
			} else {
				mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating HTTP reporting context");
				//fprintf(stderr, "Out of memory error when creating HTTP specific data structure!\n");
				return;
			}
		}


		if (temp_session->session_attr == NULL) {
			temp_session->session_attr = (temp_session_statistics_t *) malloc(sizeof (temp_session_statistics_t));
			memset(temp_session->session_attr, 0, sizeof (temp_session_statistics_t));
		}
		if (((web_session_attr_t *) temp_session->app_data)->touched == 0){
			//printf("((web_session_attr_t *) temp_session->app_data)->touched  = %u\n",((web_session_attr_t *) temp_session->app_data)->touched   );
			((web_session_attr_t *) temp_session->app_data)->touched = 1;
			((web_session_attr_t *) temp_session->app_data)->enable_http_request_response = 0;//response is not finished
			((web_session_attr_t *) temp_session->app_data)->request_counter = 1;
		}else{
			((web_session_attr_t *) temp_session->app_data)->enable_http_request_response = 1;// response is finished
			 print_ip_session_report (ipacket->session,user_args);
			 ((web_session_attr_t *) temp_session->app_data)->request_counter++;
			//((web_session_attr_t *) temp_session->app_data)->touched = 0;
		}

		http_line_struct_t * method = (http_line_struct_t *) attribute->data;
		if (method != NULL && temp_session->app_format_id == probe_context->web_id) {
			int max = (method->len > 20) ? 20 : method->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->method, (char *) method->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->method[max] = '\0';

		}
		//printf("method=%s\n",((web_session_attr_t *) temp_session->app_data)->method);
		((web_session_attr_t *) temp_session->app_data)->trans_nb += 1;
		if (((web_session_attr_t *) temp_session->app_data)->trans_nb >= 1) {
			((web_session_attr_t *) temp_session->app_data)->method_time = ipacket->p_hdr->ts;

		}
		if (((web_session_attr_t *) temp_session->app_data)->trans_nb == 1){
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

void content_len_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	http_line_struct_t* content_len = (http_line_struct_t *) attribute->data;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (content_len != NULL && temp_session != NULL && temp_session->app_data != NULL && temp_session->app_format_id == probe_context->web_id) {
		int max = (content_len->len > 20) ? 20 : content_len->len;
		strncpy(((web_session_attr_t *) temp_session->app_data)->content_len, (char *) content_len->ptr, max);
		((web_session_attr_t *) temp_session->app_data)->content_len[max] = '\0';
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
			if (((web_session_attr_t *) temp_session->app_data)->trans_nb >= 1) {
				((web_session_attr_t *) temp_session->app_data)->response_time = mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->method_time, ipacket->p_hdr->ts);
				((web_session_attr_t *) temp_session->app_data)->seen_response = 1;
			}
			((web_session_attr_t *) temp_session->app_data)->interaction_time = ipacket->p_hdr->ts;
		}


		http_line_struct_t * response = (http_line_struct_t *) attribute->data;

		if (response != NULL && temp_session->app_format_id == probe_context->web_id) {
			int max = (response->len > 1024) ? 1024 : response->len;

			strncpy(((web_session_attr_t *) temp_session->app_data)->response, (char *) response->ptr, max);
			((web_session_attr_t *) temp_session->app_data)->response[max] = '\0';
			//printf("response = %s\n",((web_session_attr_t *) temp_session->app_data)->response);

		}
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

	uint32_t rtt_ms = TIMEVAL_2_USEC(get_session_rtt(expired_session));
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
											(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_USEC(((web_session_attr_t *) temp_session->app_data)->response_time) : 0,
													(((web_session_attr_t *) temp_session->app_data)->seen_response) ? ((web_session_attr_t *) temp_session->app_data)->trans_nb : 0,
															(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint32_t) TIMEVAL_2_USEC(mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->first_request_time, ((web_session_attr_t *) temp_session->app_data)->interaction_time)) : 0,
																	((web_session_attr_t *) temp_session->app_data)->hostname,
																	((web_session_attr_t *) temp_session->app_data)->mimetype, ((web_session_attr_t *) temp_session->app_data)->referer,
																	dev_prop, cdn_flag
	);

	message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
	if (probe_context->output_to_file_enable==1)send_message_to_file_thread (message,(void*)args);
	if (probe_context->redis_enable==1)send_message_to_redis ("web.flow.report", message);
}

void print_initial_web_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){
	mmt_probe_context_t * probe_context = get_probe_context_config();
	uint32_t cdn_flag = 0;
	if (((web_session_attr_t *) temp_session->app_data)->xcdn_seen) cdn_flag = ((web_session_attr_t *) temp_session->app_data)->xcdn_seen;
	else if (get_session_content_flags(session) & MMT_CONTENT_CDN) cdn_flag = 2;
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	snprintf(&message[valid], MAX_MESS-valid,
			",%u,%u,%u,%"PRIu64",%u,%"PRIu64",\"%s\",\"%s\",\"%s\",%u,\"%s\",\"%s\",\"%s\",%s,%"PRIu64",%u", // app specific
			temp_session->app_format_id,get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
			temp_session->contentclass,
			(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint64_t) TIMEVAL_2_USEC(((web_session_attr_t *) temp_session->app_data)->response_time) : 0,
					(((web_session_attr_t *) temp_session->app_data)->seen_response) ? ((web_session_attr_t *) temp_session->app_data)->trans_nb : 0,
							(((web_session_attr_t *) temp_session->app_data)->seen_response) ? (uint64_t) TIMEVAL_2_USEC(mmt_time_diff(((web_session_attr_t *) temp_session->app_data)->first_request_time, ((web_session_attr_t *) temp_session->app_data)->interaction_time)) : 0,
									((web_session_attr_t *) temp_session->app_data)->hostname,
									((web_session_attr_t *) temp_session->app_data)->mimetype, ((web_session_attr_t *) temp_session->app_data)->referer,cdn_flag,
									((web_session_attr_t *) temp_session->app_data)->uri,((web_session_attr_t *) temp_session->app_data)->method,((web_session_attr_t *) temp_session->app_data)->response,
									(strcmp(((web_session_attr_t *) temp_session->app_data)->content_len,"\0"))?((web_session_attr_t *) temp_session->app_data)->content_len:strcpy(((web_session_attr_t *) temp_session->app_data)->content_len,"0"),
									((web_session_attr_t *) temp_session->app_data)->request_counter,((web_session_attr_t *) temp_session->app_data)->enable_http_request_response
	);

	if(temp_session->app_format_id == probe_context->web_id ){
		if (temp_session->app_data == NULL) return;
		if (((web_session_attr_t *) temp_session->app_data)->enable_http_request_response ==1)((web_session_attr_t *) temp_session->app_data)->enable_http_request_response = 0;
	}
	//temp_session->session_attr->touched = 1;

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


