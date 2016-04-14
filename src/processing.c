#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip.h"
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h> //inet_ntop
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include <time.h>
#include <windows.h>
#endif

#include "processing.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>



#ifdef _WIN32
#ifndef socklen_t
typedef int socklen_t;
#define socklen_t socklen_t
#endif
#endif

#if (_WIN32_WINNT)
void WSAAPI freeaddrinfo(struct addrinfo*);
int WSAAPI getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
int WSAAPI getnameinfo(const struct sockaddr*, socklen_t, char*, DWORD, char*, DWORD, int);
#endif

#ifdef _WIN32

const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt) {
	if (af == AF_INET) {
		struct sockaddr_in in;
		memset(&in, 0, sizeof (in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, src, sizeof (struct in_addr));
		getnameinfo((struct sockaddr *) &in, sizeof (struct
				sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	} else if (af == AF_INET6) {
		struct sockaddr_in6 in;
		memset(&in, 0, sizeof (in));
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, src, sizeof (struct in_addr6));
		getnameinfo((struct sockaddr *) &in, sizeof (struct
				sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	return NULL;
}
#endif

uint64_t expired_session_count = 1;
uint64_t session_id_probe = 1;

struct timeval mmt_time_diff(struct timeval tstart, struct timeval tend) {
	tstart.tv_sec = tend.tv_sec - tstart.tv_sec;
	tstart.tv_usec = tend.tv_usec - tstart.tv_usec;
	if ((int) tstart.tv_usec < 0) {
		tstart.tv_usec += 1000000;
		tstart.tv_sec -= 1;
	}
	return tstart;
}

int is_localv6_net(char * addr) {

	if (strncmp(addr,"fec0",4)==0)return 1;
	if (strncmp(addr,"fc00",4)==0)return 1;
	if (strncmp(addr,"fe80",4)==0)return 1;

	return 0;
}

int is_local_net(int addr) {


	if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
		return 1;
	}
	if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xC0000000 /* 192.0.0.0 */) {
		return 1;
	}
	if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xAC000000 /* 172.0.0.0 */) {
		return 1;
	}
	if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xA9000000 /* 169.0.0.0 */) {
		return 1;
	}

	return 0;
}

void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code, const char * log_msg) {
	if (level >= mmt_conf->log_level) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		FILE * log_file = (mmt_conf->log_output != NULL) ? mmt_conf->log_output : stdout;
		fprintf(log_file, "%i\t%lu\t%i\t[%s]\n", level, tv.tv_sec, code, log_msg);
		fflush(log_file);
	}
}

int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
	int offset = 0;
	if (proto_hierarchy->len < 1) {
		offset += sprintf(dest, ".");
	} else {
		int index = 1;
		offset += sprintf(dest, "%u", proto_hierarchy->proto_path[index]);
		index++;
		for (; index < proto_hierarchy->len && index < 16; index++) {
			offset += sprintf(&dest[offset], ".%u", proto_hierarchy->proto_path[index]);
		}
	}
	return offset;
}

int get_protocol_index_from_session(const proto_hierarchy_t * proto_hierarchy, uint32_t proto_id) {
	int index = 0;
	for (; index < proto_hierarchy->len && index < 16; index++) {
		if (proto_hierarchy->proto_path[index] == proto_id) return index;
	}
	return -1;
}

static mmt_probe_context_t probe_context = {0};

mmt_probe_context_t * get_probe_context_config() {
	return & probe_context;
}

void flow_nb_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	mmt_session_t * session = get_session_from_packet(ipacket);
	if(session == NULL) return;

	uint64_t * IPV4_active_sessions = NULL;
	uint64_t * IPV6_active_sessions = NULL;
	struct smp_thread *th = (struct smp_thread *) user_args;

	if (attribute->data == NULL) {
		return; //This should never happen! check it anyway
	}

	session_struct_t *temp_session = malloc(sizeof (session_struct_t));
	if (temp_session == NULL) {
		mmt_log(&probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating new flow reporting context");
		//fprintf(stderr, "Memory allocation failed when creating a new file reporting struct! This flow will be ignored! Sorry!");
		return;
	}

	memset(temp_session, '\0', sizeof (session_struct_t));

	temp_session->session_id = get_session_id(session);
	temp_session->thread_number = th->thread_number;

	temp_session->format_id = MMT_FLOW_REPORT_FORMAT;
	temp_session->app_format_id = MMT_DEFAULT_APP_REPORT_FORMAT;

	if (temp_session->isFlowExtracted)
		return;

	// Flow extraction
	int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(ipacket->session);
	temp_session->application_class= get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]);
	temp_session->proto_path=proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)];

	unsigned char *src = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
	unsigned char *dst = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);

	if (src) {
		memcpy(temp_session->src_mac, src, 6);
		temp_session->src_mac [6] = '\0';
	}
	if (dst) {
		memcpy(temp_session->dst_mac, dst, 6);
		temp_session->dst_mac [6] = '\0';
	}

	if (ipindex != -1) {

		uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
		uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);

		if (ip_src) {
			//printf("HAS IP ADDRESS \n");
			temp_session->ipclient.ipv4 = (*ip_src);
		}
		if (ip_dst) {
			temp_session->ipserver.ipv4 = (*ip_dst);
		}

		uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);
		if (proto_id != NULL) {
			temp_session->proto = *proto_id;
		} else {
			temp_session->proto = 0;
		}
		temp_session->ipversion = 4;
		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
		if (cport) {
			temp_session->clientport = *cport;
		}
		if (dport) {
			temp_session->serverport = *dport;
		}
	} else {
		void * ipv6_src = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
		void * ipv6_dst = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
		if (ipv6_src) {
			memcpy(&temp_session->ipclient.ipv6, ipv6_src, 16);
		}
		if (ipv6_dst) {
			memcpy(&temp_session->ipserver.ipv6, ipv6_dst, 16);
		}

		uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_NEXT_PROTO);
		if (proto_id != NULL) {
			temp_session->proto = *proto_id;
		} else {
			temp_session->proto = 0;
		}
		temp_session->ipversion = 6;
		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
		if (cport) {
			temp_session->clientport = *cport;
		}
		if (dport) {
			temp_session->serverport = *dport;
		}
	}
	temp_session->isFlowExtracted = 1;
	set_user_session_context(session, temp_session);
}

int packet_handler(const ipacket_t * ipacket, void * args) {

	//printf("packet_id: %lu\n", ipacket->packet_id);

	/* if (probe_context.ftp_reconstruct_enable==1)
        reconstruct_data(ipacket);*/
	return 0;

}

void proto_stats_init(void * handler) {
	register_packet_handler(handler, 5, packet_handler, NULL);
}

void proto_stats_cleanup(void * handler) {
	(void) unregister_packet_handler((mmt_handler_t *) handler, 1);
}
void * get_handler_by_name(char * func_name){

	if (strcmp(func_name,"ftp_file_name_handle")==0){
		return ftp_file_name_handle;
	}
	if (strcmp(func_name,"ftp_session_connection_type_handle")==0){
		return ftp_session_connection_type_handle;
	}
	if (strcmp(func_name,"ftp_user_name_handle")==0){
		return ftp_user_name_handle;
	}
	if (strcmp(func_name,"ftp_password_handle")==0){
		return ftp_password_handle;
	}
	if (strcmp(func_name,"ftp_response_value_handle")==0){
		return ftp_response_value_handle;
	}
	if (strcmp(func_name,"ftp_file_size_handle")==0){
		return ftp_file_size_handle;
	}
	if (strcmp(func_name,"ftp_packet_request_handle")==0){
		return ftp_packet_request_handle;
	}
	if (strcmp(func_name,"ftp_data_direction_handle")==0){
		return ftp_data_direction_handle;
	}
	if (strcmp(func_name,"ftp_response_code_handle")==0){
	    return ftp_response_code_handle;
	}
	if (strcmp(func_name,"http_method_handle")==0){
		return http_method_handle;
	}
	if (strcmp(func_name,"http_response_handle")==0){
		return http_response_handle;
	}
	if (strcmp(func_name,"mime_handle")==0){
		return mime_handle;
	}
	if (strcmp(func_name,"host_handle")==0){
		return host_handle;
	}
	if (strcmp(func_name,"uri_handle")==0){
		return uri_handle;
	}
	if (strcmp(func_name,"useragent_handle")==0){
		return useragent_handle;
	}
	if (strcmp(func_name,"referer_handle")==0){
		return referer_handle;
	}
	if (strcmp(func_name,"xcdn_seen_handle")==0){
		return xcdn_seen_handle;
	}
	if (strcmp(func_name,"rtp_version_handle")==0){
		return rtp_version_handle;
	}
	if (strcmp(func_name,"rtp_jitter_handle")==0){
		return rtp_jitter_handle;
	}
	if (strcmp(func_name,"rtp_loss_handle")==0){
		return rtp_loss_handle;
	}
	if (strcmp(func_name,"rtp_order_error_handle")==0){
		return rtp_order_error_handle;
	}
	if (strcmp(func_name,"rtp_burst_loss_handle")==0){
		return rtp_burst_loss_handle;
	}
	if (strcmp(func_name,"ssl_server_name_handle")==0){
		return ssl_server_name_handle;
	}
	return 0;
}

int register_conditional_report_handle(void * args, mmt_condition_report_t * condition_report) {
	int i = 1,j;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;
	for(j = 0; j < condition_report->attributes_nb; j++) {
		mmt_condition_attribute_t * condition_attribute = &condition_report->attributes[j];
		mmt_condition_attribute_t * handler_attribute = &condition_report->handlers[j];
		if (strcmp(handler_attribute->handler,"NULL")==0){
			i &= register_extraction_attribute_by_name(th->mmt_handler, condition_attribute->proto, condition_attribute->attribute);

		}else{
			i &= register_attribute_handler_by_name(th->mmt_handler, condition_attribute->proto,condition_attribute->attribute, get_handler_by_name (handler_attribute->handler), NULL, args);
		}
	}


	return i;
}
void conditional_reports_init(void * args) {
	int i;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	//struct smp_thread *th = (struct smp_thread *) args;

	for(i = 0; i < probe_context->condition_reports_nb; i++) {
		mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
		if(register_conditional_report_handle(args, condition_report) == 0) {
			fprintf(stderr, "Error while initializing condition report number %i!\n", condition_report->id);
			printf( "Error while initializing condition report number %i!\n", condition_report->id);
		}
	}
}
void flowstruct_init(void * args) {
	struct smp_thread *th = (struct smp_thread *) args;
	int i = 1;
	i &= register_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_SRC_PORT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_DEST_PORT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_RTT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_UDP, UDP_SRC_PORT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_UDP, UDP_DEST_PORT);

	i &= register_extraction_attribute(th->mmt_handler, PROTO_ETHERNET, ETH_DST);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_ETHERNET, ETH_SRC);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_SRC);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DST);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_PROTO_ID);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_SERVER_PORT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_CLIENT_PORT);

	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_SRC);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_DST);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_SERVER_PORT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT);

	i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, PROTO_ACTIVE_SESSIONS_COUNT);
	i &= register_extraction_attribute(th->mmt_handler, PROTO_IPV6, PROTO_ACTIVE_SESSIONS_COUNT);

	i &= register_attribute_handler(th->mmt_handler, PROTO_IP, PROTO_SESSION, flow_nb_handle, NULL, (void *)args);
	i &= register_attribute_handler(th->mmt_handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle, NULL, (void *)args);
	register_ftp_attributes(th->mmt_handler);
	if(!i) {
		//TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
		fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
	}
}

void flowstruct_cleanup(void * handler) {
}



/*
 ** encodeblock
 **
 ** encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
inline void encodeblock(unsigned char in[3], unsigned char out[4], int len) {
	out[0] = cb64[ in[0] >> 2 ];
	out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
 ** encode
 **
 ** base64 encode a string.
 */
inline int encode_str(const char *infile, char *out_file) {
	unsigned char in[3], out[4];
	int i, len;
	int copiedBytes = 0;
	while (infile[0] != '\0') {
		len = 0;
		for (i = 0; i < 3; i++) {
			in[i] = infile[0];
			if (infile[0] != '\0') {
				len++;
			} else {
				in[i] = 0;
			}
			infile++;
		}
		if (len) {
			encodeblock(in, out, len);
			for (i = 0; i < 4; i++) {
				out_file[copiedBytes] = out[i];
				copiedBytes++;
			}
		}
	}
	out_file[copiedBytes] = '\0';
	return copiedBytes;
}

int time_diff(struct timeval t1, struct timeval t2) {
	return (((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec)) / 1000;
}

mmt_dev_properties_t get_dev_properties_from_user_agent(char * user_agent, uint32_t len) {
	mmt_dev_properties_t retval = {0};
	if ((len > 8) && (mmt_strncasecmp(user_agent, "Mozilla/", 8) == 0)) {
		if ((len > 20) && (mmt_strncasecmp(&user_agent[12], "(iPhone;", 8) == 0)) {
			retval.os_id = OS_IOS;
			retval.dev_id = DEV_IPHONE;
		} else if ((len > 18) && (mmt_strncasecmp(&user_agent[12], "(iPod;", 6) == 0)) {
			retval.os_id = OS_IOS;
			retval.dev_id = DEV_IPOD;
		} else if ((len > 18) && (mmt_strncasecmp(&user_agent[12], "(iPad;", 6) == 0)) {
			retval.os_id = OS_IOS;
			retval.dev_id = DEV_IPAD;
		} else if ((len > 30) && (mmt_strncasecmp(&user_agent[12], "(Linux; U; Android", 18) == 0)) {
			retval.os_id = OS_AND;
			retval.dev_id = DEV_MOB;
		} else if ((len > 20) && (mmt_strncasecmp(&user_agent[12], "(Android", 8) == 0)) {
			retval.os_id = OS_AND;
			retval.dev_id = DEV_MOB;
		} else if ((len > 24) && (mmt_strncasecmp(&user_agent[12], "(BlackBerry;", 12) == 0)) {
			retval.os_id = OS_BLB;
			retval.dev_id = DEV_BLB;
		} else if ((len > 17) && (mmt_strncasecmp(&user_agent[12], "(X11;", 5) == 0)) {
			retval.os_id = OS_NUX;
			retval.dev_id = DEV_PC;
		} else if ((len > 23) && (mmt_strncasecmp(&user_agent[12], "(Macintosh;", 11) == 0)) {
			retval.os_id = OS_MAC;
			retval.dev_id = DEV_MAC;
		} else if ((len > 29) && (mmt_strncasecmp(&user_agent[12], "(Windows; U; MSIE", 17) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
        } else if ((len > 23) && (mmt_strncasecmp(&user_agent[12], "(Windows NT", 11) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
		} else if ((len > 35) && (mmt_strncasecmp(&user_agent[12], "(Windows; U; Windows NT", 23) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
		} else if ((len > 36) && (mmt_strncasecmp(&user_agent[12], "(compatible; Windows; U;", 24) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
		} else if ((len > 46) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 10.0; Macintosh;", 34) == 0)) {
			retval.os_id = OS_MAC;
			retval.dev_id = DEV_MAC;
		} else if ((len > 48) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 9.0; Windows Phone", 36) == 0)) {
			retval.os_id = OS_WPN;
			retval.dev_id = DEV_MOB;
		} else if ((len > 56) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 10.0; Windows NT 6.2; ARM;", 44) == 0)) {
			retval.os_id = OS_WPN;
			retval.dev_id = DEV_MOB;
		} else if ((len > 29) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE", 17) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
		}
	} else if ((len > 6) && (mmt_strncasecmp(user_agent, "Opera/", 6) == 0)) {
		if ((len > 19) && (mmt_strncasecmp(&user_agent[11], "(Windows", 8) == 0)) {
			retval.os_id = OS_WIN;
			retval.dev_id = DEV_PC;
		} else if ((len > 22) && (mmt_strncasecmp(&user_agent[11], "(Macintosh;", 11) == 0)) {
			retval.os_id = OS_MAC;
			retval.dev_id = DEV_MAC;
		} else if ((len > 16) && (mmt_strncasecmp(&user_agent[11], "(X11;", 5) == 0)) {
			retval.os_id = OS_NUX;
			retval.dev_id = DEV_PC;
		}
	}
	return retval;
}

void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
	session_struct_t * temp_session = get_user_session_context(expired_session);
	struct smp_thread *th = (struct smp_thread *) args;
	if (temp_session == NULL) {
		return;
	}

	mmt_probe_context_t * probe_context = get_probe_context_config();

	int sslindex;
	print_ip_session_report (expired_session,th);
	if (is_microflow(expired_session)) {
		microsessions_stats_t * mf_stats = &th->iprobe.mf_stats[get_session_protocol_hierarchy(expired_session)->proto_path[(get_session_protocol_hierarchy(expired_session)->len <= 16)?(get_session_protocol_hierarchy(expired_session)->len - 1):(16 - 1)]];
		update_microflows_stats(mf_stats, expired_session);
		if (is_microflow_stats_reportable(mf_stats)) {
			report_microflows_stats(mf_stats,args);
		}
	} else {
		//First we check if we should skip the reporting for this flow
		if (temp_session->app_format_id != MMT_SKIP_APP_REPORT_FORMAT) {
			if (probe_context->web_enable==1 && temp_session->app_format_id==probe_context->web_id)print_web_app_format(expired_session,(void *) th);
			else if (probe_context->ssl_enable==1 && temp_session->app_format_id==probe_context->ssl_id)print_ssl_app_format(expired_session,(void *) th);
			else if(probe_context->rtp_enable==1 && temp_session->app_format_id==probe_context->rtp_id)print_rtp_app_format(expired_session,(void *) th);
			else if(probe_context->ftp_enable==1 && temp_session->app_format_id==probe_context->ftp_id)print_ftp_app_format(expired_session, (void *)th);
			else{
				sslindex = get_protocol_index_from_session(get_session_protocol_hierarchy(expired_session), PROTO_SSL);
				if (sslindex != -1 && probe_context->ssl_enable==1 ){
					temp_session->app_format_id = probe_context->ssl_id;
					if (probe_context->ssl_enable==1 && temp_session->app_format_id==probe_context->ssl_id)print_ssl_app_format(expired_session, (void *)th);
				}
				//else print_default_app_format(expired_session,(void *)th);//jeevan if no report are enable , comment it
			}

		}
	}


	if (temp_session->app_data != NULL) {
		//Free the application specific data
		if(temp_session->app_data) free(temp_session->app_data);
		temp_session->app_data = NULL;
	}
	if (temp_session->session_attr != NULL) {
		//Free the application specific data
		if (temp_session->session_attr) free(temp_session->session_attr);
		temp_session->session_attr = NULL;
	}
	if(temp_session) free(temp_session);
	temp_session = NULL;
}
