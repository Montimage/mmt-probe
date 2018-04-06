#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>

#ifdef linux
#include <syscall.h>
#endif
#include <netinet/ip.h>
#include "tcpip/mmt_tcpip.h"


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

/* This function takes start time and end time as an input and returns their difference.*/
struct timeval mmt_time_diff(struct timeval tstart, struct timeval tend) {
	tstart.tv_sec = tend.tv_sec - tstart.tv_sec;
	tstart.tv_usec = tend.tv_usec - tstart.tv_usec;
	if ((int) tstart.tv_usec < 0) {
		tstart.tv_usec += 1000000;
		tstart.tv_sec -= 1;
	}
	return tstart;
}

/*This function takes IPv6 address and finds whether this address belongs to a local network.
 *It returns 1 if the address belongs to a IPv6 local network
 */
int is_localv6_net(char * addr) {

	if (strncmp(addr, "fec0", 4) == 0)return 1;
	if (strncmp(addr, "fc00", 4) == 0)return 1;
	if (strncmp(addr, "fe80", 4) == 0)return 1;

	return 0;
}

/*This function takes IPv4 address and finds whether this address belongs to a local network.
 *It returns 1 if the address belongs to a IPv4 local network
 */

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
/* This function writes messages to a log file, including the msg level, time and code */

void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code, const char * log_msg) {
	if (level >= mmt_conf->log_level) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		FILE * log_file = (mmt_conf->log_output != NULL) ? mmt_conf->log_output : stdout;
		fprintf(log_file, "%i\t%lu\t%i\t[%s]\n", level, tv.tv_sec, code, log_msg);
		fflush(log_file);
	}
}

#ifdef HTTP_RECONSTRUCT_MODULE
uint8_t is_http_packet(const ipacket_t * ipacket){
	uint16_t http_index = get_protocol_index_by_id(ipacket, PROTO_HTTP);
	// META->ETH->IP->TCP->HTTP
	if(http_index < 4){
		fprintf(stderr, "[error] %lu: PROTO_HTTP has index smaller than 4\n", ipacket->packet_id);
		return 0;
	}
	return 1;
}

#endif // End of HTTP_RECONSTRUCT_MODULE
/* This function puts the protocol path as a string (for example, 99.178.376,
 * where,99-Ethernet, 178-IP and 376-UDP), in a variable dest and
 * returns its length as a offset.
 * */

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

/* This function returns the index of a particular proto_id, in a proto_path.
 * If the proto_id does not exit it returns -1
 *  */

int get_protocol_index_from_session(const proto_hierarchy_t * proto_hierarchy, uint32_t proto_id) {
	int index = 0;
	for (; index < proto_hierarchy->len && index < 16; index++) {
		if (proto_hierarchy->proto_path[index] == proto_id) return index;
	}
	return -1;
}

static mmt_probe_context_t probe_context = {0};

inline mmt_probe_context_t * get_probe_context_config() {
	return & probe_context;
}

void create_session (const ipacket_t * ipacket, void * user_args){
	mmt_session_t * session = get_session_from_packet(ipacket);
	if(session == NULL) return;

	struct smp_thread *th = (struct smp_thread *) user_args;

	session_struct_t *temp_session = malloc(sizeof (session_struct_t));
	if (temp_session == NULL) {
		mmt_log(&probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating new flow reporting context");
		//fprintf(stderr, "Memory allocation failed when creating a new file reporting struct! This flow will be ignored! Sorry!");
		return;
	}

	memset(temp_session, '\0', sizeof (session_struct_t));

	temp_session->session_id = get_session_id(session);
	temp_session->thread_number = th->thread_index;

	temp_session->format_id = MMT_STATISTICS_FLOW_REPORT_FORMAT;
	temp_session->app_format_id = MMT_DEFAULT_APP_REPORT_FORMAT;

	if (temp_session->isFlowExtracted){
		free(temp_session);
		return;
	}

	// Flow extraction
	int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(ipacket->session);
	temp_session->application_class = get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]);
	temp_session->proto_path = proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)];

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
#ifdef HTTP_RECONSTRUCT_MODULE
	if(probe_context.HTTP_RECONSTRUCT_MODULE_enable == 1){
		if(is_http_packet(ipacket) == 1){
			// printf("[debug] %lu: flow_nb_handle\n", ipacket->packet_id);
			// printf("[debug] %lu: new_session_handle - 2\n", ipacket->packet_id);
			http_content_processor_t * http_content_processor = init_http_content_processor();

			if (http_content_processor == NULL) {
				fprintf(stderr, "[error] %lu: Cannot create http_content_processor\n", ipacket->packet_id);
				free(temp_session);
				return;
			}
			// printf("[debug] %lu: new_session_handle - 3\n", ipacket->packet_id);
			temp_session->http_content_processor = http_content_processor;
			// printf("[debug] %lu: new_session_handle - 4\n", ipacket->packet_id);
			http_session_data_t * http_session_data = get_http_session_data_by_id(get_session_id(session), th->list_http_session_data);
			if (http_session_data == NULL) {
				http_session_data = new_http_session_data();
				if (http_session_data) {
					http_session_data->session_id = get_session_id(session);
					http_session_data->http_session_status = HSDS_START;
					add_http_session_data(http_session_data,th);
				} else {
					fprintf(stderr, "[error] Cannot create http session data for session %lu - packet: %lu\n", get_session_id(session), ipacket->packet_id);
				}
			}
		}
	}
#endif // End of HTTP_RECONSTRUCT_MODULE	
    //    printf ("set session\n");
	set_user_session_context(session, temp_session);
}
/* This function assigns the session ID to a new flow (session), maintains session informations in session_struct_t and
 * updates mmt_session_t context with new session informations (session_struct_t).
 * */

void flow_nb_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	create_session (ipacket, (void *)user_args);
}

/* This function is called by mmt-dpi for each incoming packet.
 * It extracts packet information from a #ipacket for creating messages/reports.
 * */
int packet_handler(const ipacket_t * ipacket, void * args) {
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;
	if(probe_context->enable_session_report == 1){
		session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

		if (ipacket->session != NULL && temp_session == NULL){
			create_session (ipacket, (void *)args);
		}
		if (th->pcap_current_packet_time == 0){
			th->pcap_last_stat_report_time = ipacket->p_hdr->ts.tv_sec;
		}
		th->pcap_current_packet_time = ipacket->p_hdr->ts.tv_sec;

		if (temp_session != NULL) {
			// only for packet based on TCP
			if (temp_session->dtt_seen == 0){
				//this will exclude all the protocols except TCP
				if(TIMEVAL_2_USEC(get_session_rtt(ipacket->session)) != 0){
					struct timeval t1;
					t1.tv_sec = 0;
					t1.tv_usec = 0;
					//The download direction is opposite to set_up_direction, the download direction is from server to client
					if (get_session_last_packet_direction(ipacket->session) != get_session_setup_direction(ipacket->session)){
						t1 = get_session_last_data_packet_time_by_direction(ipacket->session,get_session_last_packet_direction(ipacket->session));
					}
					if (TIMEVAL_2_USEC(mmt_time_diff(get_session_init_time(ipacket->session),ipacket->p_hdr->ts)) > TIMEVAL_2_USEC(get_session_rtt(ipacket->session)) && t1.tv_sec > 0){
						temp_session->dtt_seen = 1;
						temp_session->dtt_start_time = ipacket->p_hdr->ts;
					}
				}
			}
		}
	}

	if (probe_context->enable_security_report == 1){
		get_security_report(ipacket,args);
	}
	if (probe_context->enable_security_report_multisession == 1){
		get_security_multisession_report(ipacket,args);
	}

	return 0;
}
/* This function registers the packet handler for each threads */
void proto_stats_init(void * arg) {
	struct smp_thread *th = (struct smp_thread *) arg;
	register_packet_handler(th->mmt_handler, 6, packet_handler, arg);
}

void proto_stats_cleanup(void * handler) {
	(void) unregister_packet_handler((mmt_handler_t *) handler, 1);
}

/* This function unregisters the attributes for a flow (session)
 * */
void flowstruct_uninit(void * args) {
        struct smp_thread *th = (struct smp_thread *) args;
        mmt_probe_context_t * probe_context = get_probe_context_config();

        int i = 1;
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, TCP_SRC_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_SRC_PORT);
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, TCP_DEST_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_DEST_PORT);
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, TCP_RTT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_TCP, TCP_RTT);
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, UDP_SRC_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_UDP, UDP_SRC_PORT);
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, UDP_DEST_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_UDP, UDP_DEST_PORT);

        if (is_registered_attribute(th->mmt_handler, PROTO_ETHERNET, ETH_DST) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_ETHERNET, ETH_DST);
        if (is_registered_attribute(th->mmt_handler, PROTO_TCP, TCP_DEST_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_ETHERNET, ETH_SRC);
        if (is_registered_attribute(th->mmt_handler, PROTO_IP, IP_SRC) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_SRC);
        if (is_registered_attribute(th->mmt_handler, PROTO_IP, IP_DST) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DST);
        if (is_registered_attribute(th->mmt_handler, PROTO_IP, IP_PROTO_ID) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_PROTO_ID);
        if (is_registered_attribute(th->mmt_handler, PROTO_IP, IP_SERVER_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_SERVER_PORT);
        if (is_registered_attribute(th->mmt_handler, PROTO_IP, IP_CLIENT_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_CLIENT_PORT);

        if (is_registered_attribute(th->mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO);
        if (is_registered_attribute(th->mmt_handler,  PROTO_IPV6, IP6_SRC) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_SRC);
        if (is_registered_attribute(th->mmt_handler, PROTO_IPV6, IP6_DST) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_DST);
        if (is_registered_attribute(th->mmt_handler, PROTO_IPV6, IP6_SERVER_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_SERVER_PORT);
        if (is_registered_attribute(th->mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT) == 1) i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT);
/*
        if (probe_context->enable_IP_fragmentation_report == 1){
                i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_FRAG_PACKET_COUNT);
                i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_FRAG_DATA_VOLUME);
                i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DF_PACKET_COUNT);
                i &= unregister_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DF_DATA_VOLUME);
        }
*/
        if (is_registered_attribute_handler(th->mmt_handler, PROTO_IP, PROTO_SESSION, flow_nb_handle) == 1) i &= unregister_attribute_handler(th->mmt_handler, PROTO_IP, PROTO_SESSION, flow_nb_handle);
        if (is_registered_attribute_handler(th->mmt_handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle) == 1) i &= unregister_attribute_handler(th->mmt_handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle);
        if (is_registered_attribute_handler(th->mmt_handler,  PROTO_IP, IP_RTT, ip_rtt_handler) == 1) i &= unregister_attribute_handler(th->mmt_handler, PROTO_IP, IP_RTT, ip_rtt_handler);
        if (is_registered_attribute_handler(th->mmt_handler, PROTO_TCP,TCP_CONN_CLOSED, tcp_closed_handler) == 1) i &= unregister_attribute_handler(th->mmt_handler, PROTO_TCP,TCP_CONN_CLOSED, tcp_closed_handler);
        if(!i) {
                //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
                fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
        }
}

/* This function registers the required attributes for a flow (session)
 * */
void flowstruct_init(void * args) {
	struct smp_thread *th = (struct smp_thread *) args;
	mmt_probe_context_t * probe_context = get_probe_context_config();

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
	if (probe_context->enable_IP_fragmentation_report == 1){
		i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_FRAG_PACKET_COUNT);
		i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_FRAG_DATA_VOLUME);
		i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DF_PACKET_COUNT);
		i &= register_extraction_attribute(th->mmt_handler, PROTO_IP, IP_DF_DATA_VOLUME);
	}

	i &= register_attribute_handler(th->mmt_handler, PROTO_IP, PROTO_SESSION, flow_nb_handle, NULL, (void *)args);
	i &= register_attribute_handler(th->mmt_handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle, NULL, (void *)args);
	i &= register_attribute_handler(th->mmt_handler, PROTO_IP, IP_RTT, ip_rtt_handler, NULL, (void *)args);
	i &=register_attribute_handler(th->mmt_handler, PROTO_TCP,TCP_CONN_CLOSED, tcp_closed_handler, NULL, (void *)args);
	/*if(probe_context->ftp_enable == 1){
		register_ftp_attributes(th->mmt_handler);
	}*/
	if(!i) {
		//TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
		fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
	}
}

void flowstruct_cleanup(void * handler) {
}



int time_diff(struct timeval t1, struct timeval t2) {
	return (((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec)) / 1000;
}

/* It provides os_id and device_id from a user_agent if it exists or returns 0
 * */
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

/* This function is called by mmt-dpi for each session time-out (expiry).
 * It provides the expired session information and frees the memory allocated.
 * */
void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
	//	debug("classification_expiry_session : %lu",get_session_id(expired_session));
	session_struct_t * temp_session = get_user_session_context(expired_session);
	struct smp_thread *th = (struct smp_thread *) args;
	if (temp_session == NULL) {
		return;
	}

#ifdef HTTP_RECONSTRUCT_MODULE
	// printf("[debug] cleaning HTTP_RECONSTRUCT_MODULE ... %lu \n",get_session_id(expired_session));
	if (temp_session->http_content_processor != NULL) {
		close_http_content_processor(temp_session->http_content_processor);
	}
	clean_http_session_data(get_session_id(expired_session),th);
#endif	

	mmt_probe_context_t * probe_context = get_probe_context_config();

	if (is_microflow(expired_session)) {
		microsessions_stats_t * mf_stats = &th->iprobe.mf_stats[get_session_protocol_hierarchy(expired_session)->proto_path[(get_session_protocol_hierarchy(expired_session)->len <= 16)?(get_session_protocol_hierarchy(expired_session)->len - 1):(16 - 1)]];
		update_microflows_stats(mf_stats, expired_session);
		if (is_microflow_stats_reportable(mf_stats)) {
			report_microflows_stats(mf_stats, args);
		}
	}else{
		if(temp_session->app_format_id == MMT_WEB_REPORT_FORMAT){
			if (temp_session->app_data == NULL) {
				if (temp_session->session_attr != NULL) {
					//Free the application specific data
					if (temp_session->session_attr) free(temp_session->session_attr);
					temp_session->session_attr = NULL;
				}
				if(temp_session) free(temp_session);
				temp_session = NULL;
				return;
			}
			if (((web_session_attr_t *) temp_session->app_data)->state_http_request_response != 0)((web_session_attr_t *) temp_session->app_data)->state_http_request_response = 0;
			if (temp_session->session_attr == NULL) {
				temp_session->session_attr = (session_stat_t *) malloc(sizeof (session_stat_t));
				memset(temp_session->session_attr, 0, sizeof (session_stat_t));
			}
			temp_session->report_counter = th->report_counter;
			print_ip_session_report (expired_session, th);
		}else{
			temp_session->report_counter = th->report_counter;
			print_ip_session_report (expired_session, th);
		}
	}

	if (temp_session->app_data != NULL) {
		//Free the application specific data
		if (temp_session->app_format_id == MMT_FTP_REPORT_FORMAT){
			if (((ftp_session_attr_t*) temp_session->app_data)->filename != NULL)free (((ftp_session_attr_t*) temp_session->app_data)->filename);
			if (((ftp_session_attr_t*) temp_session->app_data)->response_value != NULL)free(((ftp_session_attr_t*) temp_session->app_data)->response_value);
			if (((ftp_session_attr_t*) temp_session->app_data)->session_username != NULL)free(((ftp_session_attr_t*) temp_session->app_data)->session_username);
			if (((ftp_session_attr_t*) temp_session->app_data)->session_password != NULL)free(((ftp_session_attr_t*) temp_session->app_data)->session_password);
			((ftp_session_attr_t*) temp_session->app_data)->filename = NULL;
			((ftp_session_attr_t*) temp_session->app_data)->response_value = NULL;
			((ftp_session_attr_t*) temp_session->app_data)->session_username = NULL;
			((ftp_session_attr_t*) temp_session->app_data)->session_password = NULL;
		}
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
