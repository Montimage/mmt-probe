#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <inttypes.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

void print_initial_gtp_report(const mmt_session_t * session, session_struct_t * temp_session, char message [MAX_MESS + 1], int valid) {

	mmt_probe_context_t * probe_context = get_probe_context_config();

	if(session == NULL || temp_session == NULL || temp_session->app_data == NULL || temp_session->app_format_id != MMT_GTP_REPORT_FORMAT){
		return;
	}
	gtp_session_attr_t *gtp_data = (gtp_session_attr_t *) temp_session->app_data;
	if( gtp_data == NULL )
		return;

	char ip_src_str[46];
	char ip_dst_str[46];
	if (gtp_data->ip_version == 4) {
		inet_ntop(AF_INET, (void *) &gtp_data->ip_src.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &gtp_data->ip_dst.ipv4, ip_dst_str, INET_ADDRSTRLEN);
	} else if(gtp_data->ip_version == 6) {
		inet_ntop(AF_INET6, (void *) &gtp_data->ip_src.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &gtp_data->ip_dst.ipv6, ip_dst_str, INET6_ADDRSTRLEN);

	}

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);

	snprintf(&message[valid], MAX_MESS-valid,
			",%u,%u,%u," //common
			"%u,\"%s\",\"%s\"", //teid, ip_src, ip_dst
			temp_session->app_format_id,
			get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
			temp_session->contentclass,
			gtp_data->teid,
			ip_src_str,
			ip_dst_str
	);

	temp_session->session_attr->touched = 1;

	temp_session->app_data = NULL;
	free( gtp_data );
}


void gtp_teid_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;

	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if(temp_session == NULL )
		return;

	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_args;

	gtp_session_attr_t *gtp_data = NULL;
	if( temp_session->app_data == NULL ){
		gtp_data = (gtp_session_attr_t *) malloc( sizeof( gtp_session_attr_t ));
		memset(gtp_data, '\0', sizeof (gtp_session_attr_t));

		if( gtp_data == NULL ){
			mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating GTP reporting");
			return;
		}
		temp_session->app_data = gtp_data;
	}
	else
		gtp_data = (gtp_session_attr_t *) temp_session->app_data;

	temp_session->app_format_id = MMT_GTP_REPORT_FORMAT;
	gtp_data->teid = *( uint32_t *) attribute->data;
	printf(">>> teid = %u\n", gtp_data->teid );
}

void gtp_ip_src_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if(temp_session == NULL || temp_session->app_data == NULL || temp_session->app_format_id != MMT_GTP_REPORT_FORMAT)
			return;

	gtp_session_attr_t *gtp_data = (gtp_session_attr_t *) temp_session->app_data;
	if( gtp_data == NULL )
		return;

//	int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
//
//	if (ipindex != -1) {
		if( gtp_data->ip_src.ipv4 != 0 )
				return;
		gtp_data->ip_src.ipv4 = *(uint32_t *) attribute->data;
		gtp_data->ip_version = 4;
//	}else{
//		memcpy(&gtp_data->ip_src.ipv6, attribute->data, 16);
//		gtp_data->ip_version = 6;
//	}
}

void gtp_ip_dst_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if(ipacket->session == NULL) return;
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if( temp_session == NULL )
		return;

	gtp_session_attr_t *gtp_data = (gtp_session_attr_t *) temp_session->app_data;
	if( gtp_data == NULL )
		return;

//	int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
//
//	if (ipindex != -1) {
		if( gtp_data->ip_dst.ipv4 != 0 )
			return;
		gtp_data->ip_dst.ipv4 = *(uint32_t *) attribute->data;
		gtp_data->ip_version = 4;
//	}else{
//		memcpy(&gtp_data->ip_dst.ipv6, attribute->data, 16);
//		gtp_data->ip_version = 6;
//	}

}
