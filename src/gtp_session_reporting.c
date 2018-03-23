#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>


#include "gtp_session_report.h"

#define IP_ENCAP_INDEX_AFTER_GTP 1


//session is based on IP after GTP, not on IP after ETHERNET
#define _is_session_based_on_ip_after_gtp( ipacket  )\
	(get_protocol_index_by_id(ipacket, PROTO_GTP) + 1 ==  get_session_protocol_index( ipacket->session ))

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
	}else{
		ip_src_str[0] = '\0';
		ip_dst_str[0] = '\0';
	}


	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);

	snprintf(&message[valid], MAX_MESS-valid,
			",%u,%u,%u," //common: format, app_class, content_class
			"\"%s\",\"%s\",%u,%u", //ip_src, ip_dst, teid[0], teid[1]
			temp_session->app_format_id, //format
			get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
			temp_session->contentclass,
			ip_src_str,
			ip_dst_str,
			gtp_data->teids[0],
			gtp_data->teids[1]
	);

	//printf("%s\n", message );

	temp_session->session_attr->touched = 1;

	temp_session->app_data = NULL;
	free( gtp_data );
}


gtp_session_attr_t *get_gtp_session_data( const ipacket_t *ipacket ){
	int i;

	//must have a session
	if(ipacket->session == NULL)
		return NULL;

	//the session must be beyond IP over GTP
	if( ! _is_session_based_on_ip_after_gtp(ipacket) )
		return NULL;


	//the session must be initialized by Probe (in function flow_nb_handle - processing.c)
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
	if(temp_session == NULL )
		return NULL;

	gtp_session_attr_t *gtp_data = NULL;
	//if GTP data is not initialized
	if( temp_session->app_data == NULL
			//|| temp_session->app_format_id != MMT_GTP_REPORT_FORMAT
	){
		gtp_data = (gtp_session_attr_t *) malloc( sizeof( gtp_session_attr_t ));
		memset(gtp_data, '\0', sizeof (gtp_session_attr_t));

		temp_session->app_format_id = MMT_GTP_REPORT_FORMAT;
		temp_session->app_data = gtp_data;

	}
	else
		gtp_data = (gtp_session_attr_t *) temp_session->app_data;

	return gtp_data;
}

void gtp_update_data( const ipacket_t *ipacket, gtp_session_attr_t *gtp_data){
	if( gtp_data == NULL )
		return;

	//ip was extracted
	if( gtp_data->ip_version != 0 ){
		//what happen when IP is changed
		return;
	}

	//has IPv4 in protocol hierarchy ???
	const unsigned has_proto_ipv4 = get_protocol_index_by_id(ipacket, PROTO_IP);

	//IPv4
	if ( has_proto_ipv4 ) {
		gtp_data->ip_version = 4;
		gtp_data->ip_src.ipv4 = *(uint32_t *) get_attribute_extracted_data_encap_index( ipacket, PROTO_IP, IP_SRC, IP_ENCAP_INDEX_AFTER_GTP );
		gtp_data->ip_dst.ipv4 = *(uint32_t *) get_attribute_extracted_data_encap_index( ipacket, PROTO_IP, IP_DST, IP_ENCAP_INDEX_AFTER_GTP );
	}else{
		gtp_data->ip_version = 6;
		memcpy(&gtp_data->ip_src.ipv6,
				get_attribute_extracted_data_encap_index( ipacket, PROTO_IPV6, IP6_SRC, IP_ENCAP_INDEX_AFTER_GTP ),
				16);
		memcpy( gtp_data->ip_dst.ipv6,
				get_attribute_extracted_data_encap_index( ipacket, PROTO_IPV6, IP6_DST, IP_ENCAP_INDEX_AFTER_GTP ),
				16);
	}
}

void gtp_teid_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	int i;
	gtp_session_attr_t *gtp_data = get_gtp_session_data(ipacket);
	if( gtp_data == NULL ){
		return;
	}

	const uint32_t teid = *( uint32_t *) attribute->data;

	//save all TEID appear in the session
	for( i=0; i<MAX_NB_TEID; i++ )
		//existing
		if( gtp_data->teids[i] == teid )
			break;
		//add to an empty position
		else if( gtp_data->teids[i] == 0 ){
			//TODO: what happen when TEID is changed
			gtp_data->teids[i] = teid;
			break;
		}
	if( i== MAX_NB_TEID ){
		printf(">>> more than 2 TEID on a session\n");
	}
}
