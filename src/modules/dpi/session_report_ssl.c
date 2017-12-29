/*
 * session_report_ssl.c
 *
 *  Created on: Dec 29, 2017
 *      Author: nhnghia
 */

#include "header.h"

struct session_ssl_stat_struct {
	char hostname[64];
};

/* This function is called by mmt-dpi for reporting ssl server_name, if an extraction handler is registered */
static void _ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if( unlikely( ipacket->session == NULL))
    		return;

    if( ipacket->session == NULL )
    		return;

    	packet_session_t *session =
    			(packet_session_t *) get_user_session_context_from_packet(ipacket);

    	if( session == NULL )
    		return;

    	if( session->app_type != SESSION_STAT_TYPE_APP_IP
    			&& session->app_type != SESSION_STAT_TYPE_APP_SSL )
    		ABORT( "Impossible: stat_type must be %d, not %d",
    				SESSION_STAT_TYPE_APP_IP, session->app_type);

    	if( session->apps.ssl == NULL ){
    		session->apps.ssl = alloc(sizeof (session_ssl_stat_t));
    		reset_string( session->apps.ssl->hostname );
    		session->data_stat.is_touched = false;

    		session->app_type = SESSION_STAT_TYPE_APP_SSL;
    	}

    	mmt_header_line_t *val = (mmt_header_line_t *) attribute->data;
    	if( unlikely( val == NULL || val->len == 0 ))
    		return;

    	int target_size = sizeof( session->apps.ssl->hostname );

    	if( val->len < target_size )
    		target_size = val->len;
    	strncpy( session->apps.ssl->hostname, val->ptr, target_size );

    session->content_class = get_content_class_by_content_flags( get_session_content_flags(ipacket->session) );
}

static const conditional_handler_t handlers[] = {
	{.proto_id = PROTO_SSL, .att_id = SSL_SERVER_NAME, .handler = _ssl_server_name_handle},
};


//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_ssl_handlers_to_register( const conditional_handler_t **ret ){
	*ret = handlers;
	return (sizeof handlers / sizeof( conditional_handler_t ));
}

