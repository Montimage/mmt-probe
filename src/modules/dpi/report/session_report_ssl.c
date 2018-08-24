/*
 * session_report_ssl.c
 *
 *  Created on: Dec 29, 2017
 *          by: Huu Nghia
 */

#include "session_report.h"
#include "../../../lib/string_builder.h"
#include "../../../lib/malloc_ext.h"

#ifndef SIMPLE_REPORT
struct session_ssl_stat_struct {
	char hostname[64];
};

/* This function is called by mmt-dpi for reporting ssl server_name, if an extraction handler is registered */
static void _ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	session_stat_t *session_stat = session_report_get_session_stat( ipacket );
	//no session: impossible for ssl packets
	if( session_stat == NULL )
		return;

	if( session_stat->app_type != SESSION_STAT_TYPE_APP_IP
			&& session_stat->app_type != SESSION_STAT_TYPE_APP_SSL )
		ABORT( "Impossible: stat_type must be %d, not %d",
				SESSION_STAT_TYPE_APP_IP, session_stat->app_type);

	if( session_stat->apps.ssl == NULL ){
		session_stat->apps.ssl = mmt_alloc(sizeof (session_ssl_stat_t));
		reset_string( session_stat->apps.ssl->hostname );
		session_stat->app_type = SESSION_STAT_TYPE_APP_SSL;
	}

	mmt_header_line_t *val = (mmt_header_line_t *) attribute->data;
	if( unlikely( val == NULL || val->len == 0 ))
		return;

	int target_size = sizeof( session_stat->apps.ssl->hostname );

	dpi_copy_string_value( session_stat->apps.ssl->hostname, target_size, val );

	session_stat->content_class = get_content_class_by_content_flags( get_session_content_flags(ipacket->session) );
}




//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_ssl_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
			{.proto_id = PROTO_SSL, .att_id = SSL_SERVER_NAME, .handler = _ssl_server_name_handle},
	};
	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}


/* This function is for reporting ssl session statistics*/
int print_ssl_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context){
	session_ssl_stat_t *ssl = session_stat->apps.ssl;

	//does not concern
	if( unlikely( ssl == NULL || session_stat->app_type != SESSION_STAT_TYPE_APP_SSL ))
		return 0;

    int  ret = 0;
    STRING_BUILDER( ret, message, message_size,
			__STR(ssl->hostname),
			__CHAR(','),
			__INT((get_session_content_flags(dpi_session) & MMT_CONTENT_CDN) ? 2 : 0));

    return ret;
}

#endif
