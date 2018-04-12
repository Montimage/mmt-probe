/*
 * session_report_web.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */
#include "header.h"

#ifndef SIMPLE_REPORT
struct session_web_stat_struct {
	struct timeval first_request_time;

	struct timeval method_time;
	struct timeval interaction_time;
	struct timeval response_time;

	char mime_type[64];
	char hostname[96];
	char referer[64];
	char user_agent[64];
	char method[20];

	bool xcdn_seen;
	uint8_t trans_nb;
	uint8_t state_http_request_response;

	char uri[1024];
	char response[1024];
	char content_len[20];

};


/* This function resets http stats */
static inline void _reset_report(session_web_stat_t *web){

	 web->mime_type[0]   = '\0';
	 web->hostname[0]    = '\0';
	 web->referer[0]     = '\0';
	 web->user_agent[0]  = '\0';
	 web->method[0]      = '\0';
	 web->uri[0]         = '\0';
	 web->response[0]    = '\0';
	 web->content_len[0] = '\0';

	 web->response_time.tv_sec = 0;
	 web->response_time.tv_usec = 0;
	 web->method_time.tv_sec = 0;
	 web->method_time.tv_usec = 0;

	 web->xcdn_seen = false;
     web->state_http_request_response = 0;
}

static inline packet_session_t* _get_packet_session(const ipacket_t * ipacket) {

	if( ipacket->session == NULL )
		return NULL;

	packet_session_t *session =
			(packet_session_t *) get_user_session_context_from_packet(ipacket);

	if( session == NULL )
		return NULL;

	if( session->app_type != SESSION_STAT_TYPE_APP_IP
			&& session->app_type != SESSION_STAT_TYPE_APP_WEB )
		ABORT( "Impossible: stat_type must be %d, not %d",
				SESSION_STAT_TYPE_APP_IP, session->app_type);

	if( session->apps.web == NULL ){
		session->apps.web = mmt_alloc(sizeof (session_web_stat_t));
		_reset_report(session->apps.web);

		session->data_stat.is_touched = false;

//		DEBUG("Create a new Web report for session %"PRIu64", packet_id = %"PRIu64,
//				session->session_id, ipacket->packet_id );
	}
	session->app_type = SESSION_STAT_TYPE_APP_WEB;
	return session;
}


/* This function is called by mmt-dpi for reporting http method, if an extraction handler is registered
 * Initializes temp_session in the probe
 * Reporting between two http requests */
static void _web_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);

	if( unlikely( session == NULL ))
		return;

	session_web_stat_t *web = session->apps.web;

	if( ! session->data_stat.is_touched ){
		session->data_stat.is_touched = true;
		web->state_http_request_response++;//response is not finished
		//web->request_counter = 1;
		web->trans_nb = 1;
	}else{
		web->state_http_request_response = 0;// response is finished
		//session->report_counter = th->report_counter;
		//print_ip_session_report (ipacket->session, user_args);
		_reset_report( session->apps.web );
		//((web_session_attr_t *) temp_session->app_data)->request_counter++;
		web->trans_nb++;
	}

	dpi_copy_string_value(web->method, sizeof( web->method ), attribute->data );

	//((web_session_attr_t *) temp_session->app_data)->trans_nb += 1;
	if (web->trans_nb >= 1) {
		web->method_time = ipacket->p_hdr->ts;
	}

	if (web->trans_nb == 1){
		web->first_request_time = ipacket->p_hdr->ts;
	}

	//DEBUG("Web method: %s, session_id = %"PRIu64, web->method, session->session_id );
}

static void _web_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);

	if( unlikely( session == NULL ))
		return;

	session_web_stat_t *web = session->apps.web;

	if (web->trans_nb >= 1) //Needed for response_time calculation
		web->response_time = ipacket->p_hdr->ts;

	web->interaction_time = ipacket->p_hdr->ts;

	dpi_copy_string_value(web->response, sizeof( web->response ), attribute->data );
}

static void _web_referer_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->referer, sizeof( web->referer ), attribute->data );
}

static void _web_user_agent_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->user_agent, sizeof( web->user_agent ), attribute->data );
}

static void _web_uri_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->uri, sizeof( web->uri ), attribute->data );
}

static void _web_content_len_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->content_len, sizeof( web->content_len ), attribute->data );
}

static void _web_host_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;

	if( has_string( web->hostname ))
		return;

	dpi_copy_string_value(web->hostname, sizeof( web->hostname ), attribute->data );

	char *coma = strchr(web->hostname, ',');
	//Semi column found, replace it by an en of string '\0'
	if( coma )
		*coma = '\0';
}

static void _content_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	if( has_string( web->mime_type ))
		return;

	dpi_copy_string_value(web->mime_type, sizeof( web->mime_type ), attribute->data );

	char *coma = strchr(web->mime_type, ',');
	//Semi column found, replace it by an en of string '\0'
	if( coma )
		*coma = '\0';

	session->content_class = get_content_class_by_content_type( web->mime_type );
}

static void _web_xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = _get_packet_session(ipacket);
	session_web_stat_t *web = session->apps.web;

	uint8_t *xcdn_seen = (uint8_t *) attribute->data;

	if (xcdn_seen != NULL )
		web->xcdn_seen = true;
}

static const conditional_handler_t web_handlers[] = {
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_URI,          .handler = _web_uri_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_METHOD,       .handler = _web_method_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_RESPONSE,     .handler = _web_response_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_TYPE, .handler = _content_type_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_HOST,         .handler = _web_host_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_USER_AGENT,   .handler = _web_user_agent_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_REFERER,      .handler = _web_referer_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_XCDN_SEEN,    .handler = _web_xcdn_seen_handle},
	{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_LEN,  .handler = _web_content_len_handle},
};


//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_web_handlers_to_register( const conditional_handler_t **ret ){
	*ret = web_handlers;
	return (sizeof web_handlers / sizeof( conditional_handler_t ));
}


//This function is called by session_report._print_ip_session_report to append Web stat to the report message
int print_web_report(char *message, size_t message_size, packet_session_t *session, dpi_context_t *context){
	session_web_stat_t *web = session->apps.web;

	//does not concern
	if( unlikely( web == NULL || session->app_type != SESSION_STAT_TYPE_APP_WEB ))
		return 0;

	//0: CDN not detected (This does not mean it is not used :)).
	//1: 1 means CDN flags identified in the message.
	//   The referrer should identify the application. Will not be present in HTTPS flows.
	//2: CDN delivery, the application name should identify the application
	int cdn_flag = 0;
	if (web->xcdn_seen)
		cdn_flag = web->xcdn_seen;
	else if (get_session_content_flags(session->dpi_session) & MMT_CONTENT_CDN)
		cdn_flag = 2;

	int valid = snprintf(message, message_size,
			",%ld," //response time
			"%d,"   //transaction nb
			"%ld,"  //interaction time
			"\"%s\",\"%s\",\"%s\"," //host, mime, referrer
			"%d,"    //CDN flag
			"\"%s\",\"%s\",\"%s\"" //URI, method, response
			",\"%s\""   //content length
			",%d",    //request-response indicator
			has_string(web->response) ? u_second_diff( &web->response_time, &web->method_time ) : 0,
			has_string(web->response) ? web->trans_nb : 0,
			has_string(web->response) ? u_second_diff( &web->interaction_time, &web->first_request_time) : 0,

			web->hostname,
			web->mime_type,
			web->referer,

			cdn_flag,

			web->uri,
			web->method,
			web->response,
			web->content_len,

			web->state_http_request_response
	);

	if (web->state_http_request_response != 0)
		web->state_http_request_response ++;

	web->response_time.tv_sec = 0;
	web->response_time.tv_usec = 0;

	session->data_stat.is_touched = true;
	return valid;
}
#endif
