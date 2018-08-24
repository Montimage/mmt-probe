/*
 * session_report_web.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 *
 * This file does the parts of HTTP report in the session reports.
 */
#include <limits.h>
#include "session_report.h"
#include "../../../lib/string_builder.h"
#include "../../../lib/malloc_ext.h"

#ifndef SIMPLE_REPORT
struct session_web_stat_struct {

#ifdef QOS_MODULE
	struct timeval first_request_time; //moment we see the first HTTP request in a TCP flow (that may contain many HTTP req-response)
	struct timeval request_time;       //moment we see a method request
	struct timeval response_time;      //moment we see a response
#endif

	bool xcdn_seen;
	/**
	 * Index of the current HTTP transaction in a TCP session
	 * (as in a TCP session, there may exist many different HTTP request-response)
	 */
	uint8_t request_nb;
	/**
	 * It indicates that a particular transaction is finished (with a response)
	 *    (0: complete, otherwise: >= 1): 1=first block, 2=second block, ..., 0: the last block.
	 * This is useful when a long HTTP transition passing through several report periodic.
	 * For example, in the first 5 seconds, we see only the request, next 5 seconds,
	 * we see nothing concerning this HTTP transaction, then we see its response
	 */
	uint8_t transaction_indicator;

	char mime_type[127]; //max length: 127 characters https://tools.ietf.org/html/rfc4288#section-4.2
	char hostname [HOST_NAME_MAX]; //defined in limits.h
	char referer  [255];
	char method[10];
	char uri[1024];
	char response[20];
	char content_len[20];
};


/* This function resets http stats */
static inline void _reset_report(session_web_stat_t *web){
	reset_string( web->mime_type );
	reset_string( web->hostname );
	reset_string( web->referer );
	reset_string( web->method );
	reset_string( web->uri );
	reset_string( web->response );
	reset_string( web->content_len );

#ifdef QOS_MODULE
	reset_timeval( web->response_time );
	reset_timeval( web->request_time );
	reset_timeval( web->first_request_time );
#endif

	web->xcdn_seen = false;
	web->request_nb = 0;
	web->transaction_indicator = 0;
}

static inline session_stat_t* _get_packet_session(const ipacket_t * ipacket) {

	if( ipacket->session == NULL )
		return NULL;

	session_stat_t *session = session_report_get_session_stat(ipacket);

	//must be on top of a TCP session
	if( session == NULL )
		return NULL;

	if( session->app_type != SESSION_STAT_TYPE_APP_IP
			&& session->app_type != SESSION_STAT_TYPE_APP_WEB )
		MY_MISTAKE( "Impossible: stat_type must be %d, not %d",
				SESSION_STAT_TYPE_APP_IP, session->app_type);

	//create web report and attach it to session
	if( session->apps.web == NULL ){
		session->apps.web = mmt_alloc(sizeof (session_web_stat_t));
		_reset_report(session->apps.web);
	}
	session->app_type = SESSION_STAT_TYPE_APP_WEB;
	return session;
}


/**
 * This callback is called by DPI when it sees a HTTP method
 */
static void _web_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session    = _get_packet_session(ipacket);
	dpi_context_t *dpi_context = (dpi_context_t*) user_args;

	if( unlikely( session == NULL ))
		return;

	session_web_stat_t *web = session->apps.web;

	//we see a new hostname request while already having another one in a TCP session
	//=> report the old HTTP request-response
	if( has_string( web->hostname ) ){
		//here, we generate a report for this HTTP req-response
		session_report_do_report(ipacket->session, session, dpi_context);
		_reset_report( session->apps.web );
	}

	//increase number of HTTP transactions in a TCP session
	web->request_nb++;

	//first part of an HTTP transaction
	web->transaction_indicator = 1;

	dpi_copy_string_value(web->method, sizeof( web->method ), attribute->data );

#ifdef QOS_MODULE
	web->request_time = ipacket->p_hdr->ts;

	if (web->request_nb == 1)
		web->first_request_time = ipacket->p_hdr->ts;
#endif
}

/**
 * This callback will be called by DPI when seeing HTTP responses
 */
static void _web_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);

	if( unlikely( session == NULL ))
		return;

	session_web_stat_t *web = session->apps.web;

#ifdef QOS_MODULE
	//Remember the moment we got the response
	web->response_time = ipacket->p_hdr->ts;
#endif

	//indicate that the HTTP transaction is complete
	web->transaction_indicator = 0;

	dpi_copy_string_value(web->response, sizeof( web->response ), attribute->data );
}

/**
 * This callback will be called by DPI when seeing HTTP referers
 */
static void _web_referer_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->referer, sizeof( web->referer ), attribute->data );
}

/**
 * This callback is called when DPI sees an HTTP URI
 */
static void _web_uri_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->uri, sizeof( web->uri ), attribute->data );
}

/**
 * This callback is called when DPI sees an HTTP Content-Length
 */
static void _web_content_len_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	dpi_copy_string_value(web->content_len, sizeof( web->content_len ), attribute->data );
}

/**
 * This callback is called when DPI sees an HTTP host
 */
static void _web_host_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;

	//should not have two different hostname in a same TCP flows, but check anyway
	if( unlikely( has_string( web->hostname )))
		return;

	dpi_copy_string_value(web->hostname, sizeof( web->hostname ), attribute->data );
}

/**
 * This callback is called when DPI sees an HTTP Content-Type
 */
static void _content_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;
	if( has_string( web->mime_type ))
		return;

	dpi_copy_string_value(web->mime_type, sizeof( web->mime_type ), attribute->data );

	//session->content_class = get_content_class_by_content_type( web->mime_type );
}

/**
 * This callback is called when DPI sees an HTTP X-CDN
 */
static void _web_xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;
	session_web_stat_t *web = session->apps.web;

	uint8_t *xcdn_seen = (uint8_t *) attribute->data;

	web->xcdn_seen =  (xcdn_seen != NULL );
}

//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_web_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t web_handlers[] = {
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_URI,          .handler = _web_uri_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_METHOD,       .handler = _web_method_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_RESPONSE,     .handler = _web_response_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_TYPE, .handler = _content_type_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_HOST,         .handler = _web_host_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_REFERER,      .handler = _web_referer_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_XCDN_SEEN,    .handler = _web_xcdn_seen_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_LEN,  .handler = _web_content_len_handle},
	};

	*ret = web_handlers;
	return (sizeof web_handlers / sizeof( conditional_handler_t ));
}


#define _has_response( w ) (w->response_time.tv_sec != 0)
#define _has_request(  w ) (w->request_time.tv_sec  != 0)

//This function is called by session_report._print_ip_session_report to append Web stat to the report message
int print_web_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context){
	session_web_stat_t *web = session_stat->apps.web;

	//does not concern
	if( unlikely( web == NULL || session_stat->app_type != SESSION_STAT_TYPE_APP_WEB ))
		return 0;

	//0: CDN not detected (This does not mean it is not used :)).
	//1: 1 means CDN flags identified in the message.
	//   The referrer should identify the application. Will not be present in HTTPS flows.
	//2: CDN delivery, the application name should identify the application
	int cdn_flag = 0;
	if (web->xcdn_seen)
		cdn_flag = web->xcdn_seen;
	else if (get_session_content_flags( dpi_session ) & MMT_CONTENT_CDN)
		cdn_flag = 2;

#ifdef QOS_MODULE
		long interaction_time = (_has_response(web) && _has_request(web) ) ? u_second_diff( &web->response_time, &web->first_request_time) : 0;
		//received response before request (see HTTP session starting from packet 11760 of smallFlows.pcap)
		if( interaction_time < 0 )
			interaction_time = 0;
		long response_time = (_has_response(web) && _has_request(web) ) ? u_second_diff( &web->response_time, &web->request_time ) : 0;
		if( response_time < 0 )
			response_time = 0;
#endif

	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, message_size, ",",
#ifdef QOS_MODULE
			//response time: time from method request --> response
			__INT( response_time ),
			//nb of transaction
			__INT( web->request_nb ),
			//interaction time:
			__INT( interaction_time ),
#else
			__ARR( "0,0,0" ), //string without closing by quotes
#endif
			__STR( web->hostname ),
			__STR( web->mime_type ),
			__STR( web->referer ),
			__INT( cdn_flag ),
			__STR( web->uri ),
			__STR( web->method ),
			__STR( web->response ),
			__STR( web->content_len ),
			__INT( web->transaction_indicator )
	);

#ifdef QOS_MODULE
	reset_timeval( web->response_time );
#endif

	//increase
	web->transaction_indicator ++;

	return valid;
}
#endif
