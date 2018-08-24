/*
 * session_report_ftp.c
 *
 *  Created on: May 4, 2018
 *          by: Huu Nghia Nguyen
 */
#include "session_report.h"
#include "../../../lib/tools.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

struct session_ftp_stat_struct {
	struct timeval first_response_seen_time;
	uint8_t session_conn_type;
	uint8_t direction;
	char * session_username;
	char * session_password;
	char * response_value;
	uint32_t file_size;
	uint8_t data_type;

	char * filename;
	uint16_t response_code;
	uint64_t session_id_control_channel;

#ifdef QOS_MODULE
	uint64_t response_time;
	uint8_t data_response_time_seen;

	struct timeval file_download_starttime;
	struct timeval file_download_finishtime;
#endif
};


/* This function resets FTP session attributes */
static void _reset_ftp( session_ftp_stat_t *ftp) {
#ifdef QOS_MODULE
	ftp->file_download_starttime.tv_sec = 0;
	ftp->file_download_starttime.tv_usec = 0;
	ftp->file_download_finishtime.tv_sec = 0;
	ftp->file_download_finishtime.tv_usec = 0;
#endif
	if (ftp->filename != NULL)
		free(ftp->filename);
	ftp->filename = NULL;
}

static inline void _override_string( char **target, const char *source ){
	if( source == NULL )
		return;

	if( *target != NULL )
		mmt_probe_free( *target );
	*target = mmt_strdup( source );
}

static inline session_stat_t* _get_packet_session(const ipacket_t * ipacket) {

	if( ipacket->session == NULL )
		return NULL;

	session_stat_t *session = session_report_get_session_stat(ipacket);

	if( session == NULL )
		return NULL;

	if( session->app_type != SESSION_STAT_TYPE_APP_IP
			&& session->app_type != SESSION_STAT_TYPE_APP_FTP )
		ABORT( "Impossible: stat_type must be %d, not %d",
				SESSION_STAT_TYPE_APP_IP, session->app_type);

	if( session->apps.ftp == NULL ){
		session->apps.ftp = mmt_alloc( sizeof (session_ftp_stat_t));
		_reset_ftp( session->apps.ftp );
	}
	session->app_type = SESSION_STAT_TYPE_APP_FTP;
	return session;
}


/**
 * Handle a FTP attribute
 * - Report Response time for Data session
 * - Update FTP app data
 * @param ipacket   packet
 * @param attribute attribute
 * @param user_args user arguments
 */
static void _ftp_session_connection_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	uint8_t * conn_type = (uint8_t *) attribute->data;

	if (conn_type == NULL || (*conn_type != 2 && *conn_type != 1)) {
		DEBUG("[FTP_REPORT: %lu] Not FTP packet", ipacket->packet_id);
		return;
	}

	session_stat_t *session = _get_packet_session(ipacket);

	if (session == NULL)
		return;

	// Reconstruction
	// if (probe_context->ftp_reconstruct_enable == 1)reconstruct_ftp_data(ipacket);

	// Report
	session_ftp_stat_t * ftp = session->apps.ftp;

	ftp->session_conn_type = *conn_type;

	if (ftp->session_conn_type == 2) {
		uint64_t * control_session_id = (uint64_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_CONT_IP_SESSION_ID);
		if (control_session_id != NULL)ftp->session_id_control_channel = * control_session_id;
#ifdef QOS_MODULE
		// Report response time
		if (ftp->data_response_time_seen == 0) {
			//need to identify the control session for corresponding data session
			ftp->first_response_seen_time = ipacket->p_hdr->ts; //Needed for data transfer time
			uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_DATA_TYPE);
			if (data_type != NULL) {
				ftp->data_type = * data_type;
				if (ftp->data_type == 1) {
					// response time defined here
					// * http://www.igi-global.com/chapter/future-networked-healthcare-systems/131381
					// * FTP Response Time: It is the time elapsed between a client application sending a request to the FTP server and receiving the response packet.
					// * The response time includes the 3 way TCP handshake.
					// *
					struct timeval ts = get_session_init_time(ipacket->session);
					ftp->response_time = u_second_diff( &ts, &ipacket->p_hdr->ts);
					ftp->data_response_time_seen = 1;
					DEBUG("[FTP_REPORT: %lu] ftp_response_time = %lu\n", ipacket->packet_id, ftp->response_time);
				}
			}
		}
#endif
	}

	uint8_t * direction = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_DATA_DIRECTION);
	if (direction != NULL) {
		ftp->direction = *direction;
	}

	_override_string( &ftp->session_username, (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_USERNAME) );

	_override_string( &ftp->session_password, (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PASSWORD));

	uint32_t *file_size = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_SIZE);
	if (file_size != NULL )
		ftp->file_size = * file_size;


	_override_string( &ftp->filename, (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_NAME));

	uint16_t *response_code = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PACKET_RESPONSE_CODE);
	if( response_code != NULL ) {
		ftp->response_code = *response_code;

#ifdef QOS_MODULE
		if (ftp->response_code == 150)
			ftp->file_download_starttime  = ipacket->p_hdr->ts;
#endif
	}
}
/* This function is called, whenever packet contains FTP response value.
 * It reports FTP file transfer information, if FTP reconstruction is enabled.
 *  */
static void _ftp_response_value_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	char *response_value = (char *) attribute->data;
	session_stat_t *session = _get_packet_session(ipacket);

	if (session == NULL)
		return;

	session_ftp_stat_t * ftp = session->apps.ftp;

	if (ftp->response_value != NULL) {
		if (strcmp(ftp->response_value, response_value) != 0 ) {
			free (ftp->response_value);
			ftp->response_value = NULL;
			ftp->response_value = response_value;
		} else {
			free (response_value);
		}
	} else {
		ftp->response_value = response_value;
	}
}


//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_ftp_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
		{.proto_id = PROTO_FTP, .att_id = FTP_DATA_DIRECTION,          .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = PROTO_PAYLOAD,               .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_TYPE,             .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_DATA_LEN,         .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_DATA_TYPE,               .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_FILE_NAME,               .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_REQUEST,          .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_REQUEST_PARAMETER,.handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_RESPONSE_CODE,    .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_RESPONSE_VALUE,   .handler = _ftp_response_value_handle },
		{.proto_id = PROTO_FTP, .att_id = FTP_DATA_TRANSFER_TYPE,      .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_DATA_MODE,               .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_FILE_LAST_MODIFIED,      .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_SESSION_CONN_TYPE,       .handler = _ftp_session_connection_type_handle },
		{.proto_id = PROTO_FTP, .att_id = FTP_USERNAME,                .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_PASSWORD,                .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_LAST_COMMAND,            .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_LAST_RESPONSE_CODE,      .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_FILE_SIZE,               .handler = NULL },
		{.proto_id = PROTO_FTP, .att_id = FTP_CONT_IP_SESSION_ID,      .handler = NULL },
	};

	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}


/**
 * This function is called periodically each x seconds depending on stat-period
 * @param message
 * @param message_size
 * @param dpi_session
 * @param session_stat
 * @param context
 * @return
 */
int print_ftp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context){
	session_ftp_stat_t *ftp = session_stat->apps.ftp;

	//does not concern
	if( unlikely( ftp == NULL || session_stat->app_type != SESSION_STAT_TYPE_APP_FTP ))
		return 0;

	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, message_size, ",",
			__INT( ftp->session_conn_type ),
			__STR( (ftp->session_username == NULL) ? "null" : ftp->session_username ),
			__STR( (ftp->session_password == NULL) ? "null" : ftp->session_password ),
			__INT( ftp->file_size ),
			__STR( (ftp->filename == NULL) ? "null" : ftp->filename ),
			__INT( ftp->direction ),
			__INT( ftp->session_id_control_channel ),
#ifdef QOS_MODULE
			__INT( ftp->response_time )
#else
			__CHAR( '0' )
#endif
	);
    return valid;
}
