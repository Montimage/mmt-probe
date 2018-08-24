/*
 * session_report_rtp.c
 *
 *  Created on: May 04, 2018
 *          by: Huu Nghia
 */

#include "session_report.h"
#include "../../../lib/malloc_ext.h"

struct session_rtp_stat_struct {
	/* The reason we need this is that RTP flows may contain STUN messages. We follow here RTP packets only */
	uint32_t packets_nb;
	uint32_t jitter;
	uint32_t nb_order_error;
	uint32_t nb_lost;
	uint32_t nb_loss_bursts;
};


static inline void _reset_rtp (session_rtp_stat_t *rtp){
    rtp->jitter = 0;
    rtp->nb_lost = 0;
    rtp->nb_loss_bursts = 0;
    rtp->nb_order_error = 0;
    rtp->packets_nb = 0;
}


static inline session_stat_t* _get_packet_session(const ipacket_t * ipacket) {

	if( ipacket->session == NULL )
		return NULL;

	session_stat_t *session = session_report_get_session_stat(ipacket);

	if( session == NULL )
		return NULL;

	if( session->app_type != SESSION_STAT_TYPE_APP_IP
			&& session->app_type != SESSION_STAT_TYPE_APP_RTP )
		ABORT( "Impossible: stat_type must be %d, not %d",
				SESSION_STAT_TYPE_APP_IP, session->app_type);

	if( session->apps.rtp == NULL ){
		session->apps.rtp = mmt_alloc( sizeof (session_rtp_stat_t));
		_reset_rtp( session->apps.rtp );
	}
	session->app_type = SESSION_STAT_TYPE_APP_RTP;
	return session;
}


void _rtp_version_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;

	session->apps.rtp->packets_nb ++;
}

void _rtp_jitter_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;

	uint32_t * jitter = (uint32_t *) attribute->data;
	if (jitter != NULL && *jitter > session->apps.rtp->jitter)
		session->apps.rtp->jitter = *jitter;
}

void _rtp_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;

	uint16_t * loss = (uint16_t *) attribute->data;
	if (loss != NULL )
		session->apps.rtp->nb_lost += *loss;
}

void _rtp_error_order_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;

	uint16_t * order_error = (uint16_t *) attribute->data;
	if (order_error != NULL )
		session->apps.rtp->nb_order_error += *order_error;
}

void _rtp_burst_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	session_stat_t *session = _get_packet_session(ipacket);
	if( unlikely( session == NULL ))
		return;

	uint16_t * burst_loss = (uint16_t *) attribute->data;
	if (burst_loss != NULL )
		session->apps.rtp->nb_loss_bursts ++;
}


//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_rtp_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
		{.proto_id = PROTO_RTP, .att_id = RTP_VERSION,     .handler = _rtp_version_handle},
		{.proto_id = PROTO_RTP, .att_id = RTP_JITTER,      .handler = _rtp_jitter_handle},
		{.proto_id = PROTO_RTP, .att_id = RTP_BURST_LOSS,  .handler = _rtp_burst_loss_handle},
		{.proto_id = PROTO_RTP, .att_id = RTP_ERROR_ORDER, .handler = _rtp_error_order_handle},
		{.proto_id = PROTO_RTP, .att_id = RTP_LOSS,        .handler = _rtp_loss_handle},
	};

	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}


int print_rtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context){
	session_rtp_stat_t *rtp = session_stat->apps.rtp;

	//does not concern
	if( unlikely( rtp == NULL || session_stat->app_type != SESSION_STAT_TYPE_APP_RTP ))
		return 0;

    double loss_rate, loss_burstiness = 0, order_error = 0;

    loss_rate =  ((double) rtp->nb_lost / (rtp->nb_lost + rtp->packets_nb + 1));

    if (rtp->nb_loss_bursts) {
        loss_burstiness = ((double) rtp->nb_lost / rtp->nb_loss_bursts);
    }

    order_error = ((double) rtp->nb_order_error / (rtp->packets_nb + 1));

    size_t ret = snprintf( message, message_size,
            "%.3f,%.3f,%u,%.3f",
            loss_rate,
            loss_burstiness,
            rtp->jitter,
			order_error
    );
    _reset_rtp( rtp );
    return ret;
}
