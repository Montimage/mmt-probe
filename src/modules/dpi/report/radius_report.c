/*
 *radius_report.c
 *
 * Created on: May 7, 2018
 *         by: Huu Nghia Nguyen
 */
#include <arpa/inet.h>
#include "../dpi_tool.h"
#include "../dpi.h"
#include <tcpip/mmt_tcpip.h>
#include "radius_report.h"
#include "../../../lib/limit.h"
#include "../../../lib/malloc_ext.h"

#define MMT_RADIUS_REPORT_ALL 0
struct radius_report_context_struct{
	output_t *output;
	const radius_report_conf_t *config;
};

struct mmt_location_info_struct {
	uint32_t field_len;
	uint32_t opaque;
	uint16_t cell_lac;
	uint16_t cell_id;
};

static void _radius_code_handle(const ipacket_t *ipacket, attribute_t *attribute, void *user_args) {
	if( ipacket->session == NULL )
		return;

	uint8_t *radius_code = ((uint8_t *) attribute->data);
	if( radius_code == NULL )
			return;

	radius_report_context_t *context = (radius_report_context_t *) user_args;
	char message[ MAX_LENGTH_REPORT_MESSAGE ];

	char f_ipv4[INET_ADDRSTRLEN];
	char sgsn_ip[INET_ADDRSTRLEN];
	char ggsn_ip[INET_ADDRSTRLEN];

	//If report ALL or The code is the one we need to report, then report :)
	if (( context->config->message_code != MMT_RADIUS_REPORT_ALL) && ( *radius_code != context->config->message_code))
		return;


	char *calling_station_id = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_CALLING_STATION_ID);
	uint32_t *framed_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_FRAMED_IP_ADDRESS);

	//Report if we have a reporting condition and the condition is met
	if ((calling_station_id == NULL) || (framed_ip_address == NULL))
		return;

	uint32_t *account_status_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_STATUS_TYPE);
	char *account_session_id = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_SESSION_ID);
	char *imsi = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMSI);
	char *imei = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMEISV);
	struct mmt_location_info_struct *user_loc = (struct mmt_location_info_struct *) get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_USER_LOCATION);
	char *charg_charact = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_CHARGIN_CHARACT);
	uint8_t *rat_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_RAT_TYPE);
	uint32_t *sgsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_ADDRESS);
	uint32_t *ggsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_ADDRESS);
	//ipv6_addr_t *sgsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_IPV6);
	//ipv6_addr_t *ggsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_IPV6);
	char *sgsn_mccmnc = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_MCCMNC);

	if (framed_ip_address) {
		inet_ntop(AF_INET, framed_ip_address, f_ipv4, INET_ADDRSTRLEN);
	}
	if (sgsn_ip_address) {
		inet_ntop(AF_INET, sgsn_ip_address, sgsn_ip, INET_ADDRSTRLEN);
	}
	if (ggsn_ip_address) {
		inet_ntop(AF_INET, ggsn_ip_address, ggsn_ip, INET_ADDRSTRLEN);
	}

	int offset = 0;
		//format id, timestamp, msg code, IP address, MSISDN, Acct_session_id, Acct_status_type, IMSI, IMEI, GGSN IP, SGSN IP, SGSN-MCC-MNC, RAT type, Charging class, LAC id, Cell id
//			"%i,\"%s\",\"%s\",%i,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%i,\"%s\",%i,%i",
	STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( *radius_code ),
			__STR( (framed_ip_address != NULL)   ? f_ipv4                 : "" ),
			__STR( (calling_station_id != NULL)  ? &calling_station_id[4] : "" ),
			__INT( (account_status_type != NULL) ? *account_status_type   : 0  ),
			__STR( (account_session_id != NULL)  ? &account_session_id[4] : "" ),
			__STR( (imsi != NULL)            ? &imsi[4]                   : "" ),
			__STR( (imei != NULL)            ? &imei[4]                   : "" ),
			__STR( (ggsn_ip_address != NULL) ? ggsn_ip                    : "" ),
			__STR( (sgsn_ip_address != NULL) ? sgsn_ip                    : "" ),
			__STR( (sgsn_mccmnc != NULL)     ? &sgsn_mccmnc[4]            : "" ),
			__INT( (rat_type != NULL)        ? *((uint8_t *) rat_type)    : 0 ),
			__STR( (charg_charact != NULL)   ? &charg_charact[4]          : "" ),
			__INT( (user_loc != NULL)        ? ntohs( user_loc->cell_lac) : 0  ),
			__INT( (user_loc != NULL)        ? ntohs( user_loc->cell_id)  : 0  )
	);

	output_write_report( context->output, context->config->output_channels,
				RADIUS_REPORT_TYPE, &ipacket->p_hdr->ts, message);
}

static const conditional_handler_t handlers[] = {
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_CODE,                 .handler = _radius_code_handle},
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_CALLING_STATION_ID,   .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_FRAMED_IP_ADDRESS,    .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_ACCT_STATUS_TYPE,     .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_ACCT_SESSION_ID,      .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_IMSI,            .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_IMEISV,          .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_USER_LOCATION,   .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_CHARGIN_CHARACT, .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_RAT_TYPE,        .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_SGSN_ADDRESS,    .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_GGSN_ADDRESS,    .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_SGSN_IPV6,       .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_GGSN_IPV6,       .handler = NULL },
	{.proto_id = PROTO_RADIUS, .att_id = RADIUS_3GPP_SGSN_MCCMNC,     .handler = NULL },
};

radius_report_context_t*radius_report_register( mmt_handler_t *dpi_handler, const radius_report_conf_t *config, output_t *output ){
	if( config->is_enable == false )
		return NULL;
	radius_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( radius_report_context_t ));
	ret->output = output;
	ret->config = config;
	dpi_register_conditional_handler(dpi_handler, sizeof( handlers ) / sizeof( handlers[0]), handlers, ret);

	return ret;
}

void radius_report_unregister(mmt_handler_t *dpi_handler, radius_report_context_t *context ){
	if( context == NULL )
		return;

	//unregister
	dpi_unregister_conditional_handler( dpi_handler, sizeof( handlers ) / sizeof( handlers[0]), handlers);

	mmt_probe_free( context );
}
