#include <stdio.h>
#include <string.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip_protocols.h"
#include "processing.h"

struct mmt_location_info_struct {
    uint32_t field_len;
    uint32_t opaque;
    uint16_t cell_lac;
    uint16_t cell_id;
};

void radius_code_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    //FILE * out_file = (user_args != NULL) ? (FILE *) user_args : stdout;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    if(ipacket->session == NULL) return;
    char message[MAX_MESS + 1];
    //FILE * out_file = (probe_context->radius_out_file != NULL) ? probe_context->radius_out_file : stdout;

    //Mark this flow as SKIP REPORTING one! Yeah we don't want to report RADIUS flows
    //Just report the RADIUS specific report
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL) {
        temp_session->format_id = MMT_RADIUS_REPORT_FORMAT;
        //temp_session->app_format_id = MMT_SKIP_APP_REPORT_FORMAT;
    }

    if (attribute->data) {
        char f_ipv4[INET_ADDRSTRLEN];
        char sgsn_ip[INET_ADDRSTRLEN];
        char ggsn_ip[INET_ADDRSTRLEN];
        uint8_t code = *((uint8_t *) attribute->data);

        //If report ALL or The code is the one we need to report, then report :)
        if ((probe_context->radius_starategy == MMT_RADIUS_REPORT_ALL) || (code == probe_context->radius_message_id)) {
            char * calling_station_id = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_CALLING_STATION_ID);
            uint32_t * framed_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_FRAMED_IP_ADDRESS);

            //Report if we have a reporting condition and the condition is met
            if (probe_context->radius_condition_id == MMT_RADIUS_IP_MSISDN_PRESENT) {
                if ((calling_station_id != NULL) && (framed_ip_address != NULL)) {
                    uint32_t * account_status_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_STATUS_TYPE);
                    char * account_session_id = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_SESSION_ID);
                    char * imsi = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMSI);
                    char * imei = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMEISV);
                    char * user_loc = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_USER_LOCATION);
                    char * charg_charact = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_CHARGIN_CHARACT);
                    uint8_t * rat_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_RAT_TYPE);
                    uint32_t * sgsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_ADDRESS);
                    uint32_t * ggsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_ADDRESS);
                    //ipv6_addr_t * sgsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_IPV6);
                    //ipv6_addr_t * ggsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_IPV6);
                    char * sgsn_mccmnc = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_MCCMNC);
                    if (framed_ip_address) {
                        inet_ntop(AF_INET, framed_ip_address, f_ipv4, INET_ADDRSTRLEN);
                    }
                    if (sgsn_ip_address) {
                        inet_ntop(AF_INET, sgsn_ip_address, sgsn_ip, INET_ADDRSTRLEN);
                    }
                    if (ggsn_ip_address) {
                        inet_ntop(AF_INET, ggsn_ip_address, ggsn_ip, INET_ADDRSTRLEN);
                    }

                    //format id, timestamp, msg code, IP address, MSISDN, Acct_session_id, Acct_status_type, IMSI, IMEI, GGSN IP, SGSN IP, SGSN-MCC-MNC, RAT type, Charging class, LAC id, Cell id
                    snprintf(message, MAX_MESS,
                            "%u,%u,\"%s\",%lu.%06lu,%i,\"%s\",\"%s\",%i,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%i,\"%s\",%i,%i",
                            MMT_RADIUS_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec,
                            (int) code, (framed_ip_address != NULL) ? f_ipv4 : "",
                                    (calling_station_id != NULL) ? &calling_station_id[4] : "",
                                            (account_status_type != NULL) ? *account_status_type : 0,
                                                    (account_session_id != NULL) ? &account_session_id[4] : "",
                                                            (imsi != NULL) ? &imsi[4] : "",
                                                                    (imei != NULL) ? &imei[4] : "",
                                                                            (ggsn_ip_address != NULL) ? ggsn_ip : "",
                                                                                    (sgsn_ip_address != NULL) ? sgsn_ip : "",
                                                                                            (sgsn_mccmnc != NULL) ? &sgsn_mccmnc[4] : "",
                                                                                                    (rat_type != NULL) ? (int) *((uint8_t *) rat_type) : 0,
                                                                                                            (charg_charact != NULL) ? &charg_charact[4] : "",
                                                                                                                    (user_loc != NULL) ? (int) ntohs(((struct mmt_location_info_struct *) user_loc)->cell_lac) : 0,
                                                                                                                            (user_loc != NULL) ? (int) ntohs(((struct mmt_location_info_struct *) user_loc)->cell_id) : 0
                    );
                    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
                    //send_message_to_file ("radius.report", message);
                    if (probe_context->output_to_file_enable && probe_context->radius_output_channel[0])send_message_to_file_thread (message,(void *)user_args);
                    if (probe_context->redis_enable && probe_context->radius_output_channel[1])send_message_to_redis ("radius.report", message);
                	if (probe_context->kafka_enable == 1 && probe_context->radius_output_channel[2] )send_msg_to_kafka(probe_context->topic_object->rkt_radius, message);
                }
            } else { //Report anyway
                uint32_t * account_status_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_STATUS_TYPE);
                char * account_session_id = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_ACCT_SESSION_ID);
                char * imsi = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMSI);
                char * imei = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_IMEISV);
                char * user_loc = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_USER_LOCATION);
                char * charg_charact = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_CHARGIN_CHARACT);
                uint8_t * rat_type = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_RAT_TYPE);
                uint32_t * sgsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_ADDRESS);
                uint32_t * ggsn_ip_address = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_ADDRESS);
                //ipv6_addr_t * sgsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_IPV6);
                //ipv6_addr_t * ggsn_ipv6 = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_GGSN_IPV6);
                char * sgsn_mccmnc = get_attribute_extracted_data(ipacket, PROTO_RADIUS, RADIUS_3GPP_SGSN_MCCMNC);
                if (framed_ip_address) {
                    inet_ntop(AF_INET, framed_ip_address, f_ipv4, INET_ADDRSTRLEN);
                }
                if (sgsn_ip_address) {
                    inet_ntop(AF_INET, sgsn_ip_address, sgsn_ip, INET_ADDRSTRLEN);
                }
                if (ggsn_ip_address) {
                    inet_ntop(AF_INET, ggsn_ip_address, ggsn_ip, INET_ADDRSTRLEN);
                }

                //format id, timestamp, msg code, IP address, MSISDN, Acct_session_id, Acct_status_type, IMSI, IMEI, GGSN IP, SGSN IP, SGSN-MCC-MNC, RAT type, Charging class, LAC id, Cell id
                snprintf(message, MAX_MESS,
                        "%u,%u,\"%s\",%lu.%06lu,%i,\"%s\",\"%s\",%i,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%i,\"%s\",%i,%i",
                        MMT_RADIUS_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec,
                        (int) code, (framed_ip_address != NULL) ? f_ipv4 : "",
                                (calling_station_id != NULL) ? &calling_station_id[4] : "",
                                        (account_status_type != NULL) ? *account_status_type : 0,
                                                (account_session_id != NULL) ? &account_session_id[4] : "",
                                                        (imsi != NULL) ? &imsi[4] : "",
                                                                (imei != NULL) ? &imei[4] : "",
                                                                        (ggsn_ip_address != NULL) ? ggsn_ip : "",
                                                                                (sgsn_ip_address != NULL) ? sgsn_ip : "",
                                                                                        (sgsn_mccmnc != NULL) ? &sgsn_mccmnc[4] : "",
                                                                                                (rat_type != NULL) ? (int) *((uint8_t *) rat_type) : 0,
                                                                                                        (charg_charact != NULL) ? &charg_charact[4] : "",
                                                                                                                (user_loc != NULL) ? (int) ntohs(((struct mmt_location_info_struct *) user_loc)->cell_lac) : 0,
                                                                                                                        (user_loc != NULL) ? (int) ntohs(((struct mmt_location_info_struct *) user_loc)->cell_id) : 0
                );

                message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
                //send_message_to_file ("radius.report", message);
                if (probe_context->output_to_file_enable && probe_context->radius_output_channel[0])send_message_to_file_thread (message,(void *)user_args);
                if (probe_context->redis_enable && probe_context->radius_output_channel[1])send_message_to_redis ("radius.report", message);
            	if (probe_context->kafka_enable == 1 && probe_context->radius_output_channel[2] )send_msg_to_kafka(probe_context->topic_object->rkt_radius, message);

            }
        }
    }
}

void radius_ext_init(void * args) {
	struct smp_thread *th = (struct smp_thread *) args;
    register_attribute_handler(th->mmt_handler, PROTO_RADIUS, RADIUS_CODE, radius_code_handle, NULL, (void *)th);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_CALLING_STATION_ID);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_FRAMED_IP_ADDRESS);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_ACCT_STATUS_TYPE);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_ACCT_SESSION_ID);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_IMSI);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_IMEISV);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_USER_LOCATION);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_CHARGIN_CHARACT);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_RAT_TYPE);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_SGSN_ADDRESS);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_GGSN_ADDRESS);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_SGSN_IPV6);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_GGSN_IPV6);
    register_extraction_attribute(th->mmt_handler, PROTO_RADIUS, RADIUS_3GPP_SGSN_MCCMNC);
}

void radius_ext_cleanup(void * handler) {
}
