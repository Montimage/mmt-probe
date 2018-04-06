#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

/* This function writes FTP data to a file */
void write_data_to_file (char * path,  char * content, int len) {
	int fd = 0;
	if ( (fd = open ( path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
	{
		fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , path , strerror( errno ) );
		return;
	}

	if (len > 0) {
		debug("[FTP_RECONSTRUCT] Going to write to file: %s\n", path);
		int buf_len = write ( fd , content , len );
		debug("[FTP_RECONSTRUCT] %d bytes have been written\n", buf_len);
	}
	close ( fd );
}
/* This function resets FTP session attributes */
void reset_ftp_parameters(const ipacket_t * ipacket, session_struct_t *temp_session ) {
	((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_sec = 0;
	((ftp_session_attr_t*) temp_session->app_data)->file_download_starttime_usec = 0;
	((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_sec = 0;
	((ftp_session_attr_t*) temp_session->app_data)->file_download_finishtime_usec = 0;
	if (((ftp_session_attr_t*) temp_session->app_data)->filename != NULL)free(((ftp_session_attr_t*) temp_session->app_data)->filename);
	((ftp_session_attr_t*) temp_session->app_data)->filename = NULL;
}
/**
 * Handle a FTP attribute
 * - Report Response time for Data session
 * - Update FTP app data
 * @param ipacket   packet
 * @param attribute attribute
 * @param user_args user arguments
 */
void ftp_session_connection_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	uint8_t * conn_type = (uint8_t *) attribute->data;

	if (conn_type == NULL || (*conn_type != 2 && *conn_type != 1)) {
		debug("[FTP_REPORT: %lu] Not FTP packet", ipacket->packet_id);
		return;
	}

	mmt_probe_context_t * probe_context = get_probe_context_config();

	if (probe_context == NULL) {
		debug("[FTP_REPORT: %lu] Cannot get probe context", ipacket->packet_id);
		return;
	}

	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL) {
		debug("[FTP_REPORT: %lu] Cannot get temp_session", ipacket->packet_id);
		return;
	}

	// Reconstruction
	// if (probe_context->ftp_reconstruct_enable == 1)reconstruct_ftp_data(ipacket);

	// Report
	ftp_session_attr_t * ftp_data;
	ftp_data = NULL;

	if (temp_session->app_data == NULL) {
		ftp_data = (ftp_session_attr_t *) malloc(sizeof (ftp_session_attr_t));
		if (ftp_data != NULL) {
			memset(ftp_data, '\0', sizeof (ftp_session_attr_t));
			temp_session->app_format_id = MMT_FTP_REPORT_FORMAT;
			temp_session->app_data = (void *) ftp_data;
		} else {
			fprintf(stderr, "[FTP_REPORT: %lu] Out of memory error when creating FTP data report!\n", ipacket->packet_id);
			return;
		}
	} else {
		if (temp_session->app_format_id != MMT_FTP_REPORT_FORMAT) {
			debug("[FTP_REPORT: %lu] Not FTP report\n", ipacket->packet_id);
			return;
		}
		ftp_data = (ftp_session_attr_t*)temp_session->app_data;
	}
	ftp_data->session_conn_type = *conn_type;
	if (ftp_data->session_conn_type == 2) {
		uint64_t * control_session_id = (uint64_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_CONT_IP_SESSION_ID);
		if (control_session_id != NULL)ftp_data->session_id_control_channel = * control_session_id;
		// Report response time
		if (ftp_data->data_response_time_seen == 0) {
			//need to identify the control session for corresponding data session
			ftp_data->first_response_seen_time = ipacket->p_hdr->ts; //Needed for data transfer time
			uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_DATA_TYPE);
			if (data_type != NULL) {
				ftp_data->data_type = * data_type;
				if (ftp_data->data_type == 1) {
					// response time defined here
					// * http://www.igi-global.com/chapter/future-networked-healthcare-systems/131381
					// * FTP Response Time: It is the time elapsed between a client application sending a request to the FTP server and receiving the response packet.
					// * The response time includes the 3 way TCP handshake.
					// *
					ftp_data->response_time = TIMEVAL_2_USEC(mmt_time_diff(get_session_init_time(ipacket->session), ipacket->p_hdr->ts));
					ftp_data->data_response_time_seen = 1;
					debug("[FTP_REPORT: %lu] ftp_response_time = %lu\n", ipacket->packet_id, ftp_data->response_time);
				}
			}

		}

		// Reconstruct file
		// if (probe_context->ftp_reconstruct_enable == 1)reconstruct_ftp_data(ipacket);
		// Get data type - only reconstruct the FILE data
		if (probe_context->ftp_reconstruct_enable == 1){
			uint8_t * data_type = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_DATA_TYPE);
			if(data_type && * data_type == 1){
				// Get file name
				char * file_name = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_NAME);
				// Get packet len
				uint32_t * data_len = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PACKET_DATA_LEN);
				if(data_len && * data_len > 0){
					// Get packet payload pointer - after TCP
					char * data_payload = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, PROTO_PAYLOAD);
					if (file_name && data_payload) {
						char filename[MAX_FILE_NAME];
						char *file_path;
						file_path = str_replace(file_name, "/", "_");
						snprintf(filename, MAX_FILE_NAME, "%s%"PRIu64"_%s", probe_context->ftp_reconstruct_output_location, get_session_id(ipacket->session), file_path);
						filename[MAX_FILE_NAME-1] = '\0';
						debug("[FTP_RECONSTRUCT] Going to write data of packet %lu into file: %s\n", ipacket->packet_id,filename);
						write_data_to_file(filename, data_payload, *data_len);
						free(file_path);
					}
				}
			}
		}
	}

	uint8_t * direction = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_DATA_DIRECTION);
	if (direction != NULL) {
		ftp_data->direction = *direction;
	}

	char * username = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_USERNAME);
	if (username != NULL) {
		if (ftp_data->session_username != NULL) {
			if (strcmp(ftp_data->session_username , username) != 0 ) {
				free (ftp_data->session_username );
				ftp_data->session_username  = NULL;
				ftp_data->session_username = str_copy(username);
			}
		} else {
			ftp_data->session_username = str_copy(username);
		}
	}

	char * password = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PASSWORD);
	if (password != NULL) {
		if (ftp_data->session_password != NULL) {
			if (strcmp(ftp_data->session_password , password) != 0 ) {
				free (ftp_data->session_password );
				ftp_data->session_password  = NULL;
				ftp_data->session_password = str_copy(password);
			}
		} else {
			ftp_data->session_password = str_copy(password);
		}
	}

	uint32_t * file_size = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_SIZE);
	if (file_size != NULL ) {
		ftp_data->file_size = * file_size;
	}
	char * file_name = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_NAME);
	if (file_name != NULL) {
		if (ftp_data->filename != NULL) {
			if (strcmp(ftp_data->filename, file_name) != 0 ) {
				free (ftp_data->filename);
				ftp_data->filename = NULL;
				ftp_data->filename = str_copy(file_name);
			}
		} else {
			ftp_data->filename = str_copy(file_name);
		}
	}
	uint16_t * response_code = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PACKET_RESPONSE_CODE);
	if (response_code != NULL) {
		ftp_data->response_code = * response_code;
		if (ftp_data->response_code == 150) {
			ftp_data->file_download_starttime_sec = ipacket->p_hdr->ts.tv_sec;
			ftp_data->file_download_starttime_usec = ipacket->p_hdr->ts.tv_usec;
		}
	}
}
/* This function is called, whenever packet contains FTP response value.
 * It reports FTP file transfer information, if FTP reconstruction is enabled.
 *  */
void ftp_response_value_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	char * response_value = (char *) attribute->data;
	if (response_value == NULL) {
		debug("[FTP_REPORT: %lu] Packet does not have response_value\n", ipacket->packet_id);
		return;
	}
	if (ipacket->session == NULL) {
		debug("[FTP_REPORT: %lu] Cannot find IP session\n", ipacket->packet_id);
		free (response_value);
		return;
	}

	mmt_probe_context_t * probe_context = get_probe_context_config();

	if (probe_context == NULL) {
		debug("[FTP_REPORT: %lu] Cannot get probe context\n", ipacket->packet_id);
		free (response_value);
		return;
	}
	session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);

	if (temp_session == NULL) {
		debug("[FTP_REPORT: %lu] Cannot get temp_session\n", ipacket->packet_id);
		free (response_value);
		return;
	}

	if (temp_session->app_data == NULL) {
		debug("[FTP_REPORT: %lu] Cannot get temp_session->app_data\n", ipacket->packet_id);
		free (response_value);
		return;
	}

	if (temp_session->app_format_id != MMT_FTP_REPORT_FORMAT) {
		debug("[FTP_REPORT: %lu] Not FTP report\n", ipacket->packet_id);
		free (response_value);
		return;
	}

	ftp_session_attr_t * ftp_data;
	ftp_data = (ftp_session_attr_t*)temp_session->app_data;
	if (ftp_data->response_value != NULL) {
		if (strcmp(ftp_data->response_value, response_value) != 0 ) {
			free (ftp_data->response_value);
			ftp_data->response_value = NULL;
			ftp_data->response_value = response_value;
		} else {
			free (response_value);
		}
	} else {
		ftp_data->response_value = response_value;
	}

	char message[MAX_MESS + 1];
	int i;
	char ip_src_str[46];
	char ip_dst_str[46];

	struct timeval end_time = get_session_last_activity_time(ipacket->session);

	if (temp_session->ipversion == 4) {
		inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
	}
	for (i = 0; i < probe_context->condition_reports_nb; i++) {
		mmt_condition_report_t * condition_report = &probe_context->condition_reports[i];
		if (strcmp(ftp_data->response_value, "Transfer complete.") == 0 && strcmp(condition_report->condition.condition, "FTP") == 0 && probe_context->ftp_reconstruct_enable == 1) {
			ftp_data->file_download_finishtime_sec = ipacket->p_hdr->ts.tv_sec;
			ftp_data->file_download_finishtime_usec = ipacket->p_hdr->ts.tv_usec;
			snprintf(message, MAX_MESS,
			         "%u,%u,\"%s\",%lu.%06lu,%"PRIu64",%"PRIu32",\"%s\",\"%s\",%hu,%hu,%"PRIu8",%"PRIu8",\"%s\",\"%s\",%"PRIu32",\"%s\",%lu.%06lu,%lu.%06lu,%"PRIu64",%u",
					 MMT_FTP_RECONSTRUCTION_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, end_time.tv_sec, end_time.tv_usec, temp_session->session_id, temp_session->thread_number,
			         ip_dst_str, ip_src_str,
			         temp_session->serverport, temp_session->clientport,
			         ftp_data->session_conn_type,
			         ftp_data->direction,
			         (ftp_data->session_username == NULL) ? "null" : ftp_data->session_username,
			         (ftp_data->session_password == NULL) ? "null" : ftp_data->session_password,
			         ftp_data->file_size,
					 (ftp_data->filename == NULL) ? "null" : ftp_data->filename,
			         ftp_data->file_download_finishtime_sec,
			         ftp_data->file_download_finishtime_usec,
			         ftp_data->file_download_starttime_sec,
			         ftp_data->file_download_starttime_usec,
			         temp_session ->session_id,
			         temp_session ->thread_number
			        );
			message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message

			if (probe_context->output_to_file_enable && probe_context->ftp_reconstruct_output_channel[0])send_message_to_file_thread (message, (void *)user_args);
			if (probe_context->redis_enable && probe_context->ftp_reconstruct_output_channel[1])send_message_to_redis ("ftp.download.report", message);
			if (probe_context->kafka_enable && probe_context->ftp_reconstruct_output_channel[2] == 1)send_msg_to_kafka(probe_context->topic_object->rkt_ftp_download, message);

			reset_ftp_parameters(ipacket, temp_session);
			break;
		}
	}
}

/* This function is for reporting FTP session report */
void print_initial_ftp_report(const mmt_session_t * session, session_struct_t * temp_session, char message [MAX_MESS + 1], int valid) {
	mmt_probe_context_t * probe_context = get_probe_context_config();

	if (probe_context == NULL) {
		debug("[FTP_REPORT] Cannot get probe context\n");
		return;
	}
	
	if(session == NULL || temp_session == NULL || temp_session->app_data == NULL || temp_session->app_format_id != MMT_FTP_REPORT_FORMAT){
		debug("[FTP_REPORT] Does not have data, or not FTP report\n");
		return;
	}

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	ftp_session_attr_t * ftp_data;
	ftp_data = (ftp_session_attr_t*)temp_session->app_data;
	snprintf(&message[valid], MAX_MESS - valid,
	         ",%u,%u,%"PRIu8",\"%s\",\"%s\",%"PRIu32",\"%s\",%"PRIu8",%"PRIu64",%"PRIu64"",
	         temp_session->app_format_id, get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16) ? (proto_hierarchy->len - 1) : (16 - 1)]),
	         ftp_data->session_conn_type,
	         (ftp_data->session_username == NULL) ? "null" : ftp_data->session_username,
	         (ftp_data->session_password == NULL) ? "null" : ftp_data->session_password,
	         ftp_data->file_size,
	         (ftp_data->filename == NULL) ? "null" : ftp_data->filename,
	         ftp_data->direction,
	         ftp_data->session_id_control_channel,
	         ftp_data->response_time
	        );

	temp_session->session_attr->touched = 1;

}
