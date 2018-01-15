/*
 * configure.h
 *
 *  Created on: Dec 12, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_CONFIGURE_H_
#define SRC_LIB_CONFIGURE_H_

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include <errno.h>

#define MMT_USER_AGENT_THRESHOLD 0x20 //32KB

typedef struct multi_thread_conf_struct{
	uint16_t thread_count;
	uint32_t thread_queue_packet_threshold;
}multi_thread_conf_t;


typedef struct file_output_conf_struct{
	bool is_enable;
	char *directory;
	char *filename;
	bool is_sampled;
	//indicates the periodicity for reporting output file, i.e., a file contains statistics of traffic during x seconds
	uint16_t output_period;
	uint16_t retained_files_count; //retains the last x sampled files,
								//set to 0 to retain all files
								// ( note that the value of retain-files must be greater than the value of thread_nb + 1)
}file_output_conf_t;

typedef struct internet_service_address_struct{
	char *host_name;
	uint16_t port_number;
}internet_service_address_t;

typedef struct redis_output_conf_struct{
	bool is_enable;
	internet_service_address_t host;
}redis_output_conf_t;

typedef struct kafka_output_conf_struct{
	bool is_enable;
	internet_service_address_t host;
	//further setting for kafka connection, such as, TLS certificate, cipher type, ...
}kafka_output_conf_t;


typedef struct input_source_conf_struct{

	enum {ONLINE_ANALYSIS, OFFLINE_ANALYSIS} input_mode;
	enum {DPDK_CAPTURE, PCAP_CAPTURE} capture_mode;

	//input source for PCAP online mode (interface name) and for offline mode (pcap name), however for DPDK its interface port number
	char *input_source;
	uint16_t snap_len;
}input_source_conf_t;



typedef struct output_channel_conf_struct{
	bool is_enable;
	bool is_output_to_file;
	bool is_output_to_redis;
	bool is_output_to_kafka;
}output_channel_conf_t;

typedef struct dynamic_config_conf_struct{
	bool is_enable;
	char *descriptor;
}dynamic_config_conf_t;

typedef struct security_conf_struct{
	bool is_enable;
	uint16_t threads_size;
	char *excluded_rules;
	char *rules_mask;
	output_channel_conf_t output_channels;
}security_conf_t;


typedef struct system_stats_conf_struct{
	bool is_enable;
	uint16_t frequency; //time-interval for reporting
	output_channel_conf_t output_channels;
}system_stats_conf_t;


typedef struct behaviour_conf_struct{
	bool is_enable;
	char *directory;
}behaviour_conf_t;

typedef struct data_dump_conf_struct{
	bool is_enable;
	char *directory;
	uint16_t frequency;

	uint16_t protocols_size;
	char **protocols;
	uint16_t retained_files_count; //retains the last x sampled files,
									//set to 0 to retain all files
									// ( note that the value of retain-files must be greater than the value of thread_nb + 1)
}data_dump_conf_t;

typedef struct reconstruct_ftp_conf_struct{
	bool is_enable;
	char *directory; //indicates the folder where the output file is created
	output_channel_conf_t output_channels;
}reconstruct_data_conf_t;


typedef struct dpi_protocol_attribute_struct{
	char* proto_name;
	char* attribute_name;
}dpi_protocol_attribute_t;


typedef struct socket_output_conf_struct{
	bool is_enable;
	enum{ UNIX_SOCKET_TYPE, INTERNET_SOCKET_TYPE, ANY_SOCKET_TYPE } socket_type;
	//descriptor of UNIX socket if used
	char *unix_socket_descriptor;

	uint16_t internet_sockets_size;
	struct internet_socket_output_conf_struct{
		bool is_enable;
		internet_service_address_t host;
		uint16_t attributes_size;
		//Indicates the list of attributes that are reported
		dpi_protocol_attribute_t *attributes;
	} *internet_sockets;

	//If set to 0 the server contains multiple sockets to receive the reports.
	//If set to 1 only one socket will receive the reports :
	bool is_one_socket_server;

	//indicates the number of report per message ( sockets ) .Default is 1.
	uint16_t messages_per_report;
}socket_output_conf_t;

//This report is for security multi-session security :
typedef struct security_report_multi_sessions_conf_struct{
	bool is_enable;
	uint16_t attributes_size;
	dpi_protocol_attribute_t *attributes;

	output_channel_conf_t output_channels;
}security_multi_sessions_conf_t;

typedef struct radius_conf_struct{
	bool is_enable;
	uint16_t include_msg;
	uint16_t include_condition;
	output_channel_conf_t output_channels;
}radius_conf_t;


typedef struct micro_flow_conf_struct{
	bool is_enable;
	uint32_t include_packets_count;
	uint32_t include_bytes_count;
	uint32_t report_bytes_count;
	uint32_t report_flows_count;
	output_channel_conf_t output_channels;
}micro_flow_conf_t;

typedef struct session_timeout_conf_struct{
	uint32_t default_session_timeout;
	uint32_t long_session_timeout;
	uint32_t short_session_timeout;
	uint32_t live_session_timeout;
}session_timeout_conf_t;

typedef struct event_report_conf_struct{
	bool is_enable;
	char *title;
	dpi_protocol_attribute_t *event;
	uint16_t attributes_size;
	dpi_protocol_attribute_t *attributes;
	output_channel_conf_t output_channels;
}event_report_conf_t;


typedef struct session_report_conf_struct{
	bool is_enable;
	output_channel_conf_t output_channels;
	bool is_ftp;
	bool is_http;
	bool is_ssl;
	bool is_rtp;
}session_report_conf_t;

/**
 * Configuration of MMT-Probe
 */
typedef struct probe_conf_struct{
	uint32_t probe_id;
	char *license_file;

	input_source_conf_t *input;

	struct output_conf_struct{
		bool is_enable;
		file_output_conf_t  *file;
		redis_output_conf_t *redis;
		kafka_output_conf_t *kafka;
	}outputs;

	multi_thread_conf_t *thread;

	session_timeout_conf_t *session_timeout;
	dynamic_config_conf_t *dynamic_conf;

	struct report_conf_struct{
		security_conf_t *security;
		system_stats_conf_t *cpu_mem;
		behaviour_conf_t   *behaviour;
		socket_output_conf_t *socket;
		security_multi_sessions_conf_t *security_multisession;
		radius_conf_t *radius;
		micro_flow_conf_t *microflow;
		session_report_conf_t *session;

		uint16_t events_size;
		event_report_conf_t *events;

		data_dump_conf_t *data_dump;
	}reports;

	struct reconstruct_data_struct{
		reconstruct_data_conf_t *http;
		reconstruct_data_conf_t *ftp;
	}reconstructions;

	bool is_enable_ip_fragementation;
	bool is_enable_proto_no_session_stat;
	uint16_t stat_period;

}probe_conf_t;


probe_conf_t* load_configuration_from_file( const char* filename );

/**
 * Free all memory allocated by @load_configuration_from_file
 * @param
 */
void release_probe_configuration( probe_conf_t * );


#endif /* SRC_LIB_CONFIGURE_H_ */
