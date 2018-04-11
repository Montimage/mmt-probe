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

#define DEFINE_STRUCT( var_type, struct_name ) \
typedef struct  {                              \
	const char*name;                           \
	var_type value;                            \
}struct_name


DEFINE_STRUCT( uint16_t, UINT16_T);

typedef struct multi_thread_conf_struct{
	uint16_t thread_count;
	uint16_t readers_count;
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

typedef struct mongodb_output_conf_struct{
	bool is_enable;
	internet_service_address_t host;
	char *database_name;
	char *collection_name;
	uint32_t limit_size; //limit size of storage collection
	//further setting for kafka connection, such as, TLS certificate, cipher type, ...
}mongodb_output_conf_t;


typedef struct input_source_conf_struct{

	enum {ONLINE_ANALYSIS, OFFLINE_ANALYSIS} input_mode;
	enum {DPDK_CAPTURE, PCAP_CAPTURE} capture_mode;

	//input source for PCAP online mode (interface name) and for offline mode (pcap name), however for DPDK its interface port number
	char *input_source;
	uint16_t snap_len;
}input_source_conf_t;


typedef enum {
	CONF_OUTPUT_CHANNEL_NONE    = 0,
	CONF_OUTPUT_CHANNEL_FILE    = 1,
	CONF_OUTPUT_CHANNEL_REDIS   = 2,
	CONF_OUTPUT_CHANNEL_KAFKA   = 4,
	CONF_OUTPUT_CHANNEL_MONGODB = 8,
	CONF_OUTPUT_CHANNEL_ALL     = CONF_OUTPUT_CHANNEL_FILE | CONF_OUTPUT_CHANNEL_REDIS | CONF_OUTPUT_CHANNEL_KAFKA | CONF_OUTPUT_CHANNEL_MONGODB
}output_channel_conf_t;

#define IS_ENABLE_OUTPUT_TO( name, channels ) ( channels & CONF_OUTPUT_CHANNEL_ ##name )
#define IS_ENABLE_OUTPUT_TO_ALL_CHANNELS( channles ) ( channels & CONF_OUTPUT_CHANNEL_ALL   )
#define IS_ENABLE_OUTPUT_TO_ONE_CHANNEL(  channles ) ( channels | CONF_OUTPUT_CHANNEL_ALL   )
#define IS_DISABLE_OUTPUT( channels )                ( channels == CONF_OUTPUT_CHANNEL_NONE )

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
	uint16_t snap_len;
}data_dump_conf_t;

typedef struct reconstruct_data_conf_struct{
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

struct output_conf_struct{
	bool is_enable;
	file_output_conf_t  *file;
	redis_output_conf_t *redis;
	kafka_output_conf_t *kafka;
	mongodb_output_conf_t *mongodb;
	enum {OUTPUT_FORMAT_CSV, OUTPUT_FORMAT_JSON} format;
};

/**
 * Configuration of MMT-Probe
 */
typedef struct probe_conf_struct{
	bool is_enable_ip_fragementation;
	bool is_enable_proto_no_session_stat;

	uint32_t probe_id;

	struct output_conf_struct outputs;

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
		reconstruct_data_conf_t *tcp;
	}reconstructions;


	uint16_t stat_period;

	char *license_file;

	input_source_conf_t *input;
}probe_conf_t;


probe_conf_t* conf_load_from_file( const char* filename );

typedef enum {
	CONF_ATT__NONE = 0,
	CONF_ATT__PROBE_ID,
	CONF_ATT__LICENSE,

	CONF_ATT__INPUT__MODE,
	CONF_ATT__INPUT__SOURCE,
	CONF_ATT__INPUT__SNAP_LEN,

	CONF_ATT__BEHAVIOUR__ENABLE,
	CONF_ATT__BEHAVIOUR__OUTPUT_DIR,

	CONF_ATT__DUMP_PCAP__ENABLE,
	CONF_ATT__DUMP_PCAP__OUTPUT_DIR,
	CONF_ATT__DUMP_PCAP__PROTOCOLS,
	CONF_ATT__DUMP_PCAP__PERIOD,
	CONF_ATT__DUMP_PCAP__RETAIN_FILES,
	CONF_ATT__DUMP_PCAP__SNAP_LEN,

	CONF_ATT__FILE_OUTPUT__ENABLE,
	CONF_ATT__FILE_OUTPUT__OUTPUT_FILE,
	CONF_ATT__FILE_OUTPUT__OUTPUT_DIR,
	CONF_ATT__FILE_OUTPUT__RETAIN_FILES,
	CONF_ATT__FILE_OUTPUT__PERIOD,
}config_attribute_t;

/**
 * Convert identifier from string to number.
 * @param ident :e.g., "probe-id", "input.mode", "event-report.ip_even.enable", etc.
 * @return identifier of element. Otherwise CONF_ATT__NONE
 */
config_attribute_t conf_get_ident_att_from_string( const char *ident );

/**
 *
 * @param
 * @param ident: identifier of element will be overridden.
 * @param value: value will be overridden only if the value is different with the current one of the element.
 * @param cb
 * @return true if the value has been overridden, otherwise false
 */
bool conf_override_element( probe_conf_t*, config_attribute_t ident, const char *value );

/**
 * Free all memory allocated by @load_configuration_from_file
 * @param
 */
void conf_release( probe_conf_t * );

#endif /* SRC_LIB_CONFIGURE_H_ */
