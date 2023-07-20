/*
 * configure_override.h
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_CONFIGURE_OVERRIDE_H_
#define SRC_CONFIGURE_OVERRIDE_H_

#include "configure.h"
#include "lib/macro_apply.h"

//TODO: remove the following defines
#if 0
#define MONGODB_MODULE
#define PCAP_DUMP_MODULE
#define KAFKA_MODULE
#define REDIS_MODULE
#define SECURITY_MODULE
#define SOCKET_MODULE
#define LICENSE_CHECK
#define DPDK_MODULE
#endif

/**
 * Data type using by the attributes of the configuration
 */
typedef enum{
   NO_SUPPORT,
   BOOL,
   UINT16_T,
   UINT32_T,
   CHAR_STAR,
   LIST
} data_type_t;

typedef struct identity_struct{
	int val;
	data_type_t data_type;
	const char *ident;
}identity_t;

const identity_t* conf_get_identity_from_string( const char * ident_str );

/**
 * Override an attribute in configuration.
 * @param
 * @param ident: identifier of element will be overridden.
 * @param value: value will be overridden only if the value is different with the current one of the element.
 * @return 0 if the value has been overridden, otherwise false
 */
int conf_override_element( probe_conf_t*, const char* ident, const char *value );

/**
 * Override an attribute in configuration.
 * @param conf
 * @param ident_val
 * @param value_str
 * @return
 */
bool conf_override_element_by_id( probe_conf_t *conf, int ident_val, const char *value_str );

/**
 * Check if data_value is suitable for an identity.
 * @param ident
 * @param data_value
 * @return NULL if yes, otherwise, a text representing error reasons.
 */
const char* conf_validate_data_value( const identity_t *ident, const char *data_value );

void conf_print_identities_list();



#define _FIRST(  a, ... )   a
#define FIRST(  a )  _FIRST  a

#define _SECOND( a, b, c, d )  {.val = a, .data_type = d, .ident = b}
#define SECOND( a )  _SECOND a

#define _CASE( a, b, c, d ) case a: return c;
#define CASE( a )    _CASE a

#define COMMA() ,
#define EMPTY()

#define DECLARE_CONF_ATT( ... )                                           \
	                                                                      \
/*list of identities by number*/                                          \
typedef enum {                                                            \
	APPLY( COMMA,  FIRST, __VA_ARGS__ )                                   \
}config_identity_t;                                                       \
                                                                          \
/*list of identities*/                                                    \
static inline size_t conf_get_identities( const identity_t **lst ){       \
	static identity_t identities[ COUNT_ARGS( __VA_ARGS__ ) ] = {         \
		APPLY( COMMA, SECOND, __VA_ARGS__ )                               \
    };                                                                    \
    if( lst != NULL ) *lst = identities;                                  \
    return COUNT_ARGS( __VA_ARGS__ );                                     \
};                                                                        \
                                                                          \
/*get a file of probe_conf_t by identities number */                      \
static inline void* conf_get_ident_attribute_field(                       \
	probe_conf_t *conf, config_identity_t x ){                            \
	switch( x ){                                                          \
		APPLY( EMPTY, CASE, __VA_ARGS__ )                                 \
	}                                                                     \
	return NULL;                                                          \
}

/**
 * In the following declaration, each line uses the structure:
 *  (ident-number, ident-string, pointer-field, data-type)
 * - ident-number: is used to define enum element
 * - ident-string: is string of configuration attribute.
 *    They are the same as in mmt-probe.conf. Its level is separated by dot, for example:
 *    "input.mode" will represent "mode" in "input" block
 * - pointer-field: is a pointer pointing to a field of "conf" variable having "probe_config_t" type
 * - data-type: is data type of the attribute. It can be bool, uint16_t, uint32_t or char*
 */
DECLARE_CONF_ATT(
	(CONF_ATT__NONE, "no-support", NULL, NO_SUPPORT),

	//general
	(CONF_ATT__PROBE_ID,     "probe-id", &conf->probe_id, UINT32_T),
	(CONF_ATT__STACK_TYPE,   "stack-type", &conf->stack_type, UINT32_T),
	(CONF_ATT__STACK_OFFSET, "stack-offset", &conf->stack_offset, UINT32_T),
#ifdef LICENSE_CHECK
	(CONF_ATT__LICENSE,      "license",  &conf->license_file,  CHAR_STAR),
#endif
	(CONF_ATT__STATS_PERIOD, "stats-period", &conf->stat_period, UINT16_T ),

	(CONF_ATT__ENABLE_PROTO_WITHOUT_SESSION_REPORT, "enable-proto-without-session-report",
			&conf->is_enable_proto_no_session_report, BOOL),
	(CONF_ATT__ENABLE_IP_FRAGEMENTATION_REPORT,     "enable-ip-fragmentation-report",
			&conf->is_enable_ip_fragmentation_report, BOOL ),
	(CONF_ATT__ENABLE_REPORT_VERSION_INFO, "enable-report-version-info",
				&conf->is_enable_report_version_info, BOOL ),
	(CONF_ATT__ENABLE_IP_DEFRAGEMENTATION, "enable-ip-defragmentation", &conf->is_enable_ip_defragmentation, BOOL ),

#ifdef TCP_REASSEMBLY_MODULE
	(CONF_ATT__ENABLE_TCP_REASSEMBLY,      "enable-tcp-reassembly",     &conf->is_enable_tcp_reassembly,     BOOL ),
#endif

	//dynamic configuration
	(CONF_ATT__DYN_CONF__ENABLE,     "dynamic-config.enable",      &conf->dynamic_conf->is_enable,   BOOL),
	(CONF_ATT__DYN_CONF__DESCRIPTOR, "dynamic-config.descriptor",  &conf->dynamic_conf->descriptor,  CHAR_STAR),
	//multi-threading
	(CONF_ATT__THREAD_NB,    "thread-nb",   &conf->thread->thread_count, UINT16_T),
	(CONF_ATT__THREAD_QUEUE, "thread-queue",&conf->thread->thread_queue_packet_threshold, UINT32_T),

	//input
	(CONF_ATT__INPUT__MODE,        "input.mode",        &conf->input->input_mode,   UINT16_T),
	(CONF_ATT__INPUT__SOURCE,      "input.source",      &conf->input->input_source, CHAR_STAR),
	(CONF_ATT__INPUT__SNAP_LEN,    "input.snap-len",    &conf->input->snap_len,     UINT16_T),
	(CONF_ATT__INPUT__BUFFER_SIZE, "input.buffer-size", &conf->input->buffer_size,  UINT32_T),
	(CONF_ATT__INPUT__TIMEOUT,     "input.timeout",     &conf->input->timeout,      UINT32_T),

#ifdef DPDK_MODULE
	(CONF_ATT__INPUT__DPDK_OPTION, "input.dpdk-option", &conf->input->dpdk_options, CHAR_STAR),
#endif

	//output
	(CONF_ATT__OUTPUT__FORMAT,       "output.format",       &conf->outputs.format,       UINT16_T),
	(CONF_ATT__OUTPUT__CACHE_MAX,    "output.cache-max",    &conf->outputs.cache_max,    UINT32_T),
	(CONF_ATT__OUTPUT__CACHE_PERIOD, "output.cache-period", &conf->outputs.cache_period, UINT32_T),

	//file-output
	(CONF_ATT__FILE_OUTPUT__ENABLE,       "file-output.enable",       &conf->outputs.file->is_enable,            BOOL),
	(CONF_ATT__FILE_OUTPUT__OUTPUT_FILE,  "file-output.output-file",  &conf->outputs.file->filename,             CHAR_STAR),
	(CONF_ATT__FILE_OUTPUT__OUTPUT_DIR,   "file-output.output-dir",   &conf->outputs.file->directory,            CHAR_STAR),
	(CONF_ATT__FILE_OUTPUT__RETAIN_FILES, "file-output.sample-file",  &conf->outputs.file->is_sampled,           BOOL),
	(CONF_ATT__FILE_OUTPUT__SAMPLE_FILE,  "file-output.retain-files", &conf->outputs.file->retained_files_count, UINT16_T),

#ifdef MONGODB_MODULE
	//mongodb-output
	(CONF_ATT__MONGODB_OUTPUT__ENABLE,     "mongodb-output.enable",     &conf->outputs.mongodb->is_enable,         BOOL),
	(CONF_ATT__MONGODB_OUTPUT__HOSTNAME,   "mongodb-output.hostnam",    &conf->outputs.mongodb->host.host_name,    CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__PORT,       "mongodb-output.port",       &conf->outputs.mongodb->host.port_number,  UINT16_T),
	(CONF_ATT__MONGODB_OUTPUT__COLLECTION, "mongodb-output.collection", &conf->outputs.mongodb->collection_name,   CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__DATABASE,   "mongodb-output.database",   &conf->outputs.mongodb->database_name,     CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__LIMIT_SIZE, "mongodb-output.limit-size", &conf->outputs.mongodb->limit_size,        UINT32_T),
#endif

#ifdef KAFKA_MODULE
	//kafka-output
	(CONF_ATT__KAFKA_OUTPUT__ENABLE,   "kafka-output.enable",   &conf->outputs.kafka->is_enable,        BOOL),
	(CONF_ATT__KAFKA_OUTPUT__HOSTNAME, "kafka-output.hostname", &conf->outputs.kafka->host.host_name,   CHAR_STAR),
	(CONF_ATT__KAFKA_OUTPUT__PORT,     "kafka-output.port",     &conf->outputs.kafka->host.port_number, UINT16_T),
	(CONF_ATT__KAFKA_OUTPUT__TOPICNAME,"kafka-output.topic",    &conf->outputs.kafka->topic_name,       CHAR_STAR),
#endif

#ifdef REDIS_MODULE
	//redis-output
	(CONF_ATT__REDIS_OUTPUT__ENABLE,       "redis-output.enable",   &conf->outputs.redis->is_enable,        BOOL),
	(CONF_ATT__REDIS_OUTPUT__HOSTNAME,     "redis-output.hostname", &conf->outputs.redis->host.host_name,   CHAR_STAR),
	(CONF_ATT__REDIS_OUTPUT__CHANNEL_NAME, "redis-output.channel",  &conf->outputs.redis->channel_name,     CHAR_STAR),
	(CONF_ATT__REDIS_OUTPUT__PORT,         "redis-output.port",     &conf->outputs.redis->host.port_number, UINT16_T),
#endif

#ifdef SOCKET_MODULE
	//redis-output
	(CONF_ATT__SOCKET_OUTPUT__ENABLE,       "socket-output.enable",     &conf->outputs.socket->is_enable,                   BOOL),
	(CONF_ATT__SOCKET_OUTPUT__TYPE,         "socket-output.type",       &conf->outputs.socket->socket_type,                 UINT16_T),
	(CONF_ATT__SOCKET_OUTPUT__HOSTNAME,     "socket-output.hostname",   &conf->outputs.socket->internet_socket.host_name,   CHAR_STAR),
	(CONF_ATT__SOCKET_OUTPUT__PORT,         "socket-output.port",       &conf->outputs.socket->internet_socket.port_number, UINT16_T),
	(CONF_ATT__SOCKET_OUTPUT__DESCRIPTOR,   "socket-output.descriptor", &conf->outputs.socket->unix_socket_descriptor,      CHAR_STAR),
#endif

#ifdef PCAP_DUMP_MODULE
	//dump-pcap
	(CONF_ATT__DUMP_PCAP__ENABLE,       "dump-pcap.enable",       &conf->reports.pcap_dump->is_enable,            BOOL),
	(CONF_ATT__DUMP_PCAP__OUTPUT_DIR,   "dump-pcap.output-dir",   &conf->reports.pcap_dump->directory,            CHAR_STAR),
	(CONF_ATT__DUMP_PCAP__PROTOCOLS,    "dump-pcap.protocols",    &conf->reports.pcap_dump->protocols,            LIST),
	(CONF_ATT__DUMP_PCAP__PERIOD,       "dump-pcap.period",       &conf->reports.pcap_dump->frequency,            UINT16_T),
	(CONF_ATT__DUMP_PCAP__RETAIN_FILES, "dump-pcap.retain-files", &conf->reports.pcap_dump->retained_files_count, UINT16_T),
	(CONF_ATT__DUMP_PCAP__SNAP_LEN,     "dump-pcap.snap-len",     &conf->reports.pcap_dump->snap_len,             UINT16_T),
#endif

	//system-report
	(CONF_ATT__SYSTEM_REPORT__ENABLE,         "system-report.enable", &conf->reports.cpu_mem->is_enable, BOOL),
	(CONF_ATT__SYSTEM_REPORT__PERIOD,         "system-report.period", &conf->reports.cpu_mem->frequency, UINT16_T),
	(CONF_ATT__SYSTEM_REPORT__OUTPUT_CHANNEL, "system-report.output-channel", &conf->reports.cpu_mem->output_channels, CHAR_STAR),

	//behaviour
	(CONF_ATT__BEHAVIOUR__ENABLE,       "behaviour.enable",       &conf->reports.behaviour->is_enable, BOOL),
	(CONF_ATT__BEHAVIOUR__OUTPUT_DIR,   "behaviour.output-dir",   &conf->reports.behaviour->directory, CHAR_STAR),
	(CONF_ATT__BEHAVIOUR__OUTPUT_FILE,  "behaviour.output-file",  &conf->reports.behaviour->filename, CHAR_STAR),
	(CONF_ATT__BEHAVIOUR__RETAIN_FILES, "behaviour.retain-files", &conf->reports.behaviour->retained_files_count, UINT16_T),

#ifdef SECURITY_MODULE
	//security
	(CONF_ATT__SECURITY__ENABLE,        "security.enable",          &conf->reports.security->is_enable,      BOOL ),
	(CONF_ATT__SECURITY__THREAD_NB,     "security.thread-nb",       &conf->reports.security->threads_size,   UINT16_T),
	(CONF_ATT__SECURITY__EXCLUDE_RULES, "security.exclude-rules",   &conf->reports.security->excluded_rules, CHAR_STAR),
	(CONF_ATT__SECURITY__RULES_MASK,    "security.rules-mask",      &conf->reports.security->rules_mask,     CHAR_STAR),
	(CONF_ATT__SECURITY__OUTPUT_CHANNEL, "security.output-channel", &conf->reports.security->output_channels, LIST),
	(CONF_ATT__SECURITY__REPORT_RULE_DESCRIPTION, "security.report-rule-description", &conf->reports.security->is_report_rule_description, BOOL),
	(CONF_ATT__SECURITY__INGORE_REMAIN_FLOW,      "security.ignore-remain-flow",      &conf->reports.security->ignore_remain_flow, CHAR_STAR ),
#endif

#ifdef FTP_RECONSTRUCT_MODULE
	//reconstruct FTP
	(CONF_ATT__RECONSTRUCT_DATA__FTP__ENABLE,     "reconstruct-data.ftp.enable",     &conf->reconstructions.ftp->is_enable, BOOL),
	(CONF_ATT__RECONSTRUCT_DATA__FTP__OUTPUT_DIR, "reconstruct-data.ftp.output-dir", &conf->reconstructions.ftp->directory, CHAR_STAR),
#endif

#ifdef HTTP_RECONSTRUCT_MODULE
	//reconstruct HTTP
	(CONF_ATT__RECONSTRUCT_DATA__HTTP__ENABLE,     "reconstruct-data.http.enable",     &conf->reconstructions.http->is_enable, BOOL),
	(CONF_ATT__RECONSTRUCT_DATA__HTTP__OUTPUT_DIR, "reconstruct-data.http.output-dir", &conf->reconstructions.http->directory, CHAR_STAR ),
#endif

	//micro-flows
	(CONF_ATT__MICRO_FLOWS__ENABLE,              "micro-flows.enable",              &conf->reports.microflow->is_enable,            BOOL ),
	(CONF_ATT__MICRO_FLOWS__PACKET_THRESHOLD,    "micro-flows.packet-threshold",    &conf->reports.microflow->packet_threshold,     UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__BYTE_THRESHOLD,      "micro-flows.byte-threshold",      &conf->reports.microflow->byte_threshold,       UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_PACKET_COUNT, "micro-flows.report-packet-count", &conf->reports.microflow->report_packets_count, UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_BYTE_COUNT,   "micro-flows.report-bytes-count",  &conf->reports.microflow->report_bytes_count,   UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_FLOWSCOUNT,   "micro-flows.report-flows-count",  &conf->reports.microflow->report_flows_count,   UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__OUTPUT_CHANNEL,      "micro-flows.output-channel",      &conf->reports.microflow->output_channels,      LIST),

	//session-report
	(CONF_ATT__SESSION_REPORT__ENABLE, "session-report.enable", &conf->reports.session->is_enable, BOOL),
	(CONF_ATT__SESSION_REPORT__FTP,    "session-report.ftp",    &conf->reports.session->is_ftp,    BOOL ),
	(CONF_ATT__SESSION_REPORT__HTTP,   "session-report.http",   &conf->reports.session->is_http,   BOOL),
	(CONF_ATT__SESSION_REPORT__RTP,    "session-report.rtp",    &conf->reports.session->is_rtp,    BOOL ),
	(CONF_ATT__SESSION_REPORT__GTP,    "session-report.gtp",    &conf->reports.session->is_gtp,    BOOL ),
	(CONF_ATT__SESSION_REPORT__SSL,    "session-report.ssl",    &conf->reports.session->is_ssl,    BOOL),
(CONF_ATT__SESSION_REPORT__RTT_BASE,   "session-report.rtt-base", &conf->reports.session->rtt_base, UINT16_T),
	(CONF_ATT__SESSION_REPORT__OUTPUT_CHANNEL, "session-report.output-channel",    &conf->reports.session->output_channels, LIST),

	//radius-report
	(CONF_ATT__RADIUS_REPORT__ENABLE,         "radius-report.enable",         &conf->reports.radius->is_enable,       BOOL),
	(CONF_ATT__RADIUS_REPORT__MESSAGE_ID,     "radius-report.message-id",     &conf->reports.radius->message_code,    UINT16_T ),
	(CONF_ATT__RADIUS_REPORT__OUTPUT_CHANNEL, "radius-report.output-channel", &conf->reports.radius->output_channels, LIST )
)

/**
 * Get identity_t object from a number ID.
 * @param id
 * @return
 */
static inline const identity_t* conf_get_identity_from_id( int id ){
	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );

	if( id < 0 || id >= nb_parameters )
		return NULL;

	return &identities[ id ];
}

#endif /* SRC_CONFIGURE_OVERRIDE_H_ */
