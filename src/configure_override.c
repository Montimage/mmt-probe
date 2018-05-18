/*
 * configure_override.c
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#include "lib/log.h"
#include "lib/memory.h"

#include "configure_override.h"
#include "lib/macro_apply.h"

#define LENGTH( string ) (sizeof( string ) - 1 )
#define IS_STARTED_BY( a, b ) is_started_by( a, b, LENGTH( b ))

#define ENSURE_STARTED_BY( ident, string )                 \
	if( ! is_started_by(ident, string, LENGTH( string )))  \
		break

#define CHECK_VALUE( ident, val, ret_val )                  \
	if( strcmp( ident, val ) == 0 )                         \
		return ret_val


static bool _parse_bool( const char *value ){
	if( IS_EQUAL_STRINGS( value, "true" ) )
		return true;
	if( IS_EQUAL_STRINGS( value, "false" ) )
		return false;
	return false;
}

#define _FIRST(  a, ... )   a
#define FIRST(  a )  _FIRST  a

#define _SECOND( a, b, c, d )  {.val = a, .data_type = d, .ident = b}
#define SECOND( a )  _SECOND a

#define _CASE( a, b, c, d ) case a: return c;
#define CASE( a )    _CASE a

#define COMMA() ,
#define EMPTY()

#define DECLARE_CONF_ATT( ... )                                           \
static const size_t nb_parameters = COUNT_ARGS( __VA_ARGS__ );            \
/*list of identities by number*/                                          \
typedef enum {                                                            \
	APPLY( COMMA,  FIRST, __VA_ARGS__ )                                   \
}config_attribute_t;                                                      \
/*list of identities by strings*/                                         \
static identity_t identities[ COUNT_ARGS( __VA_ARGS__ ) ] = {             \
		APPLY( COMMA, SECOND, __VA_ARGS__ )                               \
};                                                                        \
/*get a file of probe_conf_t by identities number */                      \
static inline void* _conf_get_ident_attribute_field(                      \
	probe_conf_t *conf, config_attribute_t x ){                           \
	switch( x ){                                                          \
		APPLY( EMPTY, CASE, __VA_ARGS__ )                                 \
	}                                                                     \
	return NULL;                                                          \
}

/**
 * In the following declaration, each line uses the sturcture:
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
	(CONF_ATT__LICENSE,      "license",  &conf->license_file,  CHAR_STAR),
	(CONF_ATT__STATS_PERIOD, "stats-period", &conf->stat_period, UINT16_T ),
	(CONF_ATT__ENABLE_PROTO_WITHOUT_SESSION_REPORT, "enable-proto-without-session-report",
			&conf->is_enable_proto_no_session_report, BOOL),
	(CONF_ATT__ENABLE_IP_FRAGEMENTATION_REPORT,     "enable-ip-fragmentation-report",
			&conf->is_enable_ip_fragementation_report, BOOL ),

	//dynamic configuration
	(CONF_ATT__DYN_CONF__ENABLE,     "dynamic-config.enable",      &conf->dynamic_conf->is_enable,   BOOL),
	(CONF_ATT__DYN_CONF__DESCRIPTOR, "dynamic-config.descriptor",  &conf->dynamic_conf->descriptor,  CHAR_STAR),
	//multi-threading
	(CONF_ATT__THREAD_NB,    "thread-nb",   &conf->thread->thread_count, UINT16_T),
	(CONF_ATT__THREAD_QUEUE, "thread-queue",&conf->thread->thread_queue_packet_threshold, UINT32_T),

	//input
	(CONF_ATT__INPUT__MODE,     "input.mode",     &conf->input->input_mode,   UINT16_T),
	(CONF_ATT__INPUT__SOURCE,   "input.source",   &conf->input->input_source, CHAR_STAR),
	(CONF_ATT__INPUT__SNAP_LEN, "input.snap-len", &conf->input->snap_len,     UINT16_T),

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

	//mongodb-output
	(CONF_ATT__MONGODB_OUTPUT__ENABLE,     "mongodb-output.enable", &conf->outputs.mongodb->is_enable,           BOOL),
	(CONF_ATT__MONGODB_OUTPUT__HOSTNAME,   "mongodb-output.hostnam", &conf->outputs.mongodb->host.host_name,     CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__PORT,       "mongodb-output.port", &conf->outputs.mongodb->host.port_number,      UINT16_T),
	(CONF_ATT__MONGODB_OUTPUT__COLLECTION, "mongodb-output.collection", &conf->outputs.mongodb->collection_name, CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__DATABASE,   "mongodb-output.database", &conf->outputs.mongodb->database_name,     CHAR_STAR),
	(CONF_ATT__MONGODB_OUTPUT__LIMIT_SIZE, "mongodb-output.limit-size", &conf->outputs.mongodb->limit_size,      UINT32_T),

	//kafka-output
	(CONF_ATT__KAFKA_OUTPUT__ENABLE,   "kafka-output.enable", &conf->outputs.kafka->is_enable,        BOOL),
	(CONF_ATT__KAFKA_OUTPUT__HOSTNAME, "kafka-output.hostname", &conf->outputs.kafka->host.host_name, CHAR_STAR),
	(CONF_ATT__KAFKA_OUTPUT__PORT,     "kafka-output.port", &conf->outputs.kafka->host.port_number,   UINT16_T),

	//redis-output
	(CONF_ATT__REDIS_OUTPUT__ENABLE,   "redis-output.enable", &conf->outputs.redis->is_enable, BOOL),
	(CONF_ATT__REDIS_OUTPUT__HOSTNAME, "redis-output.hostname", &conf->outputs.redis->host.host_name, CHAR_STAR),
	(CONF_ATT__REDIS_OUTPUT__PORT,     "redis-output.port", &conf->outputs.redis->host.port_number, UINT16_T),

	//dump-pcap
	(CONF_ATT__DUMP_PCAP__ENABLE,       "dump-pcap.enable", &conf->reports.pcap_dump->is_enable, BOOL),
	(CONF_ATT__DUMP_PCAP__OUTPUT_DIR,   "dump-pcap.output-dir", &conf->reports.pcap_dump->directory, CHAR_STAR),
	(CONF_ATT__DUMP_PCAP__PROTOCOLS,    "dump-pcap.protocols", NULL, NO_SUPPORT),
	(CONF_ATT__DUMP_PCAP__PERIOD,       "dump-pcap.period", &conf->reports.pcap_dump->frequency, UINT16_T),
	(CONF_ATT__DUMP_PCAP__RETAIN_FILES, "dump-pcap.retain-files", &conf->reports.pcap_dump->retained_files_count, UINT16_T),
	(CONF_ATT__DUMP_PCAP__SNAP_LEN,     "dump-pcap.snap-len", &conf->reports.pcap_dump->snap_len, UINT16_T),

	//system-report
	(CONF_ATT__SYSTEM_REPORT__ENABLE, "system-report.enable", &conf->reports.cpu_mem->is_enable, BOOL),
	(CONF_ATT__SYSTEM_REPORT__PERIOD, "system-report.period", &conf->reports.cpu_mem->frequency, UINT16_T),
	(CONF_ATT__SYSTEM_REPORT__OUTPUT_CHANNEL, "system-report.output-channel", NULL, NO_SUPPORT), //NO SUPPORT

	//behaviour
	(CONF_ATT__BEHAVIOUR__ENABLE,     "behaviour.enable", &conf->reports.behaviour->is_enable, BOOL),
	(CONF_ATT__BEHAVIOUR__OUTPUT_DIR, "behaviour.output-dir", &conf->reports.behaviour->directory, CHAR_STAR),

	//security
	(CONF_ATT__SECURITY__ENABLE,        "security.enable", &conf->reports.security->is_enable, BOOL ),
	(CONF_ATT__SECURITY__THREAD_NB,     "security.thread-nb", &conf->reports.security->threads_size, UINT16_T),
	(CONF_ATT__SECURITY__EXCLUDE_RULES, "security.exclude-rules", &conf->reports.security->excluded_rules, CHAR_STAR),
	(CONF_ATT__SECURITY__RULES_MASK,    "security.rules-mask", &conf->reports.security->rules_mask, CHAR_STAR),
	//No support (CONF_ATT__SECURITY__OUTPUT_CHANNEL, "security."),

	//reconstruct FTP
	(CONF_ATT__RECONSTRUCT_DATA__FTP__ENABLE,     "reconstruct-data.ftp.enable", &conf->reconstructions.ftp->is_enable, BOOL),
	(CONF_ATT__RECONSTRUCT_DATA__FTP__OUTPUT_DIR, "reconstruct-data.ftp.output-dir", &conf->reconstructions.ftp->directory, CHAR_STAR),

	//reconstruct HTTP
	(CONF_ATT__RECONSTRUCT_DATA__HTTP__ENABLE,     "reconstruct-data.http.enable", &conf->reconstructions.http->is_enable, BOOL),
	(CONF_ATT__RECONSTRUCT_DATA__HTTP__OUTPUT_DIR, "reconstruct-data.http.output-dir", &conf->reconstructions.http->directory, CHAR_STAR ),

	//micro-flows
	(CONF_ATT__MICRO_FLOWS__ENABLE, "micro-flows.enable", &conf->reports.microflow->is_enable, BOOL ),
	(CONF_ATT__MICRO_FLOWS__PACKET_THRESHOLD,    "micro-flows.packet-threshold",    &conf->reports.microflow->packet_threshold,     UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__BYTE_THRESHOLD,      "micro-flows.byte-threshold",      &conf->reports.microflow->byte_threshold,       UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_PACKET_COUNT, "micro-flows.report-packet-count", &conf->reports.microflow->report_packets_count, UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_BYTE_COUNT,   "micro-flows.report-bytes-count",  &conf->reports.microflow->report_bytes_count,   UINT32_T ),
	(CONF_ATT__MICRO_FLOWS__REPORT_FLOWSCOUNT,   "micro-flows.report-flows-count",  &conf->reports.microflow->report_flows_count,   UINT32_T ),

	//session-report
	(CONF_ATT__SESSION_REPORT__ENABLE, "session-report.enable", &conf->reports.session->is_enable, BOOL),
	(CONF_ATT__SESSION_REPORT__FTP,    "session-report.ftp",    &conf->reports.session->is_ftp,    BOOL ),
	(CONF_ATT__SESSION_REPORT__HTTP,   "session-report.http",   &conf->reports.session->is_http,   BOOL),
	(CONF_ATT__SESSION_REPORT__RTP,    "session-report.rtp",    &conf->reports.session->is_rtp,    BOOL ),
	(CONF_ATT__SESSION_REPORT__SSL,    "session-report.ssl",    &conf->reports.session->is_ssl,    BOOL),
	//radius-report
	(CONF_ATT__RADIUS_REPORT__ENABLE,     "radius-report.enable",     &conf->reports.radius->is_enable,  BOOL),
	(CONF_ATT__RADIUS_REPORT__MESSAGE_ID, "radius-report.message-id", &conf->reports.radius->message_code, UINT16_T )
)

size_t conf_get_number_of_identities(){
	return nb_parameters;
}

bool need_to_restart_to_update( const identity_t *ident ){
	switch( ident->val ){
	case CONF_ATT__NONE:
	case CONF_ATT__SECURITY__ENABLE:
		return false;
	default:
		return true;
	}
}

static int _cmp (const void * a, const void * b ) {
  const identity_t *pa = (identity_t*) a;
  const identity_t *pb = (identity_t*) b;
  return strcmp(pa->ident, pb->ident);
}

static inline void _sort_identities_if_need(){
	static bool is_init = true;
	//first times: sort the table to find quickly
	if( is_init ){
		qsort( identities, nb_parameters, sizeof( identity_t ), _cmp );
		is_init = false;
	}
}

const identity_t* conf_get_ident_from_string( const char * ident_str ){
	_sort_identities_if_need();
	identity_t key = {.val = 0, .ident = ident_str};
	return (identity_t*) bsearch( &key, identities,  nb_parameters, sizeof( identity_t ), _cmp );
}


const identity_t* conf_get_ident_from_id( int id ){
	_sort_identities_if_need();
	const identity_t *ident = NULL;
	int i;
	for( i=0; i<nb_parameters; i++ )
		if( identities[i].val == id )
			return &identities[i];
	return NULL;
}

const char* conf_validate_data_value( const identity_t *ident, const char *data_value ){
	static char error_reason[1000];
	int i;

	//special data type
	switch( ident->val ){
	//input
	case CONF_ATT__INPUT__MODE:
		if( IS_EQUAL_STRINGS( data_value, "online") )
			return NULL;
		else if ( IS_EQUAL_STRINGS( data_value, "offline") )
			return NULL;
		else{
			snprintf( error_reason, sizeof( error_reason), "Unexpected value [%s] for [%s]", data_value, ident->ident );
			return error_reason;
		}
		break;
	default:
		break;
	}

	//check value depending on data type of parameter
	switch( ident->data_type ){
	case BOOL:
		if( IS_EQUAL_STRINGS( data_value, "true" ) )
			break;
		if( IS_EQUAL_STRINGS( data_value, "false" ) )
			break;

		snprintf( error_reason, sizeof(error_reason), "Expect either 'true' or 'false' as value of '%s' (not '%s')", ident->ident, data_value );
		return error_reason;
		break;

	case UINT16_T:
	case UINT32_T:
		//check if data_value contains only the number
		i = 0;
		while( data_value[i] != '\0' ){
			if( data_value[i] < '0' || data_value[i] > '9' ){
				snprintf( error_reason, sizeof( error_reason), "Expect a number as value of '%s' (not '%s')", ident->ident, data_value );
				return 0;
			}
			i ++;
		}
		break;
	default:
		break;
	}

	return NULL;
}

static inline bool _override_element_by_ident( probe_conf_t *conf, const identity_t *ident, const char *value_str ){
	uint32_t int_val = 0;
	DEBUG("Update %s to %s", ident->ident, value_str );
	void *field_ptr = _conf_get_ident_attribute_field(conf, ident->val );

	if( field_ptr == NULL ){
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return false;
	}
	char **string_ptr;

	//special data type
	switch( ident->val ){
		//input
	case CONF_ATT__INPUT__MODE:
		if( IS_EQUAL_STRINGS( value_str, "online") )
			*((int *)field_ptr) = ONLINE_ANALYSIS;
		else if ( IS_EQUAL_STRINGS( value_str, "offline") )
			*((int *)field_ptr) = OFFLINE_ANALYSIS;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		break;
	default:
		break;
	}

	switch( ident->data_type ){
	//update value depending on parameters
	case NO_SUPPORT:
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return false;
	case CHAR_STAR:
		string_ptr = (char **) field_ptr;
		//value does not change ==> do nothing
		if( IS_EQUAL_STRINGS( *string_ptr, value_str ) )
			return false;
		mmt_probe_free( *string_ptr );
		*string_ptr = mmt_strdup( value_str );
		return true;

	case BOOL:
		int_val = _parse_bool( value_str );
		//value does not change => do nothing
		if( int_val == *((bool *)field_ptr) )
			return false;
		//update value
		*((bool *)field_ptr) = int_val;
		return true;


	case UINT16_T:
		int_val = atoi( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint16_t *)field_ptr) )
			return false;
		*((uint32_t *)field_ptr) = int_val;
		return true;

	case UINT32_T:
		int_val = atol( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint32_t *)field_ptr) )
			return false;
		*((uint32_t *)field_ptr) = int_val;
		return true;
	}

	log_write( LOG_INFO, "Unknown identifier '%s'", ident->ident );
	return false;
}


/**
 * Update value of a configuration parameter.
 * The new value is updated only if it is different with the current value of the parameter.
 * @param conf
 * @param ident
 * @param value
 * @return true if the new value is updated, otherwise false
 */
bool conf_override_element( probe_conf_t *conf, const char *ident_str, const char *value_str ){
	const identity_t *ident = conf_get_ident_from_string( ident_str );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%s]", ident_str );
		return false;
	}
	return _override_element_by_ident(conf, ident, value_str );
}

bool conf_override_element_by_id( probe_conf_t *conf, int ident_val, const char *value_str ){
	const identity_t *ident = conf_get_ident_from_id( ident_val );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%d]", ident_val );
		return false;
	}
	return _override_element_by_ident(conf, ident, value_str );
}


void conf_print_identities_list(){
	int i;
	char *data_type_strings[] = {
			"",
			"bool",
			"uint16_t",
			"uint32_t",
			"char *"
	};

	_sort_identities_if_need();

	for( i=0; i<nb_parameters; i++ )
		if( identities[i].data_type !=NO_SUPPORT  )
			printf("- %s (%s)\n", identities[i].ident, data_type_strings[identities[i].data_type]);
}
