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

typedef enum{
   NO_SUPPORT,
   BOOL,
   UINT16_T,
   UINT32_T,
   CHAR_STAR
}data_type_t;

#define _FIRST(  a, ... )   a
#define FIRST(  a )  _FIRST  a

#define _SECOND( a, b, c, d )  {.val = a, .data_type = d, .ident = b}
#define SECOND( a )  _SECOND a

#define _CASE( a, b, c, d ) case a: return c;
#define CASE( a )    _CASE a

#define COMMA() ,
#define EMPTY()

typedef struct identity_struct{
	int val;
	data_type_t data_type;
	const char *ident;
}identity_t;

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
	(CONF_ATT__FILE_OUTPUT__ENABLE,       "file-output.enable", &conf->outputs.file->is_enable,                  BOOL),
	(CONF_ATT__FILE_OUTPUT__OUTPUT_FILE,  "file-output.output-file", &conf->outputs.file->filename,              CHAR_STAR),
	(CONF_ATT__FILE_OUTPUT__OUTPUT_DIR,   "file-output.output-dir", &conf->outputs.file->directory,              CHAR_STAR),
	(CONF_ATT__FILE_OUTPUT__RETAIN_FILES, "file-output.sample-file", &conf->outputs.file->is_sampled,            BOOL),
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

	//session-report
	(CONF_ATT__SESSION_REPORT__ENABLE, "session-report.enable", &conf->reports.session->is_enable, BOOL),
	(CONF_ATT__SESSION_REPORT__FTP,    "session-report.ftp", &conf->reports.session->is_ftp, BOOL ),
	(CONF_ATT__SESSION_REPORT__HTTP,   "session-report.http", &conf->reports.session->is_http, BOOL),
	(CONF_ATT__SESSION_REPORT__RTP,    "session-report.rtp", &conf->reports.session->is_rtp, BOOL ),
	(CONF_ATT__SESSION_REPORT__SSL,    "session-report.ssl", &conf->reports.session->is_ssl, BOOL)
)


int _cmp (const void * a, const void * b ) {
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

const identity_t* _conf_get_ident_from_string( const char * ident_str ){
	_sort_identities_if_need();
	identity_t key = {.val = 0, .ident = ident_str};
	return (identity_t*) bsearch( &key, identities,  nb_parameters, sizeof( identity_t ), _cmp );
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
	const identity_t *ident = _conf_get_ident_from_string( ident_str );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%s]", ident_str );
		return false;
	}

	uint32_t int_val = 0;

	void *field_ptr = _conf_get_ident_attribute_field(conf, ident->val );

	if( field_ptr == NULL ){
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident_str );
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
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", ident_str, value_str );
			return false;
		}
		break;
	default:
		break;
	}

	switch( ident->data_type ){
	//update value depending on parameters
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

	log_write( LOG_INFO, "Unknown identifier '%s'", ident_str );
	return false;
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
