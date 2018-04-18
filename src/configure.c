/*
 * configure.c
 *
 *  Created on: Dec 12, 2017
 *          by: Huu Nghia
 */

#include <confuse.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "lib/log.h"
#include "lib/memory.h"

#include "configure.h"

/* parse values for the input-mode option */
static int _conf_parse_input_mode(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
	if (IS_EQUAL_STRINGS(value, "online") )
		*(int *) result = ONLINE_ANALYSIS;
	else if (IS_EQUAL_STRINGS(value, "offline") )
		*(int *) result = OFFLINE_ANALYSIS;
	else {
		cfg_error(cfg, "invalid value for option '%s': %s", cfg_opt_name(opt), value);
		return -1;
	}
	return 0;
}

/* parse values for the output format option */
int conf_parse_output_format(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
	if( value == NULL || value[0] == '\0' || strcasecmp(value, "CSV") == 0)
		*(int *) result = OUTPUT_FORMAT_CSV;
	else if (strcasecmp(value, "JSON") == 0)
		*(int *) result = OUTPUT_FORMAT_JSON;
	else {
		cfg_error(cfg, "Invalid '%s' for option '%s'. Use either CSV or JSON.", value, cfg_opt_name(opt));
		return -1;
	}
	return 0;
}

static inline cfg_t *_load_cfg_from_file(const char *filename) {
	cfg_opt_t micro_flows_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("include-packet-count", 10, CFGF_NONE),
			CFG_INT("include-byte-count", 5, CFGF_NONE),
			CFG_INT("report-packet-count", 10000, CFGF_NONE),
			CFG_INT("report-byte-count", 5000, CFGF_NONE),
			CFG_INT("report-flow-count", 1000, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t session_timeout_opts[] = {
			CFG_INT("default-session-timeout", 60, CFGF_NONE),
			CFG_INT("long-session-timeout", 600, CFGF_NONE),
			CFG_INT("short-session-timeout", 15, CFGF_NONE),
			CFG_INT("live-session-timeout", 1500, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t redis_output_opts[] = {
			CFG_STR("hostname", "localhost", CFGF_NONE),
			CFG_INT("port", 6379, CFGF_NONE),
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t kafka_output_opts[] = {
			CFG_STR("hostname", "localhost", CFGF_NONE),
			CFG_INT("port", 9092, CFGF_NONE),
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t mongodb_output_opts[] = {
			CFG_STR("hostname", "localhost", CFGF_NONE),
			CFG_INT("port", 27017, CFGF_NONE),
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("database", "mmt-data", CFGF_NONE),
			CFG_STR("collection", "reports", CFGF_NONE),
			CFG_INT("limit-size", 0, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t dynamic_conf_opts[] = {
			CFG_STR("descriptor", "", CFGF_NONE),
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t file_output_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("output-file", 0, CFGF_NONE),
			CFG_STR("output-dir", 0, CFGF_NONE),
			CFG_INT("retain-files", 0, CFGF_NONE),
			CFG_BOOL("sample-file", true, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t dump_pcap_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("output-dir", 0, CFGF_NONE),
			CFG_STR_LIST("protocols", "{}", CFGF_NONE),
			CFG_INT("period", 0, CFGF_NONE),
			CFG_INT("retain-files", 0, CFGF_NONE),
			CFG_INT("snap-len", 0, CFGF_NONE),
			CFG_END()
		};

	cfg_opt_t security2_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("thread-nb",    0, CFGF_NONE),
			CFG_STR("rules-mask",   0, CFGF_NONE),
			CFG_STR("exclude-rules",   0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t cpu_mem_report_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("period", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t behaviour_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("output-dir", 0, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t reconstruct_data_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("output-dir", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t radius_output_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("include-msg", 0, CFGF_NONE),
			CFG_INT("include-condition", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t data_output_opts[] = {
			CFG_INT("include-user-agent", MMT_USER_AGENT_THRESHOLD, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t event_report_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR("event", "", CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t socket_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("domain", 0, CFGF_NONE),
			CFG_STR_LIST("port", "{}", CFGF_NONE),
			CFG_STR_LIST("server-address", "{}", CFGF_NONE),
			CFG_STR("socket-descriptor", "", CFGF_NONE),
			CFG_INT("one-socket-server", 1, CFGF_NONE),
			CFG_INT("num-of-report-per-msg", 1, CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t session_report_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_BOOL("ftp", false, CFGF_NONE),
			CFG_BOOL("rtp", false, CFGF_NONE),
			CFG_BOOL("http", false, CFGF_NONE),
			CFG_BOOL("ssl", false, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t input_opts[] = {
			CFG_INT_CB("mode", 0, CFGF_NONE, _conf_parse_input_mode),
			CFG_STR("source", "", CFGF_NONE),
			CFG_INT("snap-len", 65535, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t output_opts[] = {
			CFG_INT_CB("format", OUTPUT_FORMAT_CSV, CFGF_NONE, conf_parse_output_format),
			CFG_INT("cache-size", 1000, CFGF_NONE),
			CFG_INT("cache-period", 5, CFGF_NONE),
			CFG_END()
		};

	cfg_opt_t opts[] = {
			CFG_SEC("input", input_opts, CFGF_NONE),
			CFG_SEC("micro-flows", micro_flows_opts, CFGF_NONE),
			CFG_SEC("session-timeout", session_timeout_opts, CFGF_NONE),
			CFG_SEC("output", output_opts, CFGF_NONE),
			CFG_SEC("file-output", file_output_opts, CFGF_NONE),
			CFG_SEC("redis-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("kafka-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("data-output", data_output_opts, CFGF_NONE),
			CFG_SEC("security", security2_opts, CFGF_NONE),
			CFG_SEC("system-report", cpu_mem_report_opts, CFGF_NONE),
			CFG_SEC("socket", socket_opts, CFGF_NONE),
			CFG_SEC("behaviour", behaviour_opts, CFGF_NONE),
			CFG_SEC("reconstruct-data", reconstruct_data_opts, CFGF_TITLE | CFGF_MULTI ),
			CFG_SEC("mongodb-output", mongodb_output_opts, CFGF_NONE),
			CFG_SEC("dump-pcap", dump_pcap_opts, CFGF_NONE),

			CFG_INT("stats-period", 5, CFGF_NONE),
			CFG_BOOL("enable-proto-without-session-report", false, CFGF_NONE),
			CFG_BOOL("enable-ip-fragmentation-report", false, CFGF_NONE),

			CFG_INT("thread-nb", 1, CFGF_NONE),
			CFG_INT("thread-queue", 0, CFGF_NONE),
			CFG_INT("probe-id", 0, CFGF_NONE),

			CFG_STR("logfile", 0, CFGF_NONE),
			CFG_STR("license", 0, CFGF_NONE),
			CFG_INT("loglevel", 2, CFGF_NONE),

			CFG_SEC("event-report", event_report_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("session-report", session_report_opts, CFGF_NONE),
			CFG_SEC("dynamic-config", dynamic_conf_opts, CFGF_NONE),
			CFG_END()
	};

	cfg_t *cfg = cfg_init(opts, CFGF_NONE);
	switch (cfg_parse(cfg, filename)) {
	case CFG_FILE_ERROR:
		log_write(LOG_ERR, "Error: configuration file '%s' could not be read: %s\n", filename, strerror(errno));
		cfg_free( cfg );
		return NULL;
	case CFG_SUCCESS:
		break;
	case CFG_PARSE_ERROR:
		log_write(LOG_ERR, "Error: configuration file '%s' could not be parsed.\n", filename );
		cfg_free( cfg );
		return NULL;
	}

	return cfg;
}

static inline char * _cfg_get_str( cfg_t *cfg, const char *header ){
	const char *str = cfg_getstr( cfg, header );
	if (str == NULL)
		return NULL;
	return mmt_strdup( str );
}

static inline cfg_t* _get_first_cfg_block( cfg_t *cfg, const char* block_name ){
	if( ! cfg_size( cfg, block_name) )
		return NULL;
	DEBUG( "Parsing block '%s'", block_name );
	return cfg_getnsec( cfg, block_name, 0 );
}


static inline long int _cfg_getint( cfg_t *cfg, const char *ident, long int min, long int max, long int def_val, long int replaced_val ){
	long int val = cfg_getint( cfg, ident );
	if( val < min || val > max ){
		log_write( LOG_WARNING, "Not expected %ld for %s. Used default value %ld.", val, ident, replaced_val );
		return replaced_val;
	}

	if( val == def_val ){
		log_write( LOG_INFO, "Used default value %ld for %s", replaced_val, ident );
		return replaced_val;
	}
	return val;
}

static inline input_source_conf_t * _parse_input_source( cfg_t *cfg ){
	cfg = _get_first_cfg_block( cfg, "input" );
	if( cfg == NULL )
		return NULL;

	input_source_conf_t *ret = mmt_alloc( sizeof( input_source_conf_t ));

	ret->input_mode   = cfg_getint(cfg, "mode");
	ret->input_source = _cfg_get_str(cfg, "source");

#ifndef DPDK_MODULE
#ifndef PCAP_MODULE
	#error("Neither DPDK nor PCAP is defined")
#endif
#endif

#if defined DPDK_MODULE && defined PCAP_MODULE
	#error("Either DPDK_MODULE or PCAP_MODULE is defined but must not all of them")
#endif


#ifdef DPDK_MODULE
	ret->capture_mode = DPDK_CAPTURE;
#endif

#ifdef PCAP_MODULE
	ret->capture_mode = PCAP_CAPTURE;
#endif

	ret->snap_len = cfg_getint( cfg, "snap-len" );

	if( ret->snap_len == 0 )
		ret->snap_len = UINT16_MAX;

	return ret;
}


static inline file_output_conf_t *_parse_output_to_file( cfg_t *cfg ){
	cfg_t * c = _get_first_cfg_block( cfg, "file-output" );
	if( c == NULL )
		return NULL;

	file_output_conf_t *ret = mmt_alloc( sizeof( file_output_conf_t ));

	ret->is_enable  = cfg_getbool( c, "enable" );
	ret->directory  = _cfg_get_str(c, "output-dir");
	ret->filename   = _cfg_get_str(c, "output-file");
	ret->is_sampled    = cfg_getbool(c, "sample-file");
	ret->retained_files_count = cfg_getint( c, "retain-files" );

	return ret;
}

static inline pcap_dump_conf_t *_parse_dump_to_file( cfg_t *cfg ){
	cfg = _get_first_cfg_block( cfg, "dump-pcap" );
	if( cfg == NULL )
		return NULL;

	pcap_dump_conf_t *ret = mmt_alloc( sizeof( pcap_dump_conf_t ));

	ret->is_enable  = cfg_getbool( cfg, "enable" );
	ret->directory  = _cfg_get_str(cfg, "output-dir");
	ret->frequency  = cfg_getint( cfg, "period");
	ret->retained_files_count = cfg_getint( cfg, "retain-files" );
	ret->snap_len = cfg_getint( cfg, "snap-len" );

	ret->protocols_size = cfg_size( cfg, "protocols");

	ret->protocols = mmt_alloc( sizeof( void* ) * ret->protocols_size );
	int i;
	char *str;
	for( i=0; i<ret->protocols_size; i++) {
		str = cfg_getnstr(cfg, "protocols", i);
		ret->protocols[i] = mmt_strdup( str );
	}
	return ret;
}

static inline kafka_output_conf_t *_parse_output_to_kafka( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "kafka-output")) == NULL )
		return NULL;

	kafka_output_conf_t *ret = mmt_alloc( sizeof( kafka_output_conf_t ));

	ret->is_enable        = cfg_getbool( cfg,  "enable" );
	ret->host.host_name   = _cfg_get_str(cfg, "hostname");
	ret->host.port_number = cfg_getint( cfg,  "port" );

	return ret;
}

static inline mongodb_output_conf_t *_parse_output_to_mongodb( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "mongodb-output")) == NULL )
		return NULL;

	mongodb_output_conf_t *ret = mmt_alloc( sizeof( mongodb_output_conf_t ));

	ret->is_enable        = cfg_getbool( cfg,  "enable" );
	ret->host.host_name   = _cfg_get_str(cfg, "hostname");
	ret->host.port_number = cfg_getint( cfg,  "port" );
	ret->database_name    = _cfg_get_str(cfg, "database");
	ret->collection_name  = _cfg_get_str(cfg, "collection");
	ret->limit_size       = cfg_getint( cfg,  "limit-size" );

	return ret;
}

static inline redis_output_conf_t *_parse_output_to_redis( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "redis-output")) == NULL )
		return NULL;

	redis_output_conf_t *ret = mmt_alloc( sizeof( redis_output_conf_t ));

	ret->is_enable        = cfg_getbool( cfg, "enable" );
	ret->host.host_name   = _cfg_get_str(cfg, "hostname");
	ret->host.port_number = cfg_getint( cfg,  "port" );

	return ret;
}

static inline dynamic_config_conf_t *_parse_dynamic_config_block( cfg_t *cfg ){
	cfg_t * c = _get_first_cfg_block( cfg, "dynamic-config" );
	if( c == NULL )
		return NULL;

	dynamic_config_conf_t *ret = mmt_alloc( sizeof( dynamic_config_conf_t ));

	ret->is_enable  = cfg_getbool( c, "enable" );
	ret->descriptor  = _cfg_get_str(c, "descriptor");

	return ret;
}


static inline multi_thread_conf_t * _parse_thread( cfg_t *cfg ){
	multi_thread_conf_t *ret = mmt_alloc( sizeof( multi_thread_conf_t ));
	ret->thread_count                  = cfg_getint( cfg, "thread-nb" );
	ret->thread_queue_packet_threshold = cfg_getint( cfg, "thread-queue" );
	return ret;
}

static inline behaviour_conf_t *_parse_behaviour_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "behaviour")) == NULL )
		return NULL;

	behaviour_conf_t *ret = mmt_alloc( sizeof( behaviour_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->directory = _cfg_get_str(cfg, "output-dir");
	return ret;
}

static inline  output_channel_conf_t _parse_output_channel( cfg_t *cfg ){
	int nb_output_channel = cfg_size( cfg, "output-channel");
	int i;
	const char *channel_name;

	output_channel_conf_t out = CONF_OUTPUT_CHANNEL_FILE; //default is to output to file

	for( i=0; i<nb_output_channel; i++) {
		channel_name = cfg_getnstr(cfg, "output-channel", i);
		if ( strncmp( channel_name, "file", 4 ) == 0 )
			out |= CONF_OUTPUT_CHANNEL_FILE;
		else if ( strncmp( channel_name, "kafka", 5 ) == 0 )
			out |= CONF_OUTPUT_CHANNEL_KAFKA;
		else if ( strncmp( channel_name, "redis", 5 ) == 0 )
			out |= CONF_OUTPUT_CHANNEL_REDIS;
		else if ( strncmp( channel_name, "mongodb", 5 ) == 0 )
			out |= CONF_OUTPUT_CHANNEL_MONGODB;
		else
			log_write( LOG_WARNING, "Unexpected channel %s", channel_name );
	}
	return out;
}

static inline system_stats_conf_t *_parse_cpu_mem_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "system-report")) == NULL )
		return NULL;

	system_stats_conf_t *ret = mmt_alloc( sizeof( system_stats_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->frequency = cfg_getint( cfg, "period" );
	ret->output_channels = _parse_output_channel( cfg );
	return ret;
}

static inline void _parse_dpi_protocol_attribute( dpi_protocol_attribute_t * out, const char* str ){
	out->attribute_name = NULL;
	out->proto_name     = NULL;

	//str = HTTP.METHOD
	int index = 0;
	while( str[index] != '.' )
		index ++;
	out->proto_name     = mmt_strndup( str, index );
	out->attribute_name = mmt_strdup( str+index+1 ); //+1 to jump over .

}

static inline uint16_t _parse_attributes_helper( cfg_t *cfg, const char* name, dpi_protocol_attribute_t**atts ){
	int i;
	uint16_t size =  cfg_size( cfg, name );
	*atts = NULL;
	if( size == 0 )
		return size;

	dpi_protocol_attribute_t *ret = NULL;
	ret = mmt_alloc( sizeof( dpi_protocol_attribute_t ) * size );
	for( i=0; i<size; i++ )
		_parse_dpi_protocol_attribute( &ret[i], cfg_getnstr( cfg, name, i ) );

	*atts = ret;
	return size;
}




static inline void _parse_event_block( event_report_conf_t *ret, cfg_t *cfg ){
	int i;
	assert( cfg != NULL );
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->title     = mmt_strdup( cfg_title(cfg) );
	ret->event = mmt_alloc( sizeof( dpi_protocol_attribute_t ));
	_parse_dpi_protocol_attribute( ret->event, cfg_getstr( cfg, "event" ) );

	ret->attributes_size = _parse_attributes_helper( cfg, "attributes", &ret->attributes );

	ret->output_channels = _parse_output_channel( cfg );
}

static inline micro_flow_conf_t *_parse_microflow_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "micro-flows")) == NULL )
		return NULL;

	micro_flow_conf_t *ret = mmt_alloc( sizeof( micro_flow_conf_t ));
	ret->is_enable             = cfg_getbool( cfg, "enable" );
	ret->include_bytes_count   = cfg_getint( cfg, "include-byte-count" );
	ret->include_packets_count = cfg_getint( cfg, "include-packet-count" );
	ret->report_bytes_count    = cfg_getint( cfg, "report-byte-count" );
	ret->report_flows_count    = cfg_getint( cfg, "report-flow-count" );
	ret->output_channels = _parse_output_channel( cfg );
	return ret;
}


static inline security_conf_t *_parse_security_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "security")) == NULL )
		return NULL;

	security_conf_t *ret = mmt_alloc( sizeof( security_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->threads_size = cfg_getint( cfg, "thread-nb" );
	ret->excluded_rules = _cfg_get_str(cfg, "exclude-rules" );
	ret->rules_mask = _cfg_get_str(cfg, "rules-mask" );
	ret->output_channels = _parse_output_channel( cfg );
	return ret;
}

static inline session_report_conf_t *_parse_session_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "session-report")) == NULL )
		return NULL;

	session_report_conf_t *ret = mmt_alloc( sizeof( session_report_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->is_ftp    = cfg_getbool( cfg, "ftp" );
	ret->is_rtp    = cfg_getbool( cfg, "rtp" );
	ret->is_http   = cfg_getbool( cfg, "http" );
	ret->is_ssl    = cfg_getbool( cfg, "ssl" );
	ret->output_channels = _parse_output_channel( cfg );
	return ret;
}

static inline session_timeout_conf_t *_parse_session_timeout_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "session-timeout")) == NULL )
		return NULL;

	session_timeout_conf_t *ret = mmt_alloc( sizeof( session_timeout_conf_t ));
	ret->default_session_timeout = _cfg_getint( cfg, "default-session-timeout", 0, 6000, 0,   60 );
	ret->live_session_timeout    = _cfg_getint( cfg, "live-session-timeout",    0, 6000, 0, 1500 );
	ret->long_session_timeout    = _cfg_getint( cfg, "long-session-timeout",    0, 6000, 0,  600 );
	ret->short_session_timeout   = _cfg_getint( cfg, "short-session-timeout",   0, 6000, 0,   15 );
	return ret;
}

static inline socket_output_conf_t *_parse_socket_block( cfg_t *cfg ){
	int i;
	cfg_t *c = _get_first_cfg_block( cfg, "socket");
	if( c == NULL )
		return NULL;

	socket_output_conf_t *ret = mmt_alloc( sizeof( socket_output_conf_t ));
	ret->is_enable = cfg_getbool( c, "enable" );
	switch( cfg_getint( c, "domain")  ){
	case 0:
		ret->socket_type = UNIX_SOCKET_TYPE;
		break;
	case 1:
		ret->socket_type = INTERNET_SOCKET_TYPE;
		break;
	case 2:
		ret->socket_type = ANY_SOCKET_TYPE;
		break;
	}
	ret->unix_socket_descriptor = _cfg_get_str(c, "socket-descriptor" );
	ret->is_one_socket_server =  (cfg_getint( c, "one-socket-server") == 1);
	ret->messages_per_report  = cfg_getint( c, "num-of-report-per-msg");

	ret->internet_sockets_size = cfg_size( c, "port" );
	if( ret->internet_sockets_size > cfg_size( c, "server-address") ){
		printf( "Error: Number of socket.port and socket.server-address are different" );
		exit( 1 );
	}

	ret->internet_sockets = NULL;// alloc( sizeof (internet_socket_output_conf_struct ))

	return ret;
}


static inline reconstruct_data_conf_t *_parse_reconstruct_data_block( cfg_t *cfg, const char *name ){
	int size = cfg_size( cfg, "reconstruct-data");
	int i;
	cfg_t *c;

	if( size == 0 ){
		log_write( LOG_ERR, "Expected reconstruct-data blocks" );
		abort();
		return NULL;
	}

	for( i=0; i<size; i++ ){
		c = cfg_getnsec(cfg, "reconstruct-data", i );

		if( ! IS_EQUAL_STRINGS(name, cfg_title(c) ) )
			continue;

		DEBUG( "Parsing block 'reconstruct-data %s'", name );

		reconstruct_data_conf_t *ret = mmt_alloc( sizeof( reconstruct_data_conf_t ));
		ret->is_enable = cfg_getbool( c, "enable" );
		ret->directory = _cfg_get_str(c, "output-dir" );
		ret->output_channels = _parse_output_channel( c );
		return ret;
	}
	return NULL;
}


static inline void _parse_output_block( output_conf_t *output, cfg_t *cfg ){
	cfg = _get_first_cfg_block( cfg, "output");
	if( cfg == NULL ){
		log_write( LOG_ERR, "Expected output block" );
		return;
	}

	output->cache_size = cfg_getint( cfg, "cache-size") ;
	output->cache_period = cfg_getint( cfg, "cache-period") ;
	output->format  = cfg_getint(cfg, "format");

	return;
}
/**
 * Public API
 * @param filename
 * @return
 */
probe_conf_t* conf_load_from_file( const char* filename ){
	const char *str;
	int i;
	cfg_t *cfg = _load_cfg_from_file( filename );
	if( cfg == NULL ){
		return NULL;
	}

	probe_conf_t *conf = mmt_alloc( sizeof( probe_conf_t ) );

	conf->probe_id     = cfg_getint(cfg, "probe-id");
	conf->stat_period  = cfg_getint(cfg, "stats-period");
	conf->license_file = _cfg_get_str(cfg, "license" );
	conf->is_enable_proto_no_session_report  = cfg_getbool(cfg, "enable-proto-without-session-report");
	conf->is_enable_ip_fragementation_report = cfg_getbool(cfg, "enable-ip-fragmentation-report");

	conf->input = _parse_input_source( cfg );

	_parse_output_block( &conf->outputs, cfg );
	//set of output channels
	conf->outputs.file  = _parse_output_to_file( cfg );
	conf->outputs.kafka = _parse_output_to_kafka( cfg );
	conf->outputs.redis = _parse_output_to_redis( cfg );
	conf->outputs.mongodb = _parse_output_to_mongodb( cfg );
	//a global
	conf->outputs.is_enable = ( (conf->outputs.file != NULL && conf->outputs.file->is_enable )
									|| (conf->outputs.redis != NULL && conf->outputs.redis->is_enable)
									|| (conf->outputs.kafka != NULL && conf->outputs.kafka->is_enable ));

	conf->dynamic_conf = _parse_dynamic_config_block( cfg );
	//
	conf->thread = _parse_thread( cfg );

	conf->reports.behaviour = _parse_behaviour_block( cfg );
	conf->reports.cpu_mem   = _parse_cpu_mem_block( cfg );

	//events reports
	conf->reports.events_size = cfg_size( cfg, "event-report" );
	conf->reports.events  = mmt_alloc( sizeof( event_report_conf_t ) * conf->reports.events_size );
	for( i=0; i<conf->reports.events_size; i++ )
		_parse_event_block( &conf->reports.events[i], cfg_getnsec( cfg, "event-report", i) );

	//
	conf->reports.microflow = _parse_microflow_block( cfg );

	conf->reports.security = _parse_security_block( cfg );
	conf->reports.session = _parse_session_block( cfg );
	conf->reports.socket = _parse_socket_block( cfg );

	conf->reports.pcap_dump = _parse_dump_to_file(cfg);

	conf->session_timeout = _parse_session_timeout_block( cfg );

	//
	conf->reconstructions.ftp = _parse_reconstruct_data_block(cfg, "ftp");
	conf->reconstructions.http = _parse_reconstruct_data_block(cfg, "http");
	conf->reconstructions.tcp = _parse_reconstruct_data_block(cfg, "tcp");
	cfg_free( cfg );

	//validate default values
	if( conf->reports.cpu_mem->frequency == 0 )
		conf->reports.cpu_mem->frequency = 5;

	return conf;
}

static inline void _free_event_report( event_report_conf_t *ret ){
	if( ret == NULL )
		return;
	int i;
	for( i=0; i<ret->attributes_size; i++ ){
		mmt_probe_free( ret->attributes[i].proto_name );
		mmt_probe_free( ret->attributes[i].attribute_name );
	}
	mmt_probe_free( ret->attributes );
	mmt_probe_free( ret->title );
	mmt_probe_free( ret->event->proto_name );
	mmt_probe_free( ret->event->attribute_name );
	mmt_probe_free( ret->event );
}

/**
 * Public API
 * Free all memory allocated by @load_configuration_from_file
 * @param
 */
void conf_release( probe_conf_t *conf){
	if( conf == NULL )
		return;

	int i;

	mmt_probe_free( conf->input->input_source );
	mmt_probe_free( conf->input );

	for( i=0; i<conf->reports.events_size; i++ )
		_free_event_report( &conf->reports.events[i] );
	mmt_probe_free( conf->reports.events );

	if( conf->reports.behaviour ){
		mmt_probe_free( conf->reports.behaviour->directory );
		mmt_probe_free( conf->reports.behaviour );
	}

	mmt_probe_free( conf->reports.cpu_mem );
	mmt_probe_free( conf->reports.microflow );

	if( conf->reports.security ){
		mmt_probe_free( conf->reports.security->excluded_rules );
		mmt_probe_free( conf->reports.security->rules_mask );
		mmt_probe_free( conf->reports.security );
	}

	mmt_probe_free( conf->reports.session );

	if( conf->reports.socket ){
		mmt_probe_free( conf->reports.socket->unix_socket_descriptor );
		for( i=0; i<conf->reports.socket->internet_sockets_size; i++){
			//xfree(conf->reports.socket->internet_sockets[i].host.host_name );
		}
		mmt_probe_free( conf->reports.socket->internet_sockets );
		mmt_probe_free( conf->reports.socket );
	}

	if( conf->reconstructions.ftp ){
		mmt_probe_free( conf->reconstructions.ftp->directory );
		mmt_probe_free( conf->reconstructions.ftp );
	}
	if( conf->reconstructions.http ){
		mmt_probe_free( conf->reconstructions.http->directory );
		mmt_probe_free( conf->reconstructions.http );
	}

	mmt_probe_free( conf->thread );
	if( conf->outputs.file ){
		mmt_probe_free( conf->outputs.file->directory );
		mmt_probe_free( conf->outputs.file->filename );
		mmt_probe_free( conf->outputs.file );
	}
	if( conf->outputs.kafka ){
		mmt_probe_free( conf->outputs.kafka->host.host_name );
		mmt_probe_free( conf->outputs.kafka );
	}
	if( conf->outputs.redis ){
		mmt_probe_free( conf->outputs.redis->host.host_name );
		mmt_probe_free( conf->outputs.redis );
	}

	mmt_probe_free( conf->session_timeout );

	mmt_probe_free( conf->license_file );
	mmt_probe_free( conf );
}

//sizeof of a string takes into account also '\0'
#define LENGTH( string ) (sizeof( string ) - 1 )
#define IS_STARTED_BY( a, b ) is_started_by( a, b, LENGTH( b ))

#define ENSURE_STARTED_BY( ident, string )                 \
	if( ! is_started_by(ident, string, LENGTH( string )))  \
		break

#define CHECK_VALUE( ident, val, ret_val )                  \
	if( strcmp( ident, val ) == 0 )                         \
		return ret_val

config_attribute_t conf_get_ident_att_from_string( const char *ident ){
	int i;
	const char *ch;
	switch( ident[0] ){
	//behaviour
	case 'b':
		ENSURE_STARTED_BY(ident, "behaviour.");
		ident += LENGTH( "behaviour.");

		switch( ident[0] ){
		//behaviour.enable
		case 'e':
			CHECK_VALUE( ident, "enable", CONF_ATT__BEHAVIOUR__ENABLE );
			break;
		//behaviour.output-dir
		case 'o':
			CHECK_VALUE( ident, "output-dir", CONF_ATT__BEHAVIOUR__OUTPUT_DIR );
			break;
		}
		break;

		//dump-pcap, dynamic-config, data-output,
	case 'd':
		switch( ident[1] ){
		case 'a':
			ENSURE_STARTED_BY(ident, "data-output.");
			break;
		//dump-pcap
		case 'u':
			ENSURE_STARTED_BY(ident, "dump-pcap.");
			ident += LENGTH( "dump-pcap." );
			switch( ident[0] ){
			case 'e':
				CHECK_VALUE( ident, "enable", CONF_ATT__DUMP_PCAP__ENABLE );
				break;
			case 'o':
				CHECK_VALUE( ident, "output-dir", CONF_ATT__DUMP_PCAP__OUTPUT_DIR );
				break;
			case 'p':
				CHECK_VALUE( ident, "protocols", CONF_ATT__DUMP_PCAP__PROTOCOLS );
				CHECK_VALUE( ident, "period", CONF_ATT__DUMP_PCAP__PERIOD );
				break;
			case 'r':
				CHECK_VALUE( ident, "retain-files", CONF_ATT__DUMP_PCAP__RETAIN_FILES );
				break;
			case 's':
				CHECK_VALUE( ident, "snap-len", CONF_ATT__DUMP_PCAP__SNAP_LEN );
				break;
			}
			break;
		case 'y':
			break;
		}
		break;

		//enable-proto-without-session-report, enable-ip-fragmentation-report, event-report
	case 'e':
		break;

		//file-output
	case 'f':
		ENSURE_STARTED_BY(ident, "file-output.");
		ident += LENGTH( "file-output." );
		switch( ident[0] ){
		case 'e':
			CHECK_VALUE( ident, "enable", CONF_ATT__FILE_OUTPUT__ENABLE );
			break;
		case 'o':
			CHECK_VALUE( ident, "output-dir", CONF_ATT__FILE_OUTPUT__OUTPUT_DIR );
			CHECK_VALUE( ident, "output-file", CONF_ATT__FILE_OUTPUT__OUTPUT_FILE );
			break;
		case 's':
			CHECK_VALUE( ident, "sample-file", CONF_ATT__FILE_OUTPUT__SAMPLE_FILE );
			break;
		case 'r':
			CHECK_VALUE( ident, "retain-files", CONF_ATT__FILE_OUTPUT__RETAIN_FILES );
			break;
		}
		break;

		//mongodb-output
	case 'm':
		ENSURE_STARTED_BY(ident, "mongodb-output.");
		ident += LENGTH( "mongodb-output." );
		switch( ident[0] ){
		case 'e':
			CHECK_VALUE( ident, "enable", CONF_ATT__MONGODB_OUTPUT__ENABLE );
			break;
		case 'h':
			CHECK_VALUE( ident, "hostname", CONF_ATT__MONGODB_OUTPUT__HOSTNAME );
			break;
		case 'p':
			CHECK_VALUE( ident, "port", CONF_ATT__MONGODB_OUTPUT__PORT );
			break;
		case 'd':
			CHECK_VALUE( ident, "database", CONF_ATT__MONGODB_OUTPUT__DATABASE );
			break;
		case 'c':
			CHECK_VALUE( ident, "collection", CONF_ATT__MONGODB_OUTPUT__COLLECTION );
			break;
		case 'l':
			CHECK_VALUE( ident, "limit-size", CONF_ATT__MONGODB_OUTPUT__LIMIT_SIZE );
			break;
		}
		break;

	}
	return CONF_ATT__NONE;
}


static bool _parse_bool( const char *value ){
	if( IS_EQUAL_STRINGS( value, "true" ) )
		return true;
	if( IS_EQUAL_STRINGS( value, "false" ) )
		return false;
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
bool conf_override_element( probe_conf_t *conf, config_attribute_t ident, const char *value ){
	bool *bool_param = NULL, bool_val ;
	uint16_t *uint16_t_param = NULL, uint16_t_val;
	uint32_t *uint32_t_param = NULL, uint32_t_val;
	int *int_param, int_val;
	char **string_param = NULL;
	//uint64_t
	switch( ident ){
	case CONF_ATT__NONE:
		return false;

		//top level
	case CONF_ATT__PROBE_ID:
		uint32_t_param = &conf->probe_id;
		break;
	case CONF_ATT__LICENSE:
		string_param = &conf->license_file;
		break;
	case CONF_ATT__ENABLE_PROTO_WITHOUT_SESSION_REPORT:
		bool_param = &conf->is_enable_proto_no_session_report;
		break;
	case CONF_ATT__ENABLE_IP_FRAGEMENTATION_REPORT:
		bool_param = &conf->is_enable_ip_fragementation_report;
		break;
	case CONF_ATT__STATS_PERIOD:
		uint16_t_param = &conf->stat_period;
		break;

		//input
	case CONF_ATT__INPUT__MODE:
		if( IS_EQUAL_STRINGS( value, "online") )
			int_val = ONLINE_ANALYSIS;
		else if ( IS_EQUAL_STRINGS( value, "offline") )
			int_val = OFFLINE_ANALYSIS;
		else
			return false;
		//update the new value if need
		if( int_val != conf->input->input_mode ){
			conf->input->input_mode = int_val;
			return true;
		}
		break;

	case CONF_ATT__INPUT__SOURCE:
		string_param = &conf->input->input_source;
		break;
	case CONF_ATT__INPUT__SNAP_LEN:
		uint16_t_param = &conf->input->snap_len;
		break;

		//file-output
	case CONF_ATT__FILE_OUTPUT__ENABLE:
		bool_param = &conf->outputs.file->is_enable;
		break;
	case CONF_ATT__FILE_OUTPUT__SAMPLE_FILE:
		bool_param = &conf->outputs.file->is_sampled;
		break;
	case CONF_ATT__FILE_OUTPUT__RETAIN_FILES:
		uint16_t_param = &conf->outputs.file->retained_files_count;
		break;
	case CONF_ATT__FILE_OUTPUT__OUTPUT_DIR:
		string_param = &conf->outputs.file->directory;
		break;
	case CONF_ATT__FILE_OUTPUT__OUTPUT_FILE:
		string_param = &conf->outputs.file->filename;
		break;

		//mongodb-output
	case CONF_ATT__MONGODB_OUTPUT__COLLECTION:
		string_param = &conf->outputs.mongodb->collection_name;
		break;
	case CONF_ATT__MONGODB_OUTPUT__DATABASE:
		string_param = &conf->outputs.mongodb->database_name;
		break;
	case CONF_ATT__MONGODB_OUTPUT__ENABLE:
		bool_param = &conf->outputs.mongodb->is_enable;
		break;
	case CONF_ATT__MONGODB_OUTPUT__HOSTNAME:
		string_param = &conf->outputs.mongodb->host.host_name;
		break;
	case CONF_ATT__MONGODB_OUTPUT__PORT:
		uint16_t_param = &conf->outputs.mongodb->host.port_number;
		break;
	case CONF_ATT__MONGODB_OUTPUT__LIMIT_SIZE:
		uint32_t_param = &conf->outputs.mongodb->limit_size;
		break;

		//kafka-output
	case CONF_ATT__KAFKA_OUTPUT__ENABLE:
		bool_param = &conf->outputs.kafka->is_enable;
		break;
	case CONF_ATT__KAFKA_OUTPUT__HOSTNAME:
		string_param = &conf->outputs.kafka->host.host_name;
		break;
	case CONF_ATT__KAFKA_OUTPUT__PORT:
		uint16_t_param = &conf->outputs.kafka->host.port_number;
		break;

		//redis-output
	case CONF_ATT__REDIS_OUTPUT__ENABLE:
		bool_param = &conf->outputs.redis->is_enable;
		break;
	case CONF_ATT__REDIS_OUTPUT__HOSTNAME:
		string_param = &conf->outputs.redis->host.host_name;
		break;
	case CONF_ATT__REDIS_OUTPUT__PORT:
		uint16_t_param = &conf->outputs.redis->host.port_number;
		break;

	default:
		break;
	}

	//update value depending on parameters
	if( string_param != NULL ){
		//value does not change ==> do nothing
		if( IS_EQUAL_STRINGS( *string_param, value ) )
			return false;
		else{
			mmt_probe_free( *string_param );
			*string_param = mmt_strdup( value );
			return true;
		}
	}

	if( bool_param != NULL ){
		bool_val = _parse_bool( value );
		//value does not change => do nothing
		if( bool_val == *bool_param )
			return false;
		else{
			//update value
			*bool_param = bool_val;
			return true;
		}
	}

	if( uint16_t_param != NULL ){
		uint16_t_val = atoi( value );
		//value does not change ==> do nothing
		if( uint16_t_val == *uint16_t_param )
			return false;
		else{
			*uint16_t_param = uint16_t_val;
			return true;
		}
	}

	if( uint32_t_param != NULL ){
		uint32_t_val = atol( value );
		//value does not change ==> do nothing
		if( uint32_t_val == *uint32_t_param )
			return false;
		else{
			*uint32_t_param = uint32_t_val;
			return true;
		}
	}

	log_write( LOG_INFO, "Unknown identifier '%d'", ident );
	return false;
}
