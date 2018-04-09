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
	if (strcmp(value, "online") == 0)
		*(int *) result = ONLINE_ANALYSIS;
	else if (strcmp(value, "offline") == 0)
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
			CFG_INT("period", 5, CFGF_NONE),
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
			CFG_INT("frequency", 0, CFGF_NONE),
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
	cfg_opt_t security_report_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_STR_LIST("event", "{}", CFGF_NONE),
			CFG_INT("rule-type", 0, CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t security_report_multisession_opts[] = {
			CFG_BOOL("enable", false, CFGF_NONE),
			CFG_INT("file-output", 0, CFGF_NONE),
			CFG_INT("redis-output", 0, CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
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

	cfg_opt_t opts[] = {
			CFG_SEC("input", input_opts, CFGF_NONE),
			CFG_SEC("micro-flows", micro_flows_opts, CFGF_NONE),
			CFG_SEC("session-timeout", session_timeout_opts, CFGF_NONE),
			CFG_SEC("file-output", file_output_opts, CFGF_NONE),
			CFG_SEC("redis-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("kafka-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("data-output", data_output_opts, CFGF_NONE),
			CFG_SEC("security", security2_opts, CFGF_NONE),
			CFG_SEC("system-report", cpu_mem_report_opts, CFGF_NONE),
			CFG_SEC("socket", socket_opts, CFGF_NONE),
			CFG_SEC("behaviour", behaviour_opts, CFGF_NONE),
			CFG_SEC("reconstruct-data", reconstruct_data_opts, CFGF_TITLE | CFGF_MULTI ),
			CFG_SEC("radius-output", radius_output_opts, CFGF_NONE),
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
			CFG_SEC("security-report", security_report_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("security-report-multisession", security_report_multisession_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("session-report", session_report_opts, CFGF_NONE),
			CFG_SEC("dynamic-config", dynamic_conf_opts, CFGF_NONE),
			CFG_INT_CB("output-format", 0, CFGF_NONE, conf_parse_output_format),
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
	return strdup( str );
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

	input_source_conf_t *ret = alloc( sizeof( input_source_conf_t ));

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

	file_output_conf_t *ret = alloc( sizeof( file_output_conf_t ));

	ret->is_enable  = cfg_getbool( c, "enable" );
	ret->directory  = _cfg_get_str(c, "output-dir");
	ret->filename   = _cfg_get_str(c, "output-file");
	ret->output_period = cfg_getint( c, "period");
	ret->is_sampled    = (ret->output_period > 0);
	ret->retained_files_count = cfg_getint( c, "retain-files" );

	return ret;
}

static inline data_dump_conf_t *_parse_dump_to_file( cfg_t *cfg ){
	cfg = _get_first_cfg_block( cfg, "dump-pcap" );
	if( cfg == NULL )
		return NULL;

	data_dump_conf_t *ret = alloc( sizeof( data_dump_conf_t ));

	ret->is_enable  = cfg_getbool( cfg, "enable" );
	ret->directory  = _cfg_get_str(cfg, "output-dir");
	ret->frequency  = cfg_getint( cfg, "period");
	if( ret->frequency == 0 )
		ret->frequency = 3600;
	ret->retained_files_count = cfg_getint( cfg, "retain-files" );
	ret->snap_len = cfg_getint( cfg, "snap-len" );

	ret->protocols_size = cfg_size( cfg, "protocols");

	ret->protocols = alloc( sizeof( void* ) * ret->protocols_size );
	int i;
	char *str;
	for( i=0; i<ret->protocols_size; i++) {
		str = cfg_getnstr(cfg, "protocols", i);
		ret->protocols[i] = strdup( str );
	}
	return ret;
}

static inline kafka_output_conf_t *_parse_output_to_kafka( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "kafka-output")) == NULL )
		return NULL;

	kafka_output_conf_t *ret = alloc( sizeof( kafka_output_conf_t ));

	ret->is_enable        = cfg_getbool( cfg,  "enable" );
	ret->host.host_name   = _cfg_get_str(cfg, "hostname");
	ret->host.port_number = cfg_getint( cfg,  "port" );

	return ret;
}


static inline redis_output_conf_t *_parse_output_to_redis( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "redis-output")) == NULL )
		return NULL;

	redis_output_conf_t *ret = alloc( sizeof( redis_output_conf_t ));

	ret->is_enable        = cfg_getbool( cfg, "enable" );
	ret->host.host_name   = _cfg_get_str(cfg, "hostname");
	ret->host.port_number = cfg_getint( cfg,  "port" );

	return ret;
}

static inline dynamic_config_conf_t *_parse_dynamic_config_block( cfg_t *cfg ){
	cfg_t * c = _get_first_cfg_block( cfg, "dynamic-config" );
	if( c == NULL )
		return NULL;

	dynamic_config_conf_t *ret = alloc( sizeof( dynamic_config_conf_t ));

	ret->is_enable  = cfg_getbool( c, "enable" );
	ret->descriptor  = _cfg_get_str(c, "descriptor");

	return ret;
}


static inline multi_thread_conf_t * _parse_thread( cfg_t *cfg ){
	multi_thread_conf_t *ret = alloc( sizeof( multi_thread_conf_t ));
	ret->thread_count                  = cfg_getint( cfg, "thread-nb" );
	ret->thread_queue_packet_threshold = cfg_getint( cfg, "thread-queue" );
	return ret;
}

static inline behaviour_conf_t *_parse_behaviour_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "behaviour")) == NULL )
		return NULL;

	behaviour_conf_t *ret = alloc( sizeof( behaviour_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->directory = _cfg_get_str(cfg, "output-dir");
	return ret;
}

static inline void _parse_output_channel( output_channel_conf_t *out, cfg_t *cfg ){
	int nb_output_channel = cfg_size( cfg, "output-channel");
	int i;
	const char *channel_name;

	out->is_output_to_file  = true; //default is to output to file
	out->is_output_to_kafka = false;
	out->is_output_to_redis = false;

	for( i=0; i<nb_output_channel; i++) {
		channel_name = cfg_getnstr(cfg, "output-channel", i);
		if ( strncmp( channel_name, "file", 4 ) == 0 )
			out->is_output_to_file = true;
		else if ( strncmp( channel_name, "kafka", 5 ) == 0 )
			out->is_output_to_kafka = true;
		else if ( strncmp( channel_name, "redis", 5 ) == 0 )
			out->is_output_to_redis = true;
		else
			log_write( LOG_WARNING, "Unexpected channel %s", channel_name );
	}

	out->is_enable = (out->is_output_to_file || out->is_output_to_kafka || out->is_output_to_redis );
}

static inline system_stats_conf_t *_parse_cpu_mem_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "system-report")) == NULL )
		return NULL;

	system_stats_conf_t *ret = alloc( sizeof( system_stats_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->frequency = cfg_getint( cfg, "frequency" );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline void _parse_dpi_protocol_attribute( dpi_protocol_attribute_t * out, const char* str ){
	out->attribute_name = NULL;
	out->proto_name     = NULL;

	//str = HTTP.METHOD
	int index = 0;
	while( str[index] != '.' )
		index ++;
	out->proto_name     = strndup( str, index );
	out->attribute_name = strdup( str+index+1 ); //+1 to jump over .

}

static inline uint16_t _parse_attributes_helper( cfg_t *cfg, const char* name, dpi_protocol_attribute_t**atts ){
	int i;
	uint16_t size =  cfg_size( cfg, name );
	*atts = NULL;
	if( size == 0 )
		return size;

	dpi_protocol_attribute_t *ret = NULL;
	ret = alloc( sizeof( dpi_protocol_attribute_t ) * size );
	for( i=0; i<size; i++ )
		_parse_dpi_protocol_attribute( &ret[i], cfg_getnstr( cfg, name, i ) );

	*atts = ret;
	return size;
}




static inline void _parse_event_block( event_report_conf_t *ret, cfg_t *cfg ){
	int i;
	assert( cfg != NULL );
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->title     = strdup( cfg_title(cfg) );
	ret->event = alloc( sizeof( dpi_protocol_attribute_t ));
	_parse_dpi_protocol_attribute( ret->event, cfg_getstr( cfg, "event" ) );

	ret->attributes_size = _parse_attributes_helper( cfg, "attributes", &ret->attributes );

	_parse_output_channel( & ret->output_channels, cfg );
}

static inline micro_flow_conf_t *_parse_microflow_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "micro-flows")) == NULL )
		return NULL;

	micro_flow_conf_t *ret = alloc( sizeof( micro_flow_conf_t ));
	ret->is_enable             = cfg_getbool( cfg, "enable" );
	ret->include_bytes_count   = cfg_getint( cfg, "include-byte-count" );
	ret->include_packets_count = cfg_getint( cfg, "include-packet-count" );
	ret->report_bytes_count    = cfg_getint( cfg, "report-byte-count" );
	ret->report_flows_count    = cfg_getint( cfg, "report-flow-count" );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline radius_conf_t *_parse_radius_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "radius-output")) == NULL )
		return NULL;

	radius_conf_t *ret     = alloc( sizeof( radius_conf_t ));
	ret->is_enable         = cfg_getbool( cfg, "enable" );
	ret->include_msg       = cfg_getint( cfg, "include-msg" );
	ret->include_condition = cfg_getint( cfg, "include-condition" );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline security_conf_t *_parse_security_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "security")) == NULL )
		return NULL;

	security_conf_t *ret = alloc( sizeof( security_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->threads_size = cfg_getint( cfg, "thread-nb" );
	ret->excluded_rules = _cfg_get_str(cfg, "exclude-rules" );
	ret->rules_mask = _cfg_get_str(cfg, "rules-mask" );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline security_multi_sessions_conf_t *_parse_multi_session_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "security-report-multisession")) == NULL )
		return NULL;

	security_multi_sessions_conf_t *ret = alloc( sizeof( security_multi_sessions_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->attributes_size = _parse_attributes_helper(cfg, "attributes", &ret->attributes );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline session_report_conf_t *_parse_session_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "session-report")) == NULL )
		return NULL;

	session_report_conf_t *ret = alloc( sizeof( session_report_conf_t ));
	ret->is_enable = cfg_getbool( cfg, "enable" );
	ret->is_ftp    = cfg_getbool( cfg, "ftp" );
	ret->is_rtp    = cfg_getbool( cfg, "rtp" );
	ret->is_http   = cfg_getbool( cfg, "http" );
	ret->is_ssl    = cfg_getbool( cfg, "ssl" );
	_parse_output_channel( & ret->output_channels, cfg );
	return ret;
}

static inline session_timeout_conf_t *_parse_session_timeout_block( cfg_t *cfg ){
	if( (cfg = _get_first_cfg_block( cfg, "session-timeout")) == NULL )
		return NULL;

	session_timeout_conf_t *ret = alloc( sizeof( session_timeout_conf_t ));
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

	socket_output_conf_t *ret = alloc( sizeof( socket_output_conf_t ));
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

		if( strcmp(name, cfg_title(c) ) != 0 )
			continue;

		DEBUG( "Parsing block 'reconstruct-data %s'", name );

		reconstruct_data_conf_t *ret = alloc( sizeof( reconstruct_data_conf_t ));
		ret->is_enable = cfg_getbool( c, "enable" );
		ret->directory = _cfg_get_str(c, "output-dir" );
		_parse_output_channel( & ret->output_channels, c );
		return ret;
	}
	return NULL;
}
/**
 * Public API
 * @param filename
 * @return
 */
probe_conf_t* load_configuration_from_file( const char* filename ){
	const char *str;
	int i;
	cfg_t *cfg = _load_cfg_from_file( filename );
	if( cfg == NULL ){
		return NULL;
	}

	probe_conf_t *conf = alloc( sizeof( probe_conf_t ) );

	conf->probe_id     = cfg_getint(cfg, "probe-id");
	conf->stat_period  = cfg_getint(cfg, "stats-period");
	conf->outputs.format  = cfg_getint(cfg, "output-format");
	conf->license_file = _cfg_get_str(cfg, "license" );
	conf->is_enable_proto_no_session_stat = cfg_getbool(cfg, "enable-proto-without-session-report");
	conf->is_enable_ip_fragementation     = cfg_getbool(cfg, "enable-ip-fragmentation-report");

	conf->input = _parse_input_source( cfg );
	//set of output channels
	conf->outputs.file  = _parse_output_to_file( cfg );
	conf->outputs.kafka = _parse_output_to_kafka( cfg );
	conf->outputs.redis = _parse_output_to_redis( cfg );
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
	conf->reports.events  = alloc( sizeof( event_report_conf_t ) * conf->reports.events_size );
	for( i=0; i<conf->reports.events_size; i++ )
		_parse_event_block( &conf->reports.events[i], cfg_getnsec( cfg, "event-report", i) );

	//
	conf->reports.microflow = _parse_microflow_block( cfg );

	conf->reports.radius = _parse_radius_block( cfg );
	conf->reports.security = _parse_security_block( cfg );
	conf->reports.security_multisession = _parse_multi_session_block( cfg );
	conf->reports.session = _parse_session_block( cfg );
	conf->reports.socket = _parse_socket_block( cfg );

	conf->reports.data_dump = _parse_dump_to_file(cfg);

	conf->session_timeout = _parse_session_timeout_block( cfg );

	//
	conf->reconstructions.ftp = _parse_reconstruct_data_block(cfg, "ftp");
	conf->reconstructions.http = _parse_reconstruct_data_block(cfg, "http");
	conf->reconstructions.tcp = _parse_reconstruct_data_block(cfg, "tcp");
	cfg_free( cfg );
	return conf;
}

static inline void _free_event_report( event_report_conf_t *ret ){
	if( ret == NULL )
		return;
	int i;
	for( i=0; i<ret->attributes_size; i++ ){
		xfree( ret->attributes[i].proto_name );
		xfree( ret->attributes[i].attribute_name );
	}
	xfree( ret->attributes );
	xfree( ret->title );
	xfree( ret->event->proto_name );
	xfree( ret->event->attribute_name );
	xfree( ret->event );
}

/**
 * Public API
 * Free all memory allocated by @load_configuration_from_file
 * @param
 */
void release_probe_configuration( probe_conf_t *conf){
	if( conf == NULL )
		return;

	int i;

	xfree( conf->input->input_source );
	xfree( conf->input );

	for( i=0; i<conf->reports.events_size; i++ )
		_free_event_report( &conf->reports.events[i] );
	xfree( conf->reports.events );

	if( conf->reports.behaviour ){
		xfree( conf->reports.behaviour->directory );
		xfree( conf->reports.behaviour );
	}

	xfree( conf->reports.cpu_mem );
	xfree( conf->reports.microflow );
	xfree( conf->reports.radius );

	if( conf->reports.security ){
		xfree( conf->reports.security->excluded_rules );
		xfree( conf->reports.security->rules_mask );
		xfree( conf->reports.security );
	}

	if( conf->reports.security_multisession ){
		for( i=0; i<conf->reports.security_multisession->attributes_size; i++ ){
			xfree( conf->reports.security_multisession->attributes[i].proto_name );
			xfree( conf->reports.security_multisession->attributes[i].attribute_name );
		}
		xfree( conf->reports.security_multisession->attributes );
		xfree( conf->reports.security_multisession );
	}
	xfree( conf->reports.session );

	if( conf->reports.socket ){
		xfree( conf->reports.socket->unix_socket_descriptor );
		for( i=0; i<conf->reports.socket->internet_sockets_size; i++){
			//xfree(conf->reports.socket->internet_sockets[i].host.host_name );
		}
		xfree( conf->reports.socket->internet_sockets );
		xfree( conf->reports.socket );
	}

	if( conf->reconstructions.ftp ){
		xfree( conf->reconstructions.ftp->directory );
		xfree( conf->reconstructions.ftp );
	}
	if( conf->reconstructions.http ){
		xfree( conf->reconstructions.http->directory );
		xfree( conf->reconstructions.http );
	}

	xfree( conf->thread );
	if( conf->outputs.file ){
		xfree( conf->outputs.file->directory );
		xfree( conf->outputs.file->filename );
		xfree( conf->outputs.file );
	}
	if( conf->outputs.kafka ){
		xfree( conf->outputs.kafka->host.host_name );
		xfree( conf->outputs.kafka );
	}
	if( conf->outputs.redis ){
		xfree( conf->outputs.redis->host.host_name );
		xfree( conf->outputs.redis );
	}

	xfree( conf->session_timeout );

	xfree( conf->license_file );
	xfree( conf );
}
