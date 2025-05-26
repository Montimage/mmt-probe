/*
 * output.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */
#include <stdarg.h>
#include <pthread.h>
#include <uuid/uuid.h>
#include <time.h>

#include "../../configure.h"

#include "output.h"

#include "../../lib/string_builder.h"
#include "../../lib/malloc.h"
#include "../../lib/memory.h"
#include "file/file_output.h"
#include "kafka/kafka_output.h"
#include "socket/socket_output.h"
#include "mongodb/mongodb.h"
#include "redis/redis.h"

struct output_struct{
	uint16_t index;
	uint32_t probe_id;
	const char*input_src;
	struct timeval last_report_ts;
	const struct output_conf_struct *config;

	//mutex is used only in multi-threading output
	pthread_mutex_t *mutex;

	struct output_modules_struct{
		file_output_t *file;
		IF_ENABLE_REDIS(   redis_output_t *redis; )
		IF_ENABLE_KAFKA(   kafka_output_t *kafka; )
		IF_ENABLE_MONGODB( mongodb_output_t *mongodb; )
		IF_ENABLE_SOCKET(  socket_output_t *socket; )
	}modules;
};

/*
 * Only for ocpp_data: 
 * A dictionary-type struct to include the attack name if needed
 */

typedef struct attack_info{
    const char *rule_id;
	const char *attack_uuid;
    const char *attack_name;
	const char *mitre_ttp_id;
	const char *ttp_name; 
} attack_info_t;

const attack_info_t attack_name[] = {
    {"201", "9b497c8c-36be-4fd6-91ce-a6bffe5d935c", "cyberattack_ocpp16_dos_flooding_heartbeat", "T1498", "Network Denial of Service"},
	{"202", "28beb0a3-069f-44bb-b2d7-4c9490284e83", "cyberattack_ocpp16_fdi_chargingprofile", "T1565", "Charging Profile Manipulation"},
	//{"204", "28beb0a3-069f-44bb-b2d7-4c9490284e83", "lockbit_execution", "", ""},
	//{"205", "123e4567-e89b-12d3-a456-426614174122", "pac_server_dos", "T1498", "Network Denial of Service"},
	{"206", "9facae2f-7628-4090-9052-1141dbb47e38", "pac_server_dos", "T1498", "Network Denial of Service"},
    {"207", "7406f73-bc3d-4e37-87e6-d955ed0a5dec", "lockbit_execution", "", "Lockbit Execution attack"},
	{NULL, NULL, NULL, NULL, NULL} // Sentinel value to indicate the end of the dictionary
};


//public API
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src, bool is_multi_threads ){
	int i;
	if( ! config->is_enable )
		return NULL;

	output_t *ret  = mmt_alloc_and_init_zero( sizeof( output_t ));
	ret->config    = config;
	ret->index     = output_id;
	ret->input_src = input_src;
	ret->probe_id  = probe_id;

	//When using output in multi-threads, we need to synchronize their function calls by mutex
	if( is_multi_threads ){
		ret->mutex = malloc( sizeof(pthread_mutex_t) );
		pthread_mutex_init(ret->mutex, NULL);
	}else
		ret->mutex = NULL;

	if( ! ret->config->is_enable )
		return ret;


	/*
	 * Initialize the output channels
	 * The result must be NULL if output is disable to its channel,
	 * for example: ret->modules.file must be NULL if file-output.enable=false
	 */

	ret->modules.file = file_output_alloc_init( ret->config->file, output_id );

#ifdef REDIS_MODULE
	ret->modules.redis = redis_init( ret->config->redis );
#endif

#ifdef KAFKA_MODULE
	ret->modules.kafka = kafka_output_init( ret->config->kafka );
#endif

#ifdef MONGODB_MODULE
	ret->modules.mongodb = mongodb_output_alloc_init( ret->config->mongodb, ret->config->cache_max, output_id );
#endif

#ifdef SOCKET_MODULE
	ret->modules.socket = socket_output_init( ret->config->socket );
#endif
	return ret;
}

/**
 * Write an entire report to output channels
 * @param output
 * @param channels
 * @param message
 * @return
 */
static inline int _write( output_t *output, output_channel_conf_t channels, const char *message, bool raw ){
	int ret = 0;
	char new_msg[ MAX_LENGTH_REPORT_MESSAGE ];

	//we surround message inside [] to convert it to JSON
	//this needs to be done when:
	//- output format is JSON,
	//- or when we need to output to MongoDB
	if( (output->config->format == OUTPUT_FORMAT_JSON && !raw)
#ifdef MONGODB_MODULE
			|| (output->modules.mongodb && IS_ENABLE_OUTPUT_TO( MONGODB, channels ) )
#endif
			){

		//surround message by [ and ]
		new_msg[0] = '[';
		size_t len = strlen( message );
		memcpy( new_msg + 1, message, len );
		new_msg[ len+1 ] = ']';
		new_msg[ len+2 ] = '\0';

		//use new_msg when output format is JSON
		if( output->config->format == OUTPUT_FORMAT_JSON )
			message = new_msg;
	}
	//output to stdout
	if( IS_ENABLE_OUTPUT_TO( STDOUT, channels) ){
		fprintf( stdout, "%s\n", message );
		ret ++;
	}
	//output to file
	if( IS_ENABLE_OUTPUT_TO( FILE, channels )){
		file_output_write( output->modules.file, message );
		ret ++;
	}

#ifdef KAFKA_MODULE
	//output to Kafka
	if( output->modules.kafka && IS_ENABLE_OUTPUT_TO( KAFKA, channels )){
		ret += kafka_output_send( output->modules.kafka, message );
	}
#endif

#ifdef REDIS_MODULE
	//output to redis
	if( output->modules.redis && IS_ENABLE_OUTPUT_TO( REDIS, channels )){
		ret += redis_send( output->modules.redis, message );
	}
#endif

#ifdef MONGODB_MODULE
	if( output->modules.mongodb && IS_ENABLE_OUTPUT_TO( MONGODB, channels )){
		//here we output new_msg (not message)
		mongodb_output_write( output->modules.mongodb, new_msg );
		ret ++;
	}
#endif

#ifdef SOCKET_MODULE
	if( output->modules.socket && IS_ENABLE_OUTPUT_TO( SOCKET, channels )){
		ret += socket_output_send( output->modules.socket, message );
	}
#endif
	return ret;
}

char *extract_substring_with_delimiter(const char *str, char delimiter, int n) {
    if (!str || n < 0) return NULL;
    const char *start = str;
    const char *end = NULL;
    int count = 0;

    // Locate the nth delimiter
    while (*str) {
        if (*str == delimiter) {
            if (count == n) {
                end = str;
                break;
            }
            start = str + 1;
            count++;
        }
        str++;
    }

    // If n is the last delimiter, return the substring after it
    if (count == n && !end) {
        return (*start) ? strdup(start) : NULL;
    }

    // If there are not enough delimiters
    if (count < n) return NULL;

    // Allocate and copy the substring
    int length = (end) ? (end - start) : strlen(start);
    char *result = (char *)malloc(length + 1);
    if (!result) return NULL;

    strncpy(result, start, length);
    result[length] = '\0';

    return result;
}

void format_timeval_iso8601(const struct timeval *ts, int utc_timezone, char *buffer, size_t buffer_size) {
    // Convert timeval to struct tm in UTC
    struct tm tm;
    gmtime_r(&ts->tv_sec, &tm);

    // Adjust for UTC+1 timezone
    tm.tm_hour += utc_timezone;

    // Normalize the time structure in case of overflow (e.g., adding an hour might change the date)
    mktime(&tm);

    // Format date and time without fractional seconds
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &tm);
	
	size_t len = strlen(buffer);
    snprintf(buffer + len, buffer_size - len, ".%03ldZ", ts->tv_usec / 1000);
}

static inline char *extract_substring_between(const char *main_str, const char *start_sub, const char *end_sub) {
    if (!main_str || !start_sub || !end_sub) {
        // Handle null pointers
        return NULL;
    }

    // Find the start of the start_sub in main_str
    const char *start_pos = strstr(main_str, start_sub);
    if (!start_pos) {
        // start_sub not found, return NULL
        return NULL;
    }

    // Move the pointer to the end of start_sub
    start_pos += strlen(start_sub);

    // Find the start of the end_sub in main_str after the start_pos
    const char *end_pos = strstr(start_pos, end_sub);
    if (!end_pos) {
        // end_sub not found, return NULL
        return NULL;
    }

    // Calculate the length of the substring to extract
    size_t substring_length = end_pos - start_pos;

    // Allocate memory for the result substring (+1 for null terminator)
    char *result = (char *)malloc(substring_length + 1);
    if (!result) {
        // Memory allocation failed
        return NULL;
    }

    // Copy the substring into the allocated memory
    strncpy(result, start_pos, substring_length);
    result[substring_length] = '\0'; // Null-terminate the string

    return result;
}

static attack_info_t* get_attack_info(const char *rule_id) {
    for (int i = 0; attack_name[i].rule_id != NULL; i++) {
        if (strcmp(attack_name[i].rule_id, rule_id) == 0) {
            return &attack_name[i];
        }
    }
    return NULL; // Key not found
}

static const char* search_uuid_by_python_script(const char *python_path, const char *gml_file_path, const char *ip_addr){
	char command[512];
    char result[64];

    // Format the command to call the Python script
    snprintf(command, sizeof(command),
             "bash -c 'cd /home/pqv/Documents/ocpp/ && source .venv/bin/activate && python3 %s %s %s'",
             python_path, gml_file_path, ip_addr);

    // Open a pipe to read the output of the Python script
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run Python script.\n");
        return NULL;
    }

    // Read the prediction from the script output
    if (fgets(result, sizeof(result), fp) != NULL) {
		pclose(fp);
		if (strlen(result) == 0) {
			return "";
		}
        // Allocate memory for the result and copy the string
		//printf("The input ip is %s found uuid is %s\n", ip_addr, result);
        char *dynamic_result = malloc(strlen(result) + 1);
        if (dynamic_result == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            return NULL;
        }
        strcpy(dynamic_result, result);
        return dynamic_result;
    }
	pclose(fp);
	return NULL;
}

void generate_uuid(char* uuid_str) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
}

/*
 * This macro is used to synchronize only when using in multi-threading,
 * i.e., (output->mutex != NULL)
 * The code after calling this macro is ensured thread-safe.
 * __UNLOCK macro must be called before any return.
 *
 * Currently we need to lock only when security is enable.
 */
#define __LOCK_IF_NEED( output )                        \
	while( output->mutex != NULL &&                     \
		pthread_mutex_lock( output->mutex ) != 0 );     \
/*
 * This macro unlocks the mutex being locked by the macro above.
 */
#define __UNLOCK_IF_NEED( output )                      \
	while( output->mutex != NULL &&                     \
		pthread_mutex_unlock( output->mutex ) != 0 );   \


//public API
int output_write_report( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* message_body){

	__LOCK_IF_NEED( output );

	//global output is disable or no output on this channel
	if( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| IS_DISABLE_OUTPUT( channels ) ){
		__UNLOCK_IF_NEED( output );
		return 0;
	}

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;
	
	//Need to handle ocpp_data specifically because the output format will be different for this case
	char *rule_id = NULL;
	int message_constucted = 0;

	if ( message_body != NULL ){
		rule_id = extract_substring_with_delimiter(message_body, ',', 0);
	}

	if( rule_id == NULL ){
		__UNLOCK_IF_NEED( output );
		return 0;
	}

#ifdef STIX_FORMAT
	if (strcmp(rule_id, "201") == 0 ||
		strcmp(rule_id, "202") == 0 ||
		strcmp(rule_id, "204") == 0 ||
		strcmp(rule_id, "205") == 0 ||
		strcmp(rule_id, "206") == 0 ||
		strcmp(rule_id, "207") == 0) {

		char bundle_uuid[37], identity_uuid[37], observed_uuid[37];
		generate_uuid(bundle_uuid);
		generate_uuid(identity_uuid);
    	generate_uuid(observed_uuid);
		
		// Attack info
		attack_info_t* info = get_attack_info(rule_id);
		const char* attack_uuid = info->attack_uuid;
		const char* ttp_id = info->mitre_ttp_id;
		const char* mitre_ttp_name = info->ttp_name;
		const char* attack_name = info->attack_name;
		int simulated_id = 0;
		// Description from MMT
		const char* description = extract_substring_with_delimiter(message_body, ',', 3);
		
		// IP asset uuid
		const char* src_ip = extract_substring_between(message_body, "\"ocpp_data.src_ip\",\"", "\"]");
		const char* dst_ip = extract_substring_between(message_body, "\"ocpp_data.dst_ip\",\"", "\"]");
		if (src_ip == NULL && dst_ip == NULL) {
			src_ip = extract_substring_between(message_body, "\"cicflow_data.Src_IP\",\"", "\"]");
			dst_ip = extract_substring_between(message_body, "\"cicflow_data.Dst_IP\",\"", "\"]");
			simulated_id = -1;
		}
		//const char* src_asset_uuid = "123e4567-e89b-12d3-a456-426614174008";
		//const char* dst_asset_uuid = "123e4567-e89b-12d3-a456-426614174009";		
		const char* src_asset_uuid = "123e4567-e89b-12d3-a456-000000000000";
		const char* dst_asset_uuid = "123e4567-e89b-12d3-a456-000000000001";	

		// Simulation ID
		char simulation[256];
		if (simulated_id == -1) {
			snprintf(simulation, sizeof(simulation), "Real attack");
		} else {
			snprintf(simulation, sizeof(simulation), "Simulated attack with id %d", simulated_id);
		}
		
		// Timestamp
		char timestamp[30];
		format_timeval_iso8601(ts, 1, timestamp, sizeof(timestamp));

		snprintf(
			message, 8192,
			"{\n"
			"    \"type\": \"bundle\",\n"
			"    \"id\": \"bundle--%s\",\n"
			"    \"objects\": [\n"
			"      {\n"
			"        \"type\": \"identity\",\n"
			"        \"spec_version\": \"2.1\",\n"
			"        \"id\": \"identity--%s\",\n"
			"        \"created\": \"%s\",\n"
			"        \"modified\": \"%s\",\n"
			"        \"name\": \"MMT-PROBE\",\n"
			"        \"identity_class\": \"organization\",\n"
			"        \"extensions\": {\n"
			"          \"x-probe-id-ext\": {\n"
			"            \"extension_type\": \"property-extension\",\n"
			"            \"probe-id\": \"MMT-PROBE-1\"\n"
			"          }\n"
			"        }\n"
			"      },\n"
			"      {\n"
			"        \"type\": \"observed-data\",\n"
			"        \"spec_version\": \"2.1\",\n"
			"        \"id\": \"observed-data--%s\",\n"
			"        \"created\": \"%s\",\n"
			"        \"modified\": \"%s\",\n"
			"        \"first_observed\": \"%s\",\n"
			"        \"last_observed\": \"%s\",\n"
			"        \"number_observed\": 1,\n"
			"        \"object_refs\": [\n"
			"          \"ipv4-addr--%s\",\n"
			"          \"ipv4-addr--%s\",\n"
			"          \"x-attack-type--%s\"\n"
			"        ],\n"
			"        \"created_by_ref\": \"identity--%s\",\n"
			"        \"extensions\": {\n"
			"            \"x-observed-data-ext\": {\n"
			"                \"extension_type\": \"property-extension\",\n"
			"                \"description\": %s\n"
			"            }\n"
			"        }\n"
			"      },\n"
			"      {\n"
			"        \"type\": \"ipv4-addr\",\n"
			"        \"id\": \"ipv4-addr--%s\",\n"
			"        \"value\": \"%s\"\n"
			"      },\n"
			"      {\n"
			"        \"type\": \"ipv4-addr\",\n"
			"        \"id\": \"ipv4-addr--%s\",\n"
			"        \"value\": \"%s\"\n"
			"      },\n"
			"      {\n"
			"        \"type\": \"x-attack-type\",\n"
			"        \"id\": \"x-attack-type--%s\",\n"
			"        \"user_id\": \"%s\",\n"
			"        \"created\":  \"%s\",\n"
			"        \"modified\":  \"%s\",\n"
			"        \"extensions\": {\n"
			"          \"x-attack-type-ext\": {\n"
			"            \"extension_type\": \"new-sdo\"\n"
			"          },\n"
			"          \"x-simulation-ext\": {\n"
			"            \"extension_type\": \"property-extension\",\n"
			"            \"simulation\": \"%s\"\n"
			"          }\n"
			"        },\n"
			"        \"external_references\": [\n"
			"          {\n"
			"            \"source_name\": \"mitre-attack\",\n"
			"            \"url\": \"https://attack.mitre.org/techniques/%s/\",\n"
			"            \"external_id\": \"%s\"\n"
			"          }\n"
			"        ]\n"
			"      }\n"
			"    ]\n"
			"  }",
			bundle_uuid, identity_uuid, timestamp, timestamp,
			observed_uuid, timestamp, timestamp, timestamp, timestamp,
			src_asset_uuid, dst_asset_uuid, attack_uuid, identity_uuid, description,
			src_asset_uuid, src_ip,
			dst_asset_uuid, dst_ip,
			attack_uuid, attack_name, timestamp, timestamp, simulation, ttp_id, ttp_id
		);

		message_constucted = 1;
	}
#endif
	
	if( !message_constucted ){	//Other data used the same output format
	
		STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_FULL_PATH_FILE_NAME, ",",
			__INT( report_type ),
			__INT( output->probe_id ),
			__STR( output->input_src ),
			__TIME( ts )
		);

		if( message_body != NULL ){
			message[ offset ++ ] = ',';
			size_t len = strlen( message_body );
			if( len > MAX_LENGTH_REPORT_MESSAGE - offset )
				len = MAX_LENGTH_REPORT_MESSAGE - offset;
			memcpy( message+offset, message_body, len );
			message[ offset + len ] = '\0';
		}
	}

	int ret = _write( output, channels, message, false );
	output->last_report_ts.tv_sec  = ts->tv_sec;
	output->last_report_ts.tv_usec = ts->tv_usec;

	__UNLOCK_IF_NEED( output );
	return ret;
}

//public API
int output_write_report_with_format( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...){

	__LOCK_IF_NEED( output );
	//global output is disable or no output on this channel
	if( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| IS_DISABLE_OUTPUT( channels ) ){
		__UNLOCK_IF_NEED( output );
		return 0;
	}
	//we need to unlock here as hereafter are thread-safe
	//otherwise there will be a deadlock as there will be a lock in @output_write_report
	__UNLOCK_IF_NEED( output );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset, ret;

	if( unlikely( format == NULL )){
		ret = output_write_report( output, channels, report_type, ts, NULL);
	} else {
		va_list args;
		offset = 0;
		va_start( args, format );
		offset += vsnprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, format, args);
		va_end( args );

		message[ offset ] = '\0'; //well null-terminated
		ret = output_write_report( output, channels, report_type, ts, message );
	}

	return ret;
}

//public API
int output_write( output_t *output, output_channel_conf_t channels, const char *message ){
	int ret;
	__LOCK_IF_NEED( output );

	//global output is disable or no output on this channel
	if( ! output || ! output->config->is_enable || IS_DISABLE_OUTPUT(channels ))
		ret = 0;
	else
		ret = _write( output, channels, message, true );

	__UNLOCK_IF_NEED( output );
	return ret;
}

//public API
void output_flush( output_t *output ){
	if( !output )
		return;

	__LOCK_IF_NEED( output );

	if( output->modules.file )
		file_output_flush( output->modules.file );

	fflush(stdout);

#ifdef MONGODB_MODULE
	if( output->modules.mongodb
			&& output->config->mongodb->is_enable )
		mongodb_output_flush_to_database( output->modules.mongodb );
#endif

	__UNLOCK_IF_NEED( output );
}

//public API
void output_release( output_t * output){
	if( !output ) return;

	fflush(stdout);
	file_output_release( output->modules.file );

	IF_ENABLE_MONGODB( mongodb_output_release( output->modules.mongodb ); )
	IF_ENABLE_KAFKA( kafka_output_release( output->modules.kafka ); )
	IF_ENABLE_REDIS( redis_release( output->modules.redis ); )
	IF_ENABLE_SOCKET( socket_output_release( output->modules.socket ); )

	if( output->mutex ){
		pthread_mutex_destroy( output->mutex );
		mmt_probe_free( output->mutex );
	}
	mmt_probe_free( output );
}
