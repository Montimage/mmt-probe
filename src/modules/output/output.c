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

///////////////////////////// Funtions for DYNABIC //////////////////////////////////

typedef struct attack_info{
    const char *rule_id;
	const char *uc;
	const char *event_uuid;
	const char *attack_uuid;
    const char *attack_name;
	const char *mitre_ttp_id;
	const char *ttp_name; 
} attack_info_t;

const attack_info_t attack_info_list[] = {
    {"201", "uc1", "9ad941d2-526d-4988-ba62-d9870569b603", "9b497c8c-36be-4fd6-91ce-a6bffe5d935c", "cyberattack_ocpp16_dos_flooding_heartbeat", "T1498", "Network Denial of Service"},
	{"202", "uc1", "28beb0a3-069f-44bb-b2d7-4c9490284e83", "28beb0a3-069f-44bb-b2d7-4c9490284e83", "cyberattack_ocpp16_fdi_chargingprofile", "T1565", "Charging Profile Manipulation"},
	{"203", "uc2", "b75fbd14-8623-446c-8847-d42fdadbc193", "92d2178d-1887-4075-b847-81f9513e712c", "PHP_insecure_intrusion", "T1190", "Exploit public-facing web applications"},
	{"204", "uc2", "b75fbd14-8623-446c-8847-d42fdadbc193", "92d2178d-1887-4075-b847-81f9513e712c", "smb_intrusion", "T1003", "OS Credential Dumping"},
	{"210", "uc2", "b75fbd14-8623-446c-8847-d42fdadbc193", "92d2178d-1887-4075-b847-81f9513e712c", "rdp_intrusion", "T1110", "Brute Force"},
	{"211", "uc2", "b75fbd14-8623-446c-8847-d42fdadbc193", "92d2178d-1887-4075-b847-81f9513e712c", "ssh_intrusion", "T1078", "Valid Accounts"},
	//{"204", "28beb0a3-069f-44bb-b2d7-4c9490284e83", "lockbit_execution", "", ""},
	//{"205", "123e4567-e89b-12d3-a456-426614174122", "pac_server_dos", "T1498", "Network Denial of Service"},
	{"206", "uc4", "9facae2f-7628-4090-9052-1141dbb47e38", "9f83bc19-f76b-47e7-ad4d-01caf1a6dad0", "pacs_server_ddos", "T1498", "Network Denial of Service"},
    {"207", "uc4", "7406f73-bc3d-4e37-87e6-d955ed0a5dec", "33795917-9bb2-4ec0-9c6d-67ebcbd18d9a", "lockbit_execution", "", "Lockbit Execution attack"},
	{NULL, NULL, NULL, NULL, NULL, NULL} // Sentinel value to indicate the end of the dictionary
};

typedef struct asset_uuid_ip{
	const char *uc;
    const char *ip;
	const char *uuid;
} asset_uuid_ip_t;

const asset_uuid_ip_t asset_list[] = {
    {"uc1", "10.250.100.52", "cf8601c0-6cfc-4f86-8725-3a6c8c8b9f2b"},
	{"uc1", "192.168.21.22", "r5gj12ax-b83m-3200-5121-kv34uik9k8l4"},
	{"uc1", "192.168.21.210", "540f782a-fc1f-4830-8b52-4b52c8f06ff6"},
	{"uc1", "192.168.21.212", "453c592f-9197-42f2-b292-f817b3424128"},
	{"uc1", "192.168.21.206", "83c1afe9-b342-4d2b-aed4-0d9ec76f5450"},
	{"uc1", "192.168.21.222", "e3bc13aa-c00b-4099-9883-a2e58ec4e6e5"},
	{"uc2", "37.146.34.63", "7a20840f-cbd8-44c7-9ec1-ccd8b23925fa"},
	{"uc2", "131.132.36.182", "91ea1603-65a9-4aee-aeb9-0a63e03a871a"},
	{"uc2", "37.146.34.9", "4bebb167-52e4-405a-a6f4-ca4c15c9b197"},
	{"uc2", "37.146.34.53", "992337c6-3115-4cab-a9ca-6c5c50605e5"},
	{"uc2", "37.146.34.33", "a8645120-c1d2-44b1-8606-480be93cd33e"},
	{"uc2", "37.146.34.29", "a1650f87-14cf-4b31-8e8e-835e5d8325e6"},
	{"uc2", "37.146.34.51", "47323158-e850-4864-9cfb-20edf90c8ba5"},
	{"uc2", "37.146.58.180", "0e62e887-a3c3-4c6b-9544-6204dee96e34"},
	{"uc2", "37.146.34.50", "84dbdef4-09e0-47ad-8a5b-94514af0a3dd"},
	{"uc2", "131.132.36.73", "c5a8f317-d636-422e-996e-0edf442d4768"},
	{"uc2", "37.130.2.202", "7230a09a-50d6-41f1-a038-a56b673ab094"},
	{"uc2", "37.146.35.203", "b72f70b5-4d28-4565-a558-5f733d12018b"},
	{"uc2", "37.146.35.211", "ae6do5ee-89ee-1202-c585-adee28000adb"},
	{"uc2", "37.146.35.197", "d77e89aa-11ec-aea8-du7e-abe13dac0i72"},
	{"uc2", "37.146.35.195", "1aeb9f0e-8da8-1230-ef2b-9a35aedb010f"},
	{"uc4", "192.168.61.50", "e81ffd6a-1ee3-408c-9747-7ada293d9ac4"},
	{"uc4", "192.168.62.100", "422e8e2a-c635-4b19-84b2-b4d097667026"},
	{"uc4", "192.168.61.54", "9a07fb6a-ecfa-4b29-bcbd-4ff6b2aad072"},
	{NULL, NULL, NULL} // Sentinel value to indicate the end of the dictionary
};

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
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S", &tm);
	
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
    for (int i = 0; attack_info_list[i].rule_id != NULL; i++) {
        if (strcmp(attack_info_list[i].rule_id, rule_id) == 0) {
            return &attack_info_list[i];
        }
    }
    return NULL; // Key not found
}

const char* get_uuid_by_ip_usecase(const char *uc, const char *ip) {
    if (uc == NULL || ip == NULL) {
        return "";
    }    
    for (int i = 0; asset_list[i].uc != NULL; i++) {
        if (strcmp(asset_list[i].uc, uc) == 0 && 
            strcmp(asset_list[i].ip, ip) == 0) {
            return asset_list[i].uuid;
        }
    }
    return ""; // Not found
}

// static const char* search_uuid_by_python_script(const char *python_path, const char *gml_file_path, const char *ip_addr){
// 	char command[512];
//     char result[64];

//     // Format the command to call the Python script
//     snprintf(command, sizeof(command),
//              "bash -c 'cd /home/pqv/Documents/ocpp/ && source .venv/bin/activate && python3 %s %s %s'",
//              python_path, gml_file_path, ip_addr);

//     // Open a pipe to read the output of the Python script
//     FILE *fp = popen(command, "r");
//     if (fp == NULL) {
//         fprintf(stderr, "Failed to run Python script.\n");
//         return NULL;
//     }

//     // Read the prediction from the script output
//     if (fgets(result, sizeof(result), fp) != NULL) {
// 		pclose(fp);
// 		if (strlen(result) == 0) {
// 			return "";
// 		}
//         // Allocate memory for the result and copy the string
// 		//printf("The input ip is %s found uuid is %s\n", ip_addr, result);
//         char *dynamic_result = malloc(strlen(result) + 1);
//         if (dynamic_result == NULL) {
//             fprintf(stderr, "Memory allocation failed.\n");
//             return NULL;
//         }
//         strcpy(dynamic_result, result);
//         return dynamic_result;
//     }
// 	pclose(fp);
// 	return NULL;
// }

static void generate_uuid(char* uuid_str) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
}

static int construct_alert_stix_format(
	const char* message_body,
	const struct timeval* ts,
	char* message, size_t message_size
){
	if (!message_body || !message) return -1;

	char *rule_id = NULL;

	if ( message_body != NULL ){
		rule_id = extract_substring_with_delimiter(message_body, ',', 0);
	}

	if( rule_id == NULL ){
		return -1;
	}

	if (strcmp(rule_id, "201") == 0 ||
		strcmp(rule_id, "202") == 0 ||
		strcmp(rule_id, "203") == 0 ||
		strcmp(rule_id, "204") == 0 ||
		strcmp(rule_id, "210") == 0 ||
		strcmp(rule_id, "211") == 0 ||
		//strcmp(rule_id, "204") == 0 ||
		//strcmp(rule_id, "205") == 0 ||
		strcmp(rule_id, "206") == 0 ||
		strcmp(rule_id, "207") == 0) {

		// Generate UUIDs
		char bundle_uuid[37], identity_uuid[37];
		generate_uuid(bundle_uuid);
		generate_uuid(identity_uuid);
		//char observed_uuid[37];
		//const char* identity_uuid = "4e05ef27-91ea-49a2-bc97-557af4598980";
		//generate_uuid(observed_uuid);

		// Extract attack info
		attack_info_t* info = get_attack_info(rule_id);
		if (!info) return -1;
		
		const char* uc = info->uc;
		const char* event_uuid = info->event_uuid;
		const char* attack_uuid = info->attack_uuid;
		const char* ttp_id = info->mitre_ttp_id;
		const char* attack_name = info->attack_name;

		// Description from MMT
		const char* description = extract_substring_with_delimiter(message_body, ',', 3);
		
		// IP asset uuid
		const char* src_ip = extract_substring_between(message_body, "\"ocpp_data.src_ip\",\"", "\"]");
		const char* dst_ip = extract_substring_between(message_body, "\"ocpp_data.dst_ip\",\"", "\"]");

		int simulated_id = 0;
		if (!src_ip && !dst_ip) {
			src_ip = extract_substring_between(message_body, "\"cicflow_data.Src_IP\",\"", "\"]");
			dst_ip = extract_substring_between(message_body, "\"cicflow_data.Dst_IP\",\"", "\"]");
		}

		const char* src_asset_uuid = get_uuid_by_ip_usecase(uc, src_ip);
		const char* dst_asset_uuid = get_uuid_by_ip_usecase(uc, dst_ip);

		const char* simulated_id_str = extract_substring_between(message_body, "\"ocpp_data.simulation_id\",", "]");
		if( simulated_id_str != NULL ){
			simulated_id = atoi(simulated_id_str);
		}

		// simulated_id = 1;

		// Simulation ID
		char simulation[256];
		if (simulated_id == 0)
			snprintf(simulation, sizeof(simulation), "Real attack");
		else
			snprintf(simulation, sizeof(simulation), "Simulated attack", simulated_id);

		// Timestamp
		char timestamp[30];
		format_timeval_iso8601(ts, 1, timestamp, sizeof(timestamp));

		// Construct message
		snprintf(
			message, message_size,
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
			event_uuid, timestamp, timestamp, timestamp, timestamp,
			src_asset_uuid, dst_asset_uuid, attack_uuid, identity_uuid, description,
			src_asset_uuid, src_ip,
			dst_asset_uuid, dst_ip,
			attack_uuid, attack_name, timestamp, timestamp, simulation, ttp_id, ttp_id
		);
		return 1;
	}
	return 0;
}

///////////////////////////// Funtions for DYNABIC //////////////////////////////////

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
	int message_constucted = 0;

/////////////////////// DYNABIC ////////////////////////////
#ifdef STIX_FORMAT
	message_constucted = construct_alert_stix_format(message_body, ts, message, sizeof(message));
	// if output->config->kafka->topic_name contains dahsboard_alerts, we force to use normal format
	if (strstr( output->config->kafka->topic_name, "dashboard_alerts") != NULL) {
		message_constucted = 0;
	}
#endif
/////////////////////// DYNABIC	////////////////////////////
	
	if( message_constucted != 1 ){	//Other data used the same output format
	
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
