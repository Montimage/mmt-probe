/*
 * stix_alert.c
 *
 *  Created on: Feb 4, 2026
 *
 * STIX format alert construction for security reports.
 *
 * EXTENSIBILITY:
 * - To add new attack types: Edit attack_info_list[] below
 * - To add asset UUIDs: Edit asset_list[] below
 * - Empty UUID strings will trigger auto-generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#include "stix_alert.h"

/*
 * Attack information structure.
 * - rule_id: The security rule ID from mmt-security
 * - event_uuid: Project-specific event UUID (empty = auto-generate)
 * - attack_uuid: Project-specific attack UUID (empty = auto-generate)
 * - attack_name: Human-readable attack name
 * - mitre_ttp_id: MITRE ATT&CK technique ID
 * - ttp_name: MITRE technique description
 */
typedef struct {
	const char *rule_id;
	const char *event_uuid;
	const char *attack_uuid;
	const char *attack_name;
	const char *mitre_ttp_id;
	const char *ttp_name;
} attack_info_t;

/*
 * Asset information structure.
 * - ip: IP address of the asset
 * - uuid: Project-specific UUID (empty = auto-generate)
 */
typedef struct {
	const char *ip;
	const char *uuid;
} asset_ip_t;

/*
 * Attack information lookup table.
 * Add new entries here for new attack types.
 */
static const attack_info_t attack_info_list[] = {
		/* rule_id, event_uuid, attack_uuid, attack_name, mitre_ttp_id, ttp_name */
		{"201", "", "", "cyberattack_ocpp16_dos_flooding_heartbeat", "T1498",
		 "Network Denial of Service"},
		{"202", "", "", "cyberattack_ocpp16_fdi_chargingprofile", "T1565",
		 "Charging Profile Manipulation"},
		{"203", "", "", "PHP_insecure_intrusion", "T1190",
		 "Exploit public-facing web applications"},
		{"204", "", "", "smb_intrusion", "T1003", "OS Credential Dumping"},
		{"206", "", "", "pacs_server_ddos", "T1498", "Network Denial of Service"},
		{"207", "", "", "lockbit_execution", "", "Lockbit Execution attack"},
		{"210", "", "", "rdp_intrusion", "T1110", "Brute Force"},
		{"211", "", "", "ssh_intrusion", "T1078", "Valid Accounts"},
		{NULL, NULL, NULL, NULL, NULL, NULL} /* Sentinel */
};

/*
 * Asset UUID lookup table.
 * Add project-specific IP-to-UUID mappings here.
 */
static const asset_ip_t asset_list[] = {
		/* ip, uuid */
		/* Add project-specific entries here */
		{NULL, NULL} /* Sentinel */
};

/**
 * Generate a random UUID string.
 */
static void generate_uuid(char *uuid_str) {
	uuid_t uuid;
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, uuid_str);
}

/**
 * Extract substring between the nth occurrence of delimiter.
 * Caller must free the returned string.
 */
static char *extract_substring_with_delimiter(const char *str, char delimiter,
											                        int n) {
	if (!str || n < 0)
		return NULL;

	const char *start = str;
	const char *end = NULL;
	int count = 0;

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

	/* If n is the last delimiter, return the substring after it */
	if (count == n && !end)
		return (*start) ? strdup(start) : NULL;

	/* Not enough delimiters */
	if (count < n)
		return NULL;

	/* Allocate and copy the substring */
	int length = (end) ? (end - start) : strlen(start);
	char *result = (char *)malloc(length + 1);
	if (!result)
		return NULL;

	strncpy(result, start, length);
	result[length] = '\0';

	return result;
}

/**
 * Extract substring between two markers.
 * Caller must free the returned string.
 */
static char *extract_substring_between(const char *main_str,
											                 const char *start_sub,
											                 const char *end_sub) {
	if (!main_str || !start_sub || !end_sub)
		return NULL;

	const char *start_pos = strstr(main_str, start_sub);
	if (!start_pos)
		return NULL;

	start_pos += strlen(start_sub);

	const char *end_pos = strstr(start_pos, end_sub);
	if (!end_pos)
		return NULL;

	size_t substring_length = end_pos - start_pos;
	char *result = (char *)malloc(substring_length + 1);
	if (!result)
		return NULL;

	strncpy(result, start_pos, substring_length);
	result[substring_length] = '\0';

	return result;
}

/**
 * Format timeval as ISO8601 timestamp.
 */
static void format_timeval_iso8601(const struct timeval *ts, int utc_offset,
											             char *buffer, size_t buffer_size) {
	struct tm tm;
	gmtime_r(&ts->tv_sec, &tm);
	tm.tm_hour += utc_offset;
	mktime(&tm);

	strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S", &tm);
	size_t len = strlen(buffer);
	snprintf(buffer + len, buffer_size - len, ".%03ldZ", ts->tv_usec / 1000);
}

/**
 * Lookup attack info by rule_id.
 * Returns NULL if not found.
 */
static const attack_info_t *get_attack_info(const char *rule_id) {
	if (!rule_id)
		return NULL;

	for (int i = 0; attack_info_list[i].rule_id != NULL; i++) {
		if (strcmp(attack_info_list[i].rule_id, rule_id) == 0)
			return &attack_info_list[i];
	}
	return NULL;
}

/**
 * Lookup asset UUID by IP address.
 * Returns empty string if not found.
 */
static const char *get_uuid_by_ip(const char *ip) {
	if (!ip)
		return "";

	for (int i = 0; asset_list[i].ip != NULL; i++) {
		if (strcmp(asset_list[i].ip, ip) == 0)
			return asset_list[i].uuid;
	}
	return "";
}

/**
 * Get UUID string, generating one if empty or not found.
 * Uses provided buffer for generated UUIDs.
 */
static const char *get_or_generate_uuid(const char *uuid, char *buffer) {
	if (uuid && uuid[0] != '\0')
		return uuid;
	generate_uuid(buffer);
	return buffer;
}

int construct_alert_stix_format(const char *message_body,
											          const struct timeval *ts, char *message,
											          size_t message_size) {
	if (!message_body || !message)
		return -1;

	/* Extract rule_id from message */
	char *rule_id = extract_substring_with_delimiter(message_body, ',', 0);
	if (!rule_id)
		return -1;

	/* Lookup attack info - if not found, not a STIX-supported rule */
	const attack_info_t *info = get_attack_info(rule_id);
	if (!info) {
		free(rule_id);
		return 0;
	}

	/* Generate UUIDs */
	char bundle_uuid[37], identity_uuid[37];
	char event_uuid_buf[37], attack_uuid_buf[37];
	char src_asset_uuid_buf[37], dst_asset_uuid_buf[37];

	generate_uuid(bundle_uuid);
	generate_uuid(identity_uuid);

	const char *event_uuid =
			get_or_generate_uuid(info->event_uuid, event_uuid_buf);
	const char *attack_uuid =
			get_or_generate_uuid(info->attack_uuid, attack_uuid_buf);

	/* Extract description */
	char *description = extract_substring_with_delimiter(message_body, ',', 3);
	if (!description)
		description = strdup("\"Unknown\"");

	/* Extract IP addresses - try OCPP format first, then CICFlow format */
	char *src_ip =
			extract_substring_between(message_body, "\"ocpp_data.src_ip\",\"", "\"]");
	char *dst_ip =
			extract_substring_between(message_body, "\"ocpp_data.dst_ip\",\"", "\"]");

	if (!src_ip && !dst_ip) {
		src_ip = extract_substring_between(message_body,
											                 "\"cicflow_data.Src_IP\",\"", "\"]");
		dst_ip = extract_substring_between(message_body,
											                 "\"cicflow_data.Dst_IP\",\"", "\"]");
	}

	/* Lookup or generate asset UUIDs */
	const char *src_asset_lookup = get_uuid_by_ip(src_ip);
	const char *dst_asset_lookup = get_uuid_by_ip(dst_ip);
	const char *src_asset_uuid =
			get_or_generate_uuid(src_asset_lookup, src_asset_uuid_buf);
	const char *dst_asset_uuid =
			get_or_generate_uuid(dst_asset_lookup, dst_asset_uuid_buf);

	/* Extract simulation ID */
	char *simulated_id_str = extract_substring_between(
			message_body, "\"ocpp_data.simulation_id\",", "]");
	int simulated_id = simulated_id_str ? atoi(simulated_id_str) : 0;

	char simulation[64];
	snprintf(simulation, sizeof(simulation), "%s",
					 simulated_id == 0 ? "Real attack" : "Simulated attack");

	/* Format timestamp */
	char timestamp[30];
	format_timeval_iso8601(ts, 1, timestamp, sizeof(timestamp));

	/* Construct STIX message */
	snprintf(message, message_size,
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
					 bundle_uuid, identity_uuid, timestamp, timestamp, event_uuid,
					 timestamp, timestamp, timestamp, timestamp, src_asset_uuid,
					 dst_asset_uuid, attack_uuid, identity_uuid, description,
					 src_asset_uuid, src_ip ? src_ip : "", dst_asset_uuid,
					 dst_ip ? dst_ip : "", attack_uuid, info->attack_name, timestamp,
					 timestamp, simulation, info->mitre_ttp_id, info->mitre_ttp_id);

	/* Free allocated strings */
	free(rule_id);
	free(description);
	if (src_ip)
		free(src_ip);
	if (dst_ip)
		free(dst_ip);
	if (simulated_id_str)
		free(simulated_id_str);

	return 1;
}
