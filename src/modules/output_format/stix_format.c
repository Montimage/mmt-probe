/*
 * stix_format.c
 *
 * Build a STIX 2.1 bundle from an mmt-security alert message.
 */
#include "stix_format.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#define UUID_STR_LEN_NULL 37   /* 36 hex/dash chars + NUL */
#define IP_STR_MAX        64   /* fits IPv4 and IPv6 textual */
#define RULE_ID_MAX       32

static void generate_uuid(char out[UUID_STR_LEN_NULL]) {
	uuid_t uuid;
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, out);
}

static void format_timeval_iso8601(const struct timeval *ts,
                                   char *buf, size_t buf_size) {
	struct tm tm;
	gmtime_r(&ts->tv_sec, &tm);
	size_t n = strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", &tm);
	if (n < buf_size)
		snprintf(buf + n, buf_size - n, ".%03ldZ",
		         (long)(ts->tv_usec / 1000));
}

/*
 * Locate the start byte offset of CSV columns 0..max_col, treating commas
 * inside double-quoted strings as part of a field. Stops walking once
 * max_col+1 starts have been recorded, so commas inside the last column
 * (for us: the trace JSON) are not interpreted as field separators.
 *
 * Returns the number of column starts written.
 */
static int csv_locate_columns(const char *s, size_t len, int max_col,
                              size_t *col_starts) {
	col_starts[0] = 0;
	int found = 1;
	int in_quote = 0;
	for (size_t i = 0; i < len && found <= max_col; i++) {
		char c = s[i];
		if (c == '"')
			in_quote = !in_quote;
		else if (c == ',' && !in_quote)
			col_starts[found++] = i + 1;
	}
	return found;
}

/*
 * Case-insensitive substring search (portable substitute for strcasestr).
 */
static const char *istrstr(const char *haystack, const char *needle) {
	if (!*needle) return haystack;
	for (; *haystack; haystack++) {
		const char *h = haystack;
		const char *n = needle;
		while (*h && *n &&
		       ((*h | 0x20) == (*n | 0x20)))
			h++, n++;
		if (!*n) return haystack;
	}
	return NULL;
}

/*
 * Copy the value of a `"<key>","<value>"` token where @match points just
 * before the `","` boundary (i.e., at the closing quote of the key).
 * Returns 1 on success, 0 if the token isn't shaped as expected.
 */
static int copy_value_after_key(const char *match_end_of_key,
                                char *out, size_t out_size) {
	if (match_end_of_key[0] != '"' ||
	    match_end_of_key[1] != ',' ||
	    match_end_of_key[2] != '"')
		return 0;
	const char *val_start = match_end_of_key + 3;
	const char *val_end = strchr(val_start, '"');
	if (!val_end)
		return 0;
	size_t n = (size_t)(val_end - val_start);
	if (n >= out_size)
		n = out_size - 1;
	memcpy(out, val_start, n);
	out[n] = '\0';
	return 1;
}

/*
 * Find an IP value inside the trace JSON.
 * Tries the canonical IP-layer key first ("ip.src" / "ip.dst"), then falls
 * back to any key ending in ".src_ip" / ".dst_ip" (case-insensitive) — this
 * catches application-protocol-specific names like "ocpp_data.src_ip" or
 * "cicflow_data.Src_IP". Writes an empty string when nothing is found.
 */
static void extract_ip(const char *trace, int is_src,
                       char *out, size_t out_size) {
	out[0] = '\0';

	const char *primary = is_src ? "\"ip.src\"," : "\"ip.dst\",";
	const char *m = strstr(trace, primary);
	if (m) {
		/* m points at the opening quote of the key; advance to the
		 * closing quote of the key (right before `","value"`). */
		const char *key_close = m + (is_src ? 7 : 7);  /* "ip.src"/"ip.dst" both 6 chars + opening quote = 7 */
		if (copy_value_after_key(key_close, out, out_size))
			return;
	}

	const char *suffix = is_src ? ".src_ip" : ".dst_ip";
	size_t suf_len = strlen(suffix);
	const char *p = trace;
	while ((p = istrstr(p, suffix)) != NULL) {
		const char *key_close = p + suf_len;
		if (copy_value_after_key(key_close, out, out_size))
			return;
		p++;
	}
}

int construct_alert_stix_format(const char *message_body,
                                const struct timeval *ts,
                                char *out, size_t out_size) {
	if (!message_body || !out || !ts || out_size == 0)
		return 0;

	size_t body_len = strlen(message_body);

	/* Locate columns 0..4 (rule_id, verdict, rule_type, description, trace).
	 * If we don't have at least 4 column starts, the body isn't shaped like
	 * an mmt-security alert — bail out. */
	size_t col_starts[5] = {0};
	int found = csv_locate_columns(message_body, body_len, 4, col_starts);
	if (found < 4)
		return 0;

	/* rule_id (column 0) */
	size_t rule_id_len = col_starts[1] - 1 - col_starts[0];
	if (rule_id_len == 0 || rule_id_len >= RULE_ID_MAX)
		return 0;
	char rule_id_buf[RULE_ID_MAX];
	memcpy(rule_id_buf, message_body + col_starts[0], rule_id_len);
	rule_id_buf[rule_id_len] = '\0';

	/* description (column 3) — kept with its surrounding quotes since the
	 * STIX template expects a quoted JSON string here. Empty when the probe
	 * config disables report-rule-description. */
	const char *desc_ptr;
	size_t desc_len;
	if (found >= 5) {
		desc_ptr = message_body + col_starts[3];
		desc_len = col_starts[4] - 1 - col_starts[3];
	} else {
		desc_ptr = "";
		desc_len = 0;
	}
	if (!(desc_len >= 2 && desc_ptr[0] == '"' && desc_ptr[desc_len - 1] == '"')) {
		desc_ptr = "\"\"";
		desc_len = 2;
	}

	/* trace JSON (column 4) — last column, runs to end of body. NUL-terminated
	 * by the original message_body NUL. */
	const char *trace_ptr = (found >= 5) ? message_body + col_starts[4] : "";

	/* Source / destination IPs from the trace. */
	char src_ip[IP_STR_MAX];
	char dst_ip[IP_STR_MAX];
	extract_ip(trace_ptr, 1, src_ip, sizeof(src_ip));
	extract_ip(trace_ptr, 0, dst_ip, sizeof(dst_ip));

	/* Random UUIDs. */
	char bundle_uuid[UUID_STR_LEN_NULL];
	char identity_uuid[UUID_STR_LEN_NULL];
	char observed_uuid[UUID_STR_LEN_NULL];
	char src_addr_uuid[UUID_STR_LEN_NULL];
	char dst_addr_uuid[UUID_STR_LEN_NULL];
	char attack_uuid[UUID_STR_LEN_NULL];
	generate_uuid(bundle_uuid);
	generate_uuid(identity_uuid);
	generate_uuid(observed_uuid);
	generate_uuid(src_addr_uuid);
	generate_uuid(dst_addr_uuid);
	generate_uuid(attack_uuid);

	char timestamp[40];
	format_timeval_iso8601(ts, timestamp, sizeof(timestamp));

	int written = snprintf(
		out, out_size,
		"{\n"
		"  \"type\": \"bundle\",\n"
		"  \"id\": \"bundle--%s\",\n"
		"  \"objects\": [\n"
		"    {\n"
		"      \"type\": \"identity\",\n"
		"      \"spec_version\": \"2.1\",\n"
		"      \"id\": \"identity--%s\",\n"
		"      \"created\": \"%s\",\n"
		"      \"modified\": \"%s\",\n"
		"      \"name\": \"MMT-PROBE\",\n"
		"      \"identity_class\": \"organization\"\n"
		"    },\n"
		"    {\n"
		"      \"type\": \"observed-data\",\n"
		"      \"spec_version\": \"2.1\",\n"
		"      \"id\": \"observed-data--%s\",\n"
		"      \"created\": \"%s\",\n"
		"      \"modified\": \"%s\",\n"
		"      \"first_observed\": \"%s\",\n"
		"      \"last_observed\": \"%s\",\n"
		"      \"number_observed\": 1,\n"
		"      \"object_refs\": [\n"
		"        \"ipv4-addr--%s\",\n"
		"        \"ipv4-addr--%s\",\n"
		"        \"x-attack-type--%s\"\n"
		"      ],\n"
		"      \"created_by_ref\": \"identity--%s\",\n"
		"      \"extensions\": {\n"
		"        \"x-observed-data-ext\": {\n"
		"          \"extension_type\": \"property-extension\",\n"
		"          \"description\": %.*s\n"
		"        }\n"
		"      }\n"
		"    },\n"
		"    {\n"
		"      \"type\": \"ipv4-addr\",\n"
		"      \"id\": \"ipv4-addr--%s\",\n"
		"      \"value\": \"%s\"\n"
		"    },\n"
		"    {\n"
		"      \"type\": \"ipv4-addr\",\n"
		"      \"id\": \"ipv4-addr--%s\",\n"
		"      \"value\": \"%s\"\n"
		"    },\n"
		"    {\n"
		"      \"type\": \"x-attack-type\",\n"
		"      \"id\": \"x-attack-type--%s\",\n"
		"      \"name\": %.*s,\n"
		"      \"created\": \"%s\",\n"
		"      \"modified\": \"%s\",\n"
		"      \"extensions\": {\n"
		"        \"x-attack-type-ext\": {\n"
		"          \"extension_type\": \"new-sdo\"\n"
		"        }\n"
		"      },\n"
		"      \"external_references\": [\n"
		"        {\n"
		"          \"source_name\": \"mmt-security\",\n"
		"          \"external_id\": \"%s\"\n"
		"        }\n"
		"      ]\n"
		"    }\n"
		"  ]\n"
		"}",
		bundle_uuid,
		identity_uuid, timestamp, timestamp,
		observed_uuid, timestamp, timestamp, timestamp, timestamp,
		src_addr_uuid, dst_addr_uuid, attack_uuid, identity_uuid,
		(int)desc_len, desc_ptr,
		src_addr_uuid, src_ip,
		dst_addr_uuid, dst_ip,
		attack_uuid,
		(int)desc_len, desc_ptr,
		timestamp, timestamp,
		rule_id_buf
	);

	if (written < 0 || (size_t)written >= out_size)
		return 0;
	return 1;
}
