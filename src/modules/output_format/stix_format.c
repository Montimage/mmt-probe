/*
 * stix_format.c
 *
 * Build a STIX 2.1 bundle from an mmt-security alert message.
 *
 * The extraction rules and the custom extensions used here are documented in
 * docs/data-format.md ("STIX 2.1 alternative output").
 */
#include "stix_format.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#include "../../lib/log.h"

#define UUID_STR_LEN_NULL 37   /* 36 hex/dash chars + NUL */
#define ADDR_STR_MAX      64   /* fits IPv4, IPv6 and MAC textual forms */
#define RULE_ID_MAX       32
#define MAX_ADDRS         16   /* max distinct address SCOs per bundle */

/* STIX 2.1 namespace for deterministic SCO identifiers (spec section 2.9). */
static const uuid_t STIX_SCO_NAMESPACE = {
	0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c,
	0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7
};

/* ---------------------------------------------------------------------------
 * Small output buffer helper: appends, remembers overflow.
 * ------------------------------------------------------------------------- */
typedef struct {
	char  *buf;
	size_t size;
	size_t len;
	int    overflow;
} sbuf_t;

static void sb_printf(sbuf_t *sb, const char *fmt, ...) {
	if (sb->overflow)
		return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(sb->buf + sb->len, sb->size - sb->len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sb->size - sb->len) {
		sb->overflow = 1;
		return;
	}
	sb->len += (size_t)n;
}

/* Append @len bytes of @s as the content of a JSON string (no quotes). */
static void sb_json_escape(sbuf_t *sb, const char *s, size_t len) {
	for (size_t i = 0; i < len && !sb->overflow; i++) {
		unsigned char c = (unsigned char)s[i];
		switch (c) {
		case '"':  sb_printf(sb, "\\\""); break;
		case '\\': sb_printf(sb, "\\\\"); break;
		case '\n': sb_printf(sb, "\\n");  break;
		case '\r': sb_printf(sb, "\\r");  break;
		case '\t': sb_printf(sb, "\\t");  break;
		default:
			if (c < 0x20)
				sb_printf(sb, "\\u%04x", c);
			else
				sb_printf(sb, "%c", c);
		}
	}
}

/* ---------------------------------------------------------------------------
 * Identifiers and timestamps
 * ------------------------------------------------------------------------- */
static void generate_uuid(char out[UUID_STR_LEN_NULL]) {
	uuid_t uuid;
	uuid_generate_random(uuid);
	uuid_unparse_lower(uuid, out);
}

/*
 * Deterministic UUIDv5 for an address SCO, as STIX 2.1 recommends: SHA-1 over
 * the STIX namespace and the canonical JSON of the ID contributing
 * properties, which is {"value":"<addr>"} for ipv4-addr, ipv6-addr and
 * mac-addr. @value contains no character that needs JSON escaping
 * (it has been validated as an IP or normalized as a MAC).
 */
static void generate_sco_uuid(const char *value, char out[UUID_STR_LEN_NULL]) {
	char name[ADDR_STR_MAX + 16];
	int n = snprintf(name, sizeof(name), "{\"value\":\"%s\"}", value);
	uuid_t uuid;
	uuid_generate_sha1(uuid, STIX_SCO_NAMESPACE, name, (size_t)n);
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

/* ---------------------------------------------------------------------------
 * Alert body parsing
 * ------------------------------------------------------------------------- */

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
 * Find the source / destination IP inside the trace JSON.
 * Tries the canonical IP-layer key first ("ip.src" / "ip.dst"), then falls
 * back to any key ending in ".src_ip" / ".dst_ip" (case-insensitive) — this
 * catches application-protocol-specific names like "ocpp_data.src_ip" or
 * "cicflow_data.Src_IP". Writes an empty string when nothing is found.
 */
static void extract_ip(const char *trace, int is_src,
                       char *out, size_t out_size) {
	out[0] = '\0';

	const char *primary = is_src ? "[\"ip.src\",\"" : "[\"ip.dst\",\"";
	const char *m = strstr(trace, primary);
	if (m && copy_value_after_key(m + 8, out, out_size))  /* `["ip.src` is 8 chars: m+8 is the closing quote of the key */
		return;

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

/* ---------------------------------------------------------------------------
 * Address SCOs
 * ------------------------------------------------------------------------- */
typedef struct {
	const char *type;              /* "ipv4-addr", "ipv6-addr", "mac-addr" */
	char value[ADDR_STR_MAX];
	char uuid[UUID_STR_LEN_NULL];
} stix_addr_t;

typedef struct {
	stix_addr_t items[MAX_ADDRS];
	int count;
} addr_list_t;

static void addr_add(addr_list_t *l, const char *type, const char *value) {
	for (int i = 0; i < l->count; i++)
		if (strcmp(l->items[i].type, type) == 0 &&
		    strcmp(l->items[i].value, value) == 0)
			return;  /* already present: one object per distinct address */
	if (l->count >= MAX_ADDRS)
		return;
	stix_addr_t *a = &l->items[l->count++];
	a->type = type;
	snprintf(a->value, sizeof(a->value), "%s", value);
	generate_sco_uuid(a->value, a->uuid);
}

/*
 * Add an IP address. The text must parse as IPv4 (-> ipv4-addr) or IPv6
 * (-> ipv6-addr, in canonical form); anything else, including an empty
 * string, is ignored so that no SCO carries an invalid value.
 */
static void addr_add_ip(addr_list_t *l, const char *value, int skip_unspecified) {
	struct in_addr v4;
	struct in6_addr v6;
	char canon[INET6_ADDRSTRLEN];
	if (inet_pton(AF_INET, value, &v4) == 1) {
		if (skip_unspecified && v4.s_addr == 0)
			return;
		addr_add(l, "ipv4-addr", value);
	} else if (inet_pton(AF_INET6, value, &v6) == 1 &&
	           inet_ntop(AF_INET6, &v6, canon, sizeof(canon)) != NULL) {
		if (skip_unspecified && IN6_IS_ADDR_UNSPECIFIED(&v6))
			return;
		addr_add(l, "ipv6-addr", canon);
	}
}

/*
 * Add a MAC address, normalized to the STIX form (lowercase, colon-separated,
 * leading zeros). Broadcast and all-zero addresses carry no attribution and
 * are ignored, as is anything that is not a MAC-48 address.
 */
static void addr_add_mac(addr_list_t *l, const char *value) {
	unsigned int b[6];
	char sep[5];
	if (sscanf(value, "%2x%c%2x%c%2x%c%2x%c%2x%c%2x",
	           &b[0], &sep[0], &b[1], &sep[1], &b[2], &sep[2],
	           &b[3], &sep[3], &b[4], &sep[4], &b[5]) != 11
	    || strlen(value) != 17)
		return;
	int all_ff = 1, all_00 = 1;
	for (int i = 0; i < 5; i++)
		if (sep[i] != ':' && sep[i] != '-')
			return;
	for (int i = 0; i < 6; i++) {
		if (b[i] != 0xff) all_ff = 0;
		if (b[i] != 0x00) all_00 = 0;
	}
	if (all_ff || all_00)
		return;
	char mac[18];
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
	         b[0], b[1], b[2], b[3], b[4], b[5]);
	addr_add(l, "mac-addr", mac);
}

/* Trace attributes that carry addresses beyond the source / destination IP.
 * They are taken in trace order. */
static const struct {
	const char *key;    /* attribute name in the trace */
	int is_mac;
} EXTRA_ADDR_KEYS[] = {
	{ "arp.ar_sip",   0 },
	{ "arp.ar_tip",   0 },
	{ "arp.ar_sha",   1 },
	{ "arp.ar_tha",   1 },
	{ "ethernet.src", 1 },
	{ "ethernet.dst", 1 },
};

/*
 * Walk the trace and collect the extra addresses. Each attribute of the
 * mmt-security trace is serialized as ["<key>",<value>]; only string values
 * are considered. Matching is anchored on the exact `["<key>","` token.
 */
static void collect_extra_addrs(const char *trace, addr_list_t *l) {
	for (const char *p = strstr(trace, "[\""); p; p = strstr(p + 1, "[\"")) {
		const char *key = p + 2;
		for (size_t k = 0; k < sizeof(EXTRA_ADDR_KEYS) / sizeof(EXTRA_ADDR_KEYS[0]); k++) {
			size_t klen = strlen(EXTRA_ADDR_KEYS[k].key);
			if (strncmp(key, EXTRA_ADDR_KEYS[k].key, klen) != 0)
				continue;
			char value[ADDR_STR_MAX];
			if (!copy_value_after_key(key + klen, value, sizeof(value)))
				continue;
			if (EXTRA_ADDR_KEYS[k].is_mac)
				addr_add_mac(l, value);
			else
				addr_add_ip(l, value, 1);
			break;
		}
	}
}

/* ---------------------------------------------------------------------------
 * Bundle
 * ------------------------------------------------------------------------- */
int construct_alert_stix_format(const char *message_body,
                                const struct timeval *ts,
                                uint32_t probe_id,
                                const char *input_src,
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

	/* description (column 3) — the content between the surrounding quotes.
	 * Empty when the probe config disables report-rule-description. */
	const char *desc_ptr = "";
	size_t desc_len = 0;
	if (found >= 5) {
		const char *d = message_body + col_starts[3];
		size_t dl = col_starts[4] - 1 - col_starts[3];
		if (dl >= 2 && d[0] == '"' && d[dl - 1] == '"') {
			desc_ptr = d + 1;
			desc_len = dl - 2;
		}
	}

	/* trace JSON (column 4) — last column, runs to end of body. NUL-terminated
	 * by the original message_body NUL. */
	const char *trace_ptr = (found >= 5) ? message_body + col_starts[4] : "";

	/* Address SCOs: source IP, destination IP, then ARP / Ethernet addresses
	 * in trace order, one object per distinct address. */
	addr_list_t addrs = { .count = 0 };
	char ip[ADDR_STR_MAX];
	extract_ip(trace_ptr, 1, ip, sizeof(ip));
	addr_add_ip(&addrs, ip, 0);
	extract_ip(trace_ptr, 0, ip, sizeof(ip));
	addr_add_ip(&addrs, ip, 0);
	collect_extra_addrs(trace_ptr, &addrs);

	char bundle_uuid[UUID_STR_LEN_NULL];
	char identity_uuid[UUID_STR_LEN_NULL];
	char observed_uuid[UUID_STR_LEN_NULL];
	char attack_uuid[UUID_STR_LEN_NULL];
	generate_uuid(bundle_uuid);
	generate_uuid(identity_uuid);
	generate_uuid(observed_uuid);
	generate_uuid(attack_uuid);

	char timestamp[40];
	format_timeval_iso8601(ts, timestamp, sizeof(timestamp));

	sbuf_t sb = { .buf = out, .size = out_size, .len = 0, .overflow = 0 };

	sb_printf(&sb,
		"{\n"
		"  \"type\": \"bundle\",\n"
		"  \"id\": \"bundle--%s\",\n"
		"  \"objects\": [\n", bundle_uuid);

	/* identity: the probe that raised the alert */
	sb_printf(&sb,
		"    {\n"
		"      \"type\": \"identity\",\n"
		"      \"spec_version\": \"2.1\",\n"
		"      \"id\": \"identity--%s\",\n"
		"      \"created\": \"%s\",\n"
		"      \"modified\": \"%s\",\n"
		"      \"name\": \"MMT-Probe %u\",\n"
		"      \"identity_class\": \"system\",\n"
		"      \"extensions\": {\n"
		"        \"x-probe-id-ext\": {\n"
		"          \"extension_type\": \"property-extension\",\n"
		"          \"probe-id\": %u,\n"
		"          \"input-source\": \"",
		identity_uuid, timestamp, timestamp, probe_id, probe_id);
	if (input_src)
		sb_json_escape(&sb, input_src, strlen(input_src));
	sb_printf(&sb,
		"\"\n"
		"        }\n"
		"      }\n"
		"    },\n");

	/* observed-data */
	sb_printf(&sb,
		"    {\n"
		"      \"type\": \"observed-data\",\n"
		"      \"spec_version\": \"2.1\",\n"
		"      \"id\": \"observed-data--%s\",\n"
		"      \"created\": \"%s\",\n"
		"      \"modified\": \"%s\",\n"
		"      \"first_observed\": \"%s\",\n"
		"      \"last_observed\": \"%s\",\n"
		"      \"number_observed\": 1,\n"
		"      \"object_refs\": [\n",
		observed_uuid, timestamp, timestamp, timestamp, timestamp);
	for (int i = 0; i < addrs.count; i++)
		sb_printf(&sb, "        \"%s--%s\",\n", addrs.items[i].type, addrs.items[i].uuid);
	sb_printf(&sb,
		"        \"x-attack-type--%s\"\n"
		"      ],\n"
		"      \"created_by_ref\": \"identity--%s\",\n"
		"      \"extensions\": {\n"
		"        \"x-observed-data-ext\": {\n"
		"          \"extension_type\": \"property-extension\",\n"
		"          \"description\": \"",
		attack_uuid, identity_uuid);
	sb_json_escape(&sb, desc_ptr, desc_len);
	sb_printf(&sb,
		"\"\n"
		"        }\n"
		"      }\n"
		"    },\n");

	/* address SCOs */
	for (int i = 0; i < addrs.count; i++)
		sb_printf(&sb,
			"    {\n"
			"      \"type\": \"%s\",\n"
			"      \"spec_version\": \"2.1\",\n"
			"      \"id\": \"%s--%s\",\n"
			"      \"value\": \"%s\"\n"
			"    },\n",
			addrs.items[i].type, addrs.items[i].type,
			addrs.items[i].uuid, addrs.items[i].value);

	/* x-attack-type: the mmt-security rule. Its name is the rule
	 * description, or "mmt-security rule <id>" when descriptions are not
	 * reported. */
	sb_printf(&sb,
		"    {\n"
		"      \"type\": \"x-attack-type\",\n"
		"      \"id\": \"x-attack-type--%s\",\n"
		"      \"name\": \"", attack_uuid);
	if (desc_len > 0)
		sb_json_escape(&sb, desc_ptr, desc_len);
	else
		sb_printf(&sb, "mmt-security rule %s", rule_id_buf);
	sb_printf(&sb,
		"\",\n"
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
		timestamp, timestamp, rule_id_buf);

	if (sb.overflow) {
		log_write(LOG_WARNING, "STIX bundle of rule %s does not fit in %zu bytes, "
		          "the alert is reported in CSV format", rule_id_buf, out_size);
		return 0;
	}
	return 1;
}
