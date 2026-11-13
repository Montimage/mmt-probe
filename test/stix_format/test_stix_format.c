/*
 * Unit check of the STIX 2.1 alert builder (src/modules/output_format/stix_format.c).
 *
 * Build and run (needs uuid-dev):
 *   gcc -Wall -Wextra -o /tmp/test_stix test/stix_format/test_stix_format.c \
 *       src/modules/output_format/stix_format.c -luuid && /tmp/test_stix
 *
 * Checks priority / verdict / rule_type (issue #24), the per-rule priority
 * override, deterministic ids and the timestamp precision.
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "../../src/modules/output_format/stix_format.h"

static int failures = 0;

#define CHECK(cond, ...) do { \
	if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

#define TRACE_ICMP "{\"event_1\":{\"timestamp\":1682506925.089123,\"counter\":3,\"attributes\":[[\"ip.src\",\"10.0.0.1\"],[\"ip.dst\",\"10.0.0.2\"]]}}"

static char out[8192];

static int build(const char *body, long sec, long usec, unsigned probe) {
	struct timeval ts = { .tv_sec = sec, .tv_usec = usec };
	return construct_alert_stix_format(body, &ts, probe, "/data/input/x.pcap", out, sizeof(out));
}

/* Copy the string value of the first "<key>": "<value>" into @val. */
static const char *get(const char *json, const char *key, char *val, size_t n) {
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\": \"", key);
	const char *p = strstr(json, pat);
	val[0] = '\0';
	if (!p)
		return NULL;
	p += strlen(pat);
	const char *e = strchr(p, '"');
	size_t l = (size_t)(e - p) < n - 1 ? (size_t)(e - p) : n - 1;
	memcpy(val, p, l);
	val[l] = '\0';
	return val;
}

static void expect(const char *body, const char *prio, const char *verdict, const char *type) {
	char v[128];
	CHECK(build(body, 1682506925, 89123, 3), "bundle not built for %s", body);
	CHECK(strcmp(get(out, "priority", v, sizeof v) ? v : "", prio) == 0, "priority %s != %s (%s)", v, prio, body);
	CHECK(strcmp(get(out, "verdict", v, sizeof v) ? v : "", verdict) == 0, "verdict %s != %s", v, verdict);
	CHECK(strcmp(get(out, "rule_type", v, sizeof v) ? v : "", type) == 0, "rule_type %s != %s", v, type);
}

int main(void) {
	char a[64], b[64], v[64];

	/* default priority from the rule type */
	CHECK(stix_format_set_priority(NULL), "NULL spec");
	expect("20,\"detected\",\"attack\",\"ICMP redirect\"," TRACE_ICMP, "high", "detected", "attack");
	expect("21,\"detected\",\"evasion\",\"d\"," TRACE_ICMP, "medium", "detected", "evasion");
	expect("22,\"not_respected\",\"security\",\"d\"," TRACE_ICMP, "medium", "not_respected", "security");
	expect("23,\"detected\",\"test\",\"d\"," TRACE_ICMP, "low", "detected", "test");
	expect("24,\"detected\",\"other\",\"d\"," TRACE_ICMP, "medium", "detected", "other");

	/* per-rule override: only the listed rules change */
	CHECK(stix_format_set_priority(" (critical:4,5) (Low: 20-21 ,56)"), "valid spec rejected");
	expect("4,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "critical", "detected", "attack");
	expect("5,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "critical", "detected", "attack");
	expect("20,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "low", "detected", "attack");
	expect("21,\"detected\",\"evasion\",\"d\"," TRACE_ICMP, "low", "detected", "evasion");
	expect("56,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "low", "detected", "attack");
	expect("6,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "high", "detected", "attack");
	expect("22,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "high", "detected", "attack");

	/* malformed specs are rejected and clear the override */
	const char *bad[] = { "critical:4", "(urgent:4)", "(high:)", "(high:5-4)", "(high:4", "(high:4;5)", "(high:a)" };
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		CHECK(!stix_format_set_priority(bad[i]), "malformed spec accepted: %s", bad[i]);
	expect("4,\"detected\",\"attack\",\"d\"," TRACE_ICMP, "high", "detected", "attack");
	CHECK(stix_format_set_priority(""), "empty spec");

	/* deterministic ids: same alert -> same ids; different time / rule / trace / probe -> different */
	const char *body = "20,\"detected\",\"attack\",\"d\"," TRACE_ICMP;
	build(body, 1682506925, 89123, 3); get(out, "id", a, sizeof a);
	char first[8192]; strcpy(first, out);
	build(body, 1682506925, 89123, 3); get(out, "id", b, sizeof b);
	CHECK(strcmp(a, b) == 0 && strcmp(first, out) == 0, "same alert gives different bundles");
	CHECK(strncmp(a, "bundle--", 8) == 0 && a[8 + 14] == '4' && strchr("89ab", a[8 + 19]), "bundle id is not UUIDv4-shaped: %s", a);
	build(body, 1682506925, 89124, 3); get(out, "id", b, sizeof b);
	CHECK(strcmp(a, b) != 0, "1 us later gives the same bundle id");
	build(body, 1682506925, 89123, 4); get(out, "id", b, sizeof b);
	CHECK(strcmp(a, b) != 0, "other probe gives the same bundle id");
	build("21,\"detected\",\"attack\",\"d\"," TRACE_ICMP, 1682506925, 89123, 3); get(out, "id", b, sizeof b);
	CHECK(strcmp(a, b) != 0, "other rule gives the same bundle id");
	build("20,\"detected\",\"attack\",\"d\",{\"event_1\":{\"counter\":4}}", 1682506925, 89123, 3); get(out, "id", b, sizeof b);
	CHECK(strcmp(a, b) != 0, "other trace gives the same bundle id");

	/* objects of one bundle have distinct ids */
	build(body, 1682506925, 89123, 3);
	const char *types[] = { "bundle", "identity", "observed-data", "x-attack-type" };
	char ids[4][64];
	for (int i = 0; i < 4; i++) {
		char pat[64];
		snprintf(pat, sizeof pat, "\"id\": \"%s--", types[i]);
		const char *p = strstr(out, pat);
		CHECK(p != NULL, "no %s id", types[i]);
		snprintf(ids[i], sizeof ids[i], "%.36s", p ? p + strlen(pat) : "");
		for (int j = 0; j < i; j++)
			CHECK(strcmp(ids[i], ids[j]) != 0, "%s and %s share a uuid", types[i], types[j]);
	}

	/* one identity per probe: same id and content for any alert of probe 3,
	 * another id for probe 4 */
	{
		char id1[64], id2[64], id3[64], ident1[2048], ident2[2048];
		const char *p, *e;
		build(body, 1682506925, 89123, 3);
		p = strstr(out, "\"type\": \"identity\""); e = strstr(p, "\"type\": \"observed-data\"");
		snprintf(ident1, sizeof ident1, "%.*s", (int)(e - p), p);
		get(p, "id", id1, sizeof id1);
		CHECK(strstr(ident1, "\"created\": \"1970-01-01T00:00:00.000Z\"") != NULL, "identity created is not the epoch");
		build("21,\"detected\",\"evasion\",\"x\",{}", 1700000000, 5, 3);
		p = strstr(out, "\"type\": \"identity\""); e = strstr(p, "\"type\": \"observed-data\"");
		snprintf(ident2, sizeof ident2, "%.*s", (int)(e - p), p);
		get(p, "id", id2, sizeof id2);
		CHECK(strcmp(ident1, ident2) == 0, "identity differs between two alerts of one probe");
		build(body, 1682506925, 89123, 4);
		get(strstr(out, "\"type\": \"identity\""), "id", id3, sizeof id3);
		CHECK(strcmp(id1, id3) != 0, "probes 3 and 4 share an identity id");
		CHECK(id1[10 + 14] == '4', "identity id is not v4-shaped: %s", id1);
	}

	/* timestamps: created ms, first/last_observed us */
	CHECK(strcmp(get(strstr(out, "\"type\": \"observed-data\""), "created", v, sizeof v), "2023-04-26T11:02:05.089Z") == 0, "created %s", v);
	CHECK(strcmp(get(out, "first_observed", v, sizeof v), "2023-04-26T11:02:05.089123Z") == 0, "first_observed %s", v);
	CHECK(strcmp(get(out, "last_observed", v, sizeof v), "2023-04-26T11:02:05.089123Z") == 0, "last_observed %s", v);
	build(body, 1682506925, 7, 3);
	CHECK(strcmp(get(out, "first_observed", v, sizeof v), "2023-04-26T11:02:05.000007Z") == 0, "first_observed %s", v);

	printf("%s (%d failure%s)\n", failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
	return failures != 0;
}
