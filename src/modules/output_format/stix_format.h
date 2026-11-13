/*
 * stix_format.h
 *
 * Build a STIX 2.1 bundle from an mmt-security alert message.
 */
#ifndef SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_
#define SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

/**
 * Set the per-rule priority override (`security.stix-priority`).
 * Format: a sequence of `(<priority>:<rule ids>)` groups, where <priority>
 * is critical, high, medium or low (case-insensitive) and <rule ids> a
 * comma-separated list of rule ids or ranges `a-b`, e.g.
 * "(critical:4,5)(high:56,60-62)". NULL or "" clears the override.
 * Must be called before any alert is built (not thread-safe).
 *
 * @return 1 on success, 0 if @p spec is malformed (the override is cleared
 *         and an error is logged).
 */
int stix_format_set_priority(const char *spec);

/**
 * Build a STIX 2.1 JSON bundle from a security alert.
 *
 * The expected @p message_body layout is the CSV row produced by
 * mmt-probe's security callback:
 *     <rule_id>,<verdict>,<rule_type>,"<description>",<json_trace>
 *
 * @param message_body alert body coming from the security callback (NUL-terminated).
 * @param ts           timestamp of the alert.
 * @param probe_id     probe id of the running configuration (`probe-id`).
 * @param input_src    input source of the probe (interface or trace file), may be NULL.
 * @param out          buffer to receive the JSON bundle.
 * @param out_size     size of @p out in bytes.
 * @return 1 if a STIX bundle was written into @p out, 0 otherwise (caller
 *         should fall back to the default CSV format).
 */
int construct_alert_stix_format(const char *message_body,
                                const struct timeval *ts,
                                uint32_t probe_id,
                                const char *input_src,
                                char *out, size_t out_size);

#endif /* SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_ */
