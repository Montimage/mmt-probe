/*
 * stix_format.h
 *
 * Build a STIX 2.1 bundle from an mmt-security alert message.
 */
#ifndef SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_
#define SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_

#include <stddef.h>
#include <sys/time.h>

/**
 * Build a STIX 2.1 JSON bundle from a security alert.
 *
 * The expected @p message_body layout is the CSV row produced by
 * mmt-probe's security callback:
 *     <rule_id>,<verdict>,<rule_type>,"<description>",<json_trace>
 *
 * @param message_body alert body coming from the security callback (NUL-terminated).
 * @param ts           timestamp of the alert.
 * @param out          buffer to receive the JSON bundle.
 * @param out_size     size of @p out in bytes.
 * @return 1 if a STIX bundle was written into @p out, 0 otherwise (caller
 *         should fall back to the default CSV format).
 */
int construct_alert_stix_format(const char *message_body,
                                const struct timeval *ts,
                                char *out, size_t out_size);

#endif /* SRC_MODULES_OUTPUT_FORMAT_STIX_FORMAT_H_ */
