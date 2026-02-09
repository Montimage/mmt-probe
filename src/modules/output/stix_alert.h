/*
 * stix_alert.h
 *
 *  Created on: Feb 4, 2026
 *
 * STIX format alert construction for security reports.
 * Separates STIX-specific logic from the main output module.
 */

#ifndef SRC_MODULES_OUTPUT_STIX_ALERT_H_
#define SRC_MODULES_OUTPUT_STIX_ALERT_H_

#include <stddef.h>
#include <sys/time.h>

/**
 * Construct a security alert in STIX 2.1 bundle format.
 *
 * @param message_body  The raw message body from mmt-security
 * @param ts            Timestamp of the alert
 * @param message       Output buffer for the STIX JSON
 * @param message_size  Size of the output buffer
 * @return 1 if STIX format was constructed, 0 if rule not supported, -1 on
 * error
 */
int construct_alert_stix_format(const char *message_body,
                                const struct timeval *ts, char *message,
                                size_t message_size);

#endif /* SRC_MODULES_OUTPUT_STIX_ALERT_H_ */
