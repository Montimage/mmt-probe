/*
 * dynamic_conf.h
 *
 *  Created on: Dec 26, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_
#define SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_

#include <stdbool.h>

typedef enum{
	DYNAMIC_CONF_PREFIX_PROBE_ID,
	DYNAMIC_CONF_PREFIX_LICENSE,
	DYNAMIC_CONF_PREFIX_ENABLE_PROTO_WITHOUT_SESSION,
	DYNAMIC_CONF_PREFIX_ENABLE_IP_FRAGEMENTATION,
	DYNAMIC_CONF_PREFIX_STAT_PERIOD,

	DYNAMIC_CONF_PREFIX_INPUT,
	DYNAMIC_CONF_PREFIX_FILE_OUTPUT,
	DYNAMIC_CONF_PREFIX_REDIS_OUTPUT,
	DYNAMIC_CONF_PREFIX_KAFKA_OUTPUT,
	DYNAMIC_CONF_PREFIX_SECURITY,
	DYNAMIC_CONF_PREFIX_SYSTEM_REPORT,
	DYNAMIC_CONF_PREFIX_BEHAVIOUR,
	DYNAMIC_CONF_PREFIX_RECONSTRUCT_FTP,
	DYNAMIC_CONF_PREFIX_RECONSTRUCT_HTTP,
	DYNAMIC_CONF_PREFIX_RADIUS_OUTPUT,
	DYNAMIC_CONF_PREFIX_MICRO_FLOWS,
	DYNAMIC_CONF_PREFIX_SESSION_TIMEOUT,
	DYNAMIC_CONF_PREFIX_EVENT_REPORT,
	DYNAMIC_CONF_PREFIX_SESSION_REPORT,

}dynamic_conf_prefix_t;

typedef enum{
	DYNAMIC_CONF_RESPONSE_OK,
	DYNAMIC_CONF_RESPONSE_SYNTAX_ERROR,
	DYNAMIC_CONF_RESPONSE_ERROR,
};

typedef struct dynamic_conf_struct dynamic_config_context_t;

typedef void (*dynamic_conf_callback)( dynamic_conf_prefix_t prefix, const void *new_conf, void *user_data );

dynamic_config_context_t *dynamic_conf_alloc_and_init( const char * file_descriptor );

bool dynamic_conf_register( dynamic_config_context_t *context, dynamic_conf_prefix_t prefix,  dynamic_conf_callback cb, void *user_data  );

bool dynamic_conf_start( dynamic_config_context_t *context );

bool dynamic_conf_stop_and_release( dynamic_config_context_t *context );

#endif /* SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_ */
