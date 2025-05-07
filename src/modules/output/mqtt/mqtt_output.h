/*
 * mqtt_output.h
 *
 *  Created on: May 7, 2025
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_OUTPUT_MQTT_MQTT_OUTPUT_H_
#define SRC_MODULES_OUTPUT_MQTT_MQTT_OUTPUT_H_

#include "../../../configure.h"

typedef struct mqtt_output_struct mqtt_output_t;

mqtt_output_t* mqtt_output_alloc_init( const mqtt_output_conf_t*config,  uint16_t probe_id );

int mqtt_output_send( mqtt_output_t * output, const char *message );

void mqtt_output_flush( mqtt_output_t * output);

void mqtt_output_release( mqtt_output_t * output);

#endif /* SRC_MODULES_OUTPUT_MQTT_MQTT_OUTPUT_H_ */
