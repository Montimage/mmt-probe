/*
 * mqtt_output.c
 *
 *  Created on: May 7, 2025
 *      Author: nhnghia
 */

#include <MQTTClient.h>
#include "mqtt_output.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc.h"

struct mqtt_output_struct{
	uint16_t probe_id;
	const mqtt_output_conf_t *config;
	MQTTClient client;
};

static void _connect_to_mqtt(mqtt_output_t *context) {
	char client_id[100];
	snprintf(client_id, sizeof(client_id), "mmt-probe-%d", context->probe_id);

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;

	int rc;

	rc = MQTTClient_create(&context->client, context->config->address,
			client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);

	if( rc ){
		log_write( LOG_ERR, "Failed to create MQTT client '%s: %d'", client_id, rc);
		abort();
	} else
		log_write( LOG_INFO, "Created MQTT client '%s'", client_id);


	rc = MQTTClient_connect(context->client, &conn_opts);
	if( rc != MQTTCLIENT_SUCCESS ) {
		log_write(LOG_ERR, "Failed to connect MQTT to '%s': %d", context->config->address, rc);
		abort();
	} else
		log_write(LOG_INFO, "Connected MQTT to '%s'", context->config->address);
}

mqtt_output_t* mqtt_output_alloc_init( const mqtt_output_conf_t*config,  uint16_t probe_id ){
	if( config->is_enable == false)
		return NULL;
	mqtt_output_t *ret = mmt_alloc_and_init_zero( sizeof( mqtt_output_t ));
	ret->probe_id = probe_id;
	ret->config = config;

	//trigger the connection
	_connect_to_mqtt( ret );

	return ret;
}

int mqtt_output_send( mqtt_output_t *context, const char *message ){
	MQTTClient_message pubmsg = MQTTClient_message_initializer;
	MQTTClient_deliveryToken token;
	int rc;

	pubmsg.payload = (void *)message;
	pubmsg.payloadlen = (int) strlen(message);
	pubmsg.qos = 2; //Once and one only - the message will be delivered exactly once.
	pubmsg.retained = context->config->is_retain;

	rc = MQTTClient_publishMessage(context->client, context->config->topic_name, &pubmsg, &token);
	if( rc != MQTTCLIENT_SUCCESS ){
		log_write(LOG_ERR, "Failed to publish MQTT message to '%s': %d", context->config->topic_name, rc);
		return 0;
	}

	const unsigned long timeout = 10*1000; //The maximum time to wait in milliseconds.
	//wait for the message has been published
	rc = MQTTClient_waitForCompletion(context->client, token, timeout);
	return 1;
}

void mqtt_output_flush( mqtt_output_t * context){

}

void mqtt_output_release( mqtt_output_t * context){
	if( context == NULL )
		return;

	int rc = MQTTClient_disconnect(context->client, 10000);

	if( rc != MQTTCLIENT_SUCCESS)
		log_write(LOG_ERR, "Failed to disconnect MQTT client: %d", rc);

	MQTTClient_destroy(&context->client);
	mmt_probe_free( context );
}
