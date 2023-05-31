/*
 * kafka_output.c
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */
#include <rdkafka.h>
#include <time.h>

#include "kafka_output.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc.h"

struct kafka_output_struct{
	rd_kafka_topic_t *rd_topic;
	rd_kafka_t  *rd_producer;
	const kafka_output_conf_t *config;
	size_t nb_sent_messages; //number of messages that be sent successfully
	size_t nb_messages_to_send;
	time_t last_connect_timestamp;
	bool is_fail_to_send_to_kafka; //whenether we cannot send a message to the Kafka bus
};

static void _dr_msg_cb (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);

static void _release_current_kafka_connection( kafka_output_t *context ){
	if( context == NULL )
		return;
	if( context->rd_topic ){
		rd_kafka_topic_destroy( context->rd_topic );
		context->rd_topic = NULL;
	}
	if( context->rd_producer ){
		rd_kafka_destroy( context->rd_producer );
		context->rd_producer = NULL;
	}
}

static void _connect_to_kafka( kafka_output_t *context ){

	rd_kafka_conf_res_t val;
	char errstr[512];       /* librdkafka API error reporting buffer */
	char brokers[256];    /* Argument: broker list */
	const kafka_output_conf_t *config = context->config;
	rd_kafka_conf_t *rd_conf;
	snprintf( brokers, sizeof( brokers ), "%s:%u", config->host.host_name, config->host.port_number );

	log_write( LOG_INFO, "Initializing Kafka output to %s", brokers );

	/*
	 * Create Kafka client configuration place-holder
	 */
	rd_conf = rd_kafka_conf_new();

	/* Set bootstrap broker(s) as a comma-separated list of
	 * host or host:port (default port 9092).
	 * librdkafka will use the bootstrap brokers to acquire the full
	 * set of brokers from the cluster. */

	rd_kafka_conf_set(rd_conf, "queue.buffering.max.messages", "10000000", errstr, sizeof(errstr));
	rd_kafka_conf_set(rd_conf, "batch.num.messages", "10000", errstr, sizeof(errstr));
	rd_kafka_conf_set(rd_conf, "queue.buffering.max.ms", "1000", errstr, sizeof(errstr));
	val = rd_kafka_conf_set(rd_conf, "bootstrap.servers", brokers, errstr, sizeof(errstr));

	if( val != RD_KAFKA_CONF_OK ) {
		log_write( LOG_ERR, "Failed to setup Kafka bootstrap.servers: %s", errstr);
		_release_current_kafka_connection( context );
		return;
	}

	/* Set the delivery report callback.
	 * This callback will be called once per message to inform
	 * the application if delivery succeeded or failed.
	 * See dr_msg_cb() above. */
	rd_kafka_conf_set_dr_msg_cb( rd_conf, _dr_msg_cb );
	//Don't know why opaque referenced via "rd_kafka_produce" does not work
	rd_kafka_conf_set_opaque( rd_conf, context);
	/*
	 * Create producer instance.
	 *
	 * NOTE: rd_kafka_new() takes ownership of the conf object
	 *       and the application must not reference it again after
	 *       this call.
	 */
	context->rd_producer = rd_kafka_new(RD_KAFKA_PRODUCER, rd_conf, errstr, sizeof(errstr));
	if( context->rd_producer == NULL ){
		log_write( LOG_ERR, "Failed to create new kafka producer: %s", errstr);
		_release_current_kafka_connection( context );
		return;
	}

	/* Create topic object that will be reused for each message
	 * produced.
	 *
	 * Both the producer instance (rd_kafka_t) and topic objects (topic_t)
	 * are long-lived objects that should be reused as much as possible.
	 */
	context->rd_topic = rd_kafka_topic_new( context->rd_producer, config->topic_name, NULL);
	if( context->rd_topic == NULL ){
		log_write( LOG_ERR, "Failed to create new topic %s: %s", config->topic_name,
				rd_kafka_err2str( rd_kafka_last_error() ));
		_release_current_kafka_connection( context );
		return;
	}
	log_write( LOG_INFO, "Initialized successfully Kafka output to %s", brokers );

	//we just initialize the connection
	// => do not know whether we can successfully send or not a message to Kafka
	context->is_fail_to_send_to_kafka = false;
}

/**
 * Stop the current connection and create a new connection to the kafka bus
 * @param context
 */
static void _reconnect_to_kafka( kafka_output_t *context ){
	time_t now = time(NULL); //seconds since the Epoch

	//reconnect immediately for the first time
	// otherwise, retry each 10 seconds
	if( context->last_connect_timestamp == 0 ||
			now - context->last_connect_timestamp > 10){
		log_write( LOG_INFO, "Trying to reconnect to the Kafka bus" );
		log_write( LOG_WARNING, "Total number of messages which cannot be sent successfully to the Kafka bus: %zu",
					context->nb_messages_to_send - context->nb_sent_messages );

		//remember the moment we are trying to connect to the Kafka
		context->last_connect_timestamp = now;
		//first: need to release the current resource
		_release_current_kafka_connection( context );
		//then: connect again
		_connect_to_kafka( context );
	}
}

/**
 * @brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was successfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll() and executes on
 * the application's thread.
 */
static void _dr_msg_cb (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
	kafka_output_t *context = (kafka_output_t *) opaque;
	//if we cannot send successfully the message
	if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR){
		log_write( LOG_ERR, "Message delivery failed: %s",
				rd_kafka_err2str(rkmessage->err));

		context->is_fail_to_send_to_kafka = true;
	}
	else
		//remember the number of messages
		context->nb_sent_messages ++;
}


kafka_output_t *kafka_output_init( const kafka_output_conf_t * config){
	if( config->is_enable == false )
		return NULL;

	kafka_output_t *ret = mmt_alloc_and_init_zero( sizeof( kafka_output_t ));
	ret->config = config;

	//trigger the connection
	_connect_to_kafka( ret );

	return ret;
}
bool kafka_output_send( kafka_output_t *context, const char *msg ){

	size_t len;
	char *message;

	context->nb_messages_to_send ++;

	//try to reconnect when
	// - failing to initialize
	// - or failing to send a message
	if( ! context->rd_topic || context->is_fail_to_send_to_kafka )
		_reconnect_to_kafka( context );

	//cannot initialize Kafka => must to put the message on its queue
	if( ! context->rd_topic )
		return false;

	len = strlen( msg );
	message = strndup( msg, len );
	/*
	 * Send/Produce message.
	 * This is an asynchronous call, on success it will only
	 * enqueue the message on the internal producer queue.
	 * The actual delivery attempts to the broker are handled
	 * by background threads.
	 * The previously registered delivery report callback
	 * (dr_msg_cb) is used to signal back to the application
	 * when the message has been delivered (or failed).
	 */

	retry:
	if (rd_kafka_produce(
			/* Topic object */
			context->rd_topic,
			/* Use builtin partitioner to select partition*/
			RD_KAFKA_PARTITION_UA,
			//rdkafka will free(3) message when it is done with it
			RD_KAFKA_MSG_F_FREE,
			/* Message payload (value) and length */
			message, len,
			/* Optional key and its length */
			NULL, 0,
			/* Message opaque, provided in
			 * delivery report callback as
			 * msg_opaque. */
			context) == -1) {

		/* Poll to handle delivery reports */
		if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
			/* If the internal queue is full, wait for
			 * messages to be delivered and then retry.
			 * The internal queue represents both
			 * messages to be sent and messages that have
			 * been sent or failed, awaiting their
			 * delivery report callback to be called.
			 *
			 * The internal queue is limited by the
			 * configuration property
			 * queue.buffering.max.messages */
			rd_kafka_poll( context->rd_producer, 1000/*block for max 1000ms*/);
			goto retry;
		}
		//Failed to *enqueue* message for producing.
		log_write( LOG_ERR, "Failed to produce to topic %s: %s",
				rd_kafka_topic_name( context->rd_topic ),
				rd_kafka_err2str(rd_kafka_last_error()));
		return false;
	}

	/* A producer application should continually serve
	 * the delivery report queue by calling rd_kafka_poll()
	 * at frequent intervals.
	 * Either put the poll call in your main loop, or in a
	 * dedicated thread, or call it after every
	 * rd_kafka_produce() call.
	 * Just make sure that rd_kafka_poll() is still called
	 * during periods where you are not producing any messages
	 * to make sure previously produced messages have their
	 * delivery report callback served (and any other callbacks
	 * you register). */
	rd_kafka_poll( context->rd_producer, 0/*non-blocking*/);
	return true;
}

void kafka_output_release(  kafka_output_t *context ){
	if( context == NULL )
		return;

	if( context->nb_messages_to_send > context->nb_sent_messages)
		//flush all pending messages in the queue to the kafka bus
		rd_kafka_flush( context->rd_producer, 10 * 1000 /* wait for max 10 seconds */);

	log_write( LOG_WARNING, "Total number of messages which cannot be sent successfully to the Kafka bus: %zu",
		context->nb_messages_to_send - context->nb_sent_messages );

	_release_current_kafka_connection( context );
	mmt_probe_free( context );
}
