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
	rd_kafka_conf_t *rd_conf;
	rd_kafka_t  *rd_producer;
	const kafka_output_conf_t *config;
	size_t nb_no_send_messages; //number of messages that cannot be sent
	time_t last_error_timestamp;
};


static void _release_current_kafka_connection( kafka_output_t *context ){
	if( context == NULL )
		return;
	if( context->rd_producer )
		rd_kafka_destroy( context->rd_producer );
	if( context->rd_conf )
		rd_kafka_conf_destroy( context->rd_conf );
	if( context->rd_topic )
		rd_kafka_topic_destroy( context->rd_topic );
	context->last_error_timestamp = 0;
}

static void _connect_to_kafka( kafka_output_t *context ){

	rd_kafka_conf_res_t val;
	char errstr[512];       /* librdkafka API error reporting buffer */
	char brokers[256];    /* Argument: broker list */
	/*
	 * Create Kafka client configuration place-holder
	 */

	const kafka_output_conf_t *config = context->config;
	context->rd_conf = rd_kafka_conf_new();

	/* Set bootstrap broker(s) as a comma-separated list of
	 * host or host:port (default port 9092).
	 * librdkafka will use the bootstrap brokers to acquire the full
	 * set of brokers from the cluster. */

	rd_kafka_conf_set(context->rd_conf, "queue.buffering.max.messages", "10000000", errstr, sizeof(errstr));
	rd_kafka_conf_set(context->rd_conf, "batch.num.messages", "10000", errstr, sizeof(errstr));
	rd_kafka_conf_set(context->rd_conf, "queue.buffering.max.ms", "1000", errstr, sizeof(errstr));

	snprintf( brokers, sizeof( brokers ), "%s:%u", config->host.host_name, config->host.port_number );
	val = rd_kafka_conf_set(context->rd_conf, "bootstrap.servers", brokers, errstr, sizeof(errstr));

	if( val != RD_KAFKA_CONF_OK ) {
		log_write( LOG_ERR, "Failed to connect to kafka server: %s\n", errstr);
		kafka_output_release( context );
		contexturn NULL;
	}

	/* Set the delivery report callback.
	 * This callback will be called once per message to inform
	 * the application if delivery succeeded or failed.
	 * See dr_msg_cb() above. */
	rd_kafka_conf_set_dr_msg_cb( context->rd_conf, dr_msg_cb );

	/*
	 * Create producer instance.
	 *
	 * NOTE: rd_kafka_new() takes ownership of the conf object
	 *       and the application must not reference it again after
	 *       this call.
	 */
	context->rd_producer = rd_kafka_new(RD_KAFKA_PRODUCER, context->rd_conf, errstr, sizeof(errstr));
	if( context->rd_producer == NULL ){
		log_write( LOG_ERR, "Failed to create new kafka producer: %s", errstr);
		kafka_output_release( context );
		contexturn NULL;
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
		kafka_output_release( context );
		contexturn NULL;
	}
	log_write( LOG_INFO, "Connected to the Kafka %s", brokers );
}

/**
 * Stop the current connection and create a new connection to the kafka bus
 * @param context
 */
static void _reconnect_to_kafka( kafka_output_t *context ){
	log_write( LOG_INFO, "Reconnect to the Kafka bus" );
	//first: need to release the current resource
	_release_current_kafka_connection( context );
	//then: connect again
	_connect_to_kafka( context );
}

/**
 * @brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was succesfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll() and executes on
 * the application's thread.
 */
static void dr_msg_cb (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
	kafka_output_t *context = (kafka_output_t *) opaque;
	//if we cannot send successfully the message
	if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR){
		log_write( LOG_ERR, "Message delivery failed: %s",
				rd_kafka_err2str(rkmessage->err));

		time_t now = time(NULL); //seconds since the Epoch

		//remember the number of failed messages
		context->nb_no_send_messages ++;

		//reconnect after a few seconds of fail
		if( context->last_error_timestamp == 0 )
			context->last_error_timestamp = now;
		else if( now - context->last_error_timestamp > 10 ){
			_reconnect_to_kafka( context );
		}
	} else {
		//we sent successfully the message
		context->last_error_timestamp = 0;
	}
	//	else
	//fprintf(stderr,
	//		"%% Message delivered (%zd bytes, "
	//		"partition %"PRId32")\n",
	//		rkmessage->len, rkmessage->partition);

	/* The rkmessage is destroyed automatically by librdkafka*/
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

	/* Topic object */
	char errstr[512];       /* librdkafka API error reporting buffer */
	/* Topic configuration */
	size_t len = strlen( msg );
	char *message = strndup( msg, len );
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

		//Failed to *enqueue* message for producing.
		log_write( LOG_ERR, "Failed to produce to topic %s: %s",
				rd_kafka_topic_name( context->rd_topic ),
				rd_kafka_err2str(rd_kafka_last_error()));

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
			rd_kafka_poll( context->rd_producer, 10/*block for max 10ms*/);
			goto retry;
		}
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
	log_write( LOG_INFO, "Number of messages which cannot be sent successfully to the Kafka bus: %zu", context->nb_no_send_messages );

	_release_current_kafka_connection( context );
	mmt_probe_free( context );
}
