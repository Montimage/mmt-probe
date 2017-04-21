/*
 * send_msg_to_kafka.c
 *
 *  Created on: Apr 6, 2017
 *      Author: montimage
 */

//#include "rdkafka.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "processing.h"

rd_kafka_conf_t *conf = NULL;
char *topic;      /* Argument: topic to produce to */

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
static void dr_msg_cb (rd_kafka_t *rk,
		const rd_kafka_message_t *rkmessage, void *opaque) {
	if (rkmessage->err)
		fprintf(stderr, "%% Message delivery failed: %s\n",
				rd_kafka_err2str(rkmessage->err));
//	else
		//fprintf(stderr,
		//		"%% Message delivered (%zd bytes, "
		//		"partition %"PRId32")\n",
		//		rkmessage->len, rkmessage->partition);

	/* The rkmessage is destroyed automatically by librdkafka*/
}



void init_kafka(char * hostname, int port){
	mmt_probe_context_t * probe_context = get_probe_context_config();

	char errstr[512];       /* librdkafka API error reporting buffer */
	char brokers[256];    /* Argument: broker list */
	/* Temporary configuration object */

	sprintf( brokers, "%s:%u", hostname, port);


	/*
	 * Create Kafka client configuration place-holder
	 */

	conf = rd_kafka_conf_new();

	/* Set bootstrap broker(s) as a comma-separated list of
	 * host or host:port (default port 9092).
	 * librdkafka will use the bootstrap brokers to acquire the full
	 * set of brokers from the cluster. */

        rd_kafka_conf_set(conf, "queue.buffering.max.messages", "10000000", errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "batch.num.messages", "10000", errstr, sizeof(errstr)); 
        rd_kafka_conf_set(conf, "queue.buffering.max.ms", "1000", errstr, sizeof(errstr));
	
	if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
			errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%s\n", errstr);
		exit(0);
	}

	/* Set the delivery report callback.
	 * This callback will be called once per message to inform
	 * the application if delivery succeeded or failed.
	 * See dr_msg_cb() above. */
	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

	/*
	 * Create producer instance.
	 *
	 * NOTE: rd_kafka_new() takes ownership of the conf object
	 *       and the application must not reference it again after
	 *       this call.
	 */
	probe_context->kafka_producer_instance = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!probe_context->kafka_producer_instance) {
		fprintf(stderr,
				"%% Failed to create new producer: %s\n", errstr);
		exit (0);
		//return 1;
	}
	probe_context->topic_object = malloc (sizeof(kafka_topic_object_t)*1);

	if (probe_context->topic_object == NULL){
		fprintf(stderr, "%% Failed to create topic object: %s\n",
				rd_kafka_err2str(rd_kafka_last_error()));
		rd_kafka_destroy(probe_context->kafka_producer_instance);
		exit(0);
	}
	/* Create topic object that will be reused for each message
	 * produced.
	 *
	 * Both the producer instance (rd_kafka_t) and topic objects (topic_t)
	 * are long-lived objects that should be reused as much as possible.
	 */
	probe_context->topic_object->rkt_session = rd_kafka_topic_new(probe_context->kafka_producer_instance, "session.flow.report", NULL);
	probe_context->topic_object->rkt_event = rd_kafka_topic_new(probe_context->kafka_producer_instance, "event.report", NULL);
	probe_context->topic_object->rkt_cpu = rd_kafka_topic_new(probe_context->kafka_producer_instance, "cpu.report", NULL);
	probe_context->topic_object->rkt_ftp_download = rd_kafka_topic_new(probe_context->kafka_producer_instance, "ftp.download.report", NULL);
	probe_context->topic_object->rkt_multisession = rd_kafka_topic_new(probe_context->kafka_producer_instance, "multisession.report", NULL);
	probe_context->topic_object->rkt_license = rd_kafka_topic_new(probe_context->kafka_producer_instance, "license.stat", NULL);
	probe_context->topic_object->rkt_protocol_stat = rd_kafka_topic_new(probe_context->kafka_producer_instance, "protocol.stat", NULL);
	probe_context->topic_object->rkt_radius = rd_kafka_topic_new(probe_context->kafka_producer_instance, "radius.report", NULL);
	probe_context->topic_object->rkt_microflows = rd_kafka_topic_new(probe_context->kafka_producer_instance, "microflows.report", NULL);
	probe_context->topic_object->rkt_security = rd_kafka_topic_new(probe_context->kafka_producer_instance, "security.report", NULL);
	probe_context->topic_object->rkt_frag = rd_kafka_topic_new(probe_context->kafka_producer_instance, "frag.stat", NULL);
}

void send_msg_to_kafka(rd_kafka_topic_t *rkt, char *message){
	mmt_probe_context_t * probe_context = get_probe_context_config();

  /* Topic object */
	char errstr[512];       /* librdkafka API error reporting buffer */
	/* Topic configuration */
	size_t len = strlen(message);

	if (len == 0) {
		/* Empty line: only serve delivery reports */
		rd_kafka_poll(probe_context->kafka_producer_instance, 0/*non-blocking */);
                printf("WARNING:kafka message len is 0 \n");
		//continue;
	}

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
				rkt,
				/* Use builtin partitioner to select partition*/
				RD_KAFKA_PARTITION_UA,
				/* Make a copy of the payload. */
				RD_KAFKA_MSG_F_COPY,
				/* Message payload (value) and length */
				message, len,
				/* Optional key and its length */
				NULL, 0,
				/* Message opaque, provided in
				 * delivery report callback as
				 * msg_opaque. */
				NULL) == -1) {
			/**
			 * Failed to *enqueue* message for producing.
			 */
			fprintf(stderr,
					"%% Failed to produce to topic %s: %s\n",
					rd_kafka_topic_name(rkt),
					rd_kafka_err2str(rd_kafka_last_error()));

			/* Poll to handle delivery reports */
			if (rd_kafka_last_error() ==
					RD_KAFKA_RESP_ERR__QUEUE_FULL) {
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
				rd_kafka_poll(probe_context->kafka_producer_instance, 10/*block for max 1000ms*/);
				goto retry;
			}
		} else {
			//fprintf(stderr, "%% Enqueued message (%zd bytes) "
			//		"for topic %s\n",
			//		len, rd_kafka_topic_name(rkt));
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
		 rd_kafka_poll(probe_context->kafka_producer_instance, 0/*non-blocking*/);
}
