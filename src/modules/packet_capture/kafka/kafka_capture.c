/*
 * kafka_capture.c
 *
 *  Created on: Feb 10, 2025
 *      Author: viet
 *
 * Kafka input module for consuming traffic data from Kafka topics.
 * Follows the same architecture as pcap_capture.c from the reference mmt-probe.
 */

#ifndef KAFKA_INPUT_MODULE
#define KAFKA_INPUT_MODULE
#endif

#include <assert.h>
#include <rdkafka.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../../../lib/log.h"
#include "../../../lib/malloc.h"
#include "../../../lib/ms_timer.h"
#include "../../../worker.h"
#include "kafka_capture.h"

// for one thread
struct kafka_worker_context_struct {
	pthread_t thread_handler;
};

// for all application
struct kafka_probe_context_struct {
	rd_kafka_t *consumer;
	rd_kafka_topic_partition_list_t *subscription;
};

static inline void _print_traffic_statistics(const ms_timer_t *timer,
																						void *arg) {
	struct timeval tv;
	probe_context_t *context = arg;

	// Kafka is always considered as online analysis (continuous stream)
	// get statistics: for Kafka we don't have NIC stats
	context->traffic_stat.nic.receive = 0;
	context->traffic_stat.nic.drop = 0;

	gettimeofday(&tv, NULL);
	context_print_traffic_stat(context, &tv);
}

/**
 * Process a single message consumed from Kafka.
 * This treats the message payload as a data line (similar to stream_capture).
 */
static void _got_a_message(u_char *user, size_t len, const u_char *data) {
	probe_context_t *context = (probe_context_t *)user;

	struct timeval now;

	// when having data to process
	if (data != NULL && len > 0) {
		pkthdr_t pkt_header;
		// use the current time as timestamp
		pkt_header.ts.tv_sec = time(NULL);
		pkt_header.ts.tv_usec = 0;
		pkt_header.caplen = len;
		pkt_header.len = len;
		pkt_header.user_args = NULL;

		worker_process_a_packet(context->smp[0], &pkt_header, data);

		context->traffic_stat.mmt.bytes.receive += len;
		context->traffic_stat.mmt.packets.receive++;
	}

	// Kafka is always online: use system time for timer updates
	gettimeofday(&now, NULL);

	worker_context_t *worker_context = context->smp[0];
	worker_update_timer(worker_context, &now);
}

// this function is called by main thread when user presses Ctrl+C
void kafka_capture_stop(probe_context_t *context) {
	context->is_exiting = true;
}

/**
 * Release kafka consumer resources
 * @param context
 */
static inline void _kafka_capture_release(probe_context_t *context) {
	int i;
	struct kafka_probe_context_struct *kafka_ctx = context->modules.kafka;

	// close kafka consumer
	if (kafka_ctx != NULL) {
		if (kafka_ctx->consumer != NULL) {
			// unsubscribe and close consumer
			rd_kafka_consumer_close(kafka_ctx->consumer);
			rd_kafka_destroy(kafka_ctx->consumer);
			kafka_ctx->consumer = NULL;
		}

		if (kafka_ctx->subscription != NULL) {
			rd_kafka_topic_partition_list_destroy(kafka_ctx->subscription);
			kafka_ctx->subscription = NULL;
		}
	}

	// release resources of each worker
	int workers_count;
	if (IS_SMP_MODE(context))
		workers_count = context->config->thread->thread_count;
	else
		workers_count = 1;

	for (i = 0; i < workers_count; i++) {
		mmt_probe_free(context->smp[i]->kafka);
		worker_release(context->smp[i]);
	}

	mmt_probe_free(context->smp);
	mmt_probe_free(context->modules.kafka);
}

/**
 * Initialize Kafka consumer connection
 * @param context
 * @return 0 on success, -1 on failure
 */
static inline int _init_kafka_consumer(probe_context_t *context) {
	char errstr[512];
	char brokers[256];
	rd_kafka_conf_t *rd_conf;
	rd_kafka_resp_err_t err;
	const kafka_input_conf_t *config = context->config->kafka_input;

	snprintf(brokers, sizeof(brokers), "%s:%u", config->host.host_name,
					config->host.port_number);

	log_write(LOG_INFO, "Initializing Kafka input consumer from %s, topic: %s",
						brokers, config->topic_name);

	// create Kafka client configuration
	rd_conf = rd_kafka_conf_new();

	// set bootstrap brokers
	if (rd_kafka_conf_set(rd_conf, "bootstrap.servers", brokers, errstr,
												sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		log_write(LOG_ERR, "Failed to set Kafka bootstrap.servers: %s", errstr);
		rd_kafka_conf_destroy(rd_conf);
		return -1;
	}

	// set consumer group id
	if (config->group_id != NULL && strlen(config->group_id) > 0) {
		if (rd_kafka_conf_set(rd_conf, "group.id", config->group_id, errstr,
													sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			log_write(LOG_ERR, "Failed to set Kafka group.id: %s", errstr);
			rd_kafka_conf_destroy(rd_conf);
			return -1;
		}
	} else {
		// default group id
		if (rd_kafka_conf_set(rd_conf, "group.id", "mmt-probe-consumer", errstr,
													sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			log_write(LOG_ERR, "Failed to set default Kafka group.id: %s", errstr);
			rd_kafka_conf_destroy(rd_conf);
			return -1;
		}
	}

	// set auto offset reset
	if (config->offset_reset != NULL && strlen(config->offset_reset) > 0) {
		if (rd_kafka_conf_set(rd_conf, "auto.offset.reset", config->offset_reset,
													errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			log_write(LOG_ERR, "Failed to set Kafka auto.offset.reset: %s", errstr);
			rd_kafka_conf_destroy(rd_conf);
			return -1;
		}
	} else {
		rd_kafka_conf_set(rd_conf, "auto.offset.reset", "earliest", errstr,
											sizeof(errstr));
	}

	// enable auto commit
	rd_kafka_conf_set(rd_conf, "enable.auto.commit", "true", errstr,
										sizeof(errstr));

	// set SASL authentication if credentials are provided
	if (config->username != NULL && strlen(config->username) > 0) {
		rd_kafka_conf_set(rd_conf, "security.protocol", "SASL_PLAINTEXT", errstr,
											sizeof(errstr));
		rd_kafka_conf_set(rd_conf, "sasl.mechanisms", "PLAIN", errstr,
											sizeof(errstr));
		rd_kafka_conf_set(rd_conf, "sasl.username", config->username, errstr,
											sizeof(errstr));
		rd_kafka_conf_set(rd_conf, "sasl.password", config->password, errstr,
											sizeof(errstr));
	}

	// create consumer instance
	// NOTE: rd_kafka_new() takes ownership of rd_conf
	context->modules.kafka->consumer =
			rd_kafka_new(RD_KAFKA_CONSUMER, rd_conf, errstr, sizeof(errstr));
	if (context->modules.kafka->consumer == NULL) {
		log_write(LOG_ERR, "Failed to create Kafka consumer: %s", errstr);
		return -1;
	}

	// redirect all topics from the rd_kafka_poll() queue to the consumer queue
	// for use with rd_kafka_consumer_poll()
	rd_kafka_poll_set_consumer(context->modules.kafka->consumer);

	// subscribe to topic
	context->modules.kafka->subscription = rd_kafka_topic_partition_list_new(1);
	rd_kafka_topic_partition_list_add(context->modules.kafka->subscription,
																		config->topic_name, RD_KAFKA_PARTITION_UA);

	err = rd_kafka_subscribe(context->modules.kafka->consumer,
													context->modules.kafka->subscription);
	if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		log_write(LOG_ERR, "Failed to subscribe to topic '%s': %s",
							config->topic_name, rd_kafka_err2str(err));
		return -1;
	}

	log_write(LOG_INFO, "Successfully subscribed to Kafka topic '%s' on %s",
						config->topic_name, brokers);

	return 0;
}

// public API
void kafka_capture_start(probe_context_t *context) {
	int i;
	ms_timer_t traffic_stat_report_timer;
	struct timeval now_tv;
	rd_kafka_message_t *rkmessage;

	int workers_count;
	if (IS_SMP_MODE(context)) {
		ABORT("Kafka input does not support multi-threading yet. Set .conf file: "
					"thread-nb=0");
	} else {
		log_write(
				LOG_INFO,
				"Starting Kafka input mode to consume from '%s' using the main thread",
				context->config->kafka_input->topic_name);
		// this worker will run on the main thread
		workers_count = 1;
	}

	// memory for the kafka module
	context->modules.kafka =
			mmt_alloc_and_init_zero(sizeof(struct kafka_probe_context_struct));

	// allocate context for each thread
	context->smp =
			mmt_alloc_and_init_zero(sizeof(worker_context_t) * workers_count);

	// allocate and initialize memory for each worker
	for (i = 0; i < workers_count; i++) {
		context->smp[i] = worker_alloc_init(context->config->stack_type);

		// when there is only one thread (no SMP mode)
		//  => reuse the same output of the main program
		if (!IS_SMP_MODE(context))
			context->smp[i]->output = context->output;

		context->smp[i]->index = i;

		// keep a reference to its root
		context->smp[i]->probe_context = context;

		// specific for kafka module
		context->smp[i]->kafka =
				mmt_alloc_and_init_zero(sizeof(struct kafka_worker_context_struct));

		// when there is only one worker running on the main thread
		worker_on_start(context->smp[0]);
	}

	// initialize Kafka consumer
	if (_init_kafka_consumer(context) != 0) {
		ABORT("Failed to initialize Kafka consumer. Check kafka-input "
					"configuration.");
	}

	ms_timer_init(&traffic_stat_report_timer, context->config->stat_period * S2MS,
								_print_traffic_statistics, context);

	// main consume loop
	while (!context->is_exiting) {
		// poll for messages with a 500ms timeout
		rkmessage = rd_kafka_consumer_poll(context->modules.kafka->consumer, 500);

		if (rkmessage == NULL) {
			// no message available, update timer anyway
			gettimeofday(&now_tv, NULL);
			ms_timer_set_time(&traffic_stat_report_timer, &now_tv);

			// call with NULL data to trigger timer updates
			_got_a_message((u_char *)context, 0, NULL);
			continue;
		}

		if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
			if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
				// end of partition, not an error - just no more messages for now
			} else {
				log_write(LOG_ERR, "Kafka consumer error: %s",
									rd_kafka_message_errstr(rkmessage));
			}
			rd_kafka_message_destroy(rkmessage);

			gettimeofday(&now_tv, NULL);
			ms_timer_set_time(&traffic_stat_report_timer, &now_tv);
			continue;
		}

		// process the message
		if (rkmessage->payload != NULL && rkmessage->len > 0) {
			_got_a_message((u_char *)context, rkmessage->len,
										(const u_char *)rkmessage->payload);
		}

		// free the message
		rd_kafka_message_destroy(rkmessage);

		gettimeofday(&now_tv, NULL);
		ms_timer_set_time(&traffic_stat_report_timer, &now_tv);
	}

	// stop all workers
	// when there is only one worker running on the main thread
	worker_on_stop(context->smp[0]);

	worker_print_common_statistics(context);

	// all workers have been stopped
	_kafka_capture_release(context);
}
