/*
 * File:   main.c
 * Author: montimage
 *
 * Created on 31 mai 2011, 14:09
 */

//TODO:
//Debug MMT_Security for multi-threads

#ifdef linux
#include <syscall.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h> //usleep, sleep
#include "mmt_core.h"
#include "processing.h"

#include "lib/security.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "tcpip/mmt_tcpip.h"

#ifdef DPDK
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_common.h>
#endif

//static void terminate_probe_processing(int wait_thread_terminate);

uint32_t get_2_power(uint32_t nb) {
	uint32_t ret = -1;
	while (nb != 0) {
		nb >>= 1;
		ret++;
	}
	return ret;
}

/* This function unregisters the registered handlers of condition report and flowstruct_init.
 * */
int cleanup_registered_handlers(void *arg) {
	int i = 0, j = 0, k = 1;
	struct smp_thread *th = (struct smp_thread *) arg;

	if (is_registered_attribute_handler(th->mmt_handler, PROTO_IP, IP_RTT,
			ip_rtt_handler) == 1)
		k &= unregister_attribute_handler(th->mmt_handler, PROTO_IP, IP_RTT,
				ip_rtt_handler);

	if (is_registered_attribute_handler(th->mmt_handler, PROTO_TCP,
			TCP_CONN_CLOSED, tcp_closed_handler) == 1)
		k &= unregister_attribute_handler(th->mmt_handler, PROTO_TCP,
				TCP_CONN_CLOSED, tcp_closed_handler);

	if (is_registered_attribute_handler(th->mmt_handler, PROTO_IP,
			PROTO_SESSION, flow_nb_handle) == 1)
		k &= unregister_attribute_handler(th->mmt_handler, PROTO_IP,
				PROTO_SESSION, flow_nb_handle);

	if (is_registered_attribute_handler(th->mmt_handler, PROTO_IPV6,
			PROTO_SESSION, flow_nb_handle) == 1)
		k &= unregister_attribute_handler(th->mmt_handler, PROTO_IPV6,
				PROTO_SESSION, flow_nb_handle);
	for (i = 0; i < mmt_probe.mmt_conf->condition_reports_nb; i++) {
		mmt_condition_report_t * condition_report =
				&mmt_probe.mmt_conf->condition_reports[i];
		for (j = 0; j < condition_report->attributes_nb; j++) {
			mmt_condition_attribute_t * condition_attribute =
					&condition_report->attributes[j];
			mmt_condition_attribute_t * handler_attribute =
					&condition_report->handlers[j];
			uint32_t protocol_id = get_protocol_id_by_name(
					condition_attribute->proto);
			uint32_t attribute_id =
					get_attribute_id_by_protocol_and_attribute_names(
							condition_attribute->proto,
							condition_attribute->attribute);
			if (is_registered_attribute_handler(th->mmt_handler, protocol_id,
					attribute_id,
					get_handler_by_name(handler_attribute->handler)) == 1) {
				k &= unregister_attribute_handler(th->mmt_handler, protocol_id,
						attribute_id,
						get_handler_by_name(handler_attribute->handler));
			}

		}
	}
	return k;
}

void cleanup_report_allocated_memory() {

	mmt_probe_context_t * mmt_conf = mmt_probe.mmt_conf;
	int i, j = 0, l = 0;
	if (mmt_conf->server_adresses != NULL) {
		for (i = 0; i < mmt_conf->server_ip_nb; i++) {
			free(mmt_conf->server_adresses->server_portnb);
		}
		free(mmt_conf->server_adresses);
	}
	if (mmt_conf->register_new_condition_reports != NULL
			&& mmt_conf->register_new_event_reports != NULL) {
		for (i = 0; i < mmt_conf->new_condition_reports_nb; i++) {
			free(mmt_conf->register_new_condition_reports[i].attributes);
			mmt_conf->register_new_condition_reports[i].attributes = NULL;
			free(mmt_conf->register_new_condition_reports[i].handlers);
			mmt_conf->register_new_condition_reports[i].handlers = NULL;
		}

		for (i = 0; i < mmt_conf->new_event_reports_nb; i++) {
			free(mmt_conf->register_new_event_reports[i].attributes);
			mmt_conf->register_new_event_reports[i].attributes = NULL;
		}

		free(mmt_conf->register_new_condition_reports);
		mmt_conf->register_new_condition_reports = NULL;

		free(mmt_conf->register_new_event_reports);
		mmt_conf->register_new_event_reports = NULL;

	}

	for (i = 0; i < mmt_conf->condition_reports_nb; i++) {
		free(mmt_conf->condition_reports[i].attributes);
		mmt_conf->condition_reports[i].attributes = NULL;
		free(mmt_conf->condition_reports[i].handlers);
		mmt_conf->condition_reports[i].handlers = NULL;
	}
	for (i = 0; i < mmt_conf->event_reports_nb; i++) {
		free(mmt_conf->event_reports[i].attributes);
		mmt_conf->event_reports[i].attributes = NULL;
	}
	if (mmt_conf->condition_reports != NULL) {
		free(mmt_conf->condition_reports);
		mmt_conf->condition_reports = NULL;
	}
	if (mmt_conf->event_reports != NULL) {
		free(mmt_conf->event_reports);
		mmt_conf->event_reports = NULL;
	}
	for (i = 0; i < mmt_conf->security_reports_nb; i++) {
		free(mmt_conf->security_reports[i].attributes);
		mmt_conf->security_reports[i].attributes = NULL;
		for (l = 0; l < mmt_conf->security_reports[i].event_name_nb; l++) {
			free(mmt_conf->security_reports[i].event_name[l]);
			mmt_conf->security_reports[i].event_name[l] = NULL;
		}
		free(mmt_conf->security_reports[i].event_name);
		mmt_conf->security_reports[i].event_name = NULL;
		free(mmt_conf->security_reports[i].event_id);
		mmt_conf->security_reports[i].event_id = NULL;
	}
	if (mmt_conf->security_reports != NULL) {
		free(mmt_conf->security_reports);
	}

	int retval = 0;
	uint64_t count = 0;

	if (mmt_conf->thread_nb > 1) {
		for (i = 0; i < mmt_conf->thread_nb; i++) {
			if (mmt_conf->socket_enable == 1) {
				//printf ("th_nb =%2u, packets_reports_send = %"PRIu64" (%5.2f%%) \n", i,
				//mmt_probe.smp_threads[i].packet_send,
				//	 mmt_probe.smp_threads[i].packet_send * 100.0 / mmt_probe.smp_threads[i].nb_packets );
				printf("[mmt-probe-2]{%u,%"PRIu64",%f}\n", i,
						mmt_probe.smp_threads[i].packet_send,
						mmt_probe.smp_threads[i].packet_send * 100.0
								/ mmt_probe.smp_threads[i].nb_packets);

				//  mmt_conf->report_length += snprintf(&mmt_conf->report_msg[mmt_conf->report_length],1024 - mmt_conf->report_length,"%d,%"PRIu64",%f,", i, mmt_probe.smp_threads[i].packet_send, mmt_probe.smp_threads[i].packet_send * 100.0 / mmt_probe.smp_threads[i].nb_packets );
				count += mmt_probe.smp_threads[i].packet_send;

			}
#ifdef PCAP
			data_spsc_ring_free( &mmt_probe.smp_threads[i].fifo );
#endif
			if (mmt_probe.smp_threads[i].report != NULL) {
				for (j = 0; j < mmt_conf->security_reports_nb; j++) {
					if (mmt_probe.smp_threads[i].report[j].data != NULL) {
						if (mmt_probe.smp_threads[i].report[j].security_report_counter
								> 0 && mmt_probe.mmt_conf->socket_enable == 1) {

							mmt_probe.smp_threads[i].report[j].grouped_msg.msg_hdr.msg_iov =
									mmt_probe.smp_threads[i].report[j].msg;
							mmt_probe.smp_threads[i].report[j].grouped_msg.msg_hdr.msg_iovlen =
									mmt_probe.smp_threads[i].report[j].security_report_counter;
							if (mmt_probe.mmt_conf->socket_domain == 1
									|| mmt_probe.mmt_conf->socket_domain == 2)
								retval =
										sendmmsg(
												mmt_probe.smp_threads[i].sockfd_internet[j],
												&mmt_probe.smp_threads[i].report[j].grouped_msg,
												1, 0);
							if (mmt_probe.mmt_conf->socket_domain == 0
									|| mmt_probe.mmt_conf->socket_domain == 2)
								retval =
										sendmmsg(
												mmt_probe.smp_threads[i].sockfd_unix,
												&mmt_probe.smp_threads[i].report[j].grouped_msg,
												1, 0);
							if (retval == -1)
								perror("sendmmsg()");

						}

						if (mmt_probe.smp_threads[i].report[j].msg != NULL) {
							free(mmt_probe.smp_threads[i].report[j].msg);
						}
						for (l = 0; l < mmt_conf->nb_of_report_per_msg; l++)
							free(mmt_probe.smp_threads[i].report[j].data[l]);
					}
					free(mmt_probe.smp_threads[i].report[j].data);
				}

				free(mmt_probe.smp_threads[i].report);

			}

			if (mmt_probe.smp_threads[i].sockfd_internet != NULL) {
				for (j = 0; j < mmt_conf->server_ip_nb; j++) {
					if (mmt_probe.smp_threads[i].sockfd_internet[j] > 0)
						close(mmt_probe.smp_threads[i].sockfd_internet[j]);
				}
				free(mmt_probe.smp_threads[i].sockfd_internet);
			}

			if (mmt_probe.smp_threads[i].security_attributes != NULL) {
				free(mmt_probe.smp_threads[i].security_attributes);
			}

			if (mmt_probe.smp_threads[i].cache_message_list != NULL) {
				free(mmt_probe.smp_threads[i].cache_message_list);
				mmt_probe.smp_threads[i].cache_message_list = NULL;
			}

		}
		if (mmt_conf->socket_enable == 1) {
			//printf ("total_packets_report_send_by_threads = %"PRIu64" \n",count);
			//mmt_conf->report_length += snprintf(&mmt_conf->report_msg[mmt_conf->report_length - 1],1024 - mmt_conf->report_length,",%"PRIu64"}",count);
			printf("[mmt-probe-3]{%"PRIu64"} \n", count);
		}

		free(mmt_probe.smp_threads);
		mmt_probe.smp_threads = NULL;

	} else {
		if (mmt_probe.smp_threads->report != NULL) {
			for (j = 0; j < mmt_conf->security_reports_nb; j++) {
				if (mmt_probe.smp_threads->report[j].data != NULL) {
					if (mmt_probe.smp_threads->report[j].security_report_counter
							> 0 && mmt_conf->socket_enable == 1) {

						mmt_probe.smp_threads->report[j].grouped_msg.msg_hdr.msg_iov =
								mmt_probe.smp_threads->report[j].msg;
						mmt_probe.smp_threads->report[j].grouped_msg.msg_hdr.msg_iovlen =
								mmt_probe.smp_threads->report[j].security_report_counter;
						if (mmt_probe.mmt_conf->socket_domain == 1
								|| mmt_probe.mmt_conf->socket_domain == 2)
							retval =
									sendmmsg(
											mmt_probe.smp_threads->sockfd_internet[j],
											&mmt_probe.smp_threads->report[j].grouped_msg,
											1, 0);
						if (mmt_probe.mmt_conf->socket_domain == 0
								|| mmt_probe.mmt_conf->socket_domain == 2)
							retval =
									sendmmsg(mmt_probe.smp_threads->sockfd_unix,
											&mmt_probe.smp_threads->report[j].grouped_msg,
											1, 0);
						//printf ("retval = %u, len = %u\n",retval,mmt_probe.smp_threads->report[j].grouped_msg.msg_hdr.msg_iovlen);
						if (retval == -1)
							perror("sendmmsg()");
					}

					if (mmt_probe.smp_threads->report[j].msg != NULL) {
						free(mmt_probe.smp_threads->report[j].msg);
					}
					for (l = 0; l < mmt_conf->nb_of_report_per_msg; l++)
						free(mmt_probe.smp_threads->report[j].data[l]);
				}
				free(mmt_probe.smp_threads->report[j].data);

			}
			free(mmt_probe.smp_threads->report);
		}

		if (mmt_probe.smp_threads->sockfd_internet != NULL) {
			for (j = 0; j < mmt_conf->server_ip_nb; j++) {
				if (mmt_probe.smp_threads->sockfd_internet[j] > 0)
					close(mmt_probe.smp_threads->sockfd_internet[j]);
			}
			free(mmt_probe.smp_threads->sockfd_internet);
		}

		if (mmt_probe.smp_threads->security_attributes != NULL) {
			free(mmt_probe.smp_threads->security_attributes);
		}
		if (mmt_conf->socket_enable == 1) {
			// mmt_conf->report_length += snprintf(&mmt_conf->report_msg[mmt_conf->report_length],1024 - mmt_conf->report_length,"%"PRIu64",%f",mmt_probe.smp_threads->packet_send, mmt_probe.smp_threads->packet_send * 100.0 / mmt_probe.smp_threads->nb_packets);
			//mmt_conf->report_length += snprintf(&mmt_conf->report_msg[mmt_conf->report_length - 1],1024 - mmt_conf->report_length,",%"PRIu64"}",mmt_probe.smp_threads->packet_send);
			printf("[mmt-probe-2]{%u,%"PRIu64",%f} \n",
					mmt_probe.smp_threads->thread_index,
					mmt_probe.smp_threads->packet_send,
					mmt_probe.smp_threads->packet_send * 100.0
							/ mmt_probe.smp_threads->nb_packets);
			printf("[mmt-probe-3]{%"PRIu64"} \n",
					mmt_probe.smp_threads->packet_send);
		}
		if (mmt_probe.smp_threads->cache_message_list != NULL) {
			free(mmt_probe.smp_threads->cache_message_list);
			mmt_probe.smp_threads->cache_message_list = NULL;
		}

		free(mmt_probe.smp_threads);
		mmt_probe.smp_threads = NULL;
	}

	/* Destroy the producer instance */
	if (mmt_conf->kafka_producer_instance != NULL) {
		fprintf(stderr, "Flushing final messages..\n");
		rd_kafka_flush(mmt_conf->kafka_producer_instance,
				10 * 1000 /* wait for max 10 seconds */);
		/* Destroy topic object */
		if (mmt_conf->topic_object != NULL) {
			if (mmt_conf->topic_object->rkt_session != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_session);
			if (mmt_conf->topic_object->rkt_event != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_event);
			if (mmt_conf->topic_object->rkt_cpu != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_cpu);
			if (mmt_conf->topic_object->rkt_ftp_download != NULL)
				rd_kafka_topic_destroy(
						mmt_conf->topic_object->rkt_ftp_download);
			if (mmt_conf->topic_object->rkt_multisession != NULL)
				rd_kafka_topic_destroy(
						mmt_conf->topic_object->rkt_multisession);
			if (mmt_conf->topic_object->rkt_license != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_license);
			if (mmt_conf->topic_object->rkt_protocol_stat != NULL)
				rd_kafka_topic_destroy(
						mmt_conf->topic_object->rkt_protocol_stat);
			if (mmt_conf->topic_object->rkt_radius != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_radius);
			if (mmt_conf->topic_object->rkt_microflows != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_microflows);
			if (mmt_conf->topic_object->rkt_security != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_security);
			if (mmt_conf->topic_object->rkt_frag != NULL)
				rd_kafka_topic_destroy(mmt_conf->topic_object->rkt_frag);
			free(mmt_conf->topic_object);
		}
		rd_kafka_destroy(mmt_conf->kafka_producer_instance);
	}

}
/* This function is executed before exiting the program,
 * to free the allocated memory, close extraction, , cancels threads, flush the reports etc
 * */
void terminate_probe_processing(int wait_thread_terminate) {
	char lg_msg[1024];
	mmt_probe_context_t * mmt_conf = mmt_probe.mmt_conf;
	int i, j = 0, l = 0;

	//For MMT_Security
	//To finish results file (e.g. write summary in the XML file)
	todo_at_end();
	//End for MMT_Security

	//Cleanup
	if (mmt_conf->thread_nb == 1) {
		//One thread for processing packets
		//Cleanup the MMT handler
#ifdef PCAP		
		clean_up_security2(&mmt_probe);
		if (cleanup_registered_handlers (mmt_probe.smp_threads) == 0) {
			fprintf(stderr, "Error while unregistering attribute  handlers thread_nb = %u !\n",mmt_probe.smp_threads->thread_index);
		}

		radius_ext_cleanup(mmt_probe.smp_threads->mmt_handler); // cleanup our event handler for RADIUS initializations
		//process_session_timer_handler(mmt_probe.->mmt_handler);
		if (mmt_probe.smp_threads->report_counter == 0)mmt_probe.smp_threads->report_counter++;
		if (mmt_conf->enable_proto_without_session_stats == 1 || mmt_conf->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, (void *) mmt_probe.smp_threads);
		mmt_close_handler(mmt_probe.smp_threads->mmt_handler);
#endif

		if (mmt_conf->microf_enable == 1)
			report_all_protocols_microflows_stats(
					(void *) mmt_probe.smp_threads);
		if (mmt_conf->output_to_file_enable == 1)
			flush_messages_to_file_thread((void *) mmt_probe.smp_threads);
		exit_timers();
	} else {
		if (wait_thread_terminate == 1) {
			/* Add a dummy packet at each thread packet list tail */
#ifdef PCAP

			for (i = 0; i < mmt_conf->thread_nb; i++) {

				pthread_spin_lock(&mmt_probe.smp_threads[i].lock);
				list_add_tail((struct list_entry *) &mmt_probe.smp_threads[i].null_pkt,
						(struct list_entry *) &mmt_probe.smp_threads[i].pkt_head);
				pthread_spin_unlock(&mmt_probe.smp_threads[i].lock);
			}
#endif
		}

		/* wait for all threads to complete */
		if (wait_thread_terminate == 1) {
			for (i = 0; i < mmt_conf->thread_nb; i++) {
#ifdef PCAP

				pthread_join(mmt_probe.smp_threads[i].handle, NULL);
#endif

				if (mmt_conf->microf_enable == 1)
					report_all_protocols_microflows_stats(
							&mmt_probe.smp_threads[i]);
				//if (mmt_probe.smp_threads->report_counter == 0)mmt_probe.smp_threads->report_counter++;
				//if (mmt_conf->enable_proto_without_session_stats == 1)iterate_through_protocols(protocols_stats_iterator, &mmt_probe.smp_threads[i]);
				if (mmt_conf->output_to_file_enable == 1)
					flush_messages_to_file_thread(&mmt_probe.smp_threads[i]);

			}
			exit_timers();

		} else if (wait_thread_terminate == 0) {
			//We might have catched a SEGV or ABORT signal.
			//We have seen the threads in deadlock situations.
			//Wait 30 seconds then cancel the threads
			//Once cancelled, join should give "THREAD_CANCELLED" retval
#ifdef PCAP
			//sleep(30);
			atomic_store (do_abort,1);
			for (i = 0; i < mmt_conf->thread_nb; i++) {

				int s;
				s = pthread_cancel(mmt_probe.smp_threads[i].handle);
				if (s != 0) {
					exit(1);
				}
			}

#endif
#ifdef PCAP
			for (i = 0; i < mmt_conf->thread_nb; i++) {
				//pthread_join(mmt_probe.smp_threads[i].handle, NULL);
				if (mmt_probe.smp_threads[i].mmt_handler != NULL) {
					printf ("thread_id = %u, packet = %lu \n",mmt_probe.smp_threads[i].thread_index, mmt_probe.smp_threads[i].nb_packets );

					//flowstruct_cleanup(mmt_probe.smp_threads[i].mmt_handler); // cleanup our event handler
					if (cleanup_registered_handlers (&mmt_probe.smp_threads[i]) == 0) {
						fprintf(stderr, "Error while unregistering attribute  handlers thread_nb = %u !\n",mmt_probe.smp_threads[i].thread_index);
					}
					radius_ext_cleanup(mmt_probe.smp_threads[i].mmt_handler); // cleanup our event handler for RADIUS initializations
					//process_session_timer_handler(mmt_probe.smp_threads[i].mmt_handler);
					if (mmt_probe.smp_threads[i].report_counter == 0)mmt_probe.smp_threads[i].report_counter++;
					if (mmt_conf->enable_proto_without_session_stats == 1 || mmt_conf->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, &mmt_probe.smp_threads[i]);
					mmt_close_handler(mmt_probe.smp_threads[i].mmt_handler);
					mmt_probe.smp_threads[i].mmt_handler = NULL;
					free(mmt_probe.smp_threads[i].cache_message_list);
					mmt_probe.smp_threads[i].cache_message_list = NULL;
				}
				if (mmt_conf->microf_enable == 1)report_all_protocols_microflows_stats(&mmt_probe.smp_threads[i].iprobe);
				//exit_timers();

			}
#endif
			exit_timers();

		}

	}
	// cancel the thread used by cpu_mem_usage
	if (mmt_conf->cpu_mem_usage_enabled == 1) {
		int c;
		c = pthread_cancel(mmt_conf->cpu_ram_usage_thr);
		if (c != 0) {
			exit(1);
		}
	}
	//Now close the reporting files.
	//Offline or Online processing
	if (mmt_conf->input_mode == OFFLINE_ANALYSIS
			|| mmt_conf->input_mode == ONLINE_ANALYSIS) {
		if (mmt_conf->data_out_file)
			fclose(mmt_conf->data_out_file);
		sprintf(lg_msg, "Closing output results file");
		mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_CLOSE_OUTPUT, lg_msg);

	}
	cleanup_report_allocated_memory();

	if (mmt_conf->security2_enable)
		security_close();

	//printf("close_extraction_start\n");
	close_extraction();
	//printf("close_extraction_finish\n");
	//if( mmt_conf->security2_enable )
	//	close_security();
	mmt_log(mmt_conf, MMT_L_INFO, MMT_E_END, "Closing MMT Extraction engine!");
	mmt_log(mmt_conf, MMT_L_INFO, MMT_P_END, "Closing MMT Probe!");
	if (wait_thread_terminate == 1)
		if (mmt_conf->log_output)
			fclose(mmt_conf->log_output);

}

/* This signal handler ensures clean exits */
void signal_handler(int type) {
	static int i = 0;
	i++;
	int j, k, l;
	int retval = 0;
	char lg_msg[1024];
	int childpid;
	fprintf(stderr, "\n reception of signal %d\n", type);
	fflush( stderr);
#ifdef PCAP
	cleanup( 0, &mmt_probe );
#endif

	if (i == 1) {
# ifdef PCAP
		//do_abort = 1;
		atomic_store (do_abort,1);
		printf ("start terminating \n");
		terminate_probe_processing(0);
		printf ("terminate finish \n");
		/*              if (mmt_probe.mmt_conf->load_enable == 1){
		 execl("/opt/dev/mmt-probe/probe", "probe","load_running", NULL);
		 mmt_probe.mmt_conf->load_enable == 0;
		 }*/

#endif

#ifdef DPDK
		atomic_store (do_abort, 1);
		do_abort = 1;
		return;
#endif
	} else {
		signal(SIGINT, signal_handler);
		sprintf(lg_msg,
				"reception of signal %i while processing a signal exiting!",
				type);
		/*
		 mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_TERMINATION, "Multi signal received! cleaning up!");
		 if(strlen(mmt_probe.mmt_conf->input_f_name) > 1) {
		 if (remove(mmt_probe.mmt_conf->input_f_name) != 0) {
		 //fprintf(stdout, "Trace Error deleting file\n");
		 sprintf(lg_msg, "Error while deleting trace file: %s! File will remain on the system. Manual delete required!", mmt_probe.mmt_conf->input_f_name);
		 mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_DELETE, lg_msg);
		 } else {
		 sprintf(lg_msg, "Trace file %s deleted following the reception of error signal", mmt_probe.mmt_conf->input_f_name);
		 mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_TRACE_DELETE, lg_msg);
		 //fprintf(stdout, "Trace File %s successfully deleted\n", trace_file_name);
		 }
		 }
		 */
		exit(0);
	}

	switch (type) {
	case SIGSEGV:
		mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_SEGV_ERROR,
				"Segv signal received! cleaning up!");
		//terminate_probe_processing();
		//fprintf(stdout, "SEGMENTATION FAULT!!!! Exiting!!! \n");
		//Now delete the last input file if it is available. This is to avoid blocking situation in continuous trace file processing
		/*
		 if(strlen(mmt_probe.mmt_conf->input_f_name) > 1) {
		 if (remove(mmt_probe.mmt_conf->input_f_name) != 0) {
		 //fprintf(stdout, "Trace Error deleting file\n");
		 sprintf(lg_msg, "Error while deleting trace file: %s! File will remain on the system. Manual delete required!", mmt_probe.mmt_conf->input_f_name);
		 mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_DELETE, lg_msg);
		 } else {
		 sprintf(lg_msg, "Trace file %s deleted following the reception of error signal", mmt_probe.mmt_conf->input_f_name);
		 mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_TRACE_DELETE, lg_msg);
		 //fprintf(stdout, "Trace File %s successfully deleted\n", trace_file_name);
		 }
		 }
		 */
		exit(1);
	case SIGTERM:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION,
				"Termination signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(1);
	case SIGABRT:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION,
				"Abort signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(1);
	case SIGINT:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION,
				"Interruption Termination signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(0);
#ifndef _WIN32
	case SIGKILL:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION,
				"Kill signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(1);
#endif
	default:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION,
				"Received an unexpected signal!");
		exit(1);
	}
}

/* This function monitors CPU and memory usage*/
void *cpu_ram_usage_routine(void * args) {
	long double t1[7], t2[7];
	FILE *fp;
	char dump[50];
	//int freq = *((int*) f);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	char message[MAX_MESS + 1];
	int valid = 0;
	struct timeval ts;
	while (!do_abort) {
		fp = fopen("/proc/stat", "r");
		if (fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &t1[0], &t1[1], &t1[2], &t1[3])
				!= 4)
			fprintf(stderr, "\nError in fscanf the cpu stat\n");
		fclose(fp);

		fp = fopen("/proc/meminfo", "r");
		if (fscanf(fp, "%*s %Lf %*s %*s %Lf %*s %*s %Lf %*s", &t1[4], &t1[5],
				&t1[6]) != 3)
			fprintf(stderr, "\nError in fscanf the mem info\n");
		//printf("Memtotal: %Lf kB.\nMemFree: %Lf kB.\nMemAvailable: %Lf kB.\n", t1[4], t1[5], t1[6]);
		fclose(fp);

		sleep(probe_context->cpu_reports->cpu_mem_usage_rep_freq);

		fp = fopen("/proc/stat", "r");
		if (fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &t2[0], &t2[1], &t2[2], &t2[3])
				!= 4)
			fprintf(stderr, "\nError in fscanf the cpu stat\n");
		fclose(fp);

		fp = fopen("/proc/meminfo", "r");
		if (fscanf(fp, "%*s %Lf %*s %*s %Lf %*s %*s %Lf %*s", &t2[4], &t2[5],
				&t2[6]) != 3)
			fprintf(stderr, "\nError in fscanf the mem info\n");
		//printf("Memtotal: %Lf kB.\nMemFree: %Lf kB.\nMemAvailable: %Lf kB.\n", t1[4], t1[5], t1[6]);
		fclose(fp);

		probe_context->cpu_reports->cpu_usage_avg = 100
				* ((t2[0] + t2[1] + t2[2]) - (t1[0] + t1[1] + t1[2]))
				/ ((t2[0] + t2[1] + t2[2] + t2[3])
						- (t1[0] + t1[1] + t1[2] + t1[3]));
		probe_context->cpu_reports->mem_usage_avg = (t2[6] + t1[6]) * 100
				/ (2 * t1[4]);

		if (probe_context->redis_enable == 1
				|| probe_context->kafka_enable == 1) {
			valid = 0;
			//Print this report every 5 second
			time_t present_time;
			gettimeofday(&ts, NULL);

			valid = snprintf(message, MAX_MESS, "%u,%u,\"%s\",%lu.%06lu", 200,
					probe_context->probe_id_number, probe_context->input_source,
					ts.tv_sec, ts.tv_usec);

			if (probe_context->cpu_mem_usage_enabled == 1) {
				valid += snprintf(&message[valid], MAX_MESS,
						",%3.2Lf%%,%3.2Lf%% \n",
						probe_context->cpu_reports->cpu_usage_avg,
						probe_context->cpu_reports->mem_usage_avg);
			}
			message[valid] = '\0';

			if (probe_context->redis_enable
					&& probe_context->cpu_mem_output_channel[1])
				send_message_to_redis("cpu.report", message);
			if (probe_context->kafka_enable
					&& probe_context->cpu_mem_output_channel[2])
				send_msg_to_kafka(probe_context->topic_object->rkt_cpu,
						message);
			//printf("The current CPU utilization is : %Lf percent\n",cpu_usage_avg);
			//printf("Memory usage : %Lf percent (%Lf/%Lf)\n",((t2[6]+t1[6])*100/(2*t1[4])),(t2[6]+t1[6])/2, t1[4]);
		}
	}

	return (0);
}

int main(int argc, char **argv) {
	int i, j, l = 0;
	char lg_msg[1024];
	sigset_t signal_set;
	char single_file[MAX_FILE_NAME + 1] = { 0 };
	//pthread_t cpu_ram_usage_thr;
	pthread_mutex_init(&mutex_lock, NULL);
	pthread_spin_init(&spin_lock, 0);

	mmt_probe.smp_threads = NULL;
	mmt_probe.mmt_conf = NULL;

	mmt_probe_context_t * mmt_conf = get_probe_context_config();
	mmt_probe.mmt_conf = mmt_conf;
	/*
	 event_report_flag = malloc (sizeof(uint8_t));
	 config_updated = malloc (sizeof(uint8_t));
	 session_report_flag = malloc (sizeof(uint8_t));
	 security2_report_flag = malloc (sizeof(uint8_t));
	 condition_report_flag = malloc (sizeof(uint8_t));
	 behaviour_flag = malloc (sizeof(uint8_t));
	 ftp_reconstruct_flag = malloc (sizeof(uint8_t));
	 micro_flows_flag = malloc (sizeof(uint8_t));
	 */

	do_abort = malloc(sizeof(uint8_t));

	atomic_store(do_abort, 0);

	////////////////dynamic_conf/////////
	mmt_conf->event_reports = NULL;
	////////////////////

#ifdef DPDK
	/* Initialize the Environment Abstraction Layer (EAL). */
	//do_abort = 0;
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
	rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;
	parseOptions(argc, argv, mmt_conf);
#endif

#ifdef PCAP
	/*        if (argv[1] != NULL){
	 printf("argv = %s\n",argv[1]);
	 sleep (2);
	 if (strcmp(argv[1],"load_running")==0) mmt_conf->probe_load_running = 1;
	 }
	 */
	parseOptions(argc, argv, &mmt_probe);
	//        dynamic_conf();
#endif

	mmt_conf->log_output = fopen(mmt_conf->log_file, "a");

	if (mmt_conf->log_output == NULL) {
		printf("Error: log file creation failed \n");
	}

	sigfillset(&signal_set);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);

	if (mmt_conf->sampled_report == 0 && mmt_conf->output_to_file_enable) {
		int len = 0;
		len = snprintf(single_file, MAX_FILE_NAME, "%s%s",
				mmt_conf->output_location, mmt_conf->data_out);
		single_file[len] = '\0';
		update_reporting_time = time(0);

		mmt_conf->data_out_file = fopen(single_file, "w");

		if (mmt_conf->data_out_file == NULL) {
			fprintf( stderr, "\n[e] Error: %d creation of \"%s\" failed: %s\n",
					errno, single_file, strerror( errno));
			exit(0);
		}

		sprintf(lg_msg, "Open output results file: %s", single_file);
		mmt_log(mmt_conf, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);
	}
	is_stop_timer = 0;

	//if (license_expiry_check(0) == 1){
	//exit(0);
	//}
	mmt_conf->pid = getpid();
	printf("main process_id = %d", mmt_conf->pid);
	mmt_log(mmt_conf, MMT_L_INFO, MMT_P_INIT, "MMT Probe started!");

	//Add the module for printing cpu_mem_usage here
	if (mmt_conf->cpu_mem_usage_enabled == 1) {
		//printf("CPU, RAM usage report enabled\n");
		pthread_create(&mmt_conf->cpu_ram_usage_thr, NULL,
				cpu_ram_usage_routine, NULL);
	}

	if (!init_extraction()) { // general ixE initialization
		fprintf(stderr, "MMT extract init error\n");
		mmt_log(mmt_conf, MMT_L_ERROR, MMT_E_INIT_ERROR,
				"MMT Extraction engine initialization error! Exiting!");
		return EXIT_FAILURE;
	}
	//config security2
	//	if( mmt_conf->security2_enable ){
	//initialize security rules
	strcpy(mmt_conf->security2_excluded_rules, "20-50");
	if (security_open() != 0)
		return 1;
	//	}
	printf("[info] Versions: Probe v%s (%s), DPI v%s, Security v0.9b \n",
	VERSION, GIT_VERSION, //these version information are given by Makefile
			mmt_version());

	printf("[info] built %s %s\n", __DATE__, __TIME__);

	/*
	 sr_conn_ctx_t *connection = NULL;
	 sr_session_ctx_t *session = NULL;
	 sr_subscription_ctx_t *subscription = NULL;
	 mmt_init(&connection, &session);
	 read_mmt_config(session);
	 mmt_cleanup(connection, session, subscription);

	 printf ("HERE1\n");
	 mmt_init(&connection, &session);
	 mmt_change_subscribe(session, &subscription);
	 */

	//        dynamic_conf();
	/*	for(i = 0; i < mmt_conf->security_reports_nb; i++) {
	 if (mmt_conf->security_reports[i].enable == 1){
	 mmt_conf->security_reports[i].event_id = malloc (mmt_conf->security_reports[i].event_name_nb * sizeof (uint32_t *));
	 if (strcmp(mmt_conf->security_reports[i].event_name[0],"null") != 0){
	 if (mmt_conf->security_reports[i].event_name_nb > 0){
	 for (l = 0; l < mmt_conf->security_reports[i].event_name_nb; l++){
	 mmt_conf->security_reports[i].event_id[l] = get_protocol_id_by_name (mmt_conf->security_reports[i].event_name[l]);
	 if (mmt_conf->security_reports[i].event_id[l] == 0){
	 printf ("Error security report event name \n");
	 exit (1);
	 }
	 }
	 }
	 }else{
	 mmt_conf->security_reports[i].event_id[0] = 0;//when the event_name is NULL;
	 }
	 }
	 }*/

#ifdef PCAP
	if (pcap_capture(&mmt_probe) == EXIT_FAILURE) return EXIT_FAILURE;
#endif

#ifdef DPDK
	start_timer( mmt_probe.mmt_conf->sampled_report_period, flush_messages_to_file_thread, (void *) &mmt_probe);
	dpdk_capture(argc, argv, &mmt_probe );
#endif
	printf("Process Terminated successfully\n");

	terminate_probe_processing(1);

	printf("Process Terminated successfully\n");
	return EXIT_SUCCESS;
}

