#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <errno.h>
#include "processing.h"
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <sysrepo.h>
static void mmt_cleanup(sr_conn_ctx_t *connection, sr_session_ctx_t *session, sr_subscription_ctx_t *subscription)
{
	sr_unsubscribe(session, subscription);
	sr_session_stop(session);
	sr_disconnect(connection);
}

static void mmt_init(sr_conn_ctx_t **connection, sr_session_ctx_t **session)
{
	mmt_probe_context_t * probe_context = get_probe_context_config();
	int rc = SR_ERR_OK;
	rc = sr_connect("probe", SR_CONN_DEFAULT, connection);
	if (SR_ERR_OK != rc) {
		fprintf(stderr, "Error: %s\n", sr_strerror(rc));
		return;
	}

	/* normally bind to the STARTUP datastore, but in case that --load-running option was provided bind to RUNNING */
	rc = sr_session_start(*connection, (probe_context->probe_load_running ? SR_DS_RUNNING : SR_DS_STARTUP), SR_SESS_DEFAULT, session);
	if (SR_ERR_OK != rc) {
		sr_disconnect(*connection);
		fprintf(stderr, "Error: %s\n", sr_strerror(rc));
		return;
	}
}
void config_output_to_file (sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	int rc = SR_ERR_OK;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/enable", &value);
	if (SR_ERR_OK == rc) {
		probe_context->output_to_file_enable = value->data.uint32_val;
		sr_free_val(value);
		printf ("output_to_file_enable = %u\n", probe_context->output_to_file_enable);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/filename", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->data_out,value->data.string_val);
		sr_free_val(value);
		printf ("file_name = %s\n", probe_context->data_out);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/location", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->output_location,value->data.string_val);
		sr_free_val(value);
		printf ("file output location = %s\n", probe_context->output_location);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/retain_files", &value);
	if (SR_ERR_OK == rc) {
		probe_context->retain_files = value->data.uint32_val;
		sr_free_val(value);
		printf ("reatin_files_nb = %u\n", probe_context->retain_files);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/sampled_report", &value);
	if (SR_ERR_OK == rc) {
		probe_context->sampled_report = value->data.uint32_val;
		sr_free_val(value);
		printf ("sampled_report = %u\n", probe_context->sampled_report);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:file-output/file_output_period", &value);
	if (SR_ERR_OK == rc) {
		probe_context->sampled_report_period = value->data.uint32_val;
		sr_free_val(value);
		printf ("sampled_report_period = %u\n", probe_context->sampled_report_period);
	}

	if (probe_context->sampled_report > 1){
		printf("Error: Sample_report inside the output section in the configuration file has a value either 1 or 0, 1 for sampled output and 0 for single output\n");
		exit(0);
	}

	if (probe_context->output_to_file_enable == 1){
		if (probe_context->retain_files < (probe_context->thread_nb + 1) && probe_context->retain_files != 0 && probe_context->sampled_report == 1){
			printf("Error: Number of retain files inside the output section in the configuration file, should be always greater than (thread_nb + 1) \n");
			exit (0);
		}
	}
}
/***********************event based report********************/
void config_event_report (sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	mmt_probe_context_t * probe_context = get_probe_context_config();
	int rc = SR_ERR_OK;
	size_t values_cnt = 0;
	char condition[20];
	char message[1024];
	int m = 0;
	rc = sr_get_item(session, "/dynamic-mmt-probe:event/number-of-events", &value);
	if (SR_ERR_OK == rc) {
		probe_context->event_reports_nb = value->data.uint32_val;
		sr_free_val(value);
		printf ("event_report_nb = %u\n", probe_context->event_reports_nb);
	}

	//////////////////config_updated/////////////////
	if (probe_context->event_reports_nb == 0) return;
	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].event_report_flag, 1);
		}
	}
	/////////////////////////
	int j=0, k=0, i= 0;
	int len = 0;
	mmt_event_report_t * current = probe_context->event_reports;
	while ((current = probe_context->event_reports) != NULL){
		probe_context->event_reports = probe_context->event_reports->next;
		free (current);
		current  = NULL;
	}
	if (probe_context->event_reports_nb > 0) {
		for(j = 0; j < probe_context->event_reports_nb; j++) {

			mmt_event_report_t * event_reports = (mmt_event_report_t *) malloc ( sizeof(mmt_event_report_t));

			if (event_reports == NULL){
				printf("Error Memory allocation: event_reporting");
				return;
			}

			k = j + 1;
			len =snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/enable",k);
			message[len]='\0';
			rc = sr_get_item(session, message, &value);
			if (SR_ERR_OK == rc) {
				event_reports->enable = value->data.uint32_val;
				sr_free_val(value);
				printf ("enable = %u\n", event_reports->enable);
			}
			len=0;
			len= snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/condition",k);
			message[len]='\0';
			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				strcpy(condition,value->data.string_val);
				sr_free_val(value);
				printf ("condition = %s\n", condition);
			}

			if (parse_dot_proto_attribute(condition, &event_reports->event)) {
				fprintf(stderr, "Error: invalid event_report event value '%s'\n", condition);
				exit(0);
			}
			event_reports->id = k;
			printf ("event_id = %u\n", event_reports->id);
			probe_context->event_based_reporting_enable = 1;

			len =0;
			len = snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/output_to_file",k);
			message[len]= '\0';

			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				event_reports->event_output_channel[0] = value->data.uint32_val;
				sr_free_val(value);
			}
			printf ("event_output_file = %u\n", event_reports->event_output_channel[0]);
			len =0;
			len = snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/output_to_redis",k);
			message[len]= '\0';

			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				event_reports->event_output_channel[1] = value->data.uint32_val;
				sr_free_val(value);
			}
			printf ("event_output_redis = %u\n", event_reports->event_output_channel[1]);
			len =0;
			len = snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/output_to_kafka",k);
			message[len]= '\0';
			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				event_reports->event_output_channel[2] = value->data.uint32_val;
				sr_free_val(value);
			}
			printf ("event_output_kafka = %u\n", event_reports->event_output_channel[2]);
			if ((event_reports->event_output_channel[0] || event_reports->event_output_channel[1] || event_reports->event_output_channel[2]) == 0) {
				event_reports->event_output_channel[0] = 1;//default
				printf("By default event_reports output to file enabled\n");
			}

			len = 0;
			len =snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/attributes",k);
			message[len]='\0';
			rc = sr_get_items(session, message, &value, &values_cnt);
			if (SR_ERR_OK == rc) {
				event_reports->attributes_nb = values_cnt;
				sr_free_val(value);
				printf ("attributes_nb = %u\n", event_reports->attributes_nb);

			}


			if(event_reports->attributes_nb > 0) {
				event_reports->attributes = calloc(sizeof(mmt_event_attribute_t), event_reports->attributes_nb);

				for(i = 0; i < event_reports->attributes_nb; i++) {
					len = 0;
					int l = 0;
					l= i + 1;
					len = snprintf(message,256,"/dynamic-mmt-probe:event/event-based-reporting[event_id='%u']/attributes[attr_id='%u']/attr",k,l);
					message[len]= '\0';
					rc = sr_get_item(session,message, &value);
					if (SR_ERR_OK == rc) {
						strcpy(condition,value->data.string_val);
						sr_free_val(value);
					}

					if (parse_dot_proto_attribute(condition, &event_reports->attributes[i])) {
						fprintf(stderr, "Error: invalid event_report attribute  '%s'\n", condition);
						exit(0);
					}
				}
			}

			event_reports->next = probe_context->event_reports;
			probe_context->event_reports = event_reports;
		}
	}
}
/**************************************event based report****************************************/


/******************************app based report **************************************/
void config_condition_report (sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	mmt_probe_context_t * probe_context = get_probe_context_config();
	int rc = SR_ERR_OK;
	char condition[20];
	char message[1024];
	size_t values_cnt = 0;
	int m = 0;
	rc = sr_get_item(session, "/dynamic-mmt-probe:session-app-report/number-of-app", &value);
	if (SR_ERR_OK == rc) {
		probe_context->condition_reports_nb = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("condition_report_nb = %u\n", probe_context->condition_reports_nb);

	//////////////////config_updated/////////////////
	if (probe_context->condition_reports_nb == 0) return;

	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].condition_report_flag, 1);
		}
	}

	/////////////////////////
	int j=0, k=0, i= 0;
	int len = 0;
	mmt_condition_report_t * current = probe_context->condition_reports;
	while ((current = probe_context->condition_reports) != NULL){
		probe_context->condition_reports = probe_context->condition_reports->next;
		free (current);
		current  = NULL;
	}
	if (probe_context->condition_reports_nb > 0) {
		for(j = 0; j < probe_context->condition_reports_nb; j++) {

			mmt_condition_report_t * condition_reports = (mmt_condition_report_t *) malloc ( sizeof(mmt_condition_report_t));

			if (condition_reports == NULL){
				printf("Error Memory allocation: condition_reporting");
				return;
			}

			k = j + 1;
			len =snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/enable",k);
			message[len]='\0';
			rc = sr_get_item(session,message,&value);
			if (SR_ERR_OK == rc) {
				condition_reports->enable = value->data.uint32_val;
				sr_free_val(value);
				printf ("app_enable = %u\n", condition_reports->enable);
			}
			len=0;
			len= snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/condition",k);
			message[len]='\0';
			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				strcpy(condition,value->data.string_val);
				sr_free_val(value);
				printf ("condition = %s\n", condition);
			}

			if (parse_condition_attribute(condition, &condition_reports->condition)) {
				fprintf(stderr, "Error: invalid condition_report condition value '%s'\n", condition);
				exit(0);
			}
			condition_reports->id = k;
			printf ("condition_id = %u\n", condition_reports->id);
			probe_context->condition_based_reporting_enable = 1;

			len=0;
			len= snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/location",k);
			message[len]='\0';
			rc = sr_get_item(session,message, &value);
			if (SR_ERR_OK == rc) {
				strcpy(condition_reports->condition.location,value->data.string_val);
				sr_free_val(value);
				printf ("location = %s\n",condition_reports->condition.location );
			}

			if(strcmp(condition_reports->condition.condition, "FTP") == 0){
				if (condition_reports->enable == 1) probe_context->ftp_enable = 1;
				if (condition_reports->enable == 0) probe_context->ftp_enable = 0;
			}
			if(strcmp(condition_reports->condition.condition, "WEB") == 0){
				if (condition_reports->enable == 1) probe_context->web_enable = 1;
				if (condition_reports->enable == 0) probe_context->web_enable = 0;
			}
			if(strcmp(condition_reports->condition.condition, "RTP") == 0){
				if (condition_reports->enable == 1) probe_context->rtp_enable = 1;
				if (condition_reports->enable == 0) probe_context->rtp_enable = 0;
			}
			if(strcmp(condition_reports->condition.condition, "SSL") == 0){
				if (condition_reports->enable == 1) probe_context->ssl_enable = 1;
				if (condition_reports->enable == 0) probe_context->ssl_enable = 0;
			}
			if(strcmp(condition_reports->condition.condition, "HTTP-RECONSTRUCT") == 0){
#ifdef HTTP_RECONSTRUCT_MODULE                                         
				if (condition_reports->enable == 1) {
					strncpy(mmt_conf->HTTP_RECONSTRUCT_MODULE_output_location, condition_reports->condition.location, 256);
					mmt_conf->HTTP_RECONSTRUCT_MODULE_enable = 1;
				}
				if (condition_reports->enable == 0) mmt_conf->HTTP_RECONSTRUCT_MODULE_enable = 0;
#else
				condition_reports->enable = 0;//check with luong
#endif // End of HTTP_RECONSTRUCT_MODULE
			}

			len = 0;
			len =snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/app_attributes",k);
			message[len]='\0';
			rc = sr_get_items(session, message, &value, &values_cnt);
			if (SR_ERR_OK == rc) {
				condition_reports->attributes_nb = values_cnt;
				sr_free_val(value);
				printf ("attributes_nb = %u\n", condition_reports->attributes_nb);

			}

			if(condition_reports->attributes_nb > 0) {
				condition_reports->attributes = calloc(sizeof(mmt_condition_attribute_t), condition_reports->attributes_nb);
				condition_reports->handlers = calloc(sizeof(mmt_condition_attribute_t), condition_reports->attributes_nb);
				for(i = 0; i < condition_reports->attributes_nb; i++) {
					len = 0;
					int l = 0;
					l= i + 1;
					len = snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/app_attributes[app_attr_id='%u']/app_attr",k,l);
					message[len]= '\0';
					rc = sr_get_item(session,message, &value);
					if (SR_ERR_OK == rc) {
						strcpy(condition,value->data.string_val);
						sr_free_val(value);
					}

					if (condition_parse_dot_proto_attribute(condition, &condition_reports->attributes[i])) {
						fprintf(stderr, "Error: invalid condition_report attribute  '%s'\n", condition);
						exit(0);
					}
					len = 0;
					len = snprintf(message,256,"/dynamic-mmt-probe:session-app-report/app-based-reporting[app_id='%u']/app_attributes[app_attr_id='%u']/app_attr_handler",k,l);
					message[len]= '\0';
					rc = sr_get_item(session,message, &value);
					if (SR_ERR_OK == rc) {
						strcpy(condition,value->data.string_val);
						sr_free_val(value);
					}
					printf("here\n");
					if (parse_handlers_attribute(condition, &condition_reports->handlers[i])) {
						fprintf(stderr, "Error: invalid condition_report attribute handler  '%s'\n", condition);
						exit(0);
					}

				}
			}

			condition_reports->next = probe_context->condition_reports;
			probe_context->condition_reports = condition_reports;
		}
	}

}
/******************** app based report*******************/                                                                                                                                                               /*************** redis  ********************/

void config_output_to_redis(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK;
	char hostname[256 + 1];
	int port = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:redis-output/enable", &value);
	if (SR_ERR_OK == rc) {
		probe_context->redis_enable = value->data.uint32_val;
		sr_free_val(value);
		printf ("redis-enable = %u\n", probe_context->redis_enable);

	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:redis-output/hostname", &value);
	if (SR_ERR_OK == rc) {
		strcpy(hostname, value->data.string_val);
		sr_free_val(value);
		printf ("hostname = %s\n", hostname);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:redis-output/port", &value);
	if (SR_ERR_OK == rc) {
		port = value->data.uint32_val;
		sr_free_val(value);
		printf ("port = %u\n", port);
	}

	if (probe_context->redis_enable) {
		init_redis(hostname, port);
	}

}
/*************** redis  ********************/

/*************** kafka  ********************/

void config_output_to_kafka(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK;
	char hostname[256 + 1];
	int port = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:kafka-output/enable", &value);
	if (SR_ERR_OK == rc) {
		probe_context->kafka_enable = value->data.uint32_val;
		sr_free_val(value);
		printf ("kafka-enable = %u\n", probe_context->kafka_enable);

	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:kafka-output/hostname", &value);
	if (SR_ERR_OK == rc) {
		strcpy(hostname, value->data.string_val);
		sr_free_val(value);
		printf ("hostname = %s\n", hostname);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:kafka-output/port", &value);
	if (SR_ERR_OK == rc) {
		port = value->data.uint32_val;
		sr_free_val(value);
		printf ("port = %u\n", port);
	}

	if (probe_context->kafka_enable) {
		init_kafka(hostname, port);
	}

}
/*************** kafka  ********************/
/*************** session-report  ********************/

void config_session_report(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK, len = 0, m = 0,enable_session_report = 0;
	char message[256 + 1];

	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:session-report/enable", &value);
	if (SR_ERR_OK == rc) {
		enable_session_report = value->data.uint32_val;
		probe_context->enable_session_report = enable_session_report;//make this variable atomic
		sr_free_val(value);
	}

	printf ("\n session-report-enable = %u\n", enable_session_report);


	//////////////////config_updated/////////////////
	if (enable_session_report == 0) return;

	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].session_report_flag, 1);
		}
	}

	/////////////////////////

	len = snprintf(message,256,"/dynamic-mmt-probe:session-report/output_to_file");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->session_output_channel[0] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("session_output_file = %u\n", probe_context->session_output_channel[0]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:session-report/output_to_redis");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->session_output_channel[1] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("session_output_redis = %u\n", probe_context->session_output_channel[1]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:session-report/output_to_kafka");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->session_output_channel[2] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("session_output_kafka = %u\n", probe_context->session_output_channel[2]);

}

/*************** session-report  ********************/
/*************** security-report  ********************/

void config_security2_report(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK, len = 0, m = 0,enable_security2_report = 0;
	char message[256 + 1];
	const char s[2]= ",";
	char * token;
	int i = 0;

	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/enable", &value);
	if (SR_ERR_OK == rc) {
		enable_security2_report = value->data.uint32_val;
		sr_free_val(value);
	}

	printf ("\n security2-report-enable = %u\n", enable_security2_report);


	//////////////////config_updated/////////////////
	if (enable_security2_report == 0) return;

	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].security2_report_flag, 1);
		}
	}

	///////////
	probe_context->security2_enable = enable_security2_report;
	rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/thread_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->security2_threads_count = value->data.uint32_val;
		sr_free_val(value);
		printf ("thread_count = %u\n", probe_context->security2_threads_count);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/rule_mask", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->security2_rules_mask, value->data.string_val);
		sr_free_val(value);
		printf ("rule-mask = %s\n", probe_context->security2_rules_mask);
	}
	
        /*rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/excluded_rules", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->security2_excluded_rules, value->data.string_val);
		sr_free_val(value);
		printf ("exclude-rules = %s\n", probe_context->security2_excluded_rules);
	}*/

	probe_context->security2_add_rules_enable = 0;

	rc= sr_get_item(session, "/dynamic-mmt-probe:security2-report/add_rules", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->security2_add_rules, value->data.string_val);
		sr_free_val(value);
		printf ("add-rules = %s\n", probe_context->security2_add_rules);
		probe_context->security2_add_rules_enable = 1;
	}

        probe_context->security2_remove_rules_enable = 0;
	rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/count_removed_rules", &value);
	if (SR_ERR_OK == rc) {
		probe_context->security2_count_rule_remove = value->data.uint32_val;
		sr_free_val(value);
		printf ("count remove rules = %u\n", probe_context->security2_count_rule_remove);
	}

	if (probe_context->security2_count_rule_remove != 0){
		rc = sr_get_item(session, "/dynamic-mmt-probe:security2-report/remove_rules", &value);
		if (SR_ERR_OK == rc) {
			strcpy(probe_context->security2_remove_rules, value->data.string_val);
			sr_free_val(value);
			printf ("remove-rules = %s\n", probe_context->security2_remove_rules);
		}

		token = strtok(probe_context->security2_remove_rules, s);
		while (token != NULL){
			probe_context->remove_rules_array[i] = atoi(token);
			printf ("%d\n", probe_context->remove_rules_array[i]);
			token = strtok(NULL,s);
			i++;
		}
                probe_context->security2_remove_rules_enable = 1;
	}

	len = snprintf(message,256,"/dynamic-mmt-probe:security2-report/output_to_file");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->security2_output_channel[0] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("security_output_file = %u\n", probe_context->security2_output_channel[0]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:security2-report/output_to_redis");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->security2_output_channel[1] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("security2_output_redis = %u\n", probe_context->security2_output_channel[1]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:security2-report/output_to_kafka");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->security2_output_channel[2] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("security2_output_kafka = %u\n", probe_context->security2_output_channel[2]);


}
/*************** behaviour  ********************/

void config_behaviour(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK;
	char location[256 + 1];
	int behaviour_enable = 0, m = 0;

	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:behaviour/enable", &value);
	if (SR_ERR_OK == rc) {
		behaviour_enable = value->data.uint32_val;
		sr_free_val(value);
		printf ("behaviour-enable = %u\n", probe_context->behaviour_enable);

	}

	if (behaviour_enable == 0)return;
	////////////config///////////
	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].behaviour_flag, 1);
		}
	}
	//////////config////////////

	rc = sr_get_item(session, "/dynamic-mmt-probe:behaviour/location", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->behaviour_output_location, "/opt/mmt/");
		sr_free_val(value);
		printf ("behaviour_output_location = %s\n", value->data.string_val);
	}
	if(strcmp(probe_context->output_location,probe_context->behaviour_output_location)==0){
		printf("Error: The directory for the main output and the behaviour output cannot be same, please specify different directory location.\n");
		exit(0);
	}
	probe_context->behaviour_enable = behaviour_enable;

}
/*************** behaviour  ********************/

/************** ftp-recontruct  ********************/

void config_ftp_reconstruct(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK, len = 0, ftp_reconstruct = 0, m = 0;
	char location[256 + 1];
	char message[256 + 1];

	mmt_probe_context_t * probe_context = get_probe_context_config();
	printf ("inside ftp_reconstruct\n");
	rc = sr_get_item(session, "/dynamic-mmt-probe:ftp-reconstruct/enable", &value);
	if (SR_ERR_OK == rc) {
		ftp_reconstruct = value->data.uint32_val;
		sr_free_val(value);
		printf ("ftp_reconstruct_enable = %u\n", ftp_reconstruct);

	}
	if (ftp_reconstruct == 0)return;
	////////config//////
	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].ftp_reconstruct_flag, 1);
		}
	}
	////////config/////////


	rc = sr_get_item(session, "/dynamic-mmt-probe:ftp-reconstruct/location", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->ftp_reconstruct_output_location, value->data.string_val);
		sr_free_val(value);
		printf ("ftp-reconstruct_output_location = %s\n", probe_context->ftp_reconstruct_output_location);
	}

	len = snprintf(message,256,"/dynamic-mmt-probe:ftp-reconstruct/output_to_file");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->ftp_reconstruct_output_channel[0] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("ftp_reconstruct_output_file = %u\n", probe_context->ftp_reconstruct_output_channel[0]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:ftp-reconstruct/output_to_redis");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->ftp_reconstruct_output_channel[1] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("ftp_reconstruct_output_redis = %u\n", probe_context->ftp_reconstruct_output_channel[1]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:ftp-reconstruct/output_to_kafka");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->ftp_reconstruct_output_channel[2] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("ftp_reconstruct_output_kafka = %u\n", probe_context->ftp_reconstruct_output_channel[2]);


}
/*************** ftp-reconstruct  ********************/
/*************** micro-flows  ********************/

void config_micro_flows(sr_session_ctx_t * session, sr_val_t * value, struct mmt_probe_struct * mmt_probe){
	sr_val_t *values = NULL;
	int rc = SR_ERR_OK, len = 0, micro_flows = 0, m = 0;
	char message[256 + 1];

	mmt_probe_context_t * probe_context = get_probe_context_config();
	printf ("inside micro_flows\n");
	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/enable", &value);
	if (SR_ERR_OK == rc) {
		micro_flows = value->data.uint32_val;
		sr_free_val(value);
		printf ("micro_flows_enable = %u\n", micro_flows);

	}
	if (micro_flows == 0)return;
	//////config//////
	if (mmt_probe->smp_threads != NULL){
		for (m = 0; m < mmt_probe->mmt_conf->thread_nb; m++){
			atomic_store (&mmt_probe->smp_threads[m].micro_flows_flag, 1);
		}
	}
	/////config/////

	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/include_packet_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_pthreshold = value->data.uint32_val;
		sr_free_val(value);
		printf ("microflow include packet count = %u\n", probe_context->microf_pthreshold);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/include_byte_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_bthreshold = value->data.uint32_val;
		sr_free_val(value);
		printf ("microflow include byte count = %u\n", probe_context->microf_bthreshold);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/report_packet_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_report_pthreshold = value->data.uint32_val;
		sr_free_val(value);
		printf ("microflow report packet count = %u\n", probe_context->microf_report_pthreshold);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/report_byte_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_report_bthreshold = value->data.uint32_val;
		sr_free_val(value);
		printf ("microflow report byte count = %u\n", probe_context->microf_report_bthreshold);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:micro-flows/report_flow_count", &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_report_fthreshold = value->data.uint32_val;
		sr_free_val(value);
		printf ("microflow report flow count = %u\n", probe_context->microf_report_fthreshold);
	}


	len = snprintf(message,256,"/dynamic-mmt-probe:micro-flows/output_to_file");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_output_channel[0] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("microf_output_file = %u\n", probe_context->microf_output_channel[0]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:micro-flows/output_to_redis");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_output_channel[1] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("microf_output_redis = %u\n", probe_context->microf_output_channel[1]);

	len =0;
	len = snprintf(message,256,"/dynamic-mmt-probe:micro-flows/output_to_kafka");
	message[len]= '\0';

	rc = sr_get_item(session,message, &value);
	if (SR_ERR_OK == rc) {
		probe_context->microf_output_channel[2] = value->data.uint32_val;
		sr_free_val(value);
	}
	printf ("microf_output_kafka = %u\n", probe_context->microf_output_channel[2]);


}

/*************** micro-flows  ********************/

/****************************security-report**********************************/

void read_mmt_config(sr_session_ctx_t *session, struct mmt_probe_struct * mmt_probe)
{
	sr_val_t *value = NULL, *values = NULL;
	size_t values_cnt = 0, i = 0;
	int rc = SR_ERR_OK;
	//char * conf = malloc (sizeof(char)*50);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/input-source", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->input_source,value->data.string_val);
		sr_free_val(value);
		printf ("input-source = %s\n", probe_context->input_source);

	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/input-mode", &value);
	if (SR_ERR_OK == rc) {
		if (strcmp(value->data.string_val,"offline") == 0)
			probe_context->input_mode = OFFLINE_ANALYSIS;
		if (strcmp(value->data.string_val,"online") == 0)
			probe_context->input_mode = ONLINE_ANALYSIS;
		sr_free_val(value);
		printf ("input-mode = %u\n", probe_context->input_mode);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/threads", &value);
	printf ("thread_nb = %u\n", value->data.uint32_val);

	if (SR_ERR_OK == rc && probe_context->thread_nb == 0) {
		probe_context->thread_nb =value->data.uint32_val;
		sr_free_val(value);
		printf ("thread_nb = %u\n", probe_context->thread_nb);
	}


	if(value != NULL) sr_free_val(value);

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/thread-queue", &value);
	if (SR_ERR_OK == rc) {
		probe_context->thread_queue_plen =value->data.uint32_val;
		sr_free_val(value);
		printf ("thread_queue_len = %u\n", probe_context->thread_queue_plen);
		if (probe_context->thread_queue_plen == 0) probe_context->thread_queue_plen = 1000;

	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/thread-data", &value);
	if (SR_ERR_OK == rc) {
		probe_context->thread_queue_blen =value->data.uint32_val;
		sr_free_val(value);
		printf ("thread_queue_blen = %u\n", probe_context->thread_queue_blen);
		if (probe_context->thread_queue_blen == 0) probe_context->thread_queue_blen = 0xFFFFFFFF;
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/probe-identifier", &value);
	if (SR_ERR_OK == rc) {
		probe_context->probe_id_number =value->data.uint32_val;
		sr_free_val(value);
		printf ("probe_id = %u\n", probe_context->probe_id_number);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/license-path", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->license_location, value->data.string_val);
		sr_free_val(value);
		printf ("license_file = %s\n", probe_context->license_location);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/log-path", &value);
	if (SR_ERR_OK == rc) {
		strcpy(probe_context->log_file, value->data.string_val);
		sr_free_val(value);
		printf ("log_file = %s\n", probe_context->log_file);

	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/stat-report-period", &value);
	if (SR_ERR_OK == rc) {
		probe_context->stats_reporting_period = value->data.uint32_val;
		sr_free_val(value);
		printf ("stats_reporting_period = %u\n", probe_context->stats_reporting_period);
	}

	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/snap-len", &value);
	if (SR_ERR_OK == rc) {
		probe_context->requested_snap_len = value->data.uint32_val;
		sr_free_val(value);
		printf ("snap_len = %u\n", probe_context->requested_snap_len);
	}
	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/report-cache-size", &value);
	if (SR_ERR_OK == rc) {
		probe_context->report_cache_size_before_flushing = value->data.uint32_val;
		sr_free_val(value);
		printf ("cache_size = %lu\n", probe_context->report_cache_size_before_flushing);
	}
	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/enable-proto-without-session-stat", &value);
	if (SR_ERR_OK == rc) {
		probe_context->enable_proto_without_session_stats = value->data.uint32_val;
		sr_free_val(value);
		printf ("enable_proto_without_session_stat = %u\n", probe_context->enable_proto_without_session_stats);
	}
/*	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/enable-IP-fragmentation_report", &value);
	if (SR_ERR_OK == rc) {
		probe_context->enable_IP_fragmentation_report = value->data.uint32_val;
		sr_free_val(value);
		printf ("enable-IP-fragmentation_report = %u\n", probe_context->enable_IP_fragmentation_report);
	}*/
	/*        rc = sr_get_item(session, "/dynamic-mmt-probe:operation/restart", &value);
        if (SR_ERR_OK == rc) {
                if (value->data.uint32_val == 1) kill (probe_context->pid, SIGINT);
                sr_free_val(value);
        }
        rc = sr_get_item(session, "/dynamic-mmt-probe:operation/stop", &value);
        if (SR_ERR_OK == rc) {
                if (value->data.uint32_val == 1) kill (probe_context->pid, SIGKILL);
                sr_free_val(value);
        }
	 */
	config_event_report (session, value, mmt_probe);
	config_session_report (session, value,mmt_probe);
	config_security2_report (session, value,mmt_probe);
	config_behaviour (session, value,mmt_probe);
	config_ftp_reconstruct (session, value,mmt_probe);
	config_micro_flows (session, value,mmt_probe);


	config_output_to_file (session, value, mmt_probe);

	config_output_to_redis (session, value, mmt_probe);
	config_output_to_kafka (session, value, mmt_probe);
	config_condition_report (session, value, mmt_probe);

	///////////config_updated///////////////////
	

	if (mmt_probe->smp_threads != NULL){
		for (i = 0; i< mmt_probe->mmt_conf->thread_nb; i++){
			atomic_store (&mmt_probe->smp_threads[i].config_updated, 1);
			printf ("here_config....\n");
		}
	}


	/////////////////////////
	rc = sr_get_item(session, "/dynamic-mmt-probe:probe-operation/operation", &value);
	if (SR_ERR_OK == rc) {
		if (strcmp(value->data.string_val,"restart") == 0){
			/*  printf("operation = %s\n",value->data.string_val);
                  probe_context->load_enable =1;
                  kill (probe_context->pid, SIGINT);*/
		}
		else if (strcmp(value->data.string_val,"stop") == 0) kill (probe_context->pid, SIGTERM);
		sr_free_val(value);
	}
}

int mmt_config_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
	(void)session;
	(void)event;
	(void)module_name;
	(void)private_ctx;
	char exe[1024] = { 0, };
	int ret = 0, i = 0;

	struct mmt_probe_struct * mmt_probe = (struct mmt_probe_struct *) private_ctx;

        if (mmt_probe->smp_threads != NULL){
            for (i = 0; i< mmt_probe->mmt_conf->thread_nb; i++){
                if (atomic_load (&mmt_probe->smp_threads[i].config_updated) == 1) return SR_ERR_OK;
                printf ("here_config....\n");
            }
        }


	printf("\n\n========== MMT-probe CONFIG HAS CHANGED_START ==========\n\n");
	read_mmt_config(session, mmt_probe);

	printf("\n\n========== MMT-probe CONFIG HAS CHANGED_END ==========\n\n");
	return SR_ERR_OK;
}

static void mmt_change_subscribe(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription, struct mmt_probe_struct * mmt_probe)
{
	mmt_probe_context_t * probe_context = get_probe_context_config();
	int rc = SR_ERR_OK, i = 0;
	rc = sr_module_change_subscribe(session, "dynamic-mmt-probe", mmt_config_change_cb, mmt_probe, 0, SR_SUBSCR_DEFAULT, subscription);

	if (SR_ERR_OK != rc) {
		fprintf(stderr, "Error: %s\n", sr_strerror(rc));
	}
}

void dynamic_conf (struct mmt_probe_struct * mmt_probe){
	mmt_probe_context_t * probe_context = get_probe_context_config();
	long i, max_fd = sysconf(_SC_OPEN_MAX);
	int rc = SR_ERR_OK;
	probe_context->probe_load_running = 0;

	mmt_init(&probe_context->connection, &probe_context->session);

	rc = sr_set_item_str(probe_context->session, "/dynamic-mmt-probe:probe-operation/operation", "Nobody",0);
	if (SR_ERR_OK != rc) {
		fprintf(stderr, "Error: %s\n", sr_strerror(rc));
	}

	read_mmt_config(probe_context->session,mmt_probe);
	mmt_cleanup(probe_context->connection, probe_context->session, probe_context->subscription);

	probe_context->probe_load_running = 1;
	mmt_init(&probe_context->connection, &probe_context->session);
	mmt_change_subscribe(probe_context->session, &probe_context->subscription, mmt_probe);

}

