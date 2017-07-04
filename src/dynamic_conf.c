#include <stdio.h>
#include<stdlib.h>
#include <unistd.h>
//#include <mmt.h>
#include<string.h>
#include <sysrepo.h>
#include<errno.h>
#include "processing.h"

static void mmt_cleanup(sr_conn_ctx_t *connection, sr_session_ctx_t *session, sr_subscription_ctx_t *subscription)
{
        sr_unsubscribe(session, subscription);
        sr_session_stop(session);
        sr_disconnect(connection);
}

static void mmt_init(sr_conn_ctx_t **connection, sr_session_ctx_t **session)
{
        int rc = SR_ERR_OK;
        int probe_load_running = 0;
        rc = sr_connect("probe", SR_CONN_DEFAULT, connection);
        if (SR_ERR_OK != rc) {
                fprintf(stderr, "Error: %s\n", sr_strerror(rc));
                return;
        }

        /* normally bind to the STARTUP datastore, but in case that --load-running option was provided bind to RUNNING */
        rc = sr_session_start(*connection, (probe_load_running ? SR_DS_RUNNING : SR_DS_STARTUP), SR_SESS_DEFAULT, session);
        if (SR_ERR_OK != rc) {
                sr_disconnect(*connection);
                fprintf(stderr, "Error: %s\n", sr_strerror(rc));
                return;
        }
       printf("init\n");
}

void read_mmt_config(sr_session_ctx_t *session)
{
        sr_val_t *value = NULL, *values = NULL;
        size_t values_cnt = 0, i = 0;
        int rc = SR_ERR_OK;
        char * conf = malloc (sizeof(char)*50);
        mmt_probe_context_t * probe_context = get_probe_context_config();
        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/input-source", &value);
        if (SR_ERR_OK == rc) {
               strcpy(probe_context->input_source,value->data.string_val);
                sr_free_val(value);
        }
       printf ("input-source = %s\n", probe_context->input_source);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/input-mode", &value);
        if (SR_ERR_OK == rc) {
                if (strcmp(value->data.string_val,"offline") == 0)
                probe_context->input_mode = OFFLINE_ANALYSIS;
                if (strcmp(value->data.string_val,"online") == 0)
                probe_context->input_mode = ONLINE_ANALYSIS;
                sr_free_val(value);
        }
       printf ("input-mode = %u\n", probe_context->input_mode);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/threads", &value);
        if (SR_ERR_OK == rc) {
                probe_context->thread_nb =value->data.uint32_val;
                sr_free_val(value);
        }
       printf ("thread_nd = %u\n", probe_context->thread_nb);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/probe-identifier", &value);
        if (SR_ERR_OK == rc) {
                probe_context->probe_id_number =value->data.uint32_val;
                sr_free_val(value);
        }
       printf ("probe_id = %u\n", probe_context->probe_id_number);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/license-path", &value);
        if (SR_ERR_OK == rc) {
                strcpy(probe_context->license_location, value->data.string_val);
                sr_free_val(value);
        }
       printf ("license_file = %s\n", probe_context->license_location);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/log-path", &value);
        if (SR_ERR_OK == rc) {
                strcpy(probe_context->log_file, value->data.string_val);
                sr_free_val(value);
        }
       printf ("log_file = %s\n", probe_context->log_file);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/stat-report-period", &value);
        if (SR_ERR_OK == rc) {
                probe_context->stats_reporting_period = value->data.uint32_val;
                sr_free_val(value);
        }
       printf ("stats_reporting_period = %u\n", probe_context->stats_reporting_period);

        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/snap-len", &value);
        if (SR_ERR_OK == rc) {
                probe_context->requested_snap_len = value->data.uint32_val;
                sr_free_val(value);
        }
       printf ("snap_len = %u\n", probe_context->requested_snap_len);
        char condition[20];
        char message[1024];
/*        int attr1=1;
        int attr2=1;
        snprintf(message,256,"/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='%u']/attributes[attr_id='%u']/attr",attr1,attr2);
        rc = sr_get_item(session,message, &value);
        if (SR_ERR_OK == rc) {
                strcpy(condition,value->data.string_val);
                sr_free_val(value);
        }
       printf ("condition = %s\n", condition);
        char condition1[20];
        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='1']/attributes[attr_id='2']/attr", &value);
        if (SR_ERR_OK == rc) {
                strcpy(condition1,value->data.string_val);
                sr_free_val(value);
        }
       printf ("condition1 = %s\n", condition1);*/
////////////////////////
        rc = sr_get_item(session, "/dynamic-mmt-probe:probe-cfg/number-of-events", &value);
        if (SR_ERR_OK == rc) {
                probe_context->event_reports_nb = value->data.uint32_val;
                sr_free_val(value);
        }
       printf ("event_report_nb = %u\n", probe_context->event_reports_nb);
           int j=0, k=0;
           probe_context->event_reports = NULL;
           mmt_event_report_t * temp_er;
           int len = 0;
           if (probe_context->event_reports_nb > 0) {
               probe_context->event_reports = calloc(sizeof(mmt_event_report_t), probe_context->event_reports_nb);
               for(j = 0; j < probe_context->event_reports_nb; j++) {
                                temp_er = &probe_context->event_reports[j];                             
                                k = j + 1;
                                len =snprintf(message,256,"/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='%u']/enable",k);
                                message[len]='\0';
                                rc = sr_get_item(session, message, &value);
			        if (SR_ERR_OK == rc) {
                		    temp_er->enable = value->data.uint32_val;
                		   sr_free_val(value);
        			}
       				printf ("enable = %u\n", temp_er->enable);
                                len=0;
                                if (temp_er->enable == 1){
                                   len= snprintf(message,256,"/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='%u']/condition",k);		
                                    message[len]='\0';
                                    //printf("messgae=%s\n",message);
		          	    rc = sr_get_item(session,message, &value);
        			    if (SR_ERR_OK == rc) {
                		       strcpy(condition,value->data.string_val);
                		       sr_free_val(value);
        			    }
                                   printf ("condition = %s\n", condition);

                                    if (parse_dot_proto_attribute(condition, &temp_er->event)) {
                                        fprintf(stderr, "Error: invalid event_report event value '%s'\n", condition);
                                        exit(0);
                                    }
                                   probe_context->event_based_reporting_enable = 1;
                                   len = 0;
                                   len =snprintf(message,256,"/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='%u']/total_attr",k);
                                   message[len]='\0';
                                   rc = sr_get_item(session, message, &value);
                                   if (SR_ERR_OK == rc) {
                                       temp_er->attributes_nb = value->data.uint32_val;
                                       sr_free_val(value);
                                   }
                                   printf ("attributes_nb = %u\n", temp_er->attributes_nb);

                                   if(temp_er->attributes_nb > 0) { 
                                       temp_er->attributes = calloc(sizeof(mmt_event_attribute_t), temp_er->attributes_nb);

                                       for(i = 0; i < temp_er->attributes_nb; i++) {
                                           len = 0;
                                           int l = 0;
                                           l= i + 1;
                                           len = snprintf(message,256,"/dynamic-mmt-probe:probe-cfg/event-based-reporting[event_id='%u']/attributes[attr_id='%u']/attr",k,l);
        			           message[len]= '\0';
			                   rc = sr_get_item(session,message, &value);
                                           if (SR_ERR_OK == rc) {
                                               strcpy(condition,value->data.string_val);
                                               sr_free_val(value);
                                           }

                                           if (parse_dot_proto_attribute(condition, &temp_er->attributes[i])) {
                                               fprintf(stderr, "Error: invalid event_report attribute  '%s'\n", condition);
                                               exit(0);
                                           }
                                       }
                                  }
                             }
               }

	   }

//////////////////////////

}
int mmt_config_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
        (void)session;
        (void)event;
        (void)module_name;
        (void)private_ctx;
        char exe[1024] = { 0, };
        int ret = 0, i = 0;
        mmt_probe_context_t * probe_context = get_probe_context_config();
        printf("\n\n========== MMT-probe CONFIG HAS CHANGED_START ==========\n\n");
	read_mmt_config(session);
        /* since we don't see much into the dnsmasq implementation, we do a complete re-load of the process
         * instead of just re-initialization from the new configuration */

        /* get the path to our executable */
        ret = readlink("/proc/self/exe", exe, sizeof(exe)-1);
        if(ret == -1) {
                fprintf(stderr, "Error: %s\n", strerror(errno));
                return SR_ERR_INTERNAL;
        }
        exe[ret] = 0;
//        printf ("middle\n");
        /* close all file descriptors before exec */
/*        for (i = 0; i < sysconf(_SC_OPEN_MAX); i  ) {
                if (i != STDOUT_FILENO && i != STDERR_FILENO && i != STDIN_FILENO) {
                        close(i);
                }
        }
*/
//terminate_probe_processing(1);
//sleep(2);
        /* restart itself (note: dnsmasq must be running under root privileges, otherwise this fails) */
  //    execl(exe, "probe","/opt/dev/mmt-probe/probe","-c","/opt/dev/mmt-probe/mmt_online.conf", NULL);
   //probe_context->output_to_file_enable = 0; 
   printf("\n\n========== MMT-probe CONFIG HAS CHANGED_END ==========\n\n");
        return SR_ERR_OK;
}

static void mmt_change_subscribe(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription)
{
  int rc = SR_ERR_OK;

  rc = sr_module_change_subscribe(session, "dynamic-mmt-probe", mmt_config_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, subscription);
  if (SR_ERR_OK != rc) {
          fprintf(stderr, "Error: %s\n", sr_strerror(rc));
  }
printf("change_subscribe\n");
}

void dynamic_conf (){
        sr_conn_ctx_t *connection = NULL;
        sr_session_ctx_t *session = NULL;
        sr_subscription_ctx_t *subscription = NULL;

        mmt_init(&connection, &session);
        read_mmt_config(session); /* read supported config from mmt datastore */
        mmt_cleanup(connection, session, subscription);
        
        printf ("HERE1\n");
        mmt_init(&connection, &session);
	mmt_change_subscribe(session, &subscription);
//       sysrepo_cleanup(connection,session,subscription);
}

