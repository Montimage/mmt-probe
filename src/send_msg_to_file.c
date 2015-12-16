#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>

#include "mmt_core.h"
#include "processing.h"


FILE * sampled_file;
#define MAX_FILE_NAME 500
static time_t last_reporting_time=0;

void end_file(){
    FILE * temp_sem_file;
    FILE * temp_behaviour_sem_file;
    char sem_file_str [256+1]={0};
    int sem_valid=0;
    int i=0;
    char behaviour_command_str [500+1]={0};
    int behaviour_valid=0;
    char sem_behaviour_file_str [256+1]={0};
    int sem_behaviour_valid=0;
    int cr;
    mmt_probe_context_t * probe_context_msg = get_probe_context_config();

    if(sampled_file)i=fclose(sampled_file);

    if (i!=0){
        fprintf ( stderr , "\n1: Error %d closing of sampled_file failed: %s" , errno ,strerror( errno ) );
        exit(1);
    }
    if (probe_context_msg->behaviour_enable==1 && sampled_file!=NULL){

        cr=system(NULL);
        if (cr==0){
            fprintf(stderr,"No processor available on the system,while running system() command");
            exit(1);
        }

        behaviour_valid=snprintf(behaviour_command_str, MAX_FILE_NAME, "cp %s%lu_%s %s", probe_context_msg->output_location, last_reporting_time, probe_context_msg->data_out, probe_context_msg->behaviour_output_location);
        behaviour_command_str[behaviour_valid]='\0';
        cr=system(behaviour_command_str);
        if (cr!=0){
            fprintf(stderr,"\n5 Error code %d, while coping output file %s to %s ",cr, probe_context_msg->output_location,probe_context_msg->behaviour_output_location);
            exit(1);
        }

        sem_behaviour_valid=snprintf(sem_behaviour_file_str, MAX_FILE_NAME, "%s%lu_%s.sem", probe_context_msg->behaviour_output_location, last_reporting_time, probe_context_msg->data_out);
        sem_behaviour_file_str[sem_behaviour_valid]='\0';

        temp_behaviour_sem_file= fopen(sem_behaviour_file_str, "w");

        if (temp_behaviour_sem_file==NULL){
            fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_behaviour_file_str , strerror( errno ) );
            exit(1);
        }

        if(temp_behaviour_sem_file)i=fclose(temp_behaviour_sem_file);
        if (i!=0){
            fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s" , errno ,strerror( errno ) );
            exit(1);
        }

    }
    sem_valid=snprintf(sem_file_str, MAX_FILE_NAME, "%s%lu_%s.sem", probe_context_msg->output_location, last_reporting_time, probe_context_msg->data_out);
    sem_file_str[sem_valid]='\0';
    temp_sem_file= fopen(sem_file_str, "w");

    if (temp_sem_file==NULL){
        fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_str , strerror( errno ) );
        exit(1);
    }

    if(temp_sem_file)i=fclose(temp_sem_file);
    if (i!=0){
        fprintf ( stderr , "\n4: Error %d closing of temp_sem_file failed: %s" , errno ,strerror( errno ) );
        exit(1);
    }
}

void send_message_to_file (char * message) {

    time_t present_time;
    //static time_t last_reporting_time_single=0;
    present_time=time(0);
    int valid=0;
    static char sampled_file_str [256+1]={0};
    static char single_file [256+1]={0};
    char lg_msg[1024];

    mmt_probe_context_t * probe_context_msg = get_probe_context_config();
    if(probe_context_msg->sampled_report==1){

        if (last_reporting_time==0){

            valid=snprintf(sampled_file_str, MAX_FILE_NAME, "%s%lu_%s", probe_context_msg->output_location, present_time, probe_context_msg->data_out);
            sampled_file_str[valid] = '\0';
            last_reporting_time = present_time;
            sampled_file = fopen(sampled_file_str, "w");

            sprintf(lg_msg, "Open output results file: %s", sampled_file_str);
            mmt_log(probe_context_msg, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

            if (sampled_file==NULL){
                fprintf ( stderr , "\n Error: %d creation of \"%s\" failed: %s\n" , errno , sampled_file_str , strerror( errno ) );
                exit(1);
            }
        }

        if(present_time-last_reporting_time>=probe_context_msg->sampled_report_period){
            end_file();

            valid=snprintf(sampled_file_str, MAX_FILE_NAME,"%s%lu_%s", probe_context_msg->output_location,present_time,probe_context_msg->data_out);
            sampled_file_str[valid] = '\0';
            last_reporting_time = present_time;
            sampled_file = fopen(sampled_file_str, "w");

            sprintf(lg_msg, "Open output results file: %s", sampled_file_str);
            mmt_log(probe_context_msg, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

            if (sampled_file==NULL){
                fprintf ( stderr , "\n[e] Error: %d creation of \"%s\" failed: %s\n" , errno , sampled_file_str , strerror( errno ) );
                exit(1);
            }
        }
        fprintf (sampled_file, "%s\n", message);
    }

    if (probe_context_msg->sampled_report==0) {

        if (last_reporting_time==0){

            int len=0;
            len=snprintf(single_file,MAX_FILE_NAME,"%s%s",probe_context_msg->output_location,probe_context_msg->data_out);
            single_file[len]='\0';

            probe_context_msg->data_out_file = fopen(single_file, "w");

            if (probe_context_msg->data_out_file==NULL){
                fprintf ( stderr , "\n[e] Error: %d creation of \"%s\" failed: %s\n" , errno ,single_file, strerror( errno ) );
                exit(1);
            }

            sprintf(lg_msg, "Open output results file: %s", single_file);
            mmt_log(probe_context_msg, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

            last_reporting_time=present_time;
        }
        fprintf (probe_context_msg->data_out_file, "%s\n", message);
    }
}

