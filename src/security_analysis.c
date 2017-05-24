#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "processing.h"

//Begin for MMT_Security
#define OPTION_SATISFIED     1 //if = 1 then yes, output when rule satisfied
#define OPTION_NOT_SATISFIED 0 //if = 1 then yes, output when rule not satisfied

static FILE * OutputFile = NULL; //XML results output file
typedef void (*result_callback) (int prop_id, char *verdict, char *type, char *cause, char *history,struct timeval packet_timestamp,void * user_args);


//MMT_SecurityLib function to initalise the MMT_SecurityLib library
result_callback db_todo_at_start = NULL;
result_callback db_todo_when_property_is_satisfied_or_not = NULL;

extern void init_sec_lib (mmt_handler_t *mmt, char * property_file, short option_statisfied, short option_not_satisfied,
        result_callback todo_when_property_is_satisfied_or_not, result_callback db_todo_at_start,
        result_callback db_todo_when_property_is_satisfied_or_not, void * user_args);

//Next three functions can be changed to do any necessary treatment of results.
void todo_at_start(char *file_path){
    if( file_path == NULL )
        return;

    char file_name[256];
    //XML file that will contain the results (see bellow for more details)
    sprintf(file_name,"%s/results.json", file_path);
    OutputFile = fopen ( file_name, "w" );
    if( OutputFile == NULL ) {
        perror( file_name );
        exit( EXIT_FAILURE );
    }
    fprintf(OutputFile, "{\n");
}

void todo_when_property_is_satisfied_or_not (int prop_id, char *verdict, char *type, char *cause, char *history,struct timeval packet_timestamp,void * user_args){

    security_event( prop_id, verdict, type, cause, history,packet_timestamp, user_args );


    if( OutputFile != NULL ){
        struct timeval ts;
        gettimeofday( &ts, NULL );

        fprintf( OutputFile, "{\"timestamp\":%lu.%06lu,\"pid\":%d,\"verdict\":\"%s\",\"type\":\"%s\",\"cause\":\"%s\",\"history\":%s},\n",
                ts.tv_sec, ts.tv_usec,
                prop_id, verdict, type, cause, history);
    }

};

void todo_at_end(){
    if( OutputFile != NULL ){
        fprintf(OutputFile, "}");
        fclose(OutputFile);
    }
}


void init_mmt_security(mmt_handler_t *mmt_handler, char * property_file, void *args){
    //return;
	struct smp_thread *th = (struct smp_thread *) args;
    init_sec_lib( mmt_handler, property_file,
            OPTION_SATISFIED, OPTION_NOT_SATISFIED,
            todo_when_property_is_satisfied_or_not,
            db_todo_at_start,
            db_todo_when_property_is_satisfied_or_not, (void *) args);
}


//End for MMT_Security
void security_event( int prop_id, char *verdict, char *type, char *cause, char *history,struct timeval packet_timestamp, void * user_args) {
	//FILE * out_file = (probe_context.data_out_file != NULL) ? probe_context.data_out_file : stdout;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_args;
	char message[MAX_MESS + 1];
    message[0] = '\0';
    char *x = " ";
    char * xverdict = verdict; char* xtype = type; char *xcause = cause; char *xhistory = history;
    if(xverdict == NULL) xverdict = x;
    if(xtype == NULL) xtype = x;
    if(xcause == NULL) xcause = x;
    if(xhistory == NULL) xhistory = x;

	snprintf( message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%06lu,%d,\"%s\",\"%s\",\"%s\",%s",
			MMT_SECURITY_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source,
			packet_timestamp.tv_sec, packet_timestamp.tv_usec,
			prop_id, xverdict, xtype, xcause, xhistory);


	message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
	//printf("%s\n",message);
	if (th == NULL) printf("Thread structure does not exists\n");
	if (probe_context->output_to_file_enable && probe_context->security1_output_channel[0]) send_message_to_file_thread (message, th);
	if (probe_context->redis_enable && probe_context->security1_output_channel[1]) send_message_to_redis ("security.report", message);
	if (probe_context->kafka_enable && probe_context->security1_output_channel[2])send_msg_to_kafka(probe_context->topic_object->rkt_security, message);
}
//END HN
