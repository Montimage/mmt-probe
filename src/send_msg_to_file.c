#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "mmt_core.h"
#include "processing.h"
#include <pthread.h>
#include <sys/timerfd.h>


static int is_stop_timer = 0;
void flush_cache_and_exit_timers(){
	is_stop_timer = 1;
	flush_messages_to_file( NULL );
}
void exit_timers(){
	is_stop_timer = 1;
}
//start timer
typedef struct pthread_user_data{
	uint32_t period;
	void     (*callback)( void * );
	void     *user_data;
}pthread_user_data_t;

static void *wait_to_do_something( void *arg ){
	int ret;
    struct itimerspec itval;
    int timer_fd  = -1;
    uint64_t expirations = 0;
    pthread_user_data_t  *p_data = arg;

    uint32_t seconds   = p_data->period;

	/*  Create the timer */
	timer_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (timer_fd == -1){
	   perror("timerfd_create:");
	   return NULL;
	}

    /*  Make the timer periodic */
   itval.it_interval.tv_sec  = seconds;
   itval.it_interval.tv_nsec = 0;
   itval.it_value.tv_sec     = seconds;
   itval.it_value.tv_nsec    = 0;

   ret = timerfd_settime (timer_fd, 0, &itval, NULL);
   if( ret != 0 ){
	   perror("timerfd_settime:");
	   return NULL;
   }

    while( !is_stop_timer ){
    	//pthread_t id = pthread_self();//jeevan delete
		//printf("wait for %d - %lu - %d\n", seconds, id, number_pthread );
		//fflush( stdout );
		/*  Wait for the next timer event. If we have missed any the
		 *         number is written to "expirations" */
		ret = read (timer_fd, &expirations, sizeof (expirations));
		if( ret == -1 ){
		   perror ("read timer");
		   return NULL;
		}
		/*  "missed" should always be >= 1, but just to be sure, check it is not 0 anyway */
        /*
		if (expirations > 1) {
			printf("missed %lu", expirations - 1);
			fflush( stdout );
		}
        */
		(* p_data->callback)( p_data->user_data );
    }
    //end the timer
    close( timer_fd );

	if( !p_data )
		free( p_data );

	return NULL;
};


int start_timer( uint32_t period, void *callback, void *user_data){
	int ret;
	pthread_user_data_t *data = malloc( sizeof( pthread_user_data_t ));
	pthread_t pthread;

	data->period   = period;
	data->callback = callback;
	data->user_data = user_data;
	ret = pthread_create(&pthread, NULL, wait_to_do_something, data);

	if( ret != 0 ){
		perror("pthread_create:");
		exit( 0 );
	}

	return ret;
}
//end of timer

//start report messages
#define MAX_FILE_NAME 500
#define MAX_CACHE_SIZE 300002
int cache_count = 0;
char *cache_message_list[ MAX_CACHE_SIZE ];

void flush_messages_to_file( void *arg){

	FILE * file;
	char file_name_str [MAX_FILE_NAME+1]={0};
	char dup_file_name_str [MAX_FILE_NAME+1]={0};
	char sem_file_name_str [MAX_FILE_NAME+5]={0};	//file_name + ".sem"
	char lg_msg[1024];
	int valid=0;
	int i=0;
	char command_str [500+1]={0};
	mmt_probe_context_t * probe_context = get_probe_context_config();
	char message[MAX_MESS + 1];
	struct timeval ts;
	//Print this report every 5 second
	gettimeofday(&ts, NULL);
	snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu",
			200, probe_context->probe_id_number,
			probe_context->input_source,ts.tv_sec, ts.tv_usec);
	message[ MAX_MESS] = '\0';

	if (probe_context->output_to_file_enable==1)send_message_to_file (message);
	if (probe_context->redis_enable==1)send_message_to_redis ("session.flow.report", message);

	if( cache_count == 0 ){
		//nothing to write
		return;
	}

	time_t present_time;
	//static time_t last_reporting_time_single=0;
	present_time = time(0);



	//open a file
	valid = snprintf(file_name_str, MAX_FILE_NAME, "%s%lu_%s", probe_context->output_location, present_time, probe_context->data_out);
	file_name_str[valid] = '\0';

	file = fopen(file_name_str, "w");

	sprintf(lg_msg, "Open output results file: %s", file_name_str );
	mmt_log(probe_context, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

	if (file==NULL){
		fprintf ( stderr , "\n Error: %d creation of \"%s\" failed: %s\n" , errno , file_name_str , strerror( errno ) );
		exit(1);
	}

	//write messages to the file
	int ret = pthread_mutex_lock( &mutex_lock  );
    if (ret == 0) {
	  for( i=0; i<cache_count; i++ ){
		if( cache_message_list[ i ] == NULL ){
			perror("this message should not be NULL");
		}else{
		    fprintf ( file, "%s\n", cache_message_list[ i ]);
		    free( cache_message_list[ i ] );
            cache_message_list[ i ] = NULL;
        }
	  }
	cache_count = 0;
    pthread_mutex_unlock(&mutex_lock);
    }
	//close the file
	i = fclose( file );

	if (i!=0){
		fprintf ( stderr , "\n1: Error %d closing of sampled_file failed: %s" , errno ,strerror( errno ) );
		exit(1);
	}

	//duplicate the file for behaviour
	if (probe_context->behaviour_enable==1){

		//check if the system command is available
		valid=system(NULL);
		if (valid==0){
			fprintf(stderr,"No processor available on the system,while running system() command");
			exit(1);
		}

		//duplicate file
		valid = snprintf( command_str, MAX_FILE_NAME, "cp %s %s", file_name_str , probe_context->behaviour_output_location);
		command_str[ valid ]='\0';
		valid = system( command_str );
		if ( valid !=0 ){
			fprintf(stderr,"\n5 Error code %d, while coping output file %s to %s ", valid, dup_file_name_str, probe_context->behaviour_output_location);
			exit(1);
		}

		//create semaphore
		valid = snprintf(sem_file_name_str, MAX_FILE_NAME, "%s%lu_%s.sem", probe_context->behaviour_output_location, present_time, probe_context->data_out);
		sem_file_name_str[ valid ]='\0';
		file= fopen(sem_file_name_str, "w");

		if ( file==NULL ){
			fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_name_str , strerror( errno ) );
			exit(1);
		}

		valid = fclose( file );
		if ( valid!=0 ){
			fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s" , errno ,strerror( errno ) );
			exit(1);
		}
	}

	//create semaphore
	valid=snprintf(sem_file_name_str, MAX_FILE_NAME, "%s.sem", file_name_str);
	sem_file_name_str[ valid ]='\0';
	file= fopen(sem_file_name_str, "w");

	if ( file==NULL ){
		fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_name_str , strerror( errno ) );
		exit(1);
	}

	valid = fclose( file );
	if ( valid!=0 ){
		fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s" , errno ,strerror( errno ) );
		exit(1);
	}
}

void send_message_to_file (char * message) {
	static time_t last_reporting_time = 0;
    time_t present_time;
    //static time_t last_reporting_time_single=0;
	present_time=time(0);
	static char single_file [256+1]={0};
	char lg_msg[1024];
	mmt_probe_context_t * probe_context = get_probe_context_config();
    //int size_m=0, ret=0;//jeevan
	int ret=0;
	if(probe_context->sampled_report==1){
		//avoid 2 threads access in the same time
		ret = pthread_mutex_lock( &mutex_lock  );
        if (ret == 0) {
			if( cache_count >= MAX_CACHE_SIZE - 1 ){
				perror("Warning: cache size is too small");
				exit( 1 );
			}

			//cache_message_list[ cache_count ] = strdup( message );
            int len = 0;
            len = strlen(message);
			//if (len > 2999 || len < 1) fprintf ( stderr ,"Warning: 201: %d, %d\n", len, (int)cache_count);
            cache_message_list[ cache_count ] = malloc(len+1);
			if( cache_message_list[ cache_count ]  == NULL ){
               //fprintf ( stderr ,"Warning: 202, %d, %d\n", len, (int)cache_count);
            }
            else {
                memcpy(cache_message_list[ cache_count ], message, len);
                cache_message_list[ cache_count ][len]='\0';
            }
            /*
            size_m = strlen(message);
            if (size_m < 1){
                cache_message_list[ cache_count ]  == NULL;
            }else if (size_m > MAX_MESS){
                cache_message_list[ cache_count ] = malloc (MAX_MESS + 1);
                strncpy(cache_message_list[ cache_count ], message, MAX_MESS);
                cache_message_list[ cache_count ][MAX_MESS]='\0';
            }else{
                cache_message_list[ cache_count ] = malloc (size_m + 1);
                strncpy(cache_message_list[ cache_count ], message, size_m);
                cache_message_list[ cache_count ][size_m]='\0';
            }
            */
			//message is NULL or cannot duplicate the message
			if( cache_message_list[ cache_count ]  == NULL ){
			    pthread_mutex_unlock(&mutex_lock);
				fprintf ( stderr ,"Warning: 203: %s", message);
				return;
            }

			cache_count++;

			pthread_mutex_unlock(&mutex_lock);
		}
	}
	else if (probe_context->sampled_report==0) {

        if (last_reporting_time==0){

        	int len=0;
            len=snprintf(single_file,MAX_FILE_NAME,"%s%s",probe_context->output_location,probe_context->data_out);
            single_file[len]='\0';

        	probe_context->data_out_file = fopen(single_file, "w");

        	if (probe_context->data_out_file==NULL){
        	    fprintf ( stderr , "\n[e] Error: %d creation of \"%s\" failed: %s\n" , errno ,single_file, strerror( errno ) );
        	    exit(1);
            }

        	sprintf(lg_msg, "Open output results file: %s", single_file);
	        mmt_log(probe_context, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

        	last_reporting_time=present_time;

		}

        fprintf (probe_context->data_out_file, "%s\n", message);
	}

}
//end report message
