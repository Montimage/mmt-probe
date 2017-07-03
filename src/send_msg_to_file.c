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
#include "confuse.h"
#include <sys/stat.h>
#include <dirent.h>

static int load_filter( const struct dirent *entry ){
	mmt_probe_context_t * probe_context = get_probe_context_config();

	//must end by probe_context->data_out, e.g.,  dataoutput.csv
	char *ext = strstr( entry->d_name, probe_context->data_out );
	if( ext == NULL ) return 0;
	return (strlen( ext ) == strlen( probe_context->data_out ));
}
/**
 * Remove old sampled files in #folder
 * Sample file name in format: xxxxxxxxxx_abc.csv and its semaphore in format: xxxxxxxxxx_abc.csv.sem
 *  in which xxxxxxxxxx is a number represeting timestamp when the file was created
 */
int remove_old_sampled_files(const char *folder, size_t retains){
	struct dirent **entries, *entry;
	char file_name[256];
	int i, n, ret, to_remove;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	n = scandir( folder, &entries, load_filter, alphasort );
	if( n < 0 ) {
		mmt_log(probe_context, MMT_L_ERROR, MMT_P_TERMINATION, "Cannot scan output_dir!");
		exit( 1 );
	}

	to_remove = n - retains;
	//printf("total file %d, retains: %zu, to remove %d\n", n, retains, to_remove );
	if( to_remove < 0 ) to_remove = 0;

	for( i = 0 ; i < to_remove ; ++i ) {
		entry = entries[i];
		ret = snprintf( file_name, 255, "%s/%s", folder, entry->d_name );
		file_name[ ret ] = '\0';

		ret = unlink( file_name );
		if( ret ){
			mmt_log(probe_context, MMT_L_WARNING, MMT_P_STATUS, "Cannot delete old sampled files!");
		}

		ret = snprintf( file_name, 255, "%s/%s.sem", folder, entry->d_name );
		file_name[ ret ] = '\0';

		ret = unlink( file_name );
		if( ret ){
			mmt_log(probe_context, MMT_L_WARNING, MMT_P_STATUS, "Cannot delete old semaphore sampled files!");
		}
	}

	for( i = 0; i < n; i++ )
		free( entries[ i ] );
	free( entries );

	return to_remove;
}

/* This function exits a timer thread */
void exit_timers(){
	//struct smp_thread *th = (struct smp_thread *) arg;
	//flush_messages_to_file_thread( th );
	pthread_spin_lock(&spin_lock);
	is_stop_timer = 1;
	int ret = pthread_cancel(mmt_probe.timer_handler);
	pthread_spin_unlock(&spin_lock);

}

//start timer
typedef struct pthread_user_data{
	uint32_t period;
	void     (*callback)( void * );
	void     *user_data;
}pthread_user_data_t;

/* This function runs a timer and in each timer expiry executes specific tasks*/
static void *wait_to_do_something( void *arg ){
	int ret;
	struct itimerspec itval;
	int timer_fd  = -1;
	uint64_t expirations = 0;
	pthread_user_data_t  *p_data = arg;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	mmt_probe_struct_t * probe = (mmt_probe_struct_t *)p_data->user_data;
	uint32_t seconds   = p_data->period;
	int i=0;
	char lg_msg[1024];
	int ret_val;
	// Create the timer
	timer_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (timer_fd == -1){
		perror("timerfd_create:");
		return NULL;
	}

	//Make the timer periodic
	itval.it_interval.tv_sec  = seconds;
	itval.it_interval.tv_nsec = 0;
	itval.it_value.tv_sec     = seconds;
	itval.it_value.tv_nsec    = 0;

	ret = timerfd_settime (timer_fd, 0, &itval, NULL);
	if( ret != 0 ){
		perror("timerfd_settime:");
		return NULL;
	}

	while( 1 ){
		pthread_spin_lock(&spin_lock);
		if ( is_stop_timer ){
			pthread_spin_unlock(&spin_lock);
			break;
		}
		pthread_spin_unlock(&spin_lock);
		//printf("wait for %d - %lu - %d\n", seconds, id, number_pthread );
		//fflush( stdout );
		/* Wait for the next timer event. If we have missed any the
		 *         number is written to "expirations"*/


		ret = read (timer_fd, &expirations, sizeof (expirations));
		if( ret == -1 ){
			perror ("read timer");
			return NULL;
		}

		//"missed" should always be >= 1, but just to be sure, check it is not 0 anyway

		if (expirations > 1) {
			printf("missed %lu", expirations - 1);
			fflush( stdout );
		}


		if( probe_context->retain_files > 0 && probe_context->output_to_file_enable == 1){

			//-1 as this will create a new .csv as below
			//=> if we need to retain only 2 files
			// =>  at this moment we retain only 1 file
			// and a new file will be created after this function
			ret_val = remove_old_sampled_files( probe_context->output_location, probe_context->retain_files - 1 );

			sprintf(lg_msg, "Removed %d sampled files", ret_val);
			mmt_log(probe->mmt_conf, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);
		}
		for (i = 0; i < probe_context->thread_nb; i++){
			//printf("thread number_wait_to_do_something = %d \n",probe->smp_threads[i].thread_number);
			p_data->user_data = (void *) &probe->smp_threads[i];
			(* p_data->callback)( p_data->user_data );

		}

	}

	//end the timer
	close( timer_fd );

	if( p_data != NULL ){
		free( p_data );
		p_data = NULL;
	}


	return NULL;
};

/* This function creates a separate thread for a timer */
int start_timer( uint32_t period, void *callback, void *user_data){
	int ret;
	pthread_user_data_t *data = malloc( sizeof( pthread_user_data_t ));
	//pthread_t pthread;
	data->period   = period;
	data->callback = callback;
	data->user_data = user_data;
	ret = pthread_create(&mmt_probe.timer_handler, NULL, wait_to_do_something, data);

	if( ret != 0 ){
		perror("pthread_create for timer:ERROR");
		exit( 0 );
	}

	return ret;
}

//end of timer

//start report messages

/* This function writes messages from each thread queue to a separate file.
 * A semaphore is created to indicate writing is finished.
 * */
void flush_messages_to_file_thread( void *arg){

	mmt_probe_context_t * probe_context = get_probe_context_config();

	if(probe_context->sampled_report == 0)return;
	FILE * file;
	char file_name_str [MAX_FILE_NAME+1] = {0};
	char dup_file_name_str [MAX_FILE_NAME+1] = {0};
	char sem_file_name_str [MAX_FILE_NAME+5] = {0};	//file_name + ".sem"
	char lg_msg[1024];
	int valid = 0;
	int i = 0;
	char command_str [MAX_FILE_NAME+1] = {0};
	char message[MAX_MESS + 1];

	struct timeval ts;
	//Print this report every 5 second
	time_t present_time;
	present_time = time(0);
	gettimeofday(&ts, NULL);
	struct smp_thread *th = (struct smp_thread *) arg;
	double drop_percent = 0, drop_percent_NIC = 0, drop_percent_kernel =0;
	//dummy report
	if (th->thread_index == 0){
		valid = snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu",
				200, probe_context->probe_id_number,
				probe_context->input_source, ts.tv_sec, ts.tv_usec);

		if(probe_context->cpu_mem_usage_enabled == 1){
			/*if (th->nb_packets != 0) {
				drop_percent = th->nb_dropped_packets *100/ th->nb_packets;
				drop_percent_NIC = th->nb_dropped_packets_NIC * 100 / th->nb_packets;
				drop_percent_kernel = th->nb_dropped_packets_kernel * 100 / th->nb_packets;
			}*/
			valid += snprintf(&message[valid], MAX_MESS, ",%3.2Lf%%,%3.2Lf%% \n",
					probe_context->cpu_reports->cpu_usage_avg, probe_context->cpu_reports->mem_usage_avg);
		}
		message[ valid] = '\0';

		if (probe_context->output_to_file_enable) send_message_to_file_thread (message, (void *)th);
	}

	if( th->cache_count == 0 ){
		//printf ("nothing to write = %d",th->thread_number);
		//pthread_spin_unlock(&th->lock);
		return;
	}
	valid = 0;
	//open a file
	valid = snprintf(file_name_str, MAX_FILE_NAME, "%s%lu_%d_%s", probe_context->output_location, present_time, th->thread_index, probe_context->data_out);
	file_name_str[valid] = '\0';

	file = fopen(file_name_str, "w");

	sprintf(lg_msg, "Open output results file: %s", file_name_str );
	mmt_log(probe_context, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

	if (file == NULL){
		fprintf ( stderr , "\n Error: %d creation of \"%s\" failed: %s\n" , errno , file_name_str , strerror( errno ) );
		//exit(1);
	}

	//write messages to the file
	int ret = pthread_spin_lock(&th->lock);

	if (ret == 0) {
		for( i=0; i<th->cache_count; i++ ){
			if( th->cache_message_list[ i ] == NULL ){
				perror("this message should not be NULL");
			}else{
				fprintf ( file, "%s\n", th->cache_message_list[ i ]);
				//printf("message ,th->nd =%d,= %s\n",th->thread_number,th->cache_message_list[ i ]);
				if (th->cache_message_list[ i ]) free( th->cache_message_list[ i ] );
				th->cache_message_list[ i ] = NULL;
			}
		}
		th->cache_count = 0;
		//pthread_spin_unlock(&th->lock);
	}
	pthread_spin_unlock(&th->lock);

	//close the file
	i = fclose( file );

	if (i != 0){
		fprintf ( stderr , "\n1: Error %d closing of sampled_file failed: %s" , errno, strerror( errno ) );
		//exit(1);
	}
	//char * const command_str[] = {"cp",file_name_str,probe_context->behaviour_output_location, NULL};
	//duplicate the file for behaviour
	if (probe_context->behaviour_enable == 1){

		//check if the system command is available
		valid = system(NULL);
		if (valid == 0){
			fprintf(stderr,"No processor available on the system,while running system() command");
			//exit(1);
		}else{
			//duplicate file
			valid = snprintf( command_str, MAX_FILE_NAME, "cp %s %s", file_name_str , probe_context->behaviour_output_location);
			command_str[ valid ] = '\0';
			valid = system( command_str );

			if ( valid != 0 ){
				fprintf(stderr,"\n5 Error code %d, while coping output file %s to %s ", valid, dup_file_name_str, probe_context->behaviour_output_location);
				//exit(1);
			}else {

				//create semaphore
				valid = snprintf(sem_file_name_str, MAX_FILE_NAME, "%s%lu_%d_%s.sem", probe_context->behaviour_output_location, present_time, th->thread_index, probe_context->data_out);
				sem_file_name_str[ valid ] = '\0';
				file= fopen(sem_file_name_str, "w");

				if ( file == NULL ){
					fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_name_str , strerror( errno ) );
					//exit(1);
				}else{

					valid = fclose( file );
					if ( valid!=0 ){
						fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s", errno, strerror( errno ) );
						//exit(1);
					}
				}
			}
		}
	}
	//create semaphore
	valid=snprintf(sem_file_name_str, MAX_FILE_NAME, "%s.sem", file_name_str);
	sem_file_name_str[ valid ] = '\0';
	file = fopen(sem_file_name_str, "w");

	if ( file == NULL ){
		fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_name_str , strerror( errno ) );
		//exit(1);
	}else {

		valid = fclose( file );
		if ( valid != 0 ){
			fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s" , errno, strerror( errno ) );
			//exit(1);
		}
	}
}

/* This function writes message to a thread queue, if sampled_report is enable,
 * otherwise writes to a file. */
void send_message_to_file_thread (char * message, void *args) {
	mmt_probe_context_t * probe_context = get_probe_context_config();
	if(probe_context->sampled_report == 1){
		struct smp_thread *th = (struct smp_thread *) args;
		//avoid 2 threads access in the same time
		int ret = pthread_spin_lock(&th->lock);
		if (ret == 1)printf("lock failed \n");
		if (ret == 0) {
			if( th->cache_count >= probe_context->report_cache_size_before_flushing - 1 ){
				perror("Warning: cache size is too small");
				exit( 0 );
			}
			//cache_message_list[ cache_count ] = strdup( message );
			//allocate memory for number of reports
			if (th->cache_message_list == NULL)th->cache_message_list = malloc(probe_context->report_cache_size_before_flushing * sizeof( char * ) +1 );
			int len = 0;
			len = strlen(message);
			//if (len > 2999 || len < 1) fprintf ( stderr ,"Warning: 201: %d, %d\n", len, (int)th->cache_count);
			th->cache_message_list[ th->cache_count ] = malloc(len+1);
			if( th->cache_message_list[ th->cache_count ]  == NULL ){
				fprintf ( stderr ,"Warning: 202, %d, %d\n", len, (int)th->cache_count);
				perror("this array should not be NULL");
			}
			else {
				memcpy(th->cache_message_list[ th->cache_count ], message, len);
				th->cache_message_list[ th->cache_count ][len] ='\0';
			}
			//message is NULL or cannot duplicate the message
			if( th->cache_message_list[ th->cache_count ]  == NULL ){
				pthread_spin_unlock(&th->lock);
				fprintf ( stderr ,"Warning: 203: %s", message);
				return;
			}
			th->cache_count++;
		}
		pthread_spin_unlock(&th->lock);
	}else if (probe_context->sampled_report == 0) {
		fprintf (probe_context->data_out_file, "%s\n", message);
	}

}
/* This function writes license information to a file */
void send_message_to_file (char * message) {
	FILE * file;
	char file_name_str [MAX_FILE_NAME+1] = {0};
	char sem_file_name_str [MAX_FILE_NAME+5] = {0};	//file_name + ".sem"
	char lg_msg[1024];
	int valid = 0;
	int i = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	time_t present_time;
	present_time = time(0);


	valid = snprintf(file_name_str, MAX_FILE_NAME, "%s%lu_%s",probe_context->output_location,present_time,probe_context->data_out);
	file_name_str[valid] = '\0';

	file = fopen(file_name_str, "w");

	sprintf(lg_msg, "Open output results file: %s", file_name_str );
	mmt_log(probe_context, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);

	if (file == NULL){
		fprintf ( stderr , "\n Error: %d creation of \"%s\" failed: %s\n" , errno , file_name_str , strerror( errno ) );
		//exit(1);
	}else{
		fprintf ( file, "%s\n", message);

		i = fclose( file );

		if (i != 0){
			fprintf ( stderr , "\n1: Error %d closing of sampled_file failed: %s" , errno ,strerror( errno ) );
			//exit(1);
		}
	}

	//create semaphore
	valid = snprintf(sem_file_name_str, MAX_FILE_NAME, "%s.sem", file_name_str);
	sem_file_name_str[ valid ] ='\0';
	file = fopen(sem_file_name_str, "w");

	if ( file == NULL ){
		fprintf ( stderr , "\n2: Error: %d creation of \"%s\" failed: %s\n" , errno , sem_file_name_str , strerror( errno ) );
		//exit(1);
	}else{

		valid = fclose( file );
		if ( valid != 0 ){
			fprintf ( stderr , "\n4: Error %d closing of temp_behaviour_sem_file failed: %s" , errno ,strerror( errno ) );
			//exit(1);
		}
	}
}

//end report message
