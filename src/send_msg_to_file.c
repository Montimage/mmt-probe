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

int file_is_modified(const char *path) {
    struct stat file_stat;
	mmt_probe_context_t * probe_context = get_probe_context_config();

    int ret = 0;
    int err = stat(path, &file_stat);
    if (err != 0) {
        perror(" [file_is_modified] stat");
        exit(errno);
    }
    if (file_stat.st_mtime > probe_context->file_modified_time || file_stat.st_ctime > probe_context->file_modified_time){
    	probe_context->file_modified_time = file_stat.st_mtime;
    	ret = 1;
    }
    return ret;
}


cfg_t * parse_conf_new_attribute(const char *filename) {

    cfg_opt_t new_condition_report_opts[] = {
            CFG_INT("enable", 0, CFGF_NONE),
            CFG_INT("id", 0, CFGF_NONE),
            CFG_STR("condition", "", CFGF_NONE),
            CFG_STR_LIST("attributes", "{}", CFGF_NONE),
            CFG_STR_LIST("handlers", "{}", CFGF_NONE),
            CFG_END()
    };

    cfg_opt_t new_event_report_opts[] = {
            CFG_INT("enable", 0, CFGF_NONE),
            CFG_INT("id", 0, CFGF_NONE),
            CFG_STR("event", "", CFGF_NONE),
            CFG_STR_LIST("attributes", "{}", CFGF_NONE),
            CFG_END()
    };

    cfg_opt_t socket_opts[] = {
            CFG_INT("enable", 0, CFGF_NONE),
            CFG_INT("domain", 0, CFGF_NONE),
            CFG_STR_LIST("port", "{}", CFGF_NONE),
            CFG_STR("server-address", 0, CFGF_NONE),
            CFG_STR("socket-descriptor", "", CFGF_NONE),
			CFG_INT("one_socket_server", 0, CFGF_NONE),

            CFG_END()
    };
    cfg_opt_t opts[] = {
             CFG_SEC("condition_report", new_condition_report_opts, CFGF_TITLE | CFGF_MULTI),
			 CFG_SEC("event_report", new_event_report_opts, CFGF_TITLE | CFGF_MULTI),
	         CFG_SEC("socket", socket_opts, CFGF_NONE),
             CFG_END()
    };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);

    switch (cfg_parse(cfg, filename)) {
    case CFG_FILE_ERROR:
        fprintf(stderr, "warning: configuration file '%s' could not be read: %s\n", filename, strerror(errno));
        return 0;
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        return 0;
    }

    return cfg;
}

void new_conditional_reports_init(void * args) {
	int i;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	for(i = 0; i < probe_context->new_condition_reports_nb; i++) {
		mmt_condition_report_t * condition_report = &probe_context->register_new_condition_reports[i];
		//printf ("complete......\n");
		if(register_conditional_report_handle(args, condition_report) == 0) {
			fprintf(stderr, "Error while initializing condition report number %i!\n", condition_report->id);
			printf( "Error while initializing condition report number %i!\n", condition_report->id);
		}
	}

}

void new_event_reports_init(void * args) {
    int i;
    mmt_probe_context_t * probe_context = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) args;
    struct user_data *p;

    for(i = 0; i < probe_context->new_event_reports_nb; i++) {
       		th->new_event_reports = &probe_context->register_new_event_reports[i];
       		if(th->new_event_reports->enable == 1){
       			if (th->new_event_reports->id == 2000){
       				p = malloc( sizeof( struct user_data ));
       				p->smp_thread    = th;
       				p->event_reports = th->new_event_reports;
       				if (is_registered_packet_handler(th->mmt_handler,6) == 1)unregister_packet_handler(th->mmt_handler, 6);
       				register_packet_handler(th->mmt_handler, 6, packet_handler, (void *) p);
       				/*.....socket */

       				if (probe_context->socket_enable == 1 && probe_context->socket_active == 0){
       					create_socket(probe_context, args);
       				}
       			} else 	{
       				p = malloc( sizeof( struct user_data ));
       				p->smp_thread    = th;
       				p->event_reports = th->new_event_reports;
       				if (is_registered_packet_handler(th->mmt_handler,6) == 0)register_packet_handler(th->mmt_handler, 6, packet_handler, (void *) p);
       			}
       			if(register_event_report_handle((void *) p) == 0) {
       				fprintf(stderr, "Error while initializing event report number %i!\n", th->new_event_reports->id);
       			}
       		}
       	}

}
void read_attributes(){
	mmt_probe_context_t * probe_context = get_probe_context_config();

	char * config_file = probe_context->dynamic_config_file;
	cfg_t * cfg = parse_conf_new_attribute(config_file);

	probe_context->new_attribute_register_flag = 1;
	int p = 0;

	for (p = 0; p < probe_context->new_condition_reports_nb; p++){
		free (probe_context->register_new_condition_reports[p].attributes);
		probe_context->register_new_condition_reports[p].attributes = NULL;
		free (probe_context->register_new_condition_reports[p].handlers);
		probe_context->register_new_condition_reports[p].handlers = NULL;
	}

	for (p = 0; p < probe_context->new_event_reports_nb; p++){
		free (probe_context->register_new_event_reports[p].attributes);
		probe_context->register_new_event_reports[p].attributes = NULL;
	}

	if (probe_context->register_new_condition_reports != NULL) {
		free (probe_context->register_new_condition_reports);
		probe_context->register_new_condition_reports = NULL;
	}

	if (probe_context->register_new_event_reports != NULL){
		free (probe_context->register_new_event_reports);
		probe_context->register_new_event_reports = NULL;
	}
	int j = 0, i = 0;
	cfg_t *event_opts;
    int event_reports_nb = cfg_size(cfg, "event_report");
    int event_attributes_nb = 0;
    probe_context ->register_new_event_reports = NULL;
    mmt_event_report_t * temp_er;
    probe_context->new_event_reports_nb = event_reports_nb;


    if (event_reports_nb > 0) {
    	probe_context ->register_new_event_reports = calloc(sizeof(mmt_event_report_t), event_reports_nb);
    	for(j = 0; j < event_reports_nb; j++) {
    		event_opts = cfg_getnsec(cfg, "event_report", j);
    		//probe_context->event_based_reporting_enable = (uint32_t) cfg_getint(event_opts, "enable");
    		temp_er = &probe_context ->register_new_event_reports[j];
    		temp_er->enable = (uint32_t) cfg_getint(event_opts, "enable");

    		if (temp_er->enable == 1){
    			temp_er->id = (uint32_t)cfg_getint(event_opts, "id");
    			if (temp_er->id == 2000)probe_context->enable_security_report = 1;
    			if (parse_dot_proto_attribute((char *) cfg_getstr(event_opts, "event"), &temp_er->event)) {
    				fprintf(stderr, "Error: invalid event_report event value '%s'\n", (char *) cfg_getstr(event_opts, "event"));
    				exit(0);
    			}
    			probe_context->event_based_reporting_enable = (uint32_t) cfg_getint(event_opts, "enable");

    			event_attributes_nb = cfg_size(event_opts, "attributes");
    			temp_er->attributes_nb = event_attributes_nb;
    			if(event_attributes_nb > 0) {
    				temp_er->attributes = calloc(sizeof(mmt_event_attribute_t), event_attributes_nb);

    				for(i = 0; i < event_attributes_nb; i++) {
    					if (parse_dot_proto_attribute(cfg_getnstr(event_opts, "attributes", i), &temp_er->attributes[i])) {
    						fprintf(stderr, "Error: invalid event_report attribute value '%s'\n", (char *) cfg_getnstr(event_opts, "attributes", i));
    						exit(0);
    					}
    				}
    			}
    		}
    	}
    }
	cfg_t * condition_opts;
	j =0;
	i = 0;
	int condition_reports_nb = cfg_size(cfg, "condition_report");
	int condition_attributes_nb = 0;
	int condition_handlers_nb = 0;
	probe_context->register_new_condition_reports = NULL;
	mmt_condition_report_t * temp_condn;
	probe_context->new_condition_reports_nb = condition_reports_nb;
	if (condition_reports_nb > 0) {
		probe_context->register_new_condition_reports = calloc(sizeof(mmt_condition_report_t), condition_reports_nb);
		for(j = 0; j < condition_reports_nb; j++) {
			condition_opts = cfg_getnsec(cfg, "condition_report", j);
			temp_condn = & probe_context->register_new_condition_reports[j];
			temp_condn->id = (uint16_t)cfg_getint(condition_opts, "id");
			temp_condn->enable = (uint32_t)cfg_getint(condition_opts, "enable");

			if (parse_condition_attribute((char *) cfg_getstr(condition_opts, "condition"), &temp_condn->condition)) {
				fprintf(stderr, "Error: invalid condition_report condition value '%s'\n", (char *) cfg_getstr(condition_opts, "condition"));
				exit(0);
			}

			if(strcmp(temp_condn->condition.condition,"FTP") == 0){
				probe_context->ftp_id = temp_condn->id;
				if (temp_condn->enable == 1)probe_context->ftp_enable = 1;
				if (temp_condn->enable == 0)probe_context->ftp_enable = 0;
			}
			if(strcmp(temp_condn->condition.condition,"WEB") == 0){
				probe_context->web_id = temp_condn->id;
				if (temp_condn->enable == 1)probe_context->web_enable = 1;
				if (temp_condn->enable == 0)probe_context->web_enable = 0;
			}
			if(strcmp(temp_condn->condition.condition,"RTP")==0){
				probe_context->rtp_id = temp_condn->id;
				if (temp_condn->enable == 1)probe_context->rtp_enable=1;
				if (temp_condn->enable == 0)probe_context->rtp_enable=0;
			}
			if(strcmp(temp_condn->condition.condition,"SSL") == 0){
				probe_context->ssl_id = temp_condn->id;
				if (temp_condn->enable == 1)probe_context->ssl_enable = 1;
				if (temp_condn->enable == 0)probe_context->ssl_enable = 0;
			}
			if (temp_condn->enable == 1){
				condition_attributes_nb = cfg_size(condition_opts, "attributes");
				temp_condn->attributes_nb = condition_attributes_nb;

				if(condition_attributes_nb > 0) {
					temp_condn->attributes = calloc(sizeof(mmt_condition_attribute_t), condition_attributes_nb);

					for(i = 0; i < condition_attributes_nb; i++) {
						if (condition_parse_dot_proto_attribute(cfg_getnstr(condition_opts, "attributes", i), &temp_condn->attributes[i])) {
							fprintf(stderr, "Error: invalid condition_report attribute value '%s'\n", (char *) cfg_getnstr(condition_opts, "attributes", i));
							exit(0);
						}
					}
				}
				condition_handlers_nb = cfg_size(condition_opts, "handlers");
				temp_condn->handlers_nb = condition_handlers_nb;

				if(condition_handlers_nb > 0) {
					temp_condn->handlers = calloc(sizeof(mmt_condition_attribute_t), condition_handlers_nb);

					for(i = 0; i < condition_handlers_nb; i++) {
						if (parse_handlers_attribute((char *) cfg_getnstr(condition_opts, "handlers", i), &temp_condn->handlers[i])) {
							fprintf(stderr, "Error: invalid condition_report handler attribute value '%s'\n", (char *) cfg_getnstr(condition_opts, "handlers", i));
							exit(0);
						}
					}
				}
			}

		}
	}
	cfg_free(cfg);
}
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

	n = scandir( folder, &entries, load_filter, alphasort );
	if( n < 0 ) {
		mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TERMINATION, "Cannot scan output_dir!");
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
			mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_STATUS, "Cannot delete old sampled files!");
		}

		ret = snprintf( file_name, 255, "%s/%s.sem", folder, entry->d_name );
		file_name[ ret ] = '\0';

		ret = unlink( file_name );
		if( ret ){
			mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_STATUS, "Cannot delete old semaphore sampled files!");
		}
	}

	for( i=0; i<n; i++ )
		free( entries[ i ] );
   free( entries );

	return to_remove;
}


void exit_timers(){
	//struct smp_thread *th = (struct smp_thread *) arg;
	//flush_messages_to_file_thread( th );
	pthread_spin_lock(&spin_lock);
	is_stop_timer = 1;
	int ret =pthread_cancel(mmt_probe.timer_handler);
	pthread_spin_unlock(&spin_lock);

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
	mmt_probe_context_t * probe_context = get_probe_context_config();
	mmt_probe_struct_t * probe = (mmt_probe_struct_t *)p_data->user_data;
	uint32_t seconds   = p_data->period;
	int i=0;
	FILE * register_attributes;
	int file_modified_flag = 0;
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
		register_attributes = fopen(probe_context->dynamic_config_file, "r");

		if( probe_context->retain_files > 0 ){

			//-1 as this will create a new .csv as below
			//=> if we need to retain only 2 files
			// =>  at this moment we retain only 1 file
			// and a new file will be created after this function
			ret_val = remove_old_sampled_files( probe_context->output_location, probe_context->retain_files - 1 );

			sprintf(lg_msg, "Removed %d sampled files", ret_val);
			mmt_log(probe->mmt_conf, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);
		}


		if (register_attributes != NULL ){
			file_modified_flag = file_is_modified (probe_context->dynamic_config_file);
			if (file_modified_flag){
				pthread_spin_lock(&spin_lock);

				read_attributes(); // initialize once if file changed
				pthread_spin_unlock(&spin_lock);

			}
		}
		if (register_attributes != NULL)fclose(register_attributes);
		for (i = 0; i < probe_context->thread_nb; i++){
			//printf("thread number_wait_to_do_something = %d \n",probe->smp_threads[i].thread_number);
			if (file_modified_flag){
				probe->smp_threads[i].file_read_flag = 1;
			}
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

int start_timer( uint32_t period, void *callback, void *user_data){
	int ret;
	mmt_probe_context_t * probe_context = get_probe_context_config();
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

#define MAX_FILE_NAME 500
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
	char command_str [500+1] = {0};
	char message[MAX_MESS + 1];
	struct timeval ts;
	//Print this report every 5 second
	time_t present_time;
	present_time = time(0);
	gettimeofday(&ts, NULL);
	struct smp_thread *th = (struct smp_thread *) arg;

	//dummy report
	if (th->thread_number == 0){
		if(probe_context->cpu_mem_usage_enabled == 1){
			double drop_percent = 0, drop_percent_NIC = 0, drop_percent_kernel =0;
			if (th->nb_packets != 0) {
				drop_percent = th->nb_dropped_packets *100/ th->nb_packets;
				drop_percent_NIC = th->nb_dropped_packets_NIC * 100 / th->nb_packets;
				drop_percent_kernel = th->nb_dropped_packets_kernel * 100 / th->nb_packets;
				}
			snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu, %3.2Lf%%, %3.2Lf%%, %3.2f%%, %3.2f%%, %3.2f%%",
					200, probe_context->probe_id_number,
					probe_context->input_source, ts.tv_sec, ts.tv_usec, th->cpu_usage, th->mem_usage, drop_percent, drop_percent_NIC, drop_percent_kernel);
		}
		else {
			snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu",
					200, probe_context->probe_id_number,
					probe_context->input_source, ts.tv_sec, ts.tv_usec);
			}

		message[ MAX_MESS] = '\0';
		if (probe_context->output_to_file_enable == 1) send_message_to_file_thread (message, (void *)th);
		if (probe_context->redis_enable == 1)send_message_to_redis ("session.flow.report", message);
	}
	if( th->cache_count == 0 ){
		//printf ("nothing to write = %d",th->thread_number);
		//pthread_spin_unlock(&th->lock);
		return;
	}

	//open a file
	valid = snprintf(file_name_str, MAX_FILE_NAME, "%s%lu_%d_%s", probe_context->output_location, present_time, th->thread_number, probe_context->data_out);
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
				valid = snprintf(sem_file_name_str, MAX_FILE_NAME, "%s%lu_%d_%s.sem", probe_context->behaviour_output_location, present_time, th->thread_number, probe_context->data_out);
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

void send_message_to_file (char * message) {
	FILE * file;
	char file_name_str [MAX_FILE_NAME+1] = {0};
	char sem_file_name_str [MAX_FILE_NAME+5] = {0};	//file_name + ".sem"
	char lg_msg[1024];
	int valid = 0;
	int i = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	struct timeval ts;
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
