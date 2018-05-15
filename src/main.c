/*
 * main.c
 *
 *  Created on: Dec 12, 2017
 *          by: Huu Nghia
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h> //usleep, sleep
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <mmt_core.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib/log.h"
#include "lib/version.h"
#include "lib/tools.h"
#include "lib/memory.h"
#include "lib/version.h"
#include "lib/limit.h"
#include "context.h"
#include "configure_override.h"
#include "modules/routine/routine.h"

#ifdef DPDK_MODULE
#include "modules/packet_capture/dpdk/dpdk_capture.h"
#endif

#ifdef PCAP_MODULE
#include "modules/packet_capture/pcap/pcap_capture.h"
#endif

#ifdef SECURITY_MODULE
#include "modules/security/security.h"
#endif

/*
 * Default configuration file: either in the current folder or in /opt/mmt/probe
 * The former has a higher priority
 */
#define DEFAULT_CONFIG_FILE     "./mmt-probe.conf"
#define DEFAULT_CONFIG_FILE_OPT "/opt/mmt/probe/mmt-probe.conf"

static void _print_usage(const char * prg_name) {
	printf("%s [<option>]\n", prg_name);
	printf("Option:\n");
	printf("\t-v               : Print version information, then exits.\n");
	printf("\t-c <config file> : Gives the path to the configuration file (default: %s, %s).\n",
				DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_FILE_OPT);
	printf("\t-t <trace file>  : Gives the trace file for offline analyse.\n");
	printf("\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
	printf("\t-X attr=value    : Override configuration attributes.\n");
	printf("\t                    For example \"-X file-output.enable=true -Xfile-output.output-dir=/tmp/\" will enable output to file and change output directory to /tmp.\n");
	printf("\t                    This parameter can appear several times.\n");
	printf("\t-x               : Prints list of configuration attributes being able to be used with -X, then exits.\n");
	printf("\t-h               : Prints this help, then exits.\n");
}

static inline void _override_string_conf( char **conf, const char*new_val ){
	free( *conf );
	*conf = strdup( new_val );
}


static inline probe_conf_t* _parse_options( int argc, char ** argv ) {
	int opt, optcount = 0;
	int val;

	const char *options = "c:t:i:vhxX:";
	const char *config_file = DEFAULT_CONFIG_FILE;
	probe_conf_t *conf = NULL;

	extern char *optarg;
	extern int optind;

	char *string_att, *string_val;

	bool is_user_gives_conf_file = false;

	//first parser round to get configuration file
	while ((opt = getopt(argc, argv, options )) != EOF) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			is_user_gives_conf_file = true;
			break;
		case 'v':
			printf("Version:\n");
			printf( "- MMT-Probe %s\n", get_version());
			printf( "- MMT-DPI %s\n", mmt_version() );
			IF_ENABLE_SECURITY(
					printf( "- MMT-Security %s\n", security_get_version() );
			)
			printf("- Modules: %s\n", MODULES_LIST );
			exit( EXIT_SUCCESS );
		case 'h':
			_print_usage(argv[0]);
			exit( EXIT_SUCCESS );
		case 'x':
			conf_print_identities_list();
			exit( EXIT_SUCCESS );
		}
	}

	conf = conf_load_from_file( config_file );
	if( conf == NULL ){
		//config_file is indicated by user by -c parameter
		if( is_user_gives_conf_file ){
			fprintf(stderr, "Cannot read configuration file from %s\n", config_file );
			abort();
		}else{
			//try again to read config from /opt/mmt/probe/mmt-probe.conf
			config_file = DEFAULT_CONFIG_FILE_OPT;
			conf = conf_load_from_file( config_file );
			if( conf == NULL )
				abort();
		}
	}

	log_write( LOG_INFO, "Loaded configuration from '%s'", config_file );

	//reset getopt function
	optind = 0;
	//override some options inside the configuration
	while ((opt = getopt(argc, argv, options)) != EOF) {
		switch (opt) {
		//trace file
		case 't':
			_override_string_conf( &conf->input->input_source, optarg );
			//switch to offline mode
			conf->input->input_mode = OFFLINE_ANALYSIS;
			break;
			//input interface
		case 'i':
			_override_string_conf( &conf->input->input_source, optarg );
			//switch to online mode
			conf->input->input_mode = ONLINE_ANALYSIS;
			break;

		case 'X':
			//example: -X file-output.enable=true
			//we will separate the phrase "file-output.enable=true" into 2
			// to expect:
			//   string_att = "file-output.enable"
			//   string_val = "true"
			string_att = optarg;
			string_val = optarg;
			while( *string_val != '\0' ){
				//separated by = character
				if( *string_val == '=' ){
					*string_val = '\0'; //NULL ended for attribute
					//jump to the part after = character
					string_val ++;
					break;
				}
				string_val ++;
			}
			//not found = character
			if( *string_val == '\0' )
				log_write( LOG_WARNING, "Input parameter '%s' is not well-formatted (must be in format parameter=value). Ignored it.", string_att );

			if( conf_override_element(conf, string_att, string_val) )
				log_write( LOG_INFO, "Overridden value of configuration parameter '%s' by '%s'", string_att, string_val );
		}
	}

	return conf;
}

#ifdef DEBUG_MODE
	#warning "The debug compile option is reserved only for debugging"
#endif

/* Obtain a backtrace */
static void _print_execution_trace () {
	void *array[10];
	size_t size;
	char **strings;
	size_t i;
	size    = backtrace (array, 10);
	strings = backtrace_symbols (array, size);
	//i=2: ignore 2 first elements in trace as they are: this fun, then mmt_log
	for (i = 2; i < size; i++)
		log_write( LOG_ERR, "%zu. %s\n", (i-1), strings[i] );

	free (strings);
	fflush( stdout );
}


static inline void _stop_modules( probe_context_t *context){

	IF_ENABLE_PCAP(
		pcap_capture_stop(context);
	)

}

probe_context_t *get_context(){
	static probe_context_t context;
	return &context;
}

#ifdef DPDK
#define _EXIT rte_exit
#else
#define _EXIT _exit
#endif

//depending on exit value of a child process, the main process can restart or not the child process
#define EXIT_NORMALLY                _EXIT( EXIT_SUCCESS )
#define EXIT_THEN_RESTART_BY_PARENT  _EXIT( EXIT_FAILURE )

/**
 * This signal handler ensures clean exits.
 * Note: calling printf() from a signal handler is not safe since printf() is not async-signal-safe.
 *      Nevertheless, MMT-Probe will exit at the end of executing signal_handler(), thus we do not need
 *      to care about the restore point of signal_handler.
 */
void signal_handler(int type) {
	probe_context_t *context = get_context();
	if(  context->is_aborting ){
		log_write(LOG_ERR, "Received signal %d while processing other one. Exit immediately.", type );
		fflush( stdout );
		EXIT_NORMALLY;
	}

	switch( type ){
	case SIGINT:
		fprintf(stderr, "Received Ctrl+C. Releasing resource ...\n");
		log_write(LOG_INFO, "Received Ctrl+C. Releasing resource ...");
		context->is_aborting = true;

		_stop_modules( context );
		EXIT_NORMALLY;
		break;

		//segmentation fault
	case SIGSEGV:
		log_write(LOG_ERR, "Segv signal received!");
		_print_execution_trace();

		//Auto restart when segmentation fault
		//restart only if exec in online mode
		if( context->config->input->input_mode == OFFLINE_ANALYSIS )
			EXIT_NORMALLY;
		else
			EXIT_THEN_RESTART_BY_PARENT;

		break;

		//abort signal may be generated by calling abort() function.
		//In the code, this function is called when some parameters are not well configured.
		//In such a case, we need to exit normally MMT-Probe to give control to user to update the parameters
	case SIGABRT:
		log_write(LOG_ERR, "Abort signal received! Cleaning up before exiting!");
		EXIT_NORMALLY;
		break;
	}
}

static int _main_processing( int argc, char** argv ){
	signal(SIGINT,  signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);

	int ret = 0;

	probe_context_t *context = get_context();

#ifdef DPDK_MODULE
	ret = rte_eal_init( argc, argv );
	if (ret < 0)
		rte_exit_failure("Error with EAL initialization\n");
#endif

	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_open( context->config->reports.security->excluded_rules );
	)

	log_write( LOG_INFO, "MMT-Probe v%s is running on pid %d",
			get_version(),
			getpid() );
	log_write( LOG_INFO, "Modules: " MODULES_LIST );

	//DPI initialization
	if( !init_extraction() ) { // general ixE initialization
		log_write( LOG_ERR, "MMT Extraction engine initialization error! Exiting!");
		return EXIT_FAILURE;
	}else
		log_write( LOG_INFO, "MMT-DPI %s", mmt_version() );

	//other stubs, such as, system usage report
	routine_t *routine = routine_create_and_start( context );

#ifdef DPDK_MODULE
	dpdk_capture_start( context );
#else
	pcap_capture_start( context );
#endif


	//end
	close_extraction();


	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_close();
	)

	routine_stop_and_release( routine );

	return EXIT_SUCCESS;
}


#if defined DPDK_MODULE && defined PCAP_MODULE
#error("Either DPDK_MODULE or PCAP_MODULE is defined but must not all of them")
#endif


/**
 * Main process.
 * Main process will create 2 children processes:
 *  - processing process: performs main jobs
 *  -
 * @param argc
 * @param argv
 * @return
 */

#define PID_NEED_TO_CREATE 0
#define PID_NEED_TO_STOP  -1

typedef int (*children_fun_t)( int, char ** );

int main( int argc, char** argv ){
	int child_pid, status, i;
	int children_pids[ 2 ] = {PID_NEED_TO_CREATE, PID_NEED_TO_CREATE};
	children_fun_t children_processes[2] = { _main_processing, NULL };

#ifdef DYNAMIC_CONFIG_MODULE
	const int nb_children_processes = 2;
#else
	const int nb_children_processes = 1;
#endif
	//ignore Ctrl+C in main process
	signal( SIGINT, SIG_IGN );
	log_open();

	probe_context_t *context = get_context();
	context->is_aborting = false;
	context->config = _parse_options(argc, argv);
	conf_validate( context->config );

	IF_ENABLE_DEBUG(
			log_write( LOG_WARNING, "Must not run debug mode in production environment" );
	)

	IF_ENABLE_DYNAMIC_CONFIG(
		mmt_bus_create( SIGUSR1, uint8_t 3 );
	)

	while( true ){
		//create each child process
		for( i=0; i<nb_children_processes; i++ )
			if( children_pids[ i ] == PID_NEED_TO_CREATE && children_processes[i] != NULL ){
				//duplicate the current process into 2 different processes
				child_pid = fork();

				if( child_pid < 0 ) {
					ABORT( "Fork error: %s", strerror(errno) );
					return EXIT_FAILURE;
				}

				if (child_pid == 0) {
					//we are in child process
					log_write( LOG_INFO, "Create a new sub-process %d", getpid() );
					children_processes[i]( argc, argv );

					//clean resource
					conf_release( context->config );
					log_close();
					return EXIT_SUCCESS;
				}

				//in parent process
				children_pids[i] = child_pid;
			}

		//parent is blocked here until one of its children terminates
		child_pid = wait( &status );

		DEBUG("Child process %d return code: %d", child_pid, status );

		if( child_pid == -1 )
			ABORT( "Cannot wait for children: %s", strerror( errno ) );

		//The child it exist normally,
		// then lets keep it dead
		if ( WIFEXITED( status) && WEXITSTATUS( status ) == EXIT_SUCCESS )
			status = PID_NEED_TO_STOP;
		else
			status = PID_NEED_TO_CREATE;

		//update status of the child
		for( i=0; i<nb_children_processes; i++ )
			if( child_pid == children_pids[i] ){
				//mark to re-create this child
				children_pids[i] = status;
				break;
			}

		//check number of children they need to stop
		int nb_children_need_to_stop = 0;
		for( i=0; i<nb_children_processes; i++ )
			if( children_pids[i] ==  PID_NEED_TO_STOP)
				nb_children_need_to_stop ++;

		//all children need to be stopped
		if( nb_children_need_to_stop == nb_children_processes )
			break;
	}

	conf_release( context->config );
	log_close();
	printf("Bye\n");
	return EXIT_SUCCESS;
}
