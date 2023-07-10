/*
 * main.c
 *
 *  Created on: Dec 12, 2017
 *          by: Huu Nghia
 *
 * This is main of MMT-Probe.
 * It will create 2 children processes:
 *   + processing process: this this main processing of MMT-Probe
 *   + control process: it receives control commands via an UNIX socket, check them, then broadcast them.
 *                      It is created only if DYNAMIC_CONFIG_MODULE is defined.
 * There are totally 3 processes: 2 children + dispatcher (main).
 * The dispatch monitors their children, and re-create a child if it has crashed.
 * The dispatch receives also a command from the control process to start or stop the processing process.
 *
 */
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>   // stat
#include <stdbool.h>    // bool type

#include "lib/log.h"
#include "lib/version.h"
#include "lib/tools.h"
#include "lib/malloc.h"
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

#ifdef DYNAMIC_CONFIG_MODULE
#include "modules/dynamic_conf/dynamic_conf.h"
#endif

#if defined DPDK_MODULE && defined PCAP_MODULE
#error("Either DPDK_MODULE or PCAP_MODULE is defined but must not all of them")
#endif

#ifdef DEBUG_MODE
	#warning "The debug compile option is reserved only for debugging"
#endif

#ifndef MMT_BASE
	#define MMT_BASE "/opt/mmt"
#endif

/*
 * Default configuration file: either in the current folder or in /opt/mmt/probe
 * The former has a higher priority
 */
#define DEFAULT_CONFIG_FILE     "./mmt-probe.conf"
#define DEFAULT_CONFIG_FILE_OPT MMT_BASE "/probe/mmt-probe.conf"

static void _print_usage(const char * prg_name) {
	printf("%s [<Option>]\n", prg_name);
	printf("Option:\n");
	printf("\t-v               : Print version information, then exits.\n");
	printf("\t-c <config file> : Gives the path to the configuration file (default: %s, %s).\n",
				DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_FILE_OPT);
IF_ENABLE_PCAP(
	printf("\t-t <trace file>  : Gives the trace file for offline analyse.\n");
)
	printf("\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
	printf("\t-X attr=value    : Override configuration attributes.\n");
	printf("\t                    For example \"-X file-output.enable=true -Xfile-output.output-dir=/tmp/\" will enable output to file and change output directory to /tmp.\n");
	printf("\t                    This parameter can appear several times.\n");
	printf("\t-x               : Prints list of configuration attributes being able to be used with -X, then exits.\n");
	printf("\t-h               : Prints this help, then exits.\n");
}

/**
 * Free a string pointer before clone data to it
 */
static inline void _override_string_conf( char **conf, const char*new_val ){
	free( *conf );
	*conf = strdup( new_val );
}

bool _is_file_exists (const char *filename) {
	struct stat buffer;
	return (stat (filename, &buffer) == 0);
}

/**
 * 1) Parse options from execution command line to get location of configuration file.
 * 2) Load configuration from the file
 * 3) Override the configuration parameters, that was loaded from file, by the ones given from execution command line
 * @param argc
 * @param argv
 * @return
 */
static inline probe_conf_t* _parse_options( int argc, char ** argv ) {
	int opt, optcount = 0;
	int val;
#ifdef DPDK_MODULE
	const char *options = "c:i:vhxX:"; //not allow -t to analyze pcap files
#else
	const char *options = "c:t:i:vhxX:";
#endif
	const char *config_file = NULL;
	probe_conf_t *conf = NULL;

	extern char *optarg;
	extern int optind;

	char *string_att, *string_val;

	//first parser round to get configuration file
	while ((opt = getopt(argc, argv, options )) != EOF) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'v':
			printf("Version:\n");
			printf( "- MMT-Probe %s\n", get_version());
			printf( "- MMT-DPI %s\n", mmt_version() );
			IF_ENABLE_SECURITY(
					printf( "- MMT-Security %s\n", security_get_version() );
			)
			printf("- Modules: %s\n", MODULES_LIST );
			printf("- MMT_BASE: %s\n", MMT_BASE );
			exit( EXIT_SUCCESS );
		case 'h':
			_print_usage(argv[0]);
			exit( EXIT_SUCCESS );
		case 'x':
			conf_print_identities_list();
			exit( EXIT_SUCCESS );
		}
	}

	//user given
	if( config_file ){
		conf = conf_load_from_file( config_file );
		if( conf == NULL )
			abort();
	}else{
		// load ./mmt-probe.conf if it is existing
		if( _is_file_exists( DEFAULT_CONFIG_FILE) ){
			config_file = DEFAULT_CONFIG_FILE;
			conf = conf_load_from_file( config_file );
			if( conf == NULL )
				abort();
		} else {
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

			switch( conf_override_element(conf, string_att, string_val) ){
			case 0:
				log_write( LOG_INFO, "Overridden value of configuration parameter '%s' by '%s'", string_att, string_val );
				break;
			case 1: //value is incorrect
				fprintf(stderr, "Unexpected parameter value %s\n", string_val );
				exit( 1 );
				break;
			case -1:  //ident is incorrect
				fprintf(stderr, "Unknown parameter identity %s\n", string_att );
				exit( 1 );
				break;
			default: break;
			}

		}
	}

	if( conf_validate(conf) ){
		abort();
	}

	return conf;
}

static inline void _stop_modules( probe_context_t *context){
	IF_ENABLE_PCAP(
		pcap_capture_stop(context);
	)

}

//global context of MMT-Probe
probe_context_t *get_context(){
	static probe_context_t context;
	return &context;
}

static sig_atomic_t main_processing_signal = 0;
/**
 * This signal handler ensures clean exits.
 * Note: calling printf() from a signal handler is not safe since printf() is not async-signal-safe.
 *      Nevertheless, MMT-Probe will exit at the end of executing signal_handler(), thus we do not need
 *      to care about the restore point of signal_handler.
 */
void signal_handler(int type) {
	//remember signal type in order to restart its process
	main_processing_signal = type;

	probe_context_t *context = get_context();
	if(  context->is_exiting ){
		log_write(LOG_ERR, "Received signal %d while processing other one. Exit immediately.", type );
		fflush( stdout );
		EXIT_NORMALLY();
	}

	switch( type ){
	case SIGINT:
		log_write(LOG_INFO, "Received SIGINT. Main processing process is releasing resource ...");
		context->is_exiting = true;

		_stop_modules( context );
		break;

		//segmentation fault
	case SIGSEGV:
		log_write(LOG_ERR, "Segv signal received!");
		log_execution_trace(); //this function uses non signal-safety functions

		//Auto restart when segmentation fault
		//restart only if exec in online mode
		if( context->config->input->input_mode == OFFLINE_ANALYSIS )
			EXIT_NORMALLY();
		else
			EXIT_TOBE_RESTARTED();
		break;

		//abort signal may be generated by calling abort() function.
		//In the code, this function is called when some parameters are not well configured or not enough memory.
		//In such a case, we need to exit normally MMT-Probe to give control to user to update the parameters
	case SIGABRT:
		log_write(LOG_ERR, "Abort signal received! Cleaning up before exiting!");
		EXIT_NORMALLY();
		break;
	case SIGRES:
		log_write(LOG_ERR, "Restart signal received! Cleaning up before restarting!");
		_stop_modules( context );
	}
}

//need to clean resource before exiting each process
static void _clean_resource(){
	probe_context_t *context = get_context();
	IF_ENABLE_DYNAMIC_CONFIG(
		if( context->config->dynamic_conf->is_enable )
			dynamic_conf_release();
	)
	conf_release( context->config );
	log_close();
}

#ifdef STATIC_LINK
//this function is implemented inside libmmt_tcpip.a
extern void init_tcpip_plugin();

static inline void _load_tcp_plugin(){
	//check if ip proto has been loaded?
	//This can happen when MMT-Probe is compiled using STATIC_LINK param
	//  but we still have libmmt_tcpip.so in ./plugins/ or /opt/mmt/plugins folders.
	//In such a case,  the libmmt_tcpi.so will be loaded by init_extraction function.
	//So we do not need to load the internal library that has been embedded inside probe by static link.
	//In other words, we do not need to call init_tcpip_plugin function as it will
	//   cause errors when the library is loaded doubly.
	const char *name = get_protocol_name_by_id( PROTO_IP );
	if( name == NULL ){
		init_tcpip_plugin();
		log_write( LOG_INFO, "Use internal mmt_tcpip that has been embedded inside MMT-Probe");
	}else{
		log_write( LOG_INFO, "Use external mmt_tcpip that has been packaged inside libmmt_tcpip.so");
	}
}
#endif

static struct {
	uint32_t type;
	uint32_t offset;
} stack = {1, 0}; //1: Ethernet, 0: no offset => protocol Ethernet is started immediately at the first byte

static classified_proto_t _stack_classification(ipacket_t * ipacket) {
	classified_proto_t retval;
	retval.offset   = stack.offset;
	retval.proto_id = stack.type;
	retval.status   = Classified;
	return retval;
}

bool _init_protocol_stack(uint32_t stack_type, uint32_t stack_offset ){
	switch( stack_type ){
	//these stack are already registered in DPI
	case 1:   //Ethernet
	case 624: //Linux cooked capture
	case 800: //ieee802154
		//Use the function that is registered in DPI
		// => the function "_stack_classification" will no be called
		return true;
	default:
		//for the other stack, we need to register it to DPI
		//We use protocol ID as the stack number
		stack.type   = stack_type;
		stack.offset = stack_offset;
		return register_protocol_stack( stack_type, "Dynamic-Stack", _stack_classification);
	}
}


/**
 * This is the main processing process of MMT-Probe.
 * Every packets processing are done here.
 * argc and argv are the ones from main()
 * @return
 */
static int _main_processing( int argc, char** argv ){
	//must not handle SIGUSR1 as it is used by mmt_bus
	signal(SIGINT,  signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGRES,  signal_handler);

	int ret = 0;

	probe_context_t *context = get_context();

#ifdef DPDK_MODULE
	char *dpdk_argv[ 100 ];
	int dpdk_argc = string_split( context->config->input->dpdk_options, " ", &dpdk_argv[1], 100-1 );

	//the first parameter is normally program name
	dpdk_argv[0] = LOG_IDENT;
	dpdk_argc   += 1;

	ret = rte_eal_init( dpdk_argc, dpdk_argv );
	if (ret < 0)
		rte_exit_failure( "Error while EAL initialization" );
#endif

	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_open( context->config->reports.security->excluded_rules );
	)

	log_write( LOG_INFO, "MMT-Probe v%s is running on pid %d",
			get_version(),
			getpid() );
	log_write( LOG_INFO, "Modules: " MODULES_LIST );

	//when libmmt_tcpip is statically linked into mmt-probe,
	// we need to fire its bootstrap function to initialize its protocol list
	//(the function is fired automatically when the lib is dynamically loaded)
#ifdef STATIC_LINK
	_load_tcp_plugin();
#endif

	log_write( LOG_INFO, "MMT-DPI %s", mmt_version() );

	//a statistic output
	const uint16_t output_id = 0;
	context->output = output_alloc_init( output_id, &context->config->outputs, context->config->probe_id, context->config->input->input_source, true );

	if( !_init_protocol_stack( context->config->stack_type, context->config->stack_offset )  ){
		log_write( LOG_ERR, "Cannot initialize stack-type=%d! Exiting!", context->config->stack_type );
		return EXIT_FAILURE;
	}

	//other stubs, such as, system usage report
	routine_t *routine = routine_create_and_start( context );

#ifdef DPDK_MODULE
	dpdk_capture_start( context );
#else
	pcap_capture_start( context );
#endif

	IF_ENABLE_SECURITY(
		if( context->config->reports.security != NULL && context->config->reports.security->is_enable )
			security_close();
	)

	routine_stop_and_release( routine );
	//we free the output here only in SMP mode
	// because in non-SMP mode, this output is used also by a worker
	// the worker will free the output once MMT-Probe terminated
	//=> avoid double free
	if( IS_SMP_MODE(context) )
		output_release( context->output );

	//depending on signal received, exit using different value to notify the monitor process
	switch( main_processing_signal ){
	case SIGINT:
		EXIT_NORMALLY();
		break;
	case SIGRES:
		EXIT_TOBE_RESTARTED();
		break;
	}

	return EXIT_SUCCESS;
}


/**
 * this function will create 2 children processes:
 *  - processing process: performs main jobs realising by _main_processing
 *  - control process: receives control commands via UNIX domain socket and broadcast the commands to
 *  the 2 other processes (parent - or the monitor process, and the processing process)
 * The parent process - or the monitor process - monitors its children to recreate them if need, e.g., when they was crashed.
 * The parent can also stop or start the processing process depending on command received from the control process.
 * @param argc
 * @param argv
 * @return
 */

//special process id (value of pid_t)
#define PID_NEED_TO_CREATE 0
#define PID_NEED_TO_STOP  -1
#define ANY_CHILD_PROCESS -1

static void _create_sub_processes( int argc, char** argv ){
	pid_t child_pid;
	pid_t children_pids[ 2 ] = {PID_NEED_TO_CREATE, PID_NEED_TO_CREATE};
	int nb_children_processes = 1; //by default, only one sub-process for the main processing
	int  status, i;

	probe_context_t *context = get_context();

	IF_ENABLE_DYNAMIC_CONFIG(
			if( context->config->dynamic_conf->is_enable ){
				//take into account control process
				nb_children_processes = 2;
				dynamic_conf_alloc_and_init( & children_pids[0] );
			}
	)

	//an infinity loop to monitor the children processes: restart when it has been crashed
	while( true ){

		//1. create a child process for main processing
		if( children_pids[ 0 ] == PID_NEED_TO_CREATE ){
			//duplicate the current process into 2 different processes
			child_pid = fork();

			if( child_pid < 0 ) {
				ABORT( "Fork error: %s", strerror(errno) );
				exit( EXIT_FAILURE );
			}

			if (child_pid == 0) {
				//we are in child process
				log_write( LOG_INFO, "Create a new sub-process %d for main processing", getpid() );

				IF_ENABLE_DYNAMIC_CONFIG(
					if( context->config->dynamic_conf->is_enable )
						dynamic_conf_agency_start() ;
				)

				_main_processing( argc, argv );

				//clean resource
				_clean_resource();
				exit( EXIT_SUCCESS );
			}

			//in parent process
			children_pids[0] = child_pid;
		}

		//2. create a control process for dynamic configuration
		//this process receives external commands via an UNIX domain socket, then send them to the main processing
#ifdef DYNAMIC_CONFIG_MODULE
		if( context->config->dynamic_conf->is_enable && children_pids[ 1 ] == PID_NEED_TO_CREATE ){
			children_pids[1] = dynamcic_conf_create_new_process_to_receive_command( context->config->dynamic_conf->descriptor, _clean_resource );
		}
#endif

		//3. check if a child has terminated
		//parent is not blocked here since we use WNOHANG
		child_pid = waitpid( ANY_CHILD_PROCESS, &status, WNOHANG );

		if( child_pid == -1 )
			ABORT( "Cannot wait for children: %s", strerror( errno ) );

		//no child changes its state
		if( child_pid == 0 )
			goto _next_iteration;

		log_write( LOG_INFO, "Child process %d return code: %d", child_pid, status );

		//4. parent will check to re-create a new instance of a child if it was killed by segmentation fault
		//the child it exist normally, then lets keep it dead
		if ( WIFEXITED( status) && WEXITSTATUS( status ) == EXIT_SUCCESS )
			status = PID_NEED_TO_STOP;
		else //mark to re-create this child
			status = PID_NEED_TO_CREATE;

		//update status of the child
		for( i=0; i<nb_children_processes; i++ )
			if( child_pid == children_pids[i] ){
				children_pids[i] = status;
				break;
			}

		//check number of children they need to stop
		int nb_children_need_to_stop = 0;
		for( i=0; i<nb_children_processes; i++ )
			if( children_pids[i] ==  PID_NEED_TO_STOP)
				nb_children_need_to_stop ++;

		//5. all children exited normally => the father needs to be exited also
		if( nb_children_need_to_stop == nb_children_processes )
			break;

		_next_iteration:
		IF_ENABLE_DYNAMIC_CONFIG(
			//we need to check periodically if there are new commands that have been broadcasted by the control process
			if( context->config->dynamic_conf->is_enable )
				dynamic_conf_check();
		)

		//avoid exhaustively resource when having dense consecutive restarts: restart, crash, restart, crash, ...
		sleep( 1 );
	}

}


int main( int argc, char** argv ){

	//ignore Ctrl+C in main process
	signal( SIGINT, SIG_IGN );
	log_open();

	IF_ENABLE_DEBUG(
		log_write( LOG_WARNING, "Must not run debug mode in production environment" );
	)

	//DPI initialization
	if( !init_extraction() ) { // general ixE initialization
		log_write( LOG_ERR, "MMT Extraction engine initialization error! Exiting!");
		return EXIT_FAILURE;
	}

	//read configuration from file and execution parameters
	probe_context_t *context = get_context();
	//initialize: fill zero
	memset( context, 0, sizeof( probe_context_t) );

	//MMT-Probe is running.
	//This variable is false only when user want to stop MMT-Probe by sending SIGINT signal, e.g., pressing Ctrl+C
	context->is_exiting = false;
	context->config = _parse_options(argc, argv);
	if( conf_validate( context->config ) > 0 )
		return EXIT_FAILURE;

#ifdef DEBUG_MODE
	_main_processing( argc, argv );
#else
	//if MMT-Probe is used to check pcap offline
	// => no need to created sub processes
	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		_main_processing( argc, argv );
	}else{
		_create_sub_processes( argc, argv );
	}
#endif

	//end
	close_extraction();

	log_write(LOG_INFO, "Exit normally MMT-Probe");
	_clean_resource();

	printf("Bye\n");
	return EXIT_SUCCESS;
}
