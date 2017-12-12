/*
 * main.c
 *
 *  Created on: Dec 12, 2017
 *      Author: nhnghia
 */

#include <stdio.h>
#include <string.h>

#include "lib/configure.h"
#include "lib/version.h"
//#include "mmt_dpi.h"


#define DEFAULT_CONFIG_FILE "/opt/mmt/probe/mmt-probe.conf"

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-v               : Versions.\n");
	fprintf(stderr, "\t-c <config file> : Gives the path to the config file (default: %s).\n", DEFAULT_CONFIG_FILE);
	fprintf(stderr, "\t-t <trace file>  : Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-o <output file> : Gives the output file name. \n");
	fprintf(stderr, "\t-R <output dir>  : Gives the security output folder name. \n");
	fprintf(stderr, "\t-p <period>      : Gives the period in seconds for statistics reporting. \n");
	fprintf(stderr, "\t-s <0|1>         : Enables or disables protocol statistics reporting. \n");
	fprintf(stderr, "\t-f <0|1>         : Enables or disables flows reporting. \n");
	fprintf(stderr, "\t-n <probe number>: Unique probe id number. \n");
	//fprintf(stderr, "\t-c <number of cores>: see dpdk manual to assign number of cores (2 * thread_nb + 2) \n");
	fprintf(stderr, "\t-h               : Prints this help.\n");
	exit( 0 );
}

static inline void _override_string_conf( char **conf, const char*new_val ){
	free( *conf );
	*conf = strdup( new_val );
}

extern char *optarg;
static inline probe_conf_t* _parse_options( int argc, char ** argv ) {
	int opt, optcount = 0;
	int val;

	const char *config_file = DEFAULT_CONFIG_FILE;
	probe_conf_t *conf = NULL;

	while ((opt = getopt(argc, argv, "c:hv")) != EOF) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'v':
			printf( "Versions: \n Probe v%s (MMT-DPI v%s, Security v0.9b)\n",
					get_version(),
					"mmt_version()");
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	conf = load_configuration_from_file( config_file );

	//override some options inside the configuration
	while ((opt = getopt(argc, argv, "t:i:o:R:P:p:s:n:f:")) != EOF) {
		switch (opt) {
		//trace file
		case 't':
			_override_string_conf( &conf->input->input_source, optarg );
			break;
		//input interface
		case 'i':
			_override_string_conf( &conf->input->input_source, optarg );
			break;
		//stat period
		case 'p':
			conf->stat_period = atoi(optarg);
			break;
		//enable/disable no-session protocol statistic
		case 's':
			conf->is_enable_proto_no_session_stat = (atoi(optarg) == 1);
			break;
		//probe id
		case 'n':
			conf->probe_id = atoi(optarg);
			break;
		}
	}

	return conf;
}

int main( int argc, char** argv ){
	probe_conf_t *conf = _parse_options(argc, argv);

	release_probe_configuration(conf);
}
