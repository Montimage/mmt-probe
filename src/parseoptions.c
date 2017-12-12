#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> //usleep, sleep

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "processing.h"
#include "confuse.h"

#include "lib/security.h"

//normally GIT_VERSION must be given by Makefile
#ifndef GIT_VERSION
	#define GIT_VERSION ""
#endif
void dynamic_conf (struct mmt_probe_struct * mmt_probe);
void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-v               : Lists versions.\n");
	fprintf(stderr, "\t-c <config file> : Gives the path to the config file (default: /opt/mmt/probe/mmt-probe.conf).\n");
	fprintf(stderr, "\t-t <trace file>  : Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-o <output file> : Gives the output file name. \n");
	fprintf(stderr, "\t-R <output dir>  : Gives the security output folder name. \n");
	fprintf(stderr, "\t-P <properties file> : Gives the security input properties file name. \n");
	fprintf(stderr, "\t-p <period>      : Gives the period in seconds for statistics reporting. \n");
	fprintf(stderr, "\t-s <0|1>         : Enables or disables protocol statistics reporting. \n");
	fprintf(stderr, "\t-f <0|1>         : Enables or disables flows reporting. \n");
	fprintf(stderr, "\t-n <probe number>: Unique probe id number. \n");
	//fprintf(stderr, "\t-c <number of cores>: see dpdk manual to assign number of cores (2 * thread_nb + 2) \n");
	fprintf(stderr, "\t-h               : Prints this help.\n");
	exit(1);
}

/* parse values for the input-mode option */
int conf_parse_input_mode(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) {
	if (strcmp(value, "online") == 0)
		*(int *) result = ONLINE_ANALYSIS;
	else if (strcmp(value, "offline") == 0)
		*(int *) result = OFFLINE_ANALYSIS;
	else {
		cfg_error(cfg, "invalid value for option '%s': %s", cfg_opt_name(opt), value);
		return -1;
	}
	return 0;
}

cfg_t * parse_conf(const char *filename) {
	cfg_opt_t micro_flows_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_INT("include-packet-count", 10, CFGF_NONE),
			CFG_INT("include-byte-count", 5, CFGF_NONE),
			CFG_INT("report-packet-count", 10000, CFGF_NONE),
			CFG_INT("report-byte-count", 5000, CFGF_NONE),
			CFG_INT("report-flow-count", 1000, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t session_timeout_opts[] = {
			CFG_INT("default-session-timeout", 60, CFGF_NONE),
			CFG_INT("long-session-timeout", 600, CFGF_NONE),
			CFG_INT("short-session-timeout", 15, CFGF_NONE),
			CFG_INT("live-session-timeout", 1500, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t redis_output_opts[] = {
			CFG_STR("hostname", "localhost", CFGF_NONE),
			CFG_INT("port", 6379, CFGF_NONE),
			CFG_INT("enabled", 0, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t kafka_output_opts[] = {
			CFG_STR("hostname", "localhost", CFGF_NONE),
			CFG_INT("port", 9092, CFGF_NONE),
			CFG_INT("enabled", 0, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t output_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("data-file", 0, CFGF_NONE),
			CFG_STR("location", 0, CFGF_NONE),
			CFG_INT("retain-files", 0, CFGF_NONE),
			CFG_INT("sampled_report", 0, CFGF_NONE),

			CFG_END()
	};

	cfg_opt_t security1_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("results-dir", 0, CFGF_NONE),
			CFG_STR("properties-file", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t security2_opts[] = {
			CFG_INT("enable",       0, CFGF_NONE),
			CFG_INT("thread-nb",    0, CFGF_NONE),
			CFG_STR("rules-mask",   0, CFGF_NONE),
			CFG_STR("exclude-rules",   0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t cpu_mem_report_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_INT("frequency", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t behaviour_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("location", 0, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t reconstruct_ftp_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("location", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t radius_output_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_INT("include-msg", 0, CFGF_NONE),
			CFG_INT("include-condition", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t data_output_opts[] = {
			CFG_INT("include-user-agent", MMT_USER_AGENT_THRESHOLD, CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t event_report_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("event", "", CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t condition_report_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR("condition", "", CFGF_NONE),
			CFG_STR("location", 0, CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_STR_LIST("handlers", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t socket_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_INT("domain", 0, CFGF_NONE),
			CFG_STR_LIST("port", "{}", CFGF_NONE),
			CFG_STR_LIST("server-address", "{}", CFGF_NONE),
			CFG_STR("socket-descriptor", "", CFGF_NONE),
			CFG_INT("one-socket-server", 1, CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t security_report_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR_LIST("event", "{}", CFGF_NONE),
			CFG_INT("rule-type", 0, CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t security_report_multisession_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_INT("file-output", 0, CFGF_NONE),
			CFG_INT("redis-output", 0, CFGF_NONE),
			CFG_STR_LIST("attributes", "{}", CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};
	cfg_opt_t session_report_opts[] = {
			CFG_INT("enable", 0, CFGF_NONE),
			CFG_STR_LIST("output-channel", "{}", CFGF_NONE),
			CFG_END()
	};

	cfg_opt_t opts[] = {
			CFG_SEC("micro-flows", micro_flows_opts, CFGF_NONE),
			CFG_SEC("session-timeout", session_timeout_opts, CFGF_NONE),
			CFG_SEC("file-output", output_opts, CFGF_NONE),
			CFG_SEC("redis-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("kafka-output", redis_output_opts, CFGF_NONE),
			CFG_SEC("data-output", data_output_opts, CFGF_NONE),
			CFG_SEC("security1", security1_opts, CFGF_NONE),
			CFG_SEC("security2", security2_opts, CFGF_NONE),
			CFG_SEC("cpu-mem-usage", cpu_mem_report_opts, CFGF_NONE),
			CFG_SEC("socket", socket_opts, CFGF_NONE),
			CFG_SEC("behaviour", behaviour_opts, CFGF_NONE),
			CFG_SEC("reconstruct-ftp", reconstruct_ftp_opts, CFGF_NONE),
			CFG_SEC("radius-output", radius_output_opts, CFGF_NONE),
			CFG_INT("stats-period", 5, CFGF_NONE),
			CFG_INT("enable-proto-without-session-stat", 0, CFGF_NONE),
			CFG_INT("enable-IP-fragmentation-report", 0, CFGF_NONE),
			CFG_INT("enable-session-report", 0, CFGF_NONE),
			CFG_INT("file-output-period", 5, CFGF_NONE),
			CFG_INT("thread-nb", 1, CFGF_NONE),
			CFG_INT("thread-queue", 0, CFGF_NONE),
			CFG_INT("thread-data", 0, CFGF_NONE),
			CFG_INT("snap-len", 65535, CFGF_NONE),
			CFG_INT("cache-size-for-reporting", 300000, CFGF_NONE),
			CFG_INT_CB("input-mode", 0, CFGF_NONE, conf_parse_input_mode),
			CFG_STR("input-source", "nosource", CFGF_NONE),
			CFG_INT("probe-id-number", 0, CFGF_NONE),
			CFG_STR("logfile", 0, CFGF_NONE),
			CFG_STR("license_file_path", 0, CFGF_NONE),
			CFG_INT("loglevel", 2, CFGF_NONE),
			CFG_SEC("event_report", event_report_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("condition_report", condition_report_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("security-report", security_report_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_INT("num-of-report-per-msg", 1, CFGF_NONE),
			CFG_SEC("security-report-multisession", security_report_multisession_opts, CFGF_TITLE | CFGF_MULTI),
			CFG_SEC("session-report", session_report_opts, CFGF_TITLE | CFGF_MULTI),

			CFG_END()
	};

	cfg_t *cfg = cfg_init(opts, CFGF_NONE);

	switch (cfg_parse(cfg, filename)) {
	case CFG_FILE_ERROR:
		//fprintf(stderr, "warning: configuration file '%s' could not be read: %s\n", filename, strerror(errno));
		return 0;
	case CFG_SUCCESS:
		break;
	case CFG_PARSE_ERROR:
		return 0;
	}

	return cfg;
}

int condition_parse_dot_proto_attribute(char * inputstring, mmt_condition_attribute_t * protoattr) {
	char **ap, *argv[2];
	int valid = 0;
	/* code from http://www.manpagez.com/man/3/strsep/
	 * You can make it better!
	 */
	for (ap = argv; (*ap = strsep(&inputstring, ".")) != NULL;)	{
		valid ++;
		if (**ap != '\0') {
			if (++ap >= &argv[2] || valid > 2) {
				break;
			}
		}
	}

	if(valid != 2) {
		return 1;
	} else {
		strncpy(protoattr->proto, argv[0], 256);
		strncpy(protoattr->attribute, argv[1], 256);
		return 0;
	}
}

/** transforms "proto.attribute" into mmt_event_attribute_t
 *  Raturns 0 on success, a positive value otherwise
 **/
int parse_dot_proto_attribute(char * inputstring, mmt_event_attribute_t * protoattr) {
	char **ap, *argv[2];
	int valid = 0;
	/* code from http://www.manpagez.com/man/3/strsep/
	 * You can make it better!
	 */
	for (ap = argv; (*ap = strsep(&inputstring, ".")) != NULL;)	{
		valid ++;
		if (**ap != '\0') {
			if (++ap >= &argv[2] || valid > 2) {
				break;
			}
		}
	}

	if(valid != 2) {
		return 1;
	} else {
		strncpy(protoattr->proto, argv[0], 256);
		strncpy(protoattr->attribute, argv[1], 256);
	        return 0;
	}
}

/** transforms "proto.attribute" into mmt_security_attribute_t
 *  Returns 0 on success, a positive value otherwise
 **/
int parse_security_dot_proto_attribute(char * inputstring, mmt_security_attribute_t * protoattr) {
	char **ap, *argv[2];
	int valid = 0;
	/* code from http://www.manpagez.com/man/3/strsep/
	 * You can make it better!
	 */
	for (ap = argv; (*ap = strsep(&inputstring, ".")) != NULL;)	{
		valid ++;
		if (**ap != '\0') {
			if (++ap >= &argv[2] || valid > 2) {
				break;
			}
		}
	}

	if(valid != 2) {
		return 1;
	} else {
		strncpy(protoattr->proto, argv[0], 256);
		strncpy(protoattr->attribute, argv[1], 256);
		//printf("proto =%s,attr=%s \n",protoattr->proto,protoattr->attribute);
		return 0;
	}
}

int parse_condition_attribute(char * inputstring, mmt_condition_attribute_t * conditionattr) {

	if(inputstring != NULL){
		strncpy(conditionattr->condition, inputstring, 256);
		return 0;
	}
	return 1;
}
int parse_location_attribute(char * inputstring, mmt_condition_attribute_t * conditionattr) {

	if(inputstring != NULL){
		strncpy(conditionattr->location, inputstring, 256);
		return 0;
	}
	return 1;
}

int parse_handlers_attribute(char * inputstring, mmt_condition_attribute_t * handlersattr) {
	if(inputstring != NULL){
		strncpy(handlersattr->handler, inputstring, 256);
		return 0;
	}
	return 1;
}

int process_conf_result(cfg_t *cfg, mmt_probe_context_t * mmt_conf) {
	int i = 0, j = 0, k=0;
	cfg_t *event_opts;
	cfg_t *condition_opts;
	cfg_t *security_report_opts;
	cfg_t *security_report_multisession_opts;


	if (cfg) {
		//mmt_conf->enable_proto_stats = 1; //enabled by default
		mmt_conf->enable_proto_without_session_stats = (uint32_t) cfg_getint(cfg, "enable-proto-without-session-stat");
		mmt_conf->enable_IP_fragmentation_report = (uint32_t) cfg_getint(cfg, "enable-IP-fragmentation-report");
		//mmt_conf->enable_flow_stats = 1;  //enabled by default
		mmt_conf->stats_reporting_period = (uint32_t) cfg_getint(cfg, "stats-period");
		mmt_conf->sampled_report_period = (uint32_t) cfg_getint(cfg, "file-output-period");
		mmt_conf->thread_nb = (uint32_t) cfg_getint(cfg, "thread-nb");
		mmt_conf->thread_nb_2_power = get_2_power(mmt_conf->thread_nb);
		//fprintf(stdout, "thread nb is 2^%i\n", mmt_conf->thread_nb_2_power);
		mmt_conf->thread_queue_plen = (uint32_t) cfg_getint(cfg, "thread-queue");
		mmt_conf->thread_queue_blen = (uint32_t) cfg_getint(cfg, "thread-data");
		if (mmt_conf->thread_queue_plen == 0) mmt_conf->thread_queue_plen = 1000; //default value is 1000
		if (mmt_conf->thread_queue_blen == 0) mmt_conf->thread_queue_blen = 0xFFFFFFFF; //No limitation
		mmt_conf->input_mode = (uint32_t) cfg_getint(cfg, "input-mode");
		mmt_conf->report_cache_size_before_flushing = (uint64_t) cfg_getint(cfg, "cache-size-for-reporting");
		if (mmt_conf->report_cache_size_before_flushing  == 0) mmt_conf->report_cache_size_before_flushing  = 300000;

		mmt_conf->requested_snap_len = (uint32_t) cfg_getint(cfg, "snap-len");
		if (mmt_conf->requested_snap_len  == 0) mmt_conf->requested_snap_len  = 65535;

		mmt_conf->nb_of_report_per_msg = (uint32_t) cfg_getint(cfg, "num-of-report-per-msg");
		if (mmt_conf->nb_of_report_per_msg < 1){
			printf("Error: Number of report per msg should be greater than zero in case of security reporting \n");
			exit(0);
		}

		if(mmt_conf->input_mode == 0){
			printf("Error: Specify the input-mode in the configuration file, for example input-mode = \"offline\" or \"online\" \n");
			exit(0);
		}


		if (strcmp((char *) cfg_getstr(cfg, "input-source"),"nosource") != 0){
			strncpy(mmt_conf->input_source, (char *) cfg_getstr(cfg, "input-source"), 256);
		}

		mmt_conf->probe_id_number = (uint32_t) cfg_getint(cfg, "probe-id-number");

		if ((char *) cfg_getstr(cfg, "logfile") == NULL){
			printf("Error: Specify the logfile name  configuration file, for example logfile = \"log.data\"\n");
			exit(0);
		}
		strncpy(mmt_conf->log_file, (char *) cfg_getstr(cfg, "logfile"), 256);

		mmt_conf->log_level = (uint32_t) cfg_getint(cfg, "loglevel");

		if ((char *) cfg_getstr(cfg, "license_file_path") == NULL){
			printf("Error: Specify the license_file_path full path in the configuration file\n");
			exit(0);
		}
		strncpy(mmt_conf->license_location, (char *) cfg_getstr(cfg, "license_file_path"), 256);

		/***************micro flows report ********************/
		if (cfg_size(cfg, "micro-flows")) {
			cfg_t *microflows = cfg_getnsec(cfg, "micro-flows", 0);
			if (microflows->line != 0){
				char output_channel[10];
				mmt_conf->microf_enable = (uint32_t) cfg_getint(microflows, "enable");
				if (mmt_conf->microf_enable == 1){
					mmt_conf->microf_pthreshold = (uint32_t) cfg_getint(microflows, "include-packet-count");
					mmt_conf->microf_bthreshold = (uint32_t) cfg_getint(microflows, "include-byte-count")*1000/*in Bytes*/;
					mmt_conf->microf_report_pthreshold = (uint32_t) cfg_getint(microflows, "report-packet-count");
					mmt_conf->microf_report_bthreshold = (uint32_t) cfg_getint(microflows, "report-byte-count")*1000/*in Bytes*/;
					mmt_conf->microf_report_fthreshold = (uint32_t) cfg_getint(microflows, "report-flow-count");
					j = 0;
					int nb_output_channel = cfg_size(microflows, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(microflows, "output-channel", j),10);
                        if (strncmp(output_channel, "file", 4) == 0) mmt_conf->microf_output_channel[0] = 1;
                        if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->microf_output_channel[1] = 1;
                        if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->microf_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->microf_output_channel[0] = 1;
				}
			}
		}
		/***************micro flows report ********************/

		/***************Session timeout ********************/

		if (cfg_size(cfg, "session-timeout")) {
			cfg_t *session_timeout = cfg_getnsec(cfg, "session-timeout", 0);
			if (session_timeout->line != 0){
				mmt_conf->default_session_timeout = (uint32_t) cfg_getint(session_timeout, "default-session-timeout");
				if (mmt_conf->default_session_timeout == 0)mmt_conf->default_session_timeout = 60;
				mmt_conf->long_session_timeout = (uint32_t) cfg_getint(session_timeout, "long-session-timeout");
				if (mmt_conf->long_session_timeout == 0)mmt_conf->long_session_timeout = 600;
				mmt_conf->short_session_timeout = (uint32_t) cfg_getint(session_timeout, "short-session-timeout");
				if (mmt_conf->short_session_timeout == 0)mmt_conf->short_session_timeout = 15;
				mmt_conf->live_session_timeout = (uint32_t) cfg_getint(session_timeout, "live-session-timeout");
				if (mmt_conf->live_session_timeout == 0)mmt_conf->live_session_timeout = 1500;
			}
		}

		/***************Session timeout ********************/

		/***************Output files ********************/


		if (cfg_size(cfg, "file-output")) {
			cfg_t *output = cfg_getnsec(cfg, "file-output", 0);
			if (output->line != 0){
				mmt_conf->output_to_file_enable = (uint32_t) cfg_getint(output, "enable");
				strncpy(mmt_conf->data_out, (char *) cfg_getstr(output, "data-file"), 256);
				strncpy(mmt_conf->output_location, (char *) cfg_getstr(output, "location"), 256);
				mmt_conf->retain_files = (int) cfg_getint(output, "retain-files");
				mmt_conf->sampled_report = (uint32_t) cfg_getint(output, "sampled_report");
				if (mmt_conf->sampled_report > 1){
					printf("Error: Sample_report inside the output section in the configuration file has a value either 1 or 0, 1 for sampled output and 0 for single output\n");
					exit(0);
				}

				if (mmt_conf->output_to_file_enable == 1){
					if (mmt_conf->retain_files < (mmt_conf->thread_nb + 1) && mmt_conf->retain_files != 0 && mmt_conf->sampled_report == 1){
						printf("Error: Number of retain files inside the output section in the configuration file, should be always greater than (thread_nb + 1) \n");
						exit (0);
					}
				}

			}else{
				printf("Error: Output section missing in the configuration file i.e. specify output_file_name, location, sample_report etc\n");
				exit(0);
			}
		}
		/***************Output files ********************/

		/***************low bandwidth security report ********************/

		if (cfg_size(cfg, "security1")) {
			cfg_t *security = cfg_getnsec(cfg, "security1", 0);
			if (security->line != 0){
				char output_channel[10];
				mmt_conf->security_enable = (uint32_t) cfg_getint(security, "enable");
				if (mmt_conf->security_enable == 1){
					strncpy(mmt_conf->dir_out, (char *) cfg_getstr(security, "results-dir"), 256);
					strncpy(mmt_conf->properties_file, (char *) cfg_getstr(security, "properties-file"), 256);
					j = 0;
					int nb_output_channel = cfg_size(security, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(security, "output-channel", j),10);
                        if (strncmp(output_channel, "file", 4) == 0) mmt_conf->security1_output_channel[0] = 1;
                        if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->security1_output_channel[1] = 1;
                        if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->security1_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->security1_output_channel[0] = 1;
				}
			}
		}
		/***************low bandwidth security report ********************/

		/***************high bandwidth security report ********************/
		if (cfg_size(cfg, "security2")) {
			cfg_t *security = cfg_getnsec(cfg, "security2", 0);
			if (security->line != 0){
				char output_channel[10];
				mmt_conf->security2_enable        = (cfg_getint(security, "enable") != 0);
				if (mmt_conf->security2_enable){
					mmt_conf->security2_threads_count = (uint16_t) cfg_getint(security, "thread-nb");
					strncpy(mmt_conf->security2_rules_mask, cfg_getstr(security, "rules-mask"), sizeof( mmt_conf->security2_rules_mask ) - 1 );
					strncpy(mmt_conf->security2_excluded_rules, cfg_getstr(security, "exclude-rules"), sizeof( mmt_conf->security2_excluded_rules ) - 1 );
					j = 0;
					int nb_output_channel = cfg_size(security, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(security, "output-channel", j),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->security2_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->security2_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->security2_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->security2_output_channel[0] = 1;
				}
			}
		}
		/***************high bandwidth security report ********************/


		/***************session report ********************/
		if (cfg_size(cfg, "session-report")) {
			cfg_t *session = cfg_getnsec(cfg, "session-report", 0);
			if (session->line != 0){
				char output_channel[10];
				mmt_conf->enable_session_report = (uint8_t) cfg_getint(session, "enable");
				if (mmt_conf->enable_session_report){
					j = 0;
					int nb_output_channel = cfg_size(session, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(session, "output-channel", j),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->session_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->session_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->session_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->session_output_channel[0] = 1;
				}
			}
		}
		/***************session report ********************/


		/***************CPU memory usage ********************/
		if (cfg_size(cfg, "cpu-mem-usage")) {
			cfg_t *cpu_mem_usage = cfg_getnsec(cfg, "cpu-mem-usage", 0);
			if (cpu_mem_usage->line != 0){
				char output_channel[10];
				mmt_conf->cpu_mem_usage_enabled = (uint8_t) cfg_getint(cpu_mem_usage, "enable");
				if (mmt_conf->cpu_mem_usage_enabled == 1){
					//mmt_conf->cpu_mem_output_channel = strncmp(output_channel,"file",4) == 0 ? 1: strncmp(output_channel,"redis",5) == 0
						//	? 2 : strncmp(output_channel,"kafka",5) == 0 ? 3 : 1;
					mmt_conf->cpu_reports = malloc (sizeof (mmt_cpu_perf_t));
					if (mmt_conf->cpu_reports != NULL){
						mmt_conf->cpu_reports->cpu_mem_usage_rep_freq = (uint8_t) cfg_getint(cpu_mem_usage, "frequency");
						mmt_conf->cpu_reports->cpu_usage_avg = 0;
						mmt_conf->cpu_reports->mem_usage_avg = 0;

					}
					j = 0;
					int nb_output_channel = cfg_size(cpu_mem_usage, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(cpu_mem_usage, "output-channel", j),10);
	                    if (strncmp(output_channel, "file", 4) == 0) mmt_conf->cpu_mem_output_channel[0] = 1;
	                    if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->cpu_mem_output_channel[1] = 1;
	                    if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->cpu_mem_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->cpu_mem_output_channel[0] = 1;
				}
			}
		}
		/*************** CPU memory usage ********************/

		/*************** Behaviour  ********************/

		if (cfg_size(cfg, "behaviour")) {
			cfg_t *behaviour = cfg_getnsec(cfg, "behaviour", 0);
			if (behaviour->line != 0){
				mmt_conf->behaviour_enable = (uint32_t) cfg_getint(behaviour, "enable");
				strncpy(mmt_conf->behaviour_output_location, (char *) cfg_getstr(behaviour, "location"), 256);
				if(strcmp(mmt_conf->output_location,mmt_conf->behaviour_output_location)==0){
					printf("Error: The directory for the main output and the behaviour output cannot be same, please specify different directory location.\n");
					exit(0);
				}
			}
		}

		/*************** Behaviour  ********************/

		/*************** reconstruct-ftp  ********************/

		if (cfg_size(cfg, "reconstruct-ftp")) {
			cfg_t *reconstruct_ftp = cfg_getnsec(cfg, "reconstruct-ftp", 0);
			if (reconstruct_ftp->line != 0){
				mmt_conf->ftp_reconstruct_enable = (uint32_t) cfg_getint(reconstruct_ftp, "enable");
				if (mmt_conf->ftp_reconstruct_enable == 1){
					char output_channel[10];
					strncpy(mmt_conf->ftp_reconstruct_output_location, (char *) cfg_getstr(reconstruct_ftp, "location"), 256);
					j = 0;
					int nb_output_channel = cfg_size(reconstruct_ftp, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(reconstruct_ftp, "output-channel", j),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->ftp_reconstruct_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->ftp_reconstruct_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->ftp_reconstruct_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->ftp_reconstruct_output_channel[0] = 1;
				}
			}
		}
			/*************** reconstruct-ftp  ********************/

		/*************** redis  ********************/

		if (cfg_size(cfg, "redis-output")) {
			cfg_t *redis_output = cfg_getnsec(cfg, "redis-output", 0);
			if (redis_output->line != 0){
				char hostname[256 + 1];
				int port = (uint32_t) cfg_getint(redis_output, "port");
				mmt_conf->redis_enable = (uint32_t) cfg_getint(redis_output, "enabled");
				strncpy(hostname, (char *) cfg_getstr(redis_output, "hostname"), 256);
				if (mmt_conf->redis_enable) {
					init_redis(hostname, port);
				}
			}
		}
		/*************** redis  ********************/

		/*************** kafka  ********************/

		if (cfg_size(cfg, "kafka-output")) {
			cfg_t *kafka_output = cfg_getnsec(cfg, "kafka-output", 0);
			if (kafka_output->line != 0){
				char hostname[256 + 1];
				mmt_conf->kafka_enable = (uint32_t) cfg_getint(kafka_output, "enabled");
				if (mmt_conf->kafka_enable == 1){
					int port = (uint32_t) cfg_getint(kafka_output, "port");
					strncpy(hostname, (char *) cfg_getstr(kafka_output, "hostname"), 256);
					if (mmt_conf->kafka_enable) {
						init_kafka(hostname, port);
					}
				}
			}
		}
		/*************** kafka  ********************/


		/*************** Radius  ********************/

		if (cfg_size(cfg, "radius-output")) {
			cfg_t *routput = cfg_getnsec(cfg, "radius-output", 0);
			if (routput->line != 0){
				char output_channel[10];
				mmt_conf->radius_enable = (uint32_t) cfg_getint(routput, "enable");
				if (mmt_conf->radius_enable){
					if (cfg_getint(routput, "include-msg") == MMT_RADIUS_REPORT_ALL) {
						mmt_conf->radius_starategy = MMT_RADIUS_REPORT_ALL;
					} else {
						mmt_conf->radius_starategy = MMT_RADIUS_REPORT_MSG;
						mmt_conf->radius_message_id = (uint32_t) cfg_getint(routput, "include-msg");
					}
					mmt_conf->radius_condition_id = (uint32_t) cfg_getint(routput, "include-condition");
					j = 0;
					int nb_output_channel = cfg_size(routput, "output-channel");
					for(j = 0; j < nb_output_channel; j++) {
						strncpy(output_channel, (char *) cfg_getnstr(routput, "output-channel", j),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->radius_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->radius_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->radius_output_channel[2] = 1;
					}
					if (nb_output_channel == 0)mmt_conf->radius_output_channel[0] = 1;
				}
			}
		}
		/*************** Radius  ********************/

		/*************** user-agent  ********************/

		if (cfg_size(cfg, "data-output")) {
			cfg_t *doutput = cfg_getnsec(cfg, "data-output", 0);
			if (doutput->line != 0){
				mmt_conf->user_agent_parsing_threshold = (uint32_t) cfg_getint(doutput, "include-user-agent")*1000;
			}
		}
		/*************** user-agent  ********************/


		/****************************socket*********************/

		/*	int nb_port_address =0;
		int nb_server_address = 0;
		if (cfg_size(cfg, "socket")) {
			cfg_t *socket = cfg_getnsec(cfg, "socket", 0);
			int len=0;
			if (socket->line != 0){
				mmt_conf->socket_enable = (uint32_t) cfg_getint(socket, "enable");
				if (mmt_conf->socket_enable ==1 ){
					//mmt_conf->socket_domain = (uint8_t) cfg_getint(socket, "domain");
					nb_port_address = cfg_size(socket, "port");
					nb_server_address = cfg_size(socket, "server-address");
					//mmt_conf->portnb = (uint32_t) cfg_getint(socket, "port");
					mmt_conf->server_ip_nb = nb_server_address;
					mmt_conf->server_port_nb = nb_port_address;
						if(mmt_conf->server_ip_nb == mmt_conf->server_port_nb) {
							mmt_conf->server_adresses = calloc(sizeof(ip_port_t), nb_server_address);
							for(j = 0; j < nb_server_address; j++) {
								strncpy(mmt_conf->server_adresses[j].server_ip_address, (char *) cfg_getnstr(socket, "server-address", j), 18);
								mmt_conf->server_adresses[j].server_portnb = malloc(sizeof(uint32_t)*1);
								mmt_conf->server_adresses[j].server_portnb[0] = atoi(cfg_getnstr(socket, "port", j));
							}
						}else{
							printf("Error: Number of port_nb should be equal to number of server-address i.e port number not assigned in config file section socket\n");
							exit(0);
						}
				}
			}
		}*/

		int nb_port_address = 0;
		int nb_server_address = 0;
		if (cfg_size(cfg, "socket")) {
			cfg_t *socket = cfg_getnsec(cfg, "socket", 0);
			int len=0;
			if (socket->line != 0){
				mmt_conf->socket_enable = (uint32_t) cfg_getint(socket, "enable");
				mmt_conf->socket_domain = (uint8_t) cfg_getint(socket, "domain");
				if (mmt_conf->socket_enable == 1 ){
					nb_port_address = cfg_size(socket, "port");
					mmt_conf->one_socket_server = (uint8_t) cfg_getint(socket, "one-socket-server");
					if(nb_port_address > 0) {
						if (nb_port_address != mmt_conf->thread_nb && mmt_conf->one_socket_server < 1){
							printf("Error: Number of port address should be equal to thread number\n");
							exit(0);
						}
						/*						mmt_conf->port_address = malloc(sizeof(int)*nb_port_address);
								for(i = 0; i < nb_port_address; i++) {
									mmt_conf->port_address[i] = atoi(cfg_getnstr(socket, "port", i));
								}*/
					}
					nb_server_address = cfg_size(socket, "server-address");
					mmt_conf->server_ip_nb = nb_server_address;
					mmt_conf->server_port_nb = nb_port_address;
					if (mmt_conf->one_socket_server == 1){
						mmt_conf->server_adresses = calloc(sizeof(ip_port_t), nb_server_address);
						for(j = 0; j < nb_server_address; j++) {
							strncpy(mmt_conf->server_adresses[j].server_ip_address, (char *) cfg_getnstr(socket, "server-address", j),18);
							mmt_conf->server_adresses[j].server_portnb = malloc(sizeof(uint32_t)*1);
							mmt_conf->server_adresses[j].server_portnb[0] = atoi(cfg_getnstr(socket, "port", 0));
						}
					}else if (mmt_conf->one_socket_server == 0){
						if(mmt_conf->thread_nb == mmt_conf->server_port_nb) {
							mmt_conf->server_adresses = calloc(sizeof(ip_port_t), nb_server_address);

							for(j = 0; j < nb_server_address; j++) {
								strncpy(mmt_conf->server_adresses[j].server_ip_address, (char *) cfg_getnstr(socket, "server-address", j),18);
								mmt_conf->server_adresses[j].server_portnb = malloc(sizeof(uint32_t)*mmt_conf->server_port_nb);
								for(i = 0; i < nb_port_address; i++) {
									mmt_conf->server_adresses[j].server_portnb[i] = atoi(cfg_getnstr(socket, "port", i));
								}
							}
						}else{
							printf("Error: Number of port_nb should be equal to number of threads\n");

						}
					}
					strncpy(mmt_conf->unix_socket_descriptor, (char *) cfg_getstr(socket, "socket-descriptor"), 256);
				}
			}
		}

		/****************************socket*********************/

		/*****************Security report*********************/

		int security_reports_nb = cfg_size(cfg, "security-report");
		int security_attributes_nb = 0;
		int security_event_nb = 0;
		mmt_conf->security_reports = NULL;
		mmt_security_report_t * temp_sr;
		mmt_conf->security_reports_nb = security_reports_nb;
		i = 0, j = 0;

		if (security_reports_nb > 0) {
			mmt_conf->security_reports = calloc(sizeof(mmt_security_report_t), security_reports_nb);
			for(j = 0; j < security_reports_nb; j++) {
				security_report_opts = cfg_getnsec(cfg, "security-report", j);
				temp_sr = &mmt_conf->security_reports[j];
				temp_sr->enable = (uint32_t) cfg_getint(security_report_opts, "enable");

				if (temp_sr->enable == 1){

					mmt_conf->enable_security_report = 1;
					/*security_event_nb = cfg_size(security_report_opts, "event");
					temp_sr->event_name_nb = security_event_nb;
					temp_sr->rule_type = 	(uint8_t) cfg_getint(security_report_opts, "rule-type");

					if(security_event_nb > 0) {
						//temp_sr->event= calloc(sizeof(mmt_security_attribute_t),security_attributes_nb);
						temp_sr->event_name = malloc(security_event_nb * sizeof (char *) + 1);
						for (k = 0; k < security_event_nb; k++){
							temp_sr->event_name[k] = malloc(sizeof (char)*20);
							strcpy(temp_sr->event_name[k], (char *) cfg_getnstr(security_report_opts, "event", k));
							int len = strlen(temp_sr->event_name[k]);
							temp_sr->event_name[k][len] = '\0';
							//printf("name=%s\n",temp_sr->event_name[k]);

						}
					}*/

					security_attributes_nb = cfg_size(security_report_opts, "attributes");
					temp_sr->attributes_nb = security_attributes_nb;
					if(security_attributes_nb > 0) {
						temp_sr->attributes = calloc(sizeof(mmt_security_attribute_t), security_attributes_nb);
						for(i = 0; i < security_attributes_nb; i++) {
							mmt_conf->total_security_attribute_nb += 1;
							if (parse_security_dot_proto_attribute(cfg_getnstr(security_report_opts, "attributes", i), &temp_sr->attributes[i])) {
								fprintf(stderr, "Error: invalid security_report attribute value '%s'\n", (char *) cfg_getnstr(security_report_opts, "attributes", i));
								exit(0);
							}
						}
					}
				}
			}
		}

		/*****************Security report*********************/

		/******* report multisession **************/

		int security_reports_multisession_nb = cfg_size(cfg, "security-report-multisession");
		int security_attributes_multisession_nb = 0;
		mmt_conf->security_reports_multisession = NULL;
		mmt_security_report_multisession_t * temp_msr;
		mmt_conf->security_reports_multisession_nb = security_reports_multisession_nb;
		i = 0, j = 0, k=0;

		if (security_reports_multisession_nb > 0) {
			mmt_conf->security_reports_multisession = calloc(sizeof(mmt_security_report_multisession_t), security_reports_multisession_nb);
			for(j = 0; j < security_reports_multisession_nb; j++) {
				security_report_multisession_opts = cfg_getnsec(cfg, "security-report-multisession", j);
				temp_msr = &mmt_conf->security_reports_multisession[j];
				temp_msr->enable = (uint32_t) cfg_getint(security_report_multisession_opts, "enable");

				if (temp_msr->enable == 1){
					char output_channel[10];
					int nb_output_channel = cfg_size(security_report_multisession_opts, "output-channel");
					for(k = 0; k < nb_output_channel; k++) {
						strncpy(output_channel, (char *) cfg_getnstr(security_report_multisession_opts, "output-channel", k),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->multisession_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->multisession_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->multisession_output_channel[2] = 1;
					}
					if (nb_output_channel == 0) mmt_conf->multisession_output_channel[0] = 1;//default
					mmt_conf->enable_security_report_multisession = 1;
					security_attributes_multisession_nb = cfg_size(security_report_multisession_opts, "attributes");
					temp_msr->attributes_nb = security_attributes_multisession_nb;
					if(security_attributes_multisession_nb > 0) {
						temp_msr->attributes = calloc(sizeof(mmt_security_attribute_t), security_attributes_multisession_nb);
						for(i = 0; i < security_attributes_multisession_nb; i++) {
							mmt_conf->total_security_multisession_attribute_nb += 1;
							if (parse_security_dot_proto_attribute(cfg_getnstr(security_report_multisession_opts, "attributes", i), &temp_msr->attributes[i])) {
								fprintf(stderr, "Error: invalid security_report_multisession attribute value '%s'\n", (char *) cfg_getnstr(security_report_multisession_opts, "attributes", i));
								exit(0);
							}
						}
					}
				}
			}
		}

		/******* report multisession **************/

		/******* Event report **************/

		int event_reports_nb = cfg_size(cfg, "event_report");
		int event_attributes_nb = 0;
		mmt_conf->event_reports = NULL;
		mmt_event_report_t * temp_er;
		mmt_conf->event_reports_nb = event_reports_nb;
		i=0,j=0, k=0;

		if (event_reports_nb > 0) {
			mmt_conf->event_reports = calloc(sizeof(mmt_event_report_t), event_reports_nb);
			for(j = 0; j < event_reports_nb; j++) {
				event_opts = cfg_getnsec(cfg, "event_report", j);
				//mmt_conf->event_based_reporting_enable = (uint32_t) cfg_getint(event_opts, "enable");
				temp_er = & mmt_conf->event_reports[j];
				temp_er->enable = (uint32_t) cfg_getint(event_opts, "enable");

				if (temp_er->enable == 1){

					char output_channel[10];
					int nb_output_channel = cfg_size(event_opts, "output-channel");
					for(k = 0; k < nb_output_channel; k++) {
						strncpy(output_channel, (char *) cfg_getnstr(event_opts, "output-channel", k),10);
						if (strncmp(output_channel, "file", 4) == 0) mmt_conf->event_output_channel[0] = 1;
						if (strncmp(output_channel, "redis", 5) == 0) mmt_conf->event_output_channel[1] = 1;
						if (strncmp(output_channel, "kafka", 5) == 0) mmt_conf->event_output_channel[2] = 1;
					}
					if (nb_output_channel == 0) mmt_conf->event_output_channel[0] = 1;//default
					temp_er->id = j + 1;
					if (parse_dot_proto_attribute((char *) cfg_getstr(event_opts, "event"), &temp_er->event)) {
						fprintf(stderr, "Error: invalid event_report event value '%s'\n", (char *) cfg_getstr(event_opts, "event"));
						exit(0);
					}
					mmt_conf->event_based_reporting_enable = (uint32_t) cfg_getint(event_opts, "enable");
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

		/******* Event report **************/

		/******* Condition report **************/

		int condition_reports_nb = cfg_size(cfg, "condition_report");
		int condition_attributes_nb = 0;
		int condition_handlers_nb = 0;
		mmt_conf->condition_reports = NULL;
		mmt_condition_report_t * temp_condn;
		mmt_conf->condition_reports_nb = condition_reports_nb;
		i=0,j=0;

		if (condition_reports_nb > 0) {
			mmt_conf->condition_reports = calloc(sizeof(mmt_condition_report_t), condition_reports_nb);
			for(j = 0; j < condition_reports_nb; j++) {
				condition_opts = cfg_getnsec(cfg, "condition_report", j);
				temp_condn = & mmt_conf->condition_reports[j];
				temp_condn->enable = (uint32_t)cfg_getint(condition_opts, "enable");
				if (temp_condn->enable == 1){
					if (parse_condition_attribute((char *) cfg_getstr(condition_opts, "condition"), &temp_condn->condition)) {
						fprintf(stderr, "Error: invalid condition_report condition value '%s'\n", (char *) cfg_getstr(condition_opts, "condition"));
						exit(0);
					}
					mmt_conf->condition_based_reporting_enable = 1;
					char *file_location = (char *) cfg_getstr(condition_opts, "location");
					if(file_location!=NULL){
						strncpy(temp_condn->condition.location, file_location, 256);
					}

					if(strcmp(temp_condn->condition.condition, "FTP") == 0){
						if (temp_condn->enable == 1) mmt_conf->ftp_enable = 1;
						if (temp_condn->enable == 0) mmt_conf->ftp_enable = 0;
					}
					if(strcmp(temp_condn->condition.condition, "WEB") == 0){
						if (temp_condn->enable == 1) mmt_conf->web_enable = 1;
						if (temp_condn->enable == 0) mmt_conf->web_enable = 0;
					}
					if(strcmp(temp_condn->condition.condition, "RTP") == 0){
						if (temp_condn->enable == 1) mmt_conf->rtp_enable = 1;
						if (temp_condn->enable == 0) mmt_conf->rtp_enable = 0;
					}
					if(strcmp(temp_condn->condition.condition, "SSL") == 0){
						if (temp_condn->enable == 1) mmt_conf->ssl_enable = 1;
						if (temp_condn->enable == 0) mmt_conf->ssl_enable = 0;
					}
					if(strcmp(temp_condn->condition.condition, "HTTP-RECONSTRUCT") == 0){
#ifdef HTTP_RECONSTRUCT_MODULE						
						if (temp_condn->enable == 1) {
							strncpy(mmt_conf->HTTP_RECONSTRUCT_MODULE_output_location, temp_condn->condition.location, 256);
							mmt_conf->HTTP_RECONSTRUCT_MODULE_enable = 1;
							// printf("[debug] Enable http reconstruction\n");
						}
						if (temp_condn->enable == 0) mmt_conf->HTTP_RECONSTRUCT_MODULE_enable = 0;
#else						
					temp_condn->enable = 0;	
#endif // End of HTTP_RECONSTRUCT_MODULE
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
		}

		/******* Condition report **************/

		cfg_free(cfg);
	}
	return 1;
}


void parseOptions(int argc, char ** argv, struct mmt_probe_struct * mmt_probe) {
	int opt, optcount = 0;
	char * config_file = "/opt/mmt/probe/mmt-probe.conf";
	char * input = NULL;
	char * output = NULL;
	char * output_dir = NULL;
	char * properties_file = NULL;
	int period = 0;
	int proto_stats = 1;
	int probe_id_number = 0;
	int flow_stats = 1;
	int versions_only = 0;
        if (argc == 1) {
            dynamic_conf(mmt_probe);
            return;
        }


	while ((opt = getopt(argc, argv, "c:t:i:o:R:P:p:s:n:f:hv")) != EOF) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 't':
			optcount++;
			if (optcount > 1) {
				usage(argv[0]);
			}
			input = optarg;
			break;
		case 'i':
			optcount++;
			if (optcount > 1) {
				usage(argv[0]);
			}
			input = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'R':
			output_dir = optarg;
			break;
		case 'P':
			properties_file = optarg;
			break;
		case 'p':
			period = atoi(optarg);
			break;
		case 's':
			proto_stats = atoi(optarg);
			break;
		case 'n':
			probe_id_number = atoi(optarg);
			break;
		case 'f':
			flow_stats = atoi(optarg);
			break;
		case 'v':
			versions_only = 1;


			//fprintf(stderr,"Versions: \n Probe v1.0.0 \n DPI v%s \n Security v0.9b \n Compatible with Operator v1.5 \n",mmt_version());
			fprintf(stderr,"Versions: \n Probe v%s (%s) \n DPI v%s \n Security v0.9b \n Compatible with Operator v1.5 \n",
					VERSION, GIT_VERSION, //these version information are given by Makefile
					mmt_version());

			break;
		case 'h':
		default: usage(argv[0]);
		}
	}

	cfg_t *cfg = parse_conf(config_file);
	if(cfg == NULL) {
		if(versions_only != 1) fprintf(stderr, "Configuration file not found: use -c <config file> or create default file /etc/mmtprobe/mmt.conf\n");
		exit(0);
	}
	process_conf_result(cfg, mmt_probe->mmt_conf);
  
	if (input) {
		strncpy(mmt_probe->mmt_conf->input_source, input, 256);
	}
	else if (strlen(mmt_probe->mmt_conf->input_source) == 0){
		if(versions_only != 1) printf("Error:Specify the input-source in the configuration file, for example, for offline analysis: trace file name and for online analysis: network interface\n");
		exit(0);
	}

	if(output) {
		strncpy(mmt_probe->mmt_conf->data_out, output, 256);
	}

	if(output_dir) {
		strncpy(mmt_probe->mmt_conf->dir_out, output_dir, 256);
	}

	if(properties_file) {
		strncpy(mmt_probe->mmt_conf->properties_file, properties_file, 256);
	}

	if(period) {
		mmt_probe->mmt_conf->stats_reporting_period = period;
	}

	if(!proto_stats) {
		mmt_probe->mmt_conf->enable_proto_without_session_stats = 0;
	}

	if(probe_id_number) {
		mmt_probe->mmt_conf->probe_id_number = probe_id_number;
	}

	if(!flow_stats) {
		mmt_probe->mmt_conf->enable_session_report = 0;
	}

	return;
}
