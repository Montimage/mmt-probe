#ifndef PROCESSING_H
#define	PROCESSING_H
#ifdef	__cplusplus
extern "C" {
#endif
//#define _GNU_SOURCE

#include "lib/data_spsc_ring.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip_protocols.h"
#include <sysrepo.h>
#include <semaphore.h>
#include "rdkafka.h"
#include <stdatomic.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sys/socket.h>
#include <unistd.h>
#include<pcap.h>

//dynamic_conf
//#include "mmt_utils.h"

#define ONLINE_ANALYSIS 0x1
#define OFFLINE_ANALYSIS 0x2
#define MMT_RADIUS_REPORT_ALL 0x0
#define MMT_RADIUS_REPORT_MSG 0x1

//#define MMT_RADIUS_ANY_CONDITION 0x0
#define MMT_RADIUS_IP_MSISDN_PRESENT 0x1

/////////////////////////////// report formats JP
#define MMT_STATISTICS_NON_FLOW_REPORT_FORMAT    0x63 //decimal 99
#define MMT_STATISTICS_FLOW_REPORT_FORMAT    0x64 //decimal 100
#define MMT_FTP_RECONSTRUCTION_REPORT_FORMAT 0xd
#define MMT_SECURITY_REPORT_FORMAT  0xa
#define MMT_RADIUS_REPORT_FORMAT    0x9
#define MMT_MICRO_FLOW_REPORT_FORMAT    0x8
#define MMT_WEB_REPORT_FORMAT    0x1
#define MMT_FTP_REPORT_FORMAT    0x4
#define MMT_RTP_REPORT_FORMAT    0x3
#define MMT_SSL_REPORT_FORMAT    0x2
#define MMT_HTTP_RECONSTRUCT_MODULE_REPORT_FORMAT    0xb
//#define MMT_SKIP_APP_REPORT_FORMAT      0xFF //This is mainly to skip the reporting of flows of specific applications.
#define MMT_DEFAULT_APP_REPORT_FORMAT   0x0
#define MMT_IP_FRAG_REPORT_FORMAT   0x65
#define MMT_MULTI_SESSION_REPORT_FORMAT   0xc
#define MMT_LICENSE_REPORT_FORMAT 0x1E
#define MMT_EVENT_REPORT_FORMAT 0x3E8
///////////////////////////////report format JP

#define MMT_USER_AGENT_THRESHOLD 0x20 //32KB
#define MAX_MESS 3000
#define TIMEVAL_2_MSEC(tval) ((tval.tv_sec << 10) + (tval.tv_usec >> 10))
#define TIMEVAL_2_USEC(tval) ((tval.tv_sec * 1000000) + (tval.tv_usec))
#define MAX_FILE_NAME 512

pthread_mutex_t mutex_lock;
pthread_spinlock_t spin_lock;
time_t update_reporting_time;
static int is_stop_timer;
//int do_abort;
//pcap_t *handle = 0;

static struct mmt_probe_struct mmt_probe;
volatile uint8_t * do_abort;
enum os_id {
	OS_UKN, //Unknown
	OS_WIN, //Windows
	OS_NUX, //Linux
	OS_MAC, //Mac
	OS_AND, //Android
	OS_BLB, //Blackberry
	OS_SMB, //Symbian
	OS_IOS, //iOS
	OS_WPN, //Windows phone
};

enum dev_id {
	DEV_UKN, //Unknown
	DEV_PC, //PC
	DEV_MAC, //Mac
	DEV_MOB, //Mobile
	DEV_IPHONE, //iPhone
	DEV_IPAD, //iPad
	DEV_IPOD, //iPod
	DEV_BLB, //Blackberry
	DEV_TAB, //Tablet
	DEV_NOKIA, //Nokia
	DEV_SUM, //Sumsung
	DEV_HTC, //HTC
};

enum mmt_log_levels {
	MMT_L_EMERGENCY,
	MMT_L_ALERT,
	MMT_L_CRITICAL,
	MMT_L_ERROR,
	MMT_L_WARNING,
	MMT_L_NOTICE,
	MMT_L_INFO,
	MMT_L_DEBUG,
};

enum mmt_probe_log_codes {
	MMT_P_INIT = 1,
	MMT_P_END,
	MMT_E_INIT,
	MMT_E_STARTED,
	MMT_E_END,
	MMT_E_INIT_ERROR,
	MMT_E_PROCESS_ERROR,
	MMT_P_TRACE_ERROR,
	MMT_P_START_PROCESS_TRACE,
	MMT_P_TRACE_DELETE,
	MMT_P_END_PROCESS_TRACE,
	MMT_P_OPEN_OUTPUT,
	MMT_P_CLOSE_OUTPUT,
	MMT_P_STATUS,
	MMT_P_MEM_ERROR,
	MMT_P_SEGV_ERROR,
	MMT_P_ERROR,
	MMT_P_TERMINATION,
	MMT_P_INSTANCE_QUEUE_FULL,
	MMT_LICENSE,
	MMT_T_INIT,
	MMT_T_END,
};

typedef struct mmt_ipv4_ipv6_id_struct {

	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	};
} mmt_ipv4_ipv6_t;

typedef struct http_line_struct {
	const uint8_t *ptr;
	uint16_t len;
} http_line_struct_t;

typedef struct mmt_dev_properties_struct {
	uint16_t os_id;
	uint16_t dev_id;
} mmt_dev_properties_t;

typedef struct mmt_event_attribute_struct {
	char proto[256 + 1];
	char attribute[256 + 1];
	uint32_t proto_id;
	uint32_t attribute_id;
} mmt_event_attribute_t;

typedef struct mmt_event_report_struct {
	uint32_t enable;
	uint32_t id;
	mmt_event_attribute_t event;
	uint32_t attributes_nb;
	uint32_t event_output_channel[3];
	mmt_event_attribute_t * attributes;
	struct mmt_event_report_struct *next;
} mmt_event_report_t;

typedef struct mmt_condition_attribute_struct {
	char condition[256 + 1];
	char location[256 + 1];
	char proto[256 + 1];
	char attribute[256 + 1];
	char handler[256 + 1];
} mmt_condition_attribute_t;

typedef struct mmt_condition_report_struct {
	uint32_t enable;
	uint16_t id;
	mmt_condition_attribute_t condition;
	uint32_t attributes_nb;
	uint32_t handlers_nb;
	mmt_condition_attribute_t * attributes;
	mmt_condition_attribute_t * handlers;
	struct mmt_condition_report_struct *next;

} mmt_condition_report_t;

typedef struct mmt_security_attribute_struct {
	char proto[256 + 1];
	char attribute[256 + 1];
	uint32_t proto_id;
	uint32_t attribute_id;
} mmt_security_attribute_t;

typedef struct mmt_security_report_struct {
	uint32_t enable;
	uint32_t attributes_nb;
	uint32_t event_name_nb;
	char ** event_name;
	uint32_t *event_id;
	uint8_t rule_type;
	mmt_security_attribute_t * attributes;
} mmt_security_report_t;

typedef struct mmt_security_report_multisession_struct {
	uint32_t enable;
	uint32_t attributes_nb;
	mmt_security_attribute_t * attributes;
} mmt_security_report_multisession_t;

typedef struct ip_port_struct {
	char server_ip_address[18 + 1];
	uint32_t *server_portnb;
} ip_port_t;

#ifdef HTTP_RECONSTRUCT_MODULE

#define HSDS_START 1
#define HSDS_TRANSFER 2
#define HSDS_END 3
#define MAX_NB_DATA_PACKETS 1024

/**
 * HTTP content processing structure
 */
typedef struct
{
	int status; //indicates if we can process data or not, not used but can be if we wish to limit processing to one direction client-> server or server->client
	int interaction_count;//number of HTTP messages seen on the same session
	int content_type;//set to 1 if the content type is html
	int content_encoding;//set to 1 if the content encoding is gzip
	void * pre_processor;//opaque pointer to the pre-processor (in this case gzip parser)
	void * processor;//opaque pointer to the processor (in this case: html parse)
}http_content_processor_t;

typedef struct http_session_data_struct {
	uint64_t session_id;
	uint64_t http_session_status;
	char * filename;
	char * content_type;
	uint64_t current_len;
	uint64_t total_len;
	uint64_t data_packets[MAX_NB_DATA_PACKETS];
	uint8_t file_has_extension;
	struct http_session_data_struct *next;
}http_session_data_t;

// static http_session_data_t * list_http_session_data = NULL;

#endif // End of HTTP_RECONSTRUCT_MODULE

typedef struct mmt_cpu_perf_struct {
	bool is_enable;
	uint8_t cpu_mem_usage_rep_freq; //frequency to send the report
	long double cpu_usage_avg;
	long double mem_usage_avg;
} mmt_cpu_perf_t;

typedef struct kafka_topic_object_struct {
	rd_kafka_topic_t * rkt_session;
	rd_kafka_topic_t * rkt_event;
	rd_kafka_topic_t * rkt_cpu;
	rd_kafka_topic_t * rkt_ftp_download;
	rd_kafka_topic_t * rkt_multisession;
	rd_kafka_topic_t * rkt_license;
	rd_kafka_topic_t * rkt_protocol_stat;
	rd_kafka_topic_t * rkt_radius;
	rd_kafka_topic_t * rkt_microflows;
	rd_kafka_topic_t * rkt_security;
	rd_kafka_topic_t * rkt_frag;

} kafka_topic_object_t;

typedef struct mmt_probe_context_struct {
	uint32_t thread_nb;
	uint32_t thread_nb_2_power;
	uint32_t thread_queue_plen;
	uint32_t thread_queue_blen;
	uint32_t input_mode;
	uint32_t probe_id_number;
	uint64_t report_cache_size_before_flushing;
	uint32_t requested_snap_len;
	char input_source[256 + 1];
	char log_file[256 + 1];
	char data_out[256 + 1];
	char dir_out[256 + 1];
	char properties_file[256 + 1];
	char radius_out[256 + 1];
	char input_f_name[256 + 1];
	char out_f_name[256 + 1];
	char output_location[256 + 1];
	char license_location[256 + 1];
	char behaviour_output_location[256 + 1];
	char ftp_reconstruct_output_location[256 + 1];
	char dynamic_config_file[256 + 1];

	uint32_t ftp_enable;
	uint32_t web_enable;
	uint32_t rtp_enable;
	uint32_t ssl_enable;
	uint32_t behaviour_enable;
	uint32_t security_enable;
	uint32_t event_based_reporting_enable;
	uint32_t condition_based_reporting_enable;
	uint32_t enable_security_report;
	uint32_t ftp_reconstruct_enable;
	uint32_t radius_enable;
	uint32_t default_session_timeout;
	uint32_t long_session_timeout;
	uint32_t short_session_timeout;
	uint32_t live_session_timeout;

	//uint32_t output_to_file_enable;
	atomic_int output_to_file_enable;
	uint32_t redis_enable;
	uint32_t kafka_enable;
	//rd_kafka_topic_conf_t * topic_old;

	kafka_topic_object_t * topic_object;

	char out_f_name_index[256 + 1];
	FILE * data_out_file;
	int combine_radius;
	FILE * radius_out_file;
	FILE * log_output;
	uint32_t log_level;

	uint32_t enable_proto_without_session_stats;
	uint32_t enable_flow_stats;
	uint32_t enable_IP_fragmentation_report;

	uint32_t radius_starategy;
	uint32_t radius_message_id;
	uint32_t radius_condition_id;

	uint32_t microf_enable;
	uint32_t microf_pthreshold;
	uint32_t microf_bthreshold;
	uint32_t microf_report_pthreshold;
	uint32_t microf_report_bthreshold;
	uint32_t microf_report_fthreshold;
	uint32_t user_agent_parsing_threshold;
	uint32_t stats_reporting_period;
	uint32_t sampled_report_period;
	uint32_t sampled_report;
	uint32_t event_reports_nb;
	uint32_t condition_reports_nb;
	uint32_t new_condition_reports_nb;
	uint32_t new_event_reports_nb;
	mmt_event_report_t * event_reports;
	mmt_condition_report_t * condition_reports;
	mmt_condition_report_t * register_new_condition_reports;
	mmt_event_report_t * register_new_event_reports;

	uint32_t socket_enable;

	mmt_cpu_perf_t * cpu_reports;
	uint8_t cpu_mem_usage_enabled;
	pthread_t cpu_ram_usage_thr; /* thread handle */

	uint32_t new_attribute_register_flag;
	time_t file_modified_time;
	ip_port_t * server_adresses;
	uint32_t server_ip_nb;
	uint32_t server_port_nb;
	mmt_security_report_t * security_reports;
	uint32_t total_security_attribute_nb;
	uint32_t security_reports_nb;
	uint32_t nb_of_report_per_msg;
	uint8_t one_socket_server;
	uint32_t retain_files;
#ifdef HTTP_RECONSTRUCT_MODULE
	char HTTP_RECONSTRUCT_MODULE_output_location[256 + 1];
	uint16_t HTTP_RECONSTRUCT_MODULE_id;
	uint32_t HTTP_RECONSTRUCT_MODULE_enable;
#endif    // End of HTTP_RECONSTRUCT_MODULE

	uint32_t socket_domain;
	char unix_socket_descriptor[256 + 1];

	mmt_security_report_multisession_t * security_reports_multisession;
	uint32_t security_reports_multisession_nb;
	uint32_t enable_security_report_multisession;
	uint32_t total_security_multisession_attribute_nb;

	uint32_t enable_session_report;
	uint8_t microf_output_channel[3];
	uint8_t multisession_output_channel[3];
	uint8_t security1_output_channel[3];
	uint8_t event_output_channel[3];
	uint8_t session_output_channel[3];
	uint8_t radius_output_channel[3];
	uint8_t ftp_reconstruct_output_channel[3];
	uint8_t cpu_mem_output_channel[3];
	uint8_t security2_output_channel[3];

	rd_kafka_t *kafka_producer_instance; /* Producer instance handle */

	//hn - new security
	bool security2_enable;

	char security2_rules_mask[1000];
	char security2_excluded_rules[1000];
	char security2_add_rules[1000];
	char security2_remove_rules[1000];
	int security2_count_rule_remove;
	uint32_t remove_rules_array[1000];
	int security2_add_rules_enable;
	int security2_remove_rules_enable;
	//number of threads of security2 per one thread of probe
	uint8_t security2_threads_count;
	int probe_load_running;
	int pid;
	//volatile uint8_t event_report_flag;
	sr_conn_ctx_t *connection;
	sr_session_ctx_t *session;
	sr_subscription_ctx_t *subscription;
	int load_enable;
	long avail_processors;
} mmt_probe_context_t;

typedef struct microsessions_stats_struct {
	struct timeval start_time;
	struct timeval end_time;
	const char * application;
	uint32_t application_id;
	uint32_t flows_nb;
	uint32_t dl_pcount;
	uint32_t ul_pcount;
	uint32_t dl_bcount;
	uint32_t ul_bcount;
} microsessions_stats_t;

typedef struct rtp_session_attr_struct {
	uint32_t packets_nb; /* The reason we need this is that RTP flows may contain STUN messages. We follow here RTP packets only */
	uint32_t jitter;
	uint32_t nb_order_error;
	uint32_t nb_lost;
	uint32_t nb_loss_bursts;
	uint64_t rtp_throughput[2];
} rtp_session_attr_t;

typedef struct ftp_session_attr_struct {
	struct timeval first_response_seen_time;
	uint8_t session_conn_type;
	uint8_t direction;
	char * session_username;
	char * session_password;
	char * response_value;
	uint32_t file_size;
	uint8_t data_type;
	uint64_t response_time;
	uint8_t data_response_time_seen;
	char * filename;
	uint16_t response_code;
	uint64_t session_id_control_channel;
	time_t file_download_starttime_sec;
	time_t file_download_starttime_usec;
	time_t file_download_finishtime_sec;
	time_t file_download_finishtime_usec;

} ftp_session_attr_t;

typedef struct temp_session_statistics_struct {
	struct timeval start_time;
	struct timeval last_activity_time;
	uint64_t total_byte_count;
	uint64_t total_data_byte_count;
	uint64_t total_packet_count;
	uint64_t packet_count[2];
	uint64_t byte_count[2];
	uint64_t data_byte_count[2];
	uint32_t touched;
	uint64_t sum_rtt[2];
	uint64_t rtt_min_usec[2];
	uint64_t rtt_max_usec[2];
	uint64_t rtt_avg_usec[2];
	uint64_t rtt_counter[2];
	uint32_t retransmission_count;
} session_stat_t;

typedef struct web_session_attr_struct {
	struct timeval first_request_time;
	struct timeval response_time;
	struct timeval method_time;
	struct timeval interaction_time;
	char mimetype[64];
	char hostname[96];
	char referer[64];
	char useragent[64];
	uint8_t has_referer :1, has_useragent :1, xcdn_seen :1, seen_response :1;
	uint8_t trans_nb;
	char method[20];
	char uri[1024];
	char response[1024];
	char content_len[20];
	uint8_t has_uri;
	uint32_t touched;
	uint32_t state_http_request_response;
} web_session_attr_t;

typedef struct ssl_session_attr_struct {
	char hostname[64];
} ssl_session_attr_t;

typedef struct session_struct {
	uint8_t dtt_seen;
	struct timeval dtt_start_time;
	uint64_t data_transfer_time;
	uint64_t rtt_at_handshake;
	uint8_t proto;
	uint8_t isClassified;
#ifdef HTTP_RECONSTRUCT_MODULE
	http_content_processor_t * http_content_processor;
#endif // End of HTTP_RECONSTRUCT_MODULE   
	uint16_t format_id;
	uint16_t app_format_id;
	int proto_path;
	int application_class;
	char path[128];
	char path_ul[128]; //path for uplink traffic
	char path_dl[128]; //path for downlink traffic
	mmt_ipv4_ipv6_t ipclient;
	mmt_ipv4_ipv6_t ipserver;
	uint16_t clientport;
	uint16_t serverport;
	unsigned char src_mac[7];
	unsigned char dst_mac[7];
	uint8_t isFlowExtracted;
	uint8_t ipversion;
	uint32_t contentclass;
	uint32_t thread_number;
	uint64_t session_id;
	uint64_t report_counter;
	session_stat_t * session_attr;
	void * app_data;
} session_struct_t;

struct packet_element {
	struct pkthdr header;
	u_char *data;
};

/*
 * Packet with pointer on next packet
 * for list insertion
 */
struct smp_pkt {
	struct list_entry entry; /* list structure */
	struct packet_element pkt; /* real packet information */
};
typedef struct probe_internal_struct {
	uint32_t instance_id;
	microsessions_stats_t mf_stats[PROTO_MAX_IDENTIFIER];
} probe_internal_t;
struct mmsghdr {
	struct msghdr msg_hdr;	 //Actual message header.
	unsigned int msg_len;	 //Number of received or sent bytes for the  entry.
};

extern int sendmmsg(int __fd, struct mmsghdr *__vmessages, unsigned int __vlen,
		int __flags);

typedef struct security_report_buffer_struct {
	uint32_t length;
	struct mmsghdr grouped_msg;
	struct iovec * msg;
	uint64_t security_report_counter;
	unsigned char ** data;

} security_report_buffer_t;

typedef struct mmt_security_attributes_struct {
	uint32_t proto_id;
	uint32_t attribute_id;
} mmt_security_attributes_t;

/*
 * List of packets for a thread
 */
//#define MAX_CACHE_SIZE 300000
typedef struct worker_args {
	struct rte_ring *ring_in;
	char rx_to_workers[20];
	int lcore_id;
	long long int num_packet;
} worker_args_t;

struct smp_thread {
	int thread_index;
	mmt_handler_t *mmt_handler;
	probe_internal_t iprobe;
	uint32_t queue_plen;
	uint32_t queue_blen;
	pthread_t handle; /* thread handle */
	pthread_spinlock_t lock; /* lock for concurrent access */
	struct smp_pkt pkt_head; /* pointer on first packet */
	struct smp_pkt null_pkt; /* Null packet used to indicate end of packet feeding for the thread. */
	time_t last_stat_report_time;
	time_t pcap_last_stat_report_time;
	time_t pcap_current_packet_time;
	uint64_t report_counter;
	mmt_event_report_t * event_reports;
	mmt_event_report_t * new_event_reports;
	mmt_security_attributes_t * security_attributes;
	security_report_buffer_t * report;
	char **cache_message_list;
	int cache_count;
	data_spsc_ring_t fifo;
	uint64_t nb_packets, nb_dropped_packets, nb_dropped_packets_NIC,
			nb_dropped_packets_kernel;
	uint32_t * sockfd_internet;
	uint32_t sockfd_unix;
	uint64_t packet_send;
	worker_args_t * workers;
	uint8_t socket_active;

	unsigned lcore_id;	//lcore_id of probe

	//hn - new security
	unsigned security2_lcore_id; //lcore_id of security2

	sem_t sem_wait;
#ifdef HTTP_RECONSTRUCT_MODULE
	http_session_data_t * list_http_session_data;
#endif	
	volatile uint8_t event_report_flag;
	volatile uint8_t condition_report_flag;

	volatile uint8_t session_report_flag;
	volatile uint8_t security2_report_flag;
	volatile uint8_t behaviour_flag;
	volatile uint8_t ftp_reconstruct_flag;
	volatile uint8_t config_updated;
	volatile uint8_t micro_flows_flag;
};

typedef struct mmt_probe_struct {
	struct smp_thread * smp_threads;
	pthread_t timer_handler;
	//mmt_handler_t *mmt_handler; //For single threaded operations
	mmt_probe_context_t * mmt_conf;
	probe_internal_t iprobe;
	uint64_t packets_nb;
} mmt_probe_struct_t;

struct user_data {
	void *smp_thread;
	void *event_reports;
};
struct sockaddr_un {
	unsigned short sun_family; /* AF_UNIX */
	char sun_path[108];
};
void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code,
		const char * log_msg);
void init_redis(char * hostname, int port);
void proto_stats_cleanup(void * handler);
void flowstruct_init(void * handler);
void flowstruct_cleanup(void * handler);
void radius_ext_init(void * args);
void radius_ext_cleanup(void * handler);
void event_reports_init(void * args);
void conditional_reports_init(void * handler);
void security_event(int prop_id, char *verdict, char *type, char *cause,
		char *history, struct timeval packet_timestamp, void * user_args);
void protocols_stats_iterator(uint32_t proto_id, void * args);
void send_message_to_file(char * message);
void send_message_to_file_thread(char * message, void *args);
void send_message_to_redis(char *channel, char * message);
int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy,
		char * dest);
int is_local_net(int addr);
int is_localv6_net(char * addr);
void security_reports_multisession_init(void * args);

int register_event_report_handle(void * args);
uint32_t get_2_power(uint32_t nb);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
uint32_t is_microflow(const mmt_session_t * expired_session);
uint32_t is_microflow_stats_reportable(microsessions_stats_t * stats);
void report_microflows_stats(microsessions_stats_t * stats, void *args);
void update_microflows_stats(microsessions_stats_t * stats,
		const mmt_session_t * expired_session);
void reset_microflows_stats(microsessions_stats_t * stats);
void report_all_protocols_microflows_stats(void *args);
int license_expiry_check(int status);
void parseOptions(int argc, char ** argv, struct mmt_probe_struct * mmt_probe);
void todo_at_start(char *file_path);
void todo_at_end();
void init_mmt_security(mmt_handler_t *mmt_handler, char * property_file,
		void *args);
void exit_timers();
void flush_messages_to_file_thread(void *);
int start_timer(uint32_t period, void *callback, void *user_data);
struct timeval mmt_time_diff(struct timeval tstart, struct timeval tend);
void proto_stats_init(void * arg);
void read_attributes();
int condition_parse_dot_proto_attribute(char * inputstring,
		mmt_condition_attribute_t * protoattr);
int parse_condition_attribute(char * inputstring,
		mmt_condition_attribute_t * conditionattr);
int parse_handlers_attribute(char * inputstring,
		mmt_condition_attribute_t * handlersattr);
void new_conditional_reports_init(void * args);
void new_event_reports_init(void * args);
int parse_dot_proto_attribute(char * inputstring,
		mmt_event_attribute_t * protoattr);

//handlers
void ftp_response_value_handle(const ipacket_t * ipacket,
		attribute_t * attribute, void * user_args);
void ftp_session_connection_type_handle(const ipacket_t * ipacket,
		attribute_t * attribute, void * user_args);
void http_response_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void useragent_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void referer_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void http_method_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void host_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void mime_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void rtp_version_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void rtp_jitter_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void rtp_loss_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void rtp_order_error_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void rtp_burst_loss_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void uri_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void ip_rtt_handler(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void content_len_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
void flush_messages_to_file_thread(void *arg);
void tcp_closed_handler(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
int file_is_modified(const char *path);
void write_to_socket_internet(struct smp_thread *th);
void write_to_socket_unix(struct smp_thread *th);
void create_socket(mmt_probe_context_t * mmt_conf, void *args);
int packet_handler(const ipacket_t * ipacket, void * args);
void security_reports_init(void * args);
void * get_handler_by_name(char * func_name);
void flow_nb_handle(const ipacket_t * ipacket, attribute_t * attribute,
		void * user_args);
int dpdk_capture(int argc, char **argv, struct mmt_probe_struct * mmt_probe);
//void print_stats(void * args);
int cleanup_registered_handlers(void *arg);
void payload_extraction(const ipacket_t * ipacket, struct smp_thread *th,
		attribute_t * attr_extract, int report_num);
void data_extraction(const ipacket_t * ipacket, struct smp_thread *th,
		attribute_t * attr_extract, int report_num);
void ftp_last_command(const ipacket_t * ipacket, struct smp_thread *th,
		attribute_t * attr_extract, int report_num);
void ftp_last_response_code(const ipacket_t * ipacket, struct smp_thread *th,
		attribute_t * attr_extract, int report_num);
void ip_opts(const ipacket_t * ipacket, struct smp_thread *th,
		attribute_t * attr_extract, int report_num);
void get_security_multisession_report(const ipacket_t * ipacket, void * args);
void get_security_report(const ipacket_t * ipacket, void * args);
void cleanup(int signo, mmt_probe_struct_t * mmt_probe);
void process_trace_file(char * filename, mmt_probe_struct_t * mmt_probe);
void process_interface(char * ifname, struct mmt_probe_struct * mmt_probe);
void clean_up_security2();
void * smp_thread_routine(void *arg); //TODO: Static removed
int pcap_capture(struct mmt_probe_struct * mmt_probe);

void init_kafka(char * hostname, int port);
void send_msg_to_kafka(rd_kafka_topic_t *rkt, char *message);
void config_output_to_redis(sr_session_ctx_t * session, sr_val_t * value,
		struct mmt_probe_struct * mmt_probe);
void read_mmt_config(sr_session_ctx_t *session,
		struct mmt_probe_struct * mmt_probe);
void flowstruct_uninit(void * handler);

/** Luong NGUYEN: HTTP reconstruct */
#ifdef HTTP_RECONSTRUCT_MODULE
/**
 * Initialize for http reconstruction
 * - Register handle
 * - Register extract function
 * - Register session expired handle
 * @param arg [description]
 */
void http_reconstruct_init(void * arg);
/**
 * Handle new session event
 * @param ipacket   ipacket - which starts a new session
 * @param attribute session attribute
 * @param user_args user argument
 */
// void ip_new_session_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Call when a HTTP message start
 * @param ipacket   ipacket - which contains the starting of a message
 * @param attribute [description]
 * @param user_args [description]
 */
void http_message_start_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Call when a HTTP header has been detected
 * @param ipacket   ipacket
 * @param attribute [description]
 * @param user_args [description]
 */
void http_generic_header_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Call at the end of a HTTP header
 * @param ipacket   ipacket
 * @param attribute [description]
 * @param user_args [description]
 */
void http_headers_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Call on HTTP data packet
 * @param ipacket   ipacket - contains HTTP data
 * @param attribute [description]
 * @param user_args [description]
 */
void http_data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Call at the end of a HTTP message
 * @param ipacket   ipacket
 * @param attribute [description]
 * @param user_args [description]
 */
void http_message_end_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
/**
 * Packet handle to process HTTP reconstruction - call on every packet
 * @param  ipacket   ipacket
 * @param  user_args [description]
 * @return           [description]
 */
int http_packet_handler(const ipacket_t * ipacket, void * user_args);
/**
 * Session expiry handler that will be called every time MMT core detects a session expiry
 * Close the HTTP content processing structure
 */
// void http_classification_expiry_session(const mmt_session_t * expired_session, void * args);
http_session_data_t * new_http_session_data();

void add_http_session_data(http_session_data_t * current_http_data, struct smp_thread * th);

http_session_data_t * get_http_session_data_by_id(uint64_t session_id, http_session_data_t * current_http_data);

/**
 * Initializes the HTTP content processing structure
 */
inline static void * init_http_content_processor()
{
	http_content_processor_t * sp = (http_content_processor_t *) calloc( 1, sizeof( http_content_processor_t ) );
	return (void *) sp;
}

void clean_http_session_data(uint64_t session_id,struct smp_thread * th);

void * close_http_content_processor(http_content_processor_t * sp);

/**
 * Check if a packet is an HTTP packet or not
 * @param  ipacket [description]
 * @return         [description]
 */
uint8_t is_http_packet(const ipacket_t * ipacket);
void dynamic_conf (struct mmt_probe_struct * mmt_probe);
size_t get_rules_id_list_in_mask(const char * rule_mask, uint32_t ** rules_set);
static void terminate_probe_processing(int wait_thread_terminate);
#endif // End of HTTP_RECONSTRUCT_MODULE
/** END OF HTTP RECONSTRUCT */


//prototypes
void print_ip_session_report(const mmt_session_t * session, void *user_args);
void print_initial_web_report(const mmt_session_t * session,
		session_struct_t * temp_session, char message[MAX_MESS + 1], int valid);
void print_initial_rtp_report(const mmt_session_t * session,
		session_struct_t * temp_session, char message[MAX_MESS + 1], int valid);
void print_initial_ssl_report(const mmt_session_t * session,
		session_struct_t * temp_session, char message[MAX_MESS + 1], int valid);
void print_initial_ftp_report(const mmt_session_t * session,
		session_struct_t * temp_session, char message[MAX_MESS + 1], int valid);
void print_initial_default_report(const mmt_session_t * session,
		session_struct_t * temp_session, char message[MAX_MESS + 1], int valid);

int get_protocol_index_from_session(const proto_hierarchy_t * proto_hierarchy,
		uint32_t proto_id);

int register_conditional_report_handle(void * handler,
		mmt_condition_report_t * condition_report);

mmt_probe_context_t * get_probe_context_config();

mmt_dev_properties_t get_dev_properties_from_user_agent(char * user_agent,
		uint32_t len);


int time_diff(struct timeval t1, struct timeval t2);

void classification_expiry_session(const mmt_session_t * expired_session,
		void * args);

#ifdef	__cplusplus
}
#endif

#endif	/* PROCESSING_H */
