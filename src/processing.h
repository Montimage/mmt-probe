#ifndef PROCESSING_H
#define	PROCESSING_H

#ifdef	__cplusplus
extern "C" {
#endif
#include "lib/data_spsc_ring.h"
#define ONLINE_ANALYSIS 0x1
#define OFFLINE_ANALYSIS 0x2
#define OFFLINE_ANALYSIS_CONTINUOUS 0x3 

#define MMT_STATISTICS_REPORT_FORMAT    0x63 //decimal 99
//HN
#define MMT_STATISTICS_FLOW_REPORT_FORMAT    0x64 //decimal 100
#define MMT_SECURITY_REPORT_FORMAT  0xa

#define MMT_RADIUS_REPORT_FORMAT    0x9
#define MMT_MICROFLOWS_STATS_FORMAT 0x8
#define MMT_FLOW_REPORT_FORMAT      0x7

#define MMT_SKIP_APP_REPORT_FORMAT      0xFF //This is mainly to skip the reporting of flows of specific applications.
#define MMT_DEFAULT_APP_REPORT_FORMAT   0x0
//#define MMT_WEB_APP_REPORT_FORMAT       0x1
//#define MMT_SSL_APP_REPORT_FORMAT       0x2
//#define MMT_RTP_APP_REPORT_FORMAT       0x3

//#define MMT_FTP_APP_REPORT_FORMAT    0xc8

//#define MMT_FTP_DOWNLOAD_REPORT_FORMAT       201
//#define MMT_SAMPLED_RTP_APP_REPORT_FORMAT       1003

#define MMT_RADIUS_REPORT_ALL 0x0
#define MMT_RADIUS_REPORT_MSG 0x1

#define MMT_RADIUS_ANY_CONDITION 0x0
#define MMT_RADIUS_IP_MSISDN_PRESENT 0x1

#define MMT_USER_AGENT_THRESHOLD 0x20 //32KB
#define MAX_MESS 3000
#define TIMEVAL_2_MSEC(tval) ((tval.tv_sec << 10) + (tval.tv_usec >> 10))
#define TIMEVAL_2_USEC(tval) ((tval.tv_sec * 1000000) + (tval.tv_usec))
uint64_t total_session_count;
pthread_mutex_t mutex_lock;
pthread_spinlock_t spin_lock;
time_t update_reporting_time;
static int is_stop_timer;

static struct mmt_probe_struct mmt_probe;

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
} mmt_ipv4_ipv6_id_t;

typedef struct mmt_dev_properties_struct {
    uint16_t os_id;
    uint16_t dev_id;
} mmt_dev_properties_t;

typedef struct mmt_event_attribute_struct {
    char proto[256 + 1];
    char attribute[256 + 1];
} mmt_event_attribute_t;


typedef struct mmt_event_report_struct {
    uint32_t id;
    mmt_event_attribute_t event;
    uint32_t attributes_nb;
    mmt_event_attribute_t * attributes;
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
} mmt_condition_report_t;

typedef struct mmt_probe_context_struct {
    uint32_t thread_nb;
    uint32_t thread_nb_2_power;
    uint32_t thread_queue_plen;
    uint32_t thread_queue_blen;
    uint32_t input_mode;
    uint32_t probe_id_number;
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
    uint32_t ftp_enable;
    uint32_t web_enable;
    uint32_t rtp_enable;
    uint32_t ssl_enable;
    uint16_t ftp_id;
    uint16_t web_id;
    uint16_t rtp_id;
    uint16_t ssl_id;
    uint16_t ftp_reconstruct_id;
    uint16_t security_id;
    uint32_t behaviour_enable;
    uint32_t security_enable;
    uint32_t event_based_reporting_enable;
    uint32_t condition_based_reporting_enable;
    uint32_t ftp_reconstruct_enable;
    uint32_t radius_enable;
    uint32_t microflow_enable;
    uint32_t output_to_file_enable;
    uint32_t redis_enable;

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
    mmt_event_report_t * event_reports;
    mmt_condition_report_t * condition_reports;

    unsigned char *mac_address_host;	//

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
    uint64_t ul_packet_count;
    uint64_t dl_packet_count;
    uint64_t ul_byte_count;
    uint64_t dl_byte_count;        //metric
    time_t last_report_time_sec;
    time_t last_report_time_usec;//jeevan
    uint64_t rtp_throughput[2];
} rtp_session_attr_t;

/*typedef struct ftp_command_struct{
    uint16_t cmd;
    char *str_cmd;
    char *param;
}ftp_command_t;*/

/**
 * FTP response structure
 */
/*typedef struct ftp_response_struct{
    uint16_t code;
    char *str_code;
    char *value;
}ftp_response_t;*/


/*typedef struct ftp_reconstruction_struct {
    time_t file_reconstruction_starttime_sec;
    time_t file_reconstruction_starttime_usec;

}ftp_reconstruction_t;*/

typedef struct ftp_session_attr_struct {
    uint8_t session_conn_type;
    uint8_t direction;
    char * session_username;
    char * session_password;
    char * packet_request;
    char * response_value;
    uint32_t file_size;
    uint8_t data_type;
    uint64_t response_time;
    uint8_t data_response_time_seen;
    char * location;
    char * filename;
    uint16_t response_code;
    uint64_t session_id_control_channel;
    time_t file_download_starttime_sec;
    time_t file_download_starttime_usec;
    time_t file_download_finishtime_sec;
    time_t file_download_finishtime_usec;
    uint64_t ftp_throughput[2];
	//ftp_reconstruction_t * ftp_reconstruct;

} ftp_session_attr_t;

/*typedef struct ftp_packet_attr_struct {
    uint8_t packet_type;
    char * request;
    char * request_parameter;
    uint16_t response;
    char * response_value;
    uint32_t data_len;

} ftp_packet_attr_t;*/


typedef struct temp_session_statistics_struct{
    struct timeval start_time;
    struct timeval last_activity_time;
    uint64_t total_byte_count;
    uint64_t total_data_byte_count;
    uint64_t total_packet_count;
    uint64_t packet_count[2];
    uint64_t byte_count[2];
    uint64_t data_byte_count[2];
    struct timeval response_time;
    struct timeval method_time;
    uint8_t seen_response;
    uint32_t touched;
    uint64_t sum_rtt[2];
    uint64_t rtt_min_usec[2];
    uint64_t rtt_max_usec[2];
    uint64_t rtt_avg_usec[2];
    uint64_t rtt_counter[2];
    uint32_t retransmission_count;
}temp_session_statistics_t;

typedef struct web_session_attr_struct {
    struct timeval first_request_time;
    struct timeval response_time;
    struct timeval method_time;
    struct timeval interaction_time;
    char mimetype[64];
    char hostname[96];
    char referer[64];
    char useragent[64];
    uint8_t has_referer : 1, has_useragent : 1, xcdn_seen : 1, seen_response : 1;
    uint8_t trans_nb;
    char method[20];
    char uri[1024];
    char response[1024];
    char content_len[20];
    uint8_t has_uri;
    uint16_t psh_flag;
    time_t last_report_time_sec;
    uint32_t touched;
    uint64_t request_counter;
    uint32_t state_http_request_response;
    temp_session_statistics_t * http_session_attr;
} web_session_attr_t;

typedef struct ssl_session_attr_struct {
    char hostname[64];
} ssl_session_attr_t;

typedef struct session_struct {
    uint16_t format_id;
    uint16_t app_format_id;
    struct timeval latest_packet_time;
    struct timeval previous_packet_time;
    int proto_path;
    int application_class;
    char path[128];
    char path_ul[128]; //path for uplink traffic
    char path_dl[128]; //path for downlink traffic
    mmt_ipv4_ipv6_id_t ipclient;
    mmt_ipv4_ipv6_id_t ipserver;
    uint16_t clientport;
    uint16_t serverport;
    unsigned char src_mac [7];
    unsigned char dst_mac [7];
    uint8_t proto;
    uint8_t isFlowExtracted;
    uint8_t isClassified;
    uint8_t ipversion;
    uint32_t contentclass;
    uint32_t thread_number;
    uint64_t session_id;
    uint64_t report_counter;
    temp_session_statistics_t * session_attr;
    void * app_data;
} session_struct_t;

typedef struct session_expiry_check_struct {
    uint32_t expired_session_id;
} session_expiry_check_struct_t;

struct packet_element {
    struct pkthdr header;
    u_char *data;
};

/**
 * Double linked list structure
 */
struct list_entry {
    struct list_entry *next, *prev;
};

/**
 * List node initialization
 */
static inline void init_list_head(struct list_entry *list) {
    list->next = list;
    list->prev = list;
}

/**
 * Test if list is empty
 */
static inline int list_empty(struct list_entry *list) {
    return (list->next == list);
}

/**
 * Add a node at list tail
 */
static inline void list_add_tail(struct list_entry *new, struct list_entry *head) {
    new->next = head;
    head->prev->next = new;
    new->prev = head->prev;
    head->prev = new;
}

/**
 * Remove a node from list
 */
static inline void list_del(struct list_entry *entry) {
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
    entry->next = NULL;
    entry->prev = NULL;
}

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
    //FILE * data_out;
    //FILE * radius_out;
} probe_internal_t;
/*
 * List of packets for a thread
 */
#define MAX_CACHE_SIZE 300002
struct smp_thread {
    int thread_number;
    mmt_handler_t *mmt_handler;
    probe_internal_t iprobe;
    uint32_t queue_plen;
    uint32_t queue_blen;
    pthread_t handle; /* thread handle */
    pthread_spinlock_t lock; /* lock for concurrent access */
    struct smp_pkt pkt_head; /* pointer on first packet */
    struct smp_pkt null_pkt; /* Null packet used to indicate end of packet feeding for the thread. */
    time_t last_stat_report_time;
    time_t last_msg_report_time;
    int check_timer;
    uint64_t report_counter;
    mmt_event_report_t * event_reports;
    char *cache_message_list[ MAX_CACHE_SIZE ];
    int cache_count;
    
    data_spsc_ring_t fifo;
    uint64_t nb_packets, nb_dropped_packets;
};



typedef struct mmt_probe_struct {
    struct smp_thread * smp_threads;
    pthread_t timer_handler;
    //mmt_handler_t *mmt_handler; //For single threaded operations
    mmt_probe_context_t * mmt_conf;
    probe_internal_t iprobe;
    uint64_t packets_nb;
}mmt_probe_struct_t;

void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code, const char * log_msg);
void init_redis (char * hostname, int port);
void proto_stats_init(void * handler);
void proto_stats_cleanup(void * handler);
void flowstruct_init(void * handler);
void flowstruct_cleanup(void * handler);
void radius_ext_init(void * args);
void radius_ext_cleanup(void * handler);
void event_reports_init(void * args);
void conditional_reports_init(void * handler);
void security_event( int prop_id, char *verdict, char *type, char *cause, char *history , struct timeval packet_timestamp, void * user_args);
void protocols_stats_iterator(uint32_t proto_id, void * args);
void send_message_to_file (char * message);
void send_message_to_file_thread (char * message, void *args);
void send_message_to_redis (char *channel, char * message);
int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest);
int is_local_net(int addr);
int is_localv6_net(char * addr);

int register_event_report_handle(void * args);
uint32_t get_2_power(uint32_t nb);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
//void write_data_to_file (const ipacket_t * ipacket,const char * path, const char * content, int len, uint32_t * file_size);
uint32_t is_microflow(const mmt_session_t * expired_session);
uint32_t is_microflow_stats_reportable(microsessions_stats_t * stats);
void report_microflows_stats(microsessions_stats_t * stats, void *args);
void update_microflows_stats(microsessions_stats_t * stats, const mmt_session_t * expired_session);
void reset_microflows_stats(microsessions_stats_t * stats);
void report_all_protocols_microflows_stats(void *args);
int license_expiry_check(int status);
void parseOptions(int argc, char ** argv, mmt_probe_context_t * mmt_conf);
void todo_at_start(char *file_path);
//void reconstruct_data(const ipacket_t * ipacket );
void todo_at_end();
void init_mmt_security(mmt_handler_t *mmt_handler, char * property_file, void *args);
void exit_timers();
void flush_messages_to_file_thread( void *);
int start_timer( uint32_t period, void *callback, void *user_data);
struct timeval mmt_time_diff(struct timeval tstart, struct timeval tend);

void register_ftp_attributes(void * handler);

//handlers
void ftp_file_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_response_code_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_file_size_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_response_value_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_packet_request_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_password_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_user_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_data_direction_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ftp_session_connection_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void http_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void xcdn_seen_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void useragent_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void referer_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void http_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void host_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void mime_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void rtp_version_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void rtp_jitter_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void rtp_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void rtp_order_error_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void rtp_burst_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void uri_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void tcp_fin_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void print_http_request_response_report(const mmt_session_t * session, void *user_args);
void ip_rtt_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void content_len_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
void flush_messages_to_file_thread( void *arg);
void iterate_session( void *arg);
void throughput(const mmt_session_t * session,session_struct_t * temp_session,int keep_direction, double throughput []);

//prototypes
//void reset_rtp (const ipacket_t * ipacket,mmt_session_t * rtp_session,session_struct_t *temp_session);
void print_web_app_format(const mmt_session_t * expired_session, void *args);
void print_ssl_app_format(const mmt_session_t * expired_session, void *args);
void print_rtp_app_format(const mmt_session_t * expired_session, void *args);
void print_ftp_app_format(const mmt_session_t * expired_session, void *args);
void print_default_app_format(const mmt_session_t * expired_session, void *args);
void print_ip_session_report (const mmt_session_t * session, void *user_args);
void print_initial_web_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);
void print_initial_rtp_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);
void print_initial_ssl_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);
void print_initial_ftp_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);
void print_initial_default_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);

int get_protocol_index_from_session(const proto_hierarchy_t * proto_hierarchy, uint32_t proto_id);


int register_conditional_report_handle(void * handler, mmt_condition_report_t * condition_report);

mmt_probe_context_t * get_probe_context_config();

mmt_dev_properties_t get_dev_properties_from_user_agent(char * user_agent, uint32_t len);
/*
 ** Translation Table as described in RFC1113
 */
static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//static char lock_file [256+1]={0};
/*
 ** encodeblock
 **
 ** encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
inline void encodeblock(unsigned char in[3], unsigned char out[4], int len);

/*
 ** encode
 **
 ** base64 encode a string.
 */
inline int encode_str(const char *infile, char *outfile);

int time_diff(struct timeval t1, struct timeval t2);

void classification_expiry_session(const mmt_session_t * expired_session, void * args);

#ifdef	__cplusplus
}
#endif

#endif	/* PROCESSING_H */
