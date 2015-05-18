#ifndef PROCESSING_H
#define	PROCESSING_H

#ifdef	__cplusplus
extern "C" {
#endif

#define ONLINE_ANALYSIS 0x1
#define OFFLINE_ANALYSIS 0x2
#define OFFLINE_ANALYSIS_CONTINUOUS 0x3 

#define MMT_STATISTICS_REPORT_FORMAT    0x63 //decimal 99
#define MMT_RADIUS_REPORT_FORMAT    0x9
#define MMT_MICROFLOWS_STATS_FORMAT 0x8
#define MMT_FLOW_REPORT_FORMAT      0x7

#define MMT_SKIP_APP_REPORT_FORMAT      0xFFFFFFFF //This is mainly to skip the reporting of flows of specific applications.
#define MMT_DEFAULT_APP_REPORT_FORMAT   0x0
#define MMT_WEB_APP_REPORT_FORMAT       0x1
#define MMT_SSL_APP_REPORT_FORMAT       0x2
#define MMT_RTP_APP_REPORT_FORMAT       0x3

#define MMT_RADIUS_REPORT_ALL 0x0
#define MMT_RADIUS_REPORT_MSG 0x1

#define MMT_RADIUS_ANY_CONDITION 0x0
#define MMT_RADIUS_IP_MSISDN_PRESENT 0x1

#define MMT_USER_AGENT_THRESHOLD 0x20 //32KB

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
        char radius_out[256 + 1];
        char input_f_name[256 + 1]; 
        char out_f_name[256 + 1];
        char out_f_name_index[256 + 1];
        FILE * data_out_file;
        int combine_radius;
        FILE * radius_out_file;
        FILE * log_output;
        uint32_t log_level;
        
        uint32_t enable_proto_stats;
        uint32_t enable_flow_stats;

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
        uint32_t nb_loss_bursts; //metric
    } rtp_session_attr_t;

    typedef struct web_session_attr_struct {
        struct timeval first_request_time;
        struct timeval response_time;
        struct timeval interaction_time;
        char mimetype[64];
        char hostname[96];
        char referer[64];
        char useragent[64];
        uint8_t has_referer : 1, has_useragent : 1, xcdn_seen : 1, seen_response : 1;
        uint8_t trans_nb;
    } web_session_attr_t;

    typedef struct ssl_session_attr_struct {
        char hostname[64];
    } ssl_session_attr_t;

    typedef struct session_struct {
        uint16_t format_id;
        uint16_t app_format_id;
        //struct timeval start_time;
        //struct timeval end_time;
        mmt_ipv4_ipv6_id_t ipclient;
        mmt_ipv4_ipv6_id_t ipserver;
        uint16_t clientport;
        uint16_t serverport;
        uint8_t proto;
        uint8_t isFlowExtracted;
        uint8_t isClassified;
        uint8_t ipversion;
        uint32_t contentclass;

        void * app_data;
    } session_struct_t;

    typedef struct probe_internal_struct {
        uint32_t instance_id;
        microsessions_stats_t mf_stats[PROTO_MAX_IDENTIFIER];
        //FILE * data_out;
        //FILE * radius_out;
    } probe_internal_t;

    //session_struct_t * flows;

    void init_redis (char * hostname, int port);
    void proto_stats_init(void * handler);
    void proto_stats_cleanup(void * handler);
    void flowstruct_init(void * handler);
    void flowstruct_cleanup(void * handler);
    void radius_ext_init(void * handler);
    void radius_ext_cleanup(void * handler);
    void init_session_structs();
    void print_session_structs();
    void report_microflows_stats(microsessions_stats_t * stats, FILE * out_file);
    void reset_microflows_stats(microsessions_stats_t * stats);
    void report_all_protocols_microflows_stats(probe_internal_t * iprobe);

    void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code, const char * log_msg);

    mmt_probe_context_t * get_probe_context_config();

    mmt_dev_properties_t get_dev_properties_from_user_agent(char * user_agent, uint32_t len);
    /*
     ** Translation Table as described in RFC1113
     */
    static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
