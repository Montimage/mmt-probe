#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip.h"
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h> //inet_ntop
#include <netinet/in.h>
#endif

#ifdef _WIN32
#include <time.h>
#include <windows.h>
#endif

#include "processing.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>


#ifdef _WIN32
#ifndef socklen_t
typedef int socklen_t;
#define socklen_t socklen_t
#endif
#endif

#if (_WIN32_WINNT)
void WSAAPI freeaddrinfo(struct addrinfo*);
int WSAAPI getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
int WSAAPI getnameinfo(const struct sockaddr*, socklen_t, char*, DWORD, char*, DWORD, int);
#endif

#ifdef _WIN32

const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt) {
    if (af == AF_INET) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof (in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof (struct in_addr));
        getnameinfo((struct sockaddr *) &in, sizeof (struct
                sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    } else if (af == AF_INET6) {
        struct sockaddr_in6 in;
        memset(&in, 0, sizeof (in));
        in.sin6_family = AF_INET6;
        memcpy(&in.sin6_addr, src, sizeof (struct in_addr6));
        getnameinfo((struct sockaddr *) &in, sizeof (struct
                sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    }
    return NULL;
}
#endif

int is_localv6_net(char * addr) {

    if (strncmp(addr,"fec0",4)==0)return 1;
    if (strncmp(addr,"fc00",4)==0)return 1;
    if (strncmp(addr,"fe80",4)==0)return 1;

    return 0;
}

int is_local_net(int addr) {


    if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
        return 1;
    }
    if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xC0000000 /* 192.0.0.0 */) {
        return 1;
    }
    if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xAC000000 /* 172.0.0.0 */) {
        return 1;
    }
    if ((ntohl(addr) & 0xFF000000 /* 255.0.0.0 */) == 0xA9000000 /* 169.0.0.0 */) {
        return 1;
    }

    return 0;
}

void mmt_log(mmt_probe_context_t * mmt_conf, int level, int code, const char * log_msg) {
    if (level >= mmt_conf->log_level) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        FILE * log_file = (mmt_conf->log_output != NULL) ? mmt_conf->log_output : stdout;
        fprintf(log_file, "%i\t%lu\t%i\t[%s]\n", level, tv.tv_sec, code, log_msg);
        fflush(log_file);
    }
}

int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%u", proto_hierarchy->proto_path[index]);
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%u", proto_hierarchy->proto_path[index]);
        }
    }
    return offset;
}

int get_protocol_index_from_session(const proto_hierarchy_t * proto_hierarchy, uint32_t proto_id) {
    int index = 0;
    for (; index < proto_hierarchy->len && index < 16; index++) {
        if (proto_hierarchy->proto_path[index] == proto_id) return index;
    }
    return -1;
}

static mmt_probe_context_t probe_context = {0};

mmt_probe_context_t * get_probe_context_config() {
    return & probe_context;
}


void packet_handler(const ipacket_t * ipacket, void * args) {
    static time_t last_report_time = 0;

    ip_get_session_attr( ipacket );

    if (last_report_time == 0) {
        last_report_time = ipacket->p_hdr->ts.tv_sec;
        return;
    }


    if (probe_context.ftp_reconstruct_enable==1)
        reconstruct_data(ipacket);

    //ftp_packet_events(ipacket);

    printf("ipacket_id=%lu\n",ipacket->packet_id);
    if ((ipacket->p_hdr->ts.tv_sec - last_report_time) >= probe_context.stats_reporting_period) {
        iterate_through_protocols(protocols_stats_iterator, (void *) ipacket->mmt_handler);

        iterate_through_ip( ipacket->mmt_handler );

        last_report_time = ipacket->p_hdr->ts.tv_sec;
    }
}

void flow_nb_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    mmt_session_t * session = get_session_from_packet(ipacket);
    if(session == NULL) return;
    //fprintf(stdout, "Test from new flow\n");

    if (attribute->data == NULL) {
        return; //This should never happen! check it anyway
    }

    session_struct_t *temp_session = malloc(sizeof (session_struct_t));

    if (temp_session == NULL) {
        mmt_log(&probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating new flow reporting context");
        //fprintf(stderr, "Memory allocation failed when creating a new file reporting struct! This flow will be ignored! Sorry!");
        return;
    }

    memset(temp_session, '\0', sizeof (session_struct_t));

    temp_session->format_id = MMT_FLOW_REPORT_FORMAT;
    temp_session->app_format_id = MMT_DEFAULT_APP_REPORT_FORMAT;

    if (temp_session->isFlowExtracted)
        return;

    // Flow extraction
    int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
    //printf("IP index = %i\n", ipindex);
    //Process IPv4 flows
    if (ipindex != -1) {

        uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
        uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);

        if (ip_src) {
            //printf("HAS IP ADDRESS \n");
            temp_session->ipclient.ipv4 = (*ip_src);
        }
        if (ip_dst) {
            temp_session->ipserver.ipv4 = (*ip_dst);
        }

        uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);
        if (proto_id != NULL) {
            temp_session->proto = *proto_id;
        } else {
            temp_session->proto = 0;
        }
        temp_session->ipversion = 4;
        uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
        uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
        if (cport) {
            temp_session->clientport = *cport;
        }
        if (dport) {
            temp_session->serverport = *dport;
        }

    } else {
        void * ipv6_src = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
        void * ipv6_dst = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
        if (ipv6_src) {
            memcpy(&temp_session->ipclient.ipv6, ipv6_src, 16);
        }
        if (ipv6_dst) {
            memcpy(&temp_session->ipserver.ipv6, ipv6_dst, 16);
        }

        uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_NEXT_PROTO);
        if (proto_id != NULL) {
            temp_session->proto = *proto_id;
        } else {
            temp_session->proto = 0;
        }
        temp_session->ipversion = 6;
        uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
        uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
        if (cport) {
            temp_session->clientport = *cport;
        }
        if (dport) {
            temp_session->serverport = *dport;
        }
    }

    temp_session->isFlowExtracted = 1;

    set_user_session_context(session, temp_session);
}

void proto_stats_init(void * handler) {
    register_packet_handler(handler, 5, packet_handler, NULL);
}

void proto_stats_cleanup(void * handler) {
    iterate_through_protocols(protocols_stats_iterator, handler);
    (void) unregister_packet_handler((mmt_handler_t *) handler, 1);
}

void flowstruct_init(void * handler) {
    int i = 1;
    i &= register_extraction_attribute(handler, PROTO_TCP, TCP_SRC_PORT);
    i &= register_extraction_attribute(handler, PROTO_TCP, TCP_DEST_PORT);
    i &= register_extraction_attribute(handler, PROTO_UDP, UDP_SRC_PORT);
    i &= register_extraction_attribute(handler, PROTO_UDP, UDP_DEST_PORT);

    i &= register_extraction_attribute(handler, PROTO_ETHERNET, ETH_DST);
    i &= register_extraction_attribute(handler, PROTO_ETHERNET, ETH_SRC);
    i &= register_extraction_attribute(handler, PROTO_IP, IP_SRC);
    i &= register_extraction_attribute(handler, PROTO_IP, IP_DST);
    i &= register_extraction_attribute(handler, PROTO_IP, IP_PROTO_ID);
    i &= register_extraction_attribute(handler, PROTO_IP, IP_SERVER_PORT);
    i &= register_extraction_attribute(handler, PROTO_IP, IP_CLIENT_PORT);

    i &= register_extraction_attribute(handler, PROTO_IPV6, IP6_NEXT_PROTO);
    i &= register_extraction_attribute(handler, PROTO_IPV6, IP6_SRC);
    i &= register_extraction_attribute(handler, PROTO_IPV6, IP6_DST);
    i &= register_extraction_attribute(handler, PROTO_IPV6, IP6_SERVER_PORT);
    i &= register_extraction_attribute(handler, PROTO_IPV6, IP6_CLIENT_PORT);

    i &= register_attribute_handler(handler, PROTO_IP, PROTO_SESSION, flow_nb_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle, NULL, NULL);

    register_web_attributes(handler);
    register_rtp_attributes(handler);
    register_ftp_attributes(handler);
    register_ssl_attributes(handler);

    if(!i) {
        //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
        fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
    }
}

void flowstruct_cleanup(void * handler) {
}



/*
 ** encodeblock
 **
 ** encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
inline void encodeblock(unsigned char in[3], unsigned char out[4], int len) {
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
 ** encode
 **
 ** base64 encode a string.
 */
inline int encode_str(const char *infile, char *out_file) {
    unsigned char in[3], out[4];
    int i, len;
    int copiedBytes = 0;
    while (infile[0] != '\0') {
        len = 0;
        for (i = 0; i < 3; i++) {
            in[i] = infile[0];
            if (infile[0] != '\0') {
                len++;
            } else {
                in[i] = 0;
            }
            infile++;
        }
        if (len) {
            encodeblock(in, out, len);
            for (i = 0; i < 4; i++) {
                out_file[copiedBytes] = out[i];
                copiedBytes++;
            }
        }
    }
    out_file[copiedBytes] = '\0';
    return copiedBytes;
}

int time_diff(struct timeval t1, struct timeval t2) {
    return (((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec)) / 1000;
}

void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
    session_struct_t * temp_session = get_user_session_context(expired_session);
    if (temp_session == NULL) {
        return;
    }
    probe_internal_t * iprobe = (probe_internal_t *) args;

    int sslindex;

    if (is_microflow(expired_session)) {
        microsessions_stats_t * mf_stats = &iprobe->mf_stats[get_session_protocol_hierarchy(expired_session)->proto_path[(get_session_protocol_hierarchy(expired_session)->len <= 16)?(get_session_protocol_hierarchy(expired_session)->len - 1):(16 - 1)]];
        update_microflows_stats(mf_stats, expired_session);
        if (is_microflow_stats_reportable(mf_stats)) {
            report_microflows_stats(mf_stats);
        }
    } else {
        //First we check if we should skip the reporting for this flow
        if (temp_session->app_format_id != MMT_SKIP_APP_REPORT_FORMAT) {
            //We should report this flow.
            switch (temp_session->app_format_id) {
            case MMT_WEB_APP_REPORT_FORMAT:
                print_web_app_format(expired_session, iprobe);
                break;
            case MMT_SSL_APP_REPORT_FORMAT:
                print_ssl_app_format(expired_session, iprobe);
                break;
            case MMT_RTP_APP_REPORT_FORMAT:
                print_rtp_app_format(expired_session, iprobe);
                break;
            case MMT_FTP_DOWNLOAD_REPORT_FORMAT:
                break;
            default:
                sslindex = get_protocol_index_from_session(get_session_protocol_hierarchy(expired_session), PROTO_SSL);
                if (sslindex != -1) print_ssl_app_format(expired_session, iprobe);
                else print_default_app_format(expired_session,iprobe);
                break;
            }
        }
    }

    if (temp_session->app_data != NULL) {
        //Free the application specific data
        free(temp_session->app_data);
    }
    free(temp_session);
}

mmt_dev_properties_t get_dev_properties_from_user_agent(char * user_agent, uint32_t len) {
    mmt_dev_properties_t retval = {0};
    if ((len > 8) && (mmt_strncasecmp(user_agent, "Mozilla/", 8) == 0)) {
        if ((len > 20) && (mmt_strncasecmp(&user_agent[12], "(iPhone;", 8) == 0)) {
            retval.os_id = OS_IOS;
            retval.dev_id = DEV_IPHONE;
        } else if ((len > 18) && (mmt_strncasecmp(&user_agent[12], "(iPod;", 6) == 0)) {
            retval.os_id = OS_IOS;
            retval.dev_id = DEV_IPOD;
        } else if ((len > 18) && (mmt_strncasecmp(&user_agent[12], "(iPad;", 6) == 0)) {
            retval.os_id = OS_IOS;
            retval.dev_id = DEV_IPAD;
        } else if ((len > 30) && (mmt_strncasecmp(&user_agent[12], "(Linux; U; Android", 18) == 0)) {
            retval.os_id = OS_AND;
            retval.dev_id = DEV_MOB;
        } else if ((len > 20) && (mmt_strncasecmp(&user_agent[12], "(Android", 8) == 0)) {
            retval.os_id = OS_AND;
            retval.dev_id = DEV_MOB;
        } else if ((len > 24) && (mmt_strncasecmp(&user_agent[12], "(BlackBerry;", 12) == 0)) {
            retval.os_id = OS_BLB;
            retval.dev_id = DEV_BLB;
        } else if ((len > 17) && (mmt_strncasecmp(&user_agent[12], "(X11;", 5) == 0)) {
            retval.os_id = OS_NUX;
            retval.dev_id = DEV_PC;
        } else if ((len > 23) && (mmt_strncasecmp(&user_agent[12], "(Macintosh;", 11) == 0)) {
            retval.os_id = OS_MAC;
            retval.dev_id = DEV_MAC;
        } else if ((len > 29) && (mmt_strncasecmp(&user_agent[12], "(Windows; U; MSIE", 17) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        } else if ((len > 23) && (mmt_strncasecmp(&user_agent[12], "(Windows NT", 11) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        } else if ((len > 35) && (mmt_strncasecmp(&user_agent[12], "(Windows; U; Windows NT", 23) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        } else if ((len > 36) && (mmt_strncasecmp(&user_agent[12], "(compatible; Windows; U;", 24) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        } else if ((len > 46) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 10.0; Macintosh;", 34) == 0)) {
            retval.os_id = OS_MAC;
            retval.dev_id = DEV_MAC;
        } else if ((len > 48) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 9.0; Windows Phone", 36) == 0)) {
            retval.os_id = OS_WPN;
            retval.dev_id = DEV_MOB;
        } else if ((len > 56) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE 10.0; Windows NT 6.2; ARM;", 44) == 0)) {
            retval.os_id = OS_WPN;
            retval.dev_id = DEV_MOB;
        } else if ((len > 29) && (mmt_strncasecmp(&user_agent[12], "(compatible; MSIE", 17) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        }
    } else if ((len > 6) && (mmt_strncasecmp(user_agent, "Opera/", 6) == 0)) {
        if ((len > 19) && (mmt_strncasecmp(&user_agent[11], "(Windows", 8) == 0)) {
            retval.os_id = OS_WIN;
            retval.dev_id = DEV_PC;
        } else if ((len > 22) && (mmt_strncasecmp(&user_agent[11], "(Macintosh;", 11) == 0)) {
            retval.os_id = OS_MAC;
            retval.dev_id = DEV_MAC;
        } else if ((len > 16) && (mmt_strncasecmp(&user_agent[11], "(X11;", 5) == 0)) {
            retval.os_id = OS_NUX;
            retval.dev_id = DEV_PC;
        }
    }
    return retval;
}
