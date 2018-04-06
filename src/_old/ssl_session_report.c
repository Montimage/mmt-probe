#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

/* This function is called by mmt-dpi for reporting ssl server_name, if an extraction handler is registered */
void ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    mmt_probe_context_t * probe_context = get_probe_context_config();

    if (temp_session != NULL) {
        if (temp_session->app_data == NULL) {
            ssl_session_attr_t * ssl_data = (ssl_session_attr_t *) malloc(sizeof (ssl_session_attr_t));
            if (ssl_data != NULL) {
                memset(ssl_data, '\0', sizeof (ssl_session_attr_t));
                temp_session->app_format_id = MMT_SSL_REPORT_FORMAT;
                temp_session->app_data = (void *) ssl_data;
            } else {
                mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating SSL reporting context");
                //fprintf(stderr, "Out of memory error when creating SSL specific data structure!\n");
                return;
            }
        }
        http_line_struct_t * server_name = (http_line_struct_t *) attribute->data;
        if (server_name != NULL && temp_session->app_format_id == MMT_SSL_REPORT_FORMAT) {
            uint16_t max = ((uint16_t) server_name->len > 63) ? 63 : server_name->len;
            strncpy(((ssl_session_attr_t *) temp_session->app_data)->hostname, (char *) server_name->ptr, max);
            ((ssl_session_attr_t *) temp_session->app_data)->hostname[max] = '\0';
        }
    }
    temp_session->contentclass = get_content_class_by_content_flags(get_session_content_flags(ipacket->session));
}

/* This function is for reporting ssl session statistics*/
void print_initial_ssl_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){

    //case 1://missing dev_prop, cdn_flag
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);

    snprintf(&message[valid], MAX_MESS-valid,//missing CDN
            ",%u,%u,%u,\"%s\",%u", // app specific
            temp_session->app_format_id, get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
            temp_session->contentclass,
            (((ssl_session_attr_t *) temp_session->app_data) != NULL) ? ((ssl_session_attr_t *) temp_session->app_data)->hostname : "",
                    (get_session_content_flags(session) & MMT_CONTENT_CDN) ? 2 : 0

    );
    temp_session->session_attr->touched = 1;
}

