#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

/* This function writes a message for default session, for reporting to session report */
void print_initial_default_report(const mmt_session_t * session, session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	snprintf(&message[valid], MAX_MESS-valid,
            ",%u,%u,%u", // app specific
            MMT_DEFAULT_APP_REPORT_FORMAT, get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
            get_content_class_by_content_flags(get_session_content_flags(session))
			);
	 temp_session->session_attr->touched=1;
}

