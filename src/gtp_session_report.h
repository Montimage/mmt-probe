#include <inttypes.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"

#define MAX_NB_TEID 2
typedef struct gtp_session_attr_struct{
	uint32_t teids[ MAX_NB_TEID ];
	uint8_t ip_version;
	mmt_ipv4_ipv6_id_t ip_src;
	mmt_ipv4_ipv6_id_t ip_dst;
}gtp_session_attr_t;

void gtp_ip_src_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args);
gtp_session_attr_t * get_gtp_session_data( const ipacket_t *ipacket );

void gtp_update_data( const ipacket_t *ipacket, gtp_session_attr_t *gtp_data);

void print_initial_gtp_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid);
