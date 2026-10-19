/*
 * session_report.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#define BEHAVIOUR_REPORT_ID 101

#include <arpa/inet.h>
#include "session_report.h"


#include "../../../lib/string_builder.h"
#include "../../../lib/log.h"
#include "../../../lib/inet.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

//functions implemented by session_report_xxx.c
int print_web_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_ssl_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_ftp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_rtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_gtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);

static inline bool _is_zero_mac(const uint8_t *mac) {
	if (!mac) return true;
	return mac[0]==0 && mac[1]==0 && mac[2]==0 && mac[3]==0 && mac[4]==0 && mac[5]==0;
}
static inline bool _is_broadcast_mac(const uint8_t *mac) {
	if (!mac) return false;
	return mac[0]==0xff && mac[1]==0xff && mac[2]==0xff && mac[3]==0xff && mac[4]==0xff && mac[5]==0xff;
}

// Find first occurrence of proto_id in packet hierarchy, -1 if absent
static inline int _eth_first_proto_index(const ipacket_t *ipacket, uint32_t proto_id) {
	if (!ipacket || !ipacket->proto_hierarchy) return -1;
	for (int i = 0; i < ipacket->proto_hierarchy->len; i++)
		if (ipacket->proto_hierarchy->proto_path[i] == (int)proto_id)
			return i;
	return -1;
}

// Resolve the ethertype (host order, e.g. 0x8892) that produced the UNKNOWN
// terminal at unknown_idx in the packet hierarchy:
// - parent ETH (99): use extracted ETH_PROTOCOL attribute
// - parent VLAN (7) / 8021AD (656): read inner ethertype bytes (header + 2)
// Returns 0 when unavailable (then no suffix is appended).
static inline uint16_t _eth_unknown_ethertype(const ipacket_t *ipacket, int unknown_idx) {
	if (!ipacket || unknown_idx <= 0 || !ipacket->proto_hierarchy) return 0;
	if (unknown_idx >= ipacket->proto_hierarchy->len) return 0;
	if (ipacket->proto_hierarchy->proto_path[unknown_idx] != PROTO_UNKNOWN) return 0;
	int parent_idx = unknown_idx - 1;
	int parent_id = ipacket->proto_hierarchy->proto_path[parent_idx];
	if (parent_id == PROTO_ETHERNET) {
		uint16_t *ethertype = (uint16_t *) get_attribute_extracted_data_at_index(
				ipacket, PROTO_ETHERNET, ETH_PROTOCOL, parent_idx);
		if (ethertype) return *ethertype; // already host order (ntohs at extraction)
		return 0;
	}
	if (parent_id == PROTO_8021Q || parent_id == PROTO_8021AD) {
		int voff = get_packet_offset_at_index(ipacket, parent_idx);
		// VLAN header: TPID(2) + TCI(2), inner ethertype follows at +2..+3
		// (mmt_vlan_struct.code + h_proto, see proto_8021q.c)
		if (voff >= 0 && ipacket->p_hdr && voff + 4 <= (int)ipacket->p_hdr->caplen) {
			uint16_t v;
			memcpy(&v, &ipacket->data[voff + 2], sizeof(v));
			return ntohs(v);
		}
	}
	return 0;
}

// Effective hierarchy length for per-packet decisions.
// ipacket->proto_hierarchy may be repointed to a shared DPI session path
// (packet_processing.c:2580) whose tail is stale: a previous longer packet
// (e.g. GTP.ETH.VLAN.UNKNOWN, len 8) leaves trailing elements that the
// current shorter packet (e.g. GTP.ETH.PTP, len 7) never classified, yet the
// session path still shows them (observed "...99.508.0" for a PTP packet).
// A trailing UNKNOWN can never be genuine when its parent has no
// classifier producing children (ARP, PTP, UNKNOWN itself); drop such
// tails. Never mutates the shared hierarchy, only returns a shorter length.
static inline int _eth_effective_len(const proto_hierarchy_t *hier) {
	if (!hier) return 0;
	int len = hier->len;
	while (len >= 3
			&& hier->proto_path[len - 1] == PROTO_UNKNOWN
			&& (hier->proto_path[len - 2] == PROTO_ARP
				|| hier->proto_path[len - 2] == PROTO_PTP
				|| hier->proto_path[len - 2] == PROTO_UNKNOWN))
		len--;
	return len;
}

// Append ".high.low" of a host-order ethertype to a path string buffer.
// dest holds a NUL-terminated string of length *len_inout, capacity dest_size.
// Ugly: raw ethertype bytes share the proto-id namespace (e.g. 0x8892 shows
// as 136.146), but this is what downstream expects (profinet = 99.0.136.146).
// Never touches an empty path: a bare ".136.146" is not a valid protocol path.
static inline void _eth_append_suffix(char *dest, size_t dest_size, size_t *len_inout, uint16_t ethertype) {
	if (!dest || !len_inout || ethertype == 0) return;
	size_t len = *len_inout;
	if (len == 0 || dest[0] == '\0') return; // no base path: nothing to extend
	if (len + 8 >= dest_size) return; // need room for ".255.255" + NUL
	len += append_char(dest + len, dest_size - len, '.');
	len += append_number(dest + len, dest_size - len, (ethertype >> 8) & 0xFF);
	len += append_char(dest + len, dest_size - len, '.');
	len += append_number(dest + len, dest_size - len, ethertype & 0xFF);
	dest[len] = '\0';
	*len_inout = len;
}

// Index of the first PROTO_GTP layer of a hierarchy, -1 if not GTP.
// Used to cut an outer GTP session path at ".141" so that the outer row never
// advertises an inner protocol stack (see _path_ids_to_str_outside_gtp).
static inline int _path_first_gtp_index(const proto_hierarchy_t *hier) {
	if (!hier) return -1;
	for (uint32_t i = 0; i < hier->len; i++)
		if (hier->proto_path[i] == PROTO_GTP) return (int) i;
	return -1;
}

// Do two protocol hierarchies agree? Compares element by element over the
// common depth: one direction of a session can lag one protocol behind (or be
// missing altogether), which is fine, but they must never contradict each
// other. Used to keep the ul/dl paths of a single report row overlapping
// ("might different length, not branch out").
static inline bool _hier_overlap(const proto_hierarchy_t *a, const proto_hierarchy_t *b) {
	if (!a || !b || a->len == 0 || b->len == 0) return false;
	uint32_t n = (a->len < b->len) ? a->len : b->len;
	return memcmp(a->proto_path, b->proto_path, n * sizeof(int)) == 0;
}

// Render a hierarchy to a string, cutting it right after PROTO_GTP when the
// caller asks for it (truncated_out != NULL) and the hierarchy is an *outer*
// GTP session path. The inner protocol stack (ETH/VLAN/UNKNOWN/TCP/... after
// the tunnel) is reported by the inner rows instead, so the outer row stays
// stable at e.g. "99.178.376.141". Callers that pass truncated_out == NULL
// (inner sessions, non GTP) always get the complete hierarchy.
// Returns the rendered length; *truncated_out tells if a cut was applied.
static inline size_t _path_ids_to_str_outside_gtp(const proto_hierarchy_t *hier,
		char *dest, size_t dest_size, bool *truncated_out) {
	if (truncated_out) *truncated_out = false;
	if (!hier) { if (dest_size) dest[0] = '\0'; return 0; }
	int gtp = (truncated_out) ? _path_first_gtp_index(hier) : -1;
	if (gtp < 0)
		return dpi_proto_hierarchy_ids_to_str(hier, dest, dest_size);

	proto_hierarchy_t cut = *hier;
	cut.len = (uint32_t) (gtp + 1);
	*truncated_out = true;
	return dpi_proto_hierarchy_ids_to_str(&cut, dest, dest_size);
}

// Is the hierarchy that of an *outer* GTP session (tunnel present and nothing
// sessionized above it)? Those rows describe the tunnel, not the payload.
static inline bool _path_is_outer_gtp(const proto_hierarchy_t *hier) {
	int gtp = _path_first_gtp_index(hier);
	return gtp >= 0;
}

// Ugly per-packet Ethernet coverage check.
// Returns true when this packet's terminal protocol has NO periodic id=100
// session row covering it, i.e. a dedicated per-packet ETH id=100 row is
// needed. Packets already covered reuse their session rows:
// - terminal IP/IPv6/ARP: own session row exists
// - terminal L4/app with an IP/IPv6/ARP session below (regular TCP, GTP with
//   inner IP): covered by that session row (GTP inner-IP case already yields
//   2 rows: outer + inner)
// - GTP echo (terminal GTP) or empty inner: covered by outer session
// Otherwise (bare ETH terminal like UNKNOWN/PTP/LLC, GTP-inner ETH terminal
// without inner IP/ARP): needs a per-packet row.
// Uses the effective length (stale UNKNOWN tails from shared session paths
// are ignored, see _eth_effective_len).
static inline bool _eth_needs_packet_report(const ipacket_t *ipacket) {
	if (!ipacket || !ipacket->proto_hierarchy) return false;
	const proto_hierarchy_t *hier = ipacket->proto_hierarchy;
	int elen = _eth_effective_len(hier);
	if (elen < 2) return false; // need at least META + something
	// Must contain an Ethernet layer to report (we report MACs)
	if (_eth_first_proto_index(ipacket, PROTO_ETHERNET) < 0) return false;
	int last = hier->proto_path[elen - 1];
	if (last == PROTO_IP || last == PROTO_IPV6 || last == PROTO_ARP) return false;
	int gtp_idx = get_protocol_index_by_id(ipacket, PROTO_GTP);
	if (gtp_idx >= 0) {
		// GTP packet: look only at the inner portion after GTP
		if (elen - 1 <= gtp_idx) return false; // echo / empty inner
		for (int i = gtp_idx + 1; i < elen; i++) {
			int pid = hier->proto_path[i];
			if (pid == PROTO_IP || pid == PROTO_IPV6 || pid == PROTO_ARP)
				return false; // inner IP/ARP session row exists
		}
		return true; // inner terminal (UNKNOWN/PTP/...) uncovered
	}
	// Non-GTP: covered if any IP/IPv6/ARP session exists below terminal
	for (int i = 0; i < elen - 1; i++) {
		int pid = hier->proto_path[i];
		if (pid == PROTO_IP || pid == PROTO_IPV6 || pid == PROTO_ARP)
			return false;
	}
	return true;
}


static inline void _write_behaviour_report( file_output_t *output,
		int probe_id,
		const char *input_src,
		const struct timeval *timestamp,
		int proto_id,
		const char *ip_src,
		const char *ip_dst,
		uint64_t ul_volume,
		uint64_t dl_volume
		){

	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( BEHAVIOUR_REPORT_ID ),
			__INT( probe_id ),
			__STR( input_src ),
			__TIME( timestamp ),
			__INT( proto_id ),
			__INT( ul_volume ),
			__INT( dl_volume ),
			__STR( ip_src ),
			__STR( ip_dst )
	);

	file_output_write( output, message );
}


#define _div( a, b ) (b==0? 0 : a/b)

// Ugly per-packet Ethernet id=100 report (see session_report.h).
// One row per uncovered packet: volumes = wire len (inner len for GTP-inner),
// packets = 1, payload = 0, ports = 0, QoS = 0, format = 0, IPs empty.
// MACs: inner ETH (first ETH after GTP) when GTP present, else first ETH.
void session_report_emit_uncovered_eth_report(const ipacket_t * ipacket, dpi_context_t *context ){
	if (!ipacket || !context || !ipacket->proto_hierarchy) return;
	if (!_eth_needs_packet_report(ipacket)) return;

	const proto_hierarchy_t *hier = ipacket->proto_hierarchy;
	// Work on a truncated copy: the shared session path may carry stale
	// trailing UNKNOWNs from previous longer packets (see _eth_effective_len)
	proto_hierarchy_t eff_hier;
	memcpy(&eff_hier, hier, sizeof(eff_hier));
	eff_hier.len = _eth_effective_len(hier);
	int proto_id = eff_hier.proto_path[eff_hier.len - 1];

	char path[160];
	size_t path_len = dpi_proto_hierarchy_ids_to_str(&eff_hier, path, sizeof(path));
	if (proto_id == PROTO_UNKNOWN)
		_eth_append_suffix(path, sizeof(path), &path_len,
				_eth_unknown_ethertype(ipacket, eff_hier.len - 1));

	// MAC context: inner ETH for GTP, else first ETH
	int gtp_idx = get_protocol_index_by_id(ipacket, PROTO_GTP);
	int eth_idx = -1;
	if (gtp_idx >= 0) {
		for (int i = gtp_idx + 1; i < hier->len; i++)
			if (hier->proto_path[i] == PROTO_ETHERNET) { eth_idx = i; break; }
	}
	if (eth_idx < 0) eth_idx = _eth_first_proto_index(ipacket, PROTO_ETHERNET);
	uint8_t *mac_src = NULL, *mac_dst = NULL;
	if (eth_idx >= 0) {
		mac_src = (uint8_t *) get_attribute_extracted_data_at_index(
				ipacket, PROTO_ETHERNET, ETH_SRC, eth_idx);
		mac_dst = (uint8_t *) get_attribute_extracted_data_at_index(
				ipacket, PROTO_ETHERNET, ETH_DST, eth_idx);
	}
	if (!mac_src)
		mac_src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
	if (!mac_dst)
		mac_dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
	uint8_t zero_mac[6] = {0,0,0,0,0,0};
	if (!mac_src) mac_src = zero_mac;
	if (!mac_dst) mac_dst = zero_mac;

	// Volume: inside the tunnel for GTP-inner, full wire otherwise
	uint64_t vol = ipacket->p_hdr ? ipacket->p_hdr->len : 0;
	if (gtp_idx >= 0 && gtp_idx + 1 < hier->len) {
		int inner_off = get_packet_offset_at_index(ipacket, gtp_idx + 1);
		if (inner_off >= 0 && ipacket->p_hdr && inner_off < (int)ipacket->p_hdr->len)
			vol = ipacket->p_hdr->len - inner_off;
	}
	uint8_t dir = DIRECTION_UPLOAD;
	if (ipacket->session)
		dir = !!get_session_last_packet_direction(ipacket->session);
	uint64_t ul_vol = (dir == DIRECTION_UPLOAD) ? vol : 0;
	uint64_t dl_vol = (dir == DIRECTION_UPLOAD) ? 0 : vol;
	uint64_t ul_pkts = (dir == DIRECTION_UPLOAD) ? 1 : 0;
	uint64_t dl_pkts = (dir == DIRECTION_UPLOAD) ? 0 : 1;

	struct timeval ts = {0, 0};
	if (ipacket->p_hdr) ts = ipacket->p_hdr->ts;
	uint64_t total_active_sessions = get_active_session_count(context->dpi_handler);
	uint64_t session_id = ipacket->session ? get_session_id(ipacket->session) : 0;

	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int valid = 0;
#ifdef SIMPLE_REPORT
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( context->stat_periods_index ),
			__INT( proto_id ),
			__STR( path ),
			__INT( ul_vol ),
			__INT( dl_vol ),
			__STR( "" ),
			__STR( "" ),
			__MAC( mac_src ),
			__MAC( mac_dst ),
			__INT( 0 ),
			__INT( 0 )
	);
#else
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
		__INT( context->stat_periods_index),
		__INT( proto_id),
		__STR( path),
		__STR( path),
		__INT( total_active_sessions),
		__INT( vol),
		__INT( 0 ),
		__INT( 1 ),
		__INT( ul_vol),
		__INT( 0 ),
		__INT( ul_pkts),
		__INT( dl_vol),
		__INT( 0 ),
		__INT( dl_pkts),
		__TIME( &ts ),
		__STR( "" ),
		__STR( "" ),
		__MAC( mac_src ),
		__MAC( mac_dst),
		__INT( session_id ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( context->worker_index),
	#ifdef QOS_MODULE
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
		__INT( 0 ),
	#else
		__ARR( "0,0,0,0,0,0,0,0,0,0,0" ),
	#endif
		__INT( 0 ),
		__INT( get_application_class_by_protocol_id( proto_id )),
		__INT( 0 )
	);
#endif

	output_write_report( context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			&ts,
			message );
}

#ifndef SIMPLE_REPORT
//This callback is called by DPI periodically
static inline void _print_ip_session_report (const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context){
	const proto_hierarchy_t *proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = proto_hierarchy->proto_path[proto_hierarchy->len - 1];
	// Whether this session is an ARP session is a property of the session
	// itself, not of its hierarchy leaf: for ARP encapsulated in GTP the outer
	// GTP session also ends on that ARP, but it describes the tunnel and must
	// be reported with the outer counters.
	bool is_arp = session_stat->is_arp_session;
	bool is_inner = session_stat->is_gtp_inner || is_arp;
	uint64_t ul_packets = is_inner ? session_stat->inner_packets.upload : get_session_total_ul_packet_count(dpi_session);
	uint64_t dl_packets = is_inner ? session_stat->inner_packets.download : get_session_total_dl_packet_count(dpi_session);
	uint64_t total_packets = ul_packets + dl_packets;

	// check the condition if in the last interval there was a protocol activity or not
	// => no new packets since the last report times
	if( is_inner ){
		if( total_packets == (session_stat->saved_inner_packets.upload + session_stat->saved_inner_packets.download) )
			return;
	} else {
		if( total_packets == (session_stat->packets.upload + session_stat->packets.download) )
			return;
	}

	uint64_t ul_volumes = is_inner ? session_stat->inner_volumes.upload : get_session_total_ul_byte_count(dpi_session);
	uint64_t dl_volumes = is_inner ? session_stat->inner_volumes.download : get_session_total_dl_byte_count(dpi_session);
	uint64_t total_volumes = ul_volumes + dl_volumes;

	uint64_t ul_payload = is_inner ? session_stat->inner_payload.upload : get_session_total_ul_data_byte_count(dpi_session);
	uint64_t dl_payload = is_inner ? session_stat->inner_payload.download : get_session_total_dl_data_byte_count(dpi_session);
	uint64_t total_payload = ul_payload + dl_payload;


	char path_ul[160], path_dl[160], ref_path[160];

	// An outer GTP session describes the tunnel only: its per-direction path
	// is cut right after PROTO_GTP (".141"), so the row never advertises the
	// inner protocol stack (which is reported by the inner rows). Without
	// this the row path follows the last inner packet classified on this
	// shared session and can show a completely unrelated stack (a PTP packet
	// reported as "..99.178.354.0", or a stale VLAN tail "..99.7.0" on a
	// TCP packet).
	bool outer_gtp = !is_inner && _path_is_outer_gtp(proto_hierarchy);
	const proto_hierarchy_t *hier_ul = get_session_proto_path_direction( dpi_session, 1 );
	const proto_hierarchy_t *hier_dl = get_session_proto_path_direction( dpi_session, 0 );
	bool ul_cut = false, dl_cut = false;
	size_t path_ul_len = _path_ids_to_str_outside_gtp( hier_ul,
			path_ul, sizeof( path_ul), outer_gtp ? &ul_cut : NULL );

	size_t path_dl_len = _path_ids_to_str_outside_gtp( hier_dl,
			path_dl, sizeof( path_dl ), outer_gtp ? &dl_cut : NULL );

	if (outer_gtp) {
		// the cut protocol is the tunnel itself
		int gtp = _path_first_gtp_index(proto_hierarchy);
		proto_id = proto_hierarchy->proto_path[gtp];
	}

	// The two directions of a row must overlap: normally they do (one side is
	// simply one protocol behind), but a direction can also be missing (empty
	// path, which used to produce a bare ".136.146" once the ethertype suffix
	// was appended to it) or hold a stale stack from an earlier packet. When
	// they contradict each other the session's own hierarchy is used for both:
	// proto_id is taken from it, so the row stays self consistent.
	if (!_hier_overlap(hier_ul, hier_dl)) {
		bool ref_cut = false;
		size_t ref_len = _path_ids_to_str_outside_gtp(proto_hierarchy,
				ref_path, sizeof(ref_path), outer_gtp ? &ref_cut : NULL);
		if (ref_len > 0) {
			memcpy(path_ul, ref_path, ref_len + 1);
			memcpy(path_dl, ref_path, ref_len + 1);
			path_ul_len = path_dl_len = ref_len;
		} else if (path_ul_len == 0 && path_dl_len > 0) {
			memcpy(path_ul, path_dl, path_dl_len + 1);
			path_ul_len = path_dl_len;
		} else if (path_dl_len == 0 && path_ul_len > 0) {
			memcpy(path_dl, path_ul, path_ul_len + 1);
			path_dl_len = path_ul_len;
		}
	}

	if (!outer_gtp) {
		// Ugly: append ethertype bytes to UNKNOWN terminals (e.g. 99.0.136.146).
		// Only when the parent can actually provide an ethertype (ETH/VLAN);
		// other parents (TCP/IP/...) never resolve one, so a cached value would
		// be stale and misleading there.
		if (proto_id == PROTO_UNKNOWN && session_stat->has_last_unknown_ethertype
				&& proto_hierarchy->len >= 2
				&& (proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_ETHERNET
					|| proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_8021Q
					|| proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_8021AD)) {
			_eth_append_suffix(path_ul, sizeof(path_ul), &path_ul_len,
					session_stat->last_unknown_ethertype);
			_eth_append_suffix(path_dl, sizeof(path_dl), &path_dl_len,
					session_stat->last_unknown_ethertype);
		}
	}

	struct timeval timestamp = get_session_last_activity_time( dpi_session );
	// period of the packet this row is stamped with, so that it matches the
	// number carried by the other rows of that same packet
	const size_t period_index = dpi_period_index_of_packet( context, &timestamp );
	uint64_t total_active_sessions = get_active_session_count( context->dpi_handler );

#ifdef QOS_MODULE
	uint64_t handshake_time = 0, app_response_time = 0, data_transfer_time = 0;

	//calculate data only when TCP session has been establisehd
	if( ! is_zero_timestamp( & session_stat->tcp_established_ts )){

		if( ! session_stat->is_printed_handshake_time ){
			struct timeval rtt_time = get_session_rtt(dpi_session);
			handshake_time = u_second( &rtt_time );
			session_stat->is_printed_handshake_time = true;
		}

		if( !is_zero_timestamp( & session_stat->latest_tcp_data_pkt_ts ) ){

			if( ! session_stat->is_printed_app_response_time ){
				app_response_time = u_second_diff( & session_stat->latest_tcp_data_pkt_ts, & session_stat->tcp_established_ts );
				 session_stat->is_printed_app_response_time = true;
			}

			//data transfer time
			//ensure that the timestamp of the current packet (given by get_session_last_activity_time) is after the first data packet of the tcp session
			if( is_after( & session_stat->latest_tcp_data_pkt_ts, &timestamp )){
				data_transfer_time = u_second_diff( &timestamp, & session_stat->latest_tcp_data_pkt_ts );

				//update the new moment of data transfer that need to report
				session_stat->latest_tcp_data_pkt_ts = timestamp;
			}
		}
	}
#endif

	//DEBUG("handshake: %lu", handshake_time );

	struct timeval start_time = get_session_init_time(dpi_session);

	// For GTP inner, data should be inside tunnel (inner headers), not outer tunnel overhead
	uint64_t total_volumes_delta, total_payload_delta, total_packets_delta;
	uint64_t ul_volumes_delta, ul_payload_delta, ul_packets_delta;
	uint64_t dl_volumes_delta, dl_payload_delta, dl_packets_delta;
	if (is_inner) {
		total_volumes_delta = total_volumes - (session_stat->saved_inner_volumes.upload + session_stat->saved_inner_volumes.download);
		total_payload_delta = total_payload - (session_stat->saved_inner_payload.upload + session_stat->saved_inner_payload.download);
		total_packets_delta = total_packets - (session_stat->saved_inner_packets.upload + session_stat->saved_inner_packets.download);
		ul_volumes_delta = ul_volumes - session_stat->saved_inner_volumes.upload;
		ul_payload_delta = ul_payload - session_stat->saved_inner_payload.upload;
		ul_packets_delta = ul_packets - session_stat->saved_inner_packets.upload;
		dl_volumes_delta = dl_volumes - session_stat->saved_inner_volumes.download;
		dl_payload_delta = dl_payload - session_stat->saved_inner_payload.download;
		dl_packets_delta = dl_packets - session_stat->saved_inner_packets.download;
	} else {
		total_volumes_delta = total_volumes - (session_stat->volumes.upload + session_stat->volumes.download);
		total_payload_delta = total_payload - (session_stat->payload.upload + session_stat->payload.download);
		total_packets_delta = total_packets - (session_stat->packets.upload + session_stat->packets.download);
		ul_volumes_delta = ul_volumes - session_stat->volumes.upload;
		ul_payload_delta = ul_payload - session_stat->payload.upload;
		ul_packets_delta = ul_packets - session_stat->packets.upload;
		dl_volumes_delta = dl_volumes - session_stat->volumes.download;
		dl_payload_delta = dl_payload - session_stat->payload.download;
		dl_packets_delta = dl_packets - session_stat->packets.download;
	}

	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
		__INT( period_index ),
		__INT( proto_id),
		__STR( path_ul),
		__STR( path_dl),
		__INT( total_active_sessions),
		__INT( total_volumes_delta),
		__INT( total_payload_delta),
		__INT( total_packets_delta),
		__INT( ul_volumes_delta),
		__INT( ul_payload_delta),
		__INT( ul_packets_delta),
		__INT( dl_volumes_delta),
		__INT( dl_payload_delta),
		__INT( dl_packets_delta),
		__TIME( &start_time ),
		__STR( session_stat->ip_src.ip_string ),
		__STR( session_stat->ip_dst.ip_string ),
		__MAC( session_stat->mac_src ),
		__MAC( session_stat->mac_dst),
		__INT( get_session_id( dpi_session ) ),
		__INT( session_stat->port_dst ),
		__INT( session_stat->port_src),
		__INT( context->worker_index),
	#ifdef QOS_MODULE
		__INT( handshake_time ),
		__INT( app_response_time ),
		__INT( data_transfer_time ),
		__INT( session_stat->rtt.min[DIRECTION_UPLOAD] ),
		__INT( session_stat->rtt.min[DIRECTION_DOWNLOAD] ),
		__INT( session_stat->rtt.max[DIRECTION_UPLOAD] ),
		__INT( session_stat->rtt.max[DIRECTION_DOWNLOAD] ),
		__INT( _div( session_stat->rtt.sum[DIRECTION_UPLOAD]   , session_stat->rtt.counter[DIRECTION_UPLOAD] )),
		__INT( _div( session_stat->rtt.sum[DIRECTION_DOWNLOAD] , session_stat->rtt.counter[DIRECTION_DOWNLOAD] )),
		__INT( session_stat->retransmission[DIRECTION_UPLOAD] ),
		__INT( session_stat->retransmission[DIRECTION_DOWNLOAD] ),
	#else
		__ARR( "0,0,0,0,0,0,0,0,0,0,0" ), //string without closing by quotes
	#endif
		__INT(    session_stat->app_type),
		__INT(    get_application_class_by_protocol_id( proto_id )),
		__INT(    session_stat->content_class)
	);

	//depending kind of application, e.g., HTTP, FTP, ..
	//we append other information to the report
	if( session_stat->app_type ){
		message[ valid ++ ] = ','; //a comma separator between basic report part and ftp report part

		//get_application_class_by_protocol_id( session->proto_id )
		//append stats of application beyond IP
		switch( session_stat->app_type ){
		case SESSION_STAT_TYPE_APP_IP:
			break;
		case SESSION_STAT_TYPE_APP_WEB:
			valid += print_web_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_SSL:
			valid += print_ssl_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_FTP:
			valid += print_ftp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_RTP:
			valid += print_rtp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_GTP:
			valid += print_gtp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		default:
			DEBUG("Does not support stat_type = %d", session_stat->app_type );
		}
		message[ valid ] = '\0';
	}

	output_write_report( context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			//timestamp is the one of the last packet in the session
			& timestamp,
			message );

	//if output for behaviour analysis is enabled
	if( context->behaviour_output != NULL )
		_write_behaviour_report(context->behaviour_output,
				context->probe_config->probe_id,
				context->probe_config->input->input_source,
				&timestamp,
				proto_id,
				session_stat->ip_src.ip_string,
				session_stat->ip_dst.ip_string,
				ul_volumes_delta,
				dl_volumes_delta
		);


	//remember the current statistics
	if (is_inner) {
		session_stat->saved_inner_volumes.upload = ul_volumes;
		session_stat->saved_inner_volumes.download = dl_volumes;
		session_stat->saved_inner_payload.upload = ul_payload;
		session_stat->saved_inner_payload.download = dl_payload;
		session_stat->saved_inner_packets.upload = ul_packets;
		session_stat->saved_inner_packets.download = dl_packets;
	} else {
		session_stat->volumes.upload = ul_volumes;
		session_stat->volumes.download = dl_volumes;

		session_stat->payload.upload = ul_payload;
		session_stat->payload.download = dl_payload;

		session_stat->packets.upload = ul_packets;
		session_stat->packets.download = dl_packets;
	}

#ifdef QOS_MODULE

#define _reset_data( x ) x[0] = x[1] = 0

	_reset_data( session_stat->rtt.min );
	_reset_data( session_stat->rtt.max );
	_reset_data( session_stat->rtt.sum );
	_reset_data( session_stat->rtt.counter );

	_reset_data( session_stat->retransmission );
#endif
}


#else
////===> Simpler reports for MMT-Box <===////

//This callback is called by DPI periodically
static inline void _print_ip_session_report (const mmt_session_t * dpi_session, session_stat_t * session, const dpi_context_t *context){

	const proto_hierarchy_t *proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = 0;
	if( likely( proto_hierarchy->len > 0 ))
		proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];
	bool is_arp = session->is_arp_session;
	bool is_inner = session->is_gtp_inner || is_arp;
	uint64_t ul_volumes = is_inner ? session->inner_volumes.upload : get_session_total_ul_byte_count(dpi_session);
	uint64_t dl_volumes = is_inner ? session->inner_volumes.download : get_session_total_dl_byte_count(dpi_session);

	if( unlikely( ul_volumes + dl_volumes == 0 ))
		return;

	// delta check for inner vs outer
	if (is_inner) {
		if (ul_volumes == session->saved_inner_volumes.upload && dl_volumes == session->saved_inner_volumes.download)
			return;
	} else {
		if (ul_volumes == session->volumes.upload && dl_volumes == session->volumes.download)
			return;
	}

	struct timeval last_activity_time = get_session_last_activity_time( dpi_session );
	// period of the packet this row is stamped with (see _print_ip_session_report)
	const size_t period_index = dpi_period_index_of_packet( context, &last_activity_time );

	char app_path[160];

	size_t app_path_len = dpi_proto_hierarchy_ids_to_str(
			proto_hierarchy,
			app_path, sizeof( app_path) );

	// Ugly: append ethertype bytes to UNKNOWN terminals (e.g. 99.0.136.146).
	// Only when the parent can actually provide an ethertype (ETH/VLAN).
	if (proto_id == PROTO_UNKNOWN && session->has_last_unknown_ethertype
			&& proto_hierarchy->len >= 2
			&& (proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_ETHERNET
				|| proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_8021Q
				|| proto_hierarchy->proto_path[proto_hierarchy->len - 2] == PROTO_8021AD)) {
		_eth_append_suffix(app_path, sizeof(app_path), &app_path_len,
				session->last_unknown_ethertype);
	}

	uint64_t ul_delta = is_inner ? ul_volumes - session->saved_inner_volumes.upload : ul_volumes - session->volumes.upload;
	uint64_t dl_delta = is_inner ? dl_volumes - session->saved_inner_volumes.download : dl_volumes - session->volumes.download;

	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( period_index ),
			__INT( proto_id ),
			__STR( app_path ),

			__INT( ul_delta ),
			__INT( dl_delta ),

			__STR( session->ip_src.ip_string ),
			__STR( session->ip_dst.ip_string ),

			__MAC( session->mac_src ),
			__MAC( session->mac_dst ),

			__INT( session->port_dst ),
			__INT( session->port_src )
	);

	output_write_report( context->output,
				context->probe_config->reports.session->output_channels,
				SESSION_REPORT_TYPE,
				//timestamp is the one of the last packet in the session
				& last_activity_time,
				message );



	//if output for behaviour analysis is enabled
	if( context->behaviour_output != NULL )
		_write_behaviour_report(context->behaviour_output,
				context->probe_config->probe_id,
				context->probe_config->input->input_source,
				&last_activity_time,
				proto_id,
				session->ip_src.ip_string,
				session->ip_dst.ip_string,
				ul_delta,
				dl_delta
		);

	//remember the current ul and dl data volumes
	if (is_inner) {
		session->saved_inner_volumes.upload   = ul_volumes;
		session->saved_inner_volumes.download = dl_volumes;
	} else {
		session->volumes.upload   = ul_volumes;
		session->volumes.download = dl_volumes;
	}
}
#endif


session_stat_t *session_report_callback_on_starting_session ( const ipacket_t * ipacket, dpi_context_t *context ){
	mmt_session_t * dpi_session = ipacket->session;
	if( unlikely( dpi_session == NULL)){
		DEBUG("session of packet %lu must not be NULL", ipacket->packet_id );
		return NULL;
	}

	session_stat_t *session_stat = mmt_alloc_and_init_zero( sizeof (session_stat_t));

#ifndef SIMPLE_REPORT
	session_stat->app_type = SESSION_STAT_TYPE_APP_IP;
#endif
	//the index in the protocol hierarchy of the protocol session belongs to
	const uint32_t proto_session_index  = get_session_protocol_index( dpi_session );
	// Flow extraction
	const uint32_t proto_session_id = get_protocol_id_at_index(ipacket, proto_session_index);

	//must be either PROTO_IP, PROTO_IPV6 or PROTO_ARP (ARP now sessionized)
	if( unlikely( proto_session_id != PROTO_IP && proto_session_id != PROTO_IPV6 && proto_session_id != PROTO_ARP )){
		DEBUG("session of packet %lu is not on top of IP nor IPv6 nor ARP, but %d", ipacket->packet_id, proto_session_id );
		return NULL;
	}

	// an ARP session is accounted by hand (mmt-dpi keeps no byte counters)
	session_stat->is_arp_session = (proto_session_id == PROTO_ARP);

	// Detect GTP inner session: session proto is after GTP in hierarchy
	int gtp_idx = get_protocol_index_by_id(ipacket, PROTO_GTP);
	bool is_gtp_inner_session = (gtp_idx >= 0 && (int)proto_session_index > gtp_idx);
	session_stat->is_gtp_inner = is_gtp_inner_session;
	// For GTP inner, inner counters already zero via calloc

	if (proto_session_id == PROTO_ARP) {
		// ARP session: keyed by SPA+TPA (IP pair), MAC selection prefers non-zero/broadcast
		// ETH candidate: inner ETH if GTP inner, else outer ETH (index = proto_session_index-1 or gtp+1)
		uint8_t *eth_src = NULL, *eth_dst = NULL;
		if (is_gtp_inner_session) {
			int inner_eth_idx = gtp_idx + 1;
			if (inner_eth_idx < (int)ipacket->proto_hierarchy->len &&
					get_protocol_id_at_index(ipacket, inner_eth_idx) == PROTO_ETHERNET) {
				eth_src = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_SRC, inner_eth_idx);
				eth_dst = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_DST, inner_eth_idx);
			} else {
				eth_src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
				eth_dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
			}
		} else {
			// outer ARP directly after ETH
			int eth_idx = (int)proto_session_index - 1;
			if (eth_idx >= 0 && get_protocol_id_at_index(ipacket, eth_idx) == PROTO_ETHERNET) {
				eth_src = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_SRC, eth_idx);
				eth_dst = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_DST, eth_idx);
			} else {
				eth_src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
				eth_dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
			}
		}
		uint8_t *arp_sha = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ARP, ARP_AR_SHA, proto_session_index);
		uint8_t *arp_tha = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ARP, ARP_AR_THA, proto_session_index);
		uint8_t *src = NULL, *dst = NULL;
		if (arp_sha && !_is_zero_mac(arp_sha) && !_is_broadcast_mac(arp_sha))
			src = arp_sha;
		else
			src = eth_src;
		if (arp_tha && !_is_zero_mac(arp_tha) && !_is_broadcast_mac(arp_tha))
			dst = arp_tha;
		else
			dst = eth_dst;
		// Fallback if still NULL
		if (!src) src = eth_src;
		if (!dst) dst = eth_dst;
		if (likely(src)) assign_6bytes(session_stat->mac_src, src);
		if (likely(dst)) assign_6bytes(session_stat->mac_dst, dst);

		// IP from ARP SIP/TIP (IPv4)
		uint32_t *sip = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ARP, ARP_AR_SIP, proto_session_index);
		uint32_t *tip = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ARP, ARP_AR_TIP, proto_session_index);
	
		if (sip) {
			session_stat->ip_src.ipv4 = *sip;
			inet_ntop4(session_stat->ip_src.ipv4, session_stat->ip_src.ip_string);
		} else {
			session_stat->ip_src.ip_string[0] = '\0';
		}
		if (tip) {
			session_stat->ip_dst.ipv4 = *tip;
			inet_ntop4(session_stat->ip_dst.ipv4, session_stat->ip_dst.ip_string);
		} else {
			session_stat->ip_dst.ip_string[0] = '\0';
		}
		session_stat->port_src = 0;
		session_stat->port_dst = 0;
	} else {
		const bool is_session_over_ipv4 = (proto_session_id == PROTO_IP);

		uint8_t *src = NULL, *dst = NULL;
		// For IP-over-GTP (no inner ETH) keep outer MAC as per requirement.
		// For ETH-over-GTP (inner ETH exists at gtp+1), use inner MAC.
		if (is_gtp_inner_session) {
			int inner_eth_idx = gtp_idx + 1;
			if (inner_eth_idx < (int)ipacket->proto_hierarchy->len &&
					get_protocol_id_at_index(ipacket, inner_eth_idx) == PROTO_ETHERNET) {
				src = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_SRC, inner_eth_idx);
				dst = (uint8_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_ETHERNET, ETH_DST, inner_eth_idx);
			} else {
				// IP GTP: keep outer MAC (as per spec)
				src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
				dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
			}
		} else {
			src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
			dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
		}

		if (likely( src ))
			assign_6bytes( session_stat->mac_src, src );
		if (likely( dst ))
			assign_6bytes( session_stat->mac_dst, dst );

		//IPV4
		if (likely( is_session_over_ipv4 )) {

		uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_SRC, proto_session_index);
		uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_DST, proto_session_index);

		if (likely( ip_src ))
			session_stat->ip_src.ipv4 = *ip_src;

		if (likely( ip_dst ))
			session_stat->ip_dst.ipv4 = (*ip_dst);


		inet_ntop4(session_stat->ip_src.ipv4, session_stat->ip_src.ip_string);
		inet_ntop4(session_stat->ip_dst.ipv4, session_stat->ip_dst.ip_string);

		uint16_t * cport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_CLIENT_PORT, proto_session_index);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_SERVER_PORT, proto_session_index);
		if( likely( cport ))
			session_stat->port_src = *cport;

		if( likely( dport ))
			session_stat->port_dst = *dport;

	} else {
		void * ipv6_src = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_SRC, proto_session_index);
		void * ipv6_dst = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_DST, proto_session_index);
		if (likely( ipv6_src ))
			assign_16bytes( &session_stat->ip_src.ipv6, ipv6_src);
		if (likely( ipv6_dst ))
			assign_16bytes(&session_stat->ip_dst.ipv6, ipv6_dst);

		inet_ntop(AF_INET6, (void *) &session_stat->ip_src.ipv6, session_stat->ip_src.ip_string, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &session_stat->ip_dst.ipv6, session_stat->ip_dst.ip_string, INET6_ADDRSTRLEN);


		uint16_t * cport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_CLIENT_PORT, proto_session_index);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_SERVER_PORT, proto_session_index);
		if (likely( cport ))
			session_stat->port_src = *cport;
		if (likely( dport ))
			session_stat->port_dst = *dport;
		}
	} // end non-ARP

#ifdef QOS_MODULE
	//initialize a data structure to calculate RTT of data packets
	session_stat->tcp_rtt = tcp_rtt_init();
#endif

	return session_stat;
}


/* This function is called by mmt-dpi for each session time-out (expiry).
 * It provides the expired session information and frees the memory allocated.
 * */
void session_report_callback_on_ending_session(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context ) {
	if (session_stat == NULL)
		return;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//release memory being allocated for application stat (web, ftp, rtp, ssl)
	switch( session_stat->app_type ){
	default:
		break;
	}

	//
	mmt_probe_free( session_stat->apps.web );
#endif

#ifdef QOS_MODULE
	tcp_rtt_release( session_stat->tcp_rtt );
#endif

	mmt_probe_free( session_stat );
}

/**
 * Return index of a given proto_id, e.g., TCP, in the protocol hierarchy but after session protocol
 * 	of the current dpi_session
 * If there exist many TCP, e.g., ETH.IP.TCP.IP.TCP, then
 * the TCP after the current IP session will be returned
 *
 * Return -1 if not found
 */
static inline int32_t _get_protocol_index_after_session( uint32_t proto_id, const mmt_session_t *dpi_session ){
	if( dpi_session == NULL )
		return -1;

	//the index in the protocol hierarchy of the protocol session belongs to
	uint32_t proto_index  = get_session_protocol_index( dpi_session );
	const proto_hierarchy_t *proto_hierarchy = get_session_protocol_hierarchy( dpi_session );

	while( proto_index < proto_hierarchy->len ){
		if( proto_hierarchy->proto_path[ proto_index ] == proto_id )
			return proto_index;
		proto_index ++;
	}

	return -1;
}

int session_report_callback_on_receiving_packet(const ipacket_t * ipacket, session_stat_t * session_stat, dpi_context_t *context ){

	if (unlikely(session_stat == NULL))
		return 0;
	// Cache last-seen ethertype of UNKNOWN terminals for ".high.low" suffix
	// on paths ending with ".0" (e.g. profinet 0x8892 -> 99.0.136.146).
	// Uses the effective length (stale UNKNOWN tails from shared session
	// paths are ignored; their parent cannot resolve an ethertype anyway).
	if (ipacket->proto_hierarchy && ipacket->proto_hierarchy->len >= 2) {
		int eff_len = _eth_effective_len(ipacket->proto_hierarchy);
		if (eff_len >= 2
				&& ipacket->proto_hierarchy->proto_path[eff_len - 1] == PROTO_UNKNOWN) {
			uint16_t et = _eth_unknown_ethertype(ipacket, eff_len - 1);
			if (et != 0) {
				session_stat->last_unknown_ethertype = et;
				session_stat->has_last_unknown_ethertype = true;
			}
		}
	}
	// GTP inner accounting: data volume/packets/payload should be inside GTP, not outer tunnel
	// Also ARP outer (no DPI byte counters) needs manual accounting
	uint32_t sess_proto = 0;
	if (ipacket->session) {
		uint32_t sess_idx = get_session_protocol_index(ipacket->session);
		sess_proto = get_protocol_id_at_index(ipacket, sess_idx);
	}
	bool is_arp = (sess_proto == PROTO_ARP);
	bool need_inner = session_stat->is_gtp_inner || is_arp;
	if (need_inner) {
		int offset = -1;
		if (is_arp) {
			if (session_stat->is_gtp_inner) {
				int gtp_idx = get_protocol_index_by_id(ipacket, PROTO_GTP);
				if (gtp_idx >= 0) offset = get_packet_offset_at_index(ipacket, gtp_idx + 1);
			} else {
				offset = 0; // outer ARP: full packet
			}
		} else {
			int gtp_idx = get_protocol_index_by_id(ipacket, PROTO_GTP);
			if (gtp_idx >= 0) {
				int inner_start = gtp_idx + 1;
				if (inner_start < (int)ipacket->proto_hierarchy->len) {
					offset = get_packet_offset_at_index(ipacket, inner_start);
				}
			}
		}
		if (offset >= 0 && offset < (int)ipacket->p_hdr->len) {
			uint32_t inner_len = ipacket->p_hdr->len - offset;
					// Use caplen if packet was truncated? Prefer len for wire length (as outer does)
					// direction: inner session direction
					uint8_t dir = !!get_session_last_packet_direction(ipacket->session);
					if (dir == DIRECTION_UPLOAD)
						session_stat->inner_volumes.upload += inner_len;
					else
						session_stat->inner_volumes.download += inner_len;
#ifndef SIMPLE_REPORT
					if (dir == DIRECTION_UPLOAD)
						session_stat->inner_packets.upload += 1;
					else
						session_stat->inner_packets.download += 1;

					// payload: try to get inner L4 payload
					uint32_t payload_len = 0;
					int32_t tcp_idx = _get_protocol_index_after_session(PROTO_TCP, ipacket->session);
					if (tcp_idx != -1) {
						uint32_t *tcp_pl = (uint32_t*) get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_PAYLOAD_LEN, tcp_idx);
						if (tcp_pl) payload_len = *tcp_pl;
					} else {
						int32_t udp_idx = _get_protocol_index_after_session(PROTO_UDP, ipacket->session);
						if (udp_idx != -1) {
							uint16_t *udp_len = (uint16_t*) get_attribute_extracted_data_at_index(ipacket, PROTO_UDP, UDP_LEN, udp_idx);
							if (udp_len) {
								// general_short_extraction_with_ordering_change already converts to host order
								uint16_t ulen = *udp_len;
								if (ulen >= 8) payload_len = ulen - 8;
							}
						}
					}
					// fallback: if payload_len still 0, estimate as inner_len minus headers (ETH14 + IP20 + 8/20)
					// For now keep 0 if not TCP/UDP - data volume already accounts
					if (payload_len > 0) {
						if (dir == DIRECTION_UPLOAD)
							session_stat->inner_payload.upload += payload_len;
						else
							session_stat->inner_payload.download += payload_len;
					}
#endif
				}
	}

#ifndef SIMPLE_REPORT

#ifdef QOS_MODULE

	//get the index of TCP protocol in the protocol hierarchy but after IP session
	const int32_t proto_index  = _get_protocol_index_after_session( PROTO_TCP, ipacket->session );

	//found TCP
	if( proto_index != -1 ){

		//whether the current packet is the retransmission
		uint32_t *retransmission = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_RETRANSMISSION, proto_index);
		// !! to ensure dir is either 0 or 1
		uint8_t dir = !! (get_session_last_packet_direction( ipacket->session ) );

		//calculate upload and download retransmission counters
		if( retransmission != NULL )
			//DEBUG("retransmission: %u", *retransmission );
			session_stat->retransmission[ dir ]   += *retransmission;

		//calculate RTT
		uint64_t usec = 0;
		uint32_t seq_number = 0, ack_number = 0, data_len = 0, *val;
		conf_rtt_base_t rtt_base = context->probe_config->reports.session->rtt_base;
		if( rtt_base == CONF_RTT_BASE_SENDER || rtt_base == CONF_RTT_BASE_PREFER_SENDER ){
			val = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_TSVAL, proto_index);
			if( val ) seq_number = *val;
			val = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_TSECR, proto_index);
			if( val ) ack_number = *val;
		}

		if( rtt_base == CONF_RTT_BASE_CAPTOR || rtt_base == CONF_RTT_BASE_PREFER_SENDER ){
			bool is_rtt_base_captor = (rtt_base == CONF_RTT_BASE_CAPTOR);
			val = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_ACK_NB, proto_index);

			if( val //has value
				&& (is_rtt_base_captor     //rtt is based on captor
						|| ack_number == 0 //PREFER_SENDER
				) ) ack_number = *val;

			val = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_SEQ_NB, proto_index);
			if( val && (is_rtt_base_captor || seq_number == 0) ) seq_number = *val;
			//we donot need data_len when rtt uses SENDER
			if( is_rtt_base_captor ){
				val = get_attribute_extracted_data_at_index(ipacket, PROTO_TCP, TCP_PAYLOAD_LEN, proto_index);
				if( val ) data_len = *val;
			}
		}

		if( ack_number && seq_number ){
			uint32_t counter = tcp_rtt_add_packet( session_stat->tcp_rtt, dir,
					ack_number, seq_number, data_len,
					ipacket->p_hdr->ts, &usec );
			if( counter ){
				//invert direction: the current upload packet acknowledges download packets
				dir = (dir == DIRECTION_UPLOAD )? DIRECTION_DOWNLOAD : DIRECTION_UPLOAD;
				session_stat->rtt.counter[dir] += counter;
				session_stat->rtt.sum[dir]     += (usec * counter);
				if( session_stat->rtt.max[dir] < usec )
					session_stat->rtt.max[dir] = usec;
				if( session_stat->rtt.min[dir] == 0 || session_stat->rtt.min[dir] > usec )
					session_stat->rtt.min[dir] = usec;
			}
		}

		if( is_zero_timestamp( & session_stat->tcp_established_ts )){
			//this function does not work, it always return NULL
			//uint32_t *established = get_attribute_extracted_data_at_index( ipacket, PROTO_TCP, TCP_CONN_ESTABLISHED, proto_index );
			attribute_t *att = get_extracted_attribute_at_index( ipacket, PROTO_TCP, TCP_CONN_ESTABLISHED, proto_index );

			if( att && att->data )
				session_stat->tcp_established_ts = ipacket->p_hdr->ts;
		} else if( is_zero_timestamp( & session_stat->latest_tcp_data_pkt_ts )){
			//to calculate app_response_time, data_transfer_time
			if( is_after( &session_stat->tcp_established_ts, &ipacket->p_hdr->ts ) )
				session_stat->latest_tcp_data_pkt_ts = ipacket->p_hdr->ts;
		}

	} else {
		//log_write(LOG_ERR, "Impossible: %"PRIu64, ipacket->packet_id);

	}
#endif

#endif

	return 0;
}


void session_report_do_report(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context){
	_print_ip_session_report ( dpi_session, session_stat, context );
}

/**
 * This function registers the required attributes for a flow (session)
 */
static inline void
	_register_protocols( mmt_handler_t *mmt_handler ) {
	int ret = 1;
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_SRC_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_DEST_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_UDP, UDP_SRC_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_UDP, UDP_DEST_PORT);

	ret &= register_extraction_attribute(mmt_handler, PROTO_ETHERNET, ETH_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ETHERNET, ETH_SRC);
	// Ugly ETH coverage: ethertype for ".high.low" suffix on UNKNOWN paths
	ret &= register_extraction_attribute(mmt_handler, PROTO_ETHERNET, ETH_PROTOCOL);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_SRC);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_PROTO_ID);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_SERVER_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_CLIENT_PORT);

	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SRC);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SERVER_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT);

	ret &= register_extraction_attribute(mmt_handler, PROTO_ARP, ARP_AR_SHA);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ARP, ARP_AR_SIP);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ARP, ARP_AR_THA);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ARP, ARP_AR_TIP);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ARP, ARP_AR_OP);

	// For GTP inner volume/payload accounting (inner packet inside tunnel)
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_HEADER_LEN);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_TOT_LEN);
	ret &= register_extraction_attribute(mmt_handler, PROTO_UDP, UDP_LEN);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_DATA_OFF);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_PAYLOAD_LEN);

#ifdef QOS_MODULE
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_RETRANSMISSION);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_ACK_NB);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_SEQ_NB);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_PAYLOAD_LEN );
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_CONN_ESTABLISHED );
	//calculate RTT using TCP timestamp options
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_TSVAL );
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_TSECR );
#endif

	if(!ret) {
		//we need a sound error handling mechanism! Anyway, we should never get here :)
		log_write(LOG_ERR, "Error while initializing MMT handlers and extractions!");
	}
}

size_t get_session_web_handlers_to_register( const conditional_handler_t ** );
size_t get_session_ssl_handlers_to_register( const conditional_handler_t ** );
size_t get_session_rtp_handlers_to_register( const conditional_handler_t ** );
size_t get_session_gtp_handlers_to_register( const conditional_handler_t ** );

bool session_report_register( mmt_handler_t *dpi_handler, session_report_conf_t *config, dpi_context_t *dpi_context ){
	if( ! config->is_enable )
		return false;

	//register basic protocols and their attributes for IP session statistic
	_register_protocols( dpi_handler );

	size_t size;
	const conditional_handler_t* handlers;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//register protocols and attributes for application statistic: WEB, FTP, RTP, SSL
	if( config->is_http ){
		size = get_session_web_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}

	if( config->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}

	if( config->is_rtp ){
		size = get_session_rtp_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}
	if( config->is_gtp ){
		size = get_session_gtp_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}
#endif

	return true;
}


bool session_report_unregister( mmt_handler_t *dpi_handler, session_report_conf_t *config ){
	if( ! config->is_enable )
		return false;

	size_t size;
	const conditional_handler_t* handlers;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//register protocols and attributes for application statistic: WEB, FTP, RTP, SSL
	if( config->is_http ){
		size = get_session_web_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers);
	}

	if( config->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
	if( config->is_rtp ){
		size = get_session_rtp_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
	if( config->is_gtp ){
		size = get_session_gtp_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
#endif

	return true;
}
