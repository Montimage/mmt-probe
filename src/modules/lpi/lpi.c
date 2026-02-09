/*
 * ignore_dpi_packet.c
 *
 *  Created on: May 5, 2023
 *      Author: nhnghia
 */

#include "../../lib/lib.h"
#include "lpi.h"
#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <pthread.h>

struct lpi_struct{
	// if is_multi_threading == true
	//  - lpi_process_packet is called from a thread
	//  - lpi_include_ip is called from a different thread
	bool is_multi_threading;
	pthread_mutex_t mutex;
	output_t *output;
	output_channel_conf_t output_channels;
	// this timer is fired to tell dpi to perform its session reports
	ms_timer_t stat_timer;

	//a hash table: each element contains information about the packets coming from the same IP src
	hash_t *table;
	//a table containing a list of IP sources which need to be processed
	bit_t *ip_src_filter;

	size_t total_active_sessions;
};


typedef struct hash_key_struct{
	uint32_t ip_src;
	uint32_t ip_dst;
} hash_key_t;

typedef struct hash_data_struct{
	size_t nb_packets;
	size_t nb_volume_bytes;
	size_t nb_payload_bytes;
	size_t session_id;
	struct timeval start_time;
	struct timeval end_time;
	uint8_t  mac_src[6];
	uint8_t  mac_dst[6];
} hash_data_t;


static void _free_hash_key_and_data(size_t key_len, void *key, void *data, void *args){
	mmt_probe_free( key );
	mmt_probe_free( data );
}

static void _clear_hash_table( hash_t *table ){
	hash_visit( table, _free_hash_key_and_data, NULL );
	hash_clean( table );
}


static void _report_one_item( size_t key_len, void *_key, void *_data, void *args ){
	lpi_t *lpi = (lpi_t *) args;
	hash_key_t   *key = (hash_key_t *) _key;
	hash_data_t *data = (hash_data_t *) _data;
	char ip_src_str[INET6_ADDRSTRLEN];
	char ip_dst_str[INET6_ADDRSTRLEN];

	//convert IPv4 to string which is in form xxx.xxx.xxx.xxx
	inet_ntop4( key->ip_dst, ip_dst_str );
	inet_ntop4( key->ip_src, ip_src_str );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	uint32_t proto_id = PROTO_IP; //IPv4
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
		__INT( 0 ), //index of this output (main thread)
		__INT( 0 ), //unknown protocol
		__STR( "99.178.0" ), //Ethernet.IPv4
		__STR( "" ),
		__INT( lpi->total_active_sessions),
		//total:
		__INT( data->nb_volume_bytes ),
		__INT( data->nb_payload_bytes),
		__INT( data->nb_packets ),
		//upload direction: same value as total (no download)
		__INT( data->nb_volume_bytes ),
		__INT( data->nb_payload_bytes),
		__INT( data->nb_packets ),
		//no data for download
		__ARR( "0,0,0" ),
		__TIME( &data->start_time ),
		__STR( ip_src_str ),
		__STR( ip_dst_str ),
		__MAC( data->mac_src ),
		__MAC( data->mac_dst),
		__INT( data->session_id ),
		__INT( 0 ), //IP port src: 0 as we cummulate all data from IP src-dst, not by port src-dst
		__INT( 0 ), //IP port dst
		__INT( 0 ), //worker index
		//No QoS info
		__ARR( "0,0,0,0,0,0,0,0,0,0,0" ), //string without closing by quotes
		__INT( 0  ), //app type IP: SESSION_STAT_TYPE_APP_IP
		__INT( get_application_class_by_protocol_id( proto_id )),
		__INT( 0 ) //MMT_CONTENT_FAMILY_UNSPECIFIED
	);

	DEBUG("Malicious traffic: %s", message);

	output_write_report( lpi->output,
			lpi->output_channels,
			SESSION_REPORT_TYPE,
			//timestamp is the one of the last packet in the session
			& data->end_time,
			message );
}

/**
 * This function is called by the timer when it is expired.
 * We need to visit all element inside the hash table, then generate reports for them.
 * @param timer
 * @param args
 */
static void _do_stat_reports( const  ms_timer_t *timer, void *args ){
	lpi_t *lpi = (lpi_t *) args;
	hash_visit( lpi->table, _report_one_item, lpi );
	//after visiting the table, I will clean it for the next stats period
	_clear_hash_table( lpi->table );
	//also reset the number of active sesssion
	lpi->total_active_sessions = 0;
}

lpi_t* lpi_init( output_t *output, output_channel_conf_t output_channels, size_t stat_ms_period,  bool multithreading ){
	lpi_t *lpi = mmt_alloc_and_init_zero( sizeof( lpi_t));
	lpi->output = output;
	lpi->output_channels = output_channels;
	lpi->ip_src_filter = bit_create( 0x100000000 ); //a table containing 2^32 + 1 bit which is enough for IPv4 space
	// init a table which can contain 2^16 elements
	// if more element will be inserted in the table, the table will be reseted automatically to increase its capability
	//   to be able to contain more element
	// ==> the reset process takes time as it need to rehash the whole table
	lpi->table = hash_create( 0xFFFF );
	ms_timer_init( &lpi->stat_timer, stat_ms_period,
			_do_stat_reports, lpi );

	lpi->is_multi_threading = multithreading;
	pthread_mutex_init( &lpi->mutex, NULL );

	return lpi;
}

void lpi_release( lpi_t *lpi ){
	if( lpi == NULL )
		return;
	_do_stat_reports( NULL, lpi );
	hash_free( lpi->table );
	bit_free( lpi->ip_src_filter );
	pthread_mutex_destroy( &lpi->mutex );
	mmt_probe_free( lpi );
}

void lpi_update_timer( lpi_t *lpi, const struct timeval * tv){
	if( lpi == NULL )
		return;
	ms_timer_set_time( &lpi->stat_timer, tv );
}

void lpi_include_ip( lpi_t *lpi, uint32_t ipv4_source ){
	if( lpi == NULL )
		return;

	bool is_set = false;

	//lock only when we are in multi-threading mode
	if( lpi->is_multi_threading )
		pthread_mutex_lock( &lpi->mutex );

	if( bit_get( lpi->ip_src_filter, ipv4_source ) == 0 ){
		// mark this IP whose packets will be processed by LPI
		bit_set( lpi->ip_src_filter, ipv4_source );
		is_set = true;
	}

	//unlock only when we are in multi-threading mode
	if( lpi->is_multi_threading )
		pthread_mutex_unlock( &lpi->mutex );

	if( is_set ){
		uint8_t *u8_ptr;

		u8_ptr = (uint8_t *) &ipv4_source;
		log_write(LOG_WARNING, "Redirect to LPI packets whose IPv4 src = %d.%d.%d.%d",
				u8_ptr[0], u8_ptr[1], u8_ptr[2], u8_ptr[3] );
	}
}

bool lpi_process_packet( lpi_t *lpi, struct pkthdr *pkt_header, const u_char *packet ){
	if( lpi == NULL )
		return false;

	//Ethernet structure
	struct __ethernet_struct {
		uint8_t src[6];
		uint8_t dst[6];
		uint16_t proto;
	} *eth;

	uint32_t ip_src, ip_dst;
	//uint16_t port_src, port_dst;
	uint16_t ip_offset;
	//uint8_t proto_id; //ID of protocol after IP

	size_t pkt_len = pkt_header->caplen;

	// this is not elegant check IP, IPv6 etc.
	if ( unlikely( pkt_len < 38))
		return false;

	//TODO: this may ignore some cases in which the protocol stack is not Ethernet, but Linux Cooked Capture for example
	eth = (struct __ethernet_struct *) packet;


	switch( eth->proto ){
	//IP
	case 0x08:
		ip_offset = 26;
		break;
	//vlan
	case 0x81:
		ip_offset = 30;
		break;
	default:
		//for other protocol
		return false;
	}

	// find IP src/dst of the packet
	ip_src = *((uint32_t *) &packet[ ip_offset     ]);
	ip_dst = *((uint32_t *) &packet[ ip_offset + 4 ]);

	bool is_in_list = true;

	if( lpi->is_multi_threading ){
		pthread_mutex_lock( &lpi->mutex );
		is_in_list = bit_get( lpi->ip_src_filter, ip_src);
		pthread_mutex_unlock( &lpi->mutex );
	}
	else
		is_in_list = bit_get( lpi->ip_src_filter, ip_src);

	// the IP is not in the list
	if( !is_in_list )
		return false;

	const size_t key_len = sizeof( hash_key_t );
	hash_key_t key;

	key.ip_src = ip_src;
	key.ip_dst = ip_dst;

	// search whether the packet is already tracked
	hash_data_t *data = hash_search( lpi->table, key_len, (void*)&key );
	if( data == NULL ){
		//if not, track it in the hash table
		data = mmt_alloc_and_init_zero( sizeof( hash_data_t) );
		//init data for this session
		data->start_time = pkt_header->ts;
		assign_6bytes( data->mac_src, eth->src );
		assign_6bytes( data->mac_dst, eth->dst );
		data->session_id = lpi->total_active_sessions;
		//copy the ky
		void *key_ptr = mmt_memdup( &key, key_len );
		//add key and data to the hash table
		hash_add( lpi->table, key_len, key_ptr, data );

		//increase the total number of active sessions which are number of pair src-dst IP addresses
		lpi->total_active_sessions ++;
	}

	//update data
	data->nb_packets += 1;
	data->nb_volume_bytes += pkt_header->len;
	data->nb_payload_bytes += (pkt_header->len - ip_offset); //need to also minus to IP header
	data->end_time = pkt_header->ts;

	return true;
}

