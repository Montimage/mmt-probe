/*
 * tcp_rtt.c
 *
 *  Created on: May 31, 2019
 *          by: Huu-Nghia
 */

#include "tcp_rtt.h"

#include "../../../lib/string_builder.h"
#include "../../../lib/log.h"
#include "../../../lib/inet.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

struct pkt_node{
	uint32_t seq_number;
	uint16_t data_len;
	struct timeval timestamp;
	struct pkt_node *next;
};

struct tcp_rtt_struct {
	//we use a link list to store the expected ack_number for uplink and another list for downlink.
	//The list is sorted by descending order of seq_number + data_len

	struct pkt_node *pkts[2]; //uplink and downlink

};


static inline struct pkt_node * _new_pkt_node( uint32_t seq_num, uint16_t len, struct timeval ts ){
	struct pkt_node *node = mmt_alloc( sizeof( struct pkt_node ) );
	node->seq_number = seq_num;
	node->data_len = len;
	node->timestamp  = ts;
	node->next = NULL;
	return node;
}



tcp_rtt_t *tcp_rtt_init(){
	tcp_rtt_t *ret = mmt_alloc( sizeof( struct tcp_rtt_struct ) );
	ret->pkts[0] = NULL;
	ret->pkts[1] = NULL;
	return ret;
}


#define expected_ack_number( p ) (p->seq_number + p->data_len)

/**
 * Add packet to the list. The packet is characterized by 4 numbers:
 * - direction: either 0 or 1 for uplink or downlink
 * - ack_num: ACK number
 * - seq_num: Sequence number
 * - data_len: data length
 * - timestamp:
 *
 * Wee need to:
 * - for the same direction of packet: store information of the packet
 * - for the inverted direction: check whether the packet acknowledges some others
 *
 * @return number of packets being acknowledged by the current packet
 *
 * @output If the returned number is not zero, then, the
 * output usec represents the interval, in nano second between
 * the current packet and the ack packet
 * if packet acknowledges some packets storing in the list
 *
 */
uint32_t tcp_rtt_add_packet( tcp_rtt_t *rtt, uint8_t direction, uint32_t ack_num, uint32_t seq_num,
		uint16_t data_len, struct timeval timestamp, uint64_t *usec ){

	//1. add data for the current direction
	uint32_t expected_ack_num = seq_num + data_len;
	struct pkt_node *p = rtt->pkts[ direction ], *prev = NULL;

	//the list is sorted by descending order
	//=> find a suitable position to insert (if it does not exist) the expected_ack_num
	while( p!= NULL && expected_ack_number( p ) > expected_ack_num ){
		prev = p;
		p = p->next;
	}

	//Duplicated (retransmission) packet
	if( p != NULL && expected_ack_number( p ) == expected_ack_num ){
		//do nothing??
		//use new timestamp? (only if it is more recent
		if( p->timestamp.tv_sec < timestamp.tv_sec ||
				(p->timestamp.tv_usec < timestamp.tv_usec && p->timestamp.tv_sec == timestamp.tv_sec))
			p->timestamp = timestamp;
		//DEBUG("Duplicate packet having seq = %u", seq_num );

	} else {
		//create a new node, then insert it into the linked list
		struct pkt_node *new_node = _new_pkt_node( seq_num, data_len, timestamp );
		new_node->next = p;

		//the list is empty (for the first time)
		if( prev == NULL )
			rtt->pkts[ direction ] = new_node;
		else
			prev->next = new_node;
	}

	uint32_t counter = 0;

	//if this packet does not contain ACK
	if( ack_num == 0 )
		return counter;

	//2. check ack_num for other direction

	//if this packet is ack for some ones?
	uint8_t other_dir = (direction == 0? 1: 0);
	p = rtt->pkts[ other_dir ];
	prev = NULL;

	while( p!= NULL && expected_ack_number(p) != ack_num){
		prev = p;
		p = p->next;
	}


	//found one ??
	if( p != NULL && expected_ack_number( p ) == ack_num ){

		*usec = u_second_diff( &timestamp, &p->timestamp );

		//remove this node and the ones have been acknowledged
		while( p != NULL && expected_ack_number( p ) == ack_num){
			ack_num = p->seq_number; //the current seq_number can be considered as ack of the previous packets
			struct pkt_node *node = p;
			p = p->next;
			counter ++;
			//free the node
			mmt_probe_free( node );
		}

		//update list
		if( prev == NULL )
			rtt->pkts[ other_dir ] = p;
		else
			prev->next = p;
	}


	return counter;
}


static inline void _free_linked_list( struct pkt_node *node ){
	struct pkt_node *p;
	//uint16_t counter = 0;
	while( node != NULL ){
		p = node;
		DEBUG("no ack seq = %u", p->seq_number );
		mmt_probe_free( p );
		node = node->next;
		//counter ++;
	}

#ifdef DEBUG_MODE
	//if( counter )
	//	DEBUG("Rest %d packets that have no ack", counter );
#endif
}

void tcp_rtt_release( tcp_rtt_t *rtt ){
	if( rtt ){
		_free_linked_list( rtt->pkts[0] );
		_free_linked_list( rtt->pkts[1] );
		mmt_probe_free( rtt );
	}
}
