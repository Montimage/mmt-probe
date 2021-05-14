/*
 * inject_proto.h
 *
 *  Created on: May 14, 2021
 *      Author: nhnghia
 *
 * This file implements injection packets using a special protocol (TCP, UDP, SCTP, etc) rather than injecting raw packet to the output NIC
 */

#ifndef SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_PROTO_H_
#define SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_PROTO_H_

#include "../../../../configure.h"

typedef struct inject_proto_context_struct inject_proto_context_t;

#define INJECT_PROTO_NO_AVAIL (-1)

inject_proto_context_t* inject_proto_alloc( const probe_conf_t *config );

/*
 * Inject packet using a special protcol
 *
 * @return:
 *  - INJECT_PROTO_NO_AVAIL if no protocol is available, e.g., packet does not contain SCTP
 *  - number of packets (including the copies) being successfully sent
 */
int inject_proto_send_packet( inject_proto_context_t *context, const ipacket_t *ipacket, const uint8_t *packet_data, uint16_t packet_size );
void inject_proto_release( inject_proto_context_t *context );


#endif /* SRC_MODULES_SECURITY_FORWARD_PROTO_INJECT_PROTO_H_ */
