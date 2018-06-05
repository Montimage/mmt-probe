/*
 * inet.c
 *
 *  Created on: Jun 5, 2018
 *          by: Huu Nghia Nguyen
 */

#include "inet.h"
#include "string_builder.h"

int inet_ntop4( uint32_t addr, char *buf){
   const uint8_t *p = (const uint8_t *) &addr;
   int valid = 0;
   STRING_BUILDER_WITH_SEPARATOR( valid, buf, INET_ADDRSTRLEN, ".",
		   __INT(p[0]),
		   __INT(p[1]),
		   __INT(p[2]),
		   __INT(p[3]));
   buf[ valid ] = '\0';
   return valid;
}
