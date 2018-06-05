/*
 * inet.h
 *
 *  Created on: Jun 5, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_INET_H_
#define SRC_LIB_INET_H_

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define INET_ADDRSTRLEN 16

/**
 * Convert IPv4 from 32bit number to human readable string
 * @param addr
 * @param buf must point to a memory segment having at least INET_ADDRSTRLEN bytes
 * @return length of buf
 */
int inet_ntop4( uint32_t addr, char *buf );

#endif /* SRC_LIB_INET_H_ */
