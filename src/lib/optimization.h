/*
 * optimization.h
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#ifndef SRC_LIB_OPTIMIZATION_H_
#define SRC_LIB_OPTIMIZATION_H_

#ifdef PCAP
#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     (x)
#endif


#endif/* SRC_LIB_OPTIMIZATION_H_ */
