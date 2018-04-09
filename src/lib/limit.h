/*
 * limit.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_LIMIT_H_
#define SRC_LIB_LIMIT_H_
//maximal length of an absolute path
#define MAX_LENGTH_FULL_PATH_FILE_NAME  256
#define MAX_LENGTH_REPORT_MESSAGE      3000

#ifdef DEBUG_MODE
	#define IF_ENABLE_DEBUG( x ) x
#else
	#define IF_ENABLE_DEBUG( x )
#endif

#ifdef PCAP_MODULE
	#define IF_ENABLE_PCAP( x ) x
#else
	#define IF_ENABLE_PCAP( x )
#endif

#ifdef DPDK_MODULE
	#define IF_ENABLE_DPDK( x ) x
#else
	#define IF_ENABLE_DPDK( x )
#endif

#ifdef SECURITY_MODULE
	#define IF_ENABLE_SECURITY( x ) x
#else
	#define IF_ENABLE_SECURITY( x )
#endif

#ifdef DYNAMIC_CONFIG_MODULE
	#define IF_ENABLE_DYNAMIC_CONFIG( x ) x
#else
	#define IF_ENABLE_DYNAMIC_CONFIG( x )
#endif


//a string contains list of compiled modules
#define MODULES_LIST                            \
	""                                          \
	IF_ENABLE_DEBUG( "DEBUG " )                 \
	IF_ENABLE_PCAP( "PCAP " )                   \
	IF_ENABLE_DPDK( "DPDK " )                   \
	IF_ENABLE_DYNAMIC_CONFIG( "DYNAMIC_CONF " ) \
	IF_ENABLE_SECURITY("SECURITY ")


#endif /* SRC_LIB_LIMIT_H_ */
