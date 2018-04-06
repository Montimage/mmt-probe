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
	#define IF_ENABLE_PCAP_MODULE( x ) x
#else
	#define IF_ENABLE_PCAP_MODULE( x )
#endif

#ifdef DPDK_MODULE
	#define IF_ENABLE_DPDK_MODULE( x ) x
#else
	#define IF_ENABLE_DPDK_MODULE( x )
#endif

#ifdef SECURITY_MODULE
	#define IF_ENABLE_SECURITY_MODULE( x ) x
#else
	#define IF_ENABLE_SECURITY_MODULE( x )
#endif

#ifdef DYNAMIC_CONFIG_MODULE
	#define IF_ENABLE_DYNAMIC_CONFIG_MODULE( x ) x
#else
	#define IF_ENABLE_DYNAMIC_CONFIG_MODULE( x )
#endif


//a string contains list of compiled modules
#define MODULES_LIST                                   \
	""                                                 \
	IF_ENABLE_DEBUG( "DEBUG " )                        \
	IF_ENABLE_PCAP_MODULE( "PCAP " )                   \
	IF_ENABLE_DPDK_MODULE( "DPDK " )                   \
	IF_ENABLE_DYNAMIC_CONFIG_MODULE( "DYNAMIC_CONF " ) \
	IF_ENABLE_SECURITY_MODULE("SECURITY ")


#define ALWAYS_INLINE __attribute__((always_inline))

#endif /* SRC_LIB_LIMIT_H_ */
