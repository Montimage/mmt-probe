/*
 * limit.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_LIMIT_H_
#define SRC_LIB_LIMIT_H_
//maximal length of an absolute path
#define MAX_LENGTH_FULL_PATH_FILE_NAME 256
#define MAX_LENGTH_REPORT_MESSAGE      3000

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

#ifdef DYNAMIC_CONF_MODULE
	#define IF_ENABLE_DYNAMIC_CONF( x ) x
#else
	#define IF_ENABLE_DYNAMIC_CONF( x )
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


#endif /* SRC_LIB_LIMIT_H_ */
