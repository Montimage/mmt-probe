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

//TODO: remove this block
/*
#ifndef DEBUG_MODE
#define DEBUG_MODE
#endif
#ifndef PCAP_MODULE
#define PCAP_MODULE
#endif
#ifndef SECURITY_MODULE
#define SECURITY_MODULE
#endif
#ifndef DYNAMIC_CONFIG_MODULE
#define DYNAMIC_CONFIG_MODULE
#endif
#ifndef REDIS_MODULE
#define REDIS_MODULE
#endif
#ifndef KAFKA_MODULE
#define KAFKA_MODULE
#endif
#ifndef MONGODB_MODULE
#define MONGODB_MODULE
#endif
#ifndef PCAP_DUMP_MODULE
#define PCAP_DUMP_MODULE
#endif
#ifndef SIMPLE_REPORT
#define SIMPLE_REPORT
#endif
#ifndef STAT_REPORT
#define STAT_REPORT
#endif
#ifndef LICENSE_CHECK
#define LICENSE_CHECK
#endif
*/
//end of block to be removed


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

#ifdef REDIS_MODULE
	#define IF_ENABLE_REDIS( x ) x
#else
	#define IF_ENABLE_REDIS( x )
#endif

#ifdef KAFKA_MODULE
	#define IF_ENABLE_KAFKA( x ) x
#else
	#define IF_ENABLE_KAFKA( x )
#endif

#ifdef MONGODB_MODULE
	#define IF_ENABLE_MONGODB( x ) x
#else
	#define IF_ENABLE_MONGODB( x )
#endif


#ifdef PCAP_DUMP_MODULE
	#define IF_ENABLE_PCAP_DUMP( x ) x
#else
	#define IF_ENABLE_PCAP_DUMP( x )
#endif


#ifdef SIMPLE_REPORT
	#define IF_ENABLE_SIMPLE_REPORT( x ) x
	#define IF_NOT_SIMPLE_REPORT( x )
#else
	#define IF_ENABLE_SIMPLE_REPORT( x )
	#define IF_NOT_SIMPLE_REPORT( x ) x
#endif

#ifdef STAT_REPORT
	#define IF_ENABLE_STAT_REPORT( x ) x
#else
	#define IF_ENABLE_STAT_REPORT( x )
#endif

#ifdef LICENSE_CHECK
	#define IF_ENABLE_LICENSE_CHECK( x ) x
#else
	#define IF_ENABLE_LICENSE_CHECK( x )
#endif

//a string contains list of compiled modules
#define MODULES_LIST                             \
	"DPI"                                        \
	IF_ENABLE_DEBUG( ", DEBUG" )                 \
	IF_ENABLE_LICENSE_CHECK( ", LICENSE" )       \
	IF_ENABLE_REDIS( ", REDIS" )                 \
	IF_ENABLE_KAFKA( ", KAFKA" )                 \
	IF_ENABLE_MONGODB( ", MONGODB" )             \
	IF_ENABLE_PCAP_DUMP( ", PCAP_DUMP" )         \
	IF_ENABLE_PCAP( ", PCAP" )                   \
	IF_ENABLE_DPDK( ", DPDK" )                   \
	IF_ENABLE_SIMPLE_REPORT( ", SIMPLE_REPORT" ) \
	IF_ENABLE_DYNAMIC_CONFIG( ", DYNAMIC_CONF" ) \
	IF_ENABLE_SECURITY(", SECURITY ")


#endif /* SRC_LIB_LIMIT_H_ */
