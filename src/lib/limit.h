/*
 * limit.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 * This file enable/disable some macro when compiling MMT-Probe.
 */

#ifndef SRC_LIB_LIMIT_H_
#define SRC_LIB_LIMIT_H_
//maximal length of an absolute path
#define MAX_LENGTH_FULL_PATH_FILE_NAME 4096
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
//#ifndef DYNAMIC_CONFIG_MODULE
//#define DYNAMIC_CONFIG_MODULE
//#endif

//end of block to be removed

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

#ifdef SOCKET_MODULE
	#define IF_ENABLE_SOCKET( x ) x
#else
	#define IF_ENABLE_SOCKET( x )
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

#ifdef LTE_REPORT
	#define IF_ENABLE_LTE_REPORT( x ) x
#else
	#define IF_ENABLE_LTE_REPORT( x )
#endif

#if defined STAT_REPORT && !defined SIMPLE_REPORT
	#define IF_ENABLE_STAT_REPORT_FULL( x ) x
#else
	#define IF_ENABLE_STAT_REPORT_FULL( x )
#endif

#ifdef LICENSE_CHECK
	#define IF_ENABLE_LICENSE_CHECK( x ) x
#else
	#define IF_ENABLE_LICENSE_CHECK( x )
#endif

#ifdef TCP_REASSEMBLY_MODULE
	#define IF_ENABLE_TCP_REASSEMBLY( x ) x
#else
	#define IF_ENABLE_TCP_REASSEMBLY( x )
#endif

#ifdef FTP_RECONSTRUCT_MODULE
	#define IF_ENABLE_FTP_RECONSTRUCT( x ) x
#else
	#define IF_ENABLE_FTP_RECONSTRUCT( x )
#endif

#ifdef HTTP_RECONSTRUCT_MODULE
	#define IF_ENABLE_HTTP_RECONSTRUCT( x ) x
#else
	#define IF_ENABLE_HTTP_RECONSTRUCT( x )
#endif

#ifdef QOS_MODULE
	#define IF_ENABLE_QOS( x ) x
#else
	#define IF_ENABLE_QOS( x )
#endif


#ifdef DEBUG_MODE
	#define IF_ENABLE_DEBUG( x ) x
#else
	#define IF_ENABLE_DEBUG( x )
#endif

#ifdef STATIC_LINK
	#define IF_ENABLE_STATIC_LINK( x ) x
#else
	#define IF_ENABLE_STATIC_LINK( x )
#endif
//a string contains list of compiled modules
#define MODULES_LIST                                   \
	"DPI"                                              \
	IF_ENABLE_DPDK( ", DPDK" )                         \
	IF_ENABLE_DYNAMIC_CONFIG( ", DYNAMIC_CONF" )       \
	IF_ENABLE_FTP_RECONSTRUCT( ", FTP_RECONSTRUCT" )   \
	IF_ENABLE_HTTP_RECONSTRUCT( ", HTTP_RECONSTRUCT" ) \
	IF_ENABLE_KAFKA( ", KAFKA" )                       \
	IF_ENABLE_LICENSE_CHECK( ", LICENSE" )             \
	IF_ENABLE_LTE_REPORT( ", LTE_REPORT" )             \
	IF_ENABLE_MONGODB( ", MONGODB" )                   \
	IF_ENABLE_PCAP( ", PCAP" )                         \
	IF_ENABLE_PCAP_DUMP( ", PCAP_DUMP" )               \
	IF_ENABLE_QOS( ", QOS" )                           \
	IF_ENABLE_STAT_REPORT(", REPORT" )                 \
	IF_ENABLE_REDIS( ", REDIS" )                       \
	IF_ENABLE_SIMPLE_REPORT( ", SIMPLE_REPORT" )       \
	IF_ENABLE_SOCKET( ", SOCKET" )                     \
	IF_ENABLE_SECURITY(", SECURITY")                   \
	IF_ENABLE_TCP_REASSEMBLY(", TCP_REASSEMBLY" )      \
	IF_ENABLE_DEBUG( ", debug" )                       \
	IF_ENABLE_STATIC_LINK( ", static-link" )           \


#define _EXIT _exit

//depending on exit value of a child process, the main process can restart or not the child process
/**
 * Exit normally the current process, e.g., when user intends to exit the program
 */
#define EXIT_NORMALLY()        _EXIT( EXIT_SUCCESS )
/**
 * Exit the current process, then the main process will re-create a new child process to replace it.
 * This is helpful to update some parameters, or when facing some errors.
 */
#define EXIT_TOBE_RESTARTED()  _EXIT( EXIT_FAILURE )

#endif /* SRC_LIB_LIMIT_H_ */
