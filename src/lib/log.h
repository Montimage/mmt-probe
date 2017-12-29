/*
 * log.h
 *
 *  Created on: Dec 13, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_LOG_H_
#define SRC_LIB_LOG_H_

#include <syslog.h>

/**
 * Open system log file
 */
static inline void log_open(){
	openlog( "mmt-probe", LOG_NDELAY | LOG_CONS | LOG_PERROR, LOG_USER);
}

#define log_write syslog

#ifdef DEBUG_MODE
#define DEBUG( format, ... ) \
    printf( "DEBUG %s:%d: " format "\n", __FILE__, __LINE__ ,## __VA_ARGS__ )
#else
	#define DEBUG( ... )
#endif

/**
 * Close log file
 */
static inline void log_close(){
	closelog();
}


#define ABORT( format, ... )                                                \
	do{                                                                     \
		log_write( LOG_ERR, format,## __VA_ARGS__ );                        \
		abort();                                                            \
	}while( 0 )                                                             \

#endif /* SRC_LIB_LOG_H_ */
