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
	openlog("mmt-probe", LOG_NDELAY | LOG_CONS | LOG_PERROR, LOG_USER);
}

#define log_write syslog

#ifdef DEBUG_MODE
#define log_debug( format, ... ) \
    printf( "DEBUG %s:%d: " format "\n", __FILE__, __LINE__ ,## __VA_ARGS__ )
#else
	#define log_debug( ... )
#endif

/**
 * Close log file
 */
static inline void log_close(){
	closelog();
}

#endif /* SRC_LIB_LOG_H_ */
