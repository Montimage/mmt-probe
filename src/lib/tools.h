/*
 * tools.h
 *
 *  Created on: Dec 15, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_TOOLS_H_
#define SRC_LIB_TOOLS_H_
#include <sys/time.h>

#define MIN( a, b ) (a>b? b : a )
#define MAX( a, b ) (a<b? b : a )

#define MICRO_PER_SEC 1000000

/**
 * Convert a string to an integer.
 * If the result number is outside of [#low, #high] then it will be assigned to #def
 * @param string
 * @param low
 * @param high
 * @param def
 * @return
 */
static inline int mmt_atoi( const char*string, int low, int high, int def ){
	int ret = atoi( string );
	if( ret > high || ret < low ){
		ret = def;
	}
	return ret;
}

/**
 * Get interval, in micro seconds, between two timeval moments
 * @param end
 * @param start
 */
static inline long u_second_diff( const struct timeval *end, const struct timeval *start ){
	return ( end->tv_sec - start->tv_sec ) * MICRO_PER_SEC + ( end->tv_usec - start->tv_usec );
}

/**
 * Get number of micro seconds of a timeval
 * @param ts
 * @return
 */
static inline size_t u_second( const struct timeval *ts ){
	return ts->tv_sec  * MICRO_PER_SEC + ts->tv_usec;
}

/**
 * Get milli seconds of a timeval
 * @param ts
 * @return
 */
static inline size_t m_second( const struct timeval *ts ){
	return (ts->tv_sec  << 10) + (ts->tv_usec >> 10);
}

#endif /* SRC_LIB_TOOLS_H_ */
