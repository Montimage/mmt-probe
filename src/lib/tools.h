/*
 * tools.h
 *
 *  Created on: Dec 15, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_TOOLS_H_
#define SRC_LIB_TOOLS_H_

#define MIN( a, b ) (a>b? b : a )
#define MAX( a, b ) (a<b? b : a )

static inline int mmt_atoi( const char*string, int low, int high, int def ){
	int ret = atoi( string );
	if( ret > high || ret < low ){
		ret = def;
	}
	return ret;
}


static inline long u_second_diff( const struct timeval *end, const struct timeval *start ){
	return ( end->tv_sec - start->tv_sec ) * 1000000 + ( end->tv_usec - start->tv_usec );
}

static inline size_t u_second( const struct timeval *ts ){
	return ts->tv_sec  * 1000000 + ts->tv_usec;
}

static inline size_t m_second( const struct timeval *ts ){
	return (ts->tv_sec  << 10) + (ts->tv_usec >> 10);
}

#endif /* SRC_LIB_TOOLS_H_ */
