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

#endif /* SRC_LIB_TOOLS_H_ */
