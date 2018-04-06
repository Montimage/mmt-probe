/*
 * module.h
 *
 *  Created on: Mar 29, 2018
 *  Created by: Huu-Nghia Nguyen <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_MODULE_H_
#define SRC_MODULE_H_

#ifdef DEBUG
	#define __IF_DEBUG( x ) x
#else
	#define __IF_DEBUG( x )
#endif

#ifdef KAFKA
	#define __IF_KAFKA( x ) x
#else
	#define __IF_KAFKA( x )
#endif

#ifdef REDIS
	#define __IF_REDIS( x ) x
#else
	#define __IF_REDIS( x )
#endif

//new version of Security: mmt-security
#ifdef SECURITY
	#define __IF_SECURITY( x ) x
#else
	#define __IF_SECURITY( x )
#endif

//old version of Security that is inside mmt-dpi
#ifdef SECURITY_V1
	#define __IF_SECURITY_V1( x ) x
#else
	#define __IF_SECURITY_V1( x )
#endif

//a string contains list of compiled modules
#define __MODULES                   \
	""                              \
	__IF_DEBUG( "DEBUG " )          \
	__IF_KAFKA( "KAFKA " )          \
	__IF_REDIS( "REDIS " )          \
	__IF_SECURITY("SECURITY ")      \
	__IF_SECURITY_V1("SECURITY_V1 ")

#endif /* SRC_MODULE_H_ */
