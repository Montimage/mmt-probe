/*
 * version.c
 *
 *  Created on: Dec 12, 2017
 *      Author: nhnghia
 */

const char* get_version(){
#ifndef VERSION
	#define VERSION "unknown"
#endif

#ifndef GIT_VERSION
	#define GIT_VERSION "unknown"
#endif
	return VERSION " (" GIT_VERSION " - " __DATE__ " " __TIME__ ")";
}
