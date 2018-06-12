/*
 * string_builder.c
 *
 *  Created on: Jun 4, 2018
 *          by: Huu Nghia Nguyen
 */


#include "../lib/string_builder.h"

int main(){
	char message[1000];
	struct timeval time;
	time.tv_sec = 1;
	time.tv_usec = 2;
	int offset = append_timeval(message, sizeof( message ), &time );
	message[ offset ] = '\0';
	printf("%s", message );
}
