/*
 * restart_proc.c
 *
 *  Created on: May 9, 2018
 *          by: Huu Nghia Nguyen
 */

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"
#include "restart_proc.h"

void restart_application( const char *filename, char *const argv[] ){
	static int counter = 0;
	int child_pid;

	//clone this process
	//why do we need to clone this process? (rather than calling execv directly)
	//
	child_pid = fork();
	if (child_pid < 0) {
		log_write( LOG_ERR, "Fork failed" );
		exit( EXIT_FAILURE );
	}

	if (child_pid  == 0) {
		//we are in the child process
		char arg_str[ 1000 ];
		int i=0, index=0;
		//join argv
		while( argv[i] != NULL ){
			index += snprintf( &arg_str[index], sizeof( arg_str) - index, " %s", argv[i] );
			i++;
		}

		log_write( LOG_INFO, "%d: Start a new process %d (%s)", ++counter, getpid(), arg_str );

		int rv = execv ( filename, argv);
		if ( rv == -1) {
			log_write( LOG_ERR, "Cannot start %s", filename );
			exit (EXIT_FAILURE);
		}else{
			//never touch here.
		}
	} else {
		//we are in the parent process => exit
		log_write( LOG_INFO, "Killing %d\n", getpid());
		exit (EXIT_FAILURE);
	}
}
