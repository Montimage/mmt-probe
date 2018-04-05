/*
 * dynamic_conf.c
 *
 *  Created on: Dec 27, 2017
 *          by: Huu Nghia
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "dynamic_conf.h"
#include "../../lib/configure.h"
#include "../../lib/linked_list.h"
#include "../../lib/memory.h"



typedef struct callback_node_struct{
	dynamic_conf_prefix_t prefix;

	void *user_data;
	dynamic_conf_callback callback;

	struct callback_node_struct *next;
}callback_node_t;;

struct dynamic_conf_struct{
	uint32_t lcore_id; //id of logical core on which the timer is running
	bool is_running;
	callback_node_t *callback_list;

	pthread_t thread_handler;
	char *file_descriptor;
	pthread_spinlock_t spin_lock;
};


dynamic_config_context_t *dynamic_conf_alloc_and_init( const char * file_descriptor ){
	dynamic_config_context_t *ret = alloc( sizeof( dynamic_config_context_t ));
	ret->file_descriptor = strdup( file_descriptor );

	ret->callback_list = NULL;
	return ret;
}

static bool _is_listening( dynamic_config_context_t *context ){
	bool ret;
	ret = context->is_running;
	return ret;
}

bool dynamic_conf_register( dynamic_config_context_t *context, dynamic_conf_prefix_t prefix,  dynamic_conf_callback cb, void *user_data  ){
	if( _is_listening(context) )
		return false;

	callback_node_t *el;
	LL_FOREACH( context->callback_list, el ){
		if( el->prefix == prefix ){
			DEBUG( "Prefix %d has been registered.", prefix );
			return false;
		}
	}

	el = alloc( sizeof(callback_node_t));
	el->prefix = prefix;
	el->callback = cb;
	el->user_data = user_data;
	el->next = NULL;
	LL_APPEND( context->callback_list, el );

	return true;
}

bool dynamic_conf_start( dynamic_config_context_t *context ){
	if( _is_listening(context) )
		return true;

	int ret = mkfifo( context->file_descriptor, 0666 );
	if( ret != 0 ){
		log_write( LOG_ERR, "Error while creating file descriptor for dynamic configuration at %s: %s",
				context->file_descriptor, strerror( errno ));
		return false;
	}


}
