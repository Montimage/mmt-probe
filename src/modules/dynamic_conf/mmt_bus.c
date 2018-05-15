/*
 * mmt_bus.c
 *
 *  Created on: May 15, 2018
 *          by: Huu Nghia Nguyen
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "mmt_bus.h"
#include "../../lib/tools.h"
#include "../../lib/log.h"

struct subscriber{
	pid_t pid;
	void *user_data;
	bus_subscriber_callback_t callback;
};

struct mmt_bus{
	int signal_id;
	uint8_t nb_subscribers;
	uint8_t nb_consumers;   //nb of subscribers that consumed the message
	struct subscriber sub_lst[ MMT_BUS_MAX_SUBSCRIBERS ];
	pthread_mutex_t mutex; //mutex to synchronize read/write data among publishers and subscribers

	size_t message_size; //real size of message being used
	char message[ MMT_BUS_MAX_MESSAGE_SIZE ];
};

static struct mmt_bus *bus = NULL;

bool mmt_bus_create( int signal_id ){
	//already created
	if( bus != NULL )
		return false;

	//size of memory segment to share
	size_t total_shared_memory_size = sizeof( struct mmt_bus);

	//create a shared memory segment
	bus = mmap(0, total_shared_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (bus == MAP_FAILED) {
		log_write(LOG_ERR, "Cannot create shared memory for %zu B: %s", total_shared_memory_size, strerror( errno ));
		abort();
	}

	//initialize memory segment
	memset( bus, 0, total_shared_memory_size );
	bus->signal_id = signal_id;

	// initialise mutex so it works properly in shared memory
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&bus->mutex, &attr);

	return true;
}

int mmt_bus_publish( const void *message, size_t message_size, size_t *nb_consumers ){
	int i;
	if( bus == NULL )
		return MMT_BUS_NO_INIT;
	if( message_size > MMT_BUS_MAX_MESSAGE_SIZE )
		return MMT_BUS_OVER_MSG_SIZE;

	bool old_msg_is_consummed = false;
	//block memory
	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return MMT_BUS_LOCK_ERROR;
	}
	if( bus->nb_consumers == bus->nb_subscribers  ){
		old_msg_is_consummed = true;

		//store data to the shared memory segment
		memcpy( bus->message, message, message_size );
		bus->message_size = message_size;

		//this message is fresh, no one consumes it
		bus->nb_consumers = 0;
	}

	//unblock
	pthread_mutex_unlock( &bus->mutex );

	if( !old_msg_is_consummed )
		return MSG_BUS_OLD_MSG_NO_CONSUME;

	//notify to all subscribers
	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ )
		if( bus->sub_lst[i].pid != 0 ){
			kill( bus->sub_lst[i].pid, bus->signal_id );
		}

	if( nb_consumers == NULL )
		return MMT_BUS_SUCCESS;

	//waiting for the message is consumed by all subscribers
	*nb_consumers = 0;
	while( *nb_consumers == 0 ){
		if( pthread_mutex_lock( &bus->mutex ) != 0){
			log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
			return MMT_BUS_LOCK_ERROR;
		}
		if( bus->nb_consumers == bus->nb_subscribers  )
			*nb_consumers = bus->nb_consumers;
		//unblock
		pthread_mutex_unlock( &bus->mutex );

		usleep( 10000 );
	}

	return MMT_BUS_SUCCESS;
}

void _signal_handler( int type ){
	int i;
	char msg[ MMT_BUS_MAX_MESSAGE_SIZE ];
	size_t msg_size = 0;

	pid_t pid = getpid();
	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ )
		if( bus->sub_lst[i].pid == pid ){
			if( bus->sub_lst[i].callback != NULL ){

				if( pthread_mutex_lock( &bus->mutex ) == 0){
					msg_size = bus->message_size;
					memcpy( msg, bus->message, msg_size );
					bus->nb_consumers ++;
					//unblock
					pthread_mutex_unlock( &bus->mutex );

					bus->sub_lst[i].callback( bus->message, bus->message_size, bus->sub_lst[i].user_data );
				}else
					log_write( LOG_ERR, "Cannot lock mmt-bus for reading: %s", strerror( errno) );
				return;
			}
		}
}

bool mmt_bus_subscribe( bus_subscriber_callback_t cb, void *user_data ){
	int i;
	pid_t pid = getpid();

	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return false;
	}

	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ ){
		//already exist
		if( bus->sub_lst[i].pid == pid )
			return false;

		//found one slot
		if( bus->sub_lst[i].pid == 0 ){
			//register in the list
			bus->sub_lst[i].pid = pid;
			bus->sub_lst[i].callback = cb;
			bus->sub_lst[i].user_data = user_data;

			bus->nb_subscribers ++;

			//register a handler to respond to a notification from a publisher
			signal( bus->signal_id, _signal_handler );

			pthread_mutex_unlock( &bus->mutex );
			return true;
		}
	}
	pthread_mutex_unlock( &bus->mutex );

	//no more slot for this
	return false;
}

bool mmt_bus_unsubscribe(){
	int i;
	pid_t pid = getpid();

	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return false;
	}

	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ ){
		//found one process
		if( bus->sub_lst[i].pid == pid ){
			bus->sub_lst[i].pid = 0; //this is enough to unregister
			//unregister signal handler
			signal( bus->signal_id, SIG_DFL );

			bus->nb_subscribers --;

			pthread_mutex_unlock( &bus->mutex );
			return true;
		}
	}

	pthread_mutex_unlock( &bus->mutex );
	return false;

}

void mmt_bus_release(){
	if( bus == NULL )
		return;
	munmap( bus, sizeof( struct mmt_bus) );
	bus = NULL;
}
