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
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "mmt_bus.h"
#include "../../lib/tools.h"
#include "../../lib/log.h"
#include "../../lib/system_info.h"

struct subscriber{
	pid_t pid;
	bool is_consumed;
	void *user_data;
	bus_subscriber_callback_t callback;
};

struct mmt_bus{

	/**
	 * Mutex to synchronize read/write data among publishers and subscribers
	 */
	pthread_mutex_t mutex;

	/**
	 * Number of real subscribers presented in the list below
	 */
	uint8_t nb_subscribers;
	/**
	 * List of subscribers
	 */
	struct subscriber sub_lst[ MMT_BUS_MAX_SUBSCRIBERS ];

	/**
	 * The message and message_size are used to transfer data from a publisher to the subscribers
	 */
	size_t message_size; //real size of message being used
	char message[ MMT_BUS_MAX_MESSAGE_SIZE ];

	/**
	 * reply_code is used to store effective returned value of one subscriber when it finishes processing the message above.
	 *
	 * All subscribers receive the message being published.
	 * A subscriber represents its processing of the message by returning an effective code that is different with DYN_CONF_CMD_DO_NOTHING.
	 *
	 * If more than one subscribers return their value, then, reply_code stores only the first return value.
	 *   That is the value being received the most early.
	 *
	 * The published message is considered as being consumed if reply_code != DYN_CONF_CMD_DO_NOTHING.
	 */
	int reply_code;
};

static struct mmt_bus *bus = NULL;

bool mmt_bus_create(){
	//already created
	if( bus != NULL )
		return false;

	//size of memory segment to share
	size_t total_shared_memory_size = sizeof( struct mmt_bus);

	//create a shared memory segment
	bus = mmap(0, total_shared_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	ASSERT(bus != MAP_FAILED, "Cannot create shared memory for %zu B: %s", total_shared_memory_size, strerror( errno ));

	//initialize memory segment
	memset( bus, 0, total_shared_memory_size );

	// initialise mutex so it works properly in shared memory
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&bus->mutex, &attr);

	return true;
}

mmt_bus_code_t mmt_bus_publish( const char*message, size_t message_size, uint16_t *reply_code ){
	int i;
	if( bus == NULL )
		return MMT_BUS_NO_INIT;

	if( message_size > MMT_BUS_MAX_MESSAGE_SIZE )
		return MMT_BUS_OVER_MSG_SIZE;

	bool old_msg_is_consummed = false;

	//cannot block memory?
	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return MMT_BUS_LOCK_ERROR;
	}

//	DEBUG("Number of subscribers: %d", bus->nb_subscribers );

	//the new message is published only if the previous one must be processed by at least one subscriber
	if( bus->reply_code != DYN_CONF_CMD_REPLY_DO_NOTHING ){
		old_msg_is_consummed = true;

		//store data to the shared memory segment
		memcpy( bus->message, message, message_size );
		bus->message_size = message_size;

		//the new message is fresh, no one consumes it
		bus->reply_code = DYN_CONF_CMD_REPLY_DO_NOTHING;
		//no subscriber consumes the message
		for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ )
			bus->sub_lst[i].is_consumed = false;
	}

	//unblock
	pthread_mutex_unlock( &bus->mutex );

	//the previous message has not been yet consumed
	if( !old_msg_is_consummed )
		return MSG_BUS_OLD_MSG_NO_CONSUME;

	//if publisher does not intend to wait for its message being consumed
	if( reply_code == NULL )
		return MMT_BUS_SUCCESS;

	//waiting for a response from one of the subscribers
	while( true ){

		if( pthread_mutex_lock( &bus->mutex ) != 0){
			log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
			return MMT_BUS_LOCK_ERROR;
		}

		//one subscriber replied
		if( bus->reply_code != DYN_CONF_CMD_REPLY_DO_NOTHING ){
			*reply_code = bus->reply_code;
			goto _end;
		}

		//unblock
		pthread_mutex_unlock( &bus->mutex );

		nanosleep( (const struct timespec[]){{ .tv_sec = 0, .tv_nsec = 10000L}}, NULL );
	}

	_end:
	pthread_mutex_unlock( &bus->mutex );

	return MMT_BUS_SUCCESS;
}

void mmt_bus_subcriber_check(){
	int i;
	char msg[ MMT_BUS_MAX_MESSAGE_SIZE ];
	size_t msg_size = 0;
	pid_t pid = mmt_probe_get_tid();
	struct subscriber *sub;
	bool is_consumed;

	if( bus == NULL )
		return;
//	DEBUG("check from subscriber %d", pid );

	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ ){
		sub = &bus->sub_lst[i];
		if( sub->pid == pid ){
			if( sub->callback != NULL ){
				if( pthread_mutex_lock( &bus->mutex ) == 0){
					is_consumed = sub->is_consumed;
					if( !is_consumed ){
						msg_size = bus->message_size;
						memcpy( msg, bus->message, msg_size );
					}
					pthread_mutex_unlock( &bus->mutex ); //unblock

					//fire the callback
					if( ! is_consumed ){

						//fire the callback of the subscriber
						int ret = sub->callback( msg, msg_size, sub->user_data );

						if( pthread_mutex_lock( &bus->mutex ) == 0){
							//mark as being consumed by this subscriber
							sub->is_consumed = true;

							//update reply code if no one updates
							if( bus->reply_code == DYN_CONF_CMD_REPLY_DO_NOTHING ){
								bus->reply_code = ret;
							}
							pthread_mutex_unlock( &bus->mutex );
						}
					}

				}else
					log_write( LOG_ERR, "Cannot lock mmt-bus for reading: %s", strerror( errno) );
				return;
			}
			log_write( LOG_ERR, "Callback off %d-th (pid = %d) is NULL", i, pid );
			return;
		}
	}
}

/**
 * Subscribe the calling process to the bus.
 * When someone publishes a message to the bus, the callback cb will be fired.
 * @param cb
 * @param user_data
 * @return true if successfully, otherwise false
 */
bool mmt_bus_subscribe( bus_subscriber_callback_t cb, void *user_data ){
	int i;
	pid_t pid;

	if( bus == NULL )
		return false;

	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return false;
	}

	DEBUG("Number of subscribers: %d", bus->nb_subscribers );
	//get the caller's thread ID (TID).  In a single-threaded
    //process, the thread ID is equal to the process ID (PID, as returned
    //by getpid(2)).  In a multithreaded process, all threads have the same
    //PID, but each one has a unique TID.
	pid = mmt_probe_get_tid();

	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ ){
		//already exist
		if( bus->sub_lst[i].pid == pid ){
			//this can be happened only by my mistake (the coder)
			//when the function is called twice
			MY_MISTAKE("subscriber %d was subscribed", pid );
			return false;
		}

		//found one slot
		if( bus->sub_lst[i].pid == 0 ){
			//register in the list
			bus->sub_lst[i].pid = pid;
			bus->sub_lst[i].callback = cb;
			bus->sub_lst[i].user_data = user_data;
			//Suppose that the new subscriber consumed old message
			//=> it can receive only the messages coming after its subscription
			bus->sub_lst[i].is_consumed = true;
			bus->nb_subscribers ++;

//			DEBUG("Number of subscribers: %d", bus->nb_subscribers );

			pthread_mutex_unlock( &bus->mutex );
			return true;
		}
	}
	pthread_mutex_unlock( &bus->mutex );

	log_write( LOG_ERR, "Number of subscribers is bigger than the limit (%d)", MMT_BUS_MAX_SUBSCRIBERS );
	//no more slot for this
	return false;
}

bool mmt_bus_unsubscribe(){
	int i;
	pid_t pid = mmt_probe_get_tid();

	if( bus == NULL )
		return false;

	if( pthread_mutex_lock( &bus->mutex ) != 0){
		log_write( LOG_ERR, "Cannot lock mmt-bus for publishing: %s", strerror( errno) );
		return false;
	}

	for( i=0; i<MMT_BUS_MAX_SUBSCRIBERS; i++ ){
		//found one process
		if( bus->sub_lst[i].pid == pid ){
			bus->sub_lst[i].pid = 0; //this is enough to unregister

			bus->nb_subscribers --;

			pthread_mutex_unlock( &bus->mutex );

			return true;
		}
	}

	//the caller has not subscribed yet => does not exist in our list of subscribers
	pthread_mutex_unlock( &bus->mutex );
	return false;

}

void mmt_bus_release(){
	if( bus == NULL )
		return;

	munmap( bus, sizeof( struct mmt_bus) );
	bus = NULL; //avoid to release more than once
}
