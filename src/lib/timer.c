/*
 * timer.c
 *
 *  Created on: Dec 22, 2017
 *          by: Huu Nghia
 */

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/timerfd.h>

#include "timer.h"
#include "alloc.h"
#include "log.h"
#include "system_info.h"

typedef struct timer_callback_node_struct{
	void *user_data;
	mmt_timer_callback callback;
	uint32_t second;
	struct timer_callback_node_struct *next;
}timer_callback_node_t;;

struct mmt_timer_struct_t{
	uint32_t lcore_id; //id of logical core on which the timer is running
	uint32_t second; //number of seconds from starting moment
	timer_callback_node_t *callback_list;

	pthread_t thread_handler;

	pthread_spinlock_t spin_lock;
	bool is_running;
};


mmt_timer_t* mmt_timer_create( uint32_t core_id ){
	mmt_timer_t *ret = alloc( sizeof( mmt_timer_t ) );

	ret->lcore_id = core_id;
	ret->second   = 0;
	ret->callback_list = NULL;
	ret->is_running = false;
	return ret;
}

void *_timer_handler( void *args ){
	mmt_timer_t *timer = (mmt_timer_t *) args;
	timer_callback_node_t *node;
	timer->is_running = true;

	uint64_t expirations = 0;

	move_the_current_thread_to_a_core( timer->lcore_id, 0 );

	// Create the timer
	int timer_fd = timerfd_create (CLOCK_REALTIME, TFD_NONBLOCK);
	if( timer_fd != 0 ){
		log_write(LOG_ERR, "Cannot create timer descriptor: %s", strerror( errno ) );
		return NULL;
	}

	struct itimerspec itval;
	//Make the timer periodic
	itval.it_interval.tv_sec  = 1; //1second
	itval.it_interval.tv_nsec = 0;
	itval.it_value.tv_sec     = 1; //1second
	itval.it_value.tv_nsec    = 0;

	int ret = timerfd_settime (timer_fd, 0, &itval, NULL);
	if( ret != 0 ){
		log_write(LOG_ERR, "Cannot set timer: %s", strerror( errno ) );
		return NULL;
	}

	while( true ){
		ret = read (timer_fd, &expirations, sizeof (expirations));
		if( ret != 0 ){
			log_write(LOG_ERR, "Cannot read timer: %s", strerror( errno ) );
			break;
		}

		if( !mmt_timer_is_running( timer ) )
			break;

		timer->second ++;

		//"missed" should always be >= 1, but just to be sure, check it is not 0 anyway
//		if (expirations > 1) {
//			printf("missed %lu", expirations - 1);
//			fflush( stdout );
//		}

		node = timer->callback_list;
		while( node != NULL ){
			if( node->second == timer->second )
				node->callback( timer, node->user_data );
			node = node->next;
		}
	}
	pthread_exit( NULL );
	return NULL;
}

bool mmt_timer_start( mmt_timer_t *timer ){
	if( mmt_timer_is_running( timer ) )
		return false;

	int ret = pthread_create( &timer->thread_handler, NULL, _timer_handler, timer );

	return (ret == 0);
}

bool mmt_timer_is_running( mmt_timer_t *timer ){
	bool ret;
	pthread_spin_lock(& timer->spin_lock);
	ret = timer->is_running;
	pthread_spin_unlock(& timer->spin_lock);
	return ret;
}

void mmt_timer_stop( mmt_timer_t *timer ){
	pthread_spin_lock(& timer->spin_lock);
	timer->is_running = false;
	pthread_spin_unlock(& timer->spin_lock);
}

bool mmt_timer_release( mmt_timer_t *timer ){
	if( mmt_timer_is_running( timer ) )
		return false;
	//free its list
	timer_callback_node_t *prv, *node = timer->callback_list;
	while( node != NULL ){
		prv = node;
		node = node->next;

		//call its callback last time
		node->callback( timer, node->user_data );

		xfree( prv );
	}

	xfree( timer );
	return true;
}

bool mmt_timer_register_callback( mmt_timer_t *timer, uint32_t second, mmt_timer_callback cb, void *user_data ){
	if( mmt_timer_is_running( timer ) )
		return false;

	timer_callback_node_t *node = alloc( sizeof( timer_callback_node_t ));
	node->next      = NULL;
	node->callback  = cb;
	node->second    = second;
	node->user_data = user_data;

	if( timer->callback_list == NULL )
		timer->callback_list = node;
	else{
		timer_callback_node_t *tmp = timer->callback_list;
		//goto the last node
		while( tmp->next != NULL )
			tmp = tmp->next;
		//append
		tmp->next = node;
	}
	return true;
}
