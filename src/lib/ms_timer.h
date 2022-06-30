/*
 * ms_timer.h
 *
 * A timer fires each millisecond
 *
 *  Created on: Apr 6, 2022
 *      Author: nhnghia
 */

#ifndef SRC_LIB_MS_TIMER_H_
#define SRC_LIB_MS_TIMER_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

//1 second = 1M microsecond
#define S2US  1000000
//1 millisecond = 1K microseconds
#define MS2US    1000
//1 second = 1K milliseconds
#define S2MS     1000

typedef struct _ms_timer ms_timer_t;

typedef void (ms_timer_callback)( const ms_timer_t *, void *);

struct _ms_timer{
	size_t ns_elapse_since_last_trigger;
	size_t ms_interval;
	struct timeval time;
	ms_timer_callback *fn_callback;
	void *callback_args;
};

static inline void ms_timer_init( ms_timer_t *timer, size_t ms_interval,
		ms_timer_callback *fn_callback, void *callback_args){
	timer->ns_elapse_since_last_trigger = 0;
	timer->time.tv_sec   = 0;
	timer->time.tv_usec  = 0;
	timer->callback_args = callback_args;
	timer->fn_callback   = fn_callback;
	timer->ms_interval   = ms_interval;
}

static inline bool ms_timer_set_time( ms_timer_t *timer, const struct timeval *tv ){
	size_t ns, new_ns;
	//for the first time
	if( timer->time.tv_sec == 0 && timer->time.tv_usec == 0){
		//remember the timestamp
		timer->time.tv_sec  = tv->tv_sec;
		timer->time.tv_usec = tv->tv_usec;
		return false;
	}
	ns     = timer->time.tv_sec * S2US + timer->time.tv_usec;
	new_ns = tv->tv_sec     * S2US + tv->tv_usec;
	//one millisecond of distance
	if( new_ns - ns < timer->ms_interval * MS2US )
		return false;

	timer->ns_elapse_since_last_trigger = new_ns - ns;
	//remember the timestamp
	timer->time.tv_sec  = tv->tv_sec;
	timer->time.tv_usec = tv->tv_usec;

	//fire the callback
	timer->fn_callback( timer, timer->callback_args );
	return true;
}

#endif /* SRC_LIB_MS_TIMER_H_ */
