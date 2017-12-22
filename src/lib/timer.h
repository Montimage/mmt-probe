/*
 * timer.h
 *
 *  Created on: Dec 22, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_TIMER_H_
#define SRC_LIB_TIMER_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct mmt_timer_struct_t mmt_timer_t;


typedef void( *mmt_timer_callback )( const mmt_timer_t *timer, void *user_data );


mmt_timer_t* mmt_timer_create( uint32_t core_id );

bool mmt_timer_register_callback( mmt_timer_t *timer, uint32_t second, mmt_timer_callback cb, void *user_data );

void mmt_timer_stop( mmt_timer_t *timer );

bool mmt_timer_is_running( mmt_timer_t *timer );

bool mmt_timer_start( mmt_timer_t *timer );

bool mmt_timer_release( mmt_timer_t *timer);

#endif /* SRC_LIB_TIMER_H_ */
