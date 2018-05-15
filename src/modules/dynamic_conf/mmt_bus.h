/*
 * mmt_bus.h
 *
 *  Created on: May 11, 2018
 *          by: Huu Nghia Nguyen
 * A communication bus between processes.
 */

#ifndef SRC_LIB_MMT_BUS_H_
#define SRC_LIB_MMT_BUS_H_

#include <stdbool.h>
#include <stdio.h>

#define MMT_BUS_MAX_MESSAGE_SIZE 10000
//number of subscribers
#define MMT_BUS_MAX_SUBSCRIBERS      3

bool mmt_bus_create( int signal_id );

void mmt_bus_release( );

typedef enum{
	MMT_BUS_SUCCESS,
	MMT_BUS_LOCK_ERROR,
	MMT_BUS_OVER_MSG_SIZE,
	MMT_BUS_NO_INIT,
	MSG_BUS_OLD_MSG_NO_CONSUME
}mmt_bus_code_t;
/**
 *
 * @param topic_id
 * @param message
 * @param message_size
 * @param nb_consumers if this is not NULL,
 * 			the function will be blocked until the message are consumed by all subscribers,
 * 			then the function will set value of nb_consumers as number of subscribers.
 *
 * @return
 */
mmt_bus_code_t mmt_bus_publish( const void *message, size_t message_size, size_t *nb_consumers );

/**
 * @param message
 * @param message_size
 * @param user_data
 *
 * @note: the functions used inside bus_subscriber_callback_t must be async-safe
 *  as they are called inside an interrupt handler.
 */
typedef void (*bus_subscriber_callback_t)( const char *message, size_t message_size, void *user_data );

/**
 * Subscribe the calling process to the bus.
 * When someone publishes a message to the bus, the callback cb will be fired.
 * @param cb
 * @param user_data
 * @return true if successfully, otherwise false
 */
bool mmt_bus_subscribe( bus_subscriber_callback_t cb, void *user_data );

/**
 * Unsubscribe the calling process from the bus.
 * After unsubscribing, its callbacks are not fire when someone publishes a message to the bus.
 * The signal_id is also re-attach to the default handler (using  SIG_DFL).
 * @return true if successfully, otherwise false
 */
bool mmt_bus_unsubscribe();
#endif /* SRC_LIB_MMT_BUS_H_ */
