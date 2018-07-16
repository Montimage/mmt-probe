/*
 * mmt_bus.h
 *
 *  Created on: May 11, 2018
 *          by: Huu Nghia Nguyen
 * A communication bus among processes and thread.
 * Each subscriber is identified by its thread ID given by function mmt_probe_get_tid().
 */

#ifndef SRC_LIB_MMT_BUS_H_
#define SRC_LIB_MMT_BUS_H_

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>

#include "command.h"
//we send a message that can contain at least one command_t
#define MMT_BUS_MAX_MESSAGE_SIZE ( sizeof( command_t) )

//number of subscribers
#define MMT_BUS_MAX_SUBSCRIBERS      3

/**
 * Create a shared bus.
 * This function must be called before any `fork` in order to share the created bus among the processes.
 * @return
 */
bool mmt_bus_create();

/**
 * Release the resource being allocated to the bus.
 * This function must be called on each concerned process when it does not need to access to the bus.
 */
void mmt_bus_release( );

typedef enum{
	MMT_BUS_SUCCESS            = 0,
	MMT_BUS_LOCK_ERROR         = 1,
	MMT_BUS_OVER_MSG_SIZE      = 2,
	MMT_BUS_NO_INIT            = 3,
	MSG_BUS_OLD_MSG_NO_CONSUME = 4
}mmt_bus_code_t;

/**
 *
 * @param topic_id
 * @param message
 * @param message_size
 * @param reply_code if this is not NULL,
 * 			the caller will be blocked until the message is consumed, then processed by at least one subscriber.
 * 			A subscriber marks its processing by reply a code that is different from DYN_CONF_CMD_DO_NOTHING.
 *          The value of reply_code will be set to this code.
 *
 * @return
 * - MMT_BUS_SUCCESS if everything works well
 * - MMT_BUS_OVER_MSG_SIZE if message_size is bigger than MMT_BUS_MAX_MESSAGE_SIZE
 * - MMT_BUS_NO_INIT if the function is called before `mmt_bus_create`
 * - MSG_BUS_OLD_MSG_NO_CONSUME if the previous message has not been processed
 */
mmt_bus_code_t mmt_bus_publish( const char *message, size_t message_size, uint16_t *reply_code );

/**
 * @param message
 * @param message_size
 * @param user_data
 *
 */
typedef int (*bus_subscriber_callback_t)( const char *message, size_t message_size, void *user_data );

/**
 * Subscribe the calling process to the bus.
 * When someone publishes a message to the bus, the callback cb will be fired.
 * @param cb
 * @param user_data
 * @return true if successfully, otherwise false
 *
 * @note: each subscriber is unique by its thread ID (given by mmt_probe_get_tid())
 */
bool mmt_bus_subscribe( bus_subscriber_callback_t cb, void *user_data );

/**
 * This function must be called periodically by subscribers to check data value in the bus.
 * After checking, the callback function that was registered by `mmt_bus_subscribe` will be called.
 */
void mmt_bus_subcriber_check();
/**
 * Unsubscribe the calling process from the bus.
 * After unsubscribing, its callbacks are not fire when someone publishes a message to the bus.
 * @return true if successfully, otherwise false
 */
bool mmt_bus_unsubscribe();
#endif /* SRC_LIB_MMT_BUS_H_ */
