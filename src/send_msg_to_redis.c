#include <stdio.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "thredis.h"
#include "mmt_core.h"

static redisContext *redis = NULL;
static thredis_t* thredis = NULL;

/**
 * Connects to redis server and exits if the connection fails
 *
 * @param hostname hostname of the redis server
 * @param port port number of the redis server
 *
 *

*
 * In short, to subscribe to "localhost" channel:*/


void init_redis (char * hostname, int port) {
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    // Connect to redis if not yet done
    if (redis == NULL){
        redis = redisConnectWithTimeout(hostname, port, timeout);
        if (redis == NULL || redis->err) {
            if (redis) {
                printf("Connection error nb %d: %s\n", redis->err, redis->errstr);
                redisFree(redis);
            } else {
                printf("Connection error: can't allocate redis context\n");
            }
            exit(1);
        }
        if (thredis == NULL){
            thredis = thredis_new(redis);
            if(thredis == NULL) {
                printf("Thredis wrapper thredis_new failed\n");
                exit(1);
            }
        }
    }
}


void send_message_to_redis (char *channel, char * message) {
    // Publish to redis if it is enabled
	//printf ("\n%s_\n%s",channel,message);
    if (redis != NULL) {
        // Publish an event
        redisReply *reply;
        //reply = (redisReply *) redisCommand    (  redis, "PUBLISH %s %s", channel, message );
        reply   = (redisReply *) thredis_command (thredis, "PUBLISH %s [%s]", channel, message );

        if(reply == NULL){
            printf("Redis command error: can't allocate reply context\n");
        }else{
            if(redis->err != 0){
                printf("Redis command error nb %d: %s\n", redis->err, redis->errstr);
            }
            if(reply->type == REDIS_REPLY_ERROR){
                printf("Redis reply error nb %d: %s\n", reply->type, reply->str);
            }
            freeReplyObject(reply);
        }
    }

}
