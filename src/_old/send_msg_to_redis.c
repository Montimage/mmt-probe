#include <stdio.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include "thredis.h"
#include "mmt_core.h"
#include "processing.h"

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
	redisReply *reply;
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
			exit(0);
		}
		if (thredis == NULL){
			thredis = thredis_new(redis);
			if(thredis == NULL) {
				printf("Thredis wrapper thredis_new failed\n");
				exit(0);
			}
		}
	}
}
/* This function publish message to redis channel.
 * For multi-session reporting it LPUSH to redis channel */
void send_message_to_redis (char *channel, char * message) {
	// Publish to redis if it is enabled
	mmt_probe_context_t * probe_context = get_probe_context_config();
         printf("message=%s\n",message);
	if (redis != NULL) {
		// Publish an event
		redisReply *reply;
		//reply = (redisReply *) redisCommand    (  redis, "PUBLISH %s %s", channel, message );
		if (probe_context->enable_security_report_multisession == 1 && strcmp(channel,"multisession.report") == 0){
			reply = (redisReply *) thredis_command (thredis,"LPUSH %s %s", channel, message);

		}else {
			reply   = (redisReply *) thredis_command (thredis, "PUBLISH %s %s", channel, message);
		}
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

