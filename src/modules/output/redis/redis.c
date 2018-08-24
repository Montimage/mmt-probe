/*
 * redis.c
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */

#include "redis.h"
#include "thredis.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc.h"

static redisContext *redis = NULL;
static thredis_t* thredis = NULL;

struct redis_output_struct{
	const redis_output_conf_t *config;
};

redis_output_t *redis_init( const redis_output_conf_t *conf ){
	if( ! conf->is_enable )
		return NULL;

	struct timeval timeout = { 1, 500000 }; // 1.5 seconds

	// Connect to redis if not yet done
	if (redis == NULL){
		redis = redisConnectWithTimeout(conf->host.host_name, conf->host.port_number, timeout);
		if (redis == NULL || redis->err) {
			if (redis) {
				log_write( LOG_ERR, "Connection error nb %d: %s", redis->err, redis->errstr);
				redisFree(redis);
				abort();
			} else {
				ABORT( "Connection error: can't allocate redis context");
			}

		}

		if (thredis == NULL){
			thredis = thredis_new(redis);
			if(thredis == NULL)
				ABORT("Thredis wrapper thredis_new failed");
		}
	}
	redis_output_t *ret = mmt_alloc_and_init_zero( sizeof( redis_output_t ) );
	ret->config = conf;
	return ret;
}

void redis_release( redis_output_t *context){
	if( context )
		mmt_probe_free( context );

	if( thredis ){
		thredis_close( thredis );
		thredis = NULL;
	}
	if( redis ){
		redisFree( redis );
		redis = NULL;
	}
}

bool redis_send( redis_output_t *redis_context, const char *msg ){
	// Publish to redis if it is enabled
	if (redis == NULL)
		return false;

	// Publish an event
	redisReply *reply =  thredis_command( thredis, "PUBLISH %s %s", redis_context->config->channel_name, msg );

	if(reply == NULL){
		log_write( LOG_ERR, "Redis command error: can't allocate reply context");
		return false;
	}else{
		if(redis->err != 0){
			log_write( LOG_ERR, "Redis command error nb %d: %s", redis->err, redis->errstr);
			goto _fail;
		}
		if(reply->type == REDIS_REPLY_ERROR){
			log_write( LOG_ERR, "Redis reply error nb %d: %s", reply->type, reply->str);
			goto _fail;
		}

		freeReplyObject(reply);
		return true;
	}

	_fail:
	freeReplyObject(reply);
	return false;
}
