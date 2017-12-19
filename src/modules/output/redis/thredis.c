#include <errno.h>
#include <hiredis/hiredis.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "thredis.h"
struct redis_wait {
	struct redis_wait* next;
	redisReply* reply;
	pthread_mutex_t mutex;
	pthread_cond_t done;
};
struct thredis {
	redisContext* redis;
	pthread_mutex_t mutex;
	pthread_t reader_thread;
	struct redis_wait* wait_head;
	struct redis_wait** wait_tail;
};
static struct redis_wait*
pop_waiter(thredis_t* thredis) {
	struct redis_wait* wait = thredis->wait_head;
	thredis->wait_head = wait->next;
	if (thredis->wait_head == NULL) {
		thredis->wait_tail = &thredis->wait_head;
	}
	return wait;
}
static void push_waiter(thredis_t* thredis, struct redis_wait* waiter) {
	*thredis->wait_tail = waiter;
	thredis->wait_tail = &waiter->next;
}
static void deliver_reply(thredis_t* thredis, redisReply* reply) {
	struct redis_wait* wait = pop_waiter(thredis);
	wait->reply = reply;
	pthread_mutex_lock(&wait->mutex);
	pthread_cond_signal(&wait->done);
	pthread_mutex_unlock(&wait->mutex);
}
static void*
reader_thread_main(void* ctx) {
	thredis_t* thredis = ctx;
	struct pollfd pfd = { .fd = thredis->redis->fd, .events = POLLIN };
	while (1) {
		int rc = poll(&pfd, 1, -1);
		if (rc < 0 && errno == EINTR) {
			continue;
		}
		if (pfd.revents & POLLERR) {
			// TODO - how do we tell the user about this error?
			pthread_mutex_lock(&thredis->mutex);
			while (thredis->wait_head) {
				deliver_reply(thredis, NULL);
			}
			thredis->redis = NULL;
			pthread_mutex_unlock(&thredis->mutex);
			return NULL;
		}
		if (pfd.revents & POLLIN) {
			pthread_mutex_lock(&thredis->mutex);
			if (redisBufferRead(thredis->redis) != REDIS_OK) {
				// TODO - how do we tell the user about this error?
				while (thredis->wait_head) {
					deliver_reply(thredis, NULL);
				}
				thredis->redis = NULL;
				pthread_mutex_unlock(&thredis->mutex);
				return NULL;
			}
			while (1) {
				redisReply* reply = NULL;
				if (redisGetReplyFromReader(thredis->redis,
						(void**) &reply) != REDIS_OK) {
					// TODO - how do we tell the user about this error?
					while (thredis->wait_head) {
						deliver_reply(thredis, NULL);
					}
					thredis->redis = NULL;
					pthread_mutex_unlock(&thredis->mutex);
					return NULL;
				}
				if (reply == NULL) {
					break;
				}
				deliver_reply(thredis, reply);
			}
			pthread_mutex_unlock(&thredis->mutex);
		}
	}
}
static int flush_writes(redisContext* redis) {
	int done = 0;
	while (!done) {
		int rc = redisBufferWrite(redis, &done);
		if (rc != REDIS_OK) {
			return rc;
		}
	}
	return REDIS_OK;
}
thredis_t*
thredis_new(redisContext* redis) {
	thredis_t* thredis = malloc(sizeof(*thredis));
	if (!thredis) {
		return NULL;
	}
	thredis->redis = redis;
	thredis->wait_head = NULL;
	thredis->wait_tail = &thredis->wait_head;
	if (pthread_mutex_init(&thredis->mutex, NULL)) {
		free(thredis);
		return NULL;
	}
	if (pthread_create(&thredis->reader_thread, NULL, reader_thread_main,
			thredis)) {
		pthread_mutex_destroy(&thredis->mutex);
		free(thredis);
		return NULL;
	}
	return thredis;
}
void thredis_close(thredis_t* thredis) {
	pthread_mutex_lock(&thredis->mutex);
	pthread_cancel(thredis->reader_thread);
	pthread_join(thredis->reader_thread, NULL);
	pthread_mutex_unlock(&thredis->mutex);
	pthread_mutex_destroy(&thredis->mutex);
	free(thredis);
}
redisReply*
thredis_command(thredis_t* thredis, const char* format, ...) {
	va_list va;
	va_start(va, format);
	pthread_mutex_lock(&thredis->mutex);
	if (!thredis->redis) {
		pthread_mutex_unlock(&thredis->mutex);
		va_end(va);
		return NULL;
	}
	if (redisvAppendCommand(thredis->redis, format, va) != REDIS_OK) {
		pthread_mutex_unlock(&thredis->mutex);
		va_end(va);
		return NULL;
	}
	if (flush_writes(thredis->redis) != REDIS_OK) {
		pthread_mutex_unlock(&thredis->mutex);
		va_end(va);
		return NULL;
	}
	struct redis_wait wait = { .next = NULL, .reply = NULL, };
	pthread_mutex_init(&wait.mutex, NULL);
	pthread_cond_init(&wait.done, NULL);
	push_waiter(thredis, &wait);
	pthread_mutex_lock(&wait.mutex);
	pthread_mutex_unlock(&thredis->mutex);
	va_end(va);
	pthread_cond_wait(&wait.done, &wait.mutex);
	pthread_mutex_unlock(&wait.mutex);
	pthread_cond_destroy(&wait.done);
	pthread_mutex_destroy(&wait.mutex);
	return wait.reply;
}
