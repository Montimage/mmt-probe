/*
 * dpdk_alloc_perf.c
 *
 *  Created on: Aug 24, 2018
 *          by: Huu Nghia Nguyen
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>

static int
lcore_hello(__attribute__((unused)) void *arg){
	const size_t loop = 100000;
	size_t i;
	size_t start_ts;
	size_t rte_ts = 0, glib_ts = 0;
	void *rte_p, *glib_p;

	size_t size;
	srand(time(NULL));

	for( i=0; i<loop; i++ ){
		//memory segment size
		size = rand() % 2048;

		//glib
		start_ts = rte_rdtsc();
		glib_p = malloc( size );
		glib_ts += rte_rdtsc() - start_ts;

		//dpdk
		start_ts = rte_rdtsc();
		rte_p = rte_malloc( NULL, size, 0 );
		rte_ts += rte_rdtsc() - start_ts;

		//glib
		start_ts = rte_rdtsc();
		free( glib_p );
		glib_ts += rte_rdtsc() - start_ts;

		//dpdk
		start_ts = rte_rdtsc();
		rte_free( rte_p );
		rte_ts += rte_rdtsc() - start_ts;
	}

	printf("core %u:  rte: %zu (%.2f), glib: %zu (%.2f)\n",
			rte_lcore_id(),
			rte_ts,  rte_ts*100.0/loop,
			glib_ts, glib_ts*100.0/loop );
	return 0;
}

int main(int argc, char **argv) {
	int ret;
	unsigned lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* call it on master lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();
	return 0;
}
