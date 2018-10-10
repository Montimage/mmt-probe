/*
 * dpdk_rdtsc.c
 *
 *  Created on: Oct 10, 2018
 *      Author: nhnghia
 *
 * Performance of rte_rdtsc
 */

#include <rte_cycles.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdint.h>

#define MICRO_PER_SEC 1000000

static uint64_t nb_cycles_per_second;

static inline void _gettimeofday( struct timeval *time ){

	uint64_t t = rte_rdtsc();

	time->tv_sec  = t / nb_cycles_per_second;
	time->tv_usec = (t - time->tv_sec * nb_cycles_per_second * US_PER_S * 1.0 ) / nb_cycles_per_second;
}

int main(int argc, char *argv[]){
	const size_t num_syscalls = 1000000000;
	struct timeval begin, end, nao;
	size_t i;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");


	nb_cycles_per_second = rte_get_timer_hz();

	if( nb_cycles_per_second == 0 ){
		printf("Cannot get rte_get_timer_hz\n");
		return 1;
	}


	gettimeofday(&begin, NULL);
	for (i = 0; i < num_syscalls; ++i) {
		_gettimeofday(&nao);
	}
	gettimeofday(&end, NULL);
	printf("start time = %ld.%06ld\n", begin.tv_sec, begin.tv_usec);
	printf("end time   = %ld.%06ld\n", end.tv_sec, end.tv_usec);
	printf("Number of Calls = %zu\n", num_syscalls);
	printf("Time per call: %.5f microsecond\n",
			( end.tv_sec * MICRO_PER_SEC + end.tv_usec - (begin.tv_sec * MICRO_PER_SEC + begin.tv_usec) ) * 1.0 / num_syscalls );

	printf("Now: %ld.%ld\n", nao.tv_sec, nao.tv_usec );

	return 0;
}
