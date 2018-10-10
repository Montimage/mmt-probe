/*
 * gettimeofday.c
 *
 *  Created on: Oct 5, 2018
 *      Author: nhnghia
 *
 *
 * Benchmark performance of `gettimeofday` function.
 * Compile: gcc clock_gettime.c -o clock_gettime
 */


#include <stdio.h>
#include <time.h>

#define NANO_PER_SEC 1000000000

int main(void)
{
        const size_t num_syscalls = 1000000000;
        struct timespec begin, end, nao;
        const clockid_t clock_id = CLOCK_REALTIME_COARSE;
        int i;
        clock_gettime( clock_id, &begin );
        for (i = 0; i < num_syscalls; ++i) {
        	clock_gettime( clock_id, &nao );
        }
        clock_gettime( clock_id, &end );
        printf("time = %ld.%06ld\n", begin.tv_sec, begin.tv_nsec);
        printf("time = %ld.%06ld\n", end.tv_sec, end.tv_nsec);
        printf("Number of Calls = %zu\n", num_syscalls);
        printf("Time per call: %.3f microsecond\n",
        		( end.tv_sec * NANO_PER_SEC + end.tv_nsec - (begin.tv_sec * NANO_PER_SEC + begin.tv_nsec) ) * 1.0 / num_syscalls / 1000 );
}
