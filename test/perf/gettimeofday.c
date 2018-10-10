/*
 * gettimeofday.c
 *
 *  Created on: Oct 5, 2018
 *      Author: nhnghia
 *
 *
 * Benchmark performance of `gettimeofday` function.
 * Compile: gcc gettimeofday.c -o ben_gettimeofday
 */


#include <stdio.h>
#include <sys/time.h>

#define MICRO_PER_SEC 1000000

int main(void)
{
        const size_t num_syscalls = 1000000000;
        struct timeval begin, end, nao;
        int i;
        gettimeofday(&begin, NULL);
        for (i = 0; i < num_syscalls; ++i) {
                gettimeofday(&nao, NULL);
        }
        gettimeofday(&end, NULL);
        printf("time = %u.%06u\n", begin.tv_sec, begin.tv_usec);
        printf("time = %u.%06u\n", end.tv_sec, end.tv_usec);
        printf("Number of Calls = %u\n", num_syscalls);
        printf("Time per call: %.3f microsecond\n",
        		( end.tv_sec * MICRO_PER_SEC + end.tv_usec - (begin.tv_sec * MICRO_PER_SEC + begin.tv_usec) ) * 1.0 / num_syscalls );
}
