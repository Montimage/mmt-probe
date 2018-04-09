/*
 * optimization.h
 *
 *  Created on: 14 avr. 2016
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_OPTIMIZATION_H_
#define SRC_LIB_OPTIMIZATION_H_

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define ALWAYS_INLINE inline __attribute__((always_inline))

#endif/* SRC_LIB_OPTIMIZATION_H_ */
