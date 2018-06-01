/*
 * string_builder.h
 *
 *  Created on: Jun 1, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_STRING_BUILDER_H_
#define SRC_LIB_STRING_BUILDER_H_

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "optimization.h"

static ALWAYS_INLINE int append_char( char *dst, size_t dst_size, char c ){
	if( unlikely( dst_size == 0 ))
		return 0;
	dst[1] = c;
	return 1;
}

static ALWAYS_INLINE int append_string( char *dst, size_t dst_size, const char *src ){
	if( unlikely( dst_size < 2 ))
		return 0;
	else if( unlikely( dst_size == 2 )){
		dst[0] = '"';
		dst[1] = '"';
		return 2;
	}

	size_t src_size = strlen( src );
	dst_size -= 2; //2 characters for " and "
	if( src_size > dst_size )
		src_size = dst_size;

	//open quote
	dst[0] = '"';
	memcpy( &dst[1], src, src_size );
	//close quote
	dst[ src_size + 1 ] = '"';
	return src_size + 2;
}

/**
 * Convert number to string
 * @param string
 * @param val
 * @return
 */
static inline int append_number( char *string, size_t dst_size, uint64_t val ){
	const char digit_pairs[201] = {
			"00010203040506070809"
			"10111213141516171819"
			"20212223242526272829"
			"30313233343536373839"
			"40414243444546474849"
			"50515253545556575859"
			"60616263646566676869"
			"70717273747576777879"
			"80818283848586878889"
			"90919293949596979899"
	};

	int size = 1; //by default, there exists at least one digit

	if( val < 10 && dst_size > 0 ) {
		string[0] = '0' + val;
		return 1;
	}


	if(val>=10000)
	{
		if(val>=10000000)
		{
			if(val>=1000000000)
				size=10;
			else if(val>=100000000)
				size=9;
			else
				size=8;
		}
		else
		{
			if(val>=1000000)
				size=7;
			else if(val>=100000)
				size=6;
			else
				size=5;
		}
	}
	else
	{
		if(val>=100)
		{
			if(val>=1000)
				size=4;
			else
				size=3;
		}
		else
		{
			if(val>=10)
				size=2;
			else
				size=1;
		}
	}

	if( size > dst_size )
		return 0;

	char *c = &string[ size-1 ];
	int pos;

	//do each 2 digits
	while( val >= 100 ){
		pos = val % 100;
		val /= 100;
		*(uint16_t*)(c-1) = *(uint16_t*)( digit_pairs + 2*pos);
		c -= 2;
	}

	while( val > 0 ){
		*c--='0' + (val % 10);
		val /= 10;
	}

	return size;
}


#endif /* SRC_LIB_STRING_BUILDER_H_ */
