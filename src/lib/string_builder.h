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
#include <string.h>
#include <sys/time.h>
#include "optimization.h"
#include "macro_apply.h"
#include "log.h"

#define INET_ADDRSTRLEN 16

/**
 * Append a  character to a string
 * @param dst
 * @param dst_size
 * @param c
 * @return
 * @note this function does not append '\0' to the final result
 */
static ALWAYS_INLINE int append_char( char *dst, size_t dst_size, char c ){
	if( unlikely( dst_size == 0 ))
		return 0;
	dst[0] = c;
	return 1;
}

/**
 * Append an array of characters to a string
 * @param dst
 * @param dst_size
 * @param src
 * @return
 * @note this function may not append '\0' to the final result
 */
static ALWAYS_INLINE int append_string_without_quote( char *dst, size_t dst_size, const char *src ){
	if( unlikely( dst_size == 0 ))
		return 0;

	size_t src_size = strlen( src );
	//cannot contain all source string
	if( src_size > dst_size )
		src_size = dst_size;

	//open quote
	memcpy( dst, src, src_size );
	//close quote
	return src_size;
}

/**
 * Append a string src to another string. The final result will contain the string src surrounded by quotes
 * @param dst
 * @param dst_size
 * @param src
 * @return
 * @note this function may not append '\0' to the final result
 */
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
	//cannot contain all source string
	if( src_size > dst_size )
		src_size = dst_size;

	//open quote
	dst[0] = '"';
	if( src_size != 0 )
		memcpy( &dst[1], src, src_size );
	//close quote
	dst[ src_size + 1 ] = '"';
	return src_size + 2;
}

/**
 * Append a hex number to a string. The hex number must be less than 0xFF
 * @param dst
 * @param dst_size
 * @param val
 * @return
 * @note this function does not append '\0' to the final result
 */
static ALWAYS_INLINE int append_hex( char *dst, size_t dst_size, uint8_t val ){
	//wee need at least 2 characters: XY
	if( unlikely( dst_size < 2 ))
		return 0;
	const char *digits = "0123456789ABCDEF";
	dst[0] = digits[ val >> 4  ];
	dst[1] = digits[ val & 0xF ];
	return 2;
}

/**
 * Append a MAC address to a string. The result MAC address will be surrounded by quotes
 * @param dst
 * @param dst_size
 * @param t
 * @return
 * @note this function does not append '\0' to the final result
 */
static ALWAYS_INLINE int append_mac( char *dst, size_t dst_size, const uint8_t *t ){
	//wee need at least 2+6*2+5 characters: "11:22:33:44:55:66"
	if( unlikely( dst_size < 19 ))
		return 0;

	int offset = 0;
	dst[ offset ++ ] = '"';
	offset += append_hex( dst + offset, 2, t[0] );
	dst[ offset ++ ] = ':';

	offset += append_hex( dst + offset, 2, t[1] );
	dst[ offset ++ ] = ':';

	offset += append_hex( dst + offset, 2, t[2] );
	dst[ offset ++ ] = ':';

	offset += append_hex( dst + offset, 2, t[3] );
	dst[ offset ++ ] = ':';

	offset += append_hex( dst + offset, 2, t[4] );
	dst[ offset ++ ] = ':';

	offset += append_hex( dst + offset, 2, t[5] );
	dst[ offset ++ ] = '"';
	return offset;
}

/**
 * Convert number to string
 * @param string
 * @param val
 * @return
 * @note //TODO currently being limited by 13 digits
 */
static inline int append_number( char *dst, size_t dst_size, uint64_t val ){
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
		dst[0] = '0' + val;
		return 1;
	}

	//get number of digits
	if(val>=10000)
	{
		if(val>=10000000)
		{
			if( val >= 10000000000){
				if( val >= 1000000000000)
					size = 13;
				else if( val >= 100000000000)
					size = 12;
				else
					size = 11;
			}
			else{
				if(val>=1000000000)
					size=10;
				else if(val>=100000000)
					size=9;
				else
					size=8;
			}
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

	char *c = &dst[ size-1 ];
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

/**
 * Convert IPv4 from 32bit number to human readable string
 * @param ip
 * @param dst must point to a memory segment having at least INET_ADDRSTRLEN bytes
 * @return length of buf
 * @return
 */
static ALWAYS_INLINE int append_ipv4( char *dst, size_t dst_size, uint32_t ip  ){
	if( dst_size < INET_ADDRSTRLEN )
		return 0;
	const uint8_t *p = (const uint8_t *) &ip;
	int valid = 0;
	valid += append_number(dst+valid, dst_size-valid, p[0]);
	dst[valid++] = '.';
	valid += append_number(dst+valid, dst_size-valid, p[1]);
	dst[valid++] = '.';
	valid += append_number(dst+valid, dst_size-valid, p[2]);
	dst[valid++] = '.';
	valid += append_number(dst+valid, dst_size-valid, p[3]);
	return valid;
}

/**
 * Append a struct timeval to string using format tv_sec.tv_usec
 * This function corresponds to sprintf( dst, dst_size, "%u.%06u", t->tv_sec, tv_usec)
 * @param dst
 * @param dst_size
 * @param t
 * @return
 */
static ALWAYS_INLINE int append_timeval( char *dst, size_t dst_size, const struct timeval *t ){
	//wee need at least 12 characters: xxxxxx.
	if( unlikely( dst_size < 12 ))
		return 0;
	int offset = append_number( dst, dst_size, t->tv_sec );
	ASSERT( offset <= 12, "Impossible (%d > 12)", offset );

	//not enough for the nanosecond
	if( dst_size < offset + 7 )
		return offset;

	dst += offset;
	*dst = '.';
	dst ++;

	//tmp char
	char tmp[6];
	int len = append_number( tmp, sizeof( tmp ), t->tv_usec );
	//put tmp to end of 6 bytes of dst (left align), for example: with offset = 4
	// tmp =   1234
	// dst = 001234
	//1. pre-fill zero
	dst[0] = '0';
	dst[1] = '0';
	dst[2] = '0';
	dst[3] = '0';
	dst[4] = '0';
	dst[5] = '0';
	//2. copy tmp to end of dst
	int i;
	for( i=0; i<len; i ++ )
		dst[i + (sizeof(tmp)-len) ] = tmp[i];

	return offset + 1 + sizeof(tmp); //1 is '.'
}

/**
 * These helpers are used only inside STRING_BUILDER macro
 */
#define __ARR(x)   append_string_without_quote ( ptr+i, n-i, x )
#define __STR(x)   append_string(                ptr+i, n-i, x )
#define __INT(x)   append_number(                ptr+i, n-i, x )
#define __CHAR(x)  append_char  (                ptr+i, n-i, x )
#define __TIME(x)  append_timeval(               ptr+i, n-i, x )
#define __HEX(x)   append_hex(                   ptr+i, n-i, x )
#define __MAC(x)   append_mac(                   ptr+i, n-i, x )
#define __IPv4(x)  append_ipv4(                  ptr+i, n-i, x )

#define __BUILDER( X ) if( n > i ) i += X;
#define __EMPTY()
#define __SEPARATOR()  i += append_string_without_quote( ptr+i, n-i, sepa );

/**
 * Create a macro to build a string.
 * For example, to build a string:  "1,\"GET\", we can do:
 * char msg[100];
 * int valid = 0;
 * valid += append_number( msg+valid, sizeof(msg)-valid, 1);
 * valid += append_char  ( msg+valid, sizeof(msg)-valid, ',');
 * valid += append_string( msg+valid, sizeof(msg)-valid, "GET");
 *
 * The code above can be replaced by using this macro:
 *  int valid = 0;
 *  STRING_BUILDER( valid, msg, sizeof(msg), __INT(1), __CHAR(','), __STR("GET"));
 */
#define STRING_BUILDER( valid, dst, dst_size, ... )      \
do{                                                      \
	int i = valid, n=dst_size-1;                         \
	char *ptr = dst;                                     \
	APPLY( __EMPTY, __BUILDER, __VA_ARGS__ )             \
	ptr[i] = '\0';                                       \
	valid = i;                                           \
}while( 0 )


/**
 * Same as STRING_BUILDER but adding a separator between two consecutive elements
 */
#define STRING_BUILDER_WITH_SEPARATOR( valid, dst, dst_size, separator,... ) \
do{                                                                          \
	int i = valid, n=dst_size-1;                                             \
	char *ptr = dst;                                                         \
	const char *sepa = separator;                                            \
	APPLY( __SEPARATOR, __BUILDER, __VA_ARGS__  )                            \
	ptr[i] = '\0';                                                           \
	valid = i;                                                               \
}while( 0 )

#endif /* SRC_LIB_STRING_BUILDER_H_ */
