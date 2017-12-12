/*
 * base64.c
 *
 *  Created on: Dec 11, 2017
 *      Author: nhnghia
 */


#include "base64.h"

/*
 ** Translation Table as described in RFC1113
 */
static const char cb64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 ** encodeblock
 **
 ** encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
static inline void _encode_block(unsigned char in[3], unsigned char out[4], int len) {
	out[0] = cb64[ in[0] >> 2 ];
	out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
 ** encode
 **
 ** base64 encode a string.
 */
int base64_encode(const char *infile, char *out_file) {
	unsigned char in[3], out[4];
	int i, len;
	int copiedBytes = 0;
	while (infile[0] != '\0') {
		len = 0;
		for (i = 0; i < 3; i++) {
			in[i] = infile[0];
			if (infile[0] != '\0') {
				len++;
			} else {
				in[i] = 0;
			}
			infile++;
		}
		if (len) {
			_encode_block(in, out, len);
			for (i = 0; i < 4; i++) {
				out_file[copiedBytes] = out[i];
				copiedBytes++;
			}
		}
	}
	out_file[copiedBytes] = '\0';
	return copiedBytes;
}
