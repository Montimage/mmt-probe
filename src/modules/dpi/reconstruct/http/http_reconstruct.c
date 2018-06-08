/** Dependencies
 *  zlib
 *    sudo apt-get install zlib1g zlib1g-dev
 */



#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <zlib.h>

#include "../../../../lib/string_builder.h"
#include "../../../../lib/tools.h"

#include "../../dpi_tool.h"
#include "http_reconstruct.h"

struct http_reconstruct_struct{
	const reconstruct_data_conf_t *config;
};

#define MAX_CHUNKED_SIZE 10000

#define LEN( literal ) (sizeof( literal) - 1)
#define IS_EQUAL( a, b, s ) (strncasecmp( a, b, MIN( LEN(b), s )) == 0)

static inline const char *_get_extension_from_content_type(const ipacket_t *ipacket ) {
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_CONTENT_TYPE );
	if( data == NULL || data->len == 0 )
		return "unk";

	const char *content_type = data->ptr;
	size_t data_len = data->len;

	if (IS_EQUAL(content_type, "text/html", data_len) ) return "html";
	if (IS_EQUAL(content_type, "text/plain", data_len) ) return "txt";
	if (IS_EQUAL(content_type, "text/xml",   data_len) ) return "xml";
	if (IS_EQUAL(content_type, "text/css",  data_len) ) return "css";

	if (IS_EQUAL(content_type, "image/png",  data_len) ) return "png";
	if (IS_EQUAL(content_type, "image/jpg",  data_len) ) return "jpg";
	if (IS_EQUAL(content_type, "image/jpeg", data_len) ) return "jpeg";
	if (IS_EQUAL(content_type, "image/gif",  data_len) ) return "gif";

	if (IS_EQUAL(content_type, "zip",  data_len) ) return "zip";
	if (IS_EQUAL(content_type, "mp3",  data_len) ) return "mp3";
	if (IS_EQUAL(content_type, "mp4",  data_len) ) return "mp4";


	if (IS_EQUAL(content_type, "svg",  data_len) ) return "svg";

	if (IS_EQUAL(content_type, "application/x-javascript", data_len) ) return "js";
	if (IS_EQUAL(content_type, "application/javascript", data_len) ) return "js";
	if (IS_EQUAL(content_type, "application/x-shockwave-flash", data_len) ) return "swf";
	DEBUG("Unknown type: %.*s", data->len, data->ptr );

	return "unk";
}

/**
 * copies into @fname the file name given session identifier and interaction count
 */
static inline void _build_file_name(char *file_name, size_t file_name_size, const char *dir, const ipacket_t *ipacket ) {
	int valid = 0;
	const char *ext = _get_extension_from_content_type( ipacket );
	 int session_id = get_session_id_from_packet( ipacket );
	STRING_BUILDER( valid, file_name, file_name_size,
			__ARR( dir ),
			__ARR("file"),
			__CHAR('-'),
			__INT( session_id),
			__CHAR('.'),
			__ARR( ext ));
}


/**
 * unzip data
 */
static size_t _unzip( char *output, size_t output_len, const char  *input, size_t input_len ){
	size_t len = output_len;
	int ret = uncompress( (unsigned char *)output, &len, (unsigned char *)input, input_len );
	switch( ret ){
	case Z_OK:
		return len;
	case Z_MEM_ERROR:
	case Z_BUF_ERROR:
		log_write(LOG_ERR, "Not enough rom to uncompress data (being limited to %d)", MAX_CHUNKED_SIZE );
		return 0;
	case Z_DATA_ERROR:
		DEBUG("data format is not correct");
		return 0;
	}
	return len;
}


static inline bool _is_compressed( const ipacket_t *ipacket ){
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_CONTENT_ENCODING );
	if( data == NULL || data->len == 0 )
		return false;
	return IS_EQUAL( data->ptr, "gzip", data->len );
}

/**
 * Attribute handle that will be called for every HTTP body data chunk
 * The chunk will be process to by the gzip pre processor if content encoding
 * is gzip, then it will be processed by the html parser.
 * In all cases, the chunk will be saved into a file whose name containes the session ID
 * and the interaction number in the session to take into account keep alive HTTP sessions
 */
static void _http_data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	http_reconstruct_t *context = (http_reconstruct_t *)user_args;
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

	const mmt_header_line_t *data = (mmt_header_line_t *)attribute->data;
	char uncompressed_data[ MAX_CHUNKED_SIZE ];

	const char *data_ptr = data->ptr;
	int    data_len      = data->len;

	if( _is_compressed( ipacket ) ){
		data_len = _unzip( uncompressed_data, sizeof( uncompressed_data ), data_ptr, data_len );
		data_ptr = uncompressed_data;
	}

	if( data_len == 0 )
		return;

	_build_file_name( file_name, sizeof( file_name ), context->config->directory, ipacket );

	append_data_to_file(file_name, data_ptr, data_len );
}

http_reconstruct_t *http_reconstruct_init( const reconstruct_data_conf_t *config, mmt_handler_t *dpi_handler ){
	//	if( config->is_enable == false )
	//		return NULL;
	//struct to register attributes
	static const conditional_handler_t handlers[] = {
			{.proto_id = PROTO_HTTP, .att_id = RFC2822_RESPONSE,         .handler = _http_data_handle},
			{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_TYPE,     .handler = NULL},
			{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_ENCODING, .handler = NULL},
	};

	http_reconstruct_t *ret = mmt_alloc_and_init_zero( sizeof( http_reconstruct_t ));
	ret->config = config;

	dpi_register_conditional_handler( dpi_handler,  (sizeof (handlers) / sizeof( conditional_handler_t)), handlers, ret );
	return ret;
}
