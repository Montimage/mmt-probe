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
#include "../../dpi.h"
#include "http_reconstruct.h"
#include "content_encoding.h"
#include "file_extension_from_content_type.h"
#include "transfer_encoding.h"
#include "dechunked.h"

struct http_reconstruct_struct{
	const reconstruct_data_conf_t *config;
};


struct http_session_struct{
	const http_reconstruct_t *context;
	char *file_name;
	const char* file_extension;
	const struct content_encoding *content_encoding;
	const struct transfer_encoding *transfer_encoding;
	//we use tcp_port_source to determine packet direction
	// since we save only payload of packets from server to client, not from client to server
	uint16_t tcp_port_source;
	//whether HTTP header indicates explicitly Content-Length field
	// if not, we use MAX_HTTP_MESSAGE_SIZE as default content_length
	bool is_indicated_content_length;
	uint32_t content_length;
	uint32_t current_data_length; //<= content_length
	//for each packet, we will append its content to data
	//current_data_length is the current size of data. It must be always less than or equal to  content_length
	char *data;
};

#define MAX_HTTP_MESSAGE_SIZE 100000

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
		log_write(LOG_ERR, "unzip error when reconstructing HTTP: Not enough rom to uncompress data (being limited to %zu)", len );
		return 0;
	case Z_DATA_ERROR:
		return 0;
	}
	return len;
}


static inline const char *_get_extension_from_content_type(const ipacket_t *ipacket ) {
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_CONTENT_TYPE );
	if( data == NULL || data->len == 0 )
		return "unk";

	uint32_t len = 0;
	//if content-type having ; character, we examine only the characters before ;
	//for example: "text/html; charset=ISO-8859-1"  ==> "text/html"
	const char *content_type = (char *) data->ptr;
	while( len < data->len && content_type[len] != ';' && content_type[len] != ' ' )
		len ++;

	const struct file_extension *ext = get_file_extension_from_content_type( content_type, len);
	if( ext != NULL )
		return ext->file_extension;

	DEBUG("Unknown type: %.*s", data->len, data->ptr );

	return "unk";
}

static inline const struct content_encoding* _get_content_encoding( const ipacket_t *ipacket ){
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_CONTENT_ENCODING );
	if( data == NULL || data->len == 0 )
		return NULL;
	return get_content_encoding( data->ptr, data->len );
}


static inline const struct transfer_encoding* _get_tranfer_encoding( const ipacket_t *ipacket ){
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_TRANSFER_ENCODING );
	if( data == NULL || data->len == 0 )
		return NULL;
	return get_transfer_encoding( data->ptr, data->len );
}

static inline uint32_t _get_content_length( const ipacket_t *ipacket ){
	const mmt_header_line_t *data = get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_CONTENT_LEN );
	if( data == NULL || data->len == 0 )
		return 0;

	//ensure string is NULL-terminated
	char tmp[ data->len + 1 ];
	memcpy( tmp, data->ptr, data->len );
	tmp[ data->len ] = '\0';

	uint32_t len = atol( tmp );
	return len;
}

/**
 * @param session
 * @param data
 * @param data_len
 * @return true if data is correctly appended to session
 * false if session is terminated
 */
static inline bool _append_data( http_session_t *session, const char *data, uint32_t data_len ){
	//if data is bigger than the available room
	if( unlikely( data_len + session->current_data_length > session->content_length )){
		log_write(LOG_INFO, "content-length is not correct (expect %d, got %d)", session->content_length, data_len + session->current_data_length);
		return false;
	}

	memcpy( &session->data[session->current_data_length], data, data_len );
	session->current_data_length += data_len;
	return true;
}




//1. This callback should be called firstly in an HTTP stream when submit a request to a server
//We use HTTP.URI for filename of reconstructed files
static void _http_method_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	http_reconstruct_t *context = (http_reconstruct_t *)user_args;
	const mmt_header_line_t *data = (mmt_header_line_t *)attribute->data;

	packet_session_t *packet_session = dpi_get_packet_session( ipacket );
	//we check evenly
	if( packet_session == NULL )
		MY_MISTAKE("Impossible having HTTP meanwhile no tcp session");

	http_session_t *session = packet_session->http_session;

	//have previous data request in the same TCP/IP session
	if( session != NULL )
		http_reconstruct_flush_session_to_file_and_free( session );

	session  = mmt_alloc_and_init_zero( sizeof( http_session_t) );
	packet_session->http_session = session;

	session->context   = context;

	int valid = 0;
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

	//get request URI
	data = (mmt_header_line_t *)get_attribute_extracted_data(ipacket, PROTO_HTTP, RFC2822_URI );

	//1. we first use session-id
	int session_id  = get_session_id_from_packet( ipacket );
	valid = append_number(file_name, sizeof( file_name), session_id);

	//2. then append URI eventually
	if( data && data->len > 0 ){
		int data_len = MIN( data->len, 100); //use maximally 100 characters for URI
		memcpy(file_name + valid, data->ptr, data_len );
		valid += string_format_file_name( file_name + valid, data_len );
	}

	file_name[valid] = '\0'; //well NULL-terminated
	session->file_name = mmt_memdup( file_name, valid+1 ); //+1 to copy also '\0' at the end
}


//2. This callback should be called secondly when receiving a response from server
static void _http_response_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	const mmt_header_line_t *response = (mmt_header_line_t *)attribute->data;

	uint32_t content_length = _get_content_length(ipacket);

	//need 200 OK
	if( strncmp( response->ptr, "200 OK", response->len ) != 0 )
		return;

	packet_session_t *packet_session = dpi_get_packet_session( ipacket );
	//we check evenly
	if( packet_session == NULL //this must not happen
			|| packet_session->http_session == NULL //this happens when no URI being detected before this function call
	)
		return;

	http_session_t *session = packet_session->http_session;

	//two response consecutive in the same TCP/IP session => ignore this response
	if( session->data != NULL ){
		//http_reconstruct_flush_session_to_file_and_free( session );
		return;
	}

	//content is empty
	session->is_indicated_content_length = ( content_length != 0 );
	if( ! session->is_indicated_content_length )
		content_length = MAX_HTTP_MESSAGE_SIZE;

	//initialize information for HTTP stream
	session->content_length = content_length;
	session->data           = mmt_alloc(content_length); //init room to contains HTTP data chunks
	session->content_encoding  = _get_content_encoding( ipacket );
	session->transfer_encoding = _get_tranfer_encoding( ipacket );
	session->file_extension    = _get_extension_from_content_type( ipacket );
	session->tcp_port_source   = *(uint16_t *) get_attribute_extracted_data(ipacket, PROTO_TCP,  TCP_SRC_PORT );

	//_http_data_handle is not called for the first chunk of HTTP stream (donn't know why)

	// we need to add the first chunk
	const char *tcp_payload      = get_attribute_extracted_data(ipacket, PROTO_TCP,  PROTO_PAYLOAD );
	const void *tcp_payload_len  = get_attribute_extracted_data(ipacket, PROTO_TCP,  TCP_PAYLOAD_LEN );
	if( tcp_payload_len == NULL || tcp_payload == NULL  )
		return;
	uint32_t data_len    = *(uint32_t *)tcp_payload_len;
	uint32_t i = 3;

	//find empty line to cutoff HTTP header
	while( i<data_len )
		if(tcp_payload[i] == '\r' && tcp_payload[i-1] == '\n' && tcp_payload[i-1] == '\n')
			break;
		else
			i++;
	//jump over empty line
	i += 2;

	if( unlikely( i >= data_len )){
		DEBUG("http body is empty while its content-length=%d for packet %"PRIu64, content_length, ipacket->packet_id );
		return;
	}

	_append_data( session, tcp_payload+i, data_len-i );
}


//3.x This callback is called for every HTTP body data chunk
static void _http_data_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	const mmt_header_line_t *data = (mmt_header_line_t *)attribute->data;

	packet_session_t *packet_session = dpi_get_packet_session( ipacket );
	//we check evenly
	if( packet_session == NULL )
		MY_MISTAKE("Impossible having http meanwhile no tcp session");
	http_session_t *session = packet_session->http_session;
	if( session == NULL //this data chunk arrives before URI
			|| session->content_length == 0 //this data chunk arrives before RESPONSE
			)
		return;
	uint16_t *src_port = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_TCP,  TCP_SRC_PORT );
	//ensure that the packet is the from server to client
	if( unlikely( src_port == NULL || session->tcp_port_source != *src_port))
		return;

	_append_data( session,  data->ptr, data->len);
}

/**
 * Attribute handle that will be called every time an HTTP message end is detected
 */
static void _http_end_message_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	http_reconstruct_t *context = (http_reconstruct_t *)user_args;
	packet_session_t *packet_session = dpi_get_packet_session( ipacket );
		//we check evenly
	if( packet_session == NULL )
		MY_MISTAKE("Impossible having http meanwhile no tcp session");
	//has not been created before
	if( packet_session->http_session == NULL )
		return;

	http_session_t *session = packet_session->http_session;
	packet_session->http_session = NULL;
	http_reconstruct_flush_session_to_file_and_free( session );
}

static const conditional_handler_t handlers[] = {
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_RESPONSE,         .handler = _http_response_handle},
		{.proto_id = PROTO_HTTP, .att_id = HTTP_DATA,                .handler = _http_data_handle},
		{.proto_id = PROTO_HTTP, .att_id = HTTP_MESSAGE_END,         .handler = _http_end_message_handle},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_LEN,      .handler = NULL},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_TYPE,     .handler = NULL},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_CONTENT_ENCODING, .handler = NULL},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_TRANSFER_ENCODING,.handler = NULL},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_URI,              .handler = NULL},
		{.proto_id = PROTO_HTTP, .att_id = RFC2822_METHOD,           .handler = _http_method_handle},
		{.proto_id = PROTO_TCP,  .att_id = PROTO_PAYLOAD,            .handler = NULL},
		{.proto_id = PROTO_TCP,  .att_id = TCP_PAYLOAD_LEN,          .handler = NULL},
		{.proto_id = PROTO_TCP,  .att_id = TCP_SRC_PORT,             .handler = NULL}
};

http_reconstruct_t *http_reconstruct_init( const reconstruct_data_conf_t *config, mmt_handler_t *dpi_handler ){
		if( config->is_enable == false )
			return NULL;
	//struct to register attributes

	http_reconstruct_t *ret = mmt_alloc_and_init_zero( sizeof( http_reconstruct_t ));
	ret->config = config;

	dpi_register_conditional_handler( dpi_handler,  (sizeof (handlers) / sizeof( conditional_handler_t)), handlers, ret );
	return ret;
}

void http_reconstruct_close( mmt_handler_t *dpi_handler, http_reconstruct_t *context){
	if( context == NULL )
			return;
		dpi_unregister_conditional_handler( dpi_handler,  (sizeof (handlers) / sizeof( conditional_handler_t)), handlers );
}

void http_reconstruct_release( http_reconstruct_t *context){
	if( context == NULL )
		return;
	mmt_probe_free( context );
}

/**
 * Write a HTTP stream to file and free it
 * @param session
 */
void http_reconstruct_flush_session_to_file_and_free( http_session_t *session ){
	if( session == NULL )
		return;
	if( session->current_data_length == 0 )
		goto _free_data;

	bool is_having_full_data = (!session->is_indicated_content_length || (session->current_data_length == session->content_length ));
	if( !is_having_full_data ){
		log_write( LOG_INFO, "http trunk %s is not complete (expected %d bytes, got %d bytes)",
				session->file_name,
				session->content_length,
				session->current_data_length);
	}

	uint32_t len = session->current_data_length;
	char unzip_buffer[ MAX_HTTP_MESSAGE_SIZE ];
	char chunked_buffer[ MAX_HTTP_MESSAGE_SIZE ];
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

	//build file name
	int valid = 0;
	STRING_BUILDER( valid, file_name, sizeof( file_name),
			__ARR( session->context->config->directory ),
			__ARR("mmt-"), //add a prefix
			__ARR( session->file_name)
	);

	bool is_need_file_extension = false;
	//ensure that we always have room for file extension (and gzip error .gz_err)
	if( valid >= sizeof( file_name) ){
		valid = sizeof( file_name) - 20;
		is_need_file_extension = true;
	}
	//check if already having file extension in file_name
	else{
		int extension_len = strlen( session->file_extension);
		//session->file_extension is end of file_name
		if( memcmp( session->file_extension, file_name + (valid - extension_len), extension_len) )
			is_need_file_extension = true;
	}

	if( is_need_file_extension )
		STRING_BUILDER( valid, file_name, sizeof( file_name) - valid,
			__CHAR('.'),
			__ARR( session->file_extension) );

	void *data   = session->data;
	int ret = 0;

	//depending on type of transfer encoding, we may need to decode
	if( session->transfer_encoding ){
		//de-chunk data if need
		switch( session->transfer_encoding->ident_number ){
		case TRANSFER_ENCODING_CHUNKED:
			ret = chunk_decode( chunked_buffer, data, len );
			if( ret ){
				data = chunked_buffer;
				len  = ret;
			}else{
				log_write( LOG_INFO, "%s: chunked-encoding is incorrect", session->file_name );
			}
			break;
		default:
			break;
		}
	}

	//uncompress data if need
	if( is_having_full_data && session->content_encoding && session->content_encoding->ident_number == CONTENT_ENCODING_GZIP ){
		len  = _unzip( unzip_buffer, sizeof( unzip_buffer ), data, len );
		//error when unzip => we append .gz_err in file name
		if( len == 0 ){
			len = session->current_data_length;
			STRING_BUILDER( valid, file_name, sizeof( file_name) - valid,
						__ARR( ".gz_err" ) );
		}else
			data = unzip_buffer;
	}

	write_data_to_file( file_name, data, len);

	_free_data:
	mmt_probe_free( session->file_name );
	mmt_probe_free( session->data );
	mmt_probe_free( session );
}
