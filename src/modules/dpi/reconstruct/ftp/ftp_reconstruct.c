/*
 * ftp_reconstruct.c
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */
#include "ftp_reconstruct.h"
#include <tcpip/mmt_tcpip.h>

#include "../../../../lib/tools.h"
#include "../../../../lib/limit.h"
#include "../../dpi_tool.h"

struct ftp_reconstruct_struct{
	const reconstruct_data_conf_t *config;
};


static void _ftp_data_type_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	ftp_reconstruct_context_t *context = (ftp_reconstruct_context_t *)user_args;
	const uint8_t *data_type = (uint8_t *) attribute->data;
	if( data_type == NULL || *data_type != 1 )
		return;

	// Get file name
	char *file_name = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_FILE_NAME);
	if( file_name == NULL )
		return;

	// Get packet len
	uint32_t *data_len = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_FTP, FTP_PACKET_DATA_LEN);
	if( data_len == NULL || *data_len == 0)
		return;

	// Get packet payload pointer - after TCP
	char * data_payload = (char *) get_attribute_extracted_data(ipacket, PROTO_FTP, PROTO_PAYLOAD);
	if( data_payload == NULL )
		return;


	char output_file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	char *file_path = str_replace(file_name, "/", "_");
	snprintf(output_file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s%"PRIu64"_%s",
			context->config->directory,
			get_session_id( ipacket->session ),
			file_path );

	append_data_to_file(output_file_name, data_payload, *data_len);
	DEBUG("write %u byte to %s", *data_len, output_file_name );
	free(file_path);
}


static size_t _get_handlers( const conditional_handler_t **ret){
	static const conditional_handler_t handlers[] = {
				{.proto_id = PROTO_FTP, .att_id = PROTO_PAYLOAD,        .handler = NULL },
				{.proto_id = PROTO_FTP, .att_id = FTP_PACKET_DATA_LEN,  .handler = NULL },
				{.proto_id = PROTO_FTP, .att_id = FTP_DATA_TYPE,        .handler = _ftp_data_type_handle },
				{.proto_id = PROTO_FTP, .att_id = FTP_FILE_NAME,        .handler = NULL }
			};
	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}
ftp_reconstruct_context_t *ftp_reconstruct_init( const reconstruct_data_conf_t *conf, mmt_handler_t *dpi_handler ){
	if( ! conf->is_enable )
		return NULL;

	const conditional_handler_t *handlers = NULL;
	size_t size = _get_handlers( &handlers );

	ftp_reconstruct_context_t *ret = mmt_alloc_and_init_zero( sizeof( ftp_reconstruct_context_t ));
	ret->config = conf;

	dpi_register_conditional_handler( dpi_handler, size, handlers, ret );
	return ret;
}

void ftp_reconstruct_close( mmt_handler_t *dpi_handler, ftp_reconstruct_context_t *context){
	if( context == NULL )
			return;

	const conditional_handler_t *handlers = NULL;
	size_t size = _get_handlers( &handlers );
	dpi_unregister_conditional_handler( dpi_handler, size, handlers );
}
void ftp_reconstruct_release( ftp_reconstruct_context_t *context ){
	if( context == NULL )
		return;
	mmt_probe_free( context );
}
