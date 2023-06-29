/*
 * configure_override.c
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#include "lib/log.h"
#include "lib/malloc.h"
#include "lib/memory.h"

#include "configure_override.h"

static bool _parse_bool( const char *value ){
	if( IS_EQUAL_STRINGS( value, "true" ) )
		return true;
	if( IS_EQUAL_STRINGS( value, "false" ) )
		return false;
	return false;
}

const identity_t* conf_get_identity_from_string( const char * ident_str ){
	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );
	int i;
	for( i=0; i<nb_parameters; i++ )
		if( IS_EQUAL_STRINGS( ident_str, identities[i].ident ))
			return &identities[i];
	return NULL;
}


const char* conf_validate_data_value( const identity_t *ident, const char *data_value ){
	static char error_reason[1000];
	int i;
	int enum_val = 0;

	//special data type
	switch( ident->val ){
	//input
	case CONF_ATT__INPUT__MODE:
		if( conf_parse_input_mode( &enum_val, data_value ) )
			return NULL;
		else{
			snprintf( error_reason, sizeof( error_reason), "Unexpected value [%s] for [%s]", data_value, ident->ident );
			return error_reason;
		}
		break;
//#ifdef SECURITY_MODULE
//	case CONF_ATT__SECURITY__INGORE_REMAIN_FLOW:
//		if( conf_parse_security_ignore_mode( &enum_val, data_value ) )
//			return NULL;
//		else{
//			snprintf( error_reason, sizeof( error_reason), "Unexpected value [%s] for [%s]", data_value, ident->ident );
//			return error_reason;
//		}
//		break;
//#endif
	default:
		break;
	}

	//check value depending on data type of parameter
	switch( ident->data_type ){
	case BOOL:
		if( IS_EQUAL_STRINGS( data_value, "true" ) )
			break;
		if( IS_EQUAL_STRINGS( data_value, "false" ) )
			break;

		snprintf( error_reason, sizeof(error_reason), "Expect either 'true' or 'false' as value of '%s' (not '%s')", ident->ident, data_value );
		return error_reason;
		break;

	case UINT16_T:
	case UINT32_T:
		//check if data_value contains only the number
		i = 0;
		while( data_value[i] != '\0' ){
			if( data_value[i] < '0' || data_value[i] > '9' ){
				snprintf( error_reason, sizeof( error_reason), "Expect a number as value of '%s' (not '%s')", ident->ident, data_value );
				return 0;
			}
			i ++;
		}
		break;
	default:
		break;
	}

	return NULL;
}

static inline bool _override_element_by_ident( probe_conf_t *conf, const identity_t *ident, const char *value_str ){
	uint32_t int_val = 0;
	int i;
	DEBUG("Updating %s to %s", ident->ident, value_str );
	void *field_ptr = conf_get_ident_attribute_field(conf, ident->val );
	int enum_val = 0;

	if( field_ptr == NULL ){
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return false;
	}
	char **string_ptr;

	//special data type
	switch( ident->val ){
		//input
	case CONF_ATT__INPUT__MODE:
		if( conf_parse_input_mode( &enum_val, value_str ) )
			*((int *)field_ptr) = enum_val;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		return true;
		//
	case CONF_ATT__SESSION_REPORT__RTT_BASE:
		if( conf_parse_rtt_base(&enum_val, value_str ) )
			*((int *)field_ptr) = enum_val;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		return true;
	case CONF_ATT__OUTPUT__FORMAT:
		if( conf_parse_output_format(&enum_val, value_str ) )
			*((int *)field_ptr) = enum_val;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		return true;
#ifdef SOCKET_MODULE
	case CONF_ATT__SOCKET_OUTPUT__TYPE:
		if( conf_parse_output_socket_type(&enum_val, value_str ) )
			*((int *)field_ptr) = enum_val;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		return true;
#endif

#ifdef SECURITY_MODULE
	case CONF_ATT__SECURITY__INGORE_REMAIN_FLOW:
		if( conf_parse_security_ignore_mode( &enum_val, value_str ) )
			*((int *)field_ptr) = enum_val;
		else{
			log_write( LOG_WARNING, "Unexpected value [%s] for [%s]", value_str, ident->ident );
			return false;
		}
		return true;
#endif

	default:
		break;
	}

	switch( ident->data_type ){
	//update value depending on parameters
	case NO_SUPPORT:
		log_write( LOG_WARNING, "Have not supported yet for [%s]", ident->ident );
		return false;
	case CHAR_STAR:
		string_ptr = (char **) field_ptr;
		//value does not change ==> do nothing
		if( *string_ptr && IS_EQUAL_STRINGS( *string_ptr, value_str ) )
			return true;
		mmt_probe_free( *string_ptr );
		*string_ptr = mmt_strdup( value_str );
		return true;
	case LIST:
		switch( ident->val ){
#ifdef SECURITY_MODULE
		case CONF_ATT__SECURITY__OUTPUT_CHANNEL:
#endif
		case CONF_ATT__SESSION_REPORT__OUTPUT_CHANNEL:
		case CONF_ATT__SYSTEM_REPORT__OUTPUT_CHANNEL:
		case CONF_ATT__MICRO_FLOWS__OUTPUT_CHANNEL:
		case CONF_ATT__RADIUS_REPORT__OUTPUT_CHANNEL:
			int_val = conf_parse_output_channel( value_str );
			if( int_val == *(output_channel_conf_t *) field_ptr )
				return true;
			(*(output_channel_conf_t *) field_ptr) = int_val;
			return true;

#ifdef PCAP_DUMP_MODULE
		case CONF_ATT__DUMP_PCAP__PROTOCOLS:
			//free old memory
			if( conf->reports.pcap_dump ){
				if( conf->reports.pcap_dump->protocols != NULL ){
					for( i=0; i<conf->reports.pcap_dump->protocols_size; i++ )
						mmt_probe_free( conf->reports.pcap_dump->protocols[i] );
				}
				mmt_probe_free( conf->reports.pcap_dump->protocols );
			}else{
				conf->reports.pcap_dump = mmt_alloc_and_init_zero( sizeof( pcap_dump_conf_t ));
			}

			conf->reports.pcap_dump->protocols_size = conf_parse_list( value_str, &conf->reports.pcap_dump->protocols );
			return true;
#endif
		}
		break;
	case BOOL:
		int_val = _parse_bool( value_str );
		//value does not change => do nothing
		if( int_val == *((bool *)field_ptr) )
			return true;
		//update value
		*((bool *)field_ptr) = int_val;
		return true;


	case UINT16_T:
		int_val = atoi( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint16_t *)field_ptr) )
			return true;
		*((uint16_t *)field_ptr) = int_val;
		return true;

	case UINT32_T:
		int_val = atol( value_str );
		//value does not change ==> do nothing
		if( int_val == *((uint32_t *)field_ptr) )
			return true;
		*((uint32_t *)field_ptr) = int_val;
		return true;
	default:
		break;
	}

	log_write( LOG_ERR, "Unknown identifier '%s'", ident->ident );
	return false;
}


/**
 * Update value of a configuration parameter.
 * The new value is updated only if it is different with the current value of the parameter.
 * @param conf
 * @param ident
 * @param value
 * @return 0 if the new value is updated, otherwise false
 */
int conf_override_element( probe_conf_t *conf, const char *ident_str, const char *value_str ){
	const identity_t *ident = conf_get_identity_from_string( ident_str );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%s]", ident_str );
		return -1;
	}
	if( _override_element_by_ident(conf, ident, value_str ) )
		return 0;
	return 1;
}

bool conf_override_element_by_id( probe_conf_t *conf, int ident_val, const char *value_str ){
	const identity_t *ident = conf_get_identity_from_id( ident_val );

	if( ident == NULL ){
		log_write( LOG_WARNING, "Unknown parameter identity [%d]", ident_val );
		return false;
	}
	return _override_element_by_ident(conf, ident, value_str );
}


/**
 * Public API
 */
void conf_print_identities_list(){
	int i;
	const char *data_type_strings[] = {
			"",
			"boolean",
			"uint16_t",
			"uint32_t",
			"string",
			"string"
	};

	const identity_t *identities;
	size_t nb_parameters = conf_get_identities( &identities );

	for( i=0; i<nb_parameters; i++ )
		if( identities[i].data_type !=NO_SUPPORT  )
			printf("%s (%s)\n", identities[i].ident, data_type_strings[identities[i].data_type]);
}
