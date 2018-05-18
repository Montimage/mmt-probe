/*
 * configure_override.h
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_CONFIGURE_OVERRIDE_H_
#define SRC_CONFIGURE_OVERRIDE_H_

#include "configure.h"


typedef enum{
   NO_SUPPORT,
   BOOL,
   UINT16_T,
   UINT32_T,
   CHAR_STAR
}data_type_t;

typedef struct identity_struct{
	int val;
	data_type_t data_type;
	const char *ident;
}identity_t;

const identity_t* conf_get_ident_from_string( const char * ident_str );

bool need_to_restart_to_update( const identity_t *ident );
/**
 *
 * @param
 * @param ident: identifier of element will be overridden.
 * @param value: value will be overridden only if the value is different with the current one of the element.
 * @return true if the value has been overridden, otherwise false
 */
bool conf_override_element( probe_conf_t*, const char* ident, const char *value );

bool conf_override_element_by_id( probe_conf_t *conf, int ident_val, const char *value_str );

/**
 * Check if data_value is suitable for an identity.
 * @param ident
 * @param data_value
 * @return NULL if yes, otherwise, a text representing error reasons.
 */
const char* conf_validate_data_value( const identity_t *ident, const char *data_value );

/**
 * Get number of parameters that can be overridden
 * @return
 */
size_t conf_get_number_of_identities();

void conf_print_identities_list();

#endif /* SRC_CONFIGURE_OVERRIDE_H_ */
