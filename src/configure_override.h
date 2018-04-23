/*
 * configure_override.h
 *
 *  Created on: Apr 23, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_CONFIGURE_OVERRIDE_H_
#define SRC_CONFIGURE_OVERRIDE_H_

#include "configure.h"

/**
 *
 * @param
 * @param ident: identifier of element will be overridden.
 * @param value: value will be overridden only if the value is different with the current one of the element.
 * @return true if the value has been overridden, otherwise false
 */
bool conf_override_element( probe_conf_t*, const char* ident, const char *value );

void conf_print_identities_list();

#endif /* SRC_CONFIGURE_OVERRIDE_H_ */
