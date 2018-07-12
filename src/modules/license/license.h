/*
 * license.h
 *
 *  Created on: Apr 16, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_LICENSE_H_
#define SRC_LIB_LICENSE_H_

#include "../output/output.h"

/**
 *  This function checks MAC address, license expiry dates to validate the MMT license.
 * @return
 * - true if license is valid,
 * - false otherwise.
 */
bool license_check_expiry( const char *license_file, output_t *output );

#endif /* SRC_LIB_LICENSE_H_ */
