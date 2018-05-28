/*
 * agency.h
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 *
 * This agency must be embedded inside the processing process to receive control commands from control process
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_AGENCY_H_
#define SRC_MODULES_DYNAMIC_CONF_AGENCY_H_

#include <stdbool.h>


/**
 * In this function we decide which parameters can be updated with/without restarting MMT-Probe
 * @param ident represents the paramter identity
 * @return true if we need to restart the main processing process to be able to update the parameter
 *         false, otherwise
 */
bool dynamic_conf_need_to_restart_to_update( int ident );

/**
 * Start listening to receive control commands.
 * @return true if everything work well,
 * 		   false if mmt_bus is not initialized
 * @note This function does not block its caller workflow.
 */
bool dynamic_conf_agency_start();

void dynamic_conf_agency_stop();

#endif /* SRC_MODULES_DYNAMIC_CONF_AGENCY_H_ */
