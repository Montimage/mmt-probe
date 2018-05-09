/*
 * restart_proc.h
 *
 *  Created on: May 9, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_RESTART_PROC_H_
#define SRC_LIB_RESTART_PROC_H_
#include <stdbool.h>

/**
 *
 * @param filename
 * @param argv  is an array of null-terminated strings that is used to provide a value for the argv argument
 * to the main function of the program to be executed. The last element of this array must be a null pointer. By
 * convention, the first element of this array is the file name of the program sans directory names. , for full
 * details on how programs can access these arguments.
 * @return
 */
void restart_application( const char *filename, char *const argv[] );

#endif /* SRC_LIB_RESTART_PROC_H_ */
