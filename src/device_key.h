/*
 * device_key.h
 *
 *  Created on: Aug 14, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_DEVICE_KEY_H_
#define SRC_DEVICE_KEY_H_


#define  DEVICE_KEY_FILE  "/etc/.devicekey"


/* @breif get the global device key.the key will be use as auth key
 * @PARAMETER: void
 * @RETURN_VALUE: a none NULL char pointer
 * GaomingPan lonely-test:yes
 * */
char * get_device_key();



/* @breif get the device key from a configure file
 * @PARAMETER: void
 * @RETURN_VALUE: success return zero and set the KEY in the device key global array,
 * failed return a none zero number.
 * GaomingPan lonely-test:yes
 * */
int   init_device_key();

#endif /* SRC_DEVICE_KEY_H_ */
