/*
 * device_key.h
 *
 *  Created on: Aug 14, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_DEVICE_KEY_H_
#define SRC_DEVICE_KEY_H_


#define  DEVICE_KEY_FILE  "/etc/.devicekey"

char * get_device_key();


int   init_device_key();

#endif /* SRC_DEVICE_KEY_H_ */
