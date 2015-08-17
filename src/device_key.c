/*
 * device_key.c
 *
 *  Created on: Aug 14, 2015
 *      Author: GaomingPan
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_key.h"

<<<<<<< HEAD

static char device_key[64] = {0};



=======
/**
 * the global device key char array.
 * */
static char device_key[64] = {0};


/* @breif get the global device key.the key will be use as auth key
 * @PARAMETER: void
 * @RETURN_VALUE: a none NULL char pointer
 * GaomingPan lonely-test:yes
 * */
>>>>>>> 5e30f644f767573bfa1ed114514e20babcac1a72
char * get_device_key()
{
	return device_key;
}




<<<<<<< HEAD

=======
/* @breif get the device key from a configure file
 * @PARAMETER: void
 * @RETURN_VALUE: success return zero and set the KEY in the device key global array,
 * failed return a none zero number.
 * GaomingPan lonely-test:yes
 * */
>>>>>>> 5e30f644f767573bfa1ed114514e20babcac1a72
int init_device_key()
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read_len;

	fp = fopen(DEVICE_KEY_FILE,"r");
	if(NULL == fp)
	{
		return -1;
	}
	while((read_len = getline(&line,&len,fp)) != -1)
	{
		if('#' == line[0] || ' ' == line[0] || '\t' == line[0])
			continue;
		else
		{
			sprintf(device_key,"%s",line);
			free(line);
			fclose(fp);
			return 0;
		}
	}
	free(line);
	fclose(fp);
	return -2;
}
