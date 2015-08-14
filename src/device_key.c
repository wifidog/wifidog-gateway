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


static char device_key[64] = {0};



char * get_device_key()
{
	return device_key;
}





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
