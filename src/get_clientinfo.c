/*
 * get_clientinfo.c
 *
 *  Created on: Jul 13, 2015
 *      Author: GaomingPan
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <sys/unistd.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include "util.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "../config.h"


#include "shell_command.h"
#include "get_clientinfo.h"


static t_clientinfo *first_client_info = NULL;

static char client_auth_flag[7] = {0};

/* @breif get client host name,income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @PARAMETER:void
 * @RETURN_VALUE:zero is success,others is error.
 * @Note: after this function be called and you got some clients information,you should
 *        call clean_client_info() function to clean up,just like the fopen() and fclose().
 * GaomingPan lonely-test:yes
 * */
int collect_client_info()
{
    FILE        *fp;

	char         a_rate[20],
	             ip[18];

	t_clientinfo *p1,
	             *p2,
				 *p3;

	int          ret;

	int          line_num = 0;
	char         *line = NULL;


	/**
	 * malloc memories for clients info list.
	 * */
    first_client_info = (t_clientinfo*)malloc(sizeof(t_clientinfo));
    if(NULL == first_client_info){
    	debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
    	return -1;
    }
    first_client_info->next = NULL;
    p1 = first_client_info;
    p2 = p1;


    /**
     * get host name,ip and mac
     * */
    fp = fopen(HOST_NAME_FILE,"r");
    if(NULL == fp){

    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){
		if(NULL == p1){
			p1 = (t_clientinfo*)malloc(sizeof(t_clientinfo));
			if(NULL == p1){
				debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
				fclose(fp);
				return -1;
			}
			p2->next = p1;
			p2 = p1;
			p1->next = NULL;

		}//if(NULL == p1)
		ret = sscanf(line,"%s %s %s",p1->client_mac,p1->client_ip,p1->host_name);
		if(3 != ret){
			if(line != NULL)
				free(line);
			fclose(fp);
			return -1;
		}
		p1 = p1->next;

    }//while
    fclose(fp);
	if(line != NULL){
		free(line);
		line = NULL;
	}


    /* get up speed
     * */
    fp = fopen(UP_SPEED_FILE,"r");
    if(NULL == fp){
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){
    	ret = sscanf(line,"%s %s",ip,a_rate);
    	if(2 != ret){
			if(line != NULL)
				free(line);
			fclose(fp);
			return -1;
    	}
    	p3 = get_client_info_by_ip(ip);
    	if(NULL != p3){
    	   p3->go_speed = atoi(a_rate);
    	}

    }//while
    fclose(fp);
	if(line != NULL){
		free(line);
		line = NULL;
	}



    /* get the down speed
     * */
    fp = fopen(DOWN_SPEED_FILE,"r");
    if(NULL == fp){
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){

    	ret = sscanf(line,"%s %s",ip,a_rate);
    	if(2 != ret){
			if(line != NULL)
				free(line);
			fclose(fp);
			return -1;
    	}
    	p3 = get_client_info_by_ip(ip);
    	if(NULL != p3){
    	   p3->come_speed = atoi(a_rate);
    	}

    }//while
    fclose(fp);
	if(line != NULL){
		free(line);
		line = NULL;
	}


	return 0;
}



/* @breif get unknown host name client's income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @PARAMETER:[char *client_ip] the unknown host name client's ip
 *            [int *go_speed] the pointer for client's outgoing speed to store.
 *            [int *come_speed] the pointer for client's incoming speed to store.
 * @RETURN_VALUE:zero is success,others is error.
 * @Note: none
 * GaomingPan lonely-test:yes
 * */
int get_unknown_client_speed(char *client_ip,int *go_speed,int *come_speed)
{

    FILE *fp;

	char a_rate[20],
	     ip[18];

	int   ret;
	int   line_num = 0;
	char  *line = NULL;


    /* get up speed
     * */
    fp = fopen(UP_SPEED_FILE,"r");
    if(NULL == fp){
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){
    	ret = sscanf(line,"%s %s",ip,a_rate);
    	if(2 != ret){
			if(line != NULL)
				free(line);
			fclose(fp);
			*go_speed = 0;
			*come_speed = 0;
			return -1;
    	}

    	if(0 == strcmp(client_ip,ip)){
    		*go_speed = atoi(a_rate);
    	}

    }//while
    fclose(fp);
	if(line != NULL){
		free(line);
		line =  NULL;
	}



    /* get the down speed
     * */
    fp = fopen(DOWN_SPEED_FILE,"r");
    if(NULL == fp){
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){

    	ret = sscanf(line,"%s %s",ip,a_rate);
    	if(2 != ret){
			if(line != NULL)
				free(line);
			fclose(fp);
			*go_speed = 0;
			*come_speed = 0;
			return -1;
    	}
    	if(0 == strcmp(client_ip,ip)){
    		*come_speed = atoi(a_rate);
    	}

    }//while
    fclose(fp);
	if(line != NULL){
		free(line);
		line = NULL;
	}

	return 0;
}

/* @breif After the function collect_client_info() called,should call this function to
 *        clean up.
 * @PARAMETER:void
 * @RETURN_VALUE:void
 * @Note: function collect_client_info() and this function just like the fopen() and fclose().
 * GaomingPan lonely-test:yes
 * */
void clean_client_info()
{
	  t_clientinfo *p;

	  p = first_client_info;

	  while(NULL != p){
	    free(p);
	    p = p->next;
	  }

	  first_client_info = NULL;
}



/* @breif find the element from the client_info list by mac.
 * @PARAMETER:[const char *mac],the pointer point to by mac.
 * @RETURN_VALUE:success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * GaomingPan lonely-test:yes
 * */
t_clientinfo * get_client_info_by_mac(const char *mac)
{
	t_clientinfo *p;
	p = first_client_info;
	while(NULL != p){
		if(strcmp(mac,p->client_mac) == 0){
			return p;
		}
		p = p->next;
	}
	return NULL;
}



/* @breif find the element from the client_info list by ip.
 * @PARAMETER:[const char *ip],the pointer point to by ip.
 * @RETURN_VALUE:success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * GaomingPan lonely-test:yes
 * */
t_clientinfo * get_client_info_by_ip(const char *ip)
{
	t_clientinfo *p;
	p = first_client_info;
	while(NULL != p){
		if(strcmp(ip,p->client_ip) == 0){
			return p;
		}
		p = p->next;
	}
	return NULL;
}


/* @breif find the element from the client_info list by ip.
 * @ip,the pointer point to by client's ip.
 * @@mac,the pointer point to by client's mac.
 * GaomingPan lonely-test:yes
 * */
long get_online_time(const char *ip,const char *mac)
{
	t_client *ptr;
	long online_time = 0;

	ptr = client_list_find(ip,mac);

	if(NULL!= ptr)
		online_time = time(NULL) - ptr->record_time;

	return online_time;
}



/*@breif get a flage string
 * */
char *get_client_auth_flag()
{
	return client_auth_flag;
}



/*@breif set a flage string
 * */
void set_client_auth_flag()
{
	/*
	 * Rand a range number at [max,min]:
	 *      rand()%(max - min + 1) + min
	 */
	int i;
	for(i = 0;i<6;i++)
	   client_auth_flag[i] = rand()%(90 - 65 + 1) + 65;
}


