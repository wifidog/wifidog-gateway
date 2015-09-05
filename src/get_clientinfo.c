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

static char client_auth_flag[7];

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
    FILE *fp,
	     *fp_shell,
		 *fp_upspeed,
		 *fp_downspeed;

	char info_buf[1024],
	     //chain_test[64],
	     ip[18];

	int  speed;
	int  ret;

	char *ptr,
	     *token;

	t_clientinfo *p1,
	             *p2,
				 *p3;
	int  i = 0;

    memset(info_buf,0,1024);
    first_client_info = (t_clientinfo*)malloc(sizeof(t_clientinfo));
    if(NULL == first_client_info)
    {
    	debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
    	//printf("ERROR: at collect_client_info(), malloc error.\n");
    	return -1;
    }
    first_client_info->next = NULL;

    p1 = first_client_info;
    p2 = p1;

    /**
     * Get client ip,mac and hostname
     * */
    fp = popen(CMD_GET_CLIENT_LIST,"r");

    if(NULL == fp)
    {
    	debug(LOG_ERR,"ERROR: at collect_client_info(),popen error.");
    	//printf("ERROR: at collect_client_info(),popen error.\n");
    	return -2;
    }

    while(NULL != fgets(info_buf,1024,fp))
    {

		if(NULL == p1)
		{
			p1 = (t_clientinfo*)malloc(sizeof(t_clientinfo));
			if(NULL == p1)
			{
				debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
				//printf("ERROR: at collect_client_info(), malloc error.\n");
				pclose(fp);
				return -3;
			}
			p2->next = p1;
			p2 = p1;
			p1->next = NULL;

		}//if

    	for(ptr = strtok(info_buf," \t\r\n");ptr;ptr = strtok(NULL," \t\r\n"))
    	{
    		i++;
    		token = (char*)malloc(40);
    		if(NULL == token)
    		{
    			debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.\n");
    			//printf("ERROR: at collect_client_info(), malloc error.\n");
    			pclose(fp);
    			return -4;
    		}
    		strcpy(token,ptr);
    		if(1 == i)
    		{
    			strcpy(p1->client_mac,token);
    			free(token);
    			continue;
    		}
    		if(2 == i)
    		{
    			strcpy(p1->client_ip,token);
    			free(token);
    			continue;
    		}
    		if(3 == i)
    		{
    			strcpy(p1->host_name,token);
    			free(token);
    			break;
    		}
    	}//for
		p1 = p1->next;
    	i = 0;
    	memset(info_buf,0,1024);
    }//while

    pclose(fp);


    /* get speed files
     * */
    //memset(chain_test,0,64);
    fp_shell = popen(CMD_MAKE_SPEED_FILE,"r");
    if(NULL == fp_shell)
    {
    	debug(LOG_ERR,"ERROR: at collect_client_info(),popen for fp_shell error.");
    	//printf("ERROR: at collect_client_info(),popen for fp_shell error.\n");
    	return -5;
    }
    //fread(chain_test,64,1,fp_shell);
    pclose(fp_shell);


    /* do some clean up,if it needs.
     * */
    ret  = clean_more_chain();
    if(0 != ret)
    {
    	debug(LOG_ERR,"ERROR: clean_more_chain() return value:%d\n",ret);
    	//printf("ERROR: clean_more_chain() return value:%d\n",ret);
    }


    /* get up speed
     * */
    fp_upspeed = fopen(UP_SPEED_FILE,"r");
    if(NULL == fp_upspeed)
    {
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp_upseed error.");
    	//printf("ERROR: at collect_client_info(),fopen for fp_upseed error.\n");
    	return -6;
    }
    memset(info_buf,0,1024);
    memset(ip,0,18);
    i = 0;
    while(NULL != fgets(info_buf,1024,fp_upspeed))
    {
    	for(ptr = strtok(info_buf," \t\r\n");ptr;ptr = strtok(NULL," \t\r\n"))
    	{
    		i++;
    		token = (char*)malloc(20);
    		if(NULL == token)
    		{
    			debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
    			//printf("ERROR: at collect_client_info(), malloc error.\n");
    			fclose(fp_upspeed);
    			return -7;
    		}
    		strcpy(token,ptr);
    		if(i == 1)
    		{
    			strcpy(ip,token);
    			free(token);
    			continue;
    		}
    		if(i == 2)
    		{
    			speed = atoi(token);
    			free(token);
    			p3 = get_client_info_by_ip(ip);
    			if(NULL != p3)
    			{
    				p3->go_speed = speed;
    			}
    			memset(ip,0,18);
    			i = 0;
    			break;
    		}
    	}//for
    }//while
    fclose(fp_upspeed);


    /* get the down speed
     * */
    fp_downspeed = fopen(DOWN_SPEED_FILE,"r");
    if(NULL == fp_downspeed)
    {
    	debug(LOG_ERR,"ERROR: at collect_client_info(),fopen for fp_downspeed error.");
    	//printf("ERROR: at collect_client_info(),fopen for fp_downspeed error.\n");
    	return -8;
    }
    memset(info_buf,0,1024);
    memset(ip,0,18);
    i = 0;
    while(NULL != fgets(info_buf,1024,fp_downspeed))
    {
    	for(ptr = strtok(info_buf," \t\r\n");ptr;ptr = strtok(NULL," \t\r\n"))
    	{
    		i++;
    		token = (char*)malloc(40);
    		if(NULL == token)
    		{
    			debug(LOG_ERR,"ERROR: at collect_client_info(), malloc error.");
    			//printf("ERROR: at collect_client_info(), malloc error.\n");
    			fclose(fp_downspeed);
    			return -9;
    		}
    		strcpy(token,ptr);
    		if(i == 1)
    		{
    			strcpy(ip,token);
    			free(token);
    			continue;
    		}
    		if(i == 2)
    		{
    			speed = atoi(token);
    			free(token);
    			p3 = get_client_info_by_ip(ip);
    			if(NULL != p3)
    			{
    				p3->come_speed = speed;
    			}
    			memset(ip,0,18);
    			i = 0;
    			break;
    		}
    	}
    }//while
    fclose(fp_downspeed);

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

    FILE *fp_upspeed,
		 *fp_downspeed;

	char info_buf[1024],
	     ip[18];

	int  speed;
	int  ret;

	char *ptr,
	     *token;

	int  i = 0;

    /* get up speed
     * */
    fp_upspeed = fopen(UP_SPEED_FILE,"r");
    if(NULL == fp_upspeed)
    {
    	debug(LOG_ERR,"ERROR: at get_unknown_client_speed(...),fopen for fp_upseed error.");
    	//printf("ERROR: at collect_client_info(),fopen for fp_upseed error.\n");
    	*go_speed = *come_speed = 0;
    	return -1;
    }
    memset(info_buf,0,1024);
    memset(ip,0,18);
    i = 0;
    while(NULL != fgets(info_buf,1024,fp_upspeed))
    {
    	for(ptr = strtok(info_buf," \t\r\n");ptr;ptr = strtok(NULL," \t\r\n"))
    	{
    		i++;
    		token = (char*)malloc(20);
    		if(NULL == token)
    		{
    			debug(LOG_ERR,"ERROR: at get_unknown_client_speed(...), malloc error.");
    			//printf("ERROR: at collect_client_info(), malloc error.\n");
    			fclose(fp_upspeed);
    			*go_speed = *come_speed = 0;
    			return -2;
    		}
    		strcpy(token,ptr);
    		if(i == 1)
    		{
    			strcpy(ip,token);
    			free(token);
    			continue;
    		}
    		if(i == 2)
    		{
    			speed = atoi(token);
    			free(token);
    			if(0 == strcmp(client_ip,ip))
    			{
    				*go_speed = speed;
    			}
    			memset(ip,0,18);
    			i = 0;
    			break;
    		}
    	}//for
    }//while
    fclose(fp_upspeed);


    /* get the down speed
     * */
    fp_downspeed = fopen(DOWN_SPEED_FILE,"r");
    if(NULL == fp_downspeed)
    {
    	debug(LOG_ERR,"ERROR: at get_unknown_client_speed(...),fopen for fp_downspeed error.");
    	//printf("ERROR: at collect_client_info(),fopen for fp_downspeed error.\n");
    	*go_speed = *come_speed = 0;
    	return -3;
    }
    memset(info_buf,0,1024);
    memset(ip,0,18);
    i = 0;
    while(NULL != fgets(info_buf,1024,fp_downspeed))
    {
    	for(ptr = strtok(info_buf," \t\r\n");ptr;ptr = strtok(NULL," \t\r\n"))
    	{
    		i++;
    		token = (char*)malloc(40);
    		if(NULL == token)
    		{
    			debug(LOG_ERR,"ERROR: at get_unknown_client_speed(...), malloc error.");
    			//printf("ERROR: at collect_client_info(), malloc error.\n");
    			fclose(fp_downspeed);
    			*go_speed = *come_speed = 0;
    			return -4;
    		}
    		strcpy(token,ptr);
    		if(i == 1)
    		{
    			strcpy(ip,token);
    			free(token);
    			continue;
    		}
    		if(i == 2)
    		{
    			speed = atoi(token);
    			free(token);
    			if(0 == strcmp(client_ip,ip))
    			{
    				*come_speed = speed;
    			}
    			memset(ip,0,18);
    			i = 0;
    			break;
    		}
    	}
    }//while
    fclose(fp_downspeed);
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
	t_clientinfo *p1,
	              *p2;

	  p1 = first_client_info;
	  p2 = p1->next;

	  while(NULL != p1)
	  {
	    free(p1);
	    p1 = p2;
	    if(NULL != p2)
	      p2 = p2->next;
	  }
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
	while(NULL != p)
	{
		if(strcmp(mac,p->client_mac) == 0)
		{
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
	while(NULL != p)
	{
		if(strcmp(ip,p->client_ip) == 0)
		{
			return p;
		}
		p = p->next;
	}
	return NULL;
}



long get_online_time(const char *ip,const char *mac)
{
	t_client *ptr;
	long online_time = 0;

	ptr = client_list_find(ip,mac);

	if(NULL!= ptr)
	{
		online_time = time(NULL) - ptr->record_time;
	}

	return online_time;
}



int clean_more_chain()
{
	   FILE *fp;

	   char chain_test[10];

	   int chain_num = 0,
	               m = 0,
	    failed_count = 0;


	    memset(chain_test,0,10);
	    fp = popen(CMD_GET_CHAIN_NUM,"r");
	    if(NULL == fp)
	    {
	    	debug(LOG_ERR,"ERROR: at collect_client_info(),popen for fp_shell error.");
	    	//printf("ERROR: at collect_client_info(),popen for fp error.\n");
	    	return -1;
	    }
	    pclose(fp);

	    fp = fopen("/tmp/client.speed.chain.num","r");
	    if(NULL == fp)
	    {
	    	debug(LOG_ERR,"ERROR: fopen() /tmp/client.speed.chain.num\n");
	    	//printf("ERROR: fopen() /tmp/client.speed.chain.num\n");
		    return -2;
	    }
	    while(NULL != fgets(chain_test,10,fp))
	    {
		    m = atoi(chain_test);

		    if(m > chain_num)
		      chain_num = m;
	    }
	    fclose(fp);

	    while( --chain_num > 0)
	    {

	        fp = popen(CMD_CLEAN_SPEED_CHAIN,"r");
	        if(NULL != fp)
	        {
		       pclose(fp);
		        debug(LOG_INFO,"INFO: clean iptables chain");
		        //printf("INFO: clean iptables chain\n");
	        }
	        else
		    {
		        failed_count++;
		        debug(LOG_ERR,"ERROR: popen(CMD_CLEAN_SPEED_CHAIN,r)");
		        //printf("ERROR: popen(CMD_CLEAN_SPEED_CHAIN,r)\n");
		    }
	    }

	   return failed_count;
}



char *get_client_auth_flag()
{
	return client_auth_flag;
}




void set_client_auth_flag()
{
	// rand()%(max - min + 1) + min
	int i;
	for(i = 0;i<6;i++)
	   client_auth_flag[i] = rand()%(90 - 65 + 1) + 65;

	client_auth_flag[6] = 0;
}


