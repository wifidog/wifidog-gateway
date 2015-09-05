/*
 * get_devinfo.c
 *
 *  Created on: Jul 9, 2015
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


#include "util.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "../config.h"


#include "shell_command.h"
#include "get_devinfo.h"

extern pthread_mutex_t client_list_mutex;

static t_devinfo devinfo;
static t_cpuuse cpuuse;

t_devinfo *get_devinfo(void)
{

	if(get_apmac(devinfo.gw_mac))
	{
		debug(LOG_ERR,"MyDEBUG:get get_apmac error!");
	}

	if(get_devssid(devinfo.gw_ssid))
	{
		debug(LOG_ERR,"MyDEBUG:get ssid error!");
	}
	if(get_dogversion(devinfo.dog_version))
	{
		debug(LOG_ERR,"MyDEBUG: get_dogversion error!");
	}
	if(get_wanip(devinfo.wan_ip))
	{
		debug(LOG_ERR,"MyDEBUG: get_wanip error!\n");
	}

	devinfo.cur_conn = get_curconn();
	devinfo.dev_conn = get_devconn();

	devinfo.cpu_use = get_cpuuse(CPU_LOAD);

	if(get_wanbps(&devinfo.go_speed,&devinfo.come_speed))
	{
		debug(LOG_ERR,"MyDEBUG: get_speed error!");
	}
	if(get_trafficCount(&devinfo.outgoing,&devinfo.incoming))
	{
		debug(LOG_ERR,"MyDEBUG: get_traffic error!\n");
	}

	return &devinfo;
}

/* @breif get wireless ssid,based on uci command.
 * @PARAMETER: [char *ssid]:the char pointer for save the ssid.
 * @RETURN_VALUE: zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_devssid(char *ssid)
{
	FILE *fp;
	memset(ssid,0,DEV_SSID_NAME_LEN);
	fp = popen(CMD_GET_WIRELESS_SSID,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR," get_devssid error!");
		sprintf(ssid,"%s","null");
		return -1;
	}
	fread(ssid,DEV_SSID_NAME_LEN,1,fp);
	pclose(fp);

	int i = DEV_SSID_NAME_LEN - 1;
	for(;i > 0;i--)
	{
		if(0x0a == ssid[i])
		{
			ssid[i] = 0;
			break;
		}
	}
	return 0;
}


/* @breif get wifidog version
 * @PARAMETER:[char *dogversion]:the char pointer for save the version
 * @RETURN_VALUE:always return zero
 * GaomingPan lonely-test:no
 * */
int get_dogversion(char *dogversion)
{
	memset(dogversion,0,DEV_DOG_VERSION_LEN);
	sprintf(dogversion,"%s",VERSION);
	return 0;
}

/* @breif get wan interface ip,based on uci command.
 * @PARAMETER:[char *wanip]:the char pointer for save the wan ip
 * @RETURN_VALUE:always zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_wanip(char *wanip)
{
	FILE *fp;
	memset(wanip,0,DEV_WAN_IP_LEN);
	fp = popen(CMD_GET_WAN_IP,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"get_wanip error!");
		sprintf(wanip,"%s","0.0.0.0");
		return -1;
	}
	fread(wanip,DEV_WAN_IP_LEN - 1,1,fp);
	pclose(fp);

	int i = DEV_WAN_IP_LEN - 1;
	for(;i > 0;i--)
	{
		if(0x0a == wanip[i])
		{
			wanip[i] = 0;
			break;
		}
	}

	return 0;
}



/* @breif get ap mac address,based on uci command.
 * @PARAMETER:[char *apmac]:the char pointer for save the mac
 * @RETURN_VALUE:always zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_apmac(char *apmac)
{
	FILE *fp;
	int i;
	memset(apmac,0,DEV_MAC_ADDR_LEN);
	fp = popen(CMD_GET_AP_MAC,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"get_apmac() popen error.");
		sprintf(apmac,"%s","00-00-00-00-00-00");
		return -1;
	}
	fread(apmac,DEV_MAC_ADDR_LEN - 1,1,fp);
	pclose(fp);

	for(i = 0; i< DEV_MAC_ADDR_LEN; i++)
	{
	  if(':' == apmac[i])
	    apmac[i] = '-';
	  if(0x0a == apmac[i])
		  apmac[i] = 0;
	}

	return 0;
}


/* @breif get number of client
 * @PARAMETER:none
 * @RETURN_VALUE:the number of current connected client
 * GaomingPan lonely-test:no
 * */
int get_curconn(void)
{
	int count;
	t_client *first;

	LOCK_CLIENT_LIST();

	first = client_get_first_client();
	if (first == NULL) {
		count = 0;
	} else {
		count = 1;
		while (first->next != NULL) {
			first = first->next;
			count++;
		}
	}

	UNLOCK_CLIENT_LIST();

	return count;
}


/* @breif get number of client who connect to the device
 * @PARAMETER:none
 * @RETURN_VALUE:the number of connected client
 * GaomingPan lonely-test:no
 * */
int get_devconn(void)
{
	FILE *fp;
	char shell_cmd[1024],
	     buf[10];
	s_config *conf = config_get_config();
	memset(buf,0,10);

	sprintf(shell_cmd,"cat /proc/net/arp|grep -e \"0x2\"|grep -e \"%s\" > /tmp/.devconn;awk \'END{print NR}\' /tmp/.devconn",conf->gw_interface);
	//fp = popen("awk \'END{print NR}\' $(uci get dhcp.@dnsmasq[0].leasefile)","r");
	fp = popen(shell_cmd,"r");

	if(NULL == fp)
	{
		debug(LOG_ERR,"ERROR popen error, at get_devconn().");
		return -1;
	}
    if(0 == fread(buf,1,10,fp))
    {
    	pclose(fp);
    	return -2;
    }
    pclose(fp);
    return (atoi(buf));
}


/* @breif get cpu use infomation,based on shell command.
 * @PARAMETER:[int type] CPU_USER,CPU_SYS,CPU_NIC,CPU_IDLE,CPU_IO,CPU_IRQ,CPU_SIRQ,CPU_LOAD
 * @RETURN_VALUE:the number of current percent of CPU use.
 * GaomingPan lonely-test:yes
 * */
int get_cpuuse(int type)
{
	char num[4];
	int use,
	    i;
	FILE *fp;

	memset(num,0,4);
	for(i = 0;i < 15;i++)
	  memset(cpuuse.use_info[i],0,8);

	fp = popen(CMD_GET_CPU_USE,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"get_cpuuse error!");
		return -1;
	}
	fscanf(fp,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
	       cpuuse.use_info[0],cpuuse.use_info[1],cpuuse.use_info[2],
	       cpuuse.use_info[3],cpuuse.use_info[4],cpuuse.use_info[5],
	       cpuuse.use_info[6],cpuuse.use_info[7],cpuuse.use_info[8],
	       cpuuse.use_info[9],cpuuse.use_info[10],cpuuse.use_info[11],
	       cpuuse.use_info[12],cpuuse.use_info[13],cpuuse.use_info[14]
	      );
	pclose(fp);

//	for(;i<15;i++)
//	  printf("cpuuse.use_info[%d]:%s\n",i,cpuuse.use_info[i]);

	switch(type){
	 case CPU_USER:
	   cpuuse.use_info[CPU_USER][strlen(cpuuse.use_info[CPU_USER])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_USER]);
	   break;
	 case CPU_SYS:
	   cpuuse.use_info[CPU_SYS][strlen(cpuuse.use_info[CPU_SYS])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_SYS]);
	   break;
	 case CPU_NIC:
	   cpuuse.use_info[CPU_NIC][strlen(cpuuse.use_info[CPU_NIC])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_NIC]);
	   break;
	 case CPU_IDLE:
	   cpuuse.use_info[CPU_IDLE][strlen(cpuuse.use_info[CPU_IDLE])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_IDLE]);
	   break;
	   case CPU_LOAD:
	   cpuuse.use_info[CPU_IDLE][strlen(cpuuse.use_info[CPU_IDLE])-1] = 0;
	   use = 100 - atoi(cpuuse.use_info[CPU_IDLE]);
	   break;
	 case CPU_IO:
	   cpuuse.use_info[CPU_IDLE][strlen(cpuuse.use_info[CPU_IO])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_IO]);
	   break;
	 case CPU_IRQ:
	   cpuuse.use_info[CPU_IRQ][strlen(cpuuse.use_info[CPU_IRQ])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_IRQ]);
	   break;
	 case CPU_SIRQ:
	   cpuuse.use_info[CPU_SIRQ][strlen(cpuuse.use_info[CPU_SIRQ])-1] = 0;
	   use = atoi(cpuuse.use_info[CPU_SIRQ]);
	   break;
	  default:
	    use = -1;
	    break;
	}

	return use;
}


/* @breif get wan interface traffic,based on shell command.
 * @PARAMETER:[long *outgo,long *income],the pointer for save outgo-data and income-data.
 * @RETURN_VALUE:zero is success,others is error.
 * GaomingPan lonely-test:yes
 * */
int get_trafficCount(long *outgo,long *income)
{
	FILE *fp;
	char ifname[DEV_IFNAME_LEN];
	memset(ifname,0,DEV_IFNAME_LEN);

	fp = popen(CMD_GET_WAN_IFNAME,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"get_trafficCount() popen error.");
        *outgo = -1L;
        *income = -1L;
        return -1;
	}
	fread(ifname,DEV_IFNAME_LEN-1,1,fp);
	pclose(fp);

	int j;
	for(j = 0;j < DEV_IFNAME_LEN;j++)
	{
	  if(0x0a == ifname[j])
	  {
	    ifname[j] = 0;
	    break;
	  }
	}

    int nDevLen = strlen(ifname);
    if (nDevLen < 1 || nDevLen > DEV_IFNAME_LEN - 1)
    {
    	debug(LOG_ERR,"get_trafficCount(),dev length too long.");
        *outgo = -1L;
        *income = -1L;
        return -2;
    }
    int fd = open("/proc/net/dev", O_RDONLY | O_EXCL);
    if (-1 == fd)
    {
    	debug(LOG_ERR,"get_trafficCount(),open /proc/net/dev failed ,maybe file not exists!");
        *outgo = -1L;
        *income = -1L;
        return -3;
    }

    char buf[1024*2];
    lseek(fd, 0L, SEEK_SET);
    int nBytes = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (-1 == nBytes)
    {
    	debug(LOG_ERR,"get_trafficCount(),read bytes error.");
        *outgo = -1L;
        *income = -1L;
        return -4;
    }
    buf[nBytes] = '\0';

    //返回第一次指向ifname位置的指针
    char* pDev = strstr(buf, ifname);
    if (NULL == pDev)
     {
    	debug(LOG_ERR,"get_trafficCount(),don't find dev %s", ifname);
        *outgo = -1L;
        *income = -1L;
        return -5;
     }
     char *p;
     char *ifconfig_value;
     int i = 0;
     long rx2_tx10[2];
     /*去除空格，制表符，换行符等不需要的字段*/
     for (p = strtok(pDev, " \t\r\n"); p; p = strtok(NULL, " \t\r\n"))
      {
         i++;
         ifconfig_value = (char*)malloc(30);
         if(NULL == ifconfig_value)
         {
         	debug(LOG_ERR,"get_trafficCount(),malloc error.");
            *outgo = -1L;
            *income = -1L;
            return -6;
         }
         strcpy(ifconfig_value, p);
         /*得到的字符串中的第二个字段是接收流量*/
         if(i == 2)
         {
            rx2_tx10[0] = atoll(ifconfig_value);
         }
         /*得到的字符串中的第十个字段是发送流量*/
         if(i == 10)
         {
            rx2_tx10[1] = atoll(ifconfig_value);
            break;
         }
           free(ifconfig_value);
       }
       free(ifconfig_value);

      *income =  rx2_tx10[0];
      *outgo  =  rx2_tx10[1];

      return 0;
}


/* @breif get wan interface speed,based on shell command.
 * @PARAMETER:[int *go,int *come],the pointer for save outgo speed and income speed.
 * @RETURN_VALUE:zero is success,others is error.
 * @NOTE: this function will take a one second to wait data update,so,it's just waste time.
 * GaomingPan lonely-test:yes
 * */
int get_wanbps(int *go,int *come)
{
    long outgo = 0,
         income = 0;

    long outgo1 = 0,
         income1 = 0;
    int ret = 0;

    ret  = get_trafficCount(&outgo,&income);

    if(ret)
    {
    	debug(LOG_ERR,"1 at get_wanbps(), get_trafficCount() error return code = %d",ret);
      return -1;
    }

    sleep(1);

    ret  =  get_trafficCount(&outgo1,&income1);
    if(ret)
    {
    	debug(LOG_ERR,"2 at get_wanbps(), get_trafficCount() error return code = %d",ret);
      return -2;
    }

    *go = (int)(outgo1 - outgo);
    *come = (int)(income1 - income);

    return 0;
}
