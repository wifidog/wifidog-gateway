/*
 * extend_util.c
 *
 *  Created on: Oct 10, 2015
 *      Author: GaomingPan
 */
#include "extend_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "client_list.h"
#include "conf.h"
#include "debug.h"
#include "fw_iptables.h"
#include "util.h"
#include "../config.h"




/*================= SOME INTERNAL DEFINDS AND STRUCTURES ======================*/
/**
 * This part is get the device information functions,
 * and some Macro defines.
 * */
#define DEV_IFNAME_LEN       11
#define IFACE_DATA_FILE      "/tmp/.iface-data"
#define IFACE_CONN_FILE      "/tmp/.iface_conn"
#define CPU_USE_INFO_FILE    "/tmp/.cpu_use_info"
#define	CPU_USER             1
#define	CPU_SYS              3
#define	CPU_NIC              5
#define	CPU_IDLE             7
#define	CPU_IO               9
#define	CPU_IRQ              11
#define	CPU_SIRQ             13
#define CPU_LOAD             16


/**
 * This part is get the client's information functions,
 * and some Macro defines.
 * */
#define  UP_SPEED_FILE             "/tmp/.client.up.speed"
#define  DOWN_SPEED_FILE           "/tmp/.client.down.speed"
#define  HOST_NAME_FILE            "/tmp/.hostname.txt"

/**
 * This part is get the remote shell command functions,
 * and some Macro defines.
 * */
#define  GET_SETTINGS_INFO_CMD          "GET_settings"
#define  SETTINGS_INFO_FILE             "/tmp/.routersettings"
#define  NORMAL_CMD_RESULT_FILE         "/tmp/.normal_cmd_result"

#define  BUILE_NORMAL_CMD_RESULT_SHELL  "sed -i \"s/\\\"/ /g\" "NORMAL_CMD_RESULT_FILE "; echo \"[\" > /tmp/.normal.arr;while read line;do echo \"\\\"$line\\\"\", >> /tmp/.normal.arr;done < "NORMAL_CMD_RESULT_FILE";result=\"$(cat /tmp/.normal.arr)\";result=\"${result%,}]\";echo $result"

#define  CMD_GET_WAN_IP                 "uci -P/var/state get network.wan.ipaddr"
#define  CMD_GET_AP_MAC                 "uci get network.lan.macaddr" //"uci -P/var/state get network.lan.macaddr"
#define  CMD_GET_WIRELESS_SSID          "uci get wireless.@wifi-iface[0].ssid"
#define  WAN_IP_ADDR_FILE                "/tmp/.wan_ipaddr.txt"
#define  REMOTE_SHELL_COMMAND_LEN       1024
#define  MAX_CMD_EXECUT_OUT_LEN         4096

/**
 * This part is get the remote shell command functions,
 * and some Macro defines.
 * */
#define  DEVICE_KEY_FILE  "/etc/.devicekey"


/*=============================================================*/
/**
 * This part is get the device information functions,
 * and some Macro defines.
 * */


/**
 * @ breif a internal struct hold cpu load information for ap
 * */
struct _t_cpuuse{
	char use_info[15][8];
};


typedef struct _t_cpuuse   t_cpuuse;


/*======================== END DEFINDS ========================*/


extern pthread_mutex_t client_list_mutex;
static t_devinfo devinfo;
static t_cpuuse cpuuse;
static char apmac[DEV_MAC_ADDR_LEN] = {0};
static char apwanip[DEV_WAN_IP_LEN] = {0};
//extern char *dev_extern_iface;


/**
 * @brief this function collect the gateway device information.
 * @returnValue a type pointer of t_devinfo
 * */
t_devinfo *get_devinfo(void)
{

	memcpy(devinfo.gw_mac,apmac,DEV_MAC_ADDR_LEN);

//	if(get_apmac(devinfo.gw_mac))
//	{
//		debug(LOG_WARNING,"MyDEBUG:get get_apmac error!");
//	}

	if(get_devssid(devinfo.gw_ssid))
	{
		debug(LOG_WARNING,"ERR:get ssid error!");
	}

	if(get_dogversion(devinfo.dog_version))
	{
		debug(LOG_WARNING,"ERR: get_dogversion error!");
	}

	if(get_wanip(devinfo.wan_ip))
	{
		debug(LOG_WARNING,"ERR: get_wanip error!\n");
	}

	devinfo.cur_conn = get_curconn();
	devinfo.dev_conn = get_devconn();

	devinfo.cpu_use = get_cpuuse(CPU_LOAD);

	if(get_wanbps(&devinfo.go_speed,&devinfo.come_speed))
	{
		debug(LOG_WARNING,"ERR: get_speed error!");
	}

	if(get_trafficCount(get_dev_extern_iface(),&devinfo.incoming,&devinfo.outgoing,NULL,NULL))
	{
		debug(LOG_WARNING,"ERR: get_traffic error!\n");
	}

	return &devinfo;
}

/**
 * @brief get wireless ssid,based on uci command.
 * @param ssid: the char pointer for save the ssid.
 * @return value: zero is success,others is failed.
 * */
int get_devssid(char *ssid)
{
	FILE *fp;
	memset(ssid,0,DEV_SSID_NAME_LEN);
	fp = popen(CMD_GET_WIRELESS_SSID,"r");
	if(NULL == fp)
	{
		debug(LOG_WARNING," get_devssid error!");
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


/**
 * @breif get wifidog version
 * @param dogversion:the char pointer for save the version
 * @return value:always return zero
 * */
int get_dogversion(char *dogversion)
{
	memset(dogversion,0,DEV_DOG_VERSION_LEN);
	sprintf(dogversion,"%s",VERSION);
	return 0;
}

/**
 * @breif get wan interface ip,based on uci command.
 * @param wanip:the char pointer for save the wan ip
 * @return value:always zero is success,others is failed.
 * */
int get_wanip(char *wanip)
{
	FILE *fp;

	if(0 == strlen(apwanip)){
		/*
		fp = popen(CMD_GET_WAN_IP,"r");
		if(NULL == fp){
			debug(LOG_WARNING,"get_wanip error!");
			if(NULL != wanip)
			    sprintf(wanip,"%s","0.0.0.0");
			return -1;
		}
		fread(apwanip,DEV_WAN_IP_LEN - 1,1,fp);
		pclose(fp);

		int i = DEV_WAN_IP_LEN - 1;
		for(;i >= 0;i--){
			if(0x0a == apwanip[i]){
				apwanip[i] = 0;
				break;
			}
		}
		*/
		fp = fopen(WAN_IP_ADDR_FILE,"r");
		if(NULL == fp){
			debug(LOG_WARNING,"get_wanip error!");
			if(NULL != wanip)
			    sprintf(wanip,"%s","0.0.0.0");
			return -1;
		}
		fread(apwanip,DEV_WAN_IP_LEN - 1,1,fp);
		fclose(fp);

		int i = DEV_WAN_IP_LEN - 1;
		for(;i >= 0;i--){
			if(0x0a == apwanip[i]){
				apwanip[i] = 0;
				break;
			}
		}

	}
	if(NULL != wanip)
	    sprintf(wanip,"%s",apwanip);

	return 0;
}

/**
 * @breif get ap mac address,based on uci command.
 * @param apmac:the char pointer for save the mac
 * @return value:zero is success,others is failed.
 * */
int get_apmac(char *mac)
{
	FILE *fp;
	int   i;

	if(0 == strlen(apmac)){
	    fp = popen(CMD_GET_AP_MAC,"r");
	    if(NULL == fp){
		    debug(LOG_WARNING,"get_apmac() popen error.");
		    sprintf(apmac,"%s","00-00-00-00-00-00");
		    return -1;
	    }
	    fread(apmac,DEV_MAC_ADDR_LEN - 1,1,fp);
	    pclose(fp);

	    for(i = 0; i< DEV_MAC_ADDR_LEN; i++){
	       if(':' == apmac[i])
	           apmac[i] = '-';
	       if(apmac[i] >= 'A' && apmac[i] <= 'F')
		       apmac[i] += apmac[i] + 0x20;
	       if(0x0a == apmac[i])
		       apmac[i] = 0;
	     }
	}

	if(NULL != mac)
        mac = apmac;

	return 0;
}


/**
 * @breif get number of client it in the client list
 * @return value:the number of current connected client
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


/**
 * @breif get number of client who connect to the device
 * @return value:the number of connected client
 * */
int get_devconn(void)
{
	FILE *fp;
	char  info_buf[512],
	      num_buf[10];
	char *ptr = NULL;
	s_config *conf = config_get_config();

	fp = fopen(IFACE_CONN_FILE,"r");
	if(NULL == fp){
		debug(LOG_WARNING,"Warning: fopen error, at get_devconn().");
		return -1;
	}
    if(0 == fread(info_buf,1,512,fp)){
    	fclose(fp);
    	debug(LOG_WARNING,"Warning: read device conn error.");
    	return 0;
    }
    fclose(fp);
    ptr = strstr(info_buf,conf->gw_interface);
    if(NULL == ptr){
    	debug(LOG_WARNING,"Warning: strstr(info_buf,conf->gw_interface) return is NULL");
    	return 0;
    }
    sscanf(ptr,"%*s %s",num_buf);
    return (atoi(num_buf));
}


/**
 * @breif get cpu use infomation,based on shell command
 * @param type: CPU_USER,CPU_SYS,CPU_NIC,CPU_IDLE,CPU_IO,CPU_IRQ,CPU_SIRQ,CPU_LOAD
 * @return value:the number of current percent of CPU use.
 * */
int get_cpuuse(int type)
{
	int use,
	    i;
	FILE *fp;

	for(i = 0;i < 15;i++)
	  memset(cpuuse.use_info[i],0,8);

	fp = fopen(CPU_USE_INFO_FILE,"r");
	if(NULL == fp){
		debug(LOG_WARNING,"fopen error,at get_cpuuse(...) !");
		return -1;
	}
	fscanf(fp,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
	       cpuuse.use_info[0],cpuuse.use_info[1],cpuuse.use_info[2],
	       cpuuse.use_info[3],cpuuse.use_info[4],cpuuse.use_info[5],
	       cpuuse.use_info[6],cpuuse.use_info[7],cpuuse.use_info[8],
	       cpuuse.use_info[9],cpuuse.use_info[10],cpuuse.use_info[11],
	       cpuuse.use_info[12],cpuuse.use_info[13],cpuuse.use_info[14]
	      );
	fclose(fp);

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

/**
 * @breif get wan interface traffic,based on shell command.
 * @param iface_name: interface name
 * @param income: interface incoming
 * @param outgo: interface outgoing
 * @param rx_rate: interface RX rate
 * @param tx_rate: interface TX rate
 * @return value:zero is success,others is error
 * */
int get_trafficCount(char *iface_name,unsigned long long *income,unsigned long long *outgo,unsigned int *rx_rate,unsigned int *tx_rate)
{
	FILE *fp;
    char *iface,
	     *ptr;
    char  data[4096];
    struct stat statbuf;
    int data_size;
    int ret;

    unsigned int rx,tx;
    unsigned long long out,in;


    iface = iface_name;
    if(NULL == iface){
    	out = 0L;
    	in = 0L;
    	debug(LOG_WARNING,"at get_trafficCount(...),ifce_name is NULL.");
    	ret = -1;
    	goto ERR;
    }

    stat(IFACE_DATA_FILE,&statbuf);
    data_size = statbuf.st_size;

    fp = fopen(IFACE_DATA_FILE,"r");
    if(NULL == fp){
    	out = 0L;
    	in = 0L;
    	debug(LOG_WARNING,"at get_trafficCount(...), fopen the IFACE_DATA_FILE error.");
    	ret =  -2;
    	goto ERR;
    }
    fread(data,1,data_size,fp);
    fclose(fp);

   ptr = strstr(data,iface);
    if(NULL == ptr){
    	out = 0L;
    	in = 0L;
    	debug(LOG_WARNING,"at get_trafficCount(...), strstr(..) get iface position error.");
    	ret =  -3;
    	goto ERR;
    }
    ret = sscanf(ptr,"%*s %llu %llu %u %u",&in,&out,&rx,&tx);
    if(ret != 4)
    	goto ERR;

    if(NULL != outgo)
    	*outgo = out;
    if(NULL != income)
    	*income = in;
    if(NULL != rx_rate)
    	*rx_rate = rx;
    if(NULL != tx_rate)
    	*tx_rate = tx;

	return 0;

ERR:
	if(NULL != outgo)
		*outgo = 0;
	if(NULL != income)
		*income = 0;
	if(NULL != rx_rate)
		*rx_rate = 0;
	if(NULL != tx_rate)
		*tx_rate = 0;

	return ret;
}

/**
 * @breif get wan interface speed,based on shell command.
 * @param go:the pointer for save out rate
 * @param come:the pointer for save income rate.
 * @return value:zero is success,others is error.
 * */
int get_wanbps(unsigned int *go,unsigned int *come)
{
    unsigned int tx,rx;
    int ret = 0;
    char *iface;

    iface = get_dev_extern_iface();//config_get_config()->external_interface;
    if(NULL == iface){
    	debug(LOG_WARNING,"at get_trafficCount(...), wifidog can't find the external_interface.");
    }

    ret  = get_trafficCount(iface,NULL,NULL,&rx,&tx);
    if(ret != 0){
    	debug(LOG_WARNING,"at get_wanbps(), get_trafficCount() error return code = %d",ret);
        if(NULL != go)
            *go = 0;
        if(NULL != come)
            *come = 0;
        return -1;
    }

    if(NULL != go)
        *go = tx;
    if(NULL != come)
        *come = rx;

    return 0;
}
/*=============================================================*/

/*=============================================================*/
/**
 * This part is get the client's information functions,
 * and some Macro defines.
 * */
static t_clientinfo *first_client_info = NULL;
static char client_auth_flag[7] = {0};

/**
 * @breif get client host name,income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @return value: zero is success,others is error.
 * @Note: after this function be called and you get some clients information,you should
 *        call clean_client_info() function to clean up,just like the fopen() and fclose().
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

	if(first_client_info){
		debug(LOG_WARNING,"client's info list not NULL,can't cllecting info,will clearing the list.");
		clean_client_info();
		return -1;
	}
	/**
	 * malloc memories for clients info list.
	 * */
    first_client_info = (t_clientinfo*)malloc(sizeof(t_clientinfo));
    if(NULL == first_client_info){
    	debug(LOG_WARNING,"Warning: at collect_client_info(), malloc error.");
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

    	debug(LOG_WARNING,"Warning: at collect_client_info(),fopen error.");
    	return -1;
    }
    while(-1 != getline(&line,&line_num,fp)){
		if(NULL == p1){
			p1 = (t_clientinfo*)malloc(sizeof(t_clientinfo));
			if(NULL == p1){
				debug(LOG_WARNING,"Warning: at collect_client_info(), malloc error.");
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
    	debug(LOG_WARNING,"Warning: at collect_client_info(),fopen for fp error.");
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
    	debug(LOG_WARNING,"Warning: at collect_client_info(),fopen for fp error.");
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


/**
 * @breif get unknown host name client's income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @param client_ip: the unknown host name client's ip.
 * @param go_speed: the pointer for client's outgoing speed to store.
 * @param come_speed: the pointer for client's incoming speed to store.
 * @return value: zero is success,others is error.
 * */
int get_unknown_client_speed(const char *client_ip,int *go_speed,int *come_speed)
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
    	debug(LOG_WARNING,"Warning: at collect_client_info(),fopen for fp error.");
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
    	debug(LOG_WARNING,"Warning: at collect_client_info(),fopen for fp error.");
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

/**
 *  @breif After the function collect_client_info() called,should call this function to
 *        clean up.
 * @return value: the count number of clean
 * */
int clean_client_info()
{
	  t_clientinfo *p;
	  int          num = 0;

	  p = first_client_info;

	  while(NULL != p){
	    ++num;
		free(p);
	    p = p->next;
	  }

	  first_client_info = NULL;

	  return num;
}



/**
 * @breif find the element from the client_info list by mac.
 * @param mac: the pointer point to by mac.
 * @return value: success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
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



/**
 * @breif find the element from the client_info list by ip.
 * @param ip: the pointer point to by ip.
 * @return value: success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
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


/**
 * @breif find the element from the client_info list by ip.
 * @param ip: the pointer point to by client's ip.
 * @param mac: the pointer point to by client's mac.
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

/*
 * @breif get a flage string
 * */
char *get_client_auth_flag()
{
	return client_auth_flag;
}

/*
 * @breif set a flage string
 * */
void set_client_auth_flag()
{
	/*
	 * Rand a range number at [max,min]:
	 *      rand()%(max - min + 1) + min
	 * */
	int i;
	for(i = 0;i<6;i++)
	   client_auth_flag[i] = rand()%(90 - 65 + 1) + 65;
}


/*=============================================================*/
/**
 * This part is get the remote shell command functions,
 * and some Macro defines.
 * */
static char remote_shell_cmd[ REMOTE_SHELL_COMMAND_LEN ];
static char info_http_url[128],
			info_rmflag[20],
			normal_http_url[128],
			normal_rmflag[20];


int init_post_http_url_config(void)
{
	memset(info_http_url,0,128);
	memset(info_rmflag,0,20);
	memset(normal_http_url,0,128);
	memset(normal_rmflag,0,20);

	char buf[128];
	FILE *fp;
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.url.info_url","r");
	if(NULL == fp){
		return -1;
	}
	fread(buf,1,128,fp);
	pclose(fp);
	sprintf(info_http_url,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.url.normal_url","r");
	if(NULL == fp){
		return -2;
	}
	fread(buf,1,128,fp);
	pclose(fp);

	sprintf(normal_http_url,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.rmflag.info_rmflag","r");
	if(NULL == fp){
		return -3;
	}
	fread(buf,1,128,fp);
	pclose(fp);

	sprintf(info_rmflag,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.rmflag.normal_rmflag","r");
	if(NULL == fp){
		return -4;
	}
	fread(buf,1,128,fp);
	pclose(fp);
	sprintf(normal_rmflag,"%s",buf);

	debug(LOG_INFO,"init result :info_url:%s;info_rmflag:%s;normal_url:%s;normal_rmflag:%s", \
			info_http_url,info_rmflag, \
			normal_http_url,normal_rmflag
			);

	return 0;
}




int post_get_info_execut_output(char *cmd_output_path)
{
	char output[MAX_CMD_EXECUT_OUT_LEN];
	FILE *fp;
	sprintf(output,"wget --post-data=\"$(cat %s)\" %s \n rm  -f ./%s",cmd_output_path,info_http_url,info_rmflag);
	fp = popen(output,"r");
	if(NULL == fp){
		debug(LOG_WARNING,"popen error,at int post_get_info_execut_output(char *cmd_output_path,char *http_url,char * rm_flag)");
		return -1;
	}
	pclose(fp);
	return 0;
}



int post_normal_execut_output(char *gw_id, char *cmd_id)
{
	char output[MAX_CMD_EXECUT_OUT_LEN];
	FILE *fp;

	sprintf(output,"wget --post-data=\"{\\\"gw_id\\\":\\\"%s\\\","
			                          "\\\"cmd_id\\\":\\\"%s\\\","
			                          "\\\"type\\\":\\\"normal\\\","
			                          "\\\"message\\\":$(%s)}\"  %s \n rm ./%s",
				                       gw_id,cmd_id,
									   BUILE_NORMAL_CMD_RESULT_SHELL,
									   normal_http_url,
									   normal_rmflag
		   );
	debug(LOG_INFO,"output_normal:--> %s",output);
	fp = popen(output,"r");
	if(NULL == fp){
		debug(LOG_WARNING,"popen error,at int post_nomal_execut_output(char *post_data,char *http_url,char *rm_flag)");
		return -1;
	}
	pclose(fp);
	return 0;
}


char *get_shell_command(char *cmdptr)
{

	if(NULL == cmdptr){
		debug(LOG_WARNING,"REMOTE shell: remote shell command is null.");
		return NULL;
	}
	memset(remote_shell_cmd,0,REMOTE_SHELL_COMMAND_LEN);
	sprintf(remote_shell_cmd,"%s",cmdptr);

	return remote_shell_cmd;
}



int excute_shell_command(char *gw_id,char *shellcmd)
{
	FILE *fp;

	char cmd_id[512],
		 get_info_cmd[512],
		 normal_cmd[MAX_CMD_EXECUT_OUT_LEN],
		 cmdresult[1024];

	char *pos_id,
		 *pos_cmd;

	int   is_get_info = 0;

	memset(cmdresult,0,1024);
	memset(cmd_id,0,512);
	memset(get_info_cmd,0,512);

	pos_id = shellcmd;
	pos_cmd = strstr(shellcmd,"|");

	snprintf(cmd_id,++pos_cmd - pos_id - 1,"%s",++pos_id);

	pos_cmd = ++pos_cmd;

	snprintf(get_info_cmd,30,"%s",pos_cmd);

	is_get_info = strcmp(get_info_cmd,GET_SETTINGS_INFO_CMD";");

	debug(LOG_INFO,"cmd_id:%s,get_inf_cmd:%s,is_get_info cmp:%d",cmd_id,get_info_cmd,is_get_info);

	if(0 == is_get_info){
		get_info_cmd[strlen(get_info_cmd) - 1] = 0;// delete the semicolon it at the tail
		sprintf(get_info_cmd,"%s %s %s",get_info_cmd,gw_id,cmd_id);/* add gw_id and cmd_id to the command as
		                                                               the parameter of the command */
		fp = popen(get_info_cmd,"r");
	}else{
		/* if the command is a normal command,just do it.
		 * */
	  sprintf(normal_cmd,"RESULT=\"$(%s)\";echo \"$RESULT\" > "NORMAL_CMD_RESULT_FILE,pos_cmd);
	  fp = popen(normal_cmd,"r");
	}

	debug(LOG_INFO,"pos_cmd:%s",pos_cmd);

	if(NULL == fp){
		debug(LOG_WARNING,"excute_shell_command popen error....");
		return -1;
	}

	pclose(fp);

	if(0 == is_get_info){
		post_get_info_execut_output(SETTINGS_INFO_FILE);

	}else{

		post_normal_execut_output(gw_id,cmd_id);
	}
	return 0;
}



/**
 * the global device key char array.
 * */
static char device_key[64] = {0};


/* @breif get the global device key.the key will be use as auth key
 * @PARAMETER: void
 * @RETURN_VALUE: a none NULL char pointer
 * GaomingPan lonely-test:yes
 * */
char * get_device_key()
{
	return device_key;
}




/* @breif get the device key from a configure file
 * @PARAMETER: void
 * @RETURN_VALUE: success return zero and set the KEY in the device key global array,
 * failed return a none zero number.
 * GaomingPan lonely-test:yes
 * */
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

/*=============================================================*/
