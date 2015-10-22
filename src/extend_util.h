/*
 * extend_util.h
 *
 *  Created on: Oct 10, 2015
 *      Author: GaomingPan
 */

#ifndef _EXTEND_UTIL_H_
#define _EXTEND_UTIL_H_

/**
 * @ breif a internal struct hold information for ap
 * */
#define DEV_MAC_ADDR_LEN     18
#define DEV_SSID_NAME_LEN    20
#define DEV_DOG_VERSION_LEN  20
#define DEV_WAN_IP_LEN       16
struct _t_devinfo{
	char gw_mac[DEV_MAC_ADDR_LEN];          // ap mac address
	char gw_ssid[DEV_SSID_NAME_LEN];        // ap wireless ssid
	char dog_version[DEV_DOG_VERSION_LEN];  // wifidog version,private.
	char wan_ip[DEV_WAN_IP_LEN];            // ap's wan interface ip
	int  cur_conn;                          // number of current connection client
	int  dev_conn;							// number of connection in the device,maybe some has no authentication.
	int  cpu_use;                          // percent of use CPU
	unsigned int  go_speed;                 // wan interface go out speed
	unsigned int  come_speed;              // wan interface come in speed
	unsigned long long incoming;           // wan interface incoming bytes
	unsigned long long outgoing;            // wan interface outgoing bytes
};

/**
 * @breif a internal sturct for client_info list
 * */
#define  CLIENT_HOST_NAME_LEN     40
#define  CLIENT_MAC_ADDRESS_LEN   18
#define  CLIENT_IP_ADDRESS_LEN    16
struct _t_clientinfo{

	char client_mac[CLIENT_MAC_ADDRESS_LEN];
	char client_ip[CLIENT_IP_ADDRESS_LEN];
	char host_name[CLIENT_HOST_NAME_LEN];
	int  go_speed;
	int  come_speed;
	struct _t_clientinfo *next;

};
typedef struct _t_clientinfo            t_clientinfo;
typedef struct _t_devinfo               t_devinfo;

/*=============================================================*/
/**
 * This part is get the device information functions,
 * and some Macro defines.
 * */

/**
 * @brief this function collect the gateway device information.
 * @returnValue a type pointer of t_devinfo
 * */
t_devinfo *get_devinfo(void);

/**
 * @brief get wireless ssid,based on uci command.
 * @param ssid: the char pointer for save the ssid.
 * @return value: zero is success,others is failed.
 * */
int get_devssid(char *ssid);

/**
 * @breif get wifidog version
 * @param dogversion:the char pointer for save the version
 * @return value:always return zero
 * */
int get_dogversion(char *dogversion);


/**
 * @breif get wan interface ip,based on uci command.
 * @param wanip:the char pointer for save the wan ip
 * @return value:always zero is success,others is failed.
 * */
int get_wanip(char *wanip);

/**
 * @breif get ap mac address,based on uci command.
 * @param apmac:the char pointer for save the mac
 * @return value:zero is success,others is failed.
 * */
int get_apmac(char *apmac);

/**
 * @breif get number of client it in the client list
 * @return value:the number of current connected client
 * */
int get_curconn(void);


/**
 * @breif get number of client who connect to the device
 * @return value:the number of connected client
 * */
int get_devconn(void);


/**
 * @breif get cpu use infomation,based on shell command
 * @param type: CPU_USER,CPU_SYS,CPU_NIC,CPU_IDLE,CPU_IO,CPU_IRQ,CPU_SIRQ,CPU_LOAD
 * @return value:the number of current percent of CPU use.
 * */
int get_cpuuse(int type);


/**
 * @breif get wan interface speed,based on shell command.
 * @param go:the pointer for save out rate
 * @param come:the pointer for save income rate.
 * @return value:zero is success,others is error.
 * */
int get_wanbps(unsigned int *go,unsigned int *come);


/**
 * @breif get wan interface traffic,based on shell command.
 * @param iface_name: interface name
 * @param income: interface incoming
 * @param outgo: interface outgoing
 * @param rx_rate: interface RX rate
 * @param tx_rate: interface TX rate
 * @return value:zero is success,others is error
 * */
int get_trafficCount(char *iface_name,unsigned long long *income,unsigned long long *outgo,unsigned int *rx_rate,unsigned int *tx_rate);

/*=============================================================*/


/*=============================================================*/
/**
 * This part is get the client's information functions,
 * and some Macro defines.
 * */


/**
 * @breif get client host name,income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @return value: zero is success,others is error.
 * @Note: after this function be called and you get some clients information,you should
 *        call clean_client_info() function to clean up,just like the fopen() and fclose().
 * */
int collect_client_info();


/**
 * @breif get unknown host name client's income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @param client_ip: the unknown host name client's ip.
 * @param go_speed: the pointer for client's outgoing speed to store.
 * @param come_speed: the pointer for client's incoming speed to store.
 * @return value: zero is success,others is error.
 * */
int get_unknown_client_speed(const char *client_ip,int *go_speed,int *come_speed);



/**
 *  @breif After the function collect_client_info() called,should call this function to
 *        clean up.
 * @return value: the count number of clean
 * */
int clean_client_info();


/**
 * @breif find the element from the client_info list by mac.
 * @param mac: the pointer point to by mac.
 * @return value: success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * */
t_clientinfo * get_client_info_by_mac(const char *mac);


/**
 * @breif find the element from the client_info list by ip.
 * @param ip: the pointer point to by ip.
 * @return value: success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * */
t_clientinfo * get_client_info_by_ip(const char *ip);


/**
 * @breif find the element from the client_info list by ip.
 * @param ip: the pointer point to by client's ip.
 * @param mac: the pointer point to by client's mac.
 * */
long get_online_time(const char *ip,const char *mac);



/*
 * @breif get a flage string
 * */
char *get_client_auth_flag();


/*
 * @breif set a flage string
 * */
void set_client_auth_flag();

/*=============================================================*/


/*=============================================================*/
/**
 * This part is get the remote shell command functions,
 * and some Macro defines.
 * */


char *get_shell_command(char *cmdptr);

int excute_shell_command(char *gw_id,char *shellcmd);

int post_get_info_execut_output(char *cmd_output_path);

int post_normal_execut_output(char *gw_id, char *cmd_id);

int init_post_http_url_config(void);


/*=============================================================*/

/*=============================================================*/
/**
 * This part is get the remote shell command functions,
 * and some Macro defines.
 * */

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

#endif /* _EXTEND_UTIL_H_ */
