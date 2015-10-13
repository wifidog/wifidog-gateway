/*
 * get_devinfo.h
 *
 *  Created on: Jul 9, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_GET_DEVINFO_H_
#define SRC_GET_DEVINFO_H_

#define DEV_MAC_ADDR_LEN     18
#define DEV_SSID_NAME_LEN    20
#define DEV_DOG_VERSION_LEN  20
#define DEV_WAN_IP_LEN       16
#define DEV_IFNAME_LEN       11

#define IFACE_DATA_FILE   "/tmp/iface-data"


#define	CPU_USER     1
#define	CPU_SYS      3
#define	CPU_NIC      5
#define	CPU_IDLE     7
#define	CPU_IO       9
#define	CPU_IRQ      11
#define	CPU_SIRQ     13
#define CPU_LOAD     16




/*@ breif a struct hold information for ap*/
typedef struct _t_devinfo{
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
}t_devinfo;



typedef struct _t_cpuuse{
	char use_info[15][8];
}t_cpuuse;


t_devinfo *get_devinfo(void);

/* @breif get wireless ssid,based on uci command.
 * @PARAMETER: [char *ssid]:the char pointer for save the ssid.
 * @RETURN_VALUE: zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_devssid(char *ssid);

/* @breif get wifidog version
 * @PARAMETER:[char *dogversion]:the char pointer for save the version
 * @RETURN_VALUE:always return zero
 * GaomingPan lonely-test:no
 * */
int get_dogversion(char *dogversion);


/* @breif get wan interface ip,based on uci command.
 * @PARAMETER:[char *wanip]:the char pointer for save the wan ip
 * @RETURN_VALUE:always zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_wanip(char *wanip);

/* @breif get ap mac address,based on uci command.
 * @PARAMETER:[char *apmac]:the char pointer for save the mac
 * @RETURN_VALUE:always zero is success,others is failed.
 * GaomingPan lonely-test:yes
 * */
int get_apmac(char *apmac);

/* @breif get number of client
 * @PARAMETER:none
 * @RETURN_VALUE:the number of current connected client
 * GaomingPan lonely-test:no
 * */
int get_curconn(void);


/* @breif get number of client who connect to the device
 * @PARAMETER:none
 * @RETURN_VALUE:the number of connected client
 * GaomingPan lonely-test:no
 * */
int get_devconn(void);

/* @breif get cpu use infomation,based on shell command
 * @PARAMETER:[int type] CPU_USER,CPU_SYS,CPU_NIC,CPU_IDLE,CPU_IO,CPU_IRQ,CPU_SIRQ,CPU_LOAD
 * @RETURN_VALUE:the number of current percent of CPU use.
 * GaomingPan lonely-test:yes
 * */
int get_cpuuse(int type);


/* @breif get wan interface speed,based on shell command.
 * @PARAMETER:[int *go,int *come],the pointer for save outgo speed and income speed.
 * @RETURN_VALUE:zero is success,others is error.
 * GaomingPan lonely-test:yes
 * */
int get_wanbps(unsigned int *go,unsigned int *come);


/* @breif get wan interface traffic,based on shell command.
 * @PARAMETER:[long *outgo,long *income],the pointer for save outgo-data and income-data.
 * @RETURN_VALUE:zero is success,others is error.
 * GaomingPan lonely-test:yes
 * */
int get_trafficCount(char *iface_name,unsigned long long *income,unsigned long long *outgo,unsigned int *rx_rate,unsigned int *tx_rate);


#endif /* SRC_GET_DEVINFO_H_ */
