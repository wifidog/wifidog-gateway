/*
 * get_clientinfo.h
 *
 *  Created on: Jul 13, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_GET_CLIENTINFO_H_
#define SRC_GET_CLIENTINFO_H_


#define  CLIENT_HOST_NAME_LEN     40
#define  CLIENT_MAC_ADDRESS_LEN   18
#define  CLIENT_IP_ADDRESS_LEN    16

#define  UP_SPEED_FILE             "/tmp/client.up.speed"
#define  DOWN_SPEED_FILE           "/tmp/client.down.speed"


/*@breif the sturct for client_info list
 * */
typedef struct _t_clientinfo{

	char client_mac[CLIENT_MAC_ADDRESS_LEN];
	char client_ip[CLIENT_IP_ADDRESS_LEN];
	char host_name[CLIENT_HOST_NAME_LEN];
	int  go_speed;
	int  come_speed;
	struct _t_clientinfo *next;

} t_clientinfo;


/* @breif get client host name,income speed and outgo speed,based on shell command.
 *        this functions take at least 1 second to run,because of execute the shell
 *        command have to sleep 1 second to collect client speed.
 * @PARAMETER:void
 * @RETURN_VALUE:zero is success,others is error.
 * @Note: after this function be called and you get some clients information,you should
 *        call clean_client_info() function to clean up,just like the fopen() and fclose().
 * GaomingPan lonely-test:yes
 * */
int collect_client_info();


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
int get_unknown_client_speed(char *client_ip,int *go_speed,int *come_speed);



/* @breif After the function collect_client_info() called,should call this function to
 *        clean up.
 * @PARAMETER:void
 * @RETURN_VALUE:void
 * @Note: function collect_client_info() and this function just like the fopen() and fclose().
 * GaomingPan lonely-test:yes
 * */
void clean_client_info();


/* @breif find the element from the client_info list by mac.
 * @PARAMETER:[const char *mac],the pointer point to by mac.
 * @RETURN_VALUE:success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * GaomingPan lonely-test:yes
 * */
t_clientinfo * get_client_info_by_mac(const char *mac);


/* @breif find the element from the client_info list by ip.
 * @PARAMETER:[const char *ip],the pointer point to by ip.
 * @RETURN_VALUE:success return the t_clientinfo pointer that point to target element,
 *               fail return the NULL.
 * GaomingPan lonely-test:yes
 * */
t_clientinfo * get_client_info_by_ip(const char *ip);


long get_online_time(const char *ip,const char *mac);

/***
int clean_more_chain();
***/

char *get_client_auth_flag();

void set_client_auth_flag();


#endif /* SRC_GET_CLIENTINFO_H_ */




