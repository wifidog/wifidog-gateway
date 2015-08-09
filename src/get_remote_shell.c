/*
 * get_remote_shell.c
 *
 *  Created on: Jul 14, 2015
 *      Author: GaomingPan
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"

#include "get_remote_shell.h"



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
	if(NULL == fp)
	{
		return -1;
	}
	fread(buf,1,128,fp);
	pclose(fp);
	sprintf(info_http_url,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.url.normal_url","r");
	if(NULL == fp)
	{
		return -2;
	}
	fread(buf,1,128,fp);
	pclose(fp);

	sprintf(normal_http_url,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.rmflag.info_rmflag","r");
	if(NULL == fp)
	{
		return -3;
	}
	fread(buf,1,128,fp);
	pclose(fp);

	sprintf(info_rmflag,"%s",buf);
	memset(buf,0,128);

	fp = popen("uci get dog_post_conf.rmflag.normal_rmflag","r");
	if(NULL == fp)
	{
		return -4;
	}
	fread(buf,1,128,fp);
	pclose(fp);
	sprintf(normal_rmflag,"%s",buf);

	printf("\ninit result:\n\t%s\n\t%s\n\t%s\n\t%\n\n", \
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
	printf("\npath:%s\nurl:%s\nrmflag:%s\n\n",cmd_output_path,info_http_url,info_rmflag);
	fp = popen(output,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"popen error,at int post_get_info_execut_output(char *cmd_output_path,char *http_url,char * rm_flag)");
		printf("ERROR: popen error,at int post_get_info_execut_output(char *cmd_output_path,char *http_url,char * rm_flag)\n");
		return -1;
	}
	pclose(fp);
	return 0;
}



int post_normal_execut_output(char *gw_id, char *cmd_id)
{
	char output[MAX_CMD_EXECUT_OUT_LEN];
	FILE *fp;

	sprintf(output,"wget --post-data=\"{\\\"gw_id\\\":\\\"%s\\\",\\\"cmd_id\\\":\\\"%s\\\",\\\"message\\\":[$(%s)]}\"  %s \n rm ./%s", \
			gw_id,cmd_id,BUILE_NORMAL_CMD_RESULT_SHELL,normal_http_url,normal_rmflag);
	debug(LOG_INFO,"output_normal:--> %s",output);
	fp = popen(output,"r");
	if(NULL == fp)
	{
		debug(LOG_ERR,"popen error,at int post_nomal_execut_output(char *post_data,char *http_url,char *rm_flag)");
		printf("ERROR: popen error,at int post_nomal_execut_output(char *post_data,char *http_url,char *rm_flag)\n");
		return -1;
	}
	pclose(fp);
	return 0;
}






char *get_shell_command(char *cmdptr)
{

	if(NULL == cmdptr)
	{
		printf("REMOTE shell: remote shell command is null.\n");
		return NULL;
	}
	memset(remote_shell_cmd,0,REMOTE_SHELL_COMMAND_LEN);
	sprintf(remote_shell_cmd,"%s",cmdptr);

	return remote_shell_cmd;
}




int excute_shell_command(char *gw_id,char *shellcmd)
{
	char cmd_id[20],
		 get_info_cmd[30],
		 normal_cmd[MAX_CMD_EXECUT_OUT_LEN];
	char *pos_id,
		 *pos_cmd;
	int   is_get_info = 0;
	FILE *fp;
	char cmdresult[1024];

	memset(cmdresult,0,1024);
	memset(cmd_id,0,20);
	memset(get_info_cmd,0,30);

	pos_id = shellcmd;
	pos_cmd = strstr(shellcmd,"|");

	snprintf(cmd_id,++pos_cmd - pos_id - 1,"%s",++pos_id);

	pos_cmd = ++pos_cmd;

	snprintf(get_info_cmd,30,"%s",pos_cmd);

	is_get_info = strcmp(get_info_cmd,GET_SETTINGS_INFO_CMD);

	printf("\ncmd_id:%s\nget_inf_cmd:%s\nis_get_info:%d\n\n",cmd_id,get_info_cmd,is_get_info);

	if(0 == is_get_info)
	{
		sprintf(get_info_cmd,"%s %s %s",get_info_cmd,gw_id,cmd_id);
		fp = popen(get_info_cmd,"r");
	}
	else
	{
	  sprintf(normal_cmd,"echo \"\" > "NORMAL_CMD_RESULT_FILE"RESULT=\"$(%s)\";echo \"$RESULT\" >> "NORMAL_CMD_RESULT_FILE,pos_cmd);
	  fp = popen(normal_cmd,"r");
	}

	printf("\npos_cmd:\n\t%s\n\n",pos_cmd);

	if(NULL == fp)
	{
		printf("excute_shell_command popen error....\n");
		return -1;
	}
	//fread(cmdresult,1024,1,fp);
	pclose(fp);
	//printf("\n\ncmd result:\n %s\n\n",cmdresult);

	if(0 == is_get_info)
	{
		post_get_info_execut_output(SETTINGS_INFO_FILE);

	}else{

		post_normal_execut_output(gw_id,cmd_id);
	}
	return 0;
}


