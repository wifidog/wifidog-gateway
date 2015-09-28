/*
 * get_remote_shell.h
 *
 *  Created on: Jul 14, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_GET_REMOTE_SHELL_H_
#define SRC_GET_REMOTE_SHELL_H_

#define GET_SETTINGS_INFO_CMD        "GET_settings"

#define SETTINGS_INFO_FILE           "/tmp/routersettings"

#define NORMAL_CMD_RESULT_FILE       "/tmp/.normal_cmd_result"

#define BUILE_NORMAL_CMD_RESULT_SHELL  "result=\"\";while read line;do result=\"\\\"$result$line\\\",\";done < "NORMAL_CMD_RESULT_FILE";result=${result%,};echo $result"


#define  REMOTE_SHELL_COMMAND_LEN    1024
#define  MAX_CMD_EXECUT_OUT_LEN      4096

char *get_shell_command(char *cmdptr);

int excute_shell_command(char *gw_id,char *shellcmd);

int post_get_info_execut_output(char *cmd_output_path);

int post_normal_execut_output(char *gw_id, char *cmd_id);

int init_post_http_url_config(void);

#endif /* SRC_GET_REMOTE_SHELL_H_ */


