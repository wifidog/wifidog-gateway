/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Header$ */
/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

void config_init(void);
void config_init_override(void);
void config_read(char *filename);
void config_validate(void);
void config_notnull(void *parm, char *parmname);
int parse_value(char *);
char *get_string(char *ptr);

typedef struct {
    char *configfile;
    int daemon;
    int debuglevel;
    char *gw_id;
    char *gw_interface;
    char *gw_address;
    int gw_port;
    char *authserv_hostname;
    int authserv_port;
    char *authserv_path;
    char *authserv_loginurl;
    char *httpdname;
    int httpdmaxconn;
    int clienttimeout;
    int checkinterval;
    char *fwscripts_path;
    char *fwtype;
    int log_syslog;
    int syslog_facility;
} s_config;

#endif /* _CONFIG_H_ */
