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

/* Defaults for configuration values */
#define DEFAULT_CONFIGFILE "/etc/wifidog.conf"
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_HTTPDMAXCONN 10
#define DEFAULT_GATEWAYID "default"
#define DEFAULT_GATEWAYPORT 2060
#define DEFAULT_AUTHSERVPORT 80
#define DEFAULT_HTTPDNAME "WiFiDog"
#define DEFAULT_CLIENTTIMEOUT 5
#define DEFAULT_CHECKINTERVAL 5
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON

void config_init(void);
void config_init_override(void);
void config_read(char *filename);
void config_validate(void);

/**
 * Configuration structure
 */
typedef struct {
    char configfile[255];	/**< name of the config file */
    int daemon;			/**< if daemon > 0, use daemon mode */
    int debuglevel;		/**< Debug information verbosity */
    char *external_interface;	/**< External network interface name for
				     firewall rules */
    char *gw_id;		/**< ID of the Gateway, sent to central
				     server */
    char *gw_interface;		/**< Interface we will accept connections on */
    char *gw_address;		/**< Internal IP address for our web
				     server */
    int gw_port;		/**< Port the webserver will run on */
    char *authserv_hostname;	/**< Hostname of the central server */
    int authserv_port;		/**< Port the central server listens on */
    char *authserv_path;	/**< Path to the authentication script on
				     the central server */
    char *authserv_loginurl;	/**< Full URL to the login page */
    char *httpdname;		/**< Name the web server will return when
				     replying to a request */
    int httpdmaxconn;		/**< Used by libhttpd, not sure what it
				     does */
    int clienttimeout;		/**< How many CheckIntervals before a client
				     must be re-authenticated */
    int checkinterval;		/**< Frequency the the client timeout check
				     thread will run. */
    int log_syslog;		/**< boolean, wether to log to syslog */
    int syslog_facility;	/**< facility to use when using syslog for
				     logging */
} s_config;

#endif /* _CONFIG_H_ */
