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
/** @internal
  @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */
#include "common.h"

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

s_config config;
int missing_parms;

typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthservHostname,
	oAuthservPort,
	oAuthservPath,
	oAuthservLoginUrl,
	oHTTPDMaxConn,
	oHTTPDName,
	oClientTimeout,
	oCheckInterval,
    oSyslogFacility
} OpCodes;

struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "daemon",             oDaemon },
	{ "debuglevel",         oDebugLevel },
	{ "gatewayid",          oGatewayID },
	{ "gatewayinterface",   oGatewayInterface },
	{ "gatewayaddress",     oGatewayAddress },
	{ "gatewayport",        oGatewayPort },
	{ "authservhostname",   oAuthservHostname },
	{ "authservport",       oAuthservPort },
	{ "authservpath",       oAuthservPath },
	{ "authservloginurl",   oAuthservLoginUrl },
	{ "httpdmaxconn",       oHTTPDMaxConn },
	{ "httpdname",          oHTTPDName },
	{ "clienttimeout",      oClientTimeout },
	{ "checkinterval",      oCheckInterval },
	{ "syslogfacility", 	oSyslogFacility },
	{ NULL,                 oBadOption },
};

void
config_init(void)
{
	debug(LOG_DEBUG, "Setting default config parameters");
	config.configfile = (char *)malloc(255);
	strcpy(config.configfile, DEFAULT_CONFIGFILE);
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
	config.gw_id = DEFAULT_GATEWAYID;
	config.gw_interface = NULL;
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.authserv_hostname = NULL;
	config.authserv_port = DEFAULT_AUTHSERVPORT;
	config.authserv_path = NULL;
	config.authserv_loginurl = NULL;
	config.httpdname = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
    config.daemon = -1;
    config.log_syslog = DEFAULT_LOG_SYSLOG;
}

/**
 * @brief Initialize the variables we override with the command line
 *
 *
 * Initialize the variables we override with the command line after the config has been read
 * if they haven't been initialized by the configuration file
 */
void
config_init_override(void)
{
    if (!config.daemon) config.daemon = DEFAULT_DAEMON;
}

OpCodes
parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", 
			filename, linenum, cp);
	return oBadOption;
}

void
config_read(char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, ' '))) {
			p1[0] = '\0';
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';
		}

		if (p1) {
			p1++;

			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else if ((p2 = strstr(p1, "\r\n"))) {
				p2[0] = '\0';
			} else if ((p2 = strchr(p1, '\n'))) {
				p2[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */
			/* Strip tailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oGatewayID:
					config.gw_id = get_string(p1);
					break;
				case oGatewayInterface:
					config.gw_interface = get_string(p1);
					break;
				case oGatewayAddress:
					config.gw_address = get_string(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthservHostname:
					config.authserv_hostname = 
						get_string(p1);
					break;
				case oHTTPDName:
					config.httpdname = get_string(p1);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oAuthservPath:
					config.authserv_path = get_string(p1);
					break;
				case oAuthservLoginUrl:
					config.authserv_loginurl = 
						get_string(p1);
					break;
				case oBadOption:
                    debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oClientTimeout:
					sscanf(p1, "%d", &config.clienttimeout);
					break;
                case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				}
			}
		}
	}

	fclose(fd);
}

int
parse_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}

char *
get_string(char *ptr)
{
	char *buf;

	buf = strdup(ptr);
	return buf;
}

void
config_validate(void)
{
	config_notnull(config.gw_id, "GatewayID");
	config_notnull(config.gw_interface, "GatewayInterface");
	config_notnull(config.gw_address, "GatewayAddress");
	config_notnull(config.authserv_hostname, "AuthservHostname");
	config_notnull(config.authserv_path, "AuthservPath");
	config_notnull(config.authserv_loginurl, "AuthservLoginUrl");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

void
config_notnull(void *parm, char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

