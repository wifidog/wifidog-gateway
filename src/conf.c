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
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <string.h>

#include "common.h"

#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oExternalInterface,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthServer,
	oAuthservPath,
	oAuthservLoginUrl,
	oHTTPDMaxConn,
	oHTTPDName,
	oClientTimeout,
	oCheckInterval,
	oWdctlSocket,
	oSyslogFacility
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "daemon",             oDaemon },
	{ "debuglevel",         oDebugLevel },
	{ "externalinterface",  oExternalInterface },
	{ "gatewayid",          oGatewayID },
	{ "gatewayinterface",   oGatewayInterface },
	{ "gatewayaddress",     oGatewayAddress },
	{ "gatewayport",        oGatewayPort },
	{ "authserver",         oAuthServer },
	{ "authservpath",       oAuthservPath },
	{ "authservloginurl",   oAuthservLoginUrl },
	{ "httpdmaxconn",       oHTTPDMaxConn },
	{ "httpdname",          oHTTPDName },
	{ "clienttimeout",      oClientTimeout },
	{ "checkinterval",      oCheckInterval },
	{ "syslogfacility", 	oSyslogFacility },
	{ "wdctlsocket", 	oWdctlSocket },
	{ NULL,                 oBadOption },
};

static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);
static void config_notnull(void *parm, char *parmname);
static int parse_boolean_value(char *);
static void new_auth_server(char *, int);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
	config.external_interface = NULL;
	config.gw_id = DEFAULT_GATEWAYID;
	config.gw_interface = NULL;
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.auth_servers = NULL;
	config.authserv_path = strdup(DEFAULT_AUTHSERVPATH);
	config.authserv_loginurl = NULL;
	config.httpdname = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.daemon = -1;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.wdctl_sock = strdup(DEFAULT_WDCTL_SOCK);
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", 
			filename, linenum, cp);
	return oBadOption;
}

/**
@param filename Full path of the configuration file to be read 
*/
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
				opcode = config_parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oExternalInterface:
					config.external_interface = strdup(p1);
					break;
				case oGatewayID:
					config.gw_id = strdup(p1);
					break;
				case oGatewayInterface:
					config.gw_interface = strdup(p1);
					break;
				case oGatewayAddress:
					config.gw_address = strdup(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthServer:
					/* Check for the presence of more then
					 * one argument. */
					if (p2 != NULL && (*(p2 + 1) != '\n')
						       && (*(p2 + 1) != '\0')) {
						p2++;
						new_auth_server(p1, atoi(p2));
					} else {
						new_auth_server(p1, DEFAULT_AUTHSERVPORT);
					}
					break;
				case oHTTPDName:
					config.httpdname = strdup(p1);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oAuthservPath:
					free(config.authserv_path);
					config.authserv_path = strdup(p1);
					break;
				case oAuthservLoginUrl:
					config.authserv_loginurl = strdup(p1);
					break;
				case oBadOption:
                    debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oWdctlSocket:
					free(config.wdctl_sock);
					config.wdctl_sock = strdup(p1);
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

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
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

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.external_interface, "ExternalInterface");
	config_notnull(config.gw_id, "GatewayID");
	config_notnull(config.gw_interface, "GatewayInterface");
	config_notnull(config.gw_address, "GatewayAddress");
	config_notnull(config.auth_servers, "AuthServer");
	config_notnull(config.authserv_loginurl, "AuthservLoginUrl");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(void *parm, char *parmname)
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

/** @internal
    Register a new auth server.
*/
static void
new_auth_server(char *host, int port)
{
	t_auth_serv	*new, *tmp;

	debug(LOG_DEBUG, "Adding %s:%d to the auth server list", host, port);

	/* Allocate memory */
	new = (t_auth_serv *)malloc(sizeof(t_auth_serv));
	if (new == NULL) {
		debug(LOG_ERR, "Could not allocate memory for auth server "
				"configuration");
		exit(1);
	}
	
	/* Fill in struct */
	new->authserv_hostname = strdup(host);
	new->authserv_port = port;
	new->next = NULL;
	
	/* If it's the first, add to config, else append to last server */
	if (config.auth_servers == NULL) {
		config.auth_servers = new;
	} else {
		for (tmp = config.auth_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}
	
	debug(LOG_DEBUG, "Auth server added");
}
