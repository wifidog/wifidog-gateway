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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"

#include "util.h"

#include "../config.h"

extern pthread_mutex_t	client_list_mutex;

void
http_callback_404(httpd *webserver, request *r)
{
	char		*newlocation,
			protocol[6],
			tmp_url[MAX_BUF],
			*url;
	int		port;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		strcpy(protocol, "https");
		port = auth_server->authserv_ssl_port;
	} else {
		strcpy(protocol, "http");
		port = auth_server->authserv_http_port;
	}

	memset(tmp_url, 0, sizeof(tmp_url));
	snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s",
			r->request.host,
			r->request.path);
	url = httpdUrlEncode(tmp_url);
	
	if (!is_online()) {
		/* No point re-directing them to the auth server if we haven't been able to talk
		 * to it for a while */
		httpdOutput(r, "<html><head><title>Currently unavailable</title></head><body><h1>Uh oh!</h1>");
		httpdOutput(r, "We apologize, but it seems that we are currently unable to re-direct you to the login screen.");
		httpdOutput(r, "<p>");
		httpdOutput(r, "The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.");
		httpdOutput(r, "<p>");
		httpdPrintf(r, "In a while please <a href='%s'>click here</a> to try again.", tmp_url);
		httpdOutput(r, "</body></html>");
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else {
		/* Re-direct them to auth server */
		safe_asprintf(&newlocation, "Location: %s://%s:%d%slogin?gw_address=%s&gw_port=%d&gw_id=%s&url=%s",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path,
			config->gw_address,
			config->gw_port, 
			config->gw_id,
			url);
		httpdSetResponse(r, "307 Please authenticate yourself here\n");
		httpdAddHeader(r, newlocation);
		httpdPrintf(r, "<html><head><title>Redirection</title></head><body>"
				"Please <a href='%s://%s:%d%slogin?gw_address"
				"=%s&gw_port=%d&gw_id=%s&url=%s'>click here</a> to "
				"login",
				protocol,
				auth_server->authserv_hostname,
				port,
				auth_server->authserv_path,
				config->gw_address, 
				config->gw_port,
				config->gw_id,
				url);
		debug(LOG_INFO, "Captured %s and re-directed them to login "
			"page", r->clientAddr);
		free(newlocation);
	}

	free(url);
}

void 
http_callback_about(httpd *webserver, request *r)
{
	httpdOutput(r, "<html><head><title>About WiFiDog</title></head><body><h1>About WiFiDog:</h1>");
	httpdOutput(r, "This is WiFiDog version <b>" VERSION "</b>");
	httpdOutput(r, "<p>");
	httpdOutput(r, "Copyright (C) 2004-2005.  This software is released under the GNU GPL license.");
	httpdOutput(r, "<p>");
	httpdOutput(r, "For more information visit <a href='http://"
			"www.ilesansfil.org/wiki/WiFiDog'>http://www."
			"ilesansfil.org/wiki/WiFiDog</a>");
	httpdOutput(r, "</body></html>");
}

void 
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;

	if ((token = httpdGetVariableByName(r, "token"))) {
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for "
				"ip %s", r->clientAddr);
			httpdOutput(r, "Failed to retrieve your MAC "
					"address");
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s",
					r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);
			} else {
				debug(LOG_DEBUG, "Node for %s already "
					"exists", client->ip);
			}

			UNLOCK_CLIENT_LIST();

			authenticate_client(r);
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		httpdOutput(r, "Invalid token");
	}
}
