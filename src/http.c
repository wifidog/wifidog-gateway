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

#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"

extern pthread_mutex_t	client_list_mutex;

void
http_callback_404(httpd * webserver)
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
			webserver->request.host,
			webserver->request.path);
	url = httpdUrlEncode(tmp_url);
	
	if ((asprintf(&newlocation, "Location: %s://%s:%d%s/login?"
			"gw_address=%s&gw_port=%d&gw_id=%s&url=%s",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path,
			config->gw_address, config->gw_port, 
			config->gw_id,
			url)) == -1) {
		debug(LOG_ERR, "Failed to asprintf newlocation");
		free(url);
		free(newlocation);
		httpdOutput(webserver, "Internal error occurred");
	} else {
		/* Re-direct them to auth server */
		httpdSetResponse(webserver, "307 Please authenticate yourself here");
		httpdAddHeader(webserver, newlocation);
		httpdPrintf(webserver, "<html><head><title>Redirection</title></head><body>"
				"Please <a href='%s://%s:%d%s/login?gw_address"
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
			"page", webserver->clientAddr);
		free(url);
		free(newlocation);
	}
}

void 
http_callback_about(httpd * webserver)
{
	httpdOutput(webserver, "<html><body><h1>About:</h1>");
	httpdOutput(webserver, "This is WiFiDog. Copyright (C) 2004 and "
			"released under the GNU GPL license.");
	httpdOutput(webserver, "<p>");
	httpdOutput(webserver, "For more information visit <a href='http://"
			"www.ilesansfil.org/wiki/WiFiDog'>http://www."
			"ilesansfil.org/wiki/WiFiDog</a>");
	httpdOutput(webserver, "</body></html>");
}

void 
http_callback_auth(httpd * webserver)
{
	t_client	*client;
	httpVar * token;
	char	*mac,
		*ip;
	pthread_t tid;

	if ((token = httpdGetVariableByName(webserver, "token"))) {
		/* They supplied variable "token" */
		if (!(mac = arp_get(webserver->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for "
				"ip %s", webserver->clientAddr);
			httpdOutput(webserver, "Failed to retrieve your MAC "
					"address");
		} else {
			/* We have their MAC address */

			pthread_mutex_lock(&client_list_mutex);
			
			if ((client = client_list_find(webserver->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s",
					webserver->clientAddr);
				client_list_append(webserver->clientAddr, mac, token->value);
			} else {
				debug(LOG_DEBUG, "Node for %s already "
					"exists", client->ip);
			}

			client = client_list_find(webserver->clientAddr, mac);

			client->fd = webserver->clientSock;
			webserver->clientSock = -1;

			pthread_mutex_unlock(&client_list_mutex);

			/* That clientAddr may be freed prior to the thread
			 * finishing. XXX The duplicated string will be freed
			 * by the thread */
			ip = strdup(webserver->clientAddr);
			
			/* start sub process */
			pthread_create(&tid, NULL, (void *)thread_authenticate_client, (void *)ip);
			pthread_detach(tid);

			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		httpdOutput(webserver, "Invalid token");
	}
}
