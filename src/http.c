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
  @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include "common.h"

extern s_config config;

void
http_callback_404(httpd * webserver)
{
	char *newlocation;

	if (asprintf(&newlocation, "Location: %s?gw_address=%s&gw_port=%d&"
			"gw_id=%s", config.authserv_loginurl, 
			config.gw_address, config.gw_port, 
			config.gw_id) == -1) {
		debug(D_LOG_ERR, "Failed to asprintf newlocation");
		httpdOutput(webserver, "Internal error occurred");
	} else {
		// Re-direct them to auth server
		httpdSetResponse(webserver, "307 Please authenticate yourself here");
		httpdAddHeader(webserver, newlocation);
		httpdPrintf(webserver, "<html><head>Redirection</head><body>"
				"Please <a href='%s?gw_address=%s&gw_port=%d"
				"&gw_id=%s'>click here</a> to login", 
				config.authserv_loginurl, config.gw_address, 
				config.gw_port, config.gw_id);
		debug(D_LOG_INFO, "Captured %s and re-directed them to login "
			"page", webserver->clientAddr);
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
	t_node	*node;
	httpVar * token;
	char * mac;
	int profile;
	int temp;
	pthread_t tid;

	if (token = httpdGetVariableByName(webserver, "token")) {
		// They supplied variable "token"
		if (!(mac = arp_get(webserver->clientAddr))) {
			// We could not get their MAC address
			debug(D_LOG_ERR, "Failed to retrieve MAC address for "
				"ip %s", webserver->clientAddr);
			httpdOutput(webserver, "Failed to retrieve your MAC "
					"address");
		} else {
			// We have their MAC address

			if ((node = node_find_by_ip(webserver->clientAddr))
					== NULL) {
				debug(D_LOG_DEBUG, "New node for %s",
					webserver->clientAddr);
				node_add(webserver->clientAddr, mac,
					token->value, 0, 0);
			} else {
				debug(D_LOG_DEBUG, "Node for %s already "
					"exists", node->ip);
				if (node->rights != NULL) {
					/* log off if logged in */
					debug(D_LOG_DEBUG, "Logging off %s "
						"because they tried a new "
						"token", node->ip);
					fw_deny(node->ip, node->mac,
						node->rights->profile);
				}
			}

			node = node_find_by_ip(webserver->clientAddr);

			node->fd = webserver->clientSock;
			webserver->clientSock = -1;

			/* start sub process */
			pthread_create(&tid, NULL, (void *)auth_thread,
					(void *)node);
			pthread_detach(tid);

			free(mac);
		}
	} else {
		// They did not supply variable "token"
		httpdOutput(webserver, "Invalid token");
	}
}
