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
		/* The internet connection is down at the moment  - apologize and do not redirect anywhere */
		httpdOutput(r, "<html><head><title>Internet access currently unavailable</title></head><body><h1>Uh oh!</h1>");
		httpdOutput(r, "We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.");
		httpdOutput(r, "<p>");
		httpdOutput(r, "If at all possible, please notify the owners of this hotspot that the internet connection is out of service.");
		httpdOutput(r, "<p>");
		httpdOutput(r, "The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.");
		httpdOutput(r, "<p>");
		httpdPrintf(r, "In a while please <a href='%s'>click here</a> to try your request again.", tmp_url);
		httpdOutput(r, "</body></html>");
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else if (!is_auth_online()) {
		/* The auth server is down at the moment - apologize and do not redirect anywhere */
		httpdOutput(r, "<html><head><title>Login screen currently unavailable</title></head><body><h1>Uh oh!</h1>");
		httpdOutput(r, "We apologize, but it seems that we are currently unable to re-direct you to the login screen.");
		httpdOutput(r, "<p>");
		httpdOutput(r, "The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.");
		httpdOutput(r, "<p>");
		httpdPrintf(r, "In a couple of minutes please <a href='%s'>click here</a> to try your request again.", tmp_url);
		httpdOutput(r, "</body></html>");
		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
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
		debug(LOG_INFO, "Captured %s and re-directed them to login page", r->clientAddr);
		free(newlocation);
	}

	free(url);
}

void 
http_callback_wifidog(httpd *webserver, request *r)
{
	http_wifidog_header(r, "WiFiDog");
	httpdOutput(r, "Please use the menu on the left to navigate the features of this WiFiDog installation.");
	http_wifidog_footer(r);
}

void 
http_callback_about(httpd *webserver, request *r)
{
	http_wifidog_header(r, "About WiFiDog");
	httpdOutput(r, "This is WiFiDog version <b>" VERSION "</b>");
	http_wifidog_footer(r);
}

void 
http_callback_status(httpd *webserver, request *r)
{
	char * status = NULL;
	status = get_status_text();
	http_wifidog_header(r, "WiFiDog Status");
	httpdOutput(r, "<pre>");
	httpdOutput(r, status);
	httpdOutput(r, "</pre>");
	http_wifidog_footer(r);
	free(status);
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
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			http_wifidog_header(r, "WiFiDog Error");
			httpdOutput(r, "Failed to retrieve your MAC address");
			http_wifidog_footer(r);
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s", r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);
			} else {
				debug(LOG_DEBUG, "Node for %s already exists", client->ip);
			}

			UNLOCK_CLIENT_LIST();

			authenticate_client(r);
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		http_wifidog_header(r, "WiFiDog Error");
		httpdOutput(r, "Invalid token");
		http_wifidog_footer(r);
	}
}

void
http_wifidog_header(request *r, char *title)
{
	httpdOutput(r, "<html>\n");
	httpdOutput(r, "<head>\n");
	httpdPrintf(r, "<title>%s</title>\n", title);
	httpdPrintf(r, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>\n");
	httpdOutput(r, "</head>\n");
	httpdOutput(r, "<body topmargin=0 leftmargin=0 marginwidth=0 marginheight=0 bgcolor=white text=#628C53 link=blue alink=blue vlink=blue>\n");

	httpdOutput(r, "<table width=100%% height=100%% border=0 cellpadding=12 cellspacing=5>\n");

	httpdOutput(r, "<tr>\n");

	httpdOutput(r, "<td valign=top align=right width=30%% bgcolor=#e1f5da>\n");
	httpdOutput(r, "&nbsp;<p>\n");
	httpdOutput(r, "&nbsp;<p>\n");
	httpdOutput(r, "<a href='/wifidog/status'>WiFiDog Status</a>\n");
	httpdOutput(r, "<p>\n");
	httpdOutput(r, "<a href='/wifidog/about'>About WiFiDog</a>\n");
	httpdOutput(r, "<p>\n");
	httpdOutput(r, "<a href='http://www.ilesansfil.org/wiki/WiFiDog'>WiFiDog's homepage</a>\n");
	httpdOutput(r, "</td>\n");

	httpdOutput(r, "<td valign=top align=left>\n");
	httpdPrintf(r, "<h1>%s</h1>\n", title);
	httpdOutput(r, "<hr>\n");

}

void
http_wifidog_footer(request *r)
{
	httpdOutput(r, "</td>\n");

	httpdOutput(r, "</tr>\n");

	httpdOutput(r, "<tr>\n");

	httpdOutput(r, "<td colspan=2 height=1 valign=bottom align=center>\n");
	httpdOutput(r, "<hr>\n");
	httpdOutput(r, "<font size=1>\n");
	httpdOutput(r, "Copyright (C) 2004-2005.  This software is released under the GNU GPL license.\n");
	httpdOutput(r, "</font>\n");
	httpdOutput(r, "</td>\n");

	httpdOutput(r, "</tr>\n");

	httpdOutput(r, "</table>\n");

	httpdOutput(r, "</body>\n");
	httpdOutput(r, "</html>\n");
}
