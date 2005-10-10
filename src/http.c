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
			*protocol,
			tmp_url[MAX_BUF],
			*url;
	int		port;
	s_config	*config = config_get_config();

    memset(tmp_url, 0, sizeof(tmp_url));
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s",
            r->request.host,
            r->request.path);
    url = httpdUrlEncode(tmp_url);

    if (config->auth_servers == NULL) {
        /* Redirect to splash page, no authentication servers exist */

        safe_asprintf(&newlocation, "Location: http://%s:%d/wifidog/splash",
            config->gw_address,
            config->gw_port);

        httpdSetResponse(r, "307 Please visit here\n");
        httpdAddHeader(r, newlocation);
        http_wifidog_header(r, "Redirection");
        httpdPrintf(r, "Please <a href='http://%s:%d/wifidog/splash'>click here</a> to login",
            config->gw_address,
            config->gw_port);
        http_wifidog_footer(r);
        debug(LOG_INFO, "Captured %s requesting [%s] and re-directed them to splash page", r->clientAddr, url);
        free(newlocation);

        http_wifidog_footer(r);
        debug(LOG_INFO, "Sent %s the splash page", r->clientAddr);
    } else {

        t_auth_serv	*auth_server = get_auth_server();

        if (auth_server->authserv_use_ssl) {
            protocol = "https";
            port = auth_server->authserv_ssl_port;
        } else {
            protocol = "http";
            port = auth_server->authserv_http_port;
        }

        if (!is_online()) {
            /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
            http_wifidog_header(r, "<h3>Internet access unavailable</h3>");
            httpdOutput(r, "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>");
            httpdOutput(r, "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>");
            httpdOutput(r, "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>");
            httpdPrintf(r, "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);
            http_wifidog_footer(r);
            debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
        }
        else if (!is_auth_online()) {
            /* The auth server is down at the moment - apologize and do not redirect anywhere */
            http_wifidog_header(r, "<h3>Login screen unavailable</h3>");
            httpdOutput(r, "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>");
            httpdOutput(r, "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>");
            httpdPrintf(r, "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);
            http_wifidog_footer(r);
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
            http_wifidog_header(r, "Redirection");
            httpdPrintf(r, "Please <a href='%s://%s:%d%slogin?gw_address=%s&gw_port=%d&gw_id=%s&url=%s'>click here</a> to login",
                    protocol,
                    auth_server->authserv_hostname,
                    port,
                    auth_server->authserv_path,
                    config->gw_address, 
                    config->gw_port,
                    config->gw_id,
                    url);
            http_wifidog_footer(r);
            debug(LOG_INFO, "Captured %s requesting [%s] and re-directed them to login page", r->clientAddr, url);
            free(newlocation);
        }

	    free(url);
    }
}

void 
http_callback_wifidog(httpd *webserver, request *r)
{
	http_wifidog_header(r, "WiFiDog");
	httpdOutput(r, "Please use the menu to navigate the features of this WiFiDog installation.");
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
http_callback_splash(httpd *webserver, request *r)
{
	char * status = NULL;
	httpVar * url;

	status = get_status_text();
	http_wifidog_header(r, "Disclaimer");
	httpdOutput(r, "<p>This hotspot offers Free internet access!</p>");
	httpdOutput(r, "<p>By clicking ACCEPT, you agree that you will respect these WiFi Do's and Don'ts:</p>");
    httpdOutput(r, "<ul>\n");
    httpdOutput(r, "<li>Respect the venue's bandwidth. Don't download too many large files.\n");
    httpdOutput(r, "<li>Make Purchases and Tip.\n");
    httpdOutput(r, "<li>If it's a busy place, don't take up too much space.\n");
    httpdOutput(r, "<li>Turn down your sound or use headphones.\n");
    httpdOutput(r, "<li>Share a table.\n");
    httpdOutput(r, "<li>Thank the staff or management - let them know you appreciate the WiFi.\n");
    httpdOutput(r, "<li>If it's busy - don't overstay your welcome.\n");
    httpdOutput(r, "<li>Help others who are having trouble getting on the network.\n");
    httpdOutput(r, "<li>Remember that the WiFi is complimentary. If it doesn't work, let the staff know. Be patient.\n");
    httpdOutput(r, "</ul>\n");
	if ((url = httpdGetVariableByName(r, "url"))) {
	    httpdPrintf(r, "<a href=\"/wifidog/auth?url=%s\">ACCEPT</a>", url->value);
    } else {
	    httpdOutput(r, "<a href=\"/wifidog/auth\">ACCEPT</a>");
    }

	http_wifidog_footer(r);
	free(status);
}

void
http_callback_portal(httpd *webserver, request *r)
{
	char * status = NULL;

	status = get_status_text();
	http_wifidog_header(r, "Enjoy!");
	httpdOutput(r, "<p>Don't forget, socialize and discuss with others! (you're not at home, enjoy the place and people!)</p>");
	http_wifidog_footer(r);
	free(status);
}

void 
http_callback_auth(httpd *webserver, request *r)
{
	s_config	*config = config_get_config();
	t_client	*client;
	httpVar * token;
	char	*mac;
    char    *newlocation;

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
	} else if (config->auth_servers == NULL) {
        /* No authentication server is configured, we do not expect a token
         * auth right away */
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
				debug(LOG_DEBUG, "New client ip=%s mac=%s", r->clientAddr, mac);
				client_list_append(r->clientAddr, mac, "SpLaShOnLy");
			} else {
				debug(LOG_DEBUG, "Node for %s already exists", client->ip);
			}

            /* Find the client in the list once it's created (not very useful) */
			client = client_list_find(r->clientAddr, mac);

            debug(LOG_INFO, "ALLOWING %s [%s], the user clicked the accept button", client->ip, client->mac);
            client->fw_connection_state = FW_MARK_KNOWN;
            fw_allow(client->ip, client->mac, FW_MARK_KNOWN);

			UNLOCK_CLIENT_LIST();

			free(mac);

            httpdSetResponse(r, "307 Redirect to portal\n");
            /* If we have a portal url specified in the configuration,
               forward to it, otherwise forward to /wifidog/portal */
            if (config->portal && strncmp(config->portal, "http://", strlen("http://")) == 0) {
                debug(LOG_INFO, "Redirecting to portal at %s", config->portal);
                safe_asprintf(&newlocation, "Location: %s",
                    config->portal
                );

                httpdAddHeader(r, newlocation);
                http_wifidog_header(r, "Redirection");

                httpdPrintf(r, "Please <a href='%s'>click here</a> for the portal",
                    config->portal);
            } else {
                safe_asprintf(&newlocation, "Location: http://%s:%d/wifidog/portal",
                    config->gw_address,
                    config->gw_port);
                debug(LOG_INFO, "Redirecting to local portal");

                httpdAddHeader(r, newlocation);
                http_wifidog_header(r, "Redirection");

                httpdPrintf(r, "Please <a href='http://%s:%d/wifidog/portal'>click here</a> for the portal",
                    config->gw_address, 
                    config->gw_port);
            }

            http_wifidog_footer(r);
            free(newlocation);
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
    httpdOutput(r, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>\n");

    httpdOutput(r, "<style>\n");
    httpdOutput(r, "body {\n");
    httpdOutput(r, "  margin: 10px 60px 0 60px; \n");
    httpdOutput(r, "  font-family : bitstream vera sans, sans-serif;\n");
    httpdOutput(r, "  color: #46a43a;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a {\n");
    httpdOutput(r, "  color: #46a43a;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:active {\n");
    httpdOutput(r, "  color: #46a43a;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:link {\n");
    httpdOutput(r, "  color: #46a43a;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "a:visited {\n");
    httpdOutput(r, "  color: #46a43a;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#header {\n");
    httpdOutput(r, "  height: 30px;\n");
    httpdOutput(r, "  background-color: #B4F663;\n");
    httpdOutput(r, "  padding: 20px;\n");
    httpdOutput(r, "  font-size: 20pt;\n");
    httpdOutput(r, "  text-align: center;\n");
    httpdOutput(r, "  border: 2px solid #46a43a;\n");
    httpdOutput(r, "  border-bottom: 0;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#menu {\n");
    httpdOutput(r, "  width: 200px;\n");
    httpdOutput(r, "  float: right;\n");
    httpdOutput(r, "  background-color: #B4F663;\n");
    httpdOutput(r, "  border: 2px solid #46a43a;\n");
    httpdOutput(r, "  font-size: 80%;\n");
    httpdOutput(r, "  min-height: 300px;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#menu h2 {\n");
    httpdOutput(r, "  margin: 0;\n");
    httpdOutput(r, "  background-color: #46a43a;\n");
    httpdOutput(r, "  text-align: center;\n");
    httpdOutput(r, "  color: #B4F663;\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#copyright {\n");
    httpdOutput(r, "}\n");

    httpdOutput(r, "#content {\n");
    httpdOutput(r, "  padding: 20px;\n");
    httpdOutput(r, "  border: 2px solid #46a43a;\n");
    httpdOutput(r, "  min-height: 300px;\n");
    httpdOutput(r, "}\n");
    httpdOutput(r, "</style>\n");

    httpdOutput(r, "</head>\n");

    httpdOutput(r, "<body\n");

    httpdOutput(r, "<div id=\"header\">\n");
    httpdPrintf(r, "    %s\n", title);
    httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"menu\">\n");


    httpdOutput(r, "    <h2>Info</h2>\n");
    httpdOutput(r, "    <ul>\n");
    httpdOutput(r, "    <li>Version: " VERSION "\n");
    httpdPrintf(r, "    <li>Node ID: %s\n", config_get_config()->gw_id);
    httpdOutput(r, "    </ul>\n");
    httpdOutput(r, "    <br>\n");

    httpdOutput(r, "    <h2>Menu</h2>\n");
    httpdOutput(r, "    <ul>\n");
    httpdOutput(r, "    <li><a href='/wifidog/status'>WiFiDog Status</a>\n");
    httpdOutput(r, "    <li><a href='/wifidog/about'>About WiFiDog</a>\n");
    httpdOutput(r, "    <li><a href='http://www.wifidog.org'>WiFiDog's homepage</a>\n");
    httpdOutput(r, "    </ul>\n");
    httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"content\">\n");
    httpdPrintf(r, "<h2>%s</h2>\n", title);
}

void
http_wifidog_footer(request *r)
{
	httpdOutput(r, "</div>\n");

    httpdOutput(r, "<div id=\"copyright\">\n");
    httpdOutput(r, "Copyright (C) 2004-2005.  This software is released under the GNU GPL license.\n");
    httpdOutput(r, "</div>\n");


	httpdOutput(r, "</body>\n");
	httpdOutput(r, "</html>\n");
}
