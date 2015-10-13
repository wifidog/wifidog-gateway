<<<<<<< HEAD
/* vim: set et sw=4 ts=4 sts=4 : */
=======
>>>>>>> FETCH_HEAD
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

/* $Id$ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
<<<<<<< HEAD
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
=======

>>>>>>> FETCH_HEAD
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
<<<<<<< HEAD
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"
=======
#include "httpd.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"

#include "util.h"
>>>>>>> FETCH_HEAD

#include "../config.h"


<<<<<<< HEAD
/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url, *mac;
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    url = httpdUrlEncode(tmp_url);

    if (!is_online()) {
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
                      "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

        send_http_page(r, "Uh oh! Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
        /* The auth server is down at the moment - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>",
                      tmp_url);

        send_http_page(r, "Uh oh! Login screen unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
        /* Re-direct them to auth server */
        char *urlFragment;

        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request",
                  r->clientAddr);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment, config->gw_address, config->gw_port,
                          config->gw_id, r->clientAddr, url);
        } else {
            debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&mac=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment,
                          config->gw_address, config->gw_port, config->gw_id, r->clientAddr, mac, url);
            free(mac);
        }

        // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
        debug(LOG_INFO, "Check host %s is in whitelist or not", r->request.host);       // e.g. www.example.com
        t_firewall_rule *rule;
        //e.g. example.com is in whitelist
        // if request http://www.example.com/, it's not equal example.com.
        for (rule = get_ruleset("global"); rule != NULL; rule = rule->next) {
            debug(LOG_INFO, "rule mask %s", rule->mask);
            if (strstr(r->request.host, rule->mask) == NULL) {
                debug(LOG_INFO, "host %s is not in %s, continue", r->request.host, rule->mask);
                continue;
            }
            int host_length = strlen(r->request.host);
            int mask_length = strlen(rule->mask);
            if (host_length != mask_length) {
                char prefix[1024] = { 0 };
                // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
                strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
                strcat(prefix, ".");    // www.
                strcat(prefix, rule->mask);     // www.example.com
                if (strcasecmp(r->request.host, prefix) == 0) {
                    debug(LOG_INFO, "allow subdomain");
                    fw_allow_host(r->request.host);
                    http_send_redirect(r, tmp_url, "allow subdomain");
                    free(url);
                    free(urlFragment);
                    return;
                }
            } else {
                // e.g. "example.com" is in conf, so it had been parse to IP and added into "iptables allow" when wifidog start. but then its' A record(IP) changed, it will go to here.
                debug(LOG_INFO, "allow domain again, because IP changed");
                fw_allow_host(r->request.host);
                http_send_redirect(r, tmp_url, "allow domain");
                free(url);
                free(urlFragment);
                return;
            }
        }

        debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
        free(urlFragment);
    }
    free(url);
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

=======

extern pthread_mutex_t	client_list_mutex;

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd *webserver, request *r)
{
	char tmp_url[MAX_BUF],
			*url,
			*mac;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();

	memset(tmp_url, 0, sizeof(tmp_url));
	/* 
	 * XXX Note the code below assumes that the client's request is a plain
	 * http request to a standard port. At any rate, this handler is called only
	 * if the internet/auth server is down so it's not a huge loss, but still.
	 */
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);
	url = httpdUrlEncode(tmp_url);

	if (!is_online()) {
		/* The internet connection is down at the moment  - apologize and do not redirect anywhere */
		char * buf;
		safe_asprintf(&buf, 
			"<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
			"<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Internet access unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else if (!is_auth_online()) {
		/* The auth server is down at the moment - apologize and do not redirect anywhere */
		char * buf;
		safe_asprintf(&buf, 
			"<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Login screen unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
	}
	else {
		/* Re-direct them to auth server */
		char *urlFragment;

		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request", r->clientAddr);
			safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&url=%s",
				auth_server->authserv_login_script_path_fragment,
				config->gw_address,
				config->gw_port, 
				config->gw_id,
				url);
		} else {			
			debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
			safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&mac=%s&url=%s",
				auth_server->authserv_login_script_path_fragment,
				config->gw_address,
				config->gw_port, 
				config->gw_id,
				mac,
				url);
		}

		debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
		free(urlFragment);
	}
	free(url);
}

void 
http_callback_wifidog(httpd *webserver, request *r)
{
	send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void 
http_callback_about(httpd *webserver, request *r)
{
	send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void 
http_callback_status(httpd *webserver, request *r)
{
	const s_config *config = config_get_config();
	char * status = NULL;
	char *buf;

	if (config->httpdusername && 
			(strcmp(config->httpdusername, r->request.authUser) ||
			 strcmp(config->httpdpassword, r->request.authPassword))) {
		debug(LOG_INFO, "Status page requested, forcing authentication");
		httpdForceAuthenticate(r, config->httpdrealm);
		return;
	}

	status = get_status_text();
	safe_asprintf(&buf, "<pre>%s</pre>", status);
	send_http_page(r, "WiFiDog Status", buf);
	free(buf);
	free(status);
}
>>>>>>> FETCH_HEAD
/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
<<<<<<< HEAD
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
=======
void http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text)
{
	char *protocol = NULL;
	int port = 80;
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}
			    		
	char *url = NULL;
	safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		auth_server->authserv_hostname,
		port,
		auth_server->authserv_path,
		urlFragment
	);
	http_send_redirect(r, url, text);
	free(url);	
>>>>>>> FETCH_HEAD
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
<<<<<<< HEAD
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client_list_add(r->clientAddr, mac, token->value);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
=======
void http_send_redirect(request *r, const char *url, const char *text)
{
	char *message = NULL;
	char *header = NULL;
	char *response = NULL;
		/* Re-direct them to auth server */
	debug(LOG_DEBUG, "Redirecting client browser to %s", url);
	safe_asprintf(&header, "Location: %s", url);
	safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
	httpdSetResponse(r, response);
	httpdAddHeader(r, header);
	free(response);
	free(header);
	safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
	send_http_page(r, text ? text : "Redirection to message", message);
	free(message);
}

void 
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;
	httpVar *logout = httpdGetVariableByName(r, "logout");
	if ((token = httpdGetVariableByName(r, "token"))) {
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_DEBUG, "New client for %s", r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);
			} else if (logout) {
			    t_authresponse  authresponse;
			    s_config *config = config_get_config();
			    unsigned long long incoming = client->counters.incoming;
			    unsigned long long outgoing = client->counters.outgoing;
			    char *ip = safe_strdup(client->ip);
			    char *urlFragment = NULL;
			    t_auth_serv	*auth_server = get_auth_server();
			    				    	
			    fw_deny(client->ip, client->mac, client->fw_connection_state);
			    client_list_delete(client);
			    debug(LOG_DEBUG, "Got logout from %s", client->ip);
			    
			    /* Advertise the logout if we have an auth server */
			    if (config->auth_servers != NULL) {
					UNLOCK_CLIENT_LIST();
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token->value, 
									    incoming, outgoing);
					LOCK_CLIENT_LIST();
					
					/* Re-direct them to auth server */
					debug(LOG_INFO, "Got manual logout from client ip %s, mac %s, token %s"
					"- redirecting them to logout message", client->ip, client->mac, client->token);
					safe_asprintf(&urlFragment, "%smessage=%s",
						auth_server->authserv_msg_script_path_fragment,
						GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT
					);
					http_send_redirect_to_auth(r, urlFragment, "Redirect to logout message");
					free(urlFragment);
			    }
			    free(ip);
 			} 
 			else {
				debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
			}
			UNLOCK_CLIENT_LIST();
			if (!logout) {
				authenticate_client(r);
			}
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		send_http_page(r, "WiFiDog error", "Invalid token");
	}
}

void send_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
>>>>>>> FETCH_HEAD
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

<<<<<<< HEAD
    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
=======
    fd=open(config->htmlmsgfile, O_RDONLY);
    if (fd==-1) {
>>>>>>> FETCH_HEAD
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

<<<<<<< HEAD
    if (fstat(fd, &stat_info) == -1) {
=======
    if (fstat(fd, &stat_info)==-1) {
>>>>>>> FETCH_HEAD
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
<<<<<<< HEAD
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
=======

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
>>>>>>> FETCH_HEAD
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

<<<<<<< HEAD
    buffer[written] = 0;
=======
    buffer[written]=0;
>>>>>>> FETCH_HEAD
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
<<<<<<< HEAD
=======

>>>>>>> FETCH_HEAD
