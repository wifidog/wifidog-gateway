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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"

#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;

/** @internal
 * @brief Used to bypass libhttpd output.
 * @note Can only be called once per connection because the socket gets
 * closed. */
static void
_http_output(int fd, char *msg)
{
	char header[] = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-"
			  "Type: text/html\r\nCache-control: private, no-cache"
			  ", must-revalidate\r\nExpires: Mon, 26 Jul 1997 \r\n"
			  "05:00:00 GMT\r\nPragma: no-cache\r\n\r\n<html><head>"
			  "\n<meta http-equiv=\"Pragma\" CONTENT=\"no-cache\">"
			  "\n<meta http-equiv=\"Expires\" CONTENT=\"-1\">\n"
			  "</head>\n<body>\n";
	char footer[] = "</body></html>";
	
	debug(LOG_DEBUG, "HTTP Response: [%s%s%s]", header, msg, footer);
	
	send(fd, header, sizeof(header), 0);
	send(fd, msg, strlen(msg), 0);
	send(fd, footer, sizeof(footer), 0);
	shutdown(fd, 2);
	close(fd);
}

/** @internal
 * @brief Used to bypass libhttpd output.
 * @note Can only be called once per connection because the socket gets
 * closed. */
static void
_http_redirect(int fd, char *format, ...)
{
	char *response, *url;
	va_list vlist;

	va_start(vlist, format);

	vasprintf(&url, format, vlist);

	asprintf(&response, "HTTP/1.1 307 Please authenticate yourself here\r\nLocation: %s\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><head><title>Redirection</title></head><body>Please <a href='%s'>Click here</a> if you're not redirected.", url, url);

	debug(LOG_DEBUG, "HTTP Redirect: [%s]", response);
	
	send(fd, response, strlen(response), 0);
	shutdown(fd, 2);
	close(fd);

	free(response);
	free(url);
}

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_client_timeout_check(void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
	  timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	
		debug(LOG_DEBUG, "Running fw_counter()");
	
		fw_counter();
	}
}

/**Launches a thread to authenticate a single client against the central server and dies when done
@param r httpd request struct */
void
authenticate_client(request *r)
{
	t_client	*client;
	t_authresponse	auth_response;
	char	*ip,
		*mac,
		*token;

	pthread_mutex_lock(&client_list_mutex);

	client = client_list_find_by_ip(r->clientAddr);

	if (client == NULL) {
		debug(LOG_ERR, "Could not find client client for %s", ip);
		pthread_mutex_unlock(&client_list_mutex);
		return; /* Implicit pthread_exit() */
	}
	
	mac = strdup(client->mac);
	token = strdup(client->token);
	
	pthread_mutex_unlock(&client_list_mutex);
		
	auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, r->clientAddr,
			mac, token, 0, 0);
	
	pthread_mutex_lock(&client_list_mutex);
	
	/* can't trust the client to still exist */
	client = client_list_find(r->clientAddr, mac);
	
	if (client == NULL) {
		debug(LOG_ERR, "Could not find client node for %s (%s)",
				r->clientAddr, mac);
		pthread_mutex_unlock(&client_list_mutex);
		free(token);
		free(mac);
		return;
	}
	
	free(token);
	free(mac);

	switch(auth_response.authcode) {

	case AUTH_ERROR:
		/* Error talking to central server */
		debug(LOG_ERR, "Got %d from central server authenticating "
			"token %s from %s at %s", auth_response, client->token,
			client->ip, client->mac);
		_http_output(client->fd, "Access denied: We did not get a "
			"valid answer from the central server");
		break;

	case AUTH_DENIED:
		/* Central server said invalid token */
		//_http_output(client->fd, "Access denied");
	    _http_redirect(r->clientSock, "http://%s:%d%sgw_message.php?message=denied",
		    config_get_config()->auth_servers->authserv_hostname, 
		    config_get_config()->auth_servers->authserv_http_port,
		    config_get_config()->auth_servers->authserv_path);
		break;

    case AUTH_VALIDATION:
		client->fw_connection_state = FW_MARK_PROBATION;
        fw_allow(client->ip, client->mac, FW_MARK_PROBATION);
	    //_http_output(r->clientSock, "You have 15 minutes to activate your account, hurry up!");
	    _http_redirect(r->clientSock, "http://%s:%d%sgw_message.php?message=activate",
		    config_get_config()->auth_servers->authserv_hostname, 
		    config_get_config()->auth_servers->authserv_http_port,
		    config_get_config()->auth_servers->authserv_path);
	    break;

    case AUTH_ALLOWED:
	    client->fw_connection_state = FW_MARK_KNOWN;
       	fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
	    _http_redirect(r->clientSock, "http://%s:%d%sportal/?gw_id=%s",
	        config_get_config()->auth_servers->authserv_hostname, 
		    config_get_config()->auth_servers->authserv_http_port,
		    config_get_config()->auth_servers->authserv_path,
		    config_get_config()->gw_id);
	    break;

    case AUTH_VALIDATION_FAILED:
	    //_http_output(r->clientSock, "You have failed to validate your account in 15 minutes");
	    _http_redirect(r->clientSock, "http://%s:%d%sgw_message.php?message=failed_validation",
	        config_get_config()->auth_servers->authserv_hostname, 
	        config_get_config()->auth_servers->authserv_http_port,
	        config_get_config()->auth_servers->authserv_path);
	    break;

    default:
	    _http_output(r->clientSock, "Internal error");
	    debug(LOG_WARNING, "I don't know what the validation code %d means", auth_response.authcode);
	    break;

	}

	pthread_mutex_unlock(&client_list_mutex);
	return;
}


