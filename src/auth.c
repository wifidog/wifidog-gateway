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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
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
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;

/* Defined in util.c */
extern long served_this_session;

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
	
		fw_sync_with_authserver();
	}
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request *r)
{
	t_client	*client;
	t_authresponse	auth_response;
	char	*ip,
		*mac,
		*token;
	char *newlocation = NULL;
	char *protocol = NULL;
	s_config	*config = NULL;
	t_auth_serv	*auth_server = NULL;
	int port = 80;

	LOCK_CLIENT_LIST();

	client = client_list_find_by_ip(r->clientAddr);

	if (client == NULL) {
		debug(LOG_ERR, "Could not find client for %s", ip);
		UNLOCK_CLIENT_LIST();
		return;
	}
	
	mac = safe_strdup(client->mac);
	token = safe_strdup(client->token);
	
	UNLOCK_CLIENT_LIST();
	
	/* 
	 * At this point we've released the lock while we do an HTTP request since it could
	 * take multiple seconds to do and the gateway would effectively be frozen if we
	 * kept the lock.
	 */
	auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, r->clientAddr, mac, token, 0, 0);
	
	LOCK_CLIENT_LIST();
	
	/* can't trust the client to still exist after n seconds have passed */
	client = client_list_find(r->clientAddr, mac);
	
	if (client == NULL) {
		debug(LOG_ERR, "Could not find client node for %s (%s)", r->clientAddr, mac);
		UNLOCK_CLIENT_LIST();
		free(token);
		free(mac);
		return;
	}
	
	free(token);
	free(mac);

	/* Prepare some variables we'll need below */
	config = config_get_config();
	auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}

	switch(auth_response.authcode) {

	case AUTH_ERROR:
		/* Error talking to central server */
		debug(LOG_ERR, "Got %d from central server authenticating token %s from %s at %s", auth_response, client->token, client->ip, client->mac);
		http_wifidog_header(r, "Error!");
		httpdOutput(r, "Error: We did not get a valid answer from the central server");
		http_wifidog_footer(r);
		break;

	case AUTH_DENIED:
		/* Central server said invalid token */
		debug(LOG_INFO, "Got DENIED from central server authenticating token %s from %s at %s - redirecting them to denied message", client->token, client->ip, client->mac);
		safe_asprintf(&newlocation, "Location: %s://%s:%d%sgw_message.php?message=denied",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		httpdSetResponse(r, "307 Redirect to denied message\n");
		httpdAddHeader(r, newlocation);
		free(newlocation);
		http_wifidog_header(r, "Redirection to message");
		httpdPrintf(r, "Please <a href='%s://%s:%d%sgw_message.php?message=denied'>click here</a>.",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		http_wifidog_footer(r);
		break;

    case AUTH_VALIDATION:
		/* They just got validated for X minutes to check their email */
		debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
				"- adding to firewall and redirecting them to activate message", client->token,
				client->ip, client->mac);
		client->fw_connection_state = FW_MARK_PROBATION;
		fw_allow(client->ip, client->mac, FW_MARK_PROBATION);
		safe_asprintf(&newlocation, "Location: %s://%s:%d%sgw_message.php?message=activate",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		httpdSetResponse(r, "307 Redirect to activate message\n");
		httpdAddHeader(r, newlocation);
		free(newlocation);
		http_wifidog_header(r, "Redirection to message");
		httpdPrintf(r, "Please <a href='%s://%s:%d%sgw_message.php?message=activate'>click here</a>.",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		http_wifidog_footer(r);
	    break;

    case AUTH_ALLOWED:
		/* Logged in successfully as a regular account */
		debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
				"adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
		client->fw_connection_state = FW_MARK_KNOWN;
		fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
        served_this_session++;
		safe_asprintf(&newlocation, "Location: %s://%s:%d%sportal/?gw_id=%s",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path,
			config->gw_id
		);
		httpdSetResponse(r, "307 Redirect to portal\n");
		httpdAddHeader(r, newlocation);
		free(newlocation);
		http_wifidog_header(r, "Redirection to portal");
		httpdPrintf(r, "Please <a href='%s://%s:%d%sportal/?gw_id=%s'>click here</a> for the portal.",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path,
			config->gw_id
		);
		http_wifidog_footer(r);
	    break;

    case AUTH_VALIDATION_FAILED:
		 /* Client had X minutes to validate account by email and didn't = too late */
		debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
				"- redirecting them to failed_validation message", client->token, client->ip, client->mac);
		safe_asprintf(&newlocation, "Location: %s://%s:%d%sgw_message.php?message=failed_validation",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		httpdSetResponse(r, "307 Redirect to failed validation message\n");
		httpdAddHeader(r, newlocation);
		free(newlocation);
		http_wifidog_header(r, "Redirection to message");
		httpdPrintf(r, "Please <a href='%s://%s:%d%sgw_message.php?message=failed_validation'>click here</a>.",
			protocol,
			auth_server->authserv_hostname,
			port,
			auth_server->authserv_path
		);
		http_wifidog_footer(r);
	    break;

    default:
		debug(LOG_WARNING, "I don't know what the validation code %d means for token %s from %s at %s - sending error message", auth_response.authcode, client->token, client->ip, client->mac);
		http_wifidog_header(r, "Internal error");
		httpdOutput(r, "We can not validate your request at this time");
		http_wifidog_footer(r);
	    break;

	}

	UNLOCK_CLIENT_LIST();
	return;
}


