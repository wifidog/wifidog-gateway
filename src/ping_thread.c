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
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server to make sure everything is running properly.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>

#include "../config.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"

extern int errno;

static void ping(void);

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_ping(void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) +
				config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);

		ping();
	}
}

/** @internal
 * This function does the actual request.
 */
static void
ping(void)
{
	size_t			numbytes,
				totalbytes;
	int			sockfd;
	t_auth_serv		*auth_server;
	char			request[MAX_BUF];
	struct hostent		*he;
	struct sockaddr_in	their_addr;
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		exit(1);
	}

	auth_server = get_auth_server();
	
	if ((he = gethostbyname(auth_server->authserv_hostname)) == NULL) {
		debug(LOG_ERR, "Failed to resolve %s via gethostbyname"
				"(): %s", auth_server->authserv_hostname, 
				strerror(errno));
		debug(LOG_ERR, "Bumping auth server to last in line.");
		mark_auth_server_bad(auth_server);
		close(sockfd);
		return;
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(auth_server->authserv_http_port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));

	debug(LOG_INFO, "Connecting to auth server %s on port %d", 
			auth_server->authserv_hostname, 
			auth_server->authserv_http_port);

	if (connect(sockfd, (struct sockaddr *)&their_addr,
				sizeof(struct sockaddr)) == -1) {
		debug(LOG_ERR, "connect(): %s", strerror(errno));
		debug(LOG_ERR, "Bumping auth server to last in line.");
		mark_auth_server_bad(auth_server);
		close(sockfd);
		return;
	}

	snprintf(request, sizeof(request) - 1, "GET %s/ping/ HTTP/1.0\n"
			"User-Agent: WiFiDog %s\n"
			"Host: %s\n"
			"\n",
			auth_server->authserv_path,
			VERSION,
			auth_server->authserv_hostname);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);
	
	send(sockfd, request, strlen(request), 0);

	numbytes = totalbytes = 0;
	while ((numbytes = read(sockfd, request + totalbytes, 
				MAX_BUF - (totalbytes + 1))) > 0)
		totalbytes =+ numbytes;
	
	if (numbytes == -1) {
		debug(LOG_ERR, "read(): %s", strerror(errno));
		exit(1);
	}

	numbytes = totalbytes;
	
	request[numbytes] = '\0';

	close(sockfd);

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);
	
	if (!strstr(request, "Pong")) {
		debug(LOG_ERR, "Primary auth server offline");
		debug(LOG_ERR, "Bumping auth server to last in line.");
		mark_auth_server_bad(auth_server);
		return;
	}
	
	debug(LOG_DEBUG, "Auth Server Says: Pong");
	return;	
}
