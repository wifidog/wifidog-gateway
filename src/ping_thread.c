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
#include <errno.h>

#include "../config.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"

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
		/* Make sure we check the servers at the very begining */
		/** @todo  Note that this will only help if the second server responds.  The logic of the ping itslef should be changed so it iterates in the list until it finds one that responds ox exausts the list */
		debug(LOG_DEBUG, "Running ping()");
		ping();
		
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
	int			sockfd,
				nfds,
				done;
	t_auth_serv		*auth_server;
	char			request[MAX_BUF];
	struct in_addr		*h_addr;
	struct sockaddr_in	their_addr;
	fd_set			readfds;
	struct timeval		timeout;

	debug(LOG_DEBUG, "Entering ping()");
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		exit(1);
	}

	auth_server = get_auth_server();

	debug(LOG_DEBUG, "Using auth server %s",
			auth_server->authserv_hostname);
	
	debug(LOG_DEBUG, "Resolving IP");
	if ((h_addr = (struct in_addr *)wd_gethostbyname(auth_server->authserv_hostname)) == NULL) {
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
	their_addr.sin_addr = *h_addr;
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
		free(h_addr);
		return;
	}
	free(h_addr);
		
	snprintf(request, sizeof(request) - 1, "GET %sping/?gw_id=%s HTTP/1.0\n"
			"User-Agent: WiFiDog %s\n"
			"Host: %s\n"
			"\n",
			auth_server->authserv_path,
			config_get_config()->gw_id,
			VERSION,
			auth_server->authserv_hostname);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);
	
	send(sockfd, request, strlen(request), 0);

	debug(LOG_DEBUG, "Reading response");
	
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, request + totalbytes, 8);
					//MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "read(): %s", strerror(errno));
				mark_auth_server_bad(auth_server);
				close(sockfd);
				return;
			} else if (numbytes == 0) {
				done = 1;
			} else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d",
						numbytes, totalbytes);
			}
		} else if (nfds == 0) {
			debug(LOG_ERR, "select() timed out");
			mark_auth_server_bad(auth_server);
			close(sockfd);
			return;
		} else if (nfds < 0) {
			debug(LOG_ERR, "select(): %s", strerror(errno));
			mark_auth_server_bad(auth_server);
			close(sockfd);
			return;
		}
	} while (!done);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

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
