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
/** @file wdctl_thread.c
    @brief Monitoring and control of wifidog, server part
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
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "httpd.h"

#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;
extern	pthread_mutex_t	config_mutex;

/* Defined in ping_thread.c */
extern time_t started_time;

static void *thread_wdctl_handler(void *);
static void wdctl_status(int);
static void wdctl_stop(int);
static void wdctl_reset(int, char *);

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_wdctl(void *arg)
{
	int	sock,
		fd,
		len;
	char	*sock_name;
	struct 	sockaddr_un	sa_un;
	pthread_t	tid;

	debug(LOG_DEBUG, "Starting wdctl.");

	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = (char *)arg;
	debug(LOG_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		debug(LOG_ERR, "WDCTL socket name too long");
		exit(1);
	}
	

	debug(LOG_DEBUG, "Creating socket");
	sock = socket(PF_UNIX, SOCK_STREAM, 0);

	debug(LOG_DEBUG, "Got server socket %d", sock);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	debug(LOG_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we
					    * check a few lines before. */
	sa_un.sun_family = AF_UNIX;
	
	debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path,
			strlen(sock_name));
	
	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) 
				+ sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Could not bind control socket: %s",
				strerror(errno));
		pthread_exit(NULL);
	}

	if (listen(sock, 5)) {
		debug(LOG_ERR, "Could not listen on control socket: %s",
				strerror(errno));
		pthread_exit(NULL);
	}

	while (1) {
		memset(&sa_un, 0, sizeof(sa_un));
		if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1){
			debug(LOG_ERR, "Accept failed on control socket: %s",
					strerror(errno));
		} else {
			debug(LOG_DEBUG, "Accepted connection on wdctl "
					"socket %d (%s)", fd, sa_un.sun_path);
			pthread_create(&tid, NULL, &thread_wdctl_handler,
					(void *)fd);
			pthread_detach(tid);
		}
	}
}


static void *
thread_wdctl_handler(void *arg)
{
	int	fd,
		done,
		i;
	char	request[4096];
	ssize_t	read_bytes,
		len;

	debug(LOG_DEBUG, "Entering thread_wdctl_handler....");

	fd = (int)arg;
	
	debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

	/* Init variables */
	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));
	
	/* Read.... */
	while (!done && read_bytes < (sizeof(request) - 1)) {
		len = read(fd, request + read_bytes,
				sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++) {
			if (request[i] == '\r' || request[i] == '\n') {
				request[i] = '\0';
				done = 1;
			}
		}
		
		/* Increment position */
		read_bytes += len;
	}

	if (strcmp(request, "status") == 0) {
		wdctl_status(fd);
	} else if (strcmp(request, "stop") == 0) {
		wdctl_stop(fd);
	} else if (strncmp(request, "reset ", 6) == 0) {
		wdctl_reset(fd, (request + 6));
	}

	if (!done) {
		debug(LOG_ERR, "Invalid wdctl request.");
		shutdown(fd, 2);
		close(fd);
		pthread_exit(NULL);
	}

	debug(LOG_DEBUG, "Request received: [%s]", request);
	
	shutdown(fd, 2);
	close(fd);
	debug(LOG_DEBUG, "Exiting thread_wdctl_handler....");

	return NULL;
}

static void
wdctl_status(int fd)
{
    s_config *config;
    t_auth_serv *auth_server;
	char		buffer[STATUS_BUF_SIZ];
	ssize_t		len;
	t_client	*first;
	int		count;
	unsigned long int uptime = 0;
	unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;

    config = config_get_config();
	
	len = 0;
	snprintf(buffer, (sizeof(buffer) - len), "WiFiDog status\n\n");
	len = strlen(buffer);


	uptime = time(NULL) - started_time;
	days    = uptime / (24 * 60 * 60);
	uptime -= days * (24 * 60 * 60);
	hours   = uptime / (60 * 60);
	uptime -= hours * (60 * 60);
	minutes = uptime / 60;
	uptime -= minutes * 60;
	seconds = uptime;
	snprintf((buffer + len), (sizeof(buffer) - len), "Uptime: %ud %uh %um %us\n\n", days, hours, minutes, seconds);
	len = strlen(buffer);

	LOCK_CLIENT_LIST();
	
	first = client_get_first_client();
	
	if (first == NULL) {
		count = 0;
	} else {
		count = 1;
		while (first->next != NULL) {
			first = first->next;
			count++;
		}
	}
	
	snprintf((buffer + len), (sizeof(buffer) - len), "%d clients "
			"connected.\n", count);
	len = strlen(buffer);

	first = client_get_first_client();

	count = 0;
	while (first != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Client %d\t"
				"Ip: %s\tMac: %s\tToken: %s\n", count, 
				first->ip, first->mac, first->token);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "\tIn: %lld\t"
				"Out: %lld\n" , first->counters.incoming,
				first->counters.outgoing);
		len = strlen(buffer);

		count++;
		first = first->next;
	}
	
	UNLOCK_CLIENT_LIST();

    LOCK_CONFIG();
    
    snprintf((buffer + len), (sizeof(buffer) - len), "\nAuthentication servers:\n");
    len = strlen(buffer);

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        snprintf((buffer + len), (sizeof(buffer) - len), "  Host: %s (%s)\n", auth_server->authserv_hostname, auth_server->last_ip);
        len = strlen(buffer);
    }

    UNLOCK_CONFIG();
	
	write(fd, buffer, len);
}

/** A bit of an hack, self kills.... */
static void
wdctl_stop(int fd)
{
	pid_t	pid;

	pid = getpid();
	kill(pid, SIGINT);
}

static void
wdctl_reset(int fd, char *arg)
{
	t_client	*node;

	debug(LOG_DEBUG, "Entering wdctl_reset...");
	
	LOCK_CLIENT_LIST();
	debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);
	
	/* We get the node or return... */
	if ((node = client_list_find_by_ip(arg)) != NULL);
	else if ((node = client_list_find_by_mac(arg)) != NULL);
	else {
		debug(LOG_DEBUG, "Client not found.");
		UNLOCK_CLIENT_LIST();
		write(fd, "No", 2);
		return;
	}

	debug(LOG_DEBUG, "Got node %x.", node);
	
	/* deny.... */
	/* TODO: maybe just deleting the connection is not best... But this
	 * is a manual command, I don't anticipate it'll be that useful. */
	fw_deny(node->ip, node->mac, node->fw_connection_state);
	client_list_delete(node);
	
	UNLOCK_CLIENT_LIST();
	
	write(fd, "Yes", 3);
	
	debug(LOG_DEBUG, "Exiting wdctl_reset...");
}
