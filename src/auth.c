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
    @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#include "common.h"

pthread_mutex_t	nodes_mutex = PTHREAD_MUTEX_INITIALIZER;

s_config config;

static void _http_output(int fd, char *msg);

void
cleanup_thread(void *ptr)
{
#ifndef __UCLIBC__
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
#endif
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
#ifndef __UCLIBC__
		/* Normal, thread safe */
		timeout.tv_sec = time(NULL) + config.checkinterval;
		timeout.tv_nsec = 0;

		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
#else
		/* uClibc appears to have major issues... */
		/* XXX Not compatible with anything but Linux 2.0 to 2.4 */
		sleep(config.checkinterval);
#endif
		
		fw_counter();
	}
}

void
auth_thread(void *ptr)
{
	t_node	*node;
	int	profile;
	UserClasses	*tmp_uc;
	UserRights	*tmp_ur;
	char	*ip,
		*mac,
		*token;

	ip = (char *)ptr;

	pthread_mutex_lock(&nodes_mutex);

	node = node_find_by_ip(ip);

	if (node == NULL) {
		pthread_mutex_unlock(&nodes_mutex);
		return; /* Implicit pthread_exit() */
	}
	
	mac = strdup(node->mac);
	token = strdup(node->token);
	
	pthread_mutex_unlock(&nodes_mutex);
		
	profile = authenticate(ip, mac, token, 0);
	
	pthread_mutex_lock(&nodes_mutex);
	
	/* can't trust the node to still exist */
	node = node_find_by_ip(ip);
	
	/* don't need any of them anymore */
	free(ip);
	free(token);
	free(mac);
	
	if (node == NULL) {
		pthread_mutex_unlock(&nodes_mutex);
		return;
	}

	if (profile == -1) {
		// Error talking to central server
		debug(D_LOG_ERR, "Got %d from central server authenticating "
			"token %s from %s at %s", profile, node->token,
			node->ip, node->mac);
		_http_output(node->fd, "Access denied: We did not get a valid "
			"answer from the central server");
		node->fd = 0;
		pthread_mutex_unlock(&nodes_mutex);
		return;
	} else if (profile == 0) {
		// Central server said invalid token
		_http_output(node->fd, "Your authentication has failed or "
			"timed-out.  Please re-login");
		node->fd = 0;
		pthread_mutex_unlock(&nodes_mutex);
		return;
	}

	/* If we get here, we've got a profile > 0 */
	
	debug(D_LOG_DEBUG, "Node %s with mac %s and profile "
		"%d validated", node->ip, node->mac, profile);
	
	tmp_uc = find_userclasses(profile);
	
	if (tmp_uc == NULL) {
		debug(D_LOG_DEBUG, "Profile %d undefined", profile);
		_http_output(node->fd, "User Class not defined");
		node->fd = 0;
		pthread_mutex_unlock(&nodes_mutex);
		return;
	} else {
		debug(D_LOG_DEBUG, "Profile %d UserClasses retrieved", profile);
	}
	
	if (tmp_uc->active) {
		/* Profile is active */
		
		tmp_ur = new_userrights();
		tmp_ur->profile = profile;
		tmp_ur->start_time = time(NULL);
		tmp_ur->last_checked = time(NULL);
		tmp_ur->end_time = tmp_ur->start_time + (time_t)tmp_uc->timeout;
		
		fw_allow(node->ip, node->mac, profile);
		
		node->active = 1;
		node->rights = tmp_ur;
		
		_http_output(node->fd, "You are now good to go");
	} else {
		_http_output(node->fd, "User Class inactive");
	}
	
	node->fd = 0;

	pthread_mutex_unlock(&nodes_mutex);
	return;
}

/* XXX Can only be called once per connection */
static void
_http_output(int fd, char *msg)
{
	char response[] = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-"
			  "Type: text/html\r\n\r\n";
	
	send(fd, response, sizeof(response), 0);
	send(fd, msg, strlen(msg), 0);
	shutdown(fd, 2);
	close(fd);
}
