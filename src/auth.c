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

s_config config;

static void _http_output(int fd, char *msg);

void
cleanup_thread(void *ptr)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;

	while (1) {
		timeout.tv_sec = time(NULL) + config.checkinterval;
		timeout.tv_nsec = 0;

		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

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

	node = (t_node *)ptr;

	if (node == NULL)
		return; /* Implicit pthread_exit() */

	profile = authenticate(node->ip, node->mac, node->token, 0);

	if (profile == -1) {
		// Error talking to central server
		debug(D_LOG_ERR, "Got %d from central server authenticating "
			"token %s from %s at %s", profile, node->token,
			node->ip, node->mac);
		_http_output(node->fd, "Access denied: We did not get a valid "
			"answer from the central server");
		node->fd = 0;
		return;
	} else if (profile == 0) {
		// Central server said invalid token
		_http_output(node->fd, "Your authentication has failed or "
			"timed-out.  Please re-login");
		node->fd = 0;
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
		return;
	} else {
		debug(D_LOG_DEBUG, "Profile %d UserClasses retrieved", profile);
	}
	
	if (tmp_uc->active) {
		/* Profile is active */
		
		tmp_ur = new_userrights();
		tmp_ur->profile = profile;
		tmp_ur->start_time = time(NULL);
		tmp_ur->end_time = tmp_ur->start_time + (time_t)tmp_uc->timeout;
		
		fw_allow(node->ip, node->mac, profile);
		
		node->active = 1;
		node->rights = tmp_ur;
		
		_http_output(node->fd, "You are now good to go");
	} else {
		_http_output(node->fd, "User Class inactive");
	}
	
	node->fd = 0;

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
