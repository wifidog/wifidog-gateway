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
    @file child.c
    @brief Function for handling child sub processes
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#include "common.h"

static ChildInfo *child_list = NULL;

void
sigchld_handler(int signal)
{
	pid_t	pid;
	int	status;
	t_node	*tmp_node;
	ChildInfo	*tmp_ci;
	UserRights	*tmp_ur;
	UserClasses	*tmp_uc;
	
	pid = wait(&status);

	if (child_list == NULL)
		return; /* If we're not waiting for a pid, we still have
			   to service the signal */

	/* Prune list */

	tmp_ci = child_list;

	while (tmp_ci != NULL && tmp_ci->pid != pid)
		tmp_ci = tmp_ci->next;

	if (tmp_ci == NULL)
		return; /* No matches */
	
	if (tmp_ci == child_list) {
		if (tmp_ci->next == NULL) {
			child_list = NULL;
		} else {
			tmp_ci->next->prev = NULL;
			child_list = tmp_ci->next;
		}
	} else {
		if (tmp_ci->next == NULL) {
			tmp_ci->prev->next = NULL;
		} else {
			tmp_ci->prev->next = tmp_ci->next;
			tmp_ci->next->prev = tmp_ci->prev;
		}
	}

	/* And now, we handle the status.
	 * Statuses are unsigned chars. 0 means failure, 1 or more is the
	 * "User Class"...
	 */
	
	if (status > 0) {
		if (tmp_node = node_find_by_ip(tmp_ci->ip)) {
			/* Existing node */
			debug(D_LOG_DEBUG, "Node %s with mac %s and profile "
				"%d re-validated", tmp_ci->ip, tmp_ci->mac,
				status);
			if (tmp_node->rights->end_time < time(NULL)) {
				/* expired node */
				debug(D_LOG_DEBUG, "Connection from node %s "
					"with mac %s and profile %d has "
					"expired", tmp_ci->ip, tmp_ci->mac,
					status);
				fw_deny(tmp_ci->ip, tmp_ci->mac, status);
				node_delete(tmp_node);
			}
		} else {
			/* New node */
			debug(D_LOG_DEBUG, "Allowing %s with mac %s and "
				"profile %d", tmp_ci->ip, tmp_ci->mac, status);
			
			tmp_uc = find_userclasses(status);

			if (tmp_uc == NULL) {
				debug(D_LOG_DEBUG, "Profile %d undefined",
					status);
				return;
			}
			
			tmp_ur = new_userrights();
			tmp_ur->profile = status;
			tmp_ur->start_time = time(NULL);
			tmp_ur->end_time = tmp_ur->start_time -
						(time_t)tmp_uc->timeout;
			
			fw_allow(tmp_ci->ip, tmp_ci->mac, status);
			if (tmp_node = node_find_by_ip(tmp_ci->ip)) {
				tmp_node->active = 1;
				tmp_node->rights = tmp_ur;
			}
		}
	} else {
		/* XXX We should only get here if the UserClass has changed
		 * while the connection was active. */
		debug(D_LOG_DEBUG, "Denying %s with mac %s and profile %d", 
				tmp_ci->ip, tmp_ci->mac, status);
		if (tmp_node = node_find_by_ip(tmp_ci->ip)) {
			fw_deny(tmp_ci->ip, tmp_ci->mac, status);
			node_delete(tmp_node);
		}
	}

	free_childinfo(tmp_ci);

	return;
}

void
register_child(ChildInfo *ci)
{
	ChildInfo	*tmp_ci;

	tmp_ci = child_list;

	if (tmp_ci == NULL) {
		child_list = ci;
	} else {
		while (tmp_ci->next != NULL)
			tmp_ci = tmp_ci->next;

		tmp_ci->next = ci;
		ci->prev = tmp_ci;
	}
}

ChildInfo *
new_childinfo(void)
{
	ChildInfo	*tmp_ci;

	tmp_ci = (ChildInfo *)malloc(sizeof(ChildInfo));
	if (tmp_ci == NULL) {
		exit(-1);
	}

	memset(tmp_ci, 0, sizeof(ChildInfo));
	
	return(tmp_ci);
}

void
free_childinfo(ChildInfo *ci)
{

	if (ci->mac != NULL)
		free(ci->mac);
	
	if (ci->ip != NULL)
		free(ci->ip);

	free(ci);
}
