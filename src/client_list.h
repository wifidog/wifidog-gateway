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
/** @file client_list.h
    @brief Client List functions
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

/**
 * Counters struct for a client's bandwidth usage (in bytes)
 */
typedef struct _t_counters {
    long long	incoming;	/**< Incoming data */
    long long	outgoing;	/**< Outgoing data */
    time_t	last_updated;	/**< Last update of the counters */
} t_counters;

/**
 * Client node for the connected client linked list.
 */
typedef struct	_t_client {
	struct	_t_client *next;
	char	*ip;			/**< Client Ip address */
	char	*mac;			/**< Client Mac address */
	char	*token;			/**< Client token */
	unsigned int fw_connection_state;	/**< Connection state in the
						     firewall */
	int	fd;			/**< Client HTTP socket (valid only
					     during login before one of the
					     _http_* function is called */
	t_counters	counters;	/**< Counters for input/output of
					     the client. */
} t_client;

void client_list_init(void);
t_client *client_list_add(char *ip, char *mac, char *token);
t_client *client_list_find(char *ip, char *mac);
t_client *client_list_find_by_ip(char *ip); /* needed by iptables.c */
t_client *client_list_find_by_token(char *token);
void client_list_delete(t_client *client);
void client_list_free_node(t_client *client);

#endif /* _CLIENT_LIST_H_ */

