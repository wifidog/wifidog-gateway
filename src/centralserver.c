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
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>

#include "common.h"

#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "../config.h"

/* Defined in conf.h */

/** Initiates a transaction with the auth server, either to authenticate or to update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* #defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
int
auth_server_request(t_authresponse *authresponse, char *request_type, char *ip, char *mac, char *token, long int incoming, long int outgoing)
{
	int sockfd;
        size_t	numbytes, totalbytes;
	char buf[MAX_BUF];
	struct hostent *he;
	struct sockaddr_in their_addr;
	char *tmp;
	s_config *config = config_get_config();

	if ((he = gethostbyname(config->auth_servers->authserv_hostname)) == NULL) {
		debug(LOG_ERR, "Failed to resolve %s via gethostbyname(): "
			"%s", config->auth_servers->authserv_hostname, strerror(errno));
		return(-1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
		exit(1);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(config->auth_servers->authserv_port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));

	debug(LOG_INFO, "Connecting to auth server %s on port %d", 
		config->auth_servers->authserv_hostname, 
		config->auth_servers->authserv_port);

	if (connect(sockfd, (struct sockaddr *)&their_addr,
				sizeof(struct sockaddr)) == -1) {
		debug(LOG_ERR, "connect(): %s", strerror(errno));
		return(-1); /* non-fatal */
	}
	/**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
	sprintf(buf, "GET %s?stage=%s&ip=%s&mac=%s&token=%s&incoming=%ld&outgoing=%ld HTTP/1.0\n"
                "User-Agent: WiFiDog %s\n"
                "Host: %s\n"
                "\n",
            config->authserv_path, request_type, ip, mac, 
	    token, incoming, outgoing, VERSION, 
	    config->auth_servers->authserv_hostname);
	send(sockfd, buf, strlen(buf), 0);

	debug(LOG_DEBUG, "Sending HTTP request to auth server: %s\n", buf);

	numbytes = totalbytes = 0;
	while ((numbytes = read(sockfd, buf + totalbytes, 
				MAX_BUF - (totalbytes + 1))) > 0)
		totalbytes =+ numbytes;
	
	if (numbytes == -1) {
		debug(LOG_ERR, "read(): %s", strerror(errno));
		exit(1);
	}

	numbytes = totalbytes;
	
	buf[numbytes] = '\0';

	close(sockfd);

	if ((tmp = strstr(buf, "Auth: "))) {
		if (sscanf(tmp, "Auth: %d", &authresponse->authcode) == 1) {
			debug(LOG_INFO, "Auth server returned authentication code %d",
				authresponse->authcode);
			return(authresponse->authcode);
		} else {
			debug(LOG_WARNING, "Auth server did not return expected information");
			return(AUTH_ERROR);
		}
	} else {
		return(AUTH_ERROR);
	}

	return(AUTH_ERROR);
}

