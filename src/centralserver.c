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
  @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include "common.h"

extern s_config config;

int
authenticate(char *ip, char *mac, char *token, long int stats)
{
	int sockfd, numbytes;
	char buf[MAX_BUF];
	struct hostent *he;
	struct sockaddr_in their_addr;
	int profile;
	char *p1;

	if ((he = gethostbyname(config.authserv_hostname)) == NULL) {
		debug(D_LOG_ERR, "Failed to resolve %s via gethostbyname(): "
			"%s", config.authserv_hostname, strerror(errno));
		return(-1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		debug(D_LOG_ERR, "socket(): %s", strerror(errno));
		exit(1);
	}

	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(config.authserv_port);
	their_addr.sin_addr = *((struct in_addr *)he->h_addr);
	memset(&(their_addr.sin_zero), '\0', 8);

	debug(D_LOG_INFO, "Connecting to auth server %s on port %d", 
		config.authserv_hostname, config.authserv_port);

	if (connect(sockfd, (struct sockaddr *)&their_addr,
				sizeof(struct sockaddr)) == -1) {
		debug(D_LOG_ERR, "connect(): %s", strerror(errno));
		return(-1); /* non-fatal */
	}
	sprintf(buf, "GET %s?ip=%s&mac=%s&token=%s&stats=%ld HTTP/1.1"
		"\nHost: %s\n\n", config.authserv_path, ip, mac, token,
		stats, config.authserv_hostname);
	send(sockfd, buf, strlen(buf), 0);

	debug(D_LOG_DEBUG, "Sending HTTP request:\n#####\n%s\n#####", buf);

	if ((numbytes = recv(sockfd, buf, MAX_BUF - 1, 0)) == -1) {
		debug(D_LOG_ERR, "recv(): %s", strerror(errno));
		exit(1);
	}

	buf[numbytes] = '\0';

	close(sockfd);

	if ((p1 = strstr(buf, "Profile: "))) {
		if (sscanf(p1, "Profile: %d", &profile) == 1) {
			debug(D_LOG_INFO, "Auth server returned profile %d",
				profile);
			return(profile);
		} else {
			debug(D_LOG_WARNING, "Auth server did not return "
				"expected information");
			return(-1);
		}
	} else {
		return(-1);
	}

	return(-1);
}

