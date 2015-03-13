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


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "common.h"
#include "debug.h"

#ifdef USE_CYASSL
#include <cyassl/ssl.h>
#include "conf.h"
#endif

int http_get(const int sockfd, char *buf) {

	ssize_t	numbytes;
	size_t totalbytes;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;
	
	if (sockfd == -1) {
		/* Could not connect to server */
		debug(LOG_ERR, "Could not open socket to server!");
		return -1;
	}

	debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);

	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return -1;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += (size_t) numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return -1;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return -1;
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);
	return totalbytes;
}


#ifdef USE_CYASSL


int https_get(const int sockfd, char *buf, const char* hostname) {

	ssize_t	numbytes;
	size_t totalbytes;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;

	s_config *config;
	config = config_get_config();

	CyaSSL_Init();

	CYASSL_CTX* ctx;
	/* Create the CYASSL_CTX */
	/* Allow SSLv3 up to TLSv1.2 */
	if ( (ctx = CyaSSL_CTX_new(CyaSSLv23_client_method())) == NULL){
		debug(LOG_ERR, "Could not create CYASSL context.");
		return -1;
	}

	if (config->ssl_no_verify) {
		CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
		debug(LOG_INFO, "Disabling SSL certificate verification!");
	} else {
		/* Use trusted certs */
		/* Note: CyaSSL requires that the certificates are named by their hash values */
		int err = CyaSSL_CTX_load_verify_locations(ctx, NULL, config->ssl_certs);
		if (err != SSL_SUCCESS) {
			debug(LOG_ERR, "Could not load SSL certificates (error %d)", err);
			debug(LOG_ERR, "Make sure that SSLCertPath points to the correct path in the config file");
			debug(LOG_ERR, "Or disable certificate loading with SSLNoPeerVerification.");
			return -1;
		}
		debug(LOG_INFO, "Loading SSL certificates from %s", config->ssl_certs);
	}

	if (sockfd == -1) {
		/* Could not connect to server */
		debug(LOG_ERR, "Could not open socket to server!");
		return -1;
	}


	/* Create CYASSL object */
	CYASSL* ssl;
	if( (ssl = CyaSSL_new(ctx)) == NULL) {
		debug(LOG_ERR, "Could not create CYASSL context.");
		return -1;
	}
	// Turn on domain name check
	CyaSSL_check_domain_name(ssl, hostname);
	CyaSSL_set_fd(ssl, sockfd);


	debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
	if (CyaSSL_send(ssl, buf, strlen(buf), 0) != (int) strlen(buf)) {
		debug(LOG_ERR, "CyaSSL_send failed!");
		return -1;
	}

	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = CyaSSL_read(ssl, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return -1;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += (size_t) numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return -1;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return -1;
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);

	CyaSSL_free(ssl);
	CyaSSL_CTX_free(ctx);
	CyaSSL_Cleanup();

	return totalbytes;
}


#endif /* USE_CYASSL */

