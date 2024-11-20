/* vim: set sw=4 ts=4 sts=4 et : */
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
#include <pthread.h>
#include <string.h>
#include <syslog.h>

#include "../config.h"
#include "common.h"
#include "debug.h"
#include "pstring.h"

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "conf.h"
#endif

#ifdef USE_WOLFSSL
static WOLFSSL_CTX *get_wolfssl_ctx(const char *hostname);
#endif

/**
 * Perform an HTTP request, caller frees both request and response,
 * NULL returned on error.
 * @param sockfd Socket to use, already connected
 * @param req Request to send, fully formatted.
 * @return char Response as a string
 */
char *
http_get(const int sockfd, const char *req)
{
    ssize_t numbytes;
    int done, nfds;
    fd_set readfds;
    struct timeval timeout;
    size_t reqlen = strlen(req);
    char readbuf[MAX_BUF];
    char *retval;
    pstr_t *response = pstr_new();

    if (sockfd == -1) {
        /* Could not connect to server */
        debug(LOG_ERR, "Could not open socket to server!");
        goto error;
    }

    debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", req);
    numbytes = send(sockfd, req, reqlen, 0);
    if (numbytes <= 0) {
        debug(LOG_ERR, "send failed: %s", strerror(errno));
        goto error;
    } else if ((size_t) numbytes != reqlen) {
        debug(LOG_ERR, "send failed: only %d bytes out of %d bytes sent!", numbytes, reqlen);
        goto error;
    }

    debug(LOG_DEBUG, "Reading response");
    done = 0;
    do {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;    /* XXX magic... 30 second is as good a timeout as any */
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);

        if (nfds > 0) {
                        /** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
            memset(readbuf, 0, MAX_BUF);
            numbytes = read(sockfd, readbuf, MAX_BUF - 1);
            if (numbytes < 0) {
                debug(LOG_ERR, "An error occurred while reading from server: %s", strerror(errno));
                goto error;
            } else if (numbytes == 0) {
                done = 1;
            } else {
                readbuf[numbytes] = '\0';
                pstr_cat(response, readbuf);
                debug(LOG_DEBUG, "Read %d bytes", numbytes);
            }
        } else if (nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            goto error;
        } else if (nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            goto error;
        }
    } while (!done);

    close(sockfd);
    retval = pstr_to_string(response);
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", retval);
    return retval;

 error:
    if (sockfd >= 0) {
        close(sockfd);
    }
    retval = pstr_to_string(response);
    free(retval);
    return NULL;
}

#ifdef USE_WOLFSSL

static WOLFSSL_CTX *wolfssl_ctx = NULL;
static pthread_mutex_t wolfssl_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOCK_WOLFSSL_CTX() do { \
	debug(LOG_DEBUG, "Locking WolfSSL Context"); \
	pthread_mutex_lock(&wolfssl_ctx_mutex); \
	debug(LOG_DEBUG, "WolfSSL Context locked"); \
} while (0)

#define UNLOCK_WOLFSSL_CTX() do { \
	debug(LOG_DEBUG, "Unlocking WolfSSL Context"); \
	pthread_mutex_unlock(&wolfssl_ctx_mutex); \
	debug(LOG_DEBUG, "WolfSSL Context unlocked"); \
} while (0)

static WOLFSSL_CTX *
get_wolfssl_ctx(const char *hostname)
{
    int err;
    WOLFSSL_CTX *ret;
    s_config *config = config_get_config();

    LOCK_WOLFSSL_CTX();

    if (NULL == wolfssl_ctx) {
        wolfSSL_Init();
        /* Create the WOLFSSL_CTX */
        /* Allow TLSv1.0 up to TLSv1.2 */
        if ((wolfssl_ctx = wolfSSL_CTX_new(wolfTLSv1_client_method())) == NULL) {
            debug(LOG_ERR, "Could not create WOLFSSL context.");
            UNLOCK_WOLFSSL_CTX();
            return NULL;
        }

        if (config->ssl_cipher_list) {
            debug(LOG_INFO, "Setting SSL cipher list to [%s]", config->ssl_cipher_list);
            err = wolfSSL_CTX_set_cipher_list(wolfssl_ctx, config->ssl_cipher_list);
            if (SSL_SUCCESS != err) {
                debug(LOG_ERR, "Could not load SSL cipher list (error %d)", err);
                UNLOCK_WOLFSSL_CTX();
                return NULL;
            }
        }

#ifdef HAVE_SNI
        if (config->ssl_use_sni) {
            debug(LOG_INFO, "Setting SSL using SNI for hostname %s",
                hostname);
            err = wolfSSL_CTX_UseSNI(wolfssl_ctx, WOLFSSL_SNI_HOST_NAME, hostname,
                      strlen(hostname));
            if (SSL_SUCCESS != err) {
                debug(LOG_ERR, "Could not setup SSL using SNI for hostname %s",
                    hostname);
                UNLOCK_WOLFSSL_CTX();
                return NULL;
            }
        }
#endif

        if (config->ssl_verify) {
            /* Use trusted certs */
            /* Note: WolfSSL requires that the certificates are named by their hash values */
            debug(LOG_INFO, "Loading SSL certificates from %s", config->ssl_certs);
            err = wolfSSL_CTX_load_verify_locations(wolfssl_ctx, NULL, config->ssl_certs);
            if (err != SSL_SUCCESS) {
                debug(LOG_ERR, "Could not load SSL certificates (error %d)", err);
                if (err == ASN_UNKNOWN_OID_E) {
                    debug(LOG_ERR, "Error is ASN_UNKNOWN_OID_E - try compiling wolfssl/wolfssl with --enable-ecc");
                } else {
                    debug(LOG_ERR, "Make sure that SSLCertPath points to the correct path in the config file");
                    debug(LOG_ERR, "Or disable certificate loading with 'SSLPeerVerification No'.");
                }
                UNLOCK_WOLFSSL_CTX();
                return NULL;
            }
        } else {
            wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);
            debug(LOG_INFO, "Disabling SSL certificate verification!");
        }
    }

    ret = wolfssl_ctx;
    UNLOCK_WOLFSSL_CTX();
    return ret;
}

/**
 * Perform an HTTPS request, caller frees both request and response,
 * NULL returned on error.
 * @param sockfd Socket to use, already connected
 * @param req Request to send, fully formatted.
 * @param hostname Hostname to use in https request. Caller frees.
 * @return char Response as a string
 */
char *
https_get(const int sockfd, const char *req, const char *hostname)
{
    ssize_t numbytes;
    int done, nfds;
    fd_set readfds;
    struct timeval timeout;
    unsigned long sslerr;
    char sslerrmsg[WOLFSSL_MAX_ERROR_SZ];
    size_t reqlen = strlen(req);
    char readbuf[MAX_BUF];
    char *retval;
    pstr_t *response = pstr_new();
    WOLFSSL *ssl = NULL;
    WOLFSSL_CTX *ctx = NULL;

    s_config *config;
    config = config_get_config();

    ctx = get_wolfssl_ctx(hostname);
    if (NULL == ctx) {
        debug(LOG_ERR, "Could not get WolfSSL Context!");
        goto error;
    }

    if (sockfd == -1) {
        /* Could not connect to server */
        debug(LOG_ERR, "Could not open socket to server!");
        goto error;
    }

    /* Create WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        debug(LOG_ERR, "Could not create WolfSSL context.");
        goto error;
    }
    if (config->ssl_verify) {
        // Turn on domain name check
        // Loading of CA certificates and verification of remote host name
        // go hand in hand - one is useless without the other.
        wolfSSL_check_domain_name(ssl, hostname);
    }
    wolfSSL_set_fd(ssl, sockfd);

    debug(LOG_DEBUG, "Sending HTTPS request to auth server: [%s]\n", req);
    numbytes = wolfSSL_send(ssl, req, (int)reqlen, 0);
    if (numbytes <= 0) {
        sslerr = (unsigned long)wolfSSL_get_error(ssl, numbytes);
        wolfSSL_ERR_error_string(sslerr, sslerrmsg);
        debug(LOG_ERR, "WolfSSL_send failed: %s", sslerrmsg);
        goto error;
    } else if ((size_t) numbytes != reqlen) {
        debug(LOG_ERR, "WolfSSL_send failed: only %d bytes out of %d bytes sent!", numbytes, reqlen);
        goto error;
    }

    debug(LOG_DEBUG, "Reading response");
    done = 0;
    do {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = 30;    /* XXX magic... 30 second is as good a timeout as any */
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);

        if (nfds > 0) {
                        /** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
            memset(readbuf, 0, MAX_BUF);
            numbytes = wolfSSL_read(ssl, readbuf, MAX_BUF - 1);
            if (numbytes < 0) {
                sslerr = (unsigned long)wolfSSL_get_error(ssl, numbytes);
                wolfSSL_ERR_error_string(sslerr, sslerrmsg);
                debug(LOG_ERR, "An error occurred while reading from server: %s", sslerrmsg);
                goto error;
            } else if (numbytes == 0) {
                /* WolfSSL_read returns 0 on a clean shutdown or if the peer closed the
                   connection. We can't distinguish between these cases right now. */
                done = 1;
            } else {
                readbuf[numbytes] = '\0';
                pstr_cat(response, readbuf);
                debug(LOG_DEBUG, "Read %d bytes", numbytes);
            }
        } else if (nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            goto error;
        } else if (nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            goto error;
        }
    } while (!done);

    close(sockfd);

    wolfSSL_free(ssl);

    retval = pstr_to_string(response);
    debug(LOG_DEBUG, "HTTPS Response from Server: [%s]", retval);
    return retval;

 error:
    if (ssl) {
        wolfSSL_free(ssl);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    retval = pstr_to_string(response);
    free(retval);
    return NULL;
}

#endif                          /* USE_WOLFSSL */
