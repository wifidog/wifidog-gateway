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
    @file http.c
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"

extern s_config config;

extern fd_set master;

void
http_request(int sockfd, struct sockaddr_in their_addr)
{
    char buffer[MAX_BUF], request[MAX_BUF];
    char line[MAX_BUF], header[MAX_BUF];
    char body[MAX_BUF];
    char *token;
    void *p1, *p2;
    char *p3, *p4;
    int r_get = 0, r_token = 0, s, rc, profile;
    time_t cur_time;
    char *ip, *mac;

    cur_time = time(NULL);

    p1 = request;

    do {
        s = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        memcpy(p1, buffer, s);
        p1 += s;
    } while(!(p2 = strstr(request, "\r\n\r\n")) && s);
    request[(int)p2 - (int)request + 2] = '\0';

    if ((p1 = strstr(request, "\r\n"))) {
        memcpy(line, request, (int)p1 - (int)request);
        line[(int)p1 - (int)request] = '\0';
        if ((strncasecmp(line, "GET", 3) == 0) ||
                (strncasecmp(line, "POST", 4) == 0) ||
                (strncasecmp(line, "HEAD", 4) == 0)) {
            r_get = 1;
            if (strstr(line, "/auth") && (p3 = strchr(line, '?')) != NULL) {
                if ((p4 = strchr(p3, ' '))) {
                    p4[0] = '\0';
                }
                if ((p4 = strchr(p3, '\n'))) {
                    p4[0] = '\0';
                }
                init_cgi(p3 + 1);
                if ((token = get_cgi("token")) && (strlen(token) > 0)) {
                    r_token = 1;
                }
            }
        }
    }

    if (r_get && r_token) {
        ip = inet_ntoa(their_addr.sin_addr);
        mac = arp_get(ip);

        /* We will respond with a 200 all the time */
        http_header(header, 200, "OK", NULL);

        if (!mac) {
            http_body(body, "I could not find your hardware address for your IP address %s, please report this error to the systems administrator", ip);
        } else {
            if ((profile = auth(ip, mac, token, 0)) != -1) {
                /* Authentication succesful */
                if (profile == 0) {
                    http_body(body, "This token is not valid anymore");
                } else {
                    if ((rc = fw_allow(ip, mac, profile)) == 0) {
                        http_body(body, "You %s at %s, have been granted profile %d!", ip, mac, profile);

                        /* Add client's IP and token into a linked list so we can keep
                         * track of it on the auth server, only if he's not there already */
                        if (!node_find_by_ip(ip)) {
                            node_add(ip, mac, token, 0);
                        }
                    } else {
                        http_body(body, "Authentication was succesful, but the firewall could not be modified, I got return code %d, please contact the systems administrators");
                    }
                }
            } else {
                /* Authentication unsuccesful */
                http_body(body, "Access denied because we did not get a valid answer from the authentication server");
            }
        }
    } else if (r_get) {
        char newlocation[MAX_BUF];
        sprintf(newlocation, "%s?gw_address=%s&gw_port=%d&gw_id=%s", config.authserv_loginurl, config.gw_address, config.gw_port, config.gw_id);

        /* If we got a GET/POST/HEAD but no token, redirect */
        http_header(header, 302, "Found", "Location: %s", newlocation);
        http_body(body, "This document has moved <a href=\"%s\">here</a>", newlocation);
        debug(D_LOG_INFO, "302 - %s - %s", inet_ntoa(their_addr.sin_addr), newlocation);
    } else {
        /* Else, error page */
        http_header(header, 500, "Error", NULL);
        http_body(body, "I could not understand your request");
        debug(D_LOG_INFO, "500 - %s", inet_ntoa(their_addr.sin_addr));
    }
    sock_send(sockfd, header);
    sock_send(sockfd, body);
    
    debug(D_LOG_INFO, "Closing connection to %s", inet_ntoa(their_addr.sin_addr));
    close(sockfd);
    FD_CLR(sockfd, &master);
}

void
http_header(char *buffer, int code, char *code_msg, char *fmt, ...)
{
    va_list ap;
    char tmp[MAX_BUF];

    sprintf(buffer, "HTTP/1.1 %d %s\n", code, code_msg);
    sprintf(tmp, "Server: %s\n", config.httpdname);
    strcat(buffer, tmp);
    sprintf(tmp, "Date: %s\n", gmtdate());
    strcat(buffer, tmp);

    if (fmt) {
        va_start(ap, fmt);
        vsprintf(tmp, fmt, ap);
        va_end(ap);
        strcat(buffer, tmp);
        strcat(buffer, "\n");
    }

    strcat(buffer, "Content-Type: text/html\n");
    strcat(buffer, "Connection: close\n\n");
}

void
http_body(char *body, char *fmt, ...)
{
    va_list ap;
    char tmp[MAX_BUF];

    strcpy(body, "<HTML><HEAD></HEAD><BODY>");

    va_start(ap, fmt);
    vsprintf(tmp, fmt, ap);
    va_end(ap);

    strcat(body, tmp);
    strcat(body, "</BODY></HTML>\n\n");
}

void
sock_send(int sockfd, char *buffer)
{
    send(sockfd, buffer, strlen(buffer), 0);
}

char *
gmtdate()
{
    char *strdate;
    time_t rawtime;
    struct tm *tmtime;

    strdate = (char *)malloc(255);

    time(&rawtime);
    tmtime = gmtime(&rawtime);
    strftime(strdate, 255, "%a, %d %b %Y %T %Z", tmtime);

    return strdate;
}

int
auth(char *ip, char *mac, char *token, long int stats)
{
        int sockfd, numbytes;
        char buf[MAX_BUF];
        struct hostent *he;
        struct sockaddr_in their_addr;
        int profile;
        char *p1;

        if ((he = gethostbyname(config.authserv_hostname)) == NULL) {
            debug(D_LOG_ERR, "gethostbyname(): %s", strerror(errno));
            exit(1);
        }

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            debug(D_LOG_ERR, "socket(): %s", strerror(errno));
            exit(1);
        }

        their_addr.sin_family = AF_INET;
        their_addr.sin_port = htons(config.authserv_port);
        their_addr.sin_addr = *((struct in_addr *)he->h_addr);
        memset(&(their_addr.sin_zero), '\0', 8);

        debug(D_LOG_DEBUG, "Connecting to auth server %s on port %d", config.authserv_hostname, config.authserv_port);

        if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
            debug(D_LOG_ERR, "connect(): %s", strerror(errno));
            exit(1);
        }

        sprintf(buf, "GET %s?ip=%s&mac=%s&token=%s&stats=%ld HTTP/1.1\nHost: %s\n\n", config.authserv_path, ip, mac, token, stats, config.authserv_hostname);
        sock_send(sockfd, buf);

        debug(D_LOG_DEBUG, "Sending HTTP request:\n#####\n%s\n#####", buf);
        
        if ((numbytes = recv(sockfd, buf, MAX_BUF - 1, 0)) == -1) {
            debug(D_LOG_ERR, "recv(): %s", strerror(errno));
            exit(1);
        }

        buf[numbytes] = '\0';

        close(sockfd);

        if ((p1 = strstr(buf, "Profile: "))) {
            if (sscanf(p1, "Profile: %d", &profile) == 1) {
                debug(D_LOG_DEBUG, "Auth server returned profile %d", profile);
                return(profile);
            } else {
                debug(D_LOG_DEBUG, "Auth server did not return expected information");
                return(-1);
            }
        } else {
            return(-1);
        }

        close(sockfd);

    return(-1);
}

