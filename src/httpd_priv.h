/*
** Copyright (c) 2002  Hughes Technologies Pty Ltd.  All rights
** reserved.
**
** Terms under which this software may be used or copied are
** provided in the  specific license associated with this product.
**
** Hughes Technologies disclaims all warranties with regard to this
** software, including all implied warranties of merchantability and
** fitness, in no event shall Hughes Technologies be liable for any
** special, indirect or consequential damages or any damages whatsoever
** resulting from loss of use, data or profits, whether in an action of
** contract, negligence or other tortious action, arising out of or in
** connection with the use or performance of this software.
**
**
** Original Id: httpd_priv.h,v 1.5 2002/11/25 02:15:51 bambi Exp
**
*/

/* $Header$ */
/** @internal
  @file httpd_priv.h
  @brief HTTP Server Non exported declaration
  @author Originally by Hughes Technologies Pty Ltd.
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
 */

/*
**  libhttpd Private Header File
*/


/***********************************************************************
** Standard header preamble.  Ensure singular inclusion, setup for
** function prototypes and c++ inclusion
*/

#ifndef LIB_HTTPD_PRIV_H

#define LIB_HTTPD_H_PRIV 1

#define	LEVEL_NOTICE	"notice"
#define LEVEL_ERROR	"error"

char * _httpd_unescape(char*);
char *_httpd_escape(char*);
char _httpd_from_hex (char);


void _httpd_catFile(httpd*, char*);
void _httpd_send403(httpd*);
void _httpd_send404(httpd*);
void _httpd_sendText(httpd*, char*);
void _httpd_sendFile(httpd*, char*);
void _httpd_sendStatic(httpd*, char*);
void _httpd_sendHeaders(httpd*, int, int);
void _httpd_sanitiseUrl(char*);
void _httpd_freeVariables(httpVar*);
void _httpd_formatTimeString(httpd*, char*, int);
void _httpd_storeData(httpd*, char*);
void _httpd_writeAccessLog(httpd*);
void _httpd_writeErrorLog(httpd*, char*, char*);


int _httpd_net_read(int, char*, int);
int _httpd_net_write(int, char*, int);
int _httpd_readBuf(httpd*, char*, int);
int _httpd_readChar(httpd*, char*);
int _httpd_readLine(httpd*, char*, int);
int _httpd_checkLastModified(httpd*, int);
int _httpd_sendDirectoryEntry(httpd*, httpContent*, char*);

httpContent *_httpd_findContentEntry(httpd*, httpDir*, char*);
httpDir *_httpd_findContentDir(httpd*, char*, int);

#endif  /* LIB_HTTPD_PRIV_H */
