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
** Original Id: httpd.h,v 1.10 2002/11/25 02:15:51 bambi Exp
**
*/

/* $Header$ */
/** @internal
  @file httpd.h
  @brief HTTP Server Exported API declarations
  @author Originally by Hughes Technologies Pty Ltd.
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
 */

/*
**  libhttpd Header File
*/


/***********************************************************************
** Standard header preamble.  Ensure singular inclusion, setup for
** function prototypes and c++ inclusion
*/

#ifndef LIB_HTTPD_H

#define LIB_HTTPD_H 1

/***********************************************************************
** Macro Definitions
*/

#define	HTTP_PORT 		80
#define HTTP_MAX_LEN		10240
#define HTTP_MAX_URL		1024
#define HTTP_MAX_HEADERS	1024
#define HTTP_MAX_AUTH		128
#define	HTTP_IP_ADDR_LEN	17
#define	HTTP_TIME_STRING_LEN	40
#define	HTTP_READ_BUF_LEN	4096
#define	HTTP_ANY_ADDR		NULL

#define	HTTP_GET		1
#define	HTTP_POST		2

#define	HTTP_TRUE		1
#define HTTP_FALSE		0

#define	HTTP_FILE		1
#define HTTP_C_FUNCT		2
#define HTTP_EMBER_FUNCT	3
#define HTTP_STATIC		4
#define HTTP_WILDCARD		5
#define HTTP_C_WILDCARD		6

#define HTTP_METHOD_ERROR "\n<B>ERROR : Method Not Implemented</B>\n\n"

#define httpdRequestMethod(s) 		s->request.method
#define httpdRequestPath(s)		s->request.path
#define httpdRequestContentType(s)	s->request.contentType
#define httpdRequestContentLength(s)	s->request.contentLength

#define HTTP_ACL_PERMIT		1
#define HTTP_ACL_DENY		2



/***********************************************************************
** Type Definitions
*/

typedef	struct {
	int	method,
		contentLength,
		authLength;
	char	path[HTTP_MAX_URL],
		userAgent[HTTP_MAX_URL],
		referer[HTTP_MAX_URL],
		ifModified[HTTP_MAX_URL],
		contentType[HTTP_MAX_URL],
		authUser[HTTP_MAX_AUTH],
		authPassword[HTTP_MAX_AUTH];
} httpReq;


typedef struct _httpd_var{
	char	*name,
		*value;
	struct	_httpd_var 	*nextValue,
				*nextVariable;
} httpVar;

typedef struct _httpd_content{
	char	*name;
	int	type,
		indexFlag;
	void	(*function)();
	char	*data,
		*path;
	int	(*preload)();
	struct	_httpd_content 	*next;
} httpContent;

typedef struct {
	int		responseLength;
	httpContent	*content;
	char		headersSent,
			headers[HTTP_MAX_HEADERS],
			response[HTTP_MAX_URL],
			contentType[HTTP_MAX_URL];
} httpRes;


typedef struct _httpd_dir{
	char	*name;
	struct	_httpd_dir *children,
			*next;
	struct	_httpd_content *entries;
} httpDir;


typedef struct ip_acl_s{
        int     addr;
        char    len,
                action;
        struct  ip_acl_s *next;
} httpAcl;

typedef struct _httpd_404 {
	void	(*function)();
} http404;

typedef struct {
	int	port,
		serverSock,
		clientSock,
		readBufRemain,
		startTime;
	char	clientAddr[HTTP_IP_ADDR_LEN],
		fileBasePath[HTTP_MAX_URL],
		readBuf[HTTP_READ_BUF_LEN + 1],
		*host,
		*readBufPtr;
	httpReq	request;
	httpRes response;
	httpVar	*variables;
	httpDir	*content;
	httpAcl	*defaultAcl;
	http404  *handle404;
	FILE	*accessLog,
		*errorLog;
} httpd;



/***********************************************************************
** Function Prototypes
*/


int httpdAddCContent(httpd*,char*,char*,int,int(*)(),void(*)());
int httpdAddFileContent(httpd*,char*,char*,int,int(*)(),char*);
int httpdAddStaticContent(httpd*,char*,char*,int,int(*)(),char*);
int httpdAddWildcardContent(httpd*,char*,int(*)(),char*);
int httpdAddCWildcardContent(httpd*,char*,int(*)(),void(*)());
int httpdAddVariable(httpd*,char*, char*);
int httpdGetConnection(httpd*, struct timeval*);
int httpdReadRequest(httpd*);
int httpdCheckAcl(httpd*, httpAcl*);
int httpdAddC404Content(httpd*,void(*)());

char *httpdRequestMethodName(httpd*);
char *httpdUrlEncode(char *);

void httpdAddHeader(httpd*, char*);
void httpdSetContentType(httpd*, char*);
void httpdSetResponse(httpd*, char*);
void httpdEndRequest(httpd*);

httpd *httpdCreate();
void httpdFreeVariables(httpd*);
void httpdDumpVariables(httpd*);
void httpdOutput(httpd*, char*);
void httpdPrintf(httpd*, char*, ...);
void httpdProcessRequest(httpd*);
void httpdSendHeaders(httpd*);
void httpdSetFileBase(httpd*, char*);
void httpdSetCookie(httpd*, char*, char*);

void httpdSetErrorLog(httpd*, FILE*);
void httpdSetAccessLog(httpd*, FILE*);
void httpdSetDefaultAcl(httpd*, httpAcl*);

httpVar	*httpdGetVariableByName(httpd*, char*);
httpVar	*httpdGetVariableByPrefix(httpd*, char*);
httpVar	*httpdGetVariableByPrefixedName(httpd*, char*, char*);
httpVar *httpdGetNextVariableByPrefix(httpVar*, char*);

httpAcl *httpdAddAcl(httpd*, httpAcl*, char*, int);


/***********************************************************************
** Standard header file footer.  
*/

#endif /* file inclusion */
