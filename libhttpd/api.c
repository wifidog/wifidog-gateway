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
** $Id$
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <unistd.h> 
#include <sys/file.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h>
#include <sys/socket.h> 
#include <netdb.h>
#endif

#include "config.h"
#include "httpd.h"
#include "httpd_priv.h"

#ifdef HAVE_STDARG_H
#  include <stdarg.h>
#else
#  include <varargs.h>
#endif


char *httpdUrlEncode(str)
	char	*str;
{
        char    *new,
                *cp;

        new = (char *)_httpd_escape(str);
	if (new == NULL)
	{
		return(NULL);
	}
        cp = new;
        while(*cp)
        {
                if (*cp == ' ')
                        *cp = '+';
                cp++;
        }
	return(new);
}



char *httpdRequestMethodName(server)
	httpd	*server;
{
	static	char	tmpBuf[255];

	switch(server->request.method)
	{
		case HTTP_GET: return("GET");
		case HTTP_POST: return("POST");
		default: 
			snprintf(tmpBuf,255,"Invalid method '%d'", 
				server->request.method);
			return(tmpBuf);
	}
}


httpVar *httpdGetVariableByName(server, name)
	httpd	*server;
	char	*name;
{
	httpVar	*curVar;

	curVar = server->variables;
	while(curVar)
	{
		if (strcmp(curVar->name, name) == 0)
			return(curVar);
		curVar = curVar->nextVariable;
	}
	return(NULL);
}



httpVar *httpdGetVariableByPrefix(server, prefix)
	httpd	*server;
	char	*prefix;
{
	httpVar	*curVar;

	if (prefix == NULL)
		return(server->variables);
	curVar = server->variables;
	while(curVar)
	{
		if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
			return(curVar);
		curVar = curVar->nextVariable;
	}
	return(NULL);
}


httpVar *httpdGetVariableByPrefixedName(server, prefix, name)
	httpd	*server;
	char	*prefix,
		*name;
{
	httpVar	*curVar;
	int	prefixLen;

	if (prefix == NULL)
		return(server->variables);
	curVar = server->variables;
	prefixLen = strlen(prefix);
	while(curVar)
	{
		if (strncmp(curVar->name, prefix, prefixLen) == 0 &&
			strcmp(curVar->name + prefixLen, name) == 0)
		{
			return(curVar);
		}
		curVar = curVar->nextVariable;
	}
	return(NULL);
}


httpVar *httpdGetNextVariableByPrefix(curVar, prefix)
	httpVar	*curVar;
	char	*prefix;
{
	if(curVar)
		curVar = curVar->nextVariable;
	while(curVar)
	{
		if (strncmp(curVar->name, prefix, strlen(prefix)) == 0)
			return(curVar);
		curVar = curVar->nextVariable;
	}
	return(NULL);
}


int httpdAddVariable(server, name, value)
	httpd	*server;
	char	*name,
		*value;
{
	httpVar *curVar, *lastVar, *newVar;

	while(*name == ' ' || *name == '\t')
		name++;
	newVar = malloc(sizeof(httpVar));
	bzero(newVar, sizeof(httpVar));
	newVar->name = strdup(name);
	newVar->value = strdup(value);
	lastVar = NULL;
	curVar = server->variables;
	while(curVar)
	{
		if (strcmp(curVar->name, name) != 0)
		{
			lastVar = curVar;
			curVar = curVar->nextVariable;
			continue;
		}
		while(curVar)
		{
			lastVar = curVar;
			curVar = curVar->nextValue;
		}
		lastVar->nextValue = newVar;
		return(0);
	}
	if (lastVar)
		lastVar->nextVariable = newVar;
	else
		server->variables = newVar;
	return(0);
}

httpd *httpdCreate(host, port)
	char	*host;
	int	port;
{
	httpd	*new;
	int	sock,
		opt;
        struct  sockaddr_in     addr;

	/*
	** Create the handle and setup it's basic config
	*/
	new = malloc(sizeof(httpd));
	if (new == NULL)
		return(NULL);
	bzero(new, sizeof(httpd));
	new->port = port;
	if (host == HTTP_ANY_ADDR)
		new->host = HTTP_ANY_ADDR;
	else
		new->host = strdup(host);
	new->content = (httpDir*)malloc(sizeof(httpDir));
	bzero(new->content,sizeof(httpDir));
	new->content->name = strdup("");

	/*
	** Setup the socket
	*/
#ifdef _WIN32
	{ 
	WORD 	wVersionRequested;
	WSADATA wsaData;
	int 	err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	
	/* Found a usable winsock dll? */
	if( err != 0 ) 
	   return NULL;

	/* 
	** Confirm that the WinSock DLL supports 2.2.
	** Note that if the DLL supports versions greater 
	** than 2.2 in addition to 2.2, it will still return
	** 2.2 in wVersion since that is the version we
	** requested.
	*/

	if( LOBYTE( wsaData.wVersion ) != 2 || 
	    HIBYTE( wsaData.wVersion ) != 2 ) {

		/* 
		** Tell the user that we could not find a usable
		** WinSock DLL.
		*/
		WSACleanup( );
		return NULL;
	}

	/* The WinSock DLL is acceptable. Proceed. */
 	}
#endif

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock  < 0)
	{
		free(new);
		return(NULL);
	}
#	ifdef SO_REUSEADDR
	opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt,sizeof(int));
#	endif
	new->serverSock = sock;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	if (new->host == HTTP_ANY_ADDR)
	{
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		addr.sin_addr.s_addr = inet_addr(new->host);
	}
	addr.sin_port = htons((u_short)new->port);
	if (bind(sock,(struct sockaddr *)&addr,sizeof(addr)) <0)
	{
		close(sock);
		free(new);
		return(NULL);
	}
	listen(sock, 128);
	new->startTime = time(NULL);
	return(new);
}

void httpdDestroy(server)
	httpd	*server;
{
	if (server == NULL)
		return;
	if (server->host)
		free(server->host);
	free(server);
}



int httpdGetConnection(server, timeout)
	httpd	*server;
	struct	timeval *timeout;
{
	int	result;
	fd_set	fds;
	struct  sockaddr_in     addr;
	size_t  addrLen;
	char	*ipaddr;

	FD_ZERO(&fds);
	FD_SET(server->serverSock, &fds);
	result = 0;
	while(result == 0)
	{
		result = select(server->serverSock + 1, &fds, 0, 0, timeout);
		if (result < 0)
		{
			return(-1);
		}
		if (timeout != 0 && result == 0)
		{
			return(0);
		}
		if (result > 0)
		{
			break;
		}
	}
	bzero(&addr, sizeof(addr));
	addrLen = sizeof(addr);
	server->clientSock = accept(server->serverSock,(struct sockaddr *)&addr,
		&addrLen);
	ipaddr = inet_ntoa(addr.sin_addr);
	if (ipaddr)
		strncpy(server->clientAddr, ipaddr, HTTP_IP_ADDR_LEN);
	else
		*server->clientAddr = 0;
	server->readBufRemain = 0;
	server->readBufPtr = NULL;

	/*
	** Check the default ACL
	*/
	if (server->defaultAcl)
	{
		if (httpdCheckAcl(server, server->defaultAcl) == HTTP_ACL_DENY)
		{
			httpdEndRequest(server);
			return(-2);
		}
	}
	return(1);
}



int httpdReadRequest(server)
	httpd	*server;
{
	static	char	buf[HTTP_MAX_LEN];
	int	count,
		inHeaders;
	char	*cp, *cp2;
	int	_httpd_decode();


	/*
	** Setup for a standard response
	*/
	strcpy(server->response.headers,
		"Server: Hughes Technologies Embedded Server\n"); 
	strcpy(server->response.contentType, "text/html");
	strcpy(server->response.response,"200 Output Follows\n");
	server->response.headersSent = 0;


	/*
	** Read the request
	*/
	count = 0;
	inHeaders = 1;
	while(_httpd_readLine(server, buf, HTTP_MAX_LEN) > 0)
	{
		count++;

		/*
		** Special case for the first line.  Scan the request
		** method and path etc
		*/
		if (count == 1)
		{
			/*
			** First line.  Scan the request info
			*/
			cp = cp2 = buf;
			while(isalpha(*cp2))
				cp2++;
			*cp2 = 0;
			if (strcasecmp(cp,"GET") == 0)
				server->request.method = HTTP_GET;
			if (strcasecmp(cp,"POST") == 0)
				server->request.method = HTTP_POST;
			if (server->request.method == 0)
			{
				_httpd_net_write( server->clientSock,
				      HTTP_METHOD_ERROR,
				      strlen(HTTP_METHOD_ERROR));
				_httpd_net_write( server->clientSock, cp, 
				      strlen(cp));
				_httpd_writeErrorLog(server,LEVEL_ERROR, 
					"Invalid method received");
				return(-1);
			}
			cp = cp2+1;
			while(*cp == ' ')
				cp++;
			cp2 = cp;
			while(*cp2 != ' ' && *cp2 != 0)
				cp2++;
			*cp2 = 0;
			strncpy(server->request.path,cp,HTTP_MAX_URL);
			_httpd_sanitiseUrl(server->request.path);
			continue;
		}

		/*
		** Process the headers
		*/
		if (inHeaders)
		{
			if (*buf == 0)
			{
				/*
				** End of headers.  Continue if there's
				** data to read
				*/
				if (server->request.contentLength == 0)
					break;
				inHeaders = 0;
				break;
			}
            /**
             * Philippe commenting this out, it crashed with a
             * particular pattern sent from the browser
             * and we don't need it
			if (strncasecmp(buf,"Cookie: ",7) == 0)
			{
				char	*var,
					*val,
					*end;

				var = index(buf,':');
				while(var)
				{
					var++;
					val = index(var, '=');
					*val = 0;
					val++;
					end = index(val,';');
					if(end)
						*end = 0;
					httpdAddVariable(server, var, val);
					var = end;
				}
			}
            */
			if (strncasecmp(buf,"Authorization: ",15) == 0)
			{
				cp = index(buf,':') + 2;
				if (strncmp(cp,"Basic ", 6) != 0)
				{
					/* Unknown auth method */
				}
				else
				{
					char 	authBuf[100];

					cp = index(cp,' ') + 1;
					_httpd_decode(cp, authBuf, 100);
					server->request.authLength = 
						strlen(authBuf);
					cp = index(authBuf,':');
					if (cp)
					{
						*cp = 0;
						strncpy(
						   server->request.authPassword,
						   cp+1, HTTP_MAX_AUTH);
					}
					strncpy(server->request.authUser, 
						authBuf, HTTP_MAX_AUTH);
				}
			}
			if (strncasecmp(buf,"Referer: ",9) == 0)
			{
				cp = index(buf,':') + 2;
				if(cp)
				{
					strncpy(server->request.referer,cp,
						HTTP_MAX_URL);
				}
			}
			if (strncasecmp(buf,"If-Modified-Since: ",19) == 0)
			{
				cp = index(buf,':') + 2;
				if(cp)
				{
					strncpy(server->request.ifModified,cp,
						HTTP_MAX_URL);
					cp = index(server->request.ifModified,
						';');
					if (cp)
						*cp = 0;
				}
			}
			if (strncasecmp(buf,"Content-Type: ",14) == 0)
			{
				cp = index(buf,':') + 2;
				if(cp)
				{
					strncpy(server->request.contentType,cp,
						HTTP_MAX_URL);
				}
			}
			if (strncasecmp(buf,"Content-Length: ",16) == 0)
			{
				cp = index(buf,':') + 2;
				if(cp)
					server->request.contentLength=atoi(cp);
			}
			continue;
		}
	}

	/*
	** Process and POST data
	*/
	if (server->request.contentLength > 0)
	{
		bzero(buf, HTTP_MAX_LEN);
		_httpd_readBuf(server, buf, server->request.contentLength);
		_httpd_storeData(server, buf);
		
	}

	/*
	** Process any URL data
	*/
	cp = index(server->request.path,'?');
	if (cp != NULL)
	{
		*cp = 0;
		cp++;
		_httpd_storeData(server, cp);
	}
	return(0);
}


void httpdEndRequest(server)
	httpd	*server;
{
	_httpd_freeVariables(server->variables);
	server->variables = NULL;
	shutdown(server->clientSock,2);
	close(server->clientSock);
	bzero(&server->request, sizeof(server->request));
}


void httpdFreeVariables(server)
        httpd   *server;
{
        _httpd_freeVariables(server->variables);
}



void httpdDumpVariables(server)
	httpd	*server;
{
	httpVar	*curVar,
		*curVal;

	curVar = server->variables;
	while(curVar)
	{
		printf("Variable '%s'\n", curVar->name);
		curVal = curVar;
		while(curVal)
		{
			printf("\t= '%s'\n",curVal->value);
			curVal = curVal->nextValue;
		}
		curVar = curVar->nextVariable;
	}
}

void httpdSetFileBase(server, path)
	httpd	*server;
	char	*path;
{
	strncpy(server->fileBasePath, path, HTTP_MAX_URL);
}


int httpdAddFileContent(server, dir, name, indexFlag, preload, path)
	httpd	*server;
	char	*dir,
		*name;
	int	(*preload)();
	int	indexFlag;
	char	*path;
{
	httpDir	*dirPtr;
	httpContent *newEntry;

	dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
	newEntry =  malloc(sizeof(httpContent));
	if (newEntry == NULL)
		return(-1);
	bzero(newEntry,sizeof(httpContent));
	newEntry->name = strdup(name);
	newEntry->type = HTTP_FILE;
	newEntry->indexFlag = indexFlag;
	newEntry->preload = preload;
	newEntry->next = dirPtr->entries;
	dirPtr->entries = newEntry;
	if (*path == '/')
	{
		/* Absolute path */
		newEntry->path = strdup(path);
	}
	else
	{
		/* Path relative to base path */
		newEntry->path = malloc(strlen(server->fileBasePath) +
			strlen(path) + 2);
		snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s",
			server->fileBasePath, path);
	}
	return(0);
}



int httpdAddWildcardContent(server, dir, preload, path)
	httpd	*server;
	char	*dir;
	int	(*preload)();
	char	*path;
{
	httpDir	*dirPtr;
	httpContent *newEntry;

	dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
	newEntry =  malloc(sizeof(httpContent));
	if (newEntry == NULL)
		return(-1);
	bzero(newEntry,sizeof(httpContent));
	newEntry->name = NULL;
	newEntry->type = HTTP_WILDCARD;
	newEntry->indexFlag = HTTP_FALSE;
	newEntry->preload = preload;
	newEntry->next = dirPtr->entries;
	dirPtr->entries = newEntry;
	if (*path == '/')
	{
		/* Absolute path */
		newEntry->path = strdup(path);
	}
	else
	{
		/* Path relative to base path */
		newEntry->path = malloc(strlen(server->fileBasePath) +
			strlen(path) + 2);
		snprintf(newEntry->path, HTTP_MAX_URL, "%s/%s",
			server->fileBasePath, path);
	}
	return(0);
}




int httpdAddC404Content(server, function)
	httpd	*server;
	void	(*function)();
{
	if (!server->handle404) {
		server->handle404 = (http404*)malloc(sizeof(http404));
	}

	if (!server->handle404) {
		return(-1);
	}

	server->handle404->function = function;
	return(0);
}

int httpdAddCContent(server, dir, name, indexFlag, preload, function)
	httpd	*server;
	char	*dir;
	char	*name;
	int	(*preload)();
	void	(*function)();
{
	httpDir	*dirPtr;
	httpContent *newEntry;

		dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
	newEntry =  malloc(sizeof(httpContent));
	if (newEntry == NULL)
		return(-1);
	bzero(newEntry,sizeof(httpContent));
	newEntry->name = strdup(name);
	newEntry->type = HTTP_C_FUNCT;
	newEntry->indexFlag = indexFlag;
	newEntry->function = function;
	newEntry->preload = preload;
	newEntry->next = dirPtr->entries;
	dirPtr->entries = newEntry;
	return(0);
}


int httpdAddCWildcardContent(server, dir, preload, function)
	httpd	*server;
	char	*dir;
	int	(*preload)();
	void	(*function)();
{
	httpDir	*dirPtr;
	httpContent *newEntry;

	dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
	newEntry =  malloc(sizeof(httpContent));
	if (newEntry == NULL)
		return(-1);
	bzero(newEntry,sizeof(httpContent));
	newEntry->name = NULL;
	newEntry->type = HTTP_C_WILDCARD;
	newEntry->indexFlag = HTTP_FALSE;
	newEntry->function = function;
	newEntry->preload = preload;
	newEntry->next = dirPtr->entries;
	dirPtr->entries = newEntry;
	return(0);
}

int httpdAddStaticContent(server, dir, name, indexFlag, preload, data)
	httpd	*server;
	char	*dir;
	char	*name;
	int	(*preload)();
	char	*data;
{
	httpDir	*dirPtr;
	httpContent *newEntry;

	dirPtr = _httpd_findContentDir(server, dir, HTTP_TRUE);
	newEntry =  malloc(sizeof(httpContent));
	if (newEntry == NULL)
		return(-1);
	bzero(newEntry,sizeof(httpContent));
	newEntry->name = strdup(name);
	newEntry->type = HTTP_STATIC;
	newEntry->indexFlag = indexFlag;
	newEntry->data = data;
	newEntry->preload = preload;
	newEntry->next = dirPtr->entries;
	dirPtr->entries = newEntry;
	return(0);
}

void httpdSendHeaders(server)
	httpd	*server;
{
	_httpd_sendHeaders(server, 0, 0);
}

void httpdSetResponse(server, msg)
	httpd	*server;
	char	*msg;
{
	strncpy(server->response.response, msg, HTTP_MAX_URL);
}

void httpdSetContentType(server, type)
	httpd	*server;
	char	*type;
{
	strcpy(server->response.contentType, type);
}


void httpdAddHeader(server, msg)
	httpd	*server;
	char	*msg;
{
	strcat(server->response.headers,msg);
	if (msg[strlen(msg) - 1] != '\n')
		strcat(server->response.headers,"\n");
}

void httpdSetCookie(server, name, value)
	httpd	*server;
	char	*name,
		*value;
{
	char	buf[HTTP_MAX_URL];

	snprintf(buf,HTTP_MAX_URL, "Set-Cookie: %s=%s; path=/;", name, value);
	httpdAddHeader(server,buf);
}

void httpdOutput(server, msg)
	httpd	*server;
	char	*msg;
{
	char	buf[HTTP_MAX_LEN],
		varName[80],
		*src,
		*dest;
	int	count;

	src = msg;
	dest = buf;
	count = 0;
	while(*src && count < HTTP_MAX_LEN)
	{
		if (*src == '$')
		{
			char	*cp,
				*tmp;
			int	count2;
			httpVar	*curVar;

			tmp = src + 1;
			cp = varName;
			count2 = 0;
			while(*tmp&&(isalnum(*tmp)||*tmp == '_')&&count2 < 80)
			{
				*cp++ = *tmp++;
				count2++;
			}
			*cp = 0;
			curVar = httpdGetVariableByName(server,varName);
			if (curVar)
			{
				strcpy(dest, curVar->value);
				dest = dest + strlen(dest);
				count += strlen(dest);
			}
			else
			{
				*dest++ = '$';
				strcpy(dest, varName);
				dest += strlen(varName);
				count += 1 + strlen(varName);
			}
			src = src + strlen(varName) + 1;
			continue;
		}
		*dest++ = *src++;
		count++;
	}	
	*dest = 0;
	server->response.responseLength += strlen(buf);
	if (server->response.headersSent == 0)
		httpdSendHeaders(server);
	_httpd_net_write( server->clientSock, buf, strlen(buf));
}



#ifdef HAVE_STDARG_H
void httpdPrintf(httpd *server, char *fmt, ...)
{
#else
void httpdPrintf(va_alist)
        va_dcl
{
        httpd		*server;
        char		*fmt;
#endif
        va_list         args;
	char		buf[HTTP_MAX_LEN];

#ifdef HAVE_STDARG_H
        va_start(args, fmt);
#else
        va_start(args);
        server = (httpd *) va_arg(args, httpd * );
        fmt = (char *) va_arg(args, char *);
#endif
	if (server->response.headersSent == 0)
		httpdSendHeaders(server);
	vsnprintf(buf, HTTP_MAX_LEN, fmt, args);
	server->response.responseLength += strlen(buf);
	_httpd_net_write( server->clientSock, buf, strlen(buf));
}




void httpdProcessRequest(server)
	httpd	*server;
{
	char	dirName[HTTP_MAX_URL],
		entryName[HTTP_MAX_URL],
		*cp;
	httpDir	*dir;
	httpContent *entry;

	server->response.responseLength = 0;
	strncpy(dirName, httpdRequestPath(server), HTTP_MAX_URL);
	cp = rindex(dirName, '/');
	if (cp == NULL)
	{
		printf("Invalid request path '%s'\n",dirName);
		return;
	}
	strncpy(entryName, cp + 1, HTTP_MAX_URL);
	if (cp != dirName)
		*cp = 0;
	else
		*(cp+1) = 0;
	dir = _httpd_findContentDir(server, dirName, HTTP_FALSE);
	if (dir == NULL)
	{
		_httpd_send404(server);
		_httpd_writeAccessLog(server);
		return;
	}
	entry = _httpd_findContentEntry(server, dir, entryName);
	if (entry == NULL)
	{
		_httpd_send404(server);
		_httpd_writeAccessLog(server);
		return;
	}
	if (entry->preload)
	{
		if ((entry->preload)(server) < 0)
		{
			_httpd_writeAccessLog(server);
			return;
		}
	}
	switch(entry->type)
	{
		case HTTP_C_FUNCT:
		case HTTP_C_WILDCARD:
			(entry->function)(server);
			break;

		case HTTP_STATIC:
			_httpd_sendStatic(server, entry->data);
			break;

		case HTTP_FILE:
			_httpd_sendFile(server, entry->path);
			break;

		case HTTP_WILDCARD:
			if (_httpd_sendDirectoryEntry(server,entry,entryName)<0)
			{
				_httpd_send404(server);
			}
			break;
	}
	_httpd_writeAccessLog(server);
}

void httpdSetAccessLog(server, fp)
	httpd	*server;
	FILE	*fp;
{
	server->accessLog = fp;
}

void httpdSetErrorLog(server, fp)
	httpd	*server;
	FILE	*fp;
{
	server->errorLog = fp;
}

void httpdAuthenticate(server, realm)
	httpd	*server;
	char	*realm;
{
	char	buffer[255];

	if (server->request.authLength == 0)
	{
		httpdSetResponse(server, "401 Please Authenticate");
		snprintf(buffer,sizeof(buffer), 
			"WWW-Authenticate: Basic realm=\"%s\"\n", realm);
		httpdAddHeader(server, buffer);
		httpdOutput(server,"\n");
	}
}


void httpdForceAuthenticate(server, realm)
	httpd	*server;
	char	*realm;
{
	char	buffer[255];

	httpdSetResponse(server, "401 Please Authenticate");
	snprintf(buffer,sizeof(buffer), 
		"WWW-Authenticate: Basic realm=\"%s\"\n", realm);
	httpdAddHeader(server, buffer);
	httpdOutput(server,"\n");
}
