/*
 * CGI helper functions
 *
 * Copyright 2001-2003, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#define assert(a)

static char *query;	/* URL after '?' */
static int len;		/* Length of query */
#if defined(linux)
/* Use SVID search */
#define __USE_GNU
#include <search.h>
#endif

static void
unescape(char *s)
{
	unsigned int c;

	while ((s = strpbrk(s, "%+"))) {
		/* Parse %xx */
		if (*s == '%') {
			sscanf(s + 1, "%02x", &c);
			*s++ = (char) c;
			strncpy(s, s + 2, strlen(s) + 1);
		}
		/* Space is special */
		else if (*s == '+')
			*s++ = ' ';
	}
}	       

void
init_cgi(char *q)
{
	query = q;
	if (!query) {
		len = 0;
		return;
	}
	len = strlen(query);

	/* Parse into individual assignments */
	while (strsep(&q, "&;"));

	/* Unescape each assignment */
	for (q = query; q < (query + len);) {
		unescape(q);
		for (q += strlen(q); q < (query + len) && !*q; q++);
	}
}

char *
get_cgi(char *name)
{
	char *q;

	if (!query || !name)
		return NULL;

	for (q = query; q < (query + len) && q;) {
		if (!strncmp(q, name, strlen(name)) &&
		    q[strlen(name)] == '=')
			return &q[strlen(name) + 1];
		for (q += strlen(q); q < (query + len) && !*q; q++);
	}
	
	return NULL;
}
