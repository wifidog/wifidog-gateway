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

/*
 * $Header: /cvsroot/wifidog/wifidog/src/firewall.c,v 1.32 2004/04/23
 * 11:37:43 aprilp Exp $
 */
/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <string.h>

#include "util.h"
#include "conf.h"
#include "debug.h"

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(char *cmd_line, int quiet)
{
    int pid,
        status,
        rc;

    const char *new_argv[4];
    new_argv[0] = "/bin/sh";
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    if ((pid = fork()) < 0) {    /* fork a child process           */
        debug(LOG_ERR, "fork(): %s", strerror(errno));
        exit(1);
    } else if (pid == 0) {    /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet) close(2);
        if (execvp("/bin/sh", (char *const *)new_argv) < 0) {    /* execute the command  */
            debug(LOG_ERR, "fork(): %s", strerror(errno));
            exit(1);
        }
    } else {        /* for the parent:      */
        do {
            rc = wait(&status);
        } while (rc != pid && rc != -1);    /* wait for completion  */
    }

    return (WEXITSTATUS(status));
}
