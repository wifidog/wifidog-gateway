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
    @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"

extern s_config config;

void
_debug(char *filename, int line, int level, char *format, ...)
{
    va_list vlist;

    if (config.debuglevel >= level) {
        va_start(vlist, format);

        if (level <= LOG_WARNING) {
            fprintf(stderr, "[%d](%s:%d) ", level, filename, line);
            vfprintf(stderr, format, vlist);
            fputc('\n', stderr);
        } else if (!config.daemon) {
            fprintf(stdout, "[%d](%s:%d) ", level, filename, line);
            vfprintf(stdout, format, vlist);
            fputc('\n', stdout);
            fflush(stdout);
        }

        if (config.log_syslog) {
            openlog("wifidog", LOG_PID, config.syslog_facility);
            vsyslog(level, format, vlist);
            closelog();
        }
    }
}

