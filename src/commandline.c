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
    @file commandline.c
    @brief Command line argument handling
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"

extern s_config config;

/**
 * @brief Print usage
 *
 * Prints usage, called when wifidog is run with -h or with an unknown option
 */
void
usage(void)
{
    printf("Usage: wifidog [options]\n");
    printf("\n");
    printf("  -c [filename] Use this config file\n");
    printf("  -f            Run in foreground\n");
    printf("  -p            TCP port to listen on\n");
    printf("  -d <level>    Debug level\n");
    printf("  -s            Log to syslog\n");
    printf("  -h            Print usage\n");
    printf("\n");
}

/**
 * @brief Parse the command line and set the config accordingly
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    int c;

    while (-1 != (c = getopt(argc, argv, "c:hfp:d:s"))) {
        switch(c) {
            case 'h':
                usage();
                exit(1);
                break;

            case 'c':
                if (optarg) {
                    config.configfile = optarg;
                }
                break;

            case 'f':
                config.daemon = 0;
                break;

            case 'p':
                if (optarg) {
                    config.gw_port = atoi(optarg);
                }
                break;

            case 'd':
                if (optarg) {
                    config.debuglevel = atoi(optarg);
                }
                break;

            case 's':
                config.log_syslog = 1;
                break;

            default:
                usage();
                exit(1);
                break;
        }
    }
}

