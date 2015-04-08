/* vim: set et sw=4 ts=4 sts=4 : */
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

/** @file capabilities.c
    @author Copyright (C) 2015 Michael Haas <haas@computerlinguist.org>
*/

#include "../config.h"

#ifdef USE_LIBCAP

#include <errno.h>

#include <syslog.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
/* FILE and popen */
#include <stdio.h>
/* For strerror */
#include <string.h>
/* For exit */
#include <stdlib.h>
/* For getpwnam */
#include <pwd.h>
/* For getgrnam */
#include <grp.h>

#include "capabilities.h"
#include "debug.h"
#include "safe.h"

/**
 * Switches to non-privileged user and drops unneeded capabilities.
 *
 * Wifidog does not need to run as root. The only capabilities required
 * are:
 *  - CAP_NET_RAW: get IP addresses from sockets, ICMP ping
 *  - CAP_NET_ADMIN: modify firewall rules
 *
 * This function drops all other capabilities. As only the effective
 * user id is set, it is theoretically possible for an attacker to
 * regain root privileges.
 * Any processes started with execve will
 * have UID0. This is a convenient side effect to allow for proper
 * operation of iptables.
 *
 * Any error is considered fatal and exit() is called.
 *
 * @param user Non-privileged user
 * @param group Non-privileged group
 */
void
drop_privileges(const char *user, const char *group)
{
    int ret = 0;
    debug(LOG_DEBUG, "Entered drop_privileges");

    /*
     * We are about to drop our effective UID to a non-privileged user.
     * This clears the EFFECTIVE capabilities set, so we later re-enable
     * re-enable these. We can do that because they are not cleared from
     * the PERMITTED set.
     * Note: if we used setuid() instead of seteuid(), we would have lost the
     * PERMITTED set as well. In this case, we would need to call prctl
     * with PR_SET_KEEPCAPS.
     */
    set_user_group(user, group);
    /* The capabilities we want.
     * CAP_NET_RAW is used for our socket handling.
     * CAP_NET_ADMIN is not used directly by iptables which
     * is called by Wifidog
     */
    const int num_caps = 2;
    cap_value_t cap_values[] = { CAP_NET_RAW, CAP_NET_ADMIN };
    cap_t caps;

    caps = cap_get_proc();
    if (NULL == caps) {
        debug(LOG_ERR, "cap_get_proc failed, exiting!");
        exit(1);
    }
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    /* Clear all caps and then set the caps we desire */
    cap_clear(caps);
    cap_set_flag(caps, CAP_PERMITTED, num_caps, cap_values, CAP_SET);
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
        exit(1);
    }
    cap_free(caps),
    caps = cap_get_proc();
    if (NULL == caps) {
        debug(LOG_ERR, "cap_get_proc failed, exiting!");
        exit(1);
    }
    debug(LOG_DEBUG, "Dropped caps, now: %s", cap_to_text(caps, NULL));
    cap_free(caps);
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    if (NULL == caps) {
        debug(LOG_ERR, "cap_get_proc failed, exiting!");
        exit(1);
    }
    debug(LOG_DEBUG, "Regaining capabilities.");
    /* Re-gain privileges */
    cap_set_flag(caps, CAP_EFFECTIVE, num_caps, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_INHERITABLE, num_caps, cap_values, CAP_SET);
    /*
     * Note that we keep CAP_INHERITABLE empty. In theory, CAP_INHERITABLE
     * would be useful to execve iptables as non-root. In practice, Wifidog
     * often runs on embedded systems (OpenWrt) where the required file-based
     * capabilities are not available as the underlying file system does not
     * support extended attributes.
     *
     * The linux capabilities implementation requires that the executable is
     * specifically marked as being able to inherit capabilities from a calling
     * process. This can be done by setting the Inheritable+Effective file
     * capabilities on the executable. Alas, it's not relevant here.
     *
     * This is also the main reason why we only seteuid() instead of setuid():
     * When an executable is called as root (real UID == 0), the INHERITABLE
     * and PERMITTED file capability sets are implicitly marked as enabled.
     */
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
        exit(1);
    }
    cap_free(caps);
    caps = cap_get_proc();
    if (NULL == caps) {
        debug(LOG_ERR, "cap_get_proc failed, exiting!");
        exit(1);
    }
    debug(LOG_INFO, "Final capabilities: %s", cap_to_text(caps, NULL));
    cap_free(caps);
}


/**
 * Switches the effective user ID to 0 (root).
 *
 * If the underlying seteuid call fails, an error message is logged.
 * No other error handling is performed.
 *
 */
void switch_to_root() {
    int ret = 0;
    ret = seteuid(0);
    /* Not being able to raise privileges is not fatal. */
    if (ret != 0) {
        debug(LOG_ERR, "execute: Could not seteuid(0): %s", strerror(errno));
    }
    ret = setegid(0);
    if (ret != 0) {
        debug(LOG_ERR, "execute: Could not setegid(0): %s", strerror(errno));
    }
    debug(LOG_DEBUG, "execute: Switched to UID 0!");;
}


/**
 * Switches user and group, typically to a non-privileged user.
 *
 * If either user or group switching fails, this is considered fatal
 * and exit() is called.
 *
 * @param user name of the user
 * @param group name of the group
 *
 */
void set_user_group(const char* user, const char* group) {
    debug(LOG_DEBUG, "Switching to group %s", group);
    struct passwd *pwd = NULL;
    struct passwd *pwdresult = NULL;
    struct group *grp = NULL;
    struct group *grpresult = NULL;
    char *buf;
    ssize_t bufsize;
    int s;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize == -1) {
        /* Suggested by man getgrnam_r */
        bufsize = 16384;
    }
    buf = safe_malloc(bufsize);

    s = getgrnam_r(group, grp, buf, bufsize, &grpresult);

    if (grpresult == NULL) {
        if (s == 0) {
            debug(LOG_ERR, "GID for group %s not found!", group);
        }
        else {
            debug(LOG_ERR, "Failed to look up GID for group %s: %s", group, strerror(errno));
        }
        exit(1);
    }

    s = getpwnam_r(user, pwd, buf, bufsize, &pwdresult);
    if (pwdresult == NULL) {
        if (s == 0) {
            debug(LOG_ERR, "UID for user %s not found!", user);
        }
        else {
            debug(LOG_ERR, "Failed to look up UID for user %s: %s", user, strerror(errno));
        }
        exit(1);
    }

    set_uid_gid(pwd->pw_uid, grp->gr_gid);

}

/**
 * Switches user ID and group ID, typically to a non-privileged user.
 *
 * If either user or group switching fails, this is considered fatal
 * and exit() is called.
 *
 * @param uid the ID of the user
 * @param gid the ID of the group
 *
 */
void set_uid_gid(uid_t uid, gid_t gid) {
    int ret;
    ret = setegid(gid);
    if (ret != 0) {
        debug(LOG_ERR, "Failed to setegid() %s", strerror(errno));
        exit(1);
    }
    ret = seteuid(uid);
    if (ret != 0) {
        debug(LOG_ERR, "Failed to seteuid(): %s", strerror(errno));
        exit(1);
    }
}


/**
 * Calls popen with root privileges.
 *
 * This method is a wrapper around popen(). The effective
 * user and group IDs of the current process are temporarily set
 * to 0 (root) and then reset to the original, typically non-privileged,
 * values before returning.
 *
 * @param command First popen parameter
 * @param type Second popen parameter
 * @returns File handle pointer returned by popen
 */
FILE *popen_as_root(const char *command, const char *type) {
    FILE *p = NULL;
    uid_t uid = getuid();
    gid_t gid = getgid();
    switch_to_root();
    p = popen(command, type);
    set_uid_gid(uid, gid);
    return p;
}

#endif /* USE_LIBCAP */
