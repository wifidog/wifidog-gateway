

#include "../config.h"

#ifdef USE_LIBCAP

#include <syslog.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
/* For exit */
#include <stdlib.h>
/* For getpwnam */
#include <pwd.h>
/* For getgrnam */
#include <grp.h>

#include "debug.h"

/**
 * Switches to non-privileged user and drops unneeded capabilities.
 *
 * Wifidog does not need to run as root. The only capabilities required
 * are:
 *  - CAP_NET_RAW: get IP addresses from sockets, ICMP ping
 *  - CAP_NET_ADMIN: set up iptables
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
 * @param Non-privileged group
 */
void
drop_privileges(const char *user, const char *group)
{
    int ret = 0;
    debug(LOG_DEBUG, "Entered drop_privileges");
    /* The capabilities we want.
     * CAP_NET_RAW is used for our socket handling.
     * We actually require CAP_NET_ADMIN for iptables. However,
     * iptables must be run as root so we do that instead. */
    cap_value_t cap_values[] = { CAP_NET_RAW, CAP_NET_ADMIN };
    cap_t caps;

    caps = cap_get_proc();
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    /* Hopefully clear all caps but cap_values */
    cap_set_flag(caps, CAP_PERMITTED, 2, cap_values, CAP_SET);
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
        exit(1);
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Dropped caps, now: %s", cap_to_text(caps, NULL));
    cap_free(caps);
    /* We are about to drop our effective UID to a non-privileged user.
     * This clears the EFFECTIVE capabilities set, so we will have to
     * re-enable these. We can do that because they are not cleared from
     * the PERMITTED set.
     * Note: if we used setuid() instead of seteuid(), we would have lost the
     * PERMITTED set as well. In this case, we would need to call prctl
     * with PR_SET_KEEPCAPS.
     */
    debug(LOG_DEBUG, "Switching to group %s", group);
    /* don't free grp, see getpwnam() for details */
    struct group *grp = getgrnam(group);
    if (grp) {
        gid_t gid = grp->gr_gid;
        setegid(gid);
    } else {
        debug(LOG_ERR, "Failed to look up GID for group %s", group);
        exit(1);
    }
    debug(LOG_DEBUG, "Switching to user %s", user);
    /* don't pwd, see getpwnam() for details */
    struct passwd *pwd = getpwnam(user);
    if (pwd) {
        uid_t uid = pwd->pw_uid;
        seteuid(uid);
    } else {
        debug(LOG_ERR, "Failed to look up UID for user %s", user);
        exit(1);
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    debug(LOG_DEBUG, "Regaining capabilities.");
    /* Re-gain privileges */
    cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_values, CAP_SET);
    /* Note that we keep CAP_INHERITABLE empty. In theory, CAP_INHERITABLE
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
     * iptables will be called as root (with ALL capabilities!) and thus continue
     * to work as before.
     */
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
        exit(1);
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Regained: %s", cap_to_text(caps, NULL));
    cap_free(caps);
}

#endif /* USE_LIBCAP */
