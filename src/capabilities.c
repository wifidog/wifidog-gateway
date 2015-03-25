

#include "../config.h"

#ifdef USE_LIBCAP

#include <syslog.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
/* For getpwnam */
#include <pwd.h>
/* For getgrnam */
#include <grp.h>

#include "debug.h"

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

    // TODO: what happens on reload?

    caps = cap_get_proc();
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    /* Hopefully clear all caps but cap_values */
    cap_set_flag(caps, CAP_PERMITTED, 2, cap_values, CAP_SET);
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Dropped caps, now: %s", cap_to_text(caps, NULL));
    /* About to switch uid. This is necessary because the process can
       still read everyting owned by root - IIRC.
       However, we need to have our capabilities survive setuid */
    // TODO: also see SECBIT_KEEP_CAPS
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    cap_free(caps);
    debug(LOG_DEBUG, "Switching to group %s", group);
    struct group *grp = getgrnam(group);
    if (grp) {
        gid_t gid = grp->gr_gid;
        setgid(gid);
    } else {
        debug(LOG_ERR, "Failed to look up GID for group %s", group);
    }
    /* don't free, see getpwnam() for details */
    debug(LOG_DEBUG, "Switching to user %s", user);
    struct passwd *pwd = getpwnam(user);
    if (pwd) {
        uid_t uid = pwd->pw_uid;
        setuid(uid);
    } else {
        debug(LOG_ERR, "Failed to look up UID for user %s", user);
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Current capabilities: %s", cap_to_text(caps, NULL));
    debug(LOG_DEBUG, "Regaining privileges.");
    /* Re-gain privileges */
    cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_values, CAP_SET);
    /* Child processes get the same privileges. In particular,
     * iptables */
    cap_set_flag(caps, CAP_INHERITABLE, 2, cap_values, CAP_SET);
    ret = cap_set_proc(caps);
    if (ret == -1) {
        debug(LOG_ERR, "Could not set capabilities!");
    }
    caps = cap_get_proc();
    debug(LOG_DEBUG, "Regained: %s", cap_to_text(caps, NULL));
    cap_free(caps);
}

#endif /* USE_LIBCAP */
