#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
/* For getpwnam */
#include <pwd.h>
/* For getgrnam */
#include <grp.h>

void
drop_privileges(const char *user, const char *group)
{
    cap_value_t cap_values[] = { CAP_NET_ADMIN, CAP_NET_RAW };
    cap_t caps;

    // TODO: what happens on reload?
    caps = cap_get_proc();
    /* Hopefully clear all caps but cap_values */
    cap_set_flag(caps, CAP_PERMITTED, 2, cap_values, CAP_SET);
    cap_set_proc(caps);
    /* About to switch uid. This is necessary because the process can
       still read everyting owned by root - IIRC.
       However, we need to have our capabilities survive setuid */
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    cap_free(caps);

    struct group *grp = getgrnam(group);
    if (grp) {
        gid_t gid = grp->gr_gid;
        setgid(gid);
    }
    /* don't free, see getpwnam() for details */
    struct passwd *pwd = getpwnam(user);
    if (pwd) {
        uid_t uid = pwd->pw_uid;
        setuid(uid);
    }

    caps = cap_get_proc();
    /* Re-gain privileges */
    cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_values, CAP_SET);
    /* Child processes get the same privileges */
    cap_set_flag(caps, CAP_INHERITABLE, 2, cap_values, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
}
