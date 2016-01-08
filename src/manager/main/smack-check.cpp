#include <smack-check.h>

#include <stdlib.h>

#ifdef BUILD_WITH_SMACK
#include <sys/smack.h>
#endif

#include <dpl/log/log.h>

namespace CKM {

int smack_runtime_check(void)
{
#ifdef BUILD_WITH_SMACK
    static int smack_present = -1;
    if (-1 == smack_present) {
        if (NULL == smack_smackfs_path()) {
            LogDebug("no smack found on device");
            smack_present = 0;
        } else {
            LogDebug("found smack on device");
            smack_present = 1;
        }
    }
    return smack_present;
#else
    return 0;
#endif
}

int smack_check(void)
{
#ifndef SMACK_ENABLED
    return 0;
#else
    return smack_runtime_check();
#endif
}

} // namespace CKM
