#include <smack-check.h>

#include <stdlib.h>
#include <sys/smack.h>

#include <dpl/log/log.h>

namespace CentralKeyManager {

int smack_runtime_check(void)
{
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
}

int smack_check(void)
{
#ifndef SMACK_ENABLED
    return 0;
#else
    return smack_runtime_check();
#endif
}

} // namespace CentralKeyManager
