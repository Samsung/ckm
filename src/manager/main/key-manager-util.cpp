/*
 *  key-manager
 *
 *  Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/smack.h>
#include <unistd.h>

#include <limits>

#include <key-manager-util.h>
#include <dpl/log/log.h>

namespace {
const size_t SIZE_T_MAX = std::numeric_limits<size_t>::max();
} // namespace anonymous

namespace CKM {

int util_smack_label_is_valid(const char *smack_label)
{
    int i;

    if (!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
        goto err;

    for (i = 0; smack_label[i]; ++i) {
        if (i >= SMACK_LABEL_LEN)
            return 0;
        switch (smack_label[i]) {
            case '~':
            case ' ':
            case '/':
            case '"':
            case '\\':
            case '\'':
                goto err;
            default:
                break;
        }
    }

    return 1;
err:
    LogError("Invalid Smack label: " << (smack_label ? smack_label : ""));
    return 0;
}

char *read_exe_path_from_proc(pid_t pid)
{
    char link[32];
    char *exe = NULL;
    size_t size = 64;
    ssize_t cnt = 0;

    // get link to executable
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);

    for (;;)
    {
        exe = (char*) malloc(size);
        if (exe == NULL)
        {
            LogError("Out of memory");
            return NULL;
        }

        // read link target
        cnt = readlink(link, exe, size);

        // error
        if (cnt < 0 || (size_t) cnt > size)
        {
            LogError("Can't locate process binary for pid=" << pid);
            free(exe);
            return NULL;
        }

        // read less than requested
        if ((size_t) cnt < size)
            break;

        // read exactly the number of bytes requested
        free(exe);
        if (size > (SIZE_T_MAX >> 1))
        {
            LogError("Exe path too long (more than " << size << " characters)");
            return NULL;
        }
        size <<= 1;
    }
    // readlink does not append null byte to buffer.
    exe[cnt] = '\0';
    return exe;
}

} // namespace CKM

