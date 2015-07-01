/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       file-lock.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include "file-lock.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <stdexcept>
#include <string>
#include <sstream>

#include <stringify.h>

namespace CKM {

namespace {

// TODO replace it with custom exception when they are implemented
template <typename... Args>
std::runtime_error io_exception(const Args&... args)
{
    return std::runtime_error(Stringify::Merge(args...));
};

} // namespace anonymous

FileLock::FileLock(const char* const file)
{
    // Open lock file
    m_lockFd = TEMP_FAILURE_RETRY(creat(file, 0644));
    if (m_lockFd == -1) {
        throw io_exception("Cannot open lock file. Errno: ", strerror(errno));
    }

    if (-1 == lockf(m_lockFd, F_TLOCK, 0)) {
        if (errno == EACCES || errno == EAGAIN)
            throw io_exception("Can't acquire lock. Another instance must be running.");
        else
            throw io_exception("Can't acquire lock. Errno: ", strerror(errno));
    }

    std::string pid = std::to_string(getpid());

    ssize_t written = TEMP_FAILURE_RETRY(write(m_lockFd, pid.c_str(), pid.size()));
    if (-1 == written || static_cast<ssize_t>(pid.size()) > written)
        throw io_exception("Can't write file lock. Errno: ", strerror(errno));

    int ret = fsync(m_lockFd);
    if (-1 == ret)
        throw io_exception("Fsync failed. Errno: ",strerror(errno));
}

FileLock::~FileLock()
{
    // this will also release the lock
    close(m_lockFd);
}

} /* namespace CKM */
