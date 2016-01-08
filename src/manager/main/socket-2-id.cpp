/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       socket-2-id.cpp
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#ifdef BUILD_WITH_SMACK
#include <sys/smack.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <dpl/log/log.h>
#include <protocols.h>
#include <socket-2-id.h>

namespace CKM {

namespace {

int assignToString(std::vector<char> &vec, socklen_t len, std::string &res)
{
    if (vec.size() <= len)
        return -1;

    vec[len] = 0;            // old implementation getsockopt returns cstring without 0

    if (vec[len-1] == 0)
        --len;               // new implementation of getsockopt returns cstring size+1

    res.assign(vec.data(), len);
    return 0;
}

} // namespace anonymous

#ifdef BUILD_WITH_SMACK
int Socket2Id::getCredentialsFromSocket(int sock, std::string &res)
{
    std::vector<char> result(SMACK_LABEL_LEN+1);
    socklen_t length = SMACK_LABEL_LEN;

    if (0 == getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length))
        return assignToString(result, length, res);

    if (errno != ERANGE) {
        LogError("getsockopt failed");
        return -1;
    }

    result.resize(length+1);

    if (0 > getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length)) {
        LogError("getsockopt failed with errno: " << errno);
        return -1;
    }

    return assignToString(result, length, res);
}
#else
int Socket2Id::getCredentialsFromSocket(int sock, std::string &res) {
    ucred uc;
    socklen_t len = sizeof(struct ucred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &uc, &len) == -1) {
        return -1;
    }
    res = std::to_string(uc.uid);
    return 0;
}
#endif

void Socket2Id::resetCache()
{
    m_stringMap.clear();
}

} // namespace CKM

