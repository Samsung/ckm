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
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <security-manager.h>

#include <dpl/log/log.h>
#include <protocols.h>
#include <socket-2-id.h>

namespace CKM {
namespace {

int getCredentialsFromSocket(int sock, std::string &res)  {
    std::vector<char> result(1);
    socklen_t length = 1;

    if ((0 > getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length))
      && errno != ERANGE)
    {
        LogError("getsockopt failed");
        return -1;
    }

    result.resize(length);

    if (0 > getsockopt(sock, SOL_SOCKET, SO_PEERSEC, result.data(), &length)) {
        LogError("getsockopt failed");
        return -1;
    }

    result.push_back('\0');
    res = result.data();
    return 0;
}

int getPkgIdFromSmack(const std::string &smack, std::string &pkgId) {
    // TODO
    // Conversion from smack label to pkgId should be done
    // by security-manager. Current version of security-manager
    // does not support this feature yet.

    static const std::string SMACK_PREFIX_APPID  = "User::App::";

    if (smack.empty()) {
        LogError("Smack is empty. Connection will be rejected");
        return -1;
    }

    if (smack.compare(0, SMACK_PREFIX_APPID.size(), SMACK_PREFIX_APPID)) {
        pkgId = "/" + smack;
        LogDebug("Smack: " << smack << " Was translated to owner id: " << pkgId);
        return 0;
    }

    std::string appId = smack.substr(SMACK_PREFIX_APPID.size(), std::string::npos);

    char *pkg = nullptr;

    if (0 > security_manager_get_app_pkgid(&pkg, appId.c_str())) {
        LogError("Error in security_manager_get_app_pkgid");
        return -1;
    }

    if (!pkg) {
        LogError("PkgId could not be NULL");
        return -1;
    }

    pkgId = pkg;
    free(pkg);
    LogDebug("Smack: " << smack << " Was translated to owner id: " << pkgId);
    return 0;
}

} // namespace anonymous


int Socket2Id::translate(int sock, std::string &result) {
    std::string smack;

    if (0 > getCredentialsFromSocket(sock, smack)) {
        return -1;
    }

    StringMap::iterator it = m_stringMap.find(smack);

    if (it != m_stringMap.end()) {
        result = it->second;
        return 0;
    }

    std::string pkgId;
    if (0 > getPkgIdFromSmack(smack, pkgId)) {
        return -1;
    }

    result = pkgId;
    m_stringMap.emplace(std::move(smack), std::move(pkgId));
    return 0;
}

void Socket2Id::resetCache() {
    m_stringMap.clear();
}

} // namespace CKM

