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
 * @file       socket-2-id-mockup.cpp
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <string>

#include <dpl/log/log.h>
#include <protocols.h>
#include <socket-2-id.h>

namespace CKM {

int Socket2Id::getPkgIdFromSmack(const std::string &smack, std::string &pkgId)
{
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

    if (appId.empty()) {
        LogError("After conversion (smack->pkgId) pkgId is empty. Label: " << appId);
        return -1;
    }

    pkgId = std::move(appId);
    LogDebug("Smack: " << smack << " Was translated to owner id: " << pkgId);
    return 0;
}

int Socket2Id::translate(int sock, std::string &result)
{
    std::string smack;
    std::string pkgId;

    if (0 > getCredentialsFromSocket(sock, smack))
        return -1;

    if (0 > getPkgIdFromSmack(smack, pkgId))
        return -1;

    result = std::move(pkgId);
    return 0;
}

} // namespace CKM

