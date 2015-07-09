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
 * @file       encryption-receiver.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <encryption-receiver.h>
#include <dpl/log/log.h>
#include <protocols.h>

namespace CKM {

EncryptionReceiver::EncryptionReceiver(MessageBuffer& buffer, AsyncRequest::Map& requests) :
    m_buffer(buffer),
    m_requests(requests)
{
}

void EncryptionReceiver::processResponse()
{
    int command = 0;
    int id = 0;
    int retCode;
    RawBuffer output;
    m_buffer.Deserialize(command, id, retCode, output);

    auto it = m_requests.find(id);
    if (it == m_requests.end()) {
        LogError("Request with id " << id << " not found!");
        ThrowMsg(BadResponse, "Request with id " << id << " not found!");
    }

    // let it throw
    AsyncRequest req = std::move(m_requests.at(id));
    m_requests.erase(id);

    switch (static_cast<EncryptionCommand>(command)) {
    case EncryptionCommand::ENCRYPT:
        if (retCode == CKM_API_SUCCESS)
            req.observer->ReceivedEncrypted(std::move(output));
        else
            req.observer->ReceivedError(retCode);
        break;
    case EncryptionCommand::DECRYPT:
        if (retCode == CKM_API_SUCCESS)
            req.observer->ReceivedDecrypted(std::move(output));
        else
            req.observer->ReceivedError(retCode);
        break;
    default:
        LogError("Unknown command id: " << command);
        ThrowMsg(BadResponse, "Unknown command id: " << command);
        break;
    }
}

} /* namespace CKM */
