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
 * @file       receiver.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <receiver.h>
#include <protocols.h>
#include <dpl/log/log.h>

namespace CKM {

Receiver::Receiver(MessageBuffer& buffer, AsyncRequest::Map& requests) :
    m_buffer(buffer),
    m_requests(requests),
    m_observer(NULL)
{
}

void Receiver::parseResponse()
{
    int command;
    int id;
    m_buffer.Deserialize(command, id);

    auto it = m_requests.find(id);
    if (it == m_requests.end()) {
        LogError("Request with id " << id << " not found!");
        ThrowMsg(BadResponse, "Request with id " << id << " not found!");
    }

    // let it throw
    AsyncRequest req = std::move(m_requests.at(id));
    m_requests.erase(id);

    m_observer = req.observer;

    switch (static_cast<LogicCommand>(command)) {
    case LogicCommand::SAVE:
        parseSaveCommand();
        break;
    // TODO other cases
    default:
        LogError("Unknown command id: " << command);
        ThrowMsg(BadResponse, "Unknown command id: " << command);
        break;
    }
}

void Receiver::parseSaveCommand()
{
    int retCode;
    int dataType;

    m_buffer.Deserialize(retCode, dataType);

    DBDataType dt = static_cast<DBDataType>(dataType);
    if (dt >= DBDataType::DB_KEY_FIRST && dt <= DBDataType::DB_KEY_LAST) {
        if (retCode == CKM_API_SUCCESS)
            m_observer->ReceivedSaveKey();
        else
            m_observer->ReceivedError(retCode);
    } else {
        // TODO
    }
}

} /* namespace CKM */
