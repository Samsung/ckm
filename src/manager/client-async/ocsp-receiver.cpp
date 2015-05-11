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
 * @file       ocsp-receiver.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ocsp-receiver.h>
#include <dpl/log/log.h>

namespace CKM {

OcspReceiver::OcspReceiver(MessageBuffer& buffer, AsyncRequest::Map& requests) :
    m_buffer(buffer),
    m_requests(requests)
{
}

void OcspReceiver::parseResponse()
{
    int id = 0, retCode = 0, ocspStatus = 0;
    m_buffer.Deserialize(id, retCode, ocspStatus);

    auto it = m_requests.find(id);
    if (it == m_requests.end()) {
        LogError("Request with id " << id << " not found!");
        ThrowMsg(BadResponse, "Request with id " << id << " not found!");
    }

    // let it throw
    AsyncRequest req = std::move(m_requests.at(id));
    m_requests.erase(id);

    if (retCode == CKM_API_SUCCESS)
        req.observer->ReceivedOCSPCheck(ocspStatus);
    else
        req.observer->ReceivedError(retCode);
}

} /* namespace CKM */
