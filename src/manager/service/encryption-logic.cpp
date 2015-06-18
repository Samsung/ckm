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
 * @file       encryption-logic.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <encryption-logic.h>
#include <ckm/ckm-error.h>
#include <dpl/log/log.h>

namespace CKM {

void EncryptionLogic::Crypt(const CryptoRequest& request)
{
    // check arguments
    if(request.input.empty()) {
        LogError("No input data");
        m_service.RespondToClient(request, CKM_API_ERROR_INPUT_PARAM);
        return;
    }

    // store request in the map
    auto ret = m_requests.insert(std::make_pair(request.msgId, request));
    if (!ret.second) {
        LogError("Request with id " << request.msgId << " already exists");
        m_service.RespondToClient(request, CKM_API_ERROR_INPUT_PARAM);
        return;
    }

    // request key
    try {
        m_service.RequestKey(request);
    } catch (...) {
        LogError("Key request failed");
        m_requests.erase(request.msgId);
        m_service.RespondToClient(request, CKM_API_ERROR_SERVER_ERROR);
    }
}

void EncryptionLogic::KeyRetrieved(MsgKeyResponse response)
{
    auto it = m_requests.find(response.id);
    if (it == m_requests.end()) {
        LogError("No matching request found"); // nothing we can do
        return;
    }
    CryptoRequest req = std::move(it->second);
    m_requests.erase(it);

    if (response.error != CKM_API_SUCCESS) {
        LogError("Attempt to retrieve key failed with error: " << response.error);
        m_service.RespondToClient(req, response.error);
        return;
    }

    if (!response.key) {
        LogError("Retrieved key is empty");
        m_service.RespondToClient(req, CKM_API_ERROR_SERVER_ERROR);
        return;
    }

    // encrypt/decrypt
    try {
        RawBuffer output;
        if (req.command == EncryptionCommand::ENCRYPT)
            output = response.key->encrypt(req.cas, req.input);
        else
            output = response.key->decrypt(req.cas, req.input);
        m_service.RespondToClient(req, CKM_API_SUCCESS, output);
    } catch (const Exc::Exception& ex) {
        m_service.RespondToClient(req, ex.error());
    } catch (...) {
        LogError("Uncaught exception from encrypt/decrypt.");
        m_service.RespondToClient(req, CKM_API_ERROR_SERVER_ERROR);
    }
}

} /* namespace CKM */
