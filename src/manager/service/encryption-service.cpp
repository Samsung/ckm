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
 * @file       encryption-service.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <stdexcept>
#include <utility>
#include <encryption-service.h>
#include <protocols.h>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <crypto-request.h>

namespace {
const CKM::InterfaceID SOCKET_ID_ENCRYPTION = 0;
} // namespace anonymous

namespace CKM {

EncryptionService::EncryptionService() :
    m_logic(*this)
{
}

EncryptionService::~EncryptionService()
{
}

void EncryptionService::RespondToClient(const CryptoRequest& request,
                                        int retCode,
                                        const RawBuffer& data)
{
    try {
        RawBuffer response = MessageBuffer::Serialize(
                static_cast<int>(request.command), request.msgId, retCode, data).Pop();
        m_serviceManager->Write(request.conn, response);
    } catch (...) {
        LogError("Failed to send response to the client");
    }
}

void EncryptionService::RequestKey(const CryptoRequest& request)
{
    MsgKeyRequest kReq(request.msgId, request.cred, request.name, request.label, request.password);
    if (!m_commMgr->SendMessage(kReq))
        throw std::runtime_error("No listener found");// TODO
}

GenericSocketService::ServiceDescriptionVector EncryptionService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_ENCRYPTION, "http://tizen.org/privilege/keymanager", SOCKET_ID_ENCRYPTION}
    };
}

void EncryptionService::Start()
{
    Create();
}

void EncryptionService::Stop()
{
    Join();
}

void EncryptionService::SetCommManager(CommMgr *manager)
{
    ThreadService::SetCommManager(manager);
    Register(*manager);
}

// Encryption Service does not support any kind of security-check
// and 3rd parameter is not required
bool EncryptionService::ProcessOne(
    const ConnectionID &conn,
    ConnectionInfo &info,
    bool /*allowed*/)
{
    LogDebug("process One");
    try {
        if (!info.buffer.Ready())
            return false;

        ProcessEncryption(conn, info.credentials, info.buffer);
        return true;
    } catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } catch (const std::exception &e) {
        LogError("Std exception:: " << e.what());
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

void EncryptionService::ProcessMessage(MsgKeyResponse msg)
{
    m_logic.KeyRetrieved(std::move(msg));
}

void EncryptionService::ProcessEncryption(const ConnectionID &conn,
                                          const Credentials &cred,
                                          MessageBuffer &buffer)
{
    int tmpCmd = 0;
    CryptoRequest req;

    buffer.Deserialize(tmpCmd, req.msgId, req.cas, req.name, req.label, req.password, req.input);
    req.command = static_cast<EncryptionCommand>(tmpCmd);
    if (req.command != EncryptionCommand::ENCRYPT && req.command != EncryptionCommand::DECRYPT)
        throw std::runtime_error("Unsupported command: " + tmpCmd);

    req.conn = conn;
    req.cred = cred;
    m_logic.Crypt(req);
}

void EncryptionService::CustomHandle(const ReadEvent &event)
{
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);
    while (ProcessOne(event.connectionID, info, true));
}

void EncryptionService::CustomHandle(const SecurityEvent &/*event*/)
{
    LogError("This should not happend! SecurityEvent was called on EncryptionService!");
}

} /* namespace CKM */
