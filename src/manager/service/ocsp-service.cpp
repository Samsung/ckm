/*
 *  Copyright (c) 2014 Samsung Electronics Co.
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
 *
 * @file        ocsp-service.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       OCSP service implementation.
 */
#include <service-thread.h>
#include <generic-socket-manager.h>
#include <connection-info.h>
#include <message-buffer.h>
#include <protocols.h>

#include <dpl/serialization.h>
#include <dpl/log/log.h>

#include <ocsp-service.h>
#include <ocsp-logic.h>

namespace {
const CKM::InterfaceID SOCKET_ID_OCSP = 0;
} // namespace anonymous

namespace CKM {

OCSPService::OCSPService()
  : m_logic(new OCSPLogic())
{}

OCSPService::~OCSPService() {
    delete m_logic;
}

GenericSocketService::ServiceDescriptionVector OCSPService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_OCSP, "key-manager::api-ocsp", SOCKET_ID_OCSP}
    };
}

void OCSPService::accept(const AcceptEvent &event) {
    LogDebug("Accept event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
    info.credentials = event.credentials;
}

void OCSPService::write(const WriteEvent &event) {
    LogDebug("Write event (" << event.size << " bytes )");
}

void OCSPService::process(const ReadEvent &event) {
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);
    while(processOne(event.connectionID, info));
}

bool OCSPService::processOne(
    const ConnectionID &conn,
    ConnectionInfo &info)
{
    LogDebug ("process One");

    Try {
        if (!info.buffer.Ready())
            return false;

        auto &buffer = info.buffer;

        int commandId;
        RawBufferVector chainVector;
        Deserialization::Deserialize(buffer, commandId);
        Deserialization::Deserialize(buffer, chainVector);

        RawBuffer response = m_logic->ocspCheck(commandId, chainVector);
        m_serviceManager->Write(conn, response);

        return true;
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } catch (const std::string &e) {
        LogError("String exception(" << e << "). Closing socket");
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

void OCSPService::close(const CloseEvent &event) {
    LogDebug("Close event");
    m_connectionInfoMap.erase(event.connectionID.counter);
}

} // namespace CKM

