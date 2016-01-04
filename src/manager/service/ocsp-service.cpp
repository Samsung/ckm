/*
 *  Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
{
}

OCSPService::~OCSPService()
{
    delete m_logic;
}

void OCSPService::Start()
{
    Create();
}

void OCSPService::Stop()
{
    Join();
}

GenericSocketService::ServiceDescriptionVector OCSPService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_OCSP, "http://tizen.org/privilege/internet", SOCKET_ID_OCSP}
    };
}

bool OCSPService::ProcessOne(
    const ConnectionID &conn,
    ConnectionInfo &info,
    bool allowed)
{
    LogDebug("process One");

    Try {
        if (!info.buffer.Ready())
            return false;

        auto &buffer = info.buffer;

        int commandId = 0;
        RawBufferVector chainVector;
        buffer.Deserialize(commandId, chainVector);

        RawBuffer response = m_logic->ocspCheck(commandId, chainVector, allowed);
        m_serviceManager->Write(conn, response);

        return true;
    } Catch(MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
    } catch (const std::string &e) {
        LogError("String exception(" << e << "). Closing socket");
    } catch (...) {
        LogError("Unknown exception. Closing socket.");
    }

    m_serviceManager->Close(conn);
    return false;
}

} // namespace CKM

