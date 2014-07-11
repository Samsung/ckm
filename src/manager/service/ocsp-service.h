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
 * @file        ocsp-service.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       OCSP service implementation.
 */
#pragma once

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <connection-info.h>
#include <message-buffer.h>

namespace CKM {

class OCSPLogic;

class OCSPService
  : public CKM::GenericSocketService
  , public CKM::ServiceThread<OCSPService>
{
public:
    OCSPService();
    OCSPService(const OCSPService &) = delete;
    OCSPService(OCSPService &&) = delete;
    OCSPService& operator=(const OCSPService &) = delete;
    OCSPService& operator=(OCSPService &&) = delete;
    virtual ~OCSPService();

    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, process)
    DECLARE_THREAD_EVENT(CloseEvent, close)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void process(const ReadEvent &event);
    void close(const CloseEvent &event);
private:
    bool processOne(
        const ConnectionID &conn,
        ConnectionInfo &info);

    ConnectionInfoMap m_connectionInfoMap;
    OCSPLogic *m_logic;
};

} // namespace CKM

