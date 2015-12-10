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
 *
 *
 * @file        ckm-service.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       CKM service implementation.
 */
#pragma once

#include <mutex>
#include <message-service.h>
#include <message-buffer.h>
#include <dpl/exception.h>

namespace CKM {

class CKMLogic;

class CKMService : public ThreadMessageService<MsgKeyRequest> {
public:
    CKMService();
    CKMService(const CKMService &) = delete;
    CKMService(CKMService &&) = delete;
    CKMService& operator=(const CKMService &) = delete;
    CKMService& operator=(CKMService &&) = delete;

    // Custom add custom support for ReadEvent and SecurityEvent
    // because we want to bypass security check in CKMService
    virtual void Event(const ReadEvent &event)
    {
        CreateEvent([this, event]() { this->CustomHandle(event); });
    }

    virtual void Event(const SecurityEvent &event)
    {
        CreateEvent([this, event]() { this->CustomHandle(event); });
    }

    virtual void Start(void);
    virtual void Stop(void);

    virtual ~CKMService();

    ServiceDescriptionVector GetServiceDescription();

protected:
    // CustomHandle is used to bypass security check
    void CustomHandle(const ReadEvent &event);
    void CustomHandle(const SecurityEvent &event);

private:
    virtual void SetCommManager(CommMgr *manager);

    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, BrokenProtocol)
    };

    bool ProcessOne(
        const ConnectionID &conn,
        ConnectionInfo &info,
        bool allowed);

    RawBuffer ProcessControl(
        MessageBuffer &buffer);

    RawBuffer ProcessStorage(
        Credentials &cred,
        MessageBuffer &buffer);

    virtual void ProcessMessage(MsgKeyRequest msg);

    CKMLogic *m_logic;
};

} // namespace CKM

