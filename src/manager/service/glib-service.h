/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        glib-service.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Dbus listener implementation as service.
 */
#pragma once

#include <thread>

#include <noncopyable.h>
#include <generic-socket-manager.h>

namespace CKM {

class GLIBLogic;

class GLIBService : public CKM::GenericSocketService {
public:
    enum class State {
        NoThread,
        Work,
    };

    GLIBService();
    NONCOPYABLE(GLIBService);

    // This service does not provide any socket for communication so no events will be supported
    virtual void Event(const AcceptEvent &);
    virtual void Event(const WriteEvent &);
    virtual void Event(const ReadEvent &);
    virtual void Event(const CloseEvent &);
    virtual void Event(const SecurityEvent &);

    virtual void Start();
    virtual void Stop();

    virtual ~GLIBService();

    virtual ServiceDescriptionVector GetServiceDescription();
    virtual void SetCommManager(CommMgr *manager);
protected:
    static void ThreadLoopStatic(GLIBService *ptr);
    void ThreadLoop();

    State m_state;
    std::thread m_thread;
    GLIBLogic *m_logic;
};

} // namespace CKM

