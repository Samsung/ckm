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
 * @file       thread-service.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <generic-socket-manager.h>
#include <service-thread.h>
#include <connection-info.h>
#include <noncopyable.h>

namespace CKM {

class ThreadService: public GenericSocketService, public ServiceThread
{
public:
    ThreadService();
    virtual ~ThreadService();
    NONCOPYABLE(ThreadService);

    void Event(const AcceptEvent& event) { ThreadEvent(event); }
    void Event(const WriteEvent& event) { ThreadEvent(event); }
    void Event(const ReadEvent& event) { ThreadEvent(event); }
    void Event(const CloseEvent& event) { ThreadEvent(event); }
    void Event(const SecurityEvent &event) { ThreadEvent(event); }

protected:
    virtual bool ProcessOne(const ConnectionID &conn,
                            ConnectionInfo &info,
                            bool allowed) = 0;

    template <typename E>
    void ThreadEvent(const E& event) {
        CreateEvent([this, event]() { this->Handle(event); });
    }

    void Handle(const AcceptEvent &event);
    void Handle(const WriteEvent &event);
    void Handle(const ReadEvent &event);
    void Handle(const CloseEvent &event);
    void Handle(const SecurityEvent &event);

    ConnectionInfoMap m_connectionInfoMap;
};

} /* namespace CKM */
