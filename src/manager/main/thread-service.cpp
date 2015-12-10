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
 * @file       thread-service.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <thread-service.h>
#include <dpl/log/log.h>

namespace CKM {

ThreadService::ThreadService()
{
}

ThreadService::~ThreadService()
{
}

void ThreadService::Handle(const AcceptEvent &event)
{
    LogDebug("Accept event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
    info.credentials = event.credentials;
}

void ThreadService::Handle(const WriteEvent &event)
{
    LogDebug("Write event (" << event.size << " bytes )");
}

void ThreadService::Handle(const ReadEvent &event)
{
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    if (!info.buffer.Ready())
        return;

    if (info.checkInProgress)
        return;

    info.checkInProgress = true;
    m_serviceManager->SecurityCheck(event.connectionID);
}

void ThreadService::Handle(const CloseEvent &event)
{
    LogDebug("Close event");
    m_connectionInfoMap.erase(event.connectionID.counter);
}

void ThreadService::Handle(const SecurityEvent &event)
{
    LogDebug("Security event");
    auto it = m_connectionInfoMap.find(event.connectionID.counter);

    if (it == m_connectionInfoMap.end()) {
        LogDebug("Connection has been closed already");
        return;
    }
    auto &info = it->second;

    if (!info.checkInProgress) {
        LogDebug("Wrong status in info.checkInProgress. Expected: true.");
        return;
    }

    ProcessOne(event.connectionID, info, event.allowed);

    if (info.buffer.Ready())
        m_serviceManager->SecurityCheck(event.connectionID);
    else
        info.checkInProgress = false;
}

} /* namespace CKM */
