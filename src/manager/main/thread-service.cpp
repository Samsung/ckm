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

void ThreadService::Handle(const AcceptEvent &event) {
    LogDebug("Accept event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
    info.credentials = event.credentials;
}

void ThreadService::Handle(const WriteEvent &event) {
    LogDebug("Write event (" << event.size << " bytes )");
}

void ThreadService::Handle(const ReadEvent &event) {
    LogDebug("Read event");
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);
    while(ProcessOne(event.connectionID, info));
}

void ThreadService::Handle(const CloseEvent &event) {
    LogDebug("Close event");
    m_connectionInfoMap.erase(event.connectionID.counter);
}

} /* namespace CKM */
