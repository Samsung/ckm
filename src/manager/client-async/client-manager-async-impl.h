/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       client-manager-async-impl.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <ckm/ckm-manager-async.h>
#include <memory>
#include <connection-thread.h>
#include <protocols.h>
#include <noncopyable.h>

namespace CKM {

class ManagerAsync::Impl
{
public:
    Impl();

    NONCOPYABLE(Impl);

    virtual ~Impl();

    void saveKey(const ManagerAsync::ObserverPtr&, const Alias&, const KeyShPtr&, const Policy&);

private:
    void saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                        const Alias& alias,
                        DBDataType dataType,
                        const RawBuffer& rawData,
                        const Policy& policy);

    void observerCheck(const ManagerAsync::ObserverPtr& observer);

    typedef std::unique_ptr<ConnectionThread> ConnectionThreadPtr;

    ConnectionThreadPtr& thread() {
        if (!m_thread || m_thread->finished()) {
            m_thread.reset(new ConnectionThread());
            m_thread->run();
        }
        return m_thread;
    }

    ConnectionThreadPtr m_thread;

    static int m_counter;
};

} // namespace CKM
