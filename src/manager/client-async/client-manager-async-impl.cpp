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
 * @file       client-manager-async-impl.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <client-manager-async-impl.h>
#include <ckm/ckm-error.h>
#include <message-buffer.h>
#include <client-common.h>
#include <stdexcept>

namespace CKM {

int ManagerAsync::Impl::m_counter = 0;

ManagerAsync::Impl::Impl()
{
}

ManagerAsync::Impl::~Impl()
{
}

void ManagerAsync::Impl::saveKey(const ManagerAsync::ObserverPtr& observer,
                                 const Alias& alias,
                                 const KeyShPtr& key,
                                 const Policy& policy)
{
    observerCheck(observer);

    if (!key) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    saveBinaryData(observer, alias, toDBDataType(key->getType()), key->getDER(), policy);
}

void ManagerAsync::Impl::saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                                        const Alias& alias,
                                        DBDataType dataType,
                                        const RawBuffer& rawData,
                                        const Policy& policy)
{
    if (alias.empty() || rawData.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }

    try_catch_async([&] {
        m_counter++;

        MessageBuffer send;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::SAVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(dataType));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, rawData);
        Serialization::Serialize(send, PolicySerializable(policy));

        thread()->sendMessage(AsyncRequest(observer,
                                           SERVICE_SOCKET_CKM_STORAGE,
                                           send.Pop(),
                                           m_counter));

    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::observerCheck(const ManagerAsync::ObserverPtr& observer)
{
    if(!observer)
        throw std::invalid_argument("Empty observer");
}

} // namespace CKM
