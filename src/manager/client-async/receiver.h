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
 * @file       receiver.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <message-buffer.h>
#include <noncopyable.h>
#include <ckm/ckm-manager.h>
#include <async-request.h>

namespace CKM {

class Receiver
{
public:
    DECLARE_EXCEPTION_TYPE(CKM::Exception, BadResponse);

    Receiver(MessageBuffer& buffer, AsyncRequest::Map& reqMap);
    virtual ~Receiver() {}

    NONCOPYABLE(Receiver);

    void parseResponse();

private:
    void parseSaveCommand();

    MessageBuffer& m_buffer;
    AsyncRequest::Map& m_requests;
    ManagerAsync::ObserverPtr m_observer;
};

} /* namespace CKM */
