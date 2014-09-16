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
 * @file       service.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <string>
#include <memory>
#include <descriptor-set.h>
#include <async-request.h>
#include <noncopyable.h>
#include <client-common.h>

namespace CKM {

class Service {
public:
    Service(IDescriptorSet& descriptors, const std::string& interface);

    Service(Service&&) = default;
    Service& operator=(Service&&) = default;

    void addRequest(AsyncRequest&& req);

    void serviceError(int error);

private:
    void socketReady(int sock, short revents);

    void sendData();
    void receiveData();

    void watch(short events);

    std::string m_interface;
    std::unique_ptr<SockRAII> m_socket;
    IDescriptorSet& m_descriptors;
    AsyncRequest::Queue m_sendQueue;
    AsyncRequest::Map m_responseMap;
    std::unique_ptr<MessageBuffer> m_responseBuffer;
};

} // namespace CKM
