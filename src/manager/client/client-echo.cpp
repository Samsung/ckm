/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        client-echo.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @version     This file contains example of key-manager client implementation
 */

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <ckm/error.h>

KEY_MANAGER_API
int key_manager_echo(const char *echo, char** oche) {
    using namespace CentralKeyManager;

    if(echo == NULL){
        LogDebug("Echo message is null");
        return KEY_MANAGER_API_ERROR_INPUT_PARAM;
    }

    MessageBuffer send, recv;
    Serialization::Serialize(send, std::string(echo));

    int retCode = sendToServer(SERVICE_SOCKET_ECHO, send.Pop(), recv);

    if(retCode != KEY_MANAGER_API_SUCCESS)
        return retCode;

    std::string response;
    Deserialization::Deserialize(recv, response);

    *oche = strdup(response.c_str());

    return KEY_MANAGER_API_SUCCESS;
}
