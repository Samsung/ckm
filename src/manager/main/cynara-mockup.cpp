/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cynara-mockup.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Mockup for cynara used in ckm-tests.
 */
#include <string>

#include <cynara.h>

namespace CKM {

Cynara::Cynara(GenericSocketManager *socketManager) :
    m_socketManager(socketManager),
    m_cynara(nullptr)
{
}

void Cynara::Request(
    const std::string &,
    const std::string &,
    const std::string &,
    const std::string &,
    StatusCallback callback)
{
    callback(true);
}

void Cynara::ProcessSocket() {}

Cynara::~Cynara() {}

void Cynara::ChangeStatus(
    int,
    int,
    cynara_async_status)
{
}

void Cynara::ProcessResponse(
    cynara_check_id,
    cynara_async_call_cause,
    int)
{
}

void Cynara::SendRequest(
    const std::string &,
    const std::string &,
    const std::string &,
    const std::string &,
    StatusCallback)
{
}

void Cynara::ChangeStatusCallback(
    int,
    int,
    cynara_async_status,
    void *)
{
}

void Cynara::ProcessResponseCallback(
    cynara_check_id,
    cynara_async_call_cause,
    int,
    void *)
{
}

bool Cynara::GetUserFromSocket(
    int,
    std::string &)
{
    return true;
}

bool Cynara::GetClientFromSocket(
    int,
    std::string &)
{
    return true;
}

} // namespace CKM
