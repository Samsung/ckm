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
 * @file        cynara.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Support for cynara.
 */
#include <string>
#include <map>

#include <dpl/log/log.h>
#include <cynara.h>

#include <cynara-client-async.h>
#include <cynara-creds-socket.h>

namespace CKM {

Cynara::Cynara(GenericSocketManager *socketManager)
  : m_socketManager(socketManager)
  , m_cynara(nullptr)
{
    if (CYNARA_API_SUCCESS != cynara_async_initialize(&m_cynara, NULL, ChangeStatusCallback, this)) {
        LogError("Cynara initialization failed.");
        throw std::runtime_error("Cynara initialization failed.");
    }
}

void Cynara::Request(
    const std::string &user,
    const std::string &client,
    const std::string &session,
    const std::string &privilege,
    StatusCallback callback)
{
    int ret = cynara_async_check_cache(
      m_cynara,
      client.c_str(),
      session.c_str(),
      user.c_str(),
      privilege.c_str());

    switch (ret) {
    default:
    case CYNARA_API_ACCESS_DENIED:
        callback(false);
        break;
    case CYNARA_API_ACCESS_ALLOWED:
        callback(true);
        break;
    case CYNARA_API_CACHE_MISS:
        SendRequest(
            user,
            client,
            session,
            privilege,
            std::move(callback));
    }
}

void Cynara::ProcessSocket()
{
    if (CYNARA_API_SUCCESS != cynara_async_process(m_cynara))
        LogError("Function: cynara_async_process failed.");
}

Cynara::~Cynara()
{
    cynara_async_finish(m_cynara);
}

void Cynara::ChangeStatus(int oldFd, int newFd, cynara_async_status status)
{
    m_socketManager->CynaraSocket(oldFd, newFd, status == CYNARA_STATUS_FOR_RW);
}

void Cynara::ProcessResponse(
    cynara_check_id checkId,
    cynara_async_call_cause cause,
    int response)
{
    auto it = m_callbackMap.find(checkId);

    if (it == m_callbackMap.end())
        return;

    if (cause == CYNARA_CALL_CAUSE_ANSWER && response == CYNARA_API_ACCESS_ALLOWED)
        it->second(true);
    else
        it->second(false);

    m_callbackMap.erase(it);
}

void Cynara::SendRequest(
    const std::string &user,
    const std::string &client,
    const std::string &session,
    const std::string &privilege,
    StatusCallback callback)
{
    cynara_check_id checkId = 0;
    int ret = cynara_async_create_request(
        m_cynara,
        client.c_str(),
        session.c_str(),
        user.c_str(),
        privilege.c_str(),
        &checkId,
        ProcessResponseCallback,
        this);

    if (ret != CYNARA_API_SUCCESS)
        return callback(false);

    m_callbackMap.emplace(checkId, std::move(callback));
}

void Cynara::ChangeStatusCallback(
  int oldFd,
  int newFd,
  cynara_async_status status,
  void *ptr)
{
    static_cast<Cynara*>(ptr)->ChangeStatus(oldFd, newFd, status);
}

void Cynara::ProcessResponseCallback(
  cynara_check_id checkId,
  cynara_async_call_cause cause,
  int response,
  void *ptr)
{
    static_cast<Cynara*>(ptr)->ProcessResponse(checkId, cause, response);
}

bool Cynara::GetUserFromSocket(int socket, std::string &user)
{
    char *ptr;
    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_user(socket, USER_METHOD_DEFAULT, &ptr))
        return false;
    user = ptr;
    free(ptr);
    return true;
}

bool Cynara::GetClientFromSocket(int socket, std::string &client)
{
    char *ptr;
    if (CYNARA_API_SUCCESS != cynara_creds_socket_get_client(socket, CLIENT_METHOD_DEFAULT, &ptr))
        return false;
    client = ptr;
    free(ptr);
    return true;
}

} // namespace CKM
