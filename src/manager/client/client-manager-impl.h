/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *
 * @file        client-manager-impl.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation.
 */
#pragma once

#include <ckm/key-manager.h>

namespace CKM {

class Manager::ManagerImpl {
public:
    ManagerImpl()
      : m_counter(0)
    {}
    virtual ~ManagerImpl(){}

    int saveKey(const Alias &alias, const Key &key, const Policy &policy) {
        m_counter++;

        return try_catch([&] {
            if (user.empty() || key.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            Message send, recv;
            Serialization::Serialization(send, static_cast<int>(StorageCommand::SAVE_KEY));
            Serialization::Serialize(send, m_counter);
            Serialization::Serialize(send, alias);
            Serialization::Serialize(send, key.getImpl());
            Serialization::Serialize(send, policy);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_STORAGE,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            int id;
            Deserialization::Deserialize(recv, id);
            Deserialization::Deserialize(recv, retCode);

            if (id != m_counter) {
                return KEY_MANAGER_API_ERROR_UNKNOWN;
            }

            return retCode;
        });
    }

    int removeKey(const Alias &alias) {
        return try_catch([&] {
            if (user.empty() || key.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            Message send, recv;
            Serialization::Serialization(send, static_cast<int>(StorageCommand::REMOVE_KEY));
            Serialization::Serialize(send, m_counter);
            Serialization::Serialize(send, alias);

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_STORAGE,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            int id;
            Deserialization::Deserialize(recv, id);
            Deserialization::Deserialize(recv, retCode);

            if (id != m_counter) {
                return KEY_MANAGER_API_ERROR_UNKNOWN;
            }

            return retCode;
    }

    int getKey(const Alias &alias, const RawData &password, Key &key) {
        return try_catch([&] {
            if (user.empty() || key.empty())
                return KEY_MANAGER_API_ERROR_INPUT_PARAM;

            Message send, recv;
            Serialization::Serialization(send, static_cast<int>(StorageCommand::REMOVE_KEY));
            Serialization::Serialize(send, m_counter);
            Serialization::Serialize(send, alias);
            Serialization::Serialize(send, password);
            Serialization::Serialize(send, key.getImpl());

            int retCode = sendToServer(
                SERVICE_SOCKET_CKM_STORAGE,
                send.Pop(),
                recv);

            if (KEY_MANAGER_API_SUCCESS != retCode) {
                return retCode;
            }

            int id;
            Deserialization::Deserialize(recv, id);
            Deserialization::Deserialize(recv, retCode);

            if (id != m_counter) {
                return KEY_MANAGER_API_ERROR_UNKNOWN;
            }

            return retCode;
    }

private:
    int m_counter;
};


