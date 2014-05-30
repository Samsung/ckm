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
#include <client-manager-impl.h>
#include <message-buffer.h>
#include <client-common.h>
#include <dpl/serialization.h>
#include <protocols.h>
#include <client-key-impl.h>

namespace CKM {

int Manager::ManagerImpl::saveKey(const Alias &alias, const Key &key, const Policy &policy) {
    m_counter++;

    return try_catch([&] {
        if (alias.empty() || key.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(StorageCommand::SAVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(toDBDataType(key.getType())));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, key.getImpl());
        Serialization::Serialize(send, PolicySerializable(policy));

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int opType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, opType);
        Deserialization::Deserialize(recv, retCode);

        if (counter != m_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::removeKey(const Alias &alias) {
    return try_catch([&] {
        if (alias.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(StorageCommand::REMOVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(DBDataType::KEY_RSA_PUBLIC));
        Serialization::Serialize(send, alias);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int opType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, opType);
        Deserialization::Deserialize(recv, retCode);

        if (counter != m_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::getKey(const Alias &alias, const RawData &password, Key &key) {
    return try_catch([&] {
        if (alias.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(StorageCommand::GET));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(DBDataType::KEY_RSA_PUBLIC));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, password);

        int retCode = sendToServer(
            SERVICE_SOCKET_CKM_STORAGE,
            send.Pop(),
            recv);

        if (KEY_MANAGER_API_SUCCESS != retCode) {
            return retCode;
        }

        int command;
        int counter;
        int opType;
        Deserialization::Deserialize(recv, command);
        Deserialization::Deserialize(recv, counter);
        Deserialization::Deserialize(recv, opType);
        Deserialization::Deserialize(recv, retCode);

        if (retCode == KEY_MANAGER_API_SUCCESS)
            Deserialization::Deserialize(recv, *(key.getImpl()));

        if (counter != m_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

} // namespace CKM

