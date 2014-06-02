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
#include <dpl/serialization.h>

#include <client-manager-impl.h>
#include <client-common.h>
#include <client-key-impl.h>
#include <message-buffer.h>
#include <protocols.h>

namespace CKM {

int Manager::ManagerImpl::saveKey(const Alias &alias, const Key &key, const Policy &policy) {
    m_counter++;

    return try_catch([&] {
        if (alias.empty() || key.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::SAVE));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(toDBDataType(key.getType())));
        Serialization::Serialize(send, alias);
        Serialization::Serialize(send, key.getKey());
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
        Serialization::Serialize(send, static_cast<int>(LogicCommand::REMOVE));
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

int Manager::ManagerImpl::getBinaryData(
    const Alias &alias,
    DBDataType sendDataType,
    const RawData &password,
    DBDataType &recvDataType,
    RawData &rawData)
{
    return try_catch([&] {
        if (alias.empty())
            return KEY_MANAGER_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LogicCommand::GET));
        Serialization::Serialize(send, m_counter);
        Serialization::Serialize(send, static_cast<int>(sendDataType));
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

        if (retCode == KEY_MANAGER_API_SUCCESS) {
            int tmpDataType;
            Deserialization::Deserialize(recv, tmpDataType);
            Deserialization::Deserialize(recv, rawData);
            recvDataType = static_cast<DBDataType>(tmpDataType);
        }

        if (counter != m_counter) {
            return KEY_MANAGER_API_ERROR_UNKNOWN;
        }

        return retCode;
    });
}

int Manager::ManagerImpl::getKey(const Alias &alias, const RawData &password, Key &key) {
    DBDataType recvDataType;
    RawData rawData;

    int retCode = getBinaryData(
        alias,
        DBDataType::KEY_RSA_PUBLIC,
        password,
        recvDataType,
        rawData);

    if (retCode != KEY_MANAGER_API_SUCCESS)
        return retCode;

    Key keyParsed(rawData, toKeyType(recvDataType));

    if (keyParsed.empty())
        return KEY_MANAGER_API_ERROR_BAD_RESPONSE;

    key = keyParsed;

    return KEY_MANAGER_API_SUCCESS;
}

} // namespace CKM

